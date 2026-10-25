#!/usr/bin/env python3
"""Fast, read-only APK shell detection with an optional APKiD cross-check."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "rev-apk-shell-detect/report-v1"
SIGNATURE_SCHEMA = "rev-apk-shell-detect/signatures-v1"
DEFAULT_SIGNATURES = Path(__file__).resolve().parent / "shell-signatures.json"
DEX_NAME_PATTERN = re.compile(r"^classes(?:\d+)?\.dex$", re.IGNORECASE)
MAX_DEX_SCAN_BYTES = 32 * 1024 * 1024
MAX_PAYLOAD_SAMPLE_BYTES = 128 * 1024
MAX_PAYLOAD_SCAN_BYTES = 4 * 1024 * 1024
MAX_APKID_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CONTAINER_SCAN_BYTES = 256 * 1024 * 1024
MAX_REPORTED_MARKERS = 32

RUNTIME_DEX_MARKERS = (
    b"Ldalvik/system/DexClassLoader;",
    b"Ldalvik/system/InMemoryDexClassLoader;",
    b"Ldalvik/system/DelegateLastClassLoader;",
    b"DexFile.loadDex",
    b"openDexFileNative",
)
NATIVE_LOADER_OWNERS = (b"Ljava/lang/System;", b"Ljava/lang/Runtime;")
NATIVE_LOADER_NAMES = (b"loadLibrary", b"load")
SUSPICIOUS_PAYLOAD_SUFFIXES = (".bin", ".blob", ".dat", ".enc", ".pack", ".payload")
IGNORED_PAYLOAD_BASENAMES = {"global-metadata.dat", "resources.arsc"}


class DetectionError(RuntimeError):
    """Raised when the input or signature database cannot be analyzed safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unsafe_zip_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return True
    return any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)


def read_limited(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> tuple[bytes, bool]:
    with archive.open(info) as handle:
        data = handle.read(limit + 1)
    return data[:limit], len(data) > limit


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def dex_header(data: bytes) -> dict[str, Any] | None:
    if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
        return None
    try:
        file_size, header_size, endian_tag = struct.unpack_from("<III", data, 0x20)
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        method_ids_size = struct.unpack_from("<I", data, 0x58)[0]
        class_defs_size = struct.unpack_from("<I", data, 0x60)[0]
        data_size, data_off = struct.unpack_from("<II", data, 0x68)
    except struct.error:
        return None
    if header_size != 0x70 or endian_tag not in {0x12345678, 0x78563412}:
        return None
    if file_size < 0x70 or string_ids_size > 0x1000000:
        return None
    if string_ids_size and (string_ids_off < 0x70 or string_ids_off >= file_size):
        return None
    return {
        "declared_size": file_size,
        "class_defs_size": class_defs_size,
        "method_ids_size": method_ids_size,
        "string_ids_size": string_ids_size,
        "data_off": data_off,
        "data_size": data_size,
        "valid_data_end": data_off + data_size,
        "data_end_basis": "DEX header data_off + data_size; not the end of parsed map_list",
        "scan_truncated": len(data) < file_size,
    }


def scan_primary_container(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, header: dict[str, Any]
) -> dict[str, Any]:
    """Bounded structural scan; marker counts are candidates, not segment proof."""
    declared = int(header["declared_size"])
    data_end = int(header["valid_data_end"])
    layout: dict[str, Any] = {
        "entry": info.filename,
        "declared_file_size": declared,
        "zip_uncompressed_size": info.file_size,
        "valid_data_end": data_end,
        "data_end_basis": "DEX header data_off + data_size; not the end of parsed map_list",
        "overlay_bytes": max(0, min(declared, info.file_size) - data_end),
        "fdex_marker_count": 0,
        "fdex_trailer_count": None,
        "fdex_outer_trailer": False,
        "fdex_marker_offsets": [],
        "embedded_dex_magic_count": 0,
        "dexdata0_offset": None,
        "prefix_sample_entropy": None,
        "likely_encrypted_prefix": False,
        "scan_complete": False,
        "scan_limit_reason": None,
    }
    if data_end > MAX_CONTAINER_SCAN_BYTES:
        layout["scan_limit_reason"] = "data offset exceeds the 256 MiB bounded seek limit"
        return layout
    if not 0x70 <= data_end < min(declared, info.file_size):
        return layout
    available = min(declared, info.file_size) - data_end
    scan_bytes = min(available, MAX_CONTAINER_SCAN_BYTES)
    carry = b""
    first = bytearray()
    last = b""
    marker_offsets: list[int] = []
    with archive.open(info) as handle:
        handle.seek(data_end)
        scanned = 0
        while scanned < scan_bytes:
            chunk = handle.read(min(1024 * 1024, scan_bytes - scanned))
            if not chunk:
                break
            if len(first) < 64 * 1024:
                first.extend(chunk[:64 * 1024 - len(first)])
            block = carry + chunk
            base = data_end + scanned - len(carry)
            for needle, key in ((b"fdex", "fdex_marker_count"),
                                (b"dex\n0", "embedded_dex_magic_count")):
                position = 0
                while (position := block.find(needle, position)) >= 0:
                    # A marker wholly inside the carried bytes was counted in
                    # the previous chunk.
                    if base + position + len(needle) > data_end + scanned:
                        layout[key] += 1
                        if needle == b"fdex" and len(marker_offsets) < MAX_REPORTED_MARKERS:
                            marker_offsets.append(base + position)
                    position += 1
            carry = block[-4:]
            last = (last + chunk)[-4:]
            scanned += len(chunk)
    layout["scan_complete"] = scanned == available
    if not layout["scan_complete"]:
        layout["scan_limit_reason"] = "overlay exceeded the 256 MiB scan limit or ended early"
    layout["fdex_marker_offsets"] = marker_offsets
    outer = layout["scan_complete"] and last == b"fdex"
    layout["fdex_outer_trailer"] = outer
    if outer:
        # The EOF marker is the outer container trailer. Interior markers are
        # candidate segment trailers until their lengths are independently checked.
        layout["fdex_trailer_count"] = layout["fdex_marker_count"] - 1
    local = bytes(first)
    marker = local[:4096].find(b"dexdata0")
    if marker >= 0:
        layout["dexdata0_offset"] = data_end + marker
    sample = local[32:]
    if len(sample) >= 4096:
        sample_entropy = entropy(sample)
        layout["prefix_sample_entropy"] = round(sample_entropy, 3)
        layout["likely_encrypted_prefix"] = sample_entropy >= 7.5
    return layout


def load_signatures(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DetectionError(f"cannot read signature database {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != SIGNATURE_SCHEMA:
        raise DetectionError(f"signature database must use schema {SIGNATURE_SCHEMA}")
    families = value.get("families")
    if not isinstance(families, list) or not families:
        raise DetectionError("signature database families must be a non-empty array")
    return value


def flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(flatten_strings(item))
        return result
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(flatten_strings(item))
        return result
    return []


def extract_apkid_packers(value: Any) -> list[str]:
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            node_type = str(node.get("type", "")).lower()
            if "packer" in node_type:
                for key in ("name", "match", "value"):
                    found.update(item.strip() for item in flatten_strings(node.get(key)) if item.strip())
            for key, child in node.items():
                if "packer" in str(key).lower():
                    found.update(item.strip() for item in flatten_strings(child) if item.strip())
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return sorted(found)


def run_apkid(apk: Path, mode: str, timeout: int) -> dict[str, Any]:
    executable = shutil.which("apkid")
    result: dict[str, Any] = {
        "mode": mode,
        "available": executable is not None,
        "ran": False,
        "packer_matches": [],
        "error": None,
    }
    if mode == "off":
        return result
    if executable is None:
        if mode == "required":
            result["error"] = "apkid is required but was not found on PATH"
        return result
    try:
        completed = subprocess.run(
            [executable, "--json", str(apk)],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["ran"] = True
        result["error"] = f"apkid execution failed: {exc}"
        return result
    result["ran"] = True
    if len(completed.stdout) > MAX_APKID_OUTPUT_BYTES:
        result["error"] = "apkid JSON exceeded the 4 MiB safety limit"
        return result
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        result["error"] = f"apkid exited {completed.returncode}: {stderr[:500]}"
        return result
    try:
        parsed = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        result["error"] = f"apkid returned invalid JSON: {exc}"
        return result
    result["packer_matches"] = extract_apkid_packers(parsed)
    return result


def add_evidence(
    evidence: list[dict[str, Any]], evidence_id: str, category: str, weight: int,
    source: str, detail: str,
) -> None:
    evidence.append({
        "id": evidence_id,
        "category": category,
        "weight": weight,
        "source": source,
        "detail": detail,
    })


def identify_known_family(
    families: list[dict[str, Any]], names: list[str], dex_blobs: list[tuple[str, bytes]],
    apkid_matches: list[str],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    lower_names = {name.lower(): name for name in names}
    basenames: dict[str, list[str]] = defaultdict(list)
    for name in names:
        basenames[PurePosixPath(name).name.lower()].append(name)

    candidates: list[dict[str, Any]] = []
    for family in families:
        score = 0
        strong = False
        hits: list[dict[str, Any]] = []
        for marker in family.get("markers", []):
            kind = marker.get("kind")
            value = str(marker.get("value", ""))
            weight = int(marker.get("weight", 0))
            sources: list[str] = []
            if kind == "entry_basename":
                sources = basenames.get(value.lower(), [])
            elif kind == "entry_path" and value.lower() in lower_names:
                sources = [lower_names[value.lower()]]
            elif kind == "dex_string":
                needle = value.encode("utf-8")
                sources = [entry for entry, blob in dex_blobs if needle in blob]
            if not sources:
                continue
            score += weight
            is_unique = bool(marker.get("unique"))
            strong = strong or (is_unique and weight >= 5)
            hits.append({
                "kind": kind,
                "value": value,
                "weight": weight,
                "unique": is_unique,
                "sources": sources[:20],
            })

        aliases = [str(alias).lower() for alias in family.get("apkid_aliases", [])]
        matched_apkid = [
            match for match in apkid_matches
            if any(alias in match.lower() for alias in aliases)
        ]
        if matched_apkid:
            score += 8
            strong = True
            hits.append({
                "kind": "apkid",
                "value": matched_apkid[0],
                "weight": 8,
                "unique": True,
                "sources": ["apkid"],
            })
        if hits:
            candidates.append({
                "id": family["id"],
                "display_name": family["display_name"],
                "category": family["category"],
                "score": score,
                "strong": strong or (score >= 8 and len(hits) >= 2),
                "hits": hits,
            })

    known_apkid_matches = {
        hit["value"]
        for candidate in candidates for hit in candidate["hits"] if hit["kind"] == "apkid"
    }
    for match in apkid_matches:
        if match not in known_apkid_matches:
            candidates.append({
                "id": "apkid-" + hashlib.sha256(match.encode("utf-8")).hexdigest()[:12],
                "display_name": match,
                "category": "common",
                "score": 8,
                "strong": True,
                "hits": [{
                    "kind": "apkid", "value": match, "weight": 8,
                    "unique": True, "sources": ["apkid"],
                }],
            })

    candidates.sort(key=lambda item: (-item["score"], item["display_name"]))
    strong_candidates = [candidate for candidate in candidates if candidate["strong"]]
    conflict = len(strong_candidates) > 1 and (
        strong_candidates[0]["score"] - strong_candidates[1]["score"] < 3
    )
    winner = strong_candidates[0] if strong_candidates and not conflict else None
    return winner, candidates, conflict


def detect_apk_shell(
    apk_path: Path | str, *, signatures_path: Path | str = DEFAULT_SIGNATURES,
    apkid_mode: str = "auto", apkid_timeout: int = 60,
    apk_sha256: str | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    apk = Path(apk_path).resolve()
    if not apk.is_file():
        raise DetectionError(f"APK does not exist: {apk}")
    if apkid_mode not in {"auto", "off", "required"}:
        raise DetectionError("apkid_mode must be auto, off, or required")
    signatures = load_signatures(Path(signatures_path))
    digest = apk_sha256 or sha256_file(apk)

    try:
        archive = zipfile.ZipFile(apk)
    except (OSError, zipfile.BadZipFile) as exc:
        raise DetectionError(f"APK is not a valid ZIP: {apk}: {exc}") from exc

    evidence: list[dict[str, Any]] = []
    dex_reports: list[dict[str, Any]] = []
    dex_blobs: list[tuple[str, bytes]] = []
    suspicious_payloads: list[dict[str, Any]] = []
    container_layout: dict[str, Any] | None = None
    scan_gaps: list[str] = []
    scan_limits: list[str] = []
    try:
        infos = archive.infolist()
        if len(infos) > 200_000:
            raise DetectionError(f"APK has too many ZIP entries: {len(infos)}")
        names = [info.filename for info in infos]
        duplicate_names = sorted(name for name, count in Counter(names).items() if count > 1)
        unsafe_names = sorted(name for name in names if unsafe_zip_name(name))
        if duplicate_names:
            scan_gaps.append("duplicate ZIP entries make marker ownership ambiguous")
        if unsafe_names:
            scan_gaps.append("unsafe ZIP entry names were not opened")
        encrypted_entries = [info.filename for info in infos if info.flag_bits & 0x1]
        if encrypted_entries:
            scan_gaps.append("encrypted ZIP entries could not be inspected")
        if "AndroidManifest.xml" not in names:
            scan_gaps.append("AndroidManifest.xml is missing")

        dex_infos = [info for info in infos if DEX_NAME_PATTERN.fullmatch(info.filename)]
        if not dex_infos:
            scan_gaps.append("no root classes*.dex entry was found")
        remaining_dex_scan = MAX_DEX_SCAN_BYTES
        for info in sorted(dex_infos, key=lambda item: item.filename.lower()):
            if unsafe_zip_name(info.filename) or info.flag_bits & 0x1:
                continue
            if remaining_dex_scan <= 0:
                scan_limits.append("total DEX string scan budget was exhausted")
                break
            try:
                data, truncated = read_limited(archive, info, remaining_dex_scan)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                scan_gaps.append(f"could not read {info.filename}: {exc}")
                continue
            remaining_dex_scan -= len(data)
            parsed = dex_header(data)
            report: dict[str, Any] = {
                "entry": info.filename,
                "zip_size": info.file_size,
                "valid_header": parsed is not None,
                "scan_truncated": truncated,
            }
            if parsed:
                report.update(parsed)
                dex_blobs.append((info.filename, data))
                if truncated:
                    scan_limits.append(f"{info.filename} exceeded the bounded DEX string scan limit")
            else:
                scan_gaps.append(f"{info.filename} has no valid DEX header")
            dex_reports.append(report)

        runtime_hits: list[str] = []
        native_loader_hits: list[str] = []
        for entry, blob in dex_blobs:
            if any(marker in blob for marker in RUNTIME_DEX_MARKERS):
                runtime_hits.append(entry)
            if (
                any(owner in blob for owner in NATIVE_LOADER_OWNERS)
                and any(name in blob for name in NATIVE_LOADER_NAMES)
            ):
                native_loader_hits.append(entry)
        if runtime_hits:
            add_evidence(
                evidence, "runtime-dex-loader", "runtime_loader", 2,
                ", ".join(sorted(set(runtime_hits))),
                "DEX references a runtime class-loading API; this is not conclusive by itself.",
            )

        primary = next((item for item in dex_reports if item["entry"].lower() == "classes.dex"), None)
        if primary and primary.get("valid_header"):
            primary_info = next((info for info in dex_infos if info.filename.lower() == "classes.dex"), None)
            if primary_info and int(primary["valid_data_end"]) < int(primary["declared_size"]):
                try:
                    container_layout = scan_primary_container(archive, primary_info, primary)
                    if not container_layout["scan_complete"]:
                        scan_limits.append(str(container_layout["scan_limit_reason"]))
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    scan_gaps.append(f"could not inspect primary DEX overlay: {exc}")
        native_entries = [
            name for name in names
            if name.lower().startswith("lib/") and name.lower().endswith(".so")
        ]
        if primary and primary.get("valid_header"):
            class_count = int(primary.get("class_defs_size", 0))
            if class_count <= 25 and (native_entries or apk.stat().st_size >= 512 * 1024):
                add_evidence(
                    evidence, "small-primary-dex", "stub_dex", 2, primary["entry"],
                    f"Primary DEX declares only {class_count} classes while native or large payload content exists.",
                )

        remaining_payload_scan = MAX_PAYLOAD_SCAN_BYTES
        for info in infos:
            lowered = info.filename.lower()
            basename = PurePosixPath(lowered).name
            if (
                info.file_size < 64 * 1024
                or basename in IGNORED_PAYLOAD_BASENAMES
                or not lowered.endswith(SUSPICIOUS_PAYLOAD_SUFFIXES)
                or unsafe_zip_name(info.filename)
                or info.flag_bits & 0x1
            ):
                continue
            if remaining_payload_scan <= 0:
                scan_limits.append("opaque payload sample budget was exhausted")
                break
            try:
                sample, _ = read_limited(
                    archive, info, min(MAX_PAYLOAD_SAMPLE_BYTES, remaining_payload_scan)
                )
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            remaining_payload_scan -= len(sample)
            sample_entropy = entropy(sample)
            if sample_entropy >= 7.2:
                suspicious_payloads.append({
                    "entry": info.filename,
                    "size": info.file_size,
                    "sample_entropy": round(sample_entropy, 3),
                })
        if suspicious_payloads:
            add_evidence(
                evidence, "opaque-high-entropy-payload", "payload", 3,
                ", ".join(item["entry"] for item in suspicious_payloads[:5]),
                "Opaque high-entropy payload content may hold encrypted code; common media formats are excluded.",
            )
        has_stub_dex = any(item["category"] == "stub_dex" for item in evidence)
        if native_entries and has_stub_dex and (runtime_hits or native_loader_hits):
            add_evidence(
                evidence, "stub-native-loader-chain", "native_bootstrap", 2,
                ", ".join(native_entries[:5]),
                "Small primary DEX, an explicit loader API, and native code form a plausible shell bootstrap chain.",
            )

        apkid = run_apkid(apk, apkid_mode, apkid_timeout)
        if apkid_mode == "required" and apkid.get("error"):
            scan_gaps.append(str(apkid["error"]))
        winner, candidates, conflict = identify_known_family(
            signatures["families"], names, dex_blobs, apkid["packer_matches"]
        )
    finally:
        archive.close()

    fdex_gate = bool(
        container_layout
        and container_layout["scan_complete"]
        and container_layout["overlay_bytes"] >= 64 * 1024
        and container_layout["fdex_outer_trailer"]
        and container_layout["fdex_trailer_count"] >= 1
        and container_layout["dexdata0_offset"] is not None
    )
    if fdex_gate:
        add_evidence(
            evidence, "fdex-overlay-container", "extracted_dex_container", 7,
            str(container_layout["entry"]),
            f"DEX data ends at 0x{container_layout['valid_data_end']:x}; "
            f"{container_layout['overlay_bytes']} overlay bytes contain dexdata0, "
            f"{container_layout['fdex_trailer_count']} candidate interior fdex trailers and an EOF trailer.",
        )
    generic_score = sum(item["weight"] for item in evidence)
    generic_categories = sorted({item["category"] for item in evidence})
    category_set = set(generic_categories)
    custom_gate = (
        generic_score >= 7
        and {"stub_dex", "payload"}.issubset(category_set)
        and bool(category_set & {"runtime_loader", "native_bootstrap"})
    )

    apkid_required_failed = apkid_mode == "required" and bool(apkid.get("error"))
    if apkid_required_failed:
        status = "inconclusive"
        shell_detected = None
        shell = {"family_id": None, "family": None, "category": None, "confidence": "low"}
        gate = {
            "continue_unpacking": False,
            "reason": "the required APKiD cross-check did not complete",
        }
    elif winner:
        status = "known_shell"
        shell_detected: bool | None = True
        shell = {
            "family_id": winner["id"],
            "family": winner["display_name"],
            "category": winner["category"],
            "confidence": "high" if winner["score"] >= 7 else "medium",
        }
        gate = {
            "continue_unpacking": True,
            "reason": f"known shell family matched: {winner['display_name']}",
        }
    elif conflict:
        status = "inconclusive"
        shell_detected = None
        shell = {"family_id": None, "family": None, "category": None, "confidence": "low"}
        gate = {
            "continue_unpacking": False,
            "reason": "multiple known shell families have conflicting strong evidence",
        }
    elif custom_gate or fdex_gate:
        status = "custom_shell"
        shell_detected = True
        shell = {
            "family_id": "custom",
            "family": "Custom shell",
            "category": "custom",
            "confidence": "medium",
        }
        gate = {
            "continue_unpacking": True,
            "reason": (
                "fdex overlay structure indicates an extracted-DEX container"
                if fdex_gate else
                "multiple independent shell-structure signals passed the custom-shell gate"
            ),
        }
    elif scan_gaps or generic_score >= 3 or candidates:
        status = "inconclusive"
        shell_detected = None
        shell = {"family_id": None, "family": None, "category": None, "confidence": "low"}
        gate = {
            "continue_unpacking": False,
            "reason": "static evidence is incomplete or below the shell classification threshold",
        }
    else:
        status = "no_shell"
        shell_detected = False
        shell = {"family_id": None, "family": None, "category": None, "confidence": "medium"}
        gate = {
            "continue_unpacking": False,
            "reason": "no known signature or multi-signal shell structure was detected",
        }

    if fdex_gate:
        shell["variant"] = "fdex-overlay"
        shell["generation"] = "second-generation-candidate"
        routing = {
            "next_skill": "rev-gen2-extracted-dex-unpack",
            "confidence": "high",
            "reason": "primary DEX has a large overlay, dexdata0 marker, interior fdex markers, and an EOF fdex trailer; inspect the extracted-method layout before reconstruction",
            "downstream_skill": "rev-dex-rebuild",
            "conditional_acquisition_skill": "rev-dex-dumper",
        }
    elif status in {"known_shell", "custom_shell"} and any(
        item["category"] == "stub_dex" for item in evidence
    ) and bool(runtime_hits or native_loader_hits):
        shell["variant"] = "stub-loader"
        shell["generation"] = "first-generation-candidate"
        routing = {
            "next_skill": "rev-dex-dumper",
            "confidence": "medium",
            "reason": "small bootstrap DEX and runtime loader evidence favor a full-DEX memory dump; verify that the dump contains target app classes",
        }
    else:
        shell["variant"] = "unknown"
        shell["generation"] = "unknown"
        routing = {
            "next_skill": None,
            "confidence": "low",
            "reason": "family identification alone does not establish first- or second-generation behavior; inspect DEX and loader structure before choosing a dump or extraction workflow",
        }

    return {
        "schema": SCHEMA,
        "apk": {
            "path": str(apk),
            "size_bytes": apk.stat().st_size,
            "sha256": digest,
        },
        "status": status,
        "shell_detected": shell_detected,
        "shell": shell,
        "gate": gate,
        "container_layout": container_layout,
        "routing": routing,
        "known_candidates": candidates,
        "structural_score": generic_score,
        "structural_categories": generic_categories,
        "evidence": evidence,
        "dex": dex_reports,
        "suspicious_payloads": suspicious_payloads[:20],
        "apkid": apkid,
        "scan_gaps": scan_gaps,
        "scan_limits": scan_limits,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "limitations": [
            "no_shell means no shell was detected by this bounded static scan; it is not a proof of absence",
            "ordinary obfuscation and native code protection are not classified as APK shells",
            "custom_shell requires independent stub DEX, opaque payload, and loader/bootstrap evidence",
            "inconclusive samples need APKiD rule updates, manual static review, or a narrowly scoped runtime probe",
            "fdex interior marker counts are candidate segment trailers until decrypted segment sizes confirm them",
            "a small stub DEX and loader only suggest first-generation full-DEX dumping; validate the resulting app classes",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--signatures", type=Path, default=DEFAULT_SIGNATURES)
    parser.add_argument("--apkid", choices=("auto", "off", "required"), default="auto")
    parser.add_argument("--apkid-timeout", type=int, default=60)
    parser.add_argument("--compact", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = detect_apk_shell(
            args.apk, signatures_path=args.signatures, apkid_mode=args.apkid,
            apkid_timeout=args.apkid_timeout,
        )
    except DetectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, ensure_ascii=False, indent=None if args.compact else 2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
