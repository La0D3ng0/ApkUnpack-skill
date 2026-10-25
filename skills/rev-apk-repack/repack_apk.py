#!/usr/bin/env python3
"""Repack approved replacement entries into a new unsigned APK."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


DEX_ENTRY_RE = re.compile(r"^classes(?:\d+)?\.dex$")
SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_entry_name(name: str) -> None:
    if not name or "\\" in name:
        raise ValueError(f"invalid archive entry name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe archive entry name: {name!r}")


def is_legacy_signature(name: str) -> bool:
    upper = name.upper()
    if not upper.startswith("META-INF/"):
        return False
    leaf = upper[len("META-INF/"):]
    if "/" in leaf:
        return False
    return leaf == "MANIFEST.MF" or leaf.endswith(SIGNATURE_SUFFIXES)


def clone_info(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    cloned = zipfile.ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "reserved", "flag_bits", "volume", "internal_attr",
        "external_attr",
    ):
        if hasattr(info, attribute):
            setattr(cloned, attribute, getattr(info, attribute))
    return cloned


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    output = args.output.resolve()
    report_path = args.report.resolve() if args.report else None
    if output.exists():
        raise SystemExit(f"output already exists: {output}")
    if report_path and report_path.exists():
        raise SystemExit(f"report already exists: {report_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "rev-apk-repack/v1":
        raise SystemExit("manifest schema must be rev-apk-repack/v1")
    source = (manifest_path.parent / manifest["source_apk"]).resolve()
    if not source.is_file():
        raise SystemExit(f"source APK does not exist: {source}")
    if source == output:
        raise SystemExit("output must not overwrite the source APK")
    source_hash = digest_file(source)
    if source_hash.lower() != str(manifest.get("source_apk_sha256", "")).lower():
        raise SystemExit(f"source APK hash mismatch: {source_hash}")

    allow_new = manifest.get("allow_new_entries") is True
    remove_signatures = manifest.get("remove_legacy_signatures") is not False
    raw_replacements = manifest.get("replacements")
    if not isinstance(raw_replacements, list) or not raw_replacements:
        raise SystemExit("manifest.replacements must be a non-empty array")
    replacements: dict[str, dict] = {}
    for index, item in enumerate(raw_replacements):
        name = item.get("entry")
        file_name = item.get("file")
        if not isinstance(name, str) or not isinstance(file_name, str):
            raise SystemExit(f"replacements[{index}] requires entry and file strings")
        validate_entry_name(name)
        if name in replacements:
            raise SystemExit(f"duplicate replacement entry: {name}")
        replacement_path = (manifest_path.parent / file_name).resolve()
        if not replacement_path.is_file():
            raise SystemExit(f"replacement file does not exist: {replacement_path}")
        replacement_hash = digest_file(replacement_path)
        if replacement_hash.lower() != str(item.get("sha256", "")).lower():
            raise SystemExit(f"replacement hash mismatch for {name}: {replacement_hash}")
        if DEX_ENTRY_RE.fullmatch(name):
            validation_name = item.get("validation_report")
            if not isinstance(validation_name, str):
                raise SystemExit(f"DEX replacement {name} requires validation_report")
            validation_path = (manifest_path.parent / validation_name).resolve()
            validation = json.loads(validation_path.read_text(encoding="utf-8"))
            if validation.get("valid") is not True:
                raise SystemExit(f"DEX validation did not pass for {name}")
            if validation.get("sha256", "").lower() != replacement_hash.lower():
                raise SystemExit(f"DEX validation hash does not match replacement {name}")
        replacements[name] = {
            "path": replacement_path,
            "sha256": replacement_hash,
            "manifest": item,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    temp_handle = tempfile.NamedTemporaryFile(
        prefix=output.name + ".", suffix=".tmp", dir=output.parent, delete=False
    )
    temp_path = Path(temp_handle.name)
    temp_handle.close()
    removed: list[str] = []
    replaced: list[dict] = []
    added: list[dict] = []
    try:
        with zipfile.ZipFile(source, "r") as source_zip:
            infos = source_zip.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ValueError("source APK contains duplicate entry names")
            for name in names:
                validate_entry_name(name)
            missing = set(replacements) - set(names)
            if missing and not allow_new:
                raise ValueError(f"replacement entries are absent from source: {sorted(missing)}")

            with zipfile.ZipFile(temp_path, "w", allowZip64=True) as output_zip:
                for info in infos:
                    name = info.filename
                    if remove_signatures and is_legacy_signature(name):
                        removed.append(name)
                        continue
                    original = source_zip.read(info)
                    cloned = clone_info(info)
                    if name in replacements:
                        replacement = replacements[name]
                        content = replacement["path"].read_bytes()
                        replaced.append({
                            "entry": name,
                            "source_sha256": digest_bytes(original),
                            "replacement_sha256": replacement["sha256"],
                            "source_size": len(original),
                            "replacement_size": len(content),
                            "compression": cloned.compress_type,
                        })
                    else:
                        content = original
                    output_zip.writestr(cloned, content)

                for name in sorted(missing):
                    replacement = replacements[name]
                    content = replacement["path"].read_bytes()
                    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    output_zip.writestr(info, content)
                    added.append({
                        "entry": name,
                        "sha256": replacement["sha256"],
                        "size": len(content),
                        "compression": info.compress_type,
                    })

        with zipfile.ZipFile(temp_path, "r") as check_zip:
            bad_entry = check_zip.testzip()
            if bad_entry is not None:
                raise ValueError(f"CRC validation failed for {bad_entry}")
            output_names = check_zip.namelist()
            if len(output_names) != len(set(output_names)):
                raise ValueError("output APK contains duplicate entry names")
            for name, replacement in replacements.items():
                if digest_bytes(check_zip.read(name)) != replacement["sha256"]:
                    raise ValueError(f"output replacement hash mismatch for {name}")
            if remove_signatures and any(is_legacy_signature(name) for name in output_names):
                raise ValueError("legacy signature entries remain in output")
            if "AndroidManifest.xml" not in output_names:
                raise ValueError("output APK is missing AndroidManifest.xml")
            output_entry_count = len(output_names)

        os.replace(temp_path, output)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise

    output_hash = digest_file(output)
    if digest_file(source) != source_hash:
        raise SystemExit("source APK changed during repack")
    report = {
        "schema": "rev-apk-repack/report-v1",
        "status": "unsigned",
        "source_apk": str(source),
        "source_apk_sha256": source_hash,
        "output_apk": str(output),
        "output_apk_sha256": output_hash,
        "output_entry_count": output_entry_count,
        "removed_legacy_signatures": removed,
        "replacements": replaced,
        "added_entries": added,
        "crc_validation": "passed",
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if report_path:
        report_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
