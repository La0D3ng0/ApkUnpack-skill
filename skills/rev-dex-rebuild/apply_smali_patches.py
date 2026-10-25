#!/usr/bin/env python3
"""Apply exact method-body patches to a copy of a baksmali tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


METHOD_START = re.compile(r"^\s*\.method\b")
METHOD_END = re.compile(r"^\s*\.end\s+method\s*$")
REGISTER_LINE = re.compile(r"^\s*\.(?:locals|registers)\s+\d+\s*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smali-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--source-dex", type=Path)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def class_path(root: Path, descriptor: str) -> Path:
    if not descriptor.startswith("L") or not descriptor.endswith(";"):
        raise ValueError(f"invalid class descriptor: {descriptor!r}")
    relative = descriptor[1:-1]
    if not relative or ".." in relative.split("/"):
        raise ValueError(f"unsafe class descriptor: {descriptor!r}")
    return root.joinpath(*relative.split("/")).with_suffix(".smali")


def locate_method(lines: list[str], target_signature: str) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    index = 0
    while index < len(lines):
        if not METHOD_START.match(lines[index]):
            index += 1
            continue
        declaration = lines[index].strip().split()
        signature = declaration[-1] if declaration else ""
        end = index + 1
        while end < len(lines) and not METHOD_END.match(lines[end]):
            end += 1
        if end >= len(lines):
            raise ValueError(f"unterminated method declaration at line {index + 1}")
        if signature == target_signature:
            matches.append((index, end))
        index = end + 1
    if len(matches) != 1:
        raise ValueError(f"expected one match for {target_signature}, found {len(matches)}")
    return matches[0]


def validate_body(body: str, path: Path) -> list[str]:
    lines = body.splitlines()
    forbidden = (".method", ".end method", ".class", ".super", ".implements")
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if any(stripped.startswith(token) for token in forbidden):
            raise ValueError(f"{path}:{line_number}: class/method boundary directive is not allowed")
    register_lines = [line for line in lines if REGISTER_LINE.match(line)]
    if len(register_lines) != 1:
        raise ValueError(f"{path}: body must contain exactly one .locals or .registers directive")
    return lines


def main() -> int:
    args = parse_args()
    source_root = args.smali_root.resolve()
    output_root = args.output_root.resolve()
    manifest_path = args.manifest.resolve()
    if not source_root.is_dir():
        raise SystemExit(f"smali root does not exist: {source_root}")
    if output_root.exists():
        raise SystemExit(f"output root already exists: {output_root}")
    if args.report and args.report.exists():
        raise SystemExit(f"report already exists: {args.report}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "rev-dex-rebuild/v1":
        raise SystemExit("manifest schema must be rev-dex-rebuild/v1")
    expected_dex_hash = str(manifest.get("source_dex_sha256", "")).lower()
    if expected_dex_hash:
        if args.source_dex is None:
            raise SystemExit("--source-dex is required when source_dex_sha256 is present")
        actual_dex_hash = digest(args.source_dex)
        if actual_dex_hash != expected_dex_hash:
            raise SystemExit(f"source DEX hash mismatch: {actual_dex_hash}")
    else:
        actual_dex_hash = None

    patches = manifest.get("patches")
    if not isinstance(patches, list) or not patches:
        raise SystemExit("manifest.patches must be a non-empty array")
    prepared: dict[Path, tuple[list[str], list[dict]]] = {}
    seen_targets: set[tuple[str, str]] = set()
    patch_reports: list[dict] = []
    for index, patch in enumerate(patches):
        descriptor = patch.get("class_descriptor")
        method_name = patch.get("method_name")
        method_descriptor = patch.get("method_descriptor")
        body_file = patch.get("body_file")
        if not all(isinstance(value, str) and value for value in (
            descriptor, method_name, method_descriptor, body_file
        )):
            raise SystemExit(f"patches[{index}] has missing string fields")
        target_signature = method_name + method_descriptor
        target_key = (descriptor, target_signature)
        if target_key in seen_targets:
            raise SystemExit(f"duplicate patch target: {descriptor}->{target_signature}")
        seen_targets.add(target_key)

        source_file = class_path(source_root, descriptor)
        if not source_file.is_file():
            raise SystemExit(f"class smali file does not exist: {source_file}")
        body_path = (manifest_path.parent / body_file).resolve()
        if not body_path.is_file():
            raise SystemExit(f"body file does not exist: {body_path}")
        try:
            body_path.relative_to(manifest_path.parent)
        except ValueError as exc:
            raise SystemExit(f"body file escapes manifest directory: {body_path}") from exc
        body_lines = validate_body(body_path.read_text(encoding="utf-8"), body_path)

        if source_file not in prepared:
            prepared[source_file] = (source_file.read_text(encoding="utf-8").splitlines(), [])
        original_lines, file_patches = prepared[source_file]
        start, end = locate_method(original_lines, target_signature)
        file_patches.append({
            "start": start,
            "end": end,
            "body_lines": body_lines,
            "patch_id": str(patch.get("patch_id", f"patch-{index}")),
            "class_descriptor": descriptor,
            "method_signature": target_signature,
            "body_file": str(body_path),
            "body_sha256": digest(body_path),
        })

    shutil.copytree(source_root, output_root)
    for source_file, (original_lines, file_patches) in prepared.items():
        output_file = output_root / source_file.relative_to(source_root)
        before_hash = digest(source_file)
        updated = list(original_lines)
        for patch in sorted(file_patches, key=lambda item: item["start"], reverse=True):
            indent = "    "
            normalized_body = [line if not line else indent + line.lstrip() for line in patch["body_lines"]]
            updated[patch["start"] + 1:patch["end"]] = normalized_body
        output_file.write_text("\n".join(updated) + "\n", encoding="utf-8")
        after_hash = digest(output_file)
        for patch in file_patches:
            patch_reports.append({
                "patch_id": patch["patch_id"],
                "class_descriptor": patch["class_descriptor"],
                "method_signature": patch["method_signature"],
                "body_file": patch["body_file"],
                "body_sha256": patch["body_sha256"],
                "source_smali": str(source_file),
                "output_smali": str(output_file),
                "source_smali_sha256": before_hash,
                "output_smali_sha256": after_hash,
            })

    report = {
        "schema": "rev-dex-rebuild/smali-patch-report-v1",
        "source_root": str(source_root),
        "output_root": str(output_root),
        "source_dex_sha256": actual_dex_hash,
        "patch_count": len(patch_reports),
        "patches": patch_reports,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
