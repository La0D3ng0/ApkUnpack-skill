#!/usr/bin/env python3
"""Summarize extracted-DEX container evidence without guessing decrypt parameters."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import zipfile
from pathlib import Path


DETECTOR = Path(__file__).resolve().parents[1] / "rev-apk-shell-detect" / "detect_apk_shell.py"


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--report", type=Path, help="write a focused JSON report")
    parser.add_argument("--extract-container", type=Path,
                        help="write unmodified classes.dex to a new file")
    parser.add_argument("--payload-after-marker", type=parse_int, default=12,
                        help="observed bytes from dexdata0 marker to payload for this variant; default 12 is a hypothesis")
    args = parser.parse_args()
    if not 0 <= args.payload_after_marker <= 4096:
        parser.error("--payload-after-marker must be in 0..4096")
    if not DETECTOR.is_file():
        parser.error("rev-apk-shell-detect/detect_apk_shell.py is required beside this Skill")
    spec = importlib.util.spec_from_file_location("apk_shell_detector", DETECTOR)
    detector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detector)
    result = detector.detect_apk_shell(args.apk, apkid_mode="off")
    layout = result.get("container_layout")
    focused = {
        "schema": "rev-gen2-extracted-dex-unpack/container-triage-v1",
        "apk": result["apk"],
        "family": result["shell"]["family"],
        "variant": result["shell"]["variant"],
        "generation": result["shell"]["generation"],
        "routing": result["routing"],
        "container_layout": layout,
        "payload_offset_candidate": (
            layout["dexdata0_offset"] + args.payload_after_marker
            if layout and layout["dexdata0_offset"] is not None else None
        ),
        "payload_offset_candidate_delta": args.payload_after_marker,
        "payload_offset_candidate_basis": (
            "Observed dexdata0 record shape in the tested Bangcle fdex variant; "
            "verify against the current native parser before decryption/rebuild."
        ),
        "notes": [
            "The payload offset is a layout candidate; confirm it with the target native parser.",
            "Interior fdex markers are candidate segment ends; validate each with decrypted DEX file_size.",
            "Derive key, cipher mode, encrypted extent, and method mapping from this APK; no defaults are implied.",
        ],
    }
    report = args.report.resolve() if args.report else None
    output = args.extract_container.resolve() if args.extract_container else None
    if report and report.exists():
        parser.error(f"refusing to overwrite {report}")
    if output and output.exists():
        parser.error(f"refusing to overwrite {output}")
    if report and output and report == output:
        parser.error("report and extracted container must use different paths")
    if args.extract_container:
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.apk) as archive, archive.open("classes.dex") as source, output.open("xb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        focused["extracted_container"] = str(output)
    rendered = json.dumps(focused, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
