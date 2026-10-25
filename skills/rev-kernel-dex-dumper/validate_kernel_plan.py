#!/usr/bin/env python3
"""Validate an authorized Akane/JDex2 kernel-assisted acquisition plan."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PLAN_SCHEMA = "rev-kernel-dex-dumper/plan-v1"
LOCK_SCHEMA = "rev-kernel-dex-dumper/tool-lock-v1"
DEFAULT_LOCK = Path(__file__).resolve().parent / "tool-lock.json"
ALLOWED_ABIS = {"arm64-v8a", "armeabi-v7a"}
ALLOWED_MODES = {"companion_dex_jni_bridge", "native_art_adapter"}
ALLOWED_CONCEALMENT = {"vma_name", "hide_from_memory", "hide_path", "hide_module"}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def kernel_version(release: Any) -> tuple[int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)", str(release or ""))
    return (int(match.group(1)), int(match.group(2))) if match else None


def validate(plan: dict[str, Any], lock: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if plan.get("schema") != PLAN_SCHEMA:
        errors.append(f"schema must be {PLAN_SCHEMA}")
    if lock.get("schema") != LOCK_SCHEMA:
        errors.append(f"tool lock schema must be {LOCK_SCHEMA}")

    auth = plan.get("authorization") if isinstance(plan.get("authorization"), dict) else {}
    if auth.get("authorized") is not True or not str(auth.get("scope", "")).strip():
        errors.append("explicit authorization and non-empty scope are required")

    device = plan.get("device") if isinstance(plan.get("device"), dict) else {}
    if device.get("root") is not True:
        errors.append("root access is required")
    if device.get("disposable") is not True:
        errors.append("use a disposable lab device")
    try:
        android = int(device.get("android_version"))
    except (TypeError, ValueError):
        android = 0
    if android < 12:
        errors.append("Android 12 or later is required by the pinned Akane route")
    version = kernel_version(device.get("kernel_release"))
    if version is None or version < (5, 10):
        errors.append("kernel 5.10 or later is required")
    if str(device.get("gki_generation")) != "2.0":
        errors.append("GKI generation must be 2.0")
    if device.get("abi") not in ALLOWED_ABIS:
        errors.append("ABI must be arm64-v8a or armeabi-v7a")

    lock_tools = lock.get("tools") if isinstance(lock.get("tools"), dict) else {}
    tools = plan.get("tools") if isinstance(plan.get("tools"), dict) else {}
    for name in ("akane-injector", "jdex2"):
        expected = lock_tools.get(name, {}).get("commit") if isinstance(lock_tools.get(name), dict) else None
        actual = tools.get(name, {}).get("commit") if isinstance(tools.get(name), dict) else None
        if not expected or actual != expected:
            errors.append(f"{name} commit must match tool-lock.json")

    adapter = plan.get("adapter") if isinstance(plan.get("adapter"), dict) else {}
    if adapter.get("mode") not in ALLOWED_MODES:
        errors.append("adapter mode is unsupported")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", str(adapter.get("source_fork_commit", ""))):
        errors.append("adapter source_fork_commit must be a 40-hex commit")
    package = str(adapter.get("package", ""))
    prefix = str(adapter.get("class_prefix", ""))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]+", package):
        errors.append("adapter package is invalid")
    if not prefix or prefix in {"*", "."} or not prefix.startswith(package.split(".")[0] + "."):
        errors.append("class_prefix must be narrow and related to the target package")
    output = str(adapter.get("output_dir", ""))
    if not output.startswith("/data/local/tmp/rev-kernel-dex/") or ".." in output:
        errors.append("output_dir must be an exact case path under /data/local/tmp/rev-kernel-dex/")

    license_review = plan.get("license_review") if isinstance(plan.get("license_review"), dict) else {}
    if license_review.get("redistribute") is not False:
        errors.append("pinned upstream sources have NOASSERTION licenses; redistribute must be false")
    if not str(license_review.get("basis", "")).strip():
        errors.append("license_review basis is required")

    concealment = plan.get("concealment") if isinstance(plan.get("concealment"), dict) else {}
    features = concealment.get("features") if isinstance(concealment.get("features"), list) else []
    unknown = sorted(set(features) - ALLOWED_CONCEALMENT)
    if unknown:
        errors.append(f"unsupported concealment features: {', '.join(unknown)}")
    if concealment.get("enabled") is True:
        if concealment.get("explicitly_authorized") is not True:
            errors.append("enabled concealment requires explicitly_authorized=true")
        if not features:
            errors.append("enabled concealment requires named minimal features")
        warnings.append("compare concealment against a clean control and record behavior differences")
    elif features:
        errors.append("concealment features must be empty when concealment is disabled")

    cleanup = plan.get("cleanup") if isinstance(plan.get("cleanup"), dict) else {}
    for key in ("unload_module", "remove_exact_output", "verify_no_device_node", "reboot_on_unproven_restore"):
        if cleanup.get(key) is not True:
            errors.append(f"cleanup.{key} must be true")

    return {
        "schema": "rev-kernel-dex-dumper/validation-v1",
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "compatibility": {
            "android_version": android,
            "kernel": list(version) if version else None,
            "gki_generation": device.get("gki_generation"),
            "abi": device.get("abi"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--tool-lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    try:
        report = validate(load_json(args.plan), load_json(args.tool_lock))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 1 if args.strict and not report["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
