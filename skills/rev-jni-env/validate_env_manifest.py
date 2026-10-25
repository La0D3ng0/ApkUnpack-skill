#!/usr/bin/env python3
"""Validate a rev-jni-env environment manifest and its completion gates."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


SCHEMA = "rev-jni-env/v1"
KINDS = {
    "jni_method", "jni_field", "jni_object", "file", "property", "syscall",
    "service", "entropy", "network", "library", "other",
}
STATUSES = {"captured", "modeled", "proxied", "pending", "unsupported"}
PROVENANCE = {"static", "device_trace", "captured_fixture", "platform_contract", "assumption"}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args()


def require_object(value: object, path: str, errors: list[str]) -> dict:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return {}
    return value


def require_string(obj: dict, key: str, path: str, errors: list[str]) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}.{key} must be a non-empty string")
        return ""
    return value


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value))


def validate(data: object) -> dict:
    errors: list[str] = []
    gaps: list[str] = []
    root = require_object(data, "$", errors)
    if root.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}")

    target = require_object(root.get("target"), "target", errors)
    for key in ("apk_sha256", "module_sha256"):
        value = require_string(target, key, "target", errors)
        if value and not is_sha256(value):
            errors.append(f"target.{key} must be a 64-character SHA-256")
    for key in ("module", "abi", "process_name", "entrypoint"):
        require_string(target, key, "target", errors)
    if not isinstance(target.get("android_api"), int) or target.get("android_api", 0) <= 0:
        errors.append("target.android_api must be a positive integer")

    toolchain = require_object(root.get("toolchain"), "toolchain", errors)
    for key in ("unidbg", "jdk", "backend", "host_os"):
        require_string(toolchain, key, "toolchain", errors)

    dependencies = root.get("dependencies")
    if not isinstance(dependencies, list):
        errors.append("dependencies must be an array")
        dependencies = []
    seen_ids: set[str] = set()
    status_counts: defaultdict[str, int] = defaultdict(int)
    for index, raw in enumerate(dependencies):
        path = f"dependencies[{index}]"
        dep = require_object(raw, path, errors)
        dep_id = require_string(dep, "id", path, errors)
        if dep_id in seen_ids:
            errors.append(f"{path}.id is duplicated: {dep_id}")
        seen_ids.add(dep_id)
        kind = dep.get("kind")
        status = dep.get("status")
        name = require_string(dep, "name", path, errors)
        if kind not in KINDS:
            errors.append(f"{path}.kind is unsupported: {kind!r}")
        if status not in STATUSES:
            errors.append(f"{path}.status is unsupported: {status!r}")
        else:
            status_counts[status] += 1
        if any(token in name for token in ("*", ".*", "<any>")):
            errors.append(f"{path}.name contains catch-all scope: {name!r}")
        if not isinstance(dep.get("required"), bool):
            errors.append(f"{path}.required must be boolean")
        if not isinstance(dep.get("deterministic"), bool):
            errors.append(f"{path}.deterministic must be boolean")
        provenance = require_object(dep.get("provenance"), f"{path}.provenance", errors)
        provenance_type = provenance.get("type")
        if provenance_type not in PROVENANCE:
            errors.append(f"{path}.provenance.type is unsupported: {provenance_type!r}")
        artifact = provenance.get("artifact")
        if artifact is not None and (not isinstance(artifact, str) or not artifact.strip()):
            errors.append(f"{path}.provenance.artifact must be a non-empty string")
        if artifact is not None and not is_sha256(provenance.get("sha256")):
            errors.append(f"{path}.provenance.sha256 is required for an artifact")
        if not isinstance(dep.get("behavior"), dict):
            errors.append(f"{path}.behavior must be an object")

        if dep.get("required"):
            if status in {"pending", "unsupported"}:
                gaps.append(f"{dep_id}: required dependency is {status}")
            if dep.get("deterministic") is not True:
                gaps.append(f"{dep_id}: required dependency is not deterministic")
            if provenance_type == "assumption":
                gaps.append(f"{dep_id}: required dependency has assumption-only provenance")

    controls = require_object(root.get("controls"), "controls", errors)
    for key in ("time", "random", "filesystem", "network"):
        require_string(controls, key, "controls", errors)

    runs = root.get("baseline_runs")
    if not isinstance(runs, list):
        errors.append("baseline_runs must be an array")
        runs = []
    replay_groups: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    for index, raw in enumerate(runs):
        path = f"baseline_runs[{index}]"
        run = require_object(raw, path, errors)
        run_id = require_string(run, "run_id", path, errors)
        hashes = []
        for key in ("input_sha256", "output_sha256", "normalized_trace_sha256"):
            value = require_string(run, key, path, errors)
            if value and not is_sha256(value):
                errors.append(f"{path}.{key} must be a SHA-256")
            hashes.append(value.lower())
        if run.get("status") == "returned" and all(hashes):
            replay_groups[tuple(hashes)].add(run_id)
    deterministic_pairs = [key for key, ids in replay_groups.items() if len(ids) >= 2]
    if not deterministic_pairs:
        gaps.append("no two returned baseline runs have identical input/output/trace hashes")

    unresolved = root.get("unresolved")
    if not isinstance(unresolved, list):
        errors.append("unresolved must be an array")
        unresolved = []
    if unresolved:
        gaps.append(f"{len(unresolved)} unresolved environment item(s) remain")

    return {
        "schema": "rev-jni-env/validation-v1",
        "valid": not errors,
        "complete": not errors and not gaps,
        "dependency_count": len(dependencies),
        "dependency_status_counts": dict(sorted(status_counts.items())),
        "baseline_run_count": len(runs),
        "deterministic_replay_pair_count": len(deterministic_pairs),
        "structural_errors": errors,
        "completion_gaps": gaps,
    }


def main() -> int:
    args = parse_args()
    data = json.loads(args.manifest.read_text(encoding="utf-8"))
    report = validate(data)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if not report["valid"]:
        return 2
    if args.strict and not report["complete"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
