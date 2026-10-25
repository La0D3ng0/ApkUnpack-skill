#!/usr/bin/env python3
"""Align, sign, and verify an APK without exposing password values."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--ks-pass-env", required=True)
    parser.add_argument("--key-pass-env", required=True)
    parser.add_argument("--zipalign", required=True)
    parser.add_argument("--apksigner", required=True)
    parser.add_argument("--page-size-kb", type=int, choices=(4, 16, 64), default=16)
    parser.add_argument("--min-sdk-version", type=int)
    parser.add_argument(
        "--identity-policy", choices=("lab", "organization-test", "release-update"),
        default="lab",
    )
    parser.add_argument("--expected-cert-sha256")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_tool(value: str) -> str:
    candidate = Path(value)
    if candidate.is_file():
        return str(candidate.resolve())
    resolved = shutil.which(value)
    if resolved:
        return str(Path(resolved).resolve())
    raise SystemExit(f"tool does not exist and is not on PATH: {value}")


def normalize_certificate_digest(value: str) -> str:
    normalized = value.replace(":", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError(f"invalid certificate SHA-256 digest: {value!r}")
    return normalized


def redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def run(command: list[str], secrets: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        message = redact(result.stdout + result.stderr, secrets)
        raise RuntimeError(f"command failed ({result.returncode}): {command[0]}\n{message}")
    return result


def command_plan(args: argparse.Namespace, zipalign: str, apksigner: str,
                 source: Path, keystore: Path, aligned: str, signed: str) -> dict[str, list[str]]:
    align = [
        zipalign, "-P", str(args.page_size_kb), "-f", "-v", "4", str(source), aligned
    ]
    sign = [apksigner, "sign"]
    if args.min_sdk_version is not None:
        sign.extend(["--min-sdk-version", str(args.min_sdk_version)])
    sign.extend([
        "--ks", str(keystore), "--ks-key-alias", args.alias,
        "--ks-pass", f"env:{args.ks_pass_env}", "--key-pass", f"env:{args.key_pass_env}",
        "--out", signed, aligned,
    ])
    verify = [apksigner, "verify", "--verbose", "--print-certs"]
    if args.min_sdk_version is not None:
        verify.extend(["--min-sdk-version", str(args.min_sdk_version)])
    verify.append(signed)
    align_check = [
        zipalign, "-c", "-P", str(args.page_size_kb), "-v", "4", signed
    ]
    return {"align": align, "sign": sign, "verify": verify, "align_check": align_check}


def main() -> int:
    args = parse_args()
    source = args.input.resolve()
    output = args.output.resolve()
    keystore = args.keystore.resolve()
    report_path = args.report.resolve() if args.report else None
    for path, label in ((source, "input APK"), (keystore, "keystore")):
        if not path.is_file():
            raise SystemExit(f"{label} does not exist: {path}")
    if source == output:
        raise SystemExit("output must not overwrite the input APK")
    if output.exists():
        raise SystemExit(f"output already exists: {output}")
    if report_path and report_path.exists():
        raise SystemExit(f"report already exists: {report_path}")
    if not args.alias.strip():
        raise SystemExit("alias must not be empty")
    expected_certificate = None
    if args.expected_cert_sha256:
        try:
            expected_certificate = normalize_certificate_digest(args.expected_cert_sha256)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    if args.identity_policy == "release-update" and expected_certificate is None:
        raise SystemExit("release-update policy requires --expected-cert-sha256")
    for value, label in ((args.ks_pass_env, "ks-pass-env"), (args.key_pass_env, "key-pass-env")):
        if not value.replace("_", "a").isalnum() or value[0].isdigit():
            raise SystemExit(f"{label} is not a safe environment variable name: {value!r}")

    zipalign = resolve_tool(args.zipalign)
    apksigner = resolve_tool(args.apksigner)
    source_hash = digest(source)
    output.parent.mkdir(parents=True, exist_ok=True)

    plan = {
        "schema": "rev-signer/report-v1",
        "status": "dry_run" if args.dry_run else "pending",
        "input_apk": str(source),
        "input_apk_sha256": source_hash,
        "output_apk": str(output),
        "keystore": str(keystore),
        "keystore_sha256": digest(keystore),
        "key_alias": args.alias,
        "ks_password_source": f"env:{args.ks_pass_env}",
        "key_password_source": f"env:{args.key_pass_env}",
        "zipalign": zipalign,
        "apksigner": apksigner,
        "page_size_kb": args.page_size_kb,
        "min_sdk_version": args.min_sdk_version,
        "identity_policy": args.identity_policy,
        "expected_certificate_sha256": expected_certificate,
    }
    if args.dry_run:
        plan["commands"] = command_plan(
            args, zipalign, apksigner, source, keystore, "<temp>/aligned.apk", "<temp>/signed.apk"
        )
        plan["tool_versions"] = "not executed in dry-run"
        rendered = json.dumps(plan, indent=2) + "\n"
        if report_path:
            report_path.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0

    secrets = []
    for variable in (args.ks_pass_env, args.key_pass_env):
        secret = os.environ.get(variable)
        if not secret:
            raise SystemExit(f"required password environment variable is unset: {variable}")
        secrets.append(secret)

    apksigner_version = run([apksigner, "version"], secrets)
    zipalign_help = subprocess.run(
        [zipalign, "-h"], text=True, capture_output=True, check=False
    )

    with tempfile.TemporaryDirectory(prefix=output.name + ".", dir=output.parent) as temp_dir:
        temp_root = Path(temp_dir)
        aligned = temp_root / "aligned.apk"
        signed = temp_root / "signed.apk"
        commands = command_plan(
            args, zipalign, apksigner, source, keystore, str(aligned), str(signed)
        )
        align_result = run(commands["align"], secrets)
        sign_result = run(commands["sign"], secrets)
        verify_result = run(commands["verify"], secrets)
        align_check_result = run(commands["align_check"], secrets)
        verify_text = redact(verify_result.stdout + verify_result.stderr, secrets)
        certificate_digests = sorted({
            normalize_certificate_digest(value)
            for value in re.findall(
                r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", verify_text,
                flags=re.IGNORECASE,
            )
        })
        if not certificate_digests:
            raise RuntimeError("apksigner verification did not report a certificate SHA-256 digest")
        if expected_certificate is not None and expected_certificate not in certificate_digests:
            raise RuntimeError(
                "verified signer certificate does not match --expected-cert-sha256"
            )
        shutil.move(str(signed), output)

    if digest(source) != source_hash:
        raise SystemExit("input APK changed during signing")
    plan.update({
        "status": "verified",
        "output_apk_sha256": digest(output),
        "verified_certificate_sha256": certificate_digests,
        "certificate_identity_matches": (
            None if expected_certificate is None else expected_certificate in certificate_digests
        ),
        "commands": commands,
        "tool_versions": {
            "apksigner": redact(apksigner_version.stdout + apksigner_version.stderr, secrets).strip(),
            "zipalign_help": redact(
                zipalign_help.stdout + zipalign_help.stderr, secrets
            ).strip()[:4096],
        },
        "tool_output": {
            "align": redact(align_result.stdout + align_result.stderr, secrets),
            "sign": redact(sign_result.stdout + sign_result.stderr, secrets),
            "verify": verify_text,
            "align_check": redact(align_check_result.stdout + align_check_result.stderr, secrets),
        },
    })
    rendered = json.dumps(plan, indent=2) + "\n"
    if report_path:
        report_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
