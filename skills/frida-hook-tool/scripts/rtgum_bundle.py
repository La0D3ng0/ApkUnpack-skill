#!/usr/bin/env python3
"""Verify and stage the bundled rt-gum ARM64 build, then invoke its ctl."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifest.json"
BIN = ROOT / "bin"


def load_manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def verify(manifest):
    expected = manifest["files"]
    if set(manifest["device_files"]) != set(expected) - {"rtgum-manager-debug.apk"}:
        raise RuntimeError("Device file list and bundle manifest differ")
    actual = {p.name for p in BIN.iterdir() if p.is_file()}
    if actual != set(expected):
        raise RuntimeError(f"Bundle file set differs: missing={sorted(set(expected)-actual)}, extra={sorted(actual-set(expected))}")
    for name, record in expected.items():
        path = BIN / name
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if len(content) != record["bytes"] or digest != record["sha256"]:
            raise RuntimeError(f"Hash or size mismatch: {name}")
        if name.endswith(".apk"):
            if not zipfile.is_zipfile(path):
                raise RuntimeError(f"Invalid APK: {name}")
            with zipfile.ZipFile(path) as apk:
                if "classes.dex" not in apk.namelist() or "lib/arm64-v8a/libmako-ghost.so" not in apk.namelist():
                    raise RuntimeError(f"Manager APK lacks DEX or Mako: {name}")
        else:
            if content[:4] != b"\x7fELF" or content[4:6] != b"\x02\x01":
                raise RuntimeError(f"Not a little-endian ELF64 image: {name}")
            elf_type, machine = struct.unpack_from("<HH", content, 16)
            if machine != 183 or elf_type != (1 if name.endswith(".kpm") else 3):
                raise RuntimeError(f"Wrong ARM64 ELF type: {name}")
    print(f"bundle PASS files={len(expected)} build={manifest['build_id']}")


def adb_command(args, *parts, input_text=None, capture=False, check=True):
    command = [args.adb]
    if args.serial:
        command += ["-s", args.serial]
    command += list(parts)
    return subprocess.run(command, input=input_text, text=True, check=check,
                          capture_output=capture)


def device_profile(args, manifest):
    expected = manifest["device_profile"]
    queries = {
        "product": ("shell", "getprop", "ro.product.device"),
        "abi": ("shell", "getprop", "ro.product.cpu.abi"),
        "sdk": ("shell", "getprop", "ro.build.version.sdk"),
        "kernel": ("shell", "uname", "-r"),
    }
    for label, query in queries.items():
        actual = adb_command(args, *query, capture=True).stdout.strip()
        if actual != expected[label]:
            raise RuntimeError(f"Device {label} mismatch: expected {expected[label]!r}, got {actual!r}; rebuild and validate for this device")
        print(f"{label}={actual}")
    print("device profile PASS")


def remote_dir(manifest):
    return manifest["remote_dir"]


def device_hash(args, path):
    output = adb_command(args, "shell", "sha256sum", path, capture=True).stdout.strip()
    match = re.match(r"^([0-9a-fA-F]{64})\s+", output)
    if not match:
        raise RuntimeError(f"Cannot parse device SHA-256 for {path}")
    return match.group(1).lower()


def stage(args, manifest):
    verify(manifest)
    device_profile(args, manifest)
    destination = remote_dir(manifest)
    adb_command(args, "shell", "mkdir", "-p", destination)
    for name in manifest["device_files"]:
        remote = f"{destination}/{name}"
        exists = adb_command(args, "shell", "test", "-f", remote, check=False).returncode == 0
        if exists:
            remote_hash = device_hash(args, remote)
            if remote_hash != manifest["files"][name]["sha256"] and not args.replace:
                raise RuntimeError(f"Existing device file differs: {remote}; stop active hooks and pass stage --replace")
    for name in manifest["device_files"]:
        remote = f"{destination}/{name}"
        remote_hash = ""
        if adb_command(args, "shell", "test", "-f", remote, check=False).returncode == 0:
            remote_hash = device_hash(args, remote)
        if remote_hash != manifest["files"][name]["sha256"]:
            adb_command(args, "push", str(BIN / name), remote, capture=True)
        permission = "0700" if name == "rtgum-stage1-ctl" else "0644"
        adb_command(args, "shell", "chmod", permission, remote)
        remote_hash = device_hash(args, remote)
        if remote_hash != manifest["files"][name]["sha256"]:
            raise RuntimeError(f"Device SHA-256 mismatch: {name}")
        print(f"staged {name}")
    print(f"stage PASS dir={destination}; KPM was not loaded")


def read_secret(path, pattern, label):
    value = Path(path).read_text(encoding="ascii").strip()
    if not re.fullmatch(pattern, value):
        raise RuntimeError(f"Invalid {label} file format")
    return value


def superkey_file(args):
    path = args.superkey_file or os.environ.get("RTGUM_SUPERKEY_FILE")
    if not path:
        raise RuntimeError(
            "缺少 SuperKey 文件：请提供 --superkey-file <路径> 或设置 "
            "RTGUM_SUPERKEY_FILE；ready、dmesg 和 load 均需要此密钥。"
            "若不知道路径，请向设备所有者索取；不要改用 frida-server。"
        )
    if not Path(path).is_file():
        raise RuntimeError(f"SuperKey 文件不存在：{path}；请核对路径或向设备所有者索取")
    return path


def invoke_ctl(args, manifest, command, capture=False):
    key = read_secret(superkey_file(args), r"[A-Za-z0-9._-]+", "SuperKey")
    device_profile(args, manifest)
    destination = remote_dir(manifest)
    ctl = f"{destination}/rtgum-stage1-ctl"
    adb_command(args, "shell", "test", "-x", ctl)
    env_lines = [f"export RTGUM_SUPERKEY={shlex.quote(key)}"]
    if getattr(args, "session_key_file", None):
        session = read_secret(args.session_key_file, r"[0-9a-f]{64}", "session key")
        env_lines.append(f"export RTGUM_SESSION_KEY={shlex.quote(session)}")
    script = "\n".join(env_lines + ["exec " + " ".join(shlex.quote(item) for item in [ctl, *command])]) + "\n"
    return adb_command(args, "shell", "sh", "-s", input_text=script, capture=capture)


def pair(args, manifest):
    if not re.fullmatch(r"[0-9]{6}", args.code):
        raise RuntimeError("Pairing code must contain six digits")
    try:
        result = invoke_ctl(args, manifest, ["session-pair", args.code], capture=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError("Session pairing failed; inspect KPM status and pairing code") from error
    match = re.search(r"(?m)^ok session=([0-9a-f]{64}) mode=debug one_time=1\s*$", result.stdout)
    if not match:
        raise RuntimeError("Session pairing returned an unexpected response")
    output = Path(args.session_out).resolve()
    if ROOT == output or ROOT in output.parents:
        raise RuntimeError("Store the session key outside the Skill directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(match.group(1))
    print(f"pair PASS session_file={output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="ADB executable")
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"), help="ADB device serial")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("verify", help="check hashes, architectures, and Manager APK contents")
    sub.add_parser("device", help="read-only comparison with the validated device profile")
    staging = sub.add_parser("stage", help="push and hash-check device files without loading the KPM")
    staging.add_argument("--replace", action="store_true", help="replace differing files after stopping active hooks")
    ctl = sub.add_parser("ctl", help="run the bundled rtgum-stage1-ctl on the staged device")
    ctl.add_argument("--superkey-file", help="SuperKey file (or RTGUM_SUPERKEY_FILE)")
    ctl.add_argument("--session-key-file")
    ctl.add_argument("command", nargs="+", help="ctl command and its arguments")
    pairing = sub.add_parser("pair", help="consume a one-time debug pairing code")
    pairing.add_argument("--superkey-file", help="SuperKey file (or RTGUM_SUPERKEY_FILE)")
    pairing.add_argument("--code", required=True)
    pairing.add_argument("--session-out", required=True)
    args = parser.parse_args()
    manifest = load_manifest()
    if args.action == "verify":
        verify(manifest)
    elif args.action == "device":
        device_profile(args, manifest)
    elif args.action == "stage":
        stage(args, manifest)
    elif args.action == "pair":
        pair(args, manifest)
    else:
        if args.command[0] == "session-pair":
            raise RuntimeError("Use the pair subcommand so the session key is not printed")
        invoke_ctl(args, manifest, args.command)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
