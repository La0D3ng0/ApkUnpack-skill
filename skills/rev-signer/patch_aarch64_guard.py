#!/usr/bin/env python3
"""Apply an exact, preimage-checked patch to an AArch64 ELF copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
PT_LOAD = 1
EM_AARCH64 = 183


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_hex(value: str, label: str) -> bytes:
    compact = value.replace(" ", "").replace(":", "")
    if not compact or len(compact) % 2:
        raise ValueError(f"{label} must contain a non-empty even number of hex digits")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hexadecimal") from exc


def virtual_address_to_offset(data: bytes, virtual_address: int, size: int) -> int:
    if len(data) < ELF_HEADER.size:
        raise ValueError("input is smaller than an ELF64 header")
    header = ELF_HEADER.unpack_from(data)
    ident = header[0]
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise ValueError("input must be a little-endian ELF64 file")
    if header[2] != EM_AARCH64:
        raise ValueError(f"input machine is {header[2]}, expected AArch64 ({EM_AARCH64})")

    program_offset = header[5]
    program_entry_size = header[9]
    program_count = header[10]
    if program_entry_size < PROGRAM_HEADER.size:
        raise ValueError("ELF program-header entry is too small")
    if program_offset + program_entry_size * program_count > len(data):
        raise ValueError("ELF program-header table exceeds the input size")

    matches: list[int] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        program = PROGRAM_HEADER.unpack_from(data, offset)
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = program
        relative = virtual_address - p_vaddr
        if p_type == PT_LOAD and 0 <= relative and relative + size <= p_filesz:
            file_offset = p_offset + relative
            if file_offset + size <= len(data):
                matches.append(file_offset)
    if len(matches) != 1:
        raise ValueError(
            f"virtual address {virtual_address:#x} maps to {len(matches)} file ranges"
        )
    return matches[0]


def patch_file(
    input_path: Path,
    output_path: Path,
    virtual_address: int,
    expected: bytes,
    replacement: bytes,
) -> dict[str, object]:
    if input_path.resolve() == output_path.resolve():
        raise ValueError("output must not overwrite the input")
    if output_path.exists():
        raise ValueError(f"output already exists: {output_path}")
    if len(expected) != len(replacement):
        raise ValueError("expected and replacement byte strings must have equal length")

    data = bytearray(input_path.read_bytes())
    file_offset = virtual_address_to_offset(data, virtual_address, len(expected))
    actual = bytes(data[file_offset : file_offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"preimage mismatch at {virtual_address:#x}: expected {expected.hex()}, "
            f"found {actual.hex()}"
        )
    data[file_offset : file_offset + len(expected)] = replacement

    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, output_path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    return {
        "schema": "rev-signer/native-guard-patch/v1",
        "input": str(input_path.resolve()),
        "input_sha256": sha256(input_path),
        "output": str(output_path.resolve()),
        "output_sha256": sha256(output_path),
        "machine": "AArch64",
        "virtual_address": f"0x{virtual_address:x}",
        "file_offset": f"0x{file_offset:x}",
        "expected_hex": expected.hex(),
        "replacement_hex": replacement.hex(),
        "changed_bytes": len(expected),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vaddr", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--expect-hex", required=True)
    parser.add_argument("--replace-hex", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    expected = parse_hex(args.expect_hex, "--expect-hex")
    replacement = parse_hex(args.replace_hex, "--replace-hex")
    report = patch_file(args.input, args.output, args.vaddr, expected, replacement)
    rendered = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.report:
        if args.report.resolve() in {args.input.resolve(), args.output.resolve()}:
            raise ValueError("report must not overwrite the input or output")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
