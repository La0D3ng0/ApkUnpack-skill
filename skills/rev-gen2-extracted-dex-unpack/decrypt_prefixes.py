#!/usr/bin/env python3
"""Decrypt verified SM4-ECB DEX prefixes from an fdex container."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from sm4_core import decrypt_ecb, key_schedule


HEADER_BYTES = 0x70


def is_dex_magic(magic: bytes) -> bool:
    """Accept the DEX magic shape without pinning a tested version list."""
    return (len(magic) == 8 and magic[:4] == b"dex\n"
            and all(48 <= byte <= 57 for byte in magic[4:7])
            and magic[7] == 0)


def parse_int(value: str) -> int:
    return int(value, 0)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("ULEB128 crosses the available prefix")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("ULEB128 exceeds five bytes")


def code_off_spans(prefix: bytes) -> dict[tuple[int, int], int]:
    """Locate only code_off ULEBs provable from class_defs within this prefix."""
    if len(prefix) < HEADER_BYTES or not is_dex_magic(prefix[:8]):
        return {}
    class_count, class_off = struct.unpack_from("<II", prefix, 0x60)
    data_size, data_off = struct.unpack_from("<II", prefix, 0x68)
    if class_off < HEADER_BYTES or class_off >= len(prefix):
        return {}
    visible_classes = min(class_count, (len(prefix) - class_off) // 32)
    spans = {}
    for class_index in range(visible_classes):
        offset = struct.unpack_from("<I", prefix, class_off + 32 * class_index + 24)[0]
        if not data_off <= offset < min(len(prefix), data_off + data_size):
            continue
        try:
            counts = []
            for _ in range(4):
                count, offset = read_uleb(prefix, offset)
                counts.append(count)
            # Incomplete or implausible data cannot justify accepting a difference.
            if sum(counts) > len(prefix) - offset:
                continue
            for _ in range(counts[0] + counts[1]):
                _, offset = read_uleb(prefix, offset)
                _, offset = read_uleb(prefix, offset)
            for _ in range(counts[2] + counts[3]):
                _, offset = read_uleb(prefix, offset)  # method_idx_diff
                _, offset = read_uleb(prefix, offset)  # access_flags
                start = offset
                value, offset = read_uleb(prefix, offset)
                spans[(start, offset)] = value
        except ValueError:
            # A class_data item can end beyond the encrypted prefix. Retain only
            # fully decoded fields; all other differing bytes remain unclassified.
            continue
    return spans


def class_data_rewrite_diagnostic(offline: bytes, truth: bytes) -> dict | None:
    """Accept only equal-width code_off edits, with every differing byte accounted for."""
    if len(offline) != len(truth):
        return None
    differences = [index for index, (left, right) in enumerate(zip(offline, truth))
                   if left != right]
    if not differences:
        return None
    offline_spans = code_off_spans(offline)
    truth_spans = code_off_spans(truth)
    covered = bytearray(len(offline))
    changes = []
    for span, old_value in offline_spans.items():
        if span not in truth_spans or offline[span[0]:span[1]] == truth[span[0]:span[1]]:
            continue
        new_value = truth_spans[span]
        if old_value == new_value:
            continue
        for offset in range(*span):
            covered[offset] = 1
        changes.append({"offset": span[0], "width": span[1] - span[0],
                        "offline_code_off": old_value, "device_code_off": new_value})
    if not changes or any(not covered[offset] for offset in differences):
        return None
    return {"kind": "equal_width_class_data_code_off_rewrite",
            "changed_fields": len(changes), "different_bytes": len(differences),
            "first_difference": differences[0], "last_difference": differences[-1],
            "examples": changes[:16]}


def checked_header(container: bytes, offset: int, round_keys: tuple[int, ...]) -> dict | None:
    if offset < 0 or offset + HEADER_BYTES > len(container):
        return None
    plain = decrypt_ecb(container[offset:offset + HEADER_BYTES], round_keys)
    if not is_dex_magic(plain[:8]):
        return None
    file_size, header_size, endian_tag = struct.unpack_from("<III", plain, 0x20)
    data_size, data_off = struct.unpack_from("<II", plain, 0x68)
    if (header_size != HEADER_BYTES or endian_tag != 0x12345678
            or file_size < HEADER_BYTES or offset + file_size > len(container)
            or data_off + data_size > file_size
            or container[offset + file_size - 4:offset + file_size] != b"fdex"):
        return None
    return {
        "offset": offset,
        "file_size": file_size,
        "dex_magic": plain[:8].decode("ascii", errors="replace").rstrip("\0"),
        "data_off": data_off,
        "data_size": data_size,
        "fdex_trailer_offset": offset + file_size - 4,
    }


def discover_segments(
    container: bytes, round_keys: tuple[int, ...], payload_offset: int, alignment: int
) -> list[dict]:
    if payload_offset < 0 or alignment < 16 or alignment & (alignment - 1):
        raise ValueError("payload offset must be nonnegative and alignment a power of two >= 16")
    found = []
    for offset in range(payload_offset, len(container) - HEADER_BYTES + 1, alignment):
        first = decrypt_ecb(container[offset:offset + 16], round_keys)
        if not is_dex_magic(first[:8]):
            continue
        row = checked_header(container, offset, round_keys)
        if row is not None:
            found.append(row)
    if not found:
        raise ValueError("no validated DEX segments found at the supplied payload/alignment")
    found.sort(key=lambda row: row["offset"])
    for previous, current in zip(found, found[1:]):
        if previous["offset"] + previous["file_size"] > current["offset"]:
            raise ValueError("validated DEX segments overlap")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", type=Path, required=True,
                        help="unmodified APK classes.dex or equivalent fdex container")
    parser.add_argument("--key-file", type=Path, required=True,
                        help="binary file containing the verified 16-byte key; never pass key on CLI")
    parser.add_argument("--key-offset", type=parse_int, default=0,
                        help="byte offset of a 16-byte key inside --key-file")
    parser.add_argument("--encrypted-cap", type=parse_int, required=True,
                        help="per-DEX encrypted prefix cap verified from the native path")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--segment-offset", type=parse_int, action="append",
                        help="verified DEX start in container; repeat in DEX order")
    source.add_argument("--discover", action="store_true",
                        help="search DEX starts on the supplied payload/alignment grid")
    parser.add_argument("--payload-offset", type=parse_int,
                        help="native-verified payload offset; required with --discover")
    parser.add_argument("--alignment", type=parse_int,
                        help="native-verified segment alignment; required with --discover")
    parser.add_argument("--expected-segments", type=int,
                        help="expected count from an independent parser or checked container layout")
    parser.add_argument("--truth-prefix", type=Path, action="append",
                        help="independent device prefix/DEX for comparison; only proven same-width class_data code_off edits may differ")
    parser.add_argument("--evidence-file", type=Path,
                        help="optional existing experiment record; linked and hashed, not interpreted as proof")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if args.output_dir.exists() or not args.container.is_file() or not args.key_file.is_file():
        parser.error("require existing container/key files and a new output directory")
    if args.evidence_file is not None and not args.evidence_file.is_file():
        parser.error("--evidence-file must name an existing file")
    if args.encrypted_cap < HEADER_BYTES or args.encrypted_cap % 16:
        parser.error("--encrypted-cap must be block-aligned and at least one DEX header")
    if args.discover and (args.payload_offset is None or args.alignment is None):
        parser.error("--discover requires both --payload-offset and --alignment")
    if not args.discover and (args.payload_offset is not None or args.alignment is not None):
        parser.error("--payload-offset/--alignment apply only to --discover")
    source_key = args.key_file.read_bytes()
    if args.key_offset < 0 or args.key_offset + 16 > len(source_key):
        parser.error("--key-offset must select 16 bytes inside --key-file")
    key = source_key[args.key_offset:args.key_offset + 16]
    round_keys = key_schedule(key)
    container = args.container.read_bytes()

    if args.discover:
        segments = discover_segments(container, round_keys, args.payload_offset, args.alignment)
    else:
        offsets = args.segment_offset
        if len(set(offsets)) != len(offsets) or offsets != sorted(offsets):
            parser.error("--segment-offset values must be unique and in ascending DEX order")
        segments = []
        for offset in offsets:
            row = checked_header(container, offset, round_keys)
            if row is None:
                raise ValueError(f"no valid decrypted DEX header/trailer at 0x{offset:x}")
            segments.append(row)
    if args.expected_segments is not None and len(segments) != args.expected_segments:
        raise ValueError(f"found {len(segments)} segments; expected {args.expected_segments}")
    if args.truth_prefix and len(args.truth_prefix) != len(segments):
        parser.error("--truth-prefix count must match the discovered segment count")

    outputs = []
    for index, row in enumerate(segments, 1):
        cap = min(row["file_size"], args.encrypted_cap) & ~15
        if cap < HEADER_BYTES:
            raise ValueError(f"segment {index} cannot hold a complete encrypted DEX header")
        cipher = container[row["offset"]:row["offset"] + cap]
        plain = decrypt_ecb(cipher, round_keys)
        if not is_dex_magic(plain[:8]):
            raise ValueError(f"segment {index} prefix does not begin with DEX magic")
        record = dict(row)
        record.update({
            "dex": index,
            "encrypted_prefix_bytes": cap,
            "cipher_prefix_sha256": sha256(cipher),
            "plaintext_prefix_sha256": sha256(plain),
            "prefix_file": f"prefix-{index}.bin",
        })
        if args.truth_prefix:
            truth_file = args.truth_prefix[index - 1].read_bytes()
            if len(truth_file) < len(plain):
                raise ValueError(f"segment {index} independent prefix is shorter than the offline prefix")
            expected = truth_file[:len(plain)]
            record["independent_prefix_match"] = expected == plain
            record["independent_prefix_sha256"] = sha256(expected)
            record["independent_truth_file_sha256"] = sha256(truth_file)
            if expected == plain:
                record["independent_prefix_status"] = "identical"
            else:
                diagnostic = class_data_rewrite_diagnostic(plain, expected)
                if diagnostic is None:
                    first = next(i for i, (a, b) in enumerate(zip(plain, expected)) if a != b)
                    raise ValueError(f"segment {index} differs from independent prefix at "
                                     f"0x{first:x} outside proven equal-width class_data code_off edits")
                record["independent_prefix_status"] = "class_data_code_off_rewrite"
                record["independent_prefix_diagnostic"] = diagnostic
                print(f"segment {index}: device prefix differs only in "
                      f"{diagnostic['changed_fields']} equal-width class_data code_off fields; "
                      "continuing with offline plaintext", file=sys.stderr)
        outputs.append((plain, record))

    args.output_dir.mkdir(parents=True)
    for plain, row in outputs:
        (args.output_dir / row["prefix_file"]).write_bytes(plain)
    manifest = {
        "schema": "rev-gen2-extracted-dex-unpack/sm4-prefixes-v2",
        "cipher": "SM4-ECB, raw 16-byte blocks, no padding",
        "caller_claim": "The supplied key, offsets, and encrypted cap model SM4-ECB for this sample; this script does not establish the native algorithm or mode.",
        "evidence_file": str(args.evidence_file.resolve()) if args.evidence_file else None,
        "evidence_sha256": sha256(args.evidence_file.read_bytes()) if args.evidence_file else None,
        "container": str(args.container.resolve()),
        "container_sha256": sha256(container),
        "key_file": str(args.key_file.resolve()),
        "key_source_sha256": sha256(source_key),
        "key_offset": args.key_offset,
        "key_sha256": sha256(key),
        "encrypted_cap": args.encrypted_cap,
        "segment_discovery": (
            {"payload_offset": args.payload_offset, "alignment": args.alignment}
            if args.discover else "explicit offsets"
        ),
        "segments": [row for _, row in outputs],
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"segments": len(outputs), "manifest": str(args.output_dir / "manifest.json")},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
