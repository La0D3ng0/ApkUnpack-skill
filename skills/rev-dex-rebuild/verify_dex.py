#!/usr/bin/env python3
"""Validate core DEX header integrity, section bounds, signature, and checksum."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


SECTION_WIDTHS = {
    "string_ids": 4,
    "type_ids": 4,
    "proto_ids": 12,
    "field_ids": 8,
    "method_ids": 8,
    "class_defs": 32,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("dex", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data = args.dex.read_bytes()
    errors: list[str] = []
    report: dict[str, object] = {
        "schema": "rev-dex-rebuild/dex-validation-v1",
        "path": str(args.dex.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "actual_file_size": len(data),
    }
    if len(data) < 0x70:
        errors.append("file is shorter than the 0x70-byte DEX header")
    else:
        magic = data[:8]
        version = magic[4:7].decode("ascii", errors="replace")
        if not (magic.startswith(b"dex\n") and magic[7] == 0 and version.isdigit()):
            errors.append(f"invalid DEX magic: {magic!r}")
        values = struct.unpack_from("<26I", data, 8)
        checksum = values[0]
        file_size = values[6]
        header_size = values[7]
        endian_tag = values[8]
        map_off = values[11]
        section_values = values[12:]
        report.update({
            "dex_version": version,
            "declared_file_size": file_size,
            "header_size": header_size,
            "endian_tag": f"0x{endian_tag:08x}",
            "map_off": f"0x{map_off:x}",
        })
        if file_size != len(data):
            errors.append(f"declared file_size {file_size} does not equal actual size {len(data)}")
        if header_size != 0x70:
            errors.append(f"header_size must be 0x70, got 0x{header_size:x}")
        if endian_tag != 0x12345678:
            errors.append(f"unsupported endian_tag 0x{endian_tag:08x}")

        declared_signature = data[12:32]
        computed_signature = hashlib.sha1(data[32:]).digest()
        declared_checksum = checksum
        computed_checksum = zlib.adler32(data[12:]) & 0xFFFFFFFF
        report.update({
            "declared_signature_sha1": declared_signature.hex(),
            "computed_signature_sha1": computed_signature.hex(),
            "declared_adler32": f"0x{declared_checksum:08x}",
            "computed_adler32": f"0x{computed_checksum:08x}",
        })
        if declared_signature != computed_signature:
            errors.append("DEX SHA-1 signature mismatch")
        if declared_checksum != computed_checksum:
            errors.append("DEX Adler-32 checksum mismatch")

        names = list(SECTION_WIDTHS) + ["data"]
        sections = {}
        for index, name in enumerate(names):
            size = section_values[index * 2]
            offset = section_values[index * 2 + 1]
            width = SECTION_WIDTHS.get(name)
            end = offset + size * width if width is not None else offset + size
            sections[name] = {"size": size, "offset": f"0x{offset:x}", "end": f"0x{end:x}"}
            if size == 0 and offset != 0:
                errors.append(f"{name}: zero size with nonzero offset")
            if size != 0 and (offset < header_size or end > len(data) or end < offset):
                errors.append(f"{name}: section range is outside the file")
        report["sections"] = sections

        map_items = []
        if map_off == 0 or map_off + 4 > len(data):
            errors.append("map_off is missing or outside the file")
        else:
            map_size = struct.unpack_from("<I", data, map_off)[0]
            map_end = map_off + 4 + map_size * 12
            if map_end > len(data):
                errors.append("map_list extends beyond the file")
            else:
                seen_types: set[int] = set()
                for index in range(map_size):
                    item_type, unused, size, offset = struct.unpack_from("<HHII", data, map_off + 4 + index * 12)
                    if item_type in seen_types:
                        errors.append(f"map_list contains duplicate type 0x{item_type:04x}")
                    seen_types.add(item_type)
                    if unused != 0:
                        errors.append(f"map item 0x{item_type:04x} has nonzero unused field")
                    if size and offset >= len(data):
                        errors.append(f"map item 0x{item_type:04x} offset is outside the file")
                    map_items.append({
                        "type": f"0x{item_type:04x}", "size": size, "offset": f"0x{offset:x}"
                    })
        report["map_items"] = map_items

    report["valid"] = not errors
    report["errors"] = errors
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
