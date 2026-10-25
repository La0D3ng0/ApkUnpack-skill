"""Rebuild an observed Bangcle fdex extraction variant from native prefix output.

This narrow adapter requires a page-aligned fdex container, a verified native
decryption cap, 0x14/0x17 decoy CodeItems, and unique ordered tail CodeItem
matches. It refuses a variant when any of those invariants fails.
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys


def parse_int(value):
    return int(value, 0)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("ULEB128 extends past DEX")
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if current < 0x80:
            return value, offset
    raise ValueError("ULEB128 is longer than five bytes")


def read_sleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("SLEB128 extends past DEX")
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if current < 0x80:
            bits = shift + 7
            if current & 0x40:
                value -= 1 << bits
            return value, offset
    raise ValueError("SLEB128 is longer than five bytes")


def encode_uleb_fixed(value, width):
    result = bytearray()
    for index in range(width):
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if index + 1 < width else 0))
    if value:
        raise ValueError("new code_off does not fit reserved ULEB128 width")
    return bytes(result)


def class_methods(data):
    class_count, class_off = struct.unpack_from("<II", data, 0x60)
    if class_off + 32 * class_count > len(data):
        raise ValueError("class_defs outside DEX")
    for class_index in range(class_count):
        offset = struct.unpack_from("<I", data, class_off + 32 * class_index + 24)[0]
        if not offset:
            continue
        counts = []
        for _ in range(4):
            value, offset = read_uleb(data, offset)
            counts.append(value)
        for count in counts[:2]:
            for _ in range(count):
                _, offset = read_uleb(data, offset)
                _, offset = read_uleb(data, offset)
        for count in counts[2:]:
            method_index = 0
            for _ in range(count):
                delta, offset = read_uleb(data, offset)
                method_index += delta
                _, offset = read_uleb(data, offset)
                field_at = offset
                code_off, offset = read_uleb(data, offset)
                yield class_index, method_index, code_off, field_at, offset


def is_decoy(body):
    return (
        len(body) >= 8
        and body[:2] == b"\x00\x00"
        and sum(bool(value) for value in body) <= 3
        and any(body[index] in (0x14, 0x17) for index in (2, 4, 6))
    )


def aligned_matches(data, needle, start, stop):
    while True:
        start = data.find(needle, start, stop)
        if start < 0:
            break
        if start % 4 == 0:
            yield start
        start += 1


def code_item_end(data, start, limit):
    if start + 16 > limit:
        raise ValueError("CodeItem header extends past tail")
    tries_size = struct.unpack_from("<H", data, start + 6)[0]
    insns_size = struct.unpack_from("<I", data, start + 12)[0]
    offset = start + 16 + 2 * insns_size
    if offset > limit:
        raise ValueError("CodeItem instructions extend past tail")
    if tries_size:
        offset += 2 * (insns_size & 1) + 8 * tries_size
        if offset > limit:
            raise ValueError("CodeItem try items extend past tail")
        handler_count, offset = read_uleb(data, offset)
        if handler_count > limit - offset:
            raise ValueError("CodeItem handler count exceeds tail")
        for _ in range(handler_count):
            typed_count, offset = read_sleb(data, offset)
            if abs(typed_count) > (limit - offset) // 2:
                raise ValueError("CodeItem typed handler count exceeds tail")
            for _ in range(abs(typed_count)):
                _, offset = read_uleb(data, offset)
                _, offset = read_uleb(data, offset)
            if typed_count <= 0:
                _, offset = read_uleb(data, offset)
            if offset > limit:
                raise ValueError("CodeItem handler extends past tail")
    aligned = (offset + 3) & ~3
    if aligned > limit:
        raise ValueError("CodeItem alignment extends past tail")
    return aligned


def walk_tail(data, decoys, first):
    positions = []
    position = first
    for decoy in decoys:
        if data[position:position + 16] != decoy["header"]:
            return None
        positions.append(position)
        try:
            position = code_item_end(data, position, len(data) - 4)
        except ValueError:
            return None
    return positions


def locate_segment(container, payload_offset, prefix, encrypted_cap):
    if (len(prefix) < 0x70 or len(prefix) % 16 or
            prefix[:8] not in (b"dex\n035\0", b"dex\n037\0",
                               b"dex\n038\0", b"dex\n039\0")):
        raise ValueError("native prefix must be block aligned and begin with a DEX header")
    file_size = struct.unpack_from("<I", prefix, 0x20)[0]
    if not len(prefix) <= file_size <= len(container):
        raise ValueError("invalid native DEX file_size")
    if len(prefix) != (min(file_size, encrypted_cap) & ~15):
        raise ValueError("native prefix length disagrees with verified encrypted cap")
    if struct.unpack_from("<I", prefix, 0x24)[0] != 0x70:
        raise ValueError("invalid DEX header_size")
    candidates = []
    marker = 0
    while True:
        marker = container.find(b"fdex", marker)
        if marker < 0:
            break
        start = marker + 4 - file_size
        if start >= payload_offset and (start - payload_offset) % 4096 == 0:
            candidates.append(start)
        marker += 4
    if len(candidates) != 1:
        raise ValueError(f"fdex segment is ambiguous: {len(candidates)} candidates")
    start = candidates[0]
    if container[start + file_size - 4:start + file_size] != b"fdex":
        raise ValueError("fdex trailer missing")
    return start, file_size


def rebuild_one(container, prefix, start, file_size):
    data = bytearray(container[start:start + file_size])
    data[:len(prefix)] = prefix
    data_end = sum(struct.unpack_from("<II", data, 0x68))
    if not 0x70 <= data_end <= len(data):
        raise ValueError("invalid DEX data range")

    decoys = []
    for class_index, method_index, old, field_at, field_end in class_methods(data):
        if not old or old >= data_end or old + 16 > len(data):
            continue
        insns_size = struct.unpack_from("<I", data, old + 12)[0]
        code_end = old + 16 + 2 * insns_size
        if code_end > len(data):
            raise ValueError(f"CodeItem at 0x{old:x} extends past DEX")
        if is_decoy(data[old + 16:code_end]):
            decoys.append({
                "class_def_index": class_index,
                "method_index": method_index,
                "old_code_off": old,
                "uleb_offset": field_at,
                "uleb_end": field_end,
                "insns_size": insns_size,
                "header": bytes(data[old:old + 16]),
            })
    decoys.sort(key=lambda row: row["old_code_off"])
    if len({row["old_code_off"] for row in decoys}) != len(decoys):
        raise ValueError("two extracted methods share an original CodeItem")

    if decoys:
        first_candidates = list(aligned_matches(data, decoys[0]["header"],
                                                data_end, len(data) - 4))
        solutions = [solution for first in first_candidates
                     if (solution := walk_tail(data, decoys, first)) is not None]
        if len(solutions) != 1:
            raise ValueError(f"tail mapping is ambiguous: {len(solutions)} complete solutions")
        for decoy, new in zip(decoys, solutions[0]):
            encoded = encode_uleb_fixed(new, decoy["uleb_end"] - decoy["uleb_offset"])
            data[decoy["uleb_offset"]:decoy["uleb_end"]] = encoded
            decoy["new_code_off"] = new
            decoy["codeitem_sha256"] = sha256(data[new:new + 16 + 2 * decoy["insns_size"]])
            del decoy["header"]
    final_tail_methods = sum(
        bool(code_off) and code_off >= data_end
        for _, _, code_off, _, _ in class_methods(data)
    )
    if final_tail_methods != len(decoys):
        raise ValueError(
            "method reconciliation failed: "
            f"{len(decoys)} extracted placeholders vs {final_tail_methods} "
            "final methods with code_off beyond data_end; check for already-patched "
            "class_data in the prefix or an unmatched extraction pattern"
        )
    return bytes(data), decoys, final_tail_methods


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", type=pathlib.Path, required=True,
                        help="unaltered APK classes.dex with the fdex overlay")
    parser.add_argument("--payload-offset", type=parse_int, required=True,
                        help="native parser's offset of dexdata0 payload in classes.dex")
    parser.add_argument("--encrypted-cap", type=parse_int, required=True,
                        help="block-aligned prefix cap verified from this sample's native decrypt path")
    parser.add_argument("--prefix", type=pathlib.Path, action="append", required=True,
                        help="native decryption output, in DEX order; repeat")
    parser.add_argument("--prefix-source", choices=("offline", "device"), default="offline",
                        help="device prefixes may contain already-patched class_data and miss placeholders")
    parser.add_argument("--diagnostic-only", action="store_true",
                        help="required with device prefixes; such output is not an offline deliverable")
    parser.add_argument("--truth", type=pathlib.Path, action="append",
                        help="optional real-device DEX of matching order, used only for verification")
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("output directory already exists")
    if args.encrypted_cap < 0x70 or args.encrypted_cap % 16:
        parser.error("--encrypted-cap must be at least a DEX header and block aligned")
    if args.truth and len(args.truth) != len(args.prefix):
        parser.error("--truth count must match --prefix count")
    if args.prefix_source == "device" and not args.diagnostic_only:
        parser.error("device prefixes are diagnostic only; pass --diagnostic-only, "
                     "or use --prefix-source offline for a deliverable")
    if args.prefix_source == "device":
        print("warning: device prefixes may already contain patched class_data; "
              "this cannot prove offline method recovery", file=sys.stderr)

    container = args.container.read_bytes()
    outputs = []
    previous_end = 0
    for index, prefix_path in enumerate(args.prefix):
        prefix = prefix_path.read_bytes()
        start, size = locate_segment(container, args.payload_offset, prefix,
                                     args.encrypted_cap)
        if start < previous_end:
            raise ValueError("fdex segments overlap or are out of order")
        previous_end = start + size
        rebuilt, methods, final_tail_methods = rebuild_one(container, prefix, start, size)
        row = {
            "dex": index + 1,
            "output_file": "classes.dex" if index == 0 else f"classes{index + 1}.dex",
            "source_offset": start,
            "file_size": size,
            "native_prefix_file": str(prefix_path.resolve()),
            "native_prefix_sha256": sha256(prefix),
            "native_prefix_bytes": len(prefix),
            "extracted_methods": len(methods),
            "final_tail_code_off_methods": final_tail_methods,
            "rebuilt_sha256": sha256(rebuilt),
        }
        if args.truth:
            truth = args.truth[index].read_bytes()
            row["device_truth_file"] = str(args.truth[index].resolve())
            row["device_truth_sha256"] = sha256(truth)
            row["byte_identical_to_device"] = rebuilt == truth
            if rebuilt != truth:
                raise ValueError(f"DEX {index + 1} differs from device truth")
        outputs.append((rebuilt, methods, row))

    args.output_dir.mkdir(parents=True)
    for index, (rebuilt, methods, row) in enumerate(outputs, 1):
        (args.output_dir / row["output_file"]).write_bytes(rebuilt)
        (args.output_dir / f"method-map-{index}.json").write_text(
            json.dumps(methods, indent=2), encoding="utf-8"
        )
    manifest = {
        "container": str(args.container.resolve()),
        "container_sha256": sha256(container),
        "payload_offset": args.payload_offset,
        "encrypted_cap": args.encrypted_cap,
        "prefix_source": args.prefix_source,
        "diagnostic_only": args.diagnostic_only,
        "deliverable_eligible": args.prefix_source == "offline" and not args.diagnostic_only,
        "dex_file_naming": "classes.dex, classes2.dex, ... (no classes1.dex)",
        "variant": "Bangcle fdex / verified encrypted prefix / ordered decoy CodeItems",
        "dex_files": [row for _, _, row in outputs],
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(json.dumps({"dex_count": len(outputs),
                      "extracted_methods": sum(len(methods) for _, methods, _ in outputs),
                      "manifest": str(args.output_dir / "manifest.json")}, indent=2))


if __name__ == "__main__":
    main()
