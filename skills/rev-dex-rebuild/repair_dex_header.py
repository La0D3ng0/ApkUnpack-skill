"""Create a separate DEX copy with SHA-1 and Adler-32 header fields repaired."""

import argparse
import hashlib
import json
import pathlib
import struct
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    source = args.input.read_bytes()
    if len(source) < 0x70 or source[:4] != b"dex\n":
        raise ValueError("input is not a complete standard DEX")
    if struct.unpack_from("<I", source, 0x20)[0] != len(source):
        raise ValueError("declared file_size differs from physical input length")
    if struct.unpack_from("<I", source, 0x24)[0] != 0x70:
        raise ValueError("unexpected DEX header_size")
    if struct.unpack_from("<I", source, 0x28)[0] != 0x12345678:
        raise ValueError("unexpected DEX endian tag")
    data = bytearray(source)
    data[0x0C:0x20] = hashlib.sha1(data[0x20:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[0x0C:]))
    if data[0x20:] != source[0x20:]:
        raise AssertionError("non-header bytes changed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(json.dumps({
        "source": str(args.input.resolve()),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "output": str(args.output.resolve()),
        "output_sha256": hashlib.sha256(data).hexdigest(),
        "changed_bytes": sum(a != b for a, b in zip(source, data)),
    }, indent=2))


if __name__ == "__main__":
    main()
