#!/usr/bin/env python3
"""Find a raw SM4 key across complete captured memory using a verified DEX block."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from contextlib import nullcontext
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import numpy as np
except ImportError as exc:
    raise SystemExit("numpy is required for vectorized key scanning") from exc

from decrypt_prefixes import checked_header, parse_int
from sm4_core import CK, FK, SBOX, decrypt_block, key_schedule


BOX = np.frombuffer(SBOX, dtype=np.uint8)
CAPTURE_NAMES = {"capture", "captures", "maps", "memory", "memregions",
                 "memory-captures", "memory-dumps"}
NON_MEMORY_SUFFIXES = {".apk", ".dex", ".jar", ".json", ".log", ".md", ".txt", ".zip"}
_MEMMAPS = {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rotl(word, bits: int):
    return (word << bits) | (word >> (32 - bits))


def tau(word):
    return (
        (BOX[(word >> 24) & 255].astype(np.uint32) << 24)
        | (BOX[(word >> 16) & 255].astype(np.uint32) << 16)
        | (BOX[(word >> 8) & 255].astype(np.uint32) << 8)
        | BOX[word & 255].astype(np.uint32)
    )


def candidate_indexes(memory, positions, cipher_words, expected_words):
    """Evaluate one SM4 decryption for every 16-byte memory window in parallel."""
    keys = []
    for word_index in range(4):
        at = positions + 4 * word_index
        word = (
            (memory[at].astype(np.uint32) << 24)
            | (memory[at + 1].astype(np.uint32) << 16)
            | (memory[at + 2].astype(np.uint32) << 8)
            | memory[at + 3].astype(np.uint32)
        )
        keys.append(word ^ np.uint32(FK[word_index]))
    round_keys = []
    k0, k1, k2, k3 = keys
    for constant in CK:
        transformed = tau(k1 ^ k2 ^ k3 ^ np.uint32(constant))
        nxt = k0 ^ transformed ^ rotl(transformed, 13) ^ rotl(transformed, 23)
        round_keys.append(nxt)
        k0, k1, k2, k3 = k1, k2, k3, nxt

    x0, x1, x2, x3 = (np.full(len(positions), word, dtype=np.uint32)
                      for word in cipher_words)
    for round_key in reversed(round_keys):
        transformed = tau(x1 ^ x2 ^ x3 ^ round_key)
        nxt = (x0 ^ transformed ^ rotl(transformed, 2) ^ rotl(transformed, 10)
               ^ rotl(transformed, 18) ^ rotl(transformed, 24))
        x0, x1, x2, x3 = x1, x2, x3, nxt
    return np.flatnonzero((x3 == expected_words[0]) & (x2 == expected_words[1]))


def parse_range(value: str) -> tuple[int, int]:
    try:
        start, end = value.split(":", 1)
        return parse_int(start), parse_int(end)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("range must be START:END") from exc


def default_capture_dirs(cwd: Path) -> list[Path]:
    """Use the current capture directory, or conventional capture children of a sample workdir."""
    if cwd.name.lower() in CAPTURE_NAMES:
        return [cwd]
    return sorted(path for path in cwd.iterdir()
                  if path.is_dir() and path.name.lower() in CAPTURE_NAMES)


def captured_files(roots: list[Path], excluded: set[Path]) -> list[Path]:
    found = set()
    for root in roots:
        for path in root.rglob("*"):
            if (not path.is_file() or path.is_symlink() or path.stat().st_size < 16
                    or path.suffix.lower() in NON_MEMORY_SUFFIXES):
                continue
            resolved = path.resolve()
            if resolved not in excluded:
                found.add(resolved)
    return sorted(found)


def maps_labels(roots: list[Path]) -> dict[tuple[int | None, int], str]:
    labels = {}
    for directory in {item for root in roots for item in (root, root.parent)}:
        for path in directory.glob("maps*.txt"):
            match = re.search(r"maps-(\d+)", path.stem)
            pid = int(match.group(1)) if match else None
            raw = path.read_bytes()
            encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
            for line in raw.decode(encoding, errors="replace").splitlines():
                columns = line.split(maxsplit=5)
                if len(columns) < 2 or not re.fullmatch(r"[0-9a-fA-F]+-[0-9a-fA-F]+", columns[0]):
                    continue
                start = int(columns[0].split("-", 1)[0], 16)
                labels[(pid, start)] = columns[5] if len(columns) > 5 else ""
    return labels


def capture_metadata(path: Path, labels: dict[tuple[int | None, int], str]) -> dict:
    sidecar = Path(str(path) + ".json")
    if not sidecar.is_file():
        return {"virtual_base": None, "map_name": None, "sidecar": None}
    try:
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        base = parse_int(record["start"]) if isinstance(record["start"], str) else int(record["start"])
        pid = int(record["pid"]) if record.get("pid") is not None else None
        declared_bytes = (parse_int(record["bytes"]) if isinstance(record["bytes"], str)
                          else int(record["bytes"]))
        if base < 0 or declared_bytes != path.stat().st_size:
            raise ValueError("capture bounds/length mismatch")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid capture sidecar for {path}: {exc}") from exc
    return {"virtual_base": base,
            "map_name": (record.get("map_name") or labels.get((pid, base))
                         or labels.get((None, base))),
            "sidecar": str(sidecar.resolve()),
            "sidecar_sha256": sha256_file(sidecar),
            "declared_sha256": record.get("sha256")}


def scan_task(task):
    """Scan a disjoint set of key start positions; reopen memory in each process."""
    region_index, filename, first, count, stride, chunk_windows, cipher, cipher_words, expected_words, known = task
    if filename not in _MEMMAPS:
        _MEMMAPS[filename] = np.memmap(filename, dtype=np.uint8, mode="r")
    memory = _MEMMAPS[filename]
    candidates_found = []
    completed = 0
    while completed < count:
        amount = min(chunk_windows, count - completed)
        positions = first + (completed + np.arange(amount, dtype=np.int64)) * stride
        candidates = candidate_indexes(memory, positions, cipher_words, expected_words)
        for item in candidates:
            offset = int(positions[item])
            key = bytes(memory[offset:offset + 16])
            if decrypt_block(cipher, key_schedule(key)).startswith(known):
                candidates_found.append((offset, key))
        completed += amount
    return region_index, count, candidates_found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--capture-dir", type=Path, action="append",
                        help="scan every captured file recursively; repeat for split capture roots")
    source.add_argument("--memory", type=Path, action="append",
                        help="explicit memory file for a bounded diagnostic scan; repeat as needed")
    parser.add_argument("--base", type=parse_int, action="append",
                        help="virtual base for each --memory file; repeat in matching order")
    parser.add_argument("--range", dest="ranges", type=parse_range, action="append",
                        help="file-offset START:END for each explicit --memory file")
    parser.add_argument("--container", type=Path, required=True)
    parser.add_argument("--cipher-offset", type=parse_int, required=True,
                        help="verified start offset of one encrypted DEX segment")
    parser.add_argument("--known-plaintext-hex", required=True,
                        help="at least 8 known bytes of that DEX header, e.g. its exact magic")
    parser.add_argument("--stride", type=int, default=1,
                        help="key-window stride; default 1 checks every byte")
    parser.add_argument("--chunk-windows", type=int, default=32768)
    parser.add_argument("--task-windows", type=int, default=1048576,
                        help="key windows per multiprocessing task")
    parser.add_argument("--workers", type=int, default=min(os.cpu_count() or 1, 4),
                        help="worker processes; default up to four CPUs")
    parser.add_argument("--key-output", type=Path, required=True,
                        help="new file for the unique 16-byte key; no key bytes are printed")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if (not args.container.is_file() or args.key_output.exists() or args.report.exists()
            or args.key_output.resolve() == args.report.resolve()):
        parser.error("require existing inputs and distinct new key/report paths")
    if min(args.stride, args.chunk_windows, args.task_windows, args.workers) < 1:
        parser.error("--stride, --chunk-windows, --task-windows, and --workers must be positive")
    if (args.base or args.ranges) and not args.memory:
        parser.error("--base and --range require explicit --memory files")
    if args.base and len(args.base) != len(args.memory):
        parser.error("--base count must equal --memory count")
    if args.ranges and len(args.ranges) != len(args.memory):
        parser.error("--range count must equal --memory count")
    try:
        known = bytes.fromhex(args.known_plaintext_hex)
    except ValueError as exc:
        parser.error(f"invalid --known-plaintext-hex: {exc}")
    if not 8 <= len(known) <= 16:
        parser.error("known plaintext must contain 8..16 bytes of the first DEX block")
    container = args.container.read_bytes()
    if args.cipher_offset < 0 or args.cipher_offset + 0x70 > len(container):
        parser.error("cipher offset must point to a complete encrypted DEX header")
    cipher = container[args.cipher_offset:args.cipher_offset + 16]
    cipher_words = [int.from_bytes(cipher[i:i + 4], "big") for i in range(0, 16, 4)]
    expected_words = [int.from_bytes(known[i:i + 4], "big") for i in (0, 4)]

    if args.memory:
        if any(not path.is_file() for path in args.memory):
            parser.error("all --memory paths must be existing files")
        paths = [path.resolve() for path in args.memory]
        capture_roots = []
        mode = "explicit-memory"
    else:
        roots = args.capture_dir or default_capture_dirs(Path.cwd())
        if not roots or any(not root.is_dir() for root in roots):
            parser.error("no complete capture directory found; run from its sample workdir "
                         "or pass --capture-dir")
        capture_roots = [root.resolve() for root in roots]
        excluded = {args.container.resolve(), args.key_output.resolve(), args.report.resolve()}
        paths = captured_files(capture_roots, excluded)
        mode = "complete-capture"
        if not paths:
            parser.error("no captured memory files found under the capture directory")

    labels = maps_labels(capture_roots or [path.parent for path in paths])
    metadata = {path: capture_metadata(path, labels) for path in paths}
    if mode == "complete-capture":
        # The label comes from the captured maps/sidecar when the filename is only an address.
        def scan_priority(path: Path):
            label = ((metadata[path]["map_name"] or "") + str(path)).lower()
            return (0 if "scudo:primary" in label else 1 if "scudo" in label else 2,
                    str(path).lower())
        paths.sort(key=scan_priority)

    started = time.monotonic()
    hits = []
    distinct_keys = {}
    windows_tested = 0
    memory_rows = []
    tasks = []
    for index, path in enumerate(paths):
        size = path.stat().st_size
        meta = metadata[path]
        base = args.base[index] if args.base else meta["virtual_base"]
        start, end = args.ranges[index] if args.ranges else (0, size)
        if (base is not None and base < 0) or not 0 <= start < end <= size:
            parser.error(f"invalid base/range for {path}")
        count = max(0, (end - 16 - start) // args.stride + 1)
        for first_index in range(0, count, args.task_windows):
            amount = min(args.task_windows, count - first_index)
            tasks.append((index, str(path), start + first_index * args.stride, amount,
                          args.stride, args.chunk_windows, cipher, cipher_words, expected_words, known))
        digest = sha256_file(path)
        if meta.get("declared_sha256") and digest != meta["declared_sha256"]:
            raise ValueError(f"capture sidecar SHA-256 mismatch: {path}")
        memory_rows.append({"file": str(path.resolve()), "sha256": digest,
                            "bytes": size, "virtual_base": base,
                            "map_name": meta["map_name"], "sidecar": meta["sidecar"],
                            "sidecar_sha256": meta.get("sidecar_sha256"),
                            "scan_start": start, "scan_end": end,
                            "windows_tested": count})
    total_windows = sum(row["windows_tested"] for row in memory_rows)
    if total_windows == 0:
        parser.error("captured files contain no complete 16-byte key windows")
    total_mib = sum(row["scan_end"] - row["scan_start"] for row in memory_rows) / (1024 * 1024)
    print(f"Scanning {len(paths)} files / {total_mib:.1f} MiB with {args.workers} workers. "
          "Reference: 185 MiB took about 90 min on one worker in one run; "
          "actual time varies and multiprocessing is not linear.", file=sys.stderr, flush=True)
    next_progress = 0.1
    with (ProcessPoolExecutor(max_workers=args.workers) if args.workers > 1
          else nullcontext()) as executor:
        results = executor.map(scan_task, tasks) if executor else map(scan_task, tasks)
        for region_index, completed, candidates in results:
            windows_tested += completed
            for offset, key in candidates:
                round_keys = key_schedule(key)
                header = checked_header(container, args.cipher_offset, round_keys)
                if header is None:
                    continue
                key_digest = hashlib.sha256(key).hexdigest()
                distinct_keys[key_digest] = key
                base = memory_rows[region_index]["virtual_base"]
                hits.append({"memory_index": region_index, "file_offset": offset,
                             "virtual_address": base + offset if base is not None else None,
                             "key_sha256": key_digest, "dex_file_size": header["file_size"]})
                print(f"Validated candidate in {memory_rows[region_index]['file']} "
                      f"at file offset 0x{offset:x}; continuing complete scan",
                      file=sys.stderr, flush=True)
            fraction = windows_tested / total_windows
            if fraction >= next_progress:
                elapsed = time.monotonic() - started
                remaining = elapsed * (1 - fraction) / fraction
                print(f"Scan {fraction:.0%}: {elapsed/60:.1f} min elapsed, "
                      f"~{remaining/60:.1f} min remaining at current rate",
                      file=sys.stderr, flush=True)
                next_progress += 0.1

    report = {
        "schema": "rev-gen2-extracted-dex-unpack/sm4-key-scan-v2",
        "input_mode": mode,
        "capture_roots": [str(root) for root in capture_roots],
        "container": str(args.container.resolve()),
        "container_sha256": hashlib.sha256(container).hexdigest(),
        "cipher_offset": args.cipher_offset,
        "known_plaintext_hex": known.hex(),
        "cipher_model": "SM4-ECB first DEX block; full DEX header and fdex trailer validated",
        "numpy_version": np.__version__,
        "stride": args.stride,
        "workers": args.workers,
        "chunk_windows": args.chunk_windows,
        "task_windows": args.task_windows,
        "memory_regions": memory_rows,
        "windows_tested": windows_tested,
        "hits": hits,
        "distinct_key_count": len(distinct_keys),
        "duration_seconds": round(time.monotonic() - started, 3),
        "key_file": str(args.key_output.resolve()) if len(distinct_keys) == 1 else None,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if len(distinct_keys) == 1:
        args.key_output.parent.mkdir(parents=True, exist_ok=True)
        args.key_output.write_bytes(next(iter(distinct_keys.values())))
    print(json.dumps({"windows_tested": windows_tested,
                      "distinct_key_count": len(distinct_keys),
                      "report": str(args.report.resolve())}))
    return 0 if len(distinct_keys) == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
