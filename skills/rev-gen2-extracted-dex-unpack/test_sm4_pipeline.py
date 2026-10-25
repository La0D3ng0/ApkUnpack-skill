"""Self-contained crypto and CLI regression checks; no sample keys or APK bytes."""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sm4_core import crypt_block, decrypt_block, key_schedule


ROOT = Path(__file__).resolve().parent
KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")  # published SM4 test vector
SEGMENTS = ((0x1000, 0x200, 35), (0x2000, 0xB5, 42))
ENCRYPTED_CAP = 0x100


def make_dex(file_size: int, version: int) -> bytes:
    dex = bytearray(file_size)
    dex[:8] = f"dex\n{version:03d}\0".encode("ascii")
    struct.pack_into("<III", dex, 0x20, file_size, 0x70, 0x12345678)
    struct.pack_into("<II", dex, 0x68, file_size - 0x70, 0x70)
    for position in range(0x70, file_size - 4):
        dex[position] = (position * 13 + version) & 0xFF
    # One visible class_data item with a two-byte code_off ULEB in the prefix.
    struct.pack_into("<II", dex, 0x60, 1, 0x70)
    struct.pack_into("<I", dex, 0x70 + 24, 0x94)
    dex[0x94:0x9C] = bytes((0, 0, 1, 0, 1, 1, 0x80, 0x01))
    dex[-4:] = b"fdex"
    return bytes(dex)


def fixture(directory: Path) -> list[bytes]:
    container = bytearray(0x3000)
    plaintexts = []
    round_keys = key_schedule(KEY)
    for index, (offset, size, version) in enumerate(SEGMENTS, 1):
        dex = make_dex(size, version)
        plaintexts.append(dex)
        container[offset:offset + size] = dex
        cap = min(size, ENCRYPTED_CAP) & ~15
        for position in range(0, cap, 16):
            block = dex[position:position + 16]
            container[offset + position:offset + position + 16] = crypt_block(block, round_keys)
        (directory / f"truth-{index}.bin").write_bytes(dex[:cap])
    (directory / "container.dex").write_bytes(container)
    (directory / "key.bin").write_bytes(KEY)
    (directory / "wrong-key.bin").write_bytes(bytes(16))
    (directory / "evidence.json").write_text(
        json.dumps({"fixture": "synthetic SM4-ECB; independently constructed plaintexts"}),
        encoding="utf-8",
    )
    return plaintexts


def decrypt_command(directory: Path, output: str = "prefixes") -> list[str]:
    return [
        sys.executable, str(ROOT / "decrypt_prefixes.py"),
        "--container", str(directory / "container.dex"),
        "--key-file", str(directory / "key.bin"),
        "--encrypted-cap", hex(ENCRYPTED_CAP),
        "--output-dir", str(directory / output),
    ]


class Sm4PipelineTests(unittest.TestCase):
    def test_public_sm4_block_vector(self):
        cipher = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        self.assertEqual(crypt_block(KEY, key_schedule(KEY)), cipher)
        self.assertEqual(decrypt_block(cipher, key_schedule(KEY)), KEY)

    def test_raw_key_scan_crosses_batch_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plaintexts = fixture(directory)
            memory = bytearray(os.urandom(1024))
            memory[31:47] = KEY
            (directory / "memory.bin").write_bytes(memory)
            scan = [
                sys.executable, str(ROOT / "sm4_key_scan.py"),
                "--memory", str(directory / "memory.bin"),
                "--container", str(directory / "container.dex"),
                "--cipher-offset", hex(SEGMENTS[0][0]),
                "--known-plaintext-hex", plaintexts[0][:8].hex(),
                "--chunk-windows", "32",
                "--workers", "1",
                "--key-output", str(directory / "found-key.bin"),
                "--report", str(directory / "scan.json"),
            ]
            result = subprocess.run(scan, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((directory / "found-key.bin").read_bytes(), KEY)
            report = json.loads((directory / "scan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["hits"][0]["file_offset"], 31)

    def test_default_full_capture_discovers_scudo_and_uses_two_workers(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plaintexts = fixture(directory)
            captures = directory / "memregions"
            captures.mkdir()
            helper = os.urandom(257)
            memory = bytearray(os.urandom(301))
            memory[115:131] = KEY
            for name, data, base in (("rw-70501a4000.bin", helper, 0x70501A4000),
                                     ("rw-72bad22000.bin", memory, 0x72BAD22000)):
                path = captures / name
                path.write_bytes(data)
                Path(str(path) + ".json").write_text(json.dumps({
                    "start": base, "bytes": len(data), "pid": 12158,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }), encoding="utf-8")
            (directory / "maps-12158.txt").write_text(
                "70501a4000-70501a5000 rw-p 00000000 00:00 0 libDexHelper.so\n"
                "72bad22000-72bad23000 rw-p 00000000 00:00 0 [anon:scudo:primary]\n",
                encoding="utf-16",
            )
            command = [sys.executable, str(ROOT / "sm4_key_scan.py"),
                       "--container", str(directory / "container.dex"),
                       "--cipher-offset", hex(SEGMENTS[0][0]),
                       "--known-plaintext-hex", plaintexts[0][:8].hex(),
                       "--chunk-windows", "32", "--task-windows", "79", "--workers", "2",
                       "--key-output", str(directory / "found-key.bin"),
                       "--report", str(directory / "scan.json")]
            result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((directory / "found-key.bin").read_bytes(), KEY)
            report = json.loads((directory / "scan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["input_mode"], "complete-capture")
            self.assertEqual(report["workers"], 2)
            self.assertEqual(len(report["memory_regions"]), 2)
            self.assertIn("scudo", report["memory_regions"][0]["map_name"])
            self.assertEqual(report["windows_tested"], (301 - 15) + (257 - 15))
            self.assertEqual(report["hits"][0]["file_offset"], 115)
            self.assertEqual(report["hits"][0]["virtual_address"], 0x72BAD22000 + 115)

    def test_capture_sidecar_hash_mismatch_fails_before_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plaintexts = fixture(directory)
            captures = directory / "captures"
            captures.mkdir()
            path = captures / "rw.bin"
            path.write_bytes(os.urandom(64))
            Path(str(path) + ".json").write_text(json.dumps({
                "start": 0x1000, "bytes": 64, "sha256": "0" * 64,
            }), encoding="utf-8")
            result = subprocess.run([
                sys.executable, str(ROOT / "sm4_key_scan.py"),
                "--container", str(directory / "container.dex"),
                "--cipher-offset", hex(SEGMENTS[0][0]),
                "--known-plaintext-hex", plaintexts[0][:8].hex(),
                "--workers", "1", "--key-output", str(directory / "found-key.bin"),
                "--report", str(directory / "scan.json"),
            ], cwd=directory, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("sidecar SHA-256 mismatch", result.stderr)
            self.assertFalse((directory / "found-key.bin").exists())

    def test_discover_two_segments_and_short_fdex_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plaintexts = fixture(directory)
            command = decrypt_command(directory) + [
                "--discover", "--payload-offset", hex(SEGMENTS[0][0]),
                "--alignment", "0x1000", "--expected-segments", "2",
                "--evidence-file", str(directory / "evidence.json"),
            ]
            for index in range(1, 3):
                command += ["--truth-prefix", str(directory / f"truth-{index}.bin")]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((directory / "prefixes" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "rev-gen2-extracted-dex-unpack/sm4-prefixes-v2")
            self.assertIn("caller_claim", manifest)
            self.assertNotIn("cipher_provenance", manifest)
            self.assertEqual(manifest["evidence_file"], str((directory / "evidence.json").resolve()))
            self.assertEqual(manifest["evidence_sha256"], hashlib.sha256(
                (directory / "evidence.json").read_bytes()).hexdigest())
            self.assertEqual([row["encrypted_prefix_bytes"] for row in manifest["segments"]],
                             [0x100, 0xB0])
            self.assertTrue(all(row["independent_prefix_match"] for row in manifest["segments"]))
            for index, dex in enumerate(plaintexts, 1):
                self.assertEqual((directory / "prefixes" / f"prefix-{index}.bin").read_bytes(),
                                 dex[:0x100 if index == 1 else 0xB0])

    def test_expected_segment_count_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fixture(directory)
            result = subprocess.run(decrypt_command(directory) + [
                "--discover", "--payload-offset", "0x1000", "--alignment", "0x1000",
                "--expected-segments", "3",
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("found 2 segments; expected 3", result.stderr)
            self.assertFalse((directory / "prefixes").exists())

    def test_missing_fdex_trailer_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fixture(directory)
            container = bytearray((directory / "container.dex").read_bytes())
            offset, size, _ = SEGMENTS[1]
            container[offset + size - 4:offset + size] = b"nope"
            (directory / "container.dex").write_bytes(container)
            result = subprocess.run(decrypt_command(directory) + [
                "--segment-offset", hex(offset),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no valid decrypted DEX header/trailer", result.stderr)
            self.assertFalse((directory / "prefixes").exists())

    def test_wrong_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fixture(directory)
            command = decrypt_command(directory) + ["--segment-offset", hex(SEGMENTS[0][0])]
            command[command.index(str(directory / "key.bin"))] = str(directory / "wrong-key.bin")
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no valid decrypted DEX header/trailer", result.stderr)
            self.assertFalse((directory / "prefixes").exists())

    def test_truth_prefix_allows_only_equal_width_class_data_code_off_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plaintexts = fixture(directory)
            truth = bytearray(plaintexts[0])
            truth[0x9A:0x9C] = bytes((0xC0, 0x01))
            (directory / "device.dex").write_bytes(truth)  # full DEX is also accepted
            result = subprocess.run(decrypt_command(directory) + [
                "--segment-offset", hex(SEGMENTS[0][0]),
                "--truth-prefix", str(directory / "device.dex"),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((directory / "prefixes" / "manifest.json").read_text(encoding="utf-8"))
            row = manifest["segments"][0]
            self.assertEqual(row["independent_prefix_status"], "class_data_code_off_rewrite")
            self.assertFalse(row["independent_prefix_match"])
            self.assertEqual(row["independent_prefix_diagnostic"]["changed_fields"], 1)
            self.assertEqual((directory / "prefixes" / "prefix-1.bin").read_bytes(),
                             plaintexts[0][:ENCRYPTED_CAP])

    def test_truth_prefix_rejects_unexplained_and_changed_width_differences(self):
        for offset, replacement in ((0xA0, b"\x33"), (0x9A, b"\x7f\x00")):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                plaintexts = fixture(directory)
                truth = bytearray(plaintexts[0][:ENCRYPTED_CAP])
                truth[offset:offset + len(replacement)] = replacement
                (directory / "truth.bin").write_bytes(truth)
                result = subprocess.run(decrypt_command(directory) + [
                    "--segment-offset", hex(SEGMENTS[0][0]),
                    "--truth-prefix", str(directory / "truth.bin"),
                ], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside proven equal-width", result.stderr)
                self.assertFalse((directory / "prefixes").exists())


if __name__ == "__main__":
    unittest.main()
