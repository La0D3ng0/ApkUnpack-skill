"""Regression tests for family-independent unpacking route selection."""

import importlib.util
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path


DETECTOR = Path(__file__).with_name("detect_apk_shell.py")
spec = importlib.util.spec_from_file_location("detect_apk_shell", DETECTOR)
detector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector)


def dex(*, class_count=0, content=b"", overlay=b""):
    body = bytearray(0x200)
    body[:8] = b"dex\n035\0"
    struct.pack_into("<I", body, 0x24, 0x70)
    struct.pack_into("<I", body, 0x28, 0x12345678)
    struct.pack_into("<I", body, 0x60, class_count)
    struct.pack_into("<II", body, 0x68, 0x100, 0x100)
    body[0x70:0x70 + len(content)] = content
    body.extend(overlay)
    struct.pack_into("<I", body, 0x20, len(body))
    return body


def redacted_fdex_layout(*, data_end, marker, total_size, interior_markers):
    """Only a DEX header and synthetic marker positions; no protected APK bytes."""
    body = bytearray(total_size)
    body[:8] = b"dex\n035\0"
    struct.pack_into("<I", body, 0x20, total_size)
    struct.pack_into("<I", body, 0x24, 0x70)
    struct.pack_into("<I", body, 0x28, 0x12345678)
    struct.pack_into("<I", body, 0x60, 40)
    struct.pack_into("<II", body, 0x68, data_end - 0x100, 0x100)
    body[marker:marker + 8] = b"dexdata0"
    for position in interior_markers:
        body[position:position + 4] = b"fdex"
    body[-4:] = b"fdex"
    return body


class RoutingTests(unittest.TestCase):
    def classify(self, dex_bytes, extra=None):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", dex_bytes)
                archive.writestr("AndroidManifest.xml", b"manifest")
                for name, value in (extra or {}).items():
                    archive.writestr(name, value)
            return detector.detect_apk_shell(apk, apkid_mode="off")

    def test_fdex_routes_to_extracted_method_skill(self):
        overlay = b"\x00" * 12 + b"dexdata0" + b"\x00" * 65536 + b"fdex" + b"\x00" * 4096 + b"fdex"
        report = self.classify(dex(overlay=overlay),
                               {"lib/arm64-v8a/libDexHelper.so": b"native"})
        self.assertEqual(report["shell"]["family_id"], "bangcle-secneo")
        self.assertEqual(report["shell"]["variant"], "fdex-overlay")
        self.assertEqual(report["routing"]["next_skill"], "rev-gen2-extracted-dex-unpack")
        self.assertEqual(report["container_layout"]["fdex_trailer_count"], 1)

    def test_stub_loader_routes_to_whole_dex_dump(self):
        body = dex(content=b"Ldalvik/system/DexClassLoader; Ljava/lang/System; loadLibrary")
        report = self.classify(body, {
            "lib/arm64-v8a/libsample.so": b"native", "assets/payload.dat": os.urandom(128 * 1024)
        })
        self.assertEqual(report["shell"]["variant"], "stub-loader")
        self.assertEqual(report["routing"]["next_skill"], "rev-dex-dumper")

    def test_known_family_alone_does_not_choose_generation(self):
        report = self.classify(dex(class_count=100),
                               {"lib/arm64-v8a/libDexHelper.so": b"native"})
        self.assertEqual(report["status"], "known_shell")
        self.assertEqual(report["shell"]["variant"], "unknown")
        self.assertIsNone(report["routing"]["next_skill"])

    def test_unidentified_overlay_is_not_assumed_first_generation(self):
        body = dex(overlay=os.urandom(80 * 1024))
        report = self.classify(body, {"lib/arm64-v8a/libDexHelper.so": b"native"})
        self.assertEqual(report["status"], "known_shell")
        self.assertEqual(report["shell"]["variant"], "unknown")
        self.assertIsNone(report["routing"]["next_skill"])

    def test_opaque_overlay_with_stub_loader_favors_dump_probe(self):
        body = dex(content=b"Ldalvik/system/DexClassLoader;",
                   overlay=os.urandom(80 * 1024))
        report = self.classify(body, {"lib/arm64-v8a/libjiagu.so": b"native"})
        self.assertEqual(report["shell"]["variant"], "stub-loader")
        self.assertEqual(report["shell"]["generation"], "first-generation-candidate")
        self.assertEqual(report["routing"]["next_skill"], "rev-dex-dumper")

    def test_redacted_041_layout_shape(self):
        body = redacted_fdex_layout(
            data_end=0xFC64, marker=0xFC70, total_size=0x30000,
            interior_markers=(0x12000, 0x14000, 0x16000, 0x18000,
                              0x1A000, 0x1C000, 0x1E000, 0x22000),
        )
        report = self.classify(body, {"lib/arm64-v8a/libDexHelper.so": b"native"})
        layout = report["container_layout"]
        self.assertEqual(layout["dexdata0_offset"], 0xFC70)
        self.assertEqual(layout["fdex_marker_count"], 9)
        self.assertEqual(layout["fdex_trailer_count"], 8)
        self.assertEqual(report["routing"]["next_skill"], "rev-gen2-extracted-dex-unpack")

    def test_redacted_039_layout_shape(self):
        body = redacted_fdex_layout(
            data_end=0x4448, marker=0x4454, total_size=0x20000,
            interior_markers=(0x6000, 0x9000, 0xC000, 0x12000),
        )
        report = self.classify(body, {"lib/arm64-v8a/libDexHelper.so": b"native"})
        layout = report["container_layout"]
        self.assertEqual(layout["dexdata0_offset"], 0x4454)
        self.assertEqual(layout["fdex_marker_count"], 5)
        self.assertEqual(layout["fdex_trailer_count"], 4)

    def test_dexdata0_can_start_beyond_first_256_overlay_bytes(self):
        body = redacted_fdex_layout(
            data_end=0x1000, marker=0x1200, total_size=0x20000,
            interior_markers=(0x1800,),
        )
        report = self.classify(body)
        self.assertEqual(report["container_layout"]["dexdata0_offset"], 0x1200)
        self.assertEqual(report["shell"]["variant"], "fdex-overlay")


if __name__ == "__main__":
    unittest.main()
