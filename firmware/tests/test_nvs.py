#!/usr/bin/env python3
"""Protect receiver settings while adding one OTA credential offline."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "provision_ota", ROOT / "provision-ota-key.py"
)
OTA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OTA)


class NvsPreservationTests(unittest.TestCase):
    def setUp(self):
        self.values = {
            ("config", "node_id"): ("uint8_t", 2),
            ("config", "signed"): ("int32_t", -12345),
            ("config", "large"): ("uint64_t", (1 << 64) - 1),
            ("config", "label"): ("string", ' A, "test"\nvalue '),
            ("config", "empty"): ("string", ""),
            ("config", "multi_page"): ("blob", bytes(range(256)) * 24),
            ("nvs.net80211", "sta.ssid"): ("blob", b"fixture-network"),
            ("nvs.net80211", "sta.pswd"): ("blob", b"fixture-only"),
            ("nvs.net80211", "sta.apinfo"): ("blob", b"A" * 700),
            ("nvs.net80211", "sta.apsw"): ("blob", b"\x03\x02"),
        }
        self.raw = OTA.generate(self.values, 0x6000)

    def test_roundtrip_preserves_wifi_cache_and_multpage_blob(self):
        self.assertEqual(OTA.logical_values(self.raw), self.values)
        result, count = OTA.prepare(self.raw, "ab" * 32)
        expected = dict(self.values)
        expected[("security", "ota_psk")] = ("string", "ab" * 32)
        self.assertEqual(OTA.logical_values(result), expected)
        self.assertEqual(count, len(self.values))
        self.assertEqual(len(result), len(self.raw))

    def test_existing_key_is_not_rotated(self):
        first, _ = OTA.prepare(self.raw, "ab" * 32)
        with self.assertRaisesRegex(ValueError, "already exists"):
            OTA.prepare(first, "cd" * 32)

    def test_corruption_is_rejected_before_generation(self):
        raw = bytearray(self.raw)
        raw[28] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC mismatch"):
            OTA.prepare(bytes(raw), "ab" * 32)

    def test_wrong_partition_size_or_weak_key_is_rejected(self):
        for raw, key in [(self.raw[:-4096], "ab" * 32), (self.raw, "short")]:
            with self.assertRaises(ValueError):
                OTA.prepare(raw, key)


if __name__ == "__main__":
    unittest.main()
