"""Offline recovery and fleet binding tests; never opens a serial port."""

import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "fleet_lib_test", Path(__file__).resolve().parents[1] / "fleetlib.py"
)
fleet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet)


def load_installer():
    path = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "fleet_backup_test", path / "backup.py"
    )
    backup = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"fleetlib": fleet}):
        spec.loader.exec_module(backup)
    spec = importlib.util.spec_from_file_location(
        "fleet_install_test", path / "install.py"
    )
    installer = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"fleetlib": fleet, "backup": backup}):
        spec.loader.exec_module(installer)
    return installer


installer = load_installer()


def table(entries):
    raw = b"".join(
        struct.pack("<HBBII16sI", 0x50AA, kind, sub, offset, size, name.encode(), 0)
        for name, kind, sub, offset, size in entries
    )
    raw += b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(raw).digest()
    return raw.ljust(0x1000, b"\xff")


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads(
            (fleet.ROOT / "tests/fixtures/site/nodes.json").read_text()
        )
        self.identity = {
            "fleet_ipv4_network": str(
                ipaddress.IPv4Interface(
                    self.inventory["nodes"][0]["ip"] + "/24"
                ).network
            ),
            "fleet_first_host": 120,
            "policy": {"fleet_size": 10},
        }
        self.mac = "02:aa:bb:00:00:02"
        self.entries = [
            ("nvs", 1, 2, 0x9000, 0x6000),
            ("otadata", 1, 0, 0xF000, 0x2000),
            ("ota_0", 0, 0x10, 0x20000, 0x200000),
            ("ota_1", 0, 0x11, 0x220000, 0x200000),
        ]

    def test_verified_partition_table_and_immutable_ranges(self):
        layout = fleet.parse_partitions(table(self.entries), 16 * 1024 * 1024, 0x8000)
        self.assertTrue(layout["md5_verified"])
        self.assertEqual(layout["partitions"][2]["bytes"], 0x200000)
        corrupted = bytearray(table(self.entries))
        corrupted[16] ^= 1
        with self.assertRaises(ValueError):
            fleet.parse_partitions(corrupted, 16 * 1024 * 1024, 0x8000)
        for entries in (
            self.entries + [("overlap", 1, 0x82, 0x10000, 0x2000)],
            self.entries + [("pastend", 1, 0x82, 0x1000000, 0x1000)],
            self.entries + [("nvs", 1, 0x82, 0x500000, 0x1000)],
        ):
            with self.assertRaises(ValueError):
                fleet.parse_partitions(table(entries), 16 * 1024 * 1024, 0x8000)

    def test_blank_layout_and_unknown_psram_are_not_assumed(self):
        layout = fleet.parse_partitions(b"\xff" * 0x1000, 16 * 1024 * 1024, 0x8000)
        self.assertEqual(layout["state"], "blank_no_verified_layout")
        self.assertIsNone(fleet.embedded_psram(["Wi-Fi", "Embedded Flash 8MB"]))
        self.assertEqual(
            fleet.embedded_psram(["Embedded PSRAM 8MB (AP_3v3)"]), 8 * 1024 * 1024
        )

    def test_mac_node_and_reserved_ip_binding_never_reuses_another_unit(self):
        self.assertEqual(
            fleet.binding(2, self.mac, self.inventory, self.identity)["reserved_ip"],
            "10.77.0.121",
        )
        self.assertEqual(
            fleet.binding(4, "aa:bb:cc:dd:ee:01", self.inventory, self.identity)[
                "reserved_ip"
            ],
            "10.77.0.123",
        )
        for node, mac in (
            (1, self.mac),
            (4, self.mac),
            (True, self.mac),
            (11, self.mac),
        ):
            with self.assertRaises(ValueError):
                fleet.binding(node, mac, self.inventory, self.identity)

    def test_small_slots_block_image_without_proposing_partition_writes(self):
        identity = {
            "mac": self.mac,
            "chip": "ESP32-S3",
            "flash_bytes": 16 * 1024 * 1024,
            "embedded_psram_bytes": 8 * 1024 * 1024,
        }
        entries = self.entries[:2] + [
            ("ota_0", 0, 0x10, 0x20000, 900 * 1024),
            ("ota_1", 0, 0x11, 0x120000, 900 * 1024),
        ]
        report = {
            "identity": identity,
            "layout": fleet.parse_partitions(
                table(entries), identity["flash_bytes"], 0x8000
            ),
        }
        plan, overlay = fleet.candidate_plan(
            report,
            fleet.binding(2, self.mac, self.inventory, self.identity),
            1011552,
            "a" * 64,
        )
        self.assertEqual(plan["status"], "blocked_layout_migration_required")
        self.assertFalse(plan["flash_write_authorized"])
        self.assertIn("# CONFIG_LED_GAMMA_VIZ is not set", overlay)
        self.assertIn("# CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE is not set", overlay)
        report["layout"] = fleet.parse_partitions(
            table(self.entries), identity["flash_bytes"], 0x8000
        )
        plan, overlay = fleet.candidate_plan(
            report,
            fleet.binding(2, self.mac, self.inventory, self.identity),
            1011552,
            "a" * 64,
            "02:ac:de:77:00:03",
        )
        self.assertTrue(plan["image_fits_both_ota_slots"])
        self.assertIn('CONFIG_HOME_WIFI_PREFERRED_STA_MAC="02:aa:bb:00:00:02"', overlay)
        report["identity"]["embedded_psram_bytes"] = None
        with self.assertRaises(ValueError):
            fleet.candidate_plan(
                report,
                fleet.binding(2, self.mac, self.inventory, self.identity),
                1011552,
                "a" * 64,
            )

    def test_nvs_plan_preserves_unknown_values_and_rejects_identity_key_changes(self):
        old = {
            ("csi_cfg", "node_id"): ("uint8_t", 2),
            ("csi_cfg", "ssid"): ("string", "private-ssid"),
            ("csi_cfg", "password"): ("string", "private-password"),
            ("csi_cfg", "target_ip"): ("string", "192.0.2.1"),
            ("csi_cfg", "target_port"): ("uint16_t", 5005),
            ("vendor", "opaque"): ("blob", b"retain"),
        }
        selected = fleet.provision_values(old, 2, "a" * 64, b"p" * 32)
        self.assertTrue(all(selected[k] == value for k, value in old.items()))
        self.assertEqual(selected[("csi_cfg", "wasm_verify")], ("uint8_t", 1))
        for changes in (
            {("csi_cfg", "node_id"): ("uint8_t", 1)},
            {("security", "ota_psk"): ("string", "b" * 64)},
            {("csi_cfg", "wasm_pubkey"): ("blob", b"q" * 32)},
        ):
            with self.assertRaises(ValueError):
                fleet.provision_values({**old, **changes}, 2, "a" * 64, b"p" * 32)
        with self.assertRaises(ValueError):
            fleet.provision_values(old, 2, "a" * 64, b"p" * 32, {})

    @unittest.skipUnless(
        importlib.util.find_spec("esp_idf_nvs_partition_gen"),
        "Pinned private NVS dependency is not installed",
    )
    def test_prepared_nvs_round_trip_preserves_values_and_unique_identity(self):
        network = {
            "ssid": "test-private-network",
            "password": "test-private-password",
            "target_ip": "192.0.2.1",
            "target_port": 5005,
        }
        expected = fleet.provision_values(
            {("vendor", "opaque"): ("blob", b"retain")}, 4, "a" * 64, b"p" * 32, network
        )
        tool = fleet.nvs_tool()
        encoded = tool.generate(expected, 0x6000)
        self.assertEqual(len(encoded), 0x6000)
        self.assertEqual(tool.logical_values(encoded), expected)
        self.assertEqual(expected[("csi_cfg", "node_id")], ("uint8_t", 4))

    def test_private_files_are_exclusive_and_tampered_backup_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = fleet.create_directory(Path(temp) / "backup")
            data = bytearray(b"\xff" * 0x100000)
            data[0x8000:0x9000] = table(self.entries[:2])
            report = {
                "identity": {"flash_bytes": len(data)},
                "complete": True,
                "flash_write_performed": False,
                "flash_sha256": fleet.sha(data),
                "partition_table_offset": 0x8000,
                "layout": fleet.parse_partitions(
                    bytes(data[0x8000:0x9000]), len(data), 0x8000
                ),
                "chunks": [
                    {
                        "offset": 0,
                        "bytes": len(data),
                        "sha256": fleet.sha(data),
                        "device_md5_verified": True,
                    }
                ],
            }
            fleet.save(directory / "flash.bin", bytes(data))
            fleet.save(directory / "backup.json", report)
            self.assertEqual(os.stat(directory / "flash.bin").st_mode & 0o777, 0o600)
            fleet.verify_backup(directory)
            with self.assertRaises(FileExistsError):
                fleet.save(directory / "backup.json", report)
            (directory / "flash.bin").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                fleet.verify_backup(directory)

    def application_fixture(self):
        raw = bytearray(b"\xff" * (16 * 1024 * 1024))
        raw[0x8000:0x9000] = table(self.entries)
        seq = struct.pack("<I", 1)
        struct.pack_into("<I20xII", raw, 0xF000, 1, 2, zlib.crc32(seq, 0xFFFFFFFF))
        raw[0x20000] = 0xE9
        struct.pack_into("<I", raw, 0x20000 + 32, 0xABCD5432)
        raw[0x20000 + 48 : 0x20000 + 80] = b"0.8.8.8\0".ljust(32, b"\0")
        raw = bytes(raw)
        data = b"application candidate fixture" * 300
        report = {
            "node_id": 2,
            "flash_sha256": fleet.sha(raw),
            "identity": {
                "chip": "ESP32-S3",
                "mac": self.mac,
                "flash_bytes": len(raw),
                "embedded_psram_bytes": 8 * 1024 * 1024,
            },
            "chunks": [{"offset": 0, "bytes": len(raw)}],
            "layout": fleet.parse_partitions(raw[0x8000:0x9000], len(raw), 0x8000),
        }
        plan = {
            "schema_version": 1,
            "action": "application_only_usb",
            "coordinator_approved": True,
            "node_id": 2,
            "expected_mac": self.mac,
            "backup_sha256": fleet.sha(raw),
            "application_sha256": fleet.sha(data),
            "running_partition": "ota_0",
            "application_offset": 0x20000,
            "expected_current_version": "0.8.8.8",
            "hardware_profile": "home-s3-n16r8",
        }
        return raw, data, report, plan

    def test_application_write_is_one_attempt_after_full_backup_and_reservation(self):
        raw, data, report, plan = self.application_fixture()
        memory = bytearray(raw)
        calls = []

        class Esp:
            CHIP_NAME = "ESP32-S3"

            def read_mac(self):
                return bytes.fromhex(plan["expected_mac"].replace(":", ""))

            def flash_id(self):
                return 24 << 16

            def flash_md5sum(self, offset, size):
                calls.append("digest")
                return hashlib.md5(memory[offset : offset + size]).hexdigest()

        def reserve():
            calls.append("reserved")

        def write(esp, blocks, **kwargs):
            self.assertEqual(calls[-1], "reserved")
            calls.append("write")
            self.assertEqual(len(blocks), 1)
            offset, payload = blocks[0]
            memory[offset : offset + len(payload)] = payload

        result = installer.write_once(Esp(), plan, report, raw, data, write, reserve)
        self.assertTrue(result["device_digest_verified"])
        self.assertEqual(calls.count("write"), 1)
        self.assertEqual(calls.count("reserved"), 1)
        calls.clear()
        with self.assertRaisesRegex(ValueError, "Live flash changed"):
            installer.write_once(Esp(), plan, report, raw, data, write, reserve)
        self.assertNotIn("write", calls)
        self.assertNotIn("reserved", calls)

    def test_application_plan_cannot_select_wrong_unit_offset_or_oversized_image(self):
        raw, data, report, plan = self.application_fixture()
        for changes in (
            {"coordinator_approved": False},
            {"expected_mac": "00:11:22:33:44:55"},
            {"running_partition": "ota_1"},
            {"application_offset": 0x8000},
            {"expected_current_version": "0.7.0"},
            {"hardware_profile": "guessed"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                installer.approved_application({**plan, **changes}, report, raw, data)
        huge = b"x" * (0x200000 + 1)
        with self.assertRaises(ValueError):
            installer.approved_application(
                {**plan, "application_sha256": fleet.sha(huge)}, report, raw, huge
            )

    def test_application_plan_rejects_unreviewed_ota_slot_count(self):
        raw, data, report, plan = self.application_fixture()
        raw = bytearray(raw)
        entries = self.entries + [("ota_2", 0, 0x12, 0x420000, 0x200000)]
        raw[0x8000:0x9000] = table(entries)
        seq = struct.pack("<I", 3)
        struct.pack_into("<I20xII", raw, 0xF000, 3, 2, zlib.crc32(seq, 0xFFFFFFFF))
        report["flash_sha256"] = fleet.sha(raw)
        report["layout"] = fleet.parse_partitions(raw[0x8000:0x9000], len(raw), 0x8000)
        plan["backup_sha256"] = fleet.sha(raw)
        with self.assertRaisesRegex(ValueError, "reviewed two-slot"):
            installer.approved_application(plan, report, raw, data)

    def test_pinned_esptool_serial_failure_never_retries_image(self):
        try:
            import esptool.cmds
            from esptool.util import FatalError
            from serial import SerialException
        except ImportError:
            self.skipTest("Pinned esptool5.1.0 environment required")
        raw, data, report, plan = self.application_fixture()
        calls = []

        class Esp:
            CHIP_NAME = "ESP32-S3"
            WRITE_FLASH_ATTEMPTS = 2
            IS_STUB = True
            secure_download_mode = False
            FLASH_SECTOR_SIZE = 4096

            def read_mac(self):
                return bytes.fromhex(plan["expected_mac"].replace(":", ""))

            def flash_id(self):
                return 24 << 16

            def flash_md5sum(self, offset, size):
                return hashlib.md5(raw[offset : offset + size]).hexdigest()

            def get_secure_boot_enabled(self):
                return False

            def get_encrypted_download_disabled(self):
                return False

            def flash_defl_begin(self, *args):
                calls.append("begin")
                raise SerialException("deliberate offline fixture failure")

        with (
            patch("esptool.cmds.LoadFirmwareImage", side_effect=FatalError("fixture")),
            patch("esptool.cmds._set_flash_parameters", return_value="keep"),
            patch("esptool.cmds.detect_flash_size", return_value="16MB"),
            patch(
                "esptool.cmds._update_image_flash_params", side_effect=lambda *a: a[-1]
            ),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SerialException),
        ):
            installer.write_once(
                Esp(),
                plan,
                report,
                raw,
                data,
                esptool.cmds.write_flash,
                lambda: calls.append("reserved"),
            )
        self.assertEqual(calls, ["reserved", "begin"])

    def test_application_inspection_uses_cached_bytes_after_path_replacement(self):
        try:
            import esptool.cmds  # noqa: F401
        except ImportError:
            self.skipTest("Pinned esptool5.1.0 environment required")
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "application.bin"
            candidate.write_bytes(b"reviewed bytes")
            cached = candidate.read_bytes()

            def image_info(data):
                candidate.write_bytes(b"replacement bytes")
                self.assertIs(data, cached)
                self.assertEqual(data, b"reviewed bytes")
                print(
                    "Detected image type: ESP32-S3\nApp version: 0.8.8.8\n(valid)\n(valid)"
                )

            with patch("esptool.cmds.image_info", side_effect=image_info):
                fleet.inspect_application(cached, "0.8.8.8")
                with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                    fleet.inspect_application(cached, "different-version")
            self.assertNotEqual(candidate.read_bytes(), cached)


if __name__ == "__main__":
    unittest.main()
