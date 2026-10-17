"""Synthetic offline direct-USB gates; never open a real serial port."""

import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from site_fixture import site_fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import direct_usb as direct  # noqa: E402

sys.path.pop(0)

MAC = "02:aa:bb:00:00:01"
OLD_VERSION = "0.7.0"
VERSION = "0.8.8.9"
START = "2000-01-01T12:00:00+00:00"
ENTRIES = [
    ("nvs", 1, 2, 0x9000, 0x6000),
    ("otadata", 1, 0, 0xF000, 0x2000),
    ("phy_init", 1, 1, 0x11000, 0x1000),
    ("ota_0", 0, 0x10, 0x20000, 0x200000),
    ("ota_1", 0, 0x11, 0x220000, 0x200000),
    ("spiffs", 1, 0x82, 0x420000, 0x1E0000),
]


def table(entries=ENTRIES):
    data = b"".join(
        struct.pack("<HBBII16sI", 0x50AA, kind, sub, offset, size, name.encode(), 0)
        for name, kind, sub, offset, size in entries
    )
    return (data + b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(data).digest()).ljust(
        4096, b"\xff"
    )


def header(version=OLD_VERSION):
    data = bytearray(b"\xff" * 4096)
    data[0] = 0xE9
    struct.pack_into("<I", data, 32, 0xABCD5432)
    data[48:80] = version.encode().ljust(32, b"\0")
    return bytes(data)


def selection(seq=1, state=2):
    data = bytearray(b"\xff" * 8192)
    struct.pack_into(
        "<I20xII", data, 0, seq, state, zlib.crc32(struct.pack("<I", seq), 0xFFFFFFFF)
    )
    return bytes(data)


def values():
    return {
        ("csi_cfg", "node_id"): ("uint8_t", 1),
        ("csi_cfg", "ssid"): ("string", "synthetic-network"),
        ("csi_cfg", "password"): ("string", "synthetic-password"),
        ("csi_cfg", "target_ip"): ("string", "192.0.2.1"),
        ("csi_cfg", "target_port"): ("uint16_t", 5005),
        ("nvs.net80211", "opaque"): ("blob", bytes(range(256)) * 20),
        ("calibration", "opaque"): ("blob", b"synthetic-calibration"),
    }


class Esp:
    CHIP_NAME = "ESP32-S3"
    WRITE_FLASH_ATTEMPTS = 2
    secure_download_mode = False

    def __init__(self, nvs=None):
        self.memory = bytearray(b"\xff" * direct.FLASH_BYTES)
        self.memory[0x8000:0x9000] = table()
        self.memory[0x9000:0xF000] = nvs or direct.nvs_tool().generate(values(), 0x6000)
        self.memory[0xF000:0x11000] = selection()
        self.memory[0x20000:0x21000] = header()
        self.memory[0x220000:0x221000] = header()
        self.mac = MAC
        self.calls = []
        self._port = self

    def read_mac(self):
        return bytes.fromhex(self.mac.replace(":", ""))

    def get_chip_features(self):
        return ["Wi-Fi", "Embedded PSRAM 8MB (AP_3v3)"]

    def get_chip_description(self):
        return "synthetic ESP32-S3 N16R8"

    def flash_id(self):
        return 24 << 16

    def get_secure_boot_enabled(self):
        return False

    def get_flash_encryption_enabled(self):
        return False

    def read_flash(self, offset, size):
        self.calls.append(("read", offset, size))
        return bytes(self.memory[offset : offset + size])

    def flash_md5sum(self, offset, size):
        return hashlib.md5(self.memory[offset : offset + size]).hexdigest()

    def close(self):
        self.calls.append("close")

    def hard_reset(self):
        self.calls.append("RESET-UNEXPECTED")
        raise AssertionError("No automatic reboot permitted")


class DirectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.site_args, self.site = site_fixture(self.root)
        self.image_check = patch.object(direct, "inspect_application")
        self.image_check.start()
        self.addCleanup(self.image_check.stop)

    def fixture(self, nvs=None, erased=False, pre=None):
        esp = Esp(nvs)
        if erased:
            esp.memory[0xF000:0x11000] = b"\xff" * 8192
        report, blobs = direct.inspect_device(esp, 1, MAC, OLD_VERSION, START, pre)
        app = b"synthetic new application bytes" * 200
        candidate, payloads, key = direct.candidate_data(
            report,
            blobs,
            app,
            direct.sha(app),
            VERSION,
            "a" * 64 if nvs is None else None,
            site_context=self.site,
        )
        directory = self.root / "candidate"
        directory.mkdir(mode=0o700)
        for name, data in {
            **blobs,
            **payloads,
            "application.bin": app,
            "ota-key.private.txt": key.encode(),
        }.items():
            direct.save(directory / name, data)
        direct.save(directory / "inspection.json", report)
        candidate["inspection_sha256"] = direct.sha(
            (directory / "inspection.json").read_bytes()
        )
        direct.save(directory / "candidate.json", candidate)
        review = {
            "schema": direct.REVIEW_SCHEMA,
            "coordinator_approved": True,
            "hardware_build_profile_reviewed": True,
            "candidate_file": str(directory / "candidate.json"),
            "candidate_sha256": direct.sha((directory / "candidate.json").read_bytes()),
            "tool_hashes": candidate["tool_hashes"],
            **{
                k: candidate[k]
                for k in (
                    "node_id",
                    "expected_mac",
                    "application_sha256",
                    "application_version",
                    "hardware_profile",
                )
            },
        }
        review_path = self.root / "review.json"
        direct.save(review_path, review)
        context = direct.reviewed_context(review_path, **self.site_args)
        return esp, context, review_path

    def test_inspection_reads_only_minimal_regions_not_full_backup(self):
        esp, context, _ = self.fixture()
        self.assertEqual(sum(c[2] for c in esp.calls if c[0] == "read"), 45056)
        self.assertEqual(context["report"]["boot_selection"]["partition"], "ota_0")
        self.assertFalse(context["report"]["full_backup_created"])
        self.assertFalse(context["candidate"]["flash_write_authorized"])

    def test_exact_plan_hash_payload_version_and_unit_are_required(self):
        _, context, review_path = self.fixture()
        review = json.loads(review_path.read_bytes())
        for change in (
            {"expected_mac": "00:11:22:33:44:55"},
            {"node_id": True},
            {"application_sha256": "b" * 64},
            {"application_version": "different"},
            {"candidate_sha256": "c" * 64},
            {"hardware_build_profile_reviewed": False},
            {"tool_hashes": {}},
        ):
            with self.subTest(change=change):
                review_path.write_text(json.dumps({**review, **change}))
                with self.assertRaises(ValueError):
                    direct.reviewed_context(review_path, **self.site_args)
        review_path.write_text(json.dumps(review))
        path = context["directory"] / "application-sectors.bin"
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "payload changed"):
            direct.reviewed_context(review_path, **self.site_args)

    def test_table_rejects_unknown_apps_md5_encryption_overlap_and_wrong_nvs(self):
        bad_entries = [
            ENTRIES + [("factory", 0, 0, 0x700000, 0x100000)],
            ENTRIES + [("ota_2", 0, 0x12, 0x700000, 0x100000)],
            ENTRIES + [("keys", 1, 4, 0x700000, 4096)],
            [("nvs", 1, 2, 0x9000, 0x5000), *ENTRIES[1:]],
            ENTRIES + [("overlap", 1, 0x82, 0x9000, 4096)],
        ]
        for entries in bad_entries:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                direct.layout_parts(table(entries))
        without_md5 = table()[: 32 * len(ENTRIES)].ljust(4096, b"\xff")
        with self.assertRaisesRegex(ValueError, "MD5"):
            direct.layout_parts(without_md5)

    def test_pending_corrupt_and_unproven_erased_boot_selection_fail(self):
        headers = {"ota_0": header(), "ota_1": header()}
        for raw in (
            selection(state=0),
            selection(state=1),
            selection(state=3),
            b"\x00" * 8192,
            b"\xff" * 8192,
        ):
            with self.subTest(raw=direct.sha(raw)), self.assertRaises(ValueError):
                direct.boot_selection(raw, headers, OLD_VERSION, {})
        self.assertEqual(
            direct.boot_selection(selection(seq=2), headers, OLD_VERSION, {})[
                "partition"
            ],
            "ota_1",
        )

    def test_erased_metadata_requires_fresh_exact_same_unit_status(self):
        pre = {
            "schema": direct.STATUS_SCHEMA,
            "node_id": 1,
            "expected_mac": MAC,
            "observed_utc": "2000-01-01T11:59:00Z",
            "status": {
                "version": OLD_VERSION,
                "running_partition": "ota_0",
                "next_partition": "ota_1",
                "max_size": 900 * 1024,
            },
        }
        esp, context, _ = self.fixture(erased=True, pre=pre)
        self.assertEqual(context["candidate"]["boot_selection"]["partition"], "ota_0")
        for change in (
            {"node_id": True},
            {"expected_mac": "00:11:22:33:44:55"},
            {"observed_utc": "2000-01-01T11:49:59Z"},
            {"observed_utc": "2000-01-01T12:00:01Z"},
            {"status": {**pre["status"], "running_partition": "ota_1"}},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                direct.inspect_device(
                    esp, 1, MAC, OLD_VERSION, START, {**pre, **change}
                )
        esp.memory[0x20000:0x21000] = header("another")
        with self.assertRaises(ValueError):
            direct.inspect_device(esp, 1, MAC, OLD_VERSION, START, pre)

    def test_nvs_preserves_existing_nonhex_key_wifi_opaque_and_calibration(self):
        old = values()
        old[("security", "ota_psk")] = ("string", "existing-key-DoNotRotate")
        raw = direct.nvs_tool().generate(old, 0x6000)
        prepared, key, metadata = direct.prepared_nvs(raw, 1, site_context=self.site)
        self.assertEqual(key, "existing-key-DoNotRotate")
        self.assertTrue(metadata["ota_key_preserved"])
        actual = direct.nvs_tool().logical_values(prepared)
        self.assertTrue(all(actual[k] == v for k, v in old.items()))
        self.assertEqual(actual[("csi_cfg", "wasm_verify")], ("uint8_t", 1))
        same, _, no_change = direct.prepared_nvs(prepared, 1, site_context=self.site)
        self.assertEqual(same, prepared)
        self.assertEqual(no_change["changed_keys_without_values"], [])
        with self.assertRaises(ValueError):
            direct.prepared_nvs(raw, 1, "a" * 64, site_context=self.site)

    def test_absent_node_id_added_from_bound_candidate_preserving_every_value(self):
        old = values()
        del old[("csi_cfg", "node_id")]
        raw = direct.nvs_tool().generate(old, 0x6000)
        _, context, _ = self.fixture(nvs=raw)
        candidate = context["candidate"]
        self.assertEqual((candidate["node_id"], candidate["expected_mac"]), (1, MAC))
        actual = direct.nvs_tool().logical_values(
            context["payloads"]["nvs-prepared.bin"]
        )
        self.assertEqual(actual[("csi_cfg", "node_id")], ("uint8_t", 1))
        self.assertTrue(all(actual[k] == value for k, value in old.items()))
        self.assertIn(
            ["csi_cfg", "node_id"], candidate["nvs"]["changed_keys_without_values"]
        )
        self.assertNotIn(("csi_cfg", "node_id"), direct.nvs_tool().logical_values(raw))
        for invalid in (True, 0, 11, "1"):
            with self.subTest(node_id=invalid), self.assertRaises(ValueError):
                direct.prepared_nvs(raw, invalid, site_context=self.site)

    def test_nvs_key_controls_trust_identity_missing_network_corruption_rejected(self):
        mutants = [
            {("security", "ota_psk"): ("string", key)}
            for key in ("", "a" * 65, "with\rreturn", "with\ttab", "with\x7fdel")
        ] + [
            {("csi_cfg", "node_id"): ("uint8_t", 2)},
            {("csi_cfg", "node_id"): ("uint32_t", 1)},
            {("csi_cfg", "node_id"): ("string", "1")},
            {("csi_cfg", "wasm_pubkey"): ("blob", b"x" * 32)},
            {("csi_cfg", "wasm_verify"): ("uint32_t", 1)},
        ]
        for mutant in mutants:
            with self.subTest(keys=list(mutant)), self.assertRaises(ValueError):
                direct.prepared_nvs(
                    direct.nvs_tool().generate({**values(), **mutant}, 0x6000),
                    1,
                    site_context=self.site,
                )
        missing = values()
        del missing[("csi_cfg", "target_ip")]
        with self.assertRaises(ValueError):
            direct.prepared_nvs(
                direct.nvs_tool().generate(missing, 0x6000), 1, site_context=self.site
            )
        corrupt = bytearray(direct.nvs_tool().generate(values(), 0x6000))
        corrupt[28] ^= 1
        with self.assertRaises(ValueError):
            direct.prepared_nvs(bytes(corrupt), 1, site_context=self.site)

    def test_small_actual_slot_blocks_even_when_legacy_http_cap_not_used(self):
        esp, context, _ = self.fixture()
        entries = ENTRIES.copy()
        entries[3] = ("ota_0", 0, 0x10, 0x20000, 0x10000)
        esp.memory[0x8000:0x9000] = table(entries)
        report, blobs = direct.inspect_device(esp, 1, MAC, OLD_VERSION, START)
        app = b"x" * (0x10000 + 1)
        with self.assertRaisesRegex(ValueError, "actual selected slot"):
            direct.candidate_data(
                report,
                blobs,
                app,
                direct.sha(app),
                VERSION,
                "a" * 64,
                site_context=self.site,
            )
        large = b"x" * 1011552
        candidate, _, _ = direct.candidate_data(
            context["report"],
            context["blobs"],
            large,
            direct.sha(large),
            VERSION,
            "a" * 64,
            site_context=self.site,
        )
        self.assertGreater(candidate["application_bytes"], 900 * 1024)

    def test_single_write_reservation_and_readback_exact_ranges(self):
        esp, context, _ = self.fixture()
        before = bytes(esp.memory)
        result = {"write_attempted": False}
        calls = []

        def reserve():
            direct.reserve_attempt(context)
            calls.append("reserved")

        def writer(device, blocks, **kwargs):
            self.assertEqual(calls, ["reserved"])
            self.assertEqual(device.WRITE_FLASH_ATTEMPTS, 1)
            self.assertEqual(
                kwargs,
                {
                    "flash_size": "keep",
                    "flash_mode": "keep",
                    "flash_freq": "keep",
                    "compress": True,
                },
            )
            calls.append("write")
            for offset, raw in blocks:
                device.memory[offset : offset + len(raw)] = raw

        direct.write_once(esp, context, writer, reserve, result)
        self.assertEqual(calls, ["reserved", "write"])
        self.assertTrue(result["write_verified"])
        permitted = set()
        for block in context["candidate"]["writes"]:
            permitted.update(range(block["offset"], block["offset"] + block["bytes"]))
        changed = {
            i
            for i, (old, new) in enumerate(zip(before, esp.memory, strict=True))
            if old != new
        }
        self.assertTrue(changed <= permitted)
        self.assertEqual(esp.memory[0x8000:0x9000], before[0x8000:0x9000])
        self.assertEqual(esp.memory[0xF000:0x11000], before[0xF000:0x11000])

    def test_future_ota_requires_sector_rounded_fit_of_smaller_inactive_slot(self):
        esp = Esp()
        entries = ENTRIES.copy()
        entries[4] = ("ota_1", 0, 0x11, 0x220000, 0x10000)
        esp.memory[0x8000:0x9000] = table(entries)
        report, blobs = direct.inspect_device(esp, 1, MAC, OLD_VERSION, START)
        data = b"x" * (0x10000 + 1)
        with self.assertRaisesRegex(ValueError, "inactive slot"):
            direct.candidate_data(
                report,
                blobs,
                data,
                direct.sha(data),
                VERSION,
                "a" * 64,
                site_context=self.site,
            )
        data = data[: 0x10000 - 1]
        candidate, _, _ = direct.candidate_data(
            report,
            blobs,
            data,
            direct.sha(data),
            VERSION,
            "a" * 64,
            site_context=self.site,
        )
        self.assertEqual(candidate["application_sector_bytes"], 0x10000)
        self.assertTrue(candidate["image_fits_both_ota_slots"])
        self.assertEqual(
            candidate["ota_slot_bytes"], {"ota_0": 0x200000, "ota_1": 0x10000}
        )

    def test_unchanged_nvs_is_never_rewritten(self):
        nvs, _, _ = direct.prepared_nvs(
            direct.nvs_tool().generate(values(), 0x6000),
            1,
            "a" * 64,
            site_context=self.site,
        )
        _, context, _ = self.fixture(nvs=nvs)
        self.assertEqual(
            [p["file"] for p in context["candidate"]["writes"]],
            ["application-sectors.bin"],
        )
        self.assertEqual(context["payloads"]["nvs-prepared.bin"], nvs)

    def test_live_changes_wrong_mac_and_hardware_fail_before_reservation(self):
        esp, context, _ = self.fixture()
        for mutate in (
            lambda: setattr(esp, "mac", "00:11:22:33:44:55"),
            lambda: esp.memory.__setitem__(0x9010, 0),
            lambda: esp.memory.__setitem__(0x20000 + 5000, 0),
        ):
            original = bytes(esp.memory)
            mutate()
            reserve, writer = unittest.mock.Mock(), unittest.mock.Mock()
            with self.assertRaises(ValueError):
                direct.write_once(esp, context, writer, reserve, {})
            reserve.assert_not_called()
            writer.assert_not_called()
            esp.mac = MAC
            esp.memory[:] = original
        with (
            patch.object(esp, "get_chip_features", return_value=["Wi-Fi"]),
            self.assertRaises(ValueError),
        ):
            direct.write_once(
                esp, context, unittest.mock.Mock(), unittest.mock.Mock(), {}
            )

    def test_uncertain_write_and_corrupt_readback_consume_marker_without_retry(self):
        esp, context, _ = self.fixture()
        calls = []

        def failing(*args, **kwargs):
            calls.append("write")
            raise OSError("synthetic interruption")

        result = {}
        with self.assertRaises(OSError):
            direct.write_once(
                esp, context, failing, lambda: direct.reserve_attempt(context), result
            )
        self.assertEqual(calls, ["write"])
        self.assertTrue(result["write_attempted"])
        self.assertNotIn("write_verified", result)
        with self.assertRaises(FileExistsError):
            direct.reserve_attempt(context)

    def test_corrupt_postwrite_otadata_is_not_verified(self):
        esp, context, _ = self.fixture()

        def writer(device, blocks, **kwargs):
            for offset, raw in blocks:
                device.memory[offset : offset + len(raw)] = raw
            device.memory[0xF000] ^= 1

        result = {}
        with self.assertRaisesRegex(ValueError, "OTA metadata changed"):
            direct.write_once(
                esp, context, writer, lambda: direct.reserve_attempt(context), result
            )
        self.assertTrue(result["write_attempted"])
        self.assertNotIn("write_verified", result)

    def test_review_relocation_cannot_rearm_marker(self):
        _, context, review = self.fixture()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        second = elsewhere / "other-review.json"
        direct.save(second, review.read_bytes())
        same = direct.reviewed_context(second, **self.site_args)
        self.assertEqual(direct.attempt_marker(context), direct.attempt_marker(same))
        direct.reserve_attempt(context)
        with self.assertRaises(FileExistsError):
            direct.reserve_attempt(same)
        self.assertEqual(direct.attempt_marker(context).stat().st_mode & 0o777, 0o600)

    def test_private_reader_rejects_symlink_fifo_public_and_oversize(self):
        path = self.root / "private"
        direct.save(path, b"value")
        self.assertEqual(direct.read_file(path, 5), b"value")
        with self.assertRaises(ValueError):
            direct.read_file(path, 4)
        symbolic = self.root / "symbolic"
        symbolic.symlink_to(path)
        with self.assertRaises(ValueError):
            direct.read_file(symbolic, 5)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            direct.read_file(fifo, 5)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            direct.read_file(path, 5)

    def test_real_esptool_serial_exception_cannot_retry(self):
        import esptool.cmds
        from esptool.util import FatalError
        from serial import SerialException

        esp, context, _ = self.fixture()
        esp.IS_STUB = True
        esp.FLASH_SECTOR_SIZE = 4096
        esp.get_encrypted_download_disabled = lambda: False
        calls = []

        def begin(*args):
            calls.append("begin")
            raise SerialException("synthetic serial interruption")

        esp.flash_defl_begin = begin
        with (
            patch(
                "esptool.cmds.LoadFirmwareImage", side_effect=FatalError("synthetic")
            ),
            patch("esptool.cmds._set_flash_parameters", return_value="keep"),
            patch("esptool.cmds.detect_flash_size", return_value="16MB"),
            patch(
                "esptool.cmds._update_image_flash_params", side_effect=lambda *a: a[-1]
            ),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SerialException),
        ):
            direct.write_once(
                esp,
                context,
                esptool.cmds.write_flash,
                lambda: calls.append("reserved"),
                {},
            )
        self.assertEqual(calls, ["reserved", "begin"])

    def test_failed_install_closes_without_reset_and_retains_private_error(self):
        import esptool

        esp, context, _ = self.fixture()
        output = direct.create_directory(self.root / "attempt")
        args = argparse.Namespace(
            action="install", port="/synthetic-usb", output=output, **self.site_args
        )
        esp.run_stub = lambda: esp
        esp.change_baud = lambda _: None
        with (
            patch.object(direct, "usb_ports", return_value=[{"port": args.port}]),
            patch.object(direct, "one_packet_window"),
            patch.object(esptool, "detect_chip", return_value=esp) as connect,
            patch.object(esptool, "attach_flash"),
            patch.object(
                esptool.cmds,
                "write_flash",
                side_effect=OSError("synthetic private token"),
            ),
        ):
            result = direct.device_action(args, context)
        self.assertEqual(connect.call_args.kwargs["connect_mode"], "no-reset")
        self.assertFalse(result["complete"])
        self.assertTrue(result["write_attempted"])
        self.assertNotIn("synthetic private token", json.dumps(result))
        self.assertIn(
            "synthetic private token", (output / "serial.private.log").read_text()
        )
        self.assertEqual(esp.calls[-1], "close")
        self.assertNotIn("RESET-UNEXPECTED", esp.calls)

    def test_real_esptool_compressed_block_fatal_error_cannot_retry(self):
        import esptool.loader
        from esptool.util import FatalError

        esp, context, _ = self.fixture()
        esp.IS_STUB = True
        esp.ESP_CMDS = {"FLASH_DEFL_DATA": 17}
        esp.checksum = lambda _: 0
        calls = []

        def fail_command(*args, **kwargs):
            calls.append("block")
            raise FatalError("synthetic block failure")

        esp.check_command = fail_command

        def writer(device, blocks, **kwargs):
            esptool.loader.ESPLoader.flash_defl_block(device, b"synthetic", 0)

        with (
            patch.object(esptool.loader, "WRITE_BLOCK_ATTEMPTS", 3),
            self.assertRaises(FatalError),
        ):
            direct.write_once(
                esp, context, writer, lambda: calls.append("reserved"), {}
            )
        self.assertEqual(calls, ["reserved", "block"])

    def test_strict_json_and_cached_inspection_tamper(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e309}'):
            with self.assertRaises(ValueError):
                direct.strict_json(raw)
        _, context, _ = self.fixture()
        bad = copy.deepcopy(context["report"])
        bad["security"]["secure_boot"] = True
        with self.assertRaises(ValueError):
            direct.validate_inspection(bad, context["blobs"])

    def test_context_change_before_reservation_never_marks_or_writes(self):
        import esptool

        esp, context, _ = self.fixture()
        output = direct.create_directory(self.root / "context-change")
        args = argparse.Namespace(
            action="install", port="/synthetic-usb", output=output, **self.site_args
        )
        original = esp.flash_md5sum

        def changed(*args):
            (self.site_args["site_context"] / "nodes.json").write_bytes(b"{}")
            return original(*args)

        esp.flash_md5sum = changed
        esp.run_stub = lambda: esp
        esp.change_baud = lambda _: None
        with (
            patch.object(direct, "usb_ports", return_value=[{"port": args.port}]),
            patch.object(direct, "one_packet_window"),
            patch.object(esptool, "detect_chip", return_value=esp),
            patch.object(esptool, "attach_flash"),
            patch.object(esptool.cmds, "write_flash") as write,
        ):
            result = direct.device_action(args, context)
        self.assertFalse(result["write_attempted"])
        self.assertFalse(result["complete"])
        self.assertFalse(direct.attempt_marker(context).exists())
        write.assert_not_called()
        self.assertNotIn("RESET-UNEXPECTED", esp.calls)

    def test_identity_change_before_reservation_never_marks_or_writes(self):
        import esptool

        esp, context, _ = self.fixture()
        output = direct.create_directory(self.root / "context-change")
        args = argparse.Namespace(
            action="install", port="/synthetic-usb", output=output, **self.site_args
        )
        original = esp.flash_md5sum

        def changed(*args):
            self.site_args["installation_identity"].write_bytes(b"{}")
            return original(*args)

        esp.flash_md5sum = changed
        esp.run_stub = lambda: esp
        esp.change_baud = lambda _: None
        with (
            patch.object(direct, "usb_ports", return_value=[{"port": args.port}]),
            patch.object(direct, "one_packet_window"),
            patch.object(esptool, "detect_chip", return_value=esp),
            patch.object(esptool, "attach_flash"),
            patch.object(esptool.cmds, "write_flash") as write,
        ):
            result = direct.device_action(args, context)
        self.assertFalse(result["write_attempted"])
        self.assertFalse(result["complete"])
        self.assertFalse(direct.attempt_marker(context).exists())
        write.assert_not_called()
        self.assertNotIn("RESET-UNEXPECTED", esp.calls)

    def test_private_log_failure_never_exposes_original_nvs_exception(self):
        output = self.root / "failed"
        stdout = io.StringIO()
        argv = [
            "direct_usb.py",
            "prepare",
            "--site-context",
            str(self.site_args["site_context"]),
            "--site-context-sha256",
            self.site_args["site_context_sha256"],
            "--installation-identity",
            str(self.site_args["installation_identity"]),
            "--installation-identity-sha256",
            self.site_args["installation_identity_sha256"],
            "--inspection",
            "unused",
            "--node",
            "1",
            "--expected-mac",
            MAC,
            "--firmware",
            "unused",
            "--sha256",
            "a" * 64,
            "--version",
            VERSION,
            "--output",
            str(output),
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(
                direct, "prepare", side_effect=ValueError("synthetic private NVS token")
            ),
            patch.object(direct, "save", side_effect=OSError("synthetic full disk")),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(direct.main(), 1)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["error_type"], "ValueError")
        self.assertNotIn("synthetic", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
