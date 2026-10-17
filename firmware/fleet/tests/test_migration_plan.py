"""Synthetic offline migration fixtures; no serial, network or compiler calls."""

import copy
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from site_fixture import site_fixture


def load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parents[1] / filename
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FLEET = load("migration_fleet", "fleetlib.py")
BUILD = load("migration_build", "build_profile.py")
with patch.dict(sys.modules, {"fleetlib": FLEET, "build_profile": BUILD}):
    PLAN = load("migration_planner", "plan_migration.py")


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def table(entries):
    data = b"".join(
        struct.pack("<HBBII16sI", 0x50AA, kind, subtype, offset, size, name.encode(), 0)
        for name, kind, subtype, offset, size in entries
    )
    data += b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(data).digest()
    return data.ljust(4096, b"\xff")


def fixture(blank=False):
    mac = "02:aa:bb:00:00:02"
    identity = {
        "mac": mac,
        "chip": "ESP32-S3",
        "flash_bytes": 0x1000000,
        "embedded_psram_bytes": 0x800000,
    }
    node = {
        "node_id": 2,
        "mac": mac,
        "reserved_ip": "10.77.0.121",
        "inventory_binding_verified": True,
    }
    candidate, overlay = FLEET.candidate_plan(
        {"identity": identity, "layout": {"partitions": []}}, node, 100, "a" * 64
    )
    profile = BUILD.prepare(encoded(candidate), overlay.encode(), "0.8.8.9")
    config = {
        **BUILD.expected_overlay(profile),
        "CONFIG_IDF_TARGET": '"esp32s3"',
        "CONFIG_ESPTOOLPY_FLASHSIZE": '"16MB"',
        "CONFIG_ESPTOOLPY_FLASHMODE_DIO": "y",
        "CONFIG_ESPTOOLPY_FLASHFREQ_80M": "y",
        "CONFIG_SPIRAM": "y",
        "CONFIG_SPIRAM_MODE_OCT": "y",
        "CONFIG_SPIRAM_MEMTEST": "y",
        "CONFIG_ESP_WIFI_STATIC_TX_BUFFER": "y",
        "CONFIG_ESP_WIFI_TX_BUFFER_TYPE": "0",
        "CONFIG_HOME_CSI_ASSOCIATED_ONLY": "y",
        "CONFIG_WASM_ENABLE": "y",
        "CONFIG_WASM_VERIFY_SIGNATURE": "y",
        "CONFIG_WASM_MAX_MODULES": "4",
        "CONFIG_DISPLAY_ENABLE": "n",
        "CONFIG_CSI_MOCK_ENABLED": "n",
        "CONFIG_PARTITION_TABLE_OFFSET": "0x8000",
        "CONFIG_PARTITION_TABLE_CUSTOM": "y",
        "CONFIG_PARTITION_TABLE_FILENAME": '"partitions_display.csv"',
        "CONFIG_PARTITION_TABLE_MD5": "y",
        "CONFIG_BOOTLOADER_OFFSET_IN_FLASH": "0x0",
        "CONFIG_SECURE_BOOT": "n",
        "CONFIG_NVS_ENCRYPTION": "n",
        "CONFIG_FLASH_ENCRYPTION_ENABLED": "n",
        "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE": "n",
        "CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE": "y",
        "CONFIG_ESP_PHY_INIT_DATA_IN_PARTITION": "n",
    }
    args = {
        "write_flash_args": [
            "--flash_mode",
            "dio",
            "--flash_size",
            "16MB",
            "--flash_freq",
            "80m",
        ],
        "flash_settings": {
            "flash_mode": "dio",
            "flash_size": "16MB",
            "flash_freq": "80m",
        },
        "extra_esptool_args": {
            "after": "hard_reset",
            "before": "default_reset",
            "stub": True,
            "chip": "esp32s3",
        },
        "flash_files": {},
    }
    for name, offset, filename in (
        ("bootloader", "0x0", "bootloader/bootloader.bin"),
        ("app", "0x20000", "esp32-csi-node.bin"),
        ("partition-table", "0x8000", "partition_table/partition-table.bin"),
        ("otadata", "0xf000", "ota_data_initial.bin"),
    ):
        args[name] = {"offset": offset, "file": filename, "encrypted": "false"}
        args["flash_files"][offset] = filename
    blobs = {
        "profile.json": encoded(profile),
        "sdkconfig.fleet-reviewed": overlay.encode(),
        "sdkconfig": (
            "\n".join(
                f"# {key} is not set" if value == "n" else f"{key}={value}"
                for key, value in config.items()
            )
            + "\n"
        ).encode(),
        "version.txt": b"0.8.8.9\n",
        "esp32-csi-node.bin": b"synthetic-app" * 20,
        "bootloader.bin": b"synthetic-bootloader",
        "partition-table.bin": table(PLAN.TARGET)[:0xC00],
        "ota_data_initial.bin": b"\xff" * 0x2000,
        "flasher_args.json": encoded(args),
        "build_profile.py": (
            FLEET.ROOT / "firmware/fleet/build_profile.py"
        ).read_bytes(),
    }
    manifest = {
        "schema_version": 1,
        "files": {
            name: {"bytes": len(data), "sha256": FLEET.sha(data)}
            for name, data in blobs.items()
        },
        "source_sha256": PLAN.source_hashes(),
    }
    raw = bytearray(b"\xff" * 0x1000000)
    if not blank:
        raw[0x8000:0x9000] = table(PLAN.TARGET)
        values = {
            ("csi_cfg", "ssid"): ("string", "synthetic-network"),
            ("csi_cfg", "password"): ("string", "synthetic-secret-never-report"),
            ("csi_cfg", "target_ip"): ("string", "192.0.2.10"),
            ("csi_cfg", "target_port"): ("uint16_t", 5005),
            ("csi_cfg", "node_id"): ("uint8_t", 2),
            ("security", "ota_psk"): ("string", "c" * 64),
            ("calibration", "opaque"): ("blob", b"same-device-calibration"),
        }
        raw[0x9000:0xF000] = FLEET.nvs_tool().generate(values, 0x6000)
        raw[0x11000:0x12000] = b"P" * 0x1000
        raw[0x420000:0x421000] = b"S" * 0x1000
    raw = bytes(raw)
    report = {
        "complete": True,
        "flash_write_performed": False,
        "node_id": 2,
        "identity": identity,
        "flash_sha256": FLEET.sha(raw),
        "partition_table_offset": 0x8000,
        "layout": FLEET.parse_partitions(raw[0x8000:0x9000], len(raw), 0x8000),
        "chunks": [
            {
                "offset": 0,
                "bytes": len(raw),
                "sha256": FLEET.sha(raw),
                "device_md5_verified": True,
            }
        ],
    }
    return report, raw, manifest, blobs, node


@unittest.skipUnless(
    importlib.util.find_spec("esp_idf_nvs_partition_gen")
    and importlib.util.find_spec("esptool"),
    "Pinned offline firmware dependencies required",
)
class MigrationPlanTests(unittest.TestCase):
    def setUp(self):
        self.site_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.site_temporary.cleanup)
        self.site_args, self.site = site_fixture(self.site_temporary.name)
        self.app = patch.object(PLAN, "inspect_application")
        self.boot = patch(
            "esptool.cmds.image_info",
            side_effect=lambda data: print(
                "Detected image type: ESP32-S3\n(valid)\n(valid)"
            ),
        )
        self.app.start()
        self.boot.start()
        self.addCleanup(self.app.stop)
        self.addCleanup(self.boot.stop)

    def test_existing_device_preserves_nvs_and_every_complement_byte(self):
        report, raw, manifest, blobs, node = fixture()
        plan, payloads, key = PLAN.make_plan(
            report,
            raw,
            manifest,
            blobs,
            node,
            "two-ota-preserve-data",
            site_context=self.site,
        )
        self.assertFalse(plan["flash_write_authorized"])
        self.assertFalse(plan["layout_changes_authorized"])
        self.assertFalse(
            plan["intended_boot_selection"]["bootloader_selection_verified"]
        )
        self.assertEqual(plan["intended_boot_selection"]["partition"], "ota_0")
        self.assertEqual(key, "c" * 64)
        self.assertTrue(plan["nvs_preservation"]["all_prior_values_preserved"])
        self.assertNotIn("synthetic-secret-never-report", json.dumps(plan))
        self.assertNotIn(key, json.dumps(plan))
        memory = bytearray(raw)
        for item in plan["write_ranges"]:
            data = payloads[Path(item["file"]).name]
            self.assertEqual(FLEET.sha(data), item["sha256"])
            memory[item["offset"] : item["offset"] + item["bytes"]] = data
        self.assertEqual(
            sum(r["bytes"] for r in plan["write_ranges"] + plan["unchanged_ranges"]),
            len(raw),
        )
        for item in plan["unchanged_ranges"]:
            self.assertEqual(
                FLEET.sha(memory[item["offset"] : item["offset"] + item["bytes"]]),
                item["sha256"],
            )
        self.assertEqual(memory[0x11000:0x12000], b"P" * 4096)
        self.assertEqual(memory[0x420000:0x421000], b"S" * 4096)

    def test_blank_board_requires_explicit_network_and_generates_own_key(self):
        args = fixture(blank=True)
        with self.assertRaisesRegex(ValueError, "Missing private network"):
            PLAN.make_plan(*args, "blank-full-flash", site_context=self.site)
        network = {
            "ssid": "synthetic",
            "password": "synthetic-pass",
            "target_ip": "192.0.2.1",
            "target_port": 5005,
        }
        first, payloads, key = PLAN.make_plan(
            *args, "blank-full-flash", network, site_context=self.site
        )
        second_key = PLAN.make_plan(
            *args, "blank-full-flash", network, site_context=self.site
        )[2]
        self.assertNotEqual(key, second_key)
        self.assertFalse(first["nvs_preservation"]["ota_key_preserved"])
        self.assertEqual(
            FLEET.nvs_tool().logical_values(payloads["nvs-prepared.bin"])[
                ("csi_cfg", "node_id")
            ],
            ("uint8_t", 2),
        )

    def test_nonempty_data_relocation_or_unknown_layout_is_blocked(self):
        report, raw, *_ = fixture()
        for mutate in ("moved_spiffs", "unknown_partition", "no_md5", "wrong_subtype"):
            changed = copy.deepcopy(report)
            if mutate == "moved_spiffs":
                changed["layout"]["partitions"][-1]["offset"] = 0x200000
            elif mutate == "unknown_partition":
                changed["layout"]["partitions"][-1]["name"] = "vendor_data"
            elif mutate == "no_md5":
                changed["layout"]["md5_verified"] = False
            else:
                changed["layout"]["partitions"][0]["subtype"] = 4
            with self.subTest(case=mutate), self.assertRaises(PLAN.Blocked):
                PLAN.source_layout(changed, raw, "two-ota-preserve-data")
        report, raw, *_ = fixture(blank=True)
        with self.assertRaisesRegex(PLAN.Blocked, "entire_flash_erased"):
            PLAN.source_layout(report, b"X" + raw[1:], "blank-full-flash")

    def test_hardware_unit_and_existing_identity_conflicts_fail(self):
        for mutate in ("psram", "flash", "chip", "mac", "node"):
            args = list(fixture())
            if mutate == "psram":
                args[0]["identity"]["embedded_psram_bytes"] = None
            elif mutate == "flash":
                args[0]["identity"]["flash_bytes"] = 0x800000
            elif mutate == "chip":
                args[0]["identity"]["chip"] = "ESP32"
            elif mutate == "mac":
                args[-1]["mac"] = "00:11:22:33:44:55"
            else:
                args[-1]["node_id"] = 3
            with self.subTest(case=mutate), self.assertRaises(PLAN.Blocked):
                PLAN.make_plan(*args, "two-ota-preserve-data", site_context=self.site)
        args = list(fixture())
        profile = json.loads(args[3]["profile.json"])
        profile["station_mac"] = "00:11:22:33:44:55"
        args[3]["profile.json"] = encoded(profile)
        with self.assertRaisesRegex(PLAN.Blocked, "profile_unit"):
            PLAN.make_plan(*args, "two-ota-preserve-data", site_context=self.site)

    def test_bundle_rejects_encryption_boot_selection_layout_and_oversize(self):
        *_, blobs, node = fixture()
        for mutate in (
            "encrypted",
            "ota",
            "table",
            "app",
            "boot",
            "flash_map",
            "component",
        ):
            changed = dict(blobs)
            if mutate == "encrypted":
                changed["sdkconfig"] = changed["sdkconfig"].replace(
                    b"# CONFIG_NVS_ENCRYPTION is not set", b"CONFIG_NVS_ENCRYPTION=y"
                )
            elif mutate == "ota":
                changed["ota_data_initial.bin"] = b"X" * 0x2000
            elif mutate == "table":
                changed["partition-table.bin"] = table(PLAN.TARGET[:-1])
            elif mutate == "app":
                changed["esp32-csi-node.bin"] = b"X" * (0x200000 + 1)
            elif mutate == "boot":
                changed["bootloader.bin"] = b"X" * (0x8000 + 1)
            else:
                args = json.loads(changed["flasher_args.json"])
                if mutate == "flash_map":
                    args["flash_files"]["0x11000"] = "calibration.bin"
                else:
                    args["app"]["offset"] = "0x8000"
                changed["flasher_args.json"] = encoded(args)
            with self.subTest(case=mutate), self.assertRaises(PLAN.Blocked):
                PLAN.validate_bundle(changed, node)

    def test_hash_pins_reject_substitution_and_checks_use_cached_bytes(self):
        report, raw, manifest, blobs, node = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, data in blobs.items():
                (directory / name).write_bytes(data)
            path = directory / "bundle.json"
            path.write_bytes(encoded(manifest))
            digest = FLEET.sha(path.read_bytes())
            loaded, cached = PLAN.load_bundle(path, digest)
            (directory / "esp32-csi-node.bin").write_bytes(b"replaced")
            with self.assertRaisesRegex(PLAN.Blocked, "artifact_size"):
                PLAN.load_bundle(path, digest)
            plan = PLAN.make_plan(
                report,
                raw,
                loaded,
                cached,
                node,
                "two-ota-preserve-data",
                site_context=self.site,
            )[0]
            self.assertEqual(
                plan["build_artifacts"]["files"]["esp32-csi-node.bin"]["sha256"],
                FLEET.sha(blobs["esp32-csi-node.bin"]),
            )
            with self.assertRaisesRegex(PLAN.Blocked, "manifest_digest"):
                PLAN.load_bundle(path, "f" * 64)
            manifest["source_sha256"]["firmware/Dockerfile"] = "f" * 64
            path.write_bytes(encoded(manifest))
            with self.assertRaisesRegex(PLAN.Blocked, "source_pins"):
                PLAN.load_bundle(path, FLEET.sha(path.read_bytes()))

    def test_private_run_preserves_failed_report_and_refuses_reuse(self):
        report, raw, manifest, blobs, node = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = FLEET.create_directory(base / "backup")
            FLEET.save(backup / "flash.bin", raw)
            FLEET.save(backup / "backup.json", report)
            bundle = base / "bundle"
            bundle.mkdir()
            for name, data in blobs.items():
                (bundle / name).write_bytes(data)
            path = bundle / "bundle.json"
            path.write_bytes(encoded(manifest))
            site_args, _ = site_fixture(base)
            args = SimpleNamespace(
                **site_args,
                output=base / "plan",
                backup=backup,
                node=2,
                build_manifest=path,
                bundle_sha256=FLEET.sha(path.read_bytes()),
                source_layout="two-ota-preserve-data",
                network_settings=None,
            )
            self.assertEqual(PLAN.run(args)[0], 0)
            for file in args.output.rglob("*"):
                self.assertEqual(file.stat().st_mode & 0o077, 0)
            with self.assertRaises(FileExistsError):
                PLAN.run(args)
            args.output = base / "tampered"
            (backup / "flash.bin").write_bytes(b"X" + raw[1:])
            self.assertEqual(PLAN.run(args)[0], 1)
            failure = json.loads((args.output / "blocked.json").read_text())
            self.assertFalse(failure["flash_write_authorized"])
            self.assertNotIn("synthetic-secret-never-report", json.dumps(failure))
            self.assertFalse((args.output / "plan.json").exists())


if __name__ == "__main__":
    unittest.main()
