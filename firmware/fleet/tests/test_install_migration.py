"""Synthetic flash/transport only; reference C is read as data, never compiled."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_migration_plan as fixture
from site_fixture import site_fixture

FLEET, PLAN = fixture.FLEET, fixture.PLAN
with patch.dict(
    sys.modules,
    {"fleetlib": FLEET, "build_profile": fixture.BUILD, "plan_migration": PLAN},
):
    BOOT = fixture.load("fleet_boot_rule_test", "boot_rule.py")
    BACKUP = fixture.load("fleet_backup_migration_test", "backup.py")
    with patch.dict(sys.modules, {"boot_rule": BOOT, "backup": BACKUP}):
        INSTALL = fixture.load("fleet_install_migration_test", "install_migration.py")

REFERENCE = Path(__file__).resolve().parents[1] / "boot-rule-reference"


def boot_evidence(blobs):
    return {
        "schema_version": 1,
        "idf_commit": BOOT.IDF_COMMIT,
        "idf_image": BOOT.IDF_IMAGE,
        "idf_sources_sha256": BOOT.IDF_SOURCES,
        "bootloader_sources_unmodified": True,
        "build_exit_code": 0,
        "artifacts_sha256": {
            name: FLEET.sha(blobs[name]) for name in BOOT.BOOT_ARTIFACTS
        },
    }


class FakeESP:
    CHIP_NAME = "ESP32-S3"
    WRITE_FLASH_ATTEMPTS = 2

    def __init__(self, context):
        self.context = context
        self.memory = bytearray(context["raw"])
        self.calls = []
        self.secure = False
        self.encrypted = False
        self.mac = context["node"]["mac"]
        self._port = SimpleNamespace(close=lambda: self.calls.append("close"))

    def get_secure_boot_enabled(self):
        return self.secure

    def get_flash_encryption_enabled(self):
        return self.encrypted

    def read_mac(self):
        return bytes.fromhex(self.mac.replace(":", ""))

    def get_chip_features(self):
        return ["Embedded PSRAM 8MB (AP_3v3)"]

    def get_chip_description(self):
        return "Synthetic ESP32-S3"

    def flash_id(self):
        return 24 << 16

    def flash_md5sum(self, offset, size):
        self.calls.append(("md5", offset, size))
        return hashlib.md5(self.memory[offset : offset + size]).hexdigest()

    def run_stub(self):
        self.calls.append("stub")
        return self

    def change_baud(self, rate):
        self.calls.append(("baud", rate))

    def hard_reset(self):
        raise AssertionError("No migration path may reset automatically")

    def write(self, esp, blocks, **settings):
        if esp is not self or self.WRITE_FLASH_ATTEMPTS != 1:
            raise AssertionError("Exact transport and no automatic retries required")
        self.calls.append("write")
        for off, data in blocks:
            self.memory[off : off + len(data)] = data


@unittest.skipUnless(
    importlib.util.find_spec("esp_idf_nvs_partition_gen")
    and importlib.util.find_spec("esptool"),
    "Pinned offline dependencies required",
)
class MigrationInstallTests(unittest.TestCase):
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

    def fixture(self, blank=False):
        report, raw, manifest, blobs, node = fixture.fixture(blank)
        report["identity"]["flash_id"] = 24 << 16
        network = (
            {
                "ssid": "test-network",
                "password": "test-password",
                "target_ip": "192.0.2.10",
                "target_port": 5005,
            }
            if blank
            else None
        )
        candidate, payloads, _ = PLAN.make_plan(
            report,
            raw,
            manifest,
            blobs,
            node,
            "blank-full-flash" if blank else "two-ota-preserve-data",
            network,
            site_context=self.site,
        )
        blocks, unchanged, layout = INSTALL.validate_candidate(
            candidate,
            report,
            raw,
            manifest,
            blobs,
            node,
            payloads,
            site_context=self.site,
        )
        context = {
            "raw": raw,
            "backup": report,
            "node": node,
            "blocks": blocks,
            "unchanged": unchanged,
            "review_sha256": "r" * 64,
            "candidate_sha256": "c" * 64,
        }
        return context, candidate, manifest, blobs, payloads, layout

    def test_exact_primary_sources_and_boot_rule_bind_artifacts_without_claiming_boot(
        self,
    ):
        _, _, _, blobs, _, layout = self.fixture()
        self.assertEqual(BOOT.verify_sources(REFERENCE), BOOT.IDF_SOURCES)
        raw = fixture.encoded(boot_evidence(blobs))
        proof = BOOT.verify_boot_rule(blobs, layout, raw, FLEET.sha(raw), REFERENCE)
        self.assertEqual(proof["first_attempt_partition"], "ota_0")
        self.assertFalse(proof["physical_boot_verified"])
        self.assertTrue(proof["first_boot_may_write_otadata"])
        self.assertTrue(proof["fallback_possible_if_image_fails"])
        # Read actual pinned source branches, without claiming execution of C.
        common = (
            REFERENCE / "components/bootloader_support/src/bootloader_common_loader.c"
        ).read_text()
        utility = (
            REFERENCE / "components/bootloader_support/src/bootloader_utility.c"
        ).read_text()
        self.assertIn("s->ota_seq == UINT32_MAX", common)
        self.assertIn('"No factory image, trying OTA 0"', utility)
        self.assertIn("boot_index = 0;", utility)
        self.assertIn("otadata.ota_seq = index + 1;", utility)

    def test_boot_source_commit_build_artifact_and_override_fail_closed(self):
        _, _, _, blobs, _, layout = self.fixture()
        for key, value in (
            ("idf_commit", "0" * 40),
            ("idf_commit", "67c1de1eebe095d554d281952fde63c16ee2dca0"),
            ("idf_image", "espressif/idf:v5.4"),
            (
                "idf_image",
                "espressif/idf:v5.4@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb",
            ),
            ("build_exit_code", False),
            ("build_exit_code", 1),
            ("bootloader_sources_unmodified", False),
            ("idf_sources_sha256", {}),
            ("artifacts_sha256", {}),
        ):
            proof = {**boot_evidence(blobs), key: value}
            raw = fixture.encoded(proof)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                BOOT.verify_boot_rule(blobs, layout, raw, FLEET.sha(raw), REFERENCE)
        for key in BOOT.DISABLED:
            changed = dict(blobs)
            changed["sdkconfig"] += ("\n" + key + "=y\n").encode()
            raw = fixture.encoded(boot_evidence(changed))
            with self.subTest(override=key), self.assertRaises(ValueError):
                BOOT.verify_boot_rule(changed, layout, raw, FLEET.sha(raw), REFERENCE)
        with tempfile.TemporaryDirectory() as tmp:
            for name in BOOT.IDF_SOURCES:
                p = Path(tmp) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes((REFERENCE / name).read_bytes() + b" ")
            with self.assertRaises(ValueError):
                BOOT.verify_sources(tmp)

    def test_both_supported_sources_have_exact_whole_flash_coverage(self):
        for blank in (False, True):
            context, *_ = self.fixture(blank)
            ranges = [(off, len(data)) for off, data in context["blocks"]] + [
                (r["offset"], r["bytes"]) for r in context["unchanged"]
            ]
            end = 0
            for off, size in sorted(ranges):
                self.assertEqual(off, end)
                self.assertEqual(off % 4096, 0)
                self.assertEqual(size % 4096, 0)
                end += size
            self.assertEqual(end, 16 * 1024 * 1024)

    def test_candidate_unknown_layout_overlap_missing_range_and_payload_substitution_reject(
        self,
    ):
        context, original, manifest, blobs, payloads, _ = self.fixture()
        for mutation in (
            "layout",
            "overlap",
            "missing",
            "unchanged",
            "path",
            "promote",
            "bool",
        ):
            candidate = copy.deepcopy(original)
            if mutation == "layout":
                candidate["source_layout_class"] = "automatic"
            elif mutation == "overlap":
                candidate["write_ranges"][1]["offset"] = 0
            elif mutation == "missing":
                candidate["write_ranges"].pop()
            elif mutation == "unchanged":
                candidate["unchanged_ranges"].pop()
            elif mutation == "path":
                candidate["write_ranges"][0]["file"] = "../secret"
            elif mutation == "promote":
                candidate["intended_boot_selection"][
                    "bootloader_selection_verified"
                ] = True
            elif mutation == "bool":
                candidate["write_ranges"][0]["offset"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                INSTALL.validate_candidate(
                    candidate,
                    context["backup"],
                    context["raw"],
                    manifest,
                    blobs,
                    context["node"],
                    payloads,
                    site_context=self.site,
                )
        for name in ("bootloader.bin", "esp32-csi-node.bin"):
            bad = {**payloads, name: b"X" + payloads[name][1:]}
            with self.assertRaises(ValueError):
                INSTALL.validate_candidate(
                    original,
                    context["backup"],
                    context["raw"],
                    manifest,
                    blobs,
                    context["node"],
                    bad,
                    site_context=self.site,
                )

    def test_changed_calibration_or_network_in_prepared_nvs_reject(self):
        context, candidate, manifest, blobs, payloads, _ = self.fixture()
        for key in (("calibration", "opaque"), ("csi_cfg", "ssid")):
            values = FLEET.nvs_tool().logical_values(payloads["nvs-prepared.bin"])
            values[key] = (
                ("blob", b"different")
                if key[0] == "calibration"
                else ("string", "different")
            )
            changed = {
                **payloads,
                "nvs-prepared.bin": FLEET.nvs_tool().generate(values, 0x6000),
            }
            with self.assertRaises(ValueError):
                INSTALL.validate_candidate(
                    candidate,
                    context["backup"],
                    context["raw"],
                    manifest,
                    blobs,
                    context["node"],
                    changed,
                    site_context=self.site,
                )

    def test_live_mismatch_or_changed_backup_never_reserves_or_writes(self):
        context, *_ = self.fixture()
        for mutation in ("mac", "security", "encryption", "capacity", "psram", "flash"):
            esp = FakeESP(context)
            if mutation == "mac":
                esp.mac = "00:11:22:33:44:55"
            elif mutation == "security":
                esp.secure = True
            elif mutation == "encryption":
                esp.encrypted = True
            elif mutation == "capacity":
                esp.flash_id = lambda: 23 << 16
            elif mutation == "psram":
                esp.get_chip_features = lambda: []
            else:
                esp.memory[-1] ^= 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                INSTALL.write_once(
                    esp,
                    context,
                    esp.write,
                    lambda esp=esp: esp.calls.append("reserved"),
                )
            self.assertNotIn("write", esp.calls)
            self.assertNotIn("reserved", esp.calls)

    def test_durable_exclusive_attempt_precedes_only_write_and_reformat_cannot_rearm(
        self,
    ):
        context, *_ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            context["marker"] = Path(tmp) / "attempt.json"
            esp = FakeESP(context)
            calls = []
            fsync = os.fsync

            def synced(fd):
                calls.append("fsync")
                fsync(fd)

            def writer(*args, **kwargs):
                self.assertEqual(calls, ["fsync", "fsync"])
                self.assertEqual(context["marker"].stat().st_mode & 0o777, 0o600)
                esp.write(*args, **kwargs)

            with patch.object(INSTALL.os, "fsync", side_effect=synced):
                result = INSTALL.write_once(
                    esp, context, writer, lambda: INSTALL.reserve_attempt(context)
                )
            self.assertTrue(result["write_verified"])
            self.assertEqual(esp.calls.count("write"), 1)
            with self.assertRaises(FileExistsError):
                INSTALL.reserve_attempt(context)

    def test_reservation_failure_prevents_write(self):
        context, *_ = self.fixture()
        esp = FakeESP(context)

        def fail():
            raise OSError("synthetic reservation failure")

        with self.assertRaises(OSError):
            INSTALL.write_once(esp, context, esp.write, fail)
        self.assertNotIn("write", esp.calls)

    def test_real_pinned_esptool_serial_exception_cannot_restart_any_range(self):
        import esptool.cmds
        from esptool.util import FatalError
        from serial import SerialException

        context, *_ = self.fixture()
        esp = FakeESP(context)
        esp.IS_STUB = True
        esp.secure_download_mode = False
        esp.FLASH_SECTOR_SIZE = 4096
        esp.get_encrypted_download_disabled = lambda: False

        def begin(*args):
            esp.calls.append("begin")
            raise SerialException("synthetic interrupted first range")

        esp.flash_defl_begin = begin
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
            INSTALL.write_once(
                esp,
                context,
                esptool.cmds.write_flash,
                lambda: esp.calls.append("reserved"),
            )
        self.assertEqual(esp.calls[-2:], ["reserved", "begin"])
        self.assertEqual(esp.calls.count("begin"), 1)

    def test_partial_write_and_changed_or_unchanged_corruption_stop_without_reset(self):
        context, *_ = self.fixture()
        for mutation in ("serial_failure", "changed", "unchanged", "success"):
            with tempfile.TemporaryDirectory() as tmp:
                context["marker"] = Path(tmp) / "attempt.json"
                esp = FakeESP(context)
                result = {"write_verified": False}

                def writer(*args, esp=esp, mutation=mutation, **kwargs):
                    esp.write(*args, **kwargs)
                    if mutation == "serial_failure":
                        raise OSError("synthetic uncertain transport")
                    if mutation == "changed":
                        esp.memory[0x20000] ^= 1
                    if mutation == "unchanged":
                        esp.memory[0x11000] ^= 1

                if mutation == "success":
                    INSTALL.execute(
                        context,
                        "synthetic-port",
                        result,
                        lambda *a, esp=esp, **k: esp,
                        lambda esp: None,
                        writer,
                        **self.site_args,
                    )
                else:
                    with (
                        self.subTest(mutation=mutation),
                        self.assertRaises((ValueError, OSError)),
                    ):
                        INSTALL.execute(
                            context,
                            "synthetic-port",
                            result,
                            lambda *a, esp=esp, **k: esp,
                            lambda esp: None,
                            writer,
                            **self.site_args,
                        )
                self.assertEqual(result["write_verified"], mutation == "success")
                self.assertTrue(result["write_attempt_reserved"])
                self.assertTrue(context["marker"].exists())
                self.assertEqual(esp.calls.count("write"), 1)
                self.assertEqual(esp.calls[-1], "close")

    def test_context_change_before_reservation_never_marks_or_writes(self):
        context, *_ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            context["marker"] = Path(tmp) / "attempt.json"
            esp = FakeESP(context)
            original = esp.flash_md5sum

            def changed(*args):
                (self.site_args["site_context"] / "nodes.json").write_bytes(b"{}")
                return original(*args)

            esp.flash_md5sum = changed
            result = {"write_verified": False}
            with (
                patch.object(esp, "write") as write,
                self.assertRaisesRegex(ValueError, "reviewed snapshot"),
            ):
                INSTALL.execute(
                    context,
                    "synthetic",
                    result,
                    lambda *a, **k: esp,
                    lambda esp: None,
                    write,
                    **self.site_args,
                )
            write.assert_not_called()
            self.assertFalse(context["marker"].exists())
            self.assertFalse(result.get("write_attempt_reserved", False))
            self.assertEqual(esp.calls[-1], "close")

    def test_identity_change_before_reservation_never_marks_or_writes(self):
        context, *_ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            context["marker"] = Path(tmp) / "attempt.json"
            esp = FakeESP(context)
            original = esp.flash_md5sum

            def changed(*args):
                self.site_args["installation_identity"].write_bytes(b"{}")
                return original(*args)

            esp.flash_md5sum = changed
            result = {"write_verified": False}
            with (
                patch.object(esp, "write") as write,
                self.assertRaisesRegex(ValueError, "approved SHA256"),
            ):
                INSTALL.execute(
                    context,
                    "synthetic",
                    result,
                    lambda *a, **k: esp,
                    lambda esp: None,
                    write,
                    **self.site_args,
                )
            write.assert_not_called()
            self.assertFalse(context["marker"].exists())
            self.assertFalse(result.get("write_attempt_reserved", False))
            self.assertEqual(esp.calls[-1], "close")

    def save_inputs(self, tmp):
        context, candidate, manifest, blobs, payloads, _ = self.fixture()
        tmp = Path(tmp).resolve()
        backup = FLEET.create_directory(tmp / "backup")
        FLEET.save(backup / "backup.json", context["backup"])
        FLEET.save(backup / "flash.bin", context["raw"])
        prepared = FLEET.create_directory(tmp / "candidate")
        (prepared / "payloads").mkdir(mode=0o700)
        FLEET.save(prepared / "plan.json", candidate)
        for name, data in payloads.items():
            FLEET.save(prepared / "payloads" / name, data)
        bundle = FLEET.create_directory(tmp / "public-build")
        for name, data in blobs.items():
            FLEET.save(bundle / name, data)
        FLEET.save(bundle / "bundle.json", manifest)
        FLEET.save(bundle / "boot-build.json", boot_evidence(blobs))
        review = {
            "schema_version": 1,
            "action": "layout_migration_usb",
            "coordinator_approved": True,
            "build_provenance_reviewed": True,
            "power_loss_recovery_reviewed": True,
            "node_id": 2,
            "expected_mac": context["node"]["mac"],
            "candidate_file": str(prepared / "plan.json"),
            "candidate_sha256": FLEET.sha((prepared / "plan.json").read_bytes()),
            "backup_directory": str(backup),
            "backup_sha256": context["backup"]["flash_sha256"],
            "build_manifest": str(bundle / "bundle.json"),
            "bundle_sha256": FLEET.sha((bundle / "bundle.json").read_bytes()),
            "idf_source_directory": str(REFERENCE),
            "boot_build_evidence": str(bundle / "boot-build.json"),
            "boot_build_evidence_sha256": FLEET.sha(
                (bundle / "boot-build.json").read_bytes()
            ),
            "tool_sha256": INSTALL.tool_hashes(),
        }
        review_path = tmp / "review.json"
        FLEET.save(review_path, review)
        return review_path, review

    def test_review_wrapper_tool_candidate_and_bundle_hashes_are_checked_before_transport(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            path, original = self.save_inputs(tmp)
            context = INSTALL.load_inputs(path, **self.site_args)
            self.assertEqual(context["node"]["node_id"], 2)
            for update in (
                {"coordinator_approved": False},
                {"tool_sha256": {}},
                {"candidate_sha256": "0" * 64},
                {"bundle_sha256": "0" * 64},
                {"boot_build_evidence_sha256": "0" * 64},
                {"expected_mac": "00:11:22:33:44:55"},
                {"power_loss_recovery_reviewed": False},
            ):
                path.write_bytes(fixture.encoded({**original, **update}))
                with self.subTest(update=update), self.assertRaises(ValueError):
                    INSTALL.load_inputs(path, **self.site_args)

    def test_relocated_review_wrapper_cannot_rearm_same_canonical_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, review = self.save_inputs(tmp)
            first = INSTALL.load_inputs(path, **self.site_args)
            other = FLEET.create_directory(Path(tmp).resolve() / "other-review")
            second_path = other / "review.json"
            FLEET.save(second_path, fixture.encoded(review))
            second = INSTALL.load_inputs(second_path, **self.site_args)
            self.assertEqual(first["marker"], second["marker"])
            self.assertEqual(
                first["marker"].parent, Path(review["candidate_file"]).parent
            )
            self.assertNotEqual(first["review_sha256"], second["review_sha256"])
            INSTALL.reserve_attempt(first)
            with self.assertRaises(FileExistsError):
                INSTALL.reserve_attempt(second)

    def test_actual_check_cli_never_opens_or_enumerates_usb_and_redacts_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = self.save_inputs(tmp)
            output = Path(tmp) / "check-output"
            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "install_migration.py",
                        "check",
                        "--site-context",
                        str(self.site_args["site_context"]),
                        "--site-context-sha256",
                        self.site_args["site_context_sha256"],
                        "--installation-identity",
                        str(self.site_args["installation_identity"]),
                        "--installation-identity-sha256",
                        self.site_args["installation_identity_sha256"],
                        "--reviewed-plan",
                        str(path),
                        "--output",
                        str(output),
                    ],
                ),
                patch.object(
                    INSTALL,
                    "usb_ports",
                    side_effect=AssertionError("No USB enumeration in check"),
                ),
                patch.object(
                    INSTALL,
                    "execute",
                    side_effect=AssertionError("No USB action in check"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit) as stop,
            ):
                INSTALL.main()
            self.assertEqual(stop.exception.code, 0)
            result = json.loads((output / "result.json").read_text())
            self.assertTrue(result["offline_gates_passed"])
            self.assertFalse(result["write_verified"])
            self.assertFalse(result["physical_boot_verified"])
            self.assertNotIn("synthetic-secret", (output / "result.json").read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "result.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
