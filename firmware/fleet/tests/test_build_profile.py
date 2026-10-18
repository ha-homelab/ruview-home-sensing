"""Offline profile export and legacy context compatibility, without IDF or USB."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

FIRMWARE = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("fleet_build", FIRMWARE / "fleet/build_profile.py")
fetch = load("fleet_fetch", FIRMWARE / "fetch-source.py")
fleet = load("fleet_lib", FIRMWARE / "fleet/fleetlib.py")


class BuildProfileTests(unittest.TestCase):
    def fixture(self, preferred=False):
        mac = "02:ac:de:77:00:02"
        report = {
            "identity": {
                "chip": "ESP32-S3",
                "flash_bytes": 16 * 1024 * 1024,
                "embedded_psram_bytes": 8 * 1024 * 1024,
                "mac": mac,
            },
            "layout": {"partitions": []},
        }
        plan, overlay = fleet.candidate_plan(
            report,
            {"node_id": 2, "mac": mac},
            1011552,
            "a" * 64,
            "02:ac:de:77:00:03" if preferred else None,
        )
        return plan, overlay.encode()

    def test_default_fetch_copies_generic_inputs_without_private_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            fetch.copy_build_inputs(output)
            for name in (
                "Dockerfile",
                "sdkconfig.home-s3-n16r8",
            ):
                self.assertEqual(
                    (output / name).read_bytes(), (FIRMWARE / name).read_bytes()
                )
            self.assertIn(
                b"RUVIEW_WASM_PUBLIC_KEY_CONFIGURED 0",
                (output / "home_wasm_pubkey.h").read_bytes(),
            )
            self.assertFalse((output / "sdkconfig.home-node2-preferred-ap").exists())
            self.assertFalse((output / "fleet-build/profile.json").exists())
            self.assertTrue((output / "fleet-build/build_profile.py").is_file())

    def test_fleet_fetch_exports_only_allowlisted_private_profile_and_hashes(self):
        plan, overlay = self.fixture(preferred=True)
        plan["private_unexpected_field"] = "secret_must_never_be_copied"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            plan_path, overlay_path = directory / "plan.json", directory / "overlay"
            plan_path.write_text(json.dumps(plan))
            overlay_path.write_bytes(overlay)
            output = directory / "context"
            fetch.copy_build_inputs(output, plan_path, overlay_path, "0.8.8.9")
            profile, actual_overlay = build.load(output / "fleet-build")
            self.assertEqual(actual_overlay, overlay)
            self.assertEqual(profile["firmware_version"], "0.8.8.9")
            self.assertEqual(profile["plan_sha256"], build.sha(plan_path.read_bytes()))
            self.assertFalse(profile["flash_write_authorized"])
            self.assertNotIn("secret_must_never_be_copied", json.dumps(profile))
            # Reusing the identical selected inputs is safe; replacing is not.
            fetch.copy_build_inputs(output, plan_path, overlay_path, "0.8.8.9")
            with self.assertRaisesRegex(ValueError, "replace different"):
                fetch.copy_build_inputs(output, plan_path, overlay_path, "0.8.8.7")

    def test_preferred_fetch_authenticates_overlay_before_creating_context(self):
        _, overlay = self.fixture(preferred=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay_path = root / "overlay"
            overlay_path.write_bytes(overlay)
            overlay_path.chmod(0o600)
            output = root / "context"
            with self.assertRaisesRegex(ValueError, "approval mismatch"):
                fetch.copy_build_inputs(
                    output,
                    preferred_ap_overlay=overlay_path,
                    preferred_ap_overlay_sha256="0" * 64,
                )
            self.assertFalse(output.exists())
            fetch.copy_build_inputs(
                output,
                preferred_ap_overlay=overlay_path,
                preferred_ap_overlay_sha256=build.sha(overlay),
            )
            self.assertTrue((output / "fleet-build/build_profile.py").is_file())
            self.assertFalse((output / "fleet-build/profile.json").exists())
            self.assertFalse((output / "sdkconfig.home-node2-preferred-ap").exists())

    def test_recovery_protocol_requires_explicit_version_and_overlay(self):
        plan, overlay = self.fixture(preferred=True)
        raw = json.dumps(plan).encode()
        recovery = overlay + b"CONFIG_HOME_RUNTIME_RECOVERY_V1=y\n"
        for version in ("0.8.8.8", "0.8.8.9", "0.8.8.13"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                build.prepare(raw, recovery, version)
        for version in ("0.8.8.10", "0.8.8.11", "0.8.8.12"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    build.prepare(raw, overlay, version)
                profile = build.prepare(raw, recovery, version)
                self.assertEqual(
                    build.expected_overlay(profile)["CONFIG_HOME_RUNTIME_RECOVERY_V1"],
                    "y",
                )

    def test_rejects_unknown_hardware_overlay_keys_ap_binding_and_version(self):
        plan, overlay = self.fixture(preferred=True)
        raw = json.dumps(plan).encode()
        for invalid in (
            overlay + b'CONFIG_WIFI_PASSWORD="secret"\n',
            overlay.replace(b"NODE_ID=2", b"NODE_ID=1"),
            overlay.replace(
                b"# CONFIG_LED_GAMMA_VIZ is not set", b"CONFIG_LED_GAMMA_VIZ=y"
            ),
        ):
            with self.assertRaises(ValueError):
                build.prepare(raw, invalid, "0.8.8.9")
        for invalid in ("0.8.8.9\ncommand", "$(true)", "1", "", True):
            with self.assertRaises(ValueError):
                build.prepare(raw, overlay, invalid)
        changed = copy.deepcopy(plan)
        changed["hardware"]["embedded_psram_bytes"] = None
        with self.assertRaises(ValueError):
            build.prepare(json.dumps(changed).encode(), overlay, "0.8.8.9")
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            fetch.copy_build_inputs(Path(directory), firmware_version="0.8.8.9")

    def test_copied_helper_configures_fresh_project_and_checks_real_kconfig_contract(
        self,
    ):
        for preferred in (False, True):
            with (
                self.subTest(preferred=preferred),
                tempfile.TemporaryDirectory() as directory,
            ):
                directory = Path(directory)
                plan, overlay = self.fixture(preferred)
                profile = build.prepare(json.dumps(plan).encode(), overlay, "0.8.8.9")
                public, project = directory / "public", directory / "project"
                project.mkdir()
                build.export(public, profile, overlay)
                build.configure(public, project)
                self.assertEqual((project / "version.txt").read_text(), "0.8.8.9\n")
                self.assertEqual((project / build.CONFIG_NAME).read_bytes(), overlay)
                config = build.settings(
                    (FIRMWARE / "sdkconfig.home-s3-n16r8").read_bytes()
                )
                config.update(build.expected_overlay(profile))
                config.update(
                    CONFIG_IDF_TARGET='"esp32s3"', CONFIG_ESP_WIFI_TX_BUFFER_TYPE="0"
                )
                path = project / "sdkconfig"
                path.write_text("\n".join(f"{k}={v}" for k, v in config.items()))
                build.verify_sdkconfig(public, path)
                original = path.read_text()
                path.write_text(original + "\nCONFIG_HOME_RUNTIME_RECOVERY_V1=y\n")
                with self.assertRaisesRegex(ValueError, "Recovery protocol"):
                    build.verify_sdkconfig(public, path)
                path.write_text(original)
                path.write_text(path.read_text() + '\nCONFIG_IDF_TARGET="esp32s3"\n')
                build.verify_sdkconfig(public, path)
                with self.assertRaisesRegex(ValueError, "fresh sdkconfig"):
                    build.configure(public, project)
                path.write_text(
                    path.read_text().replace(
                        "CONFIG_WASM_VERIFY_SIGNATURE=y",
                        "CONFIG_WASM_VERIFY_SIGNATURE=n",
                    )
                )
                with self.assertRaisesRegex(ValueError, "Generated sdkconfig"):
                    build.verify_sdkconfig(public, path)
                (public / build.CONFIG_NAME).write_bytes(overlay + b"# changed\n")
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    build.load(public)


if __name__ == "__main__":
    unittest.main()
