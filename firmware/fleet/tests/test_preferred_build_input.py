"""Exercise real private-input validation and Docker prefetch order offline."""

import importlib.util
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("preferred_build", ROOT / "fleet/build_profile.py")
fetch = load("preferred_fetch", ROOT / "fetch-source.py")


class PreferredBuildInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "private.sdkconfig"
        self.raw = (ROOT / "sdkconfig.home-node2-preferred-ap.example").read_bytes()
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.pin = build.sha(self.raw)

    def test_exact_bytes_and_generated_hardware_guards(self):
        project = self.root / "project"
        project.mkdir()
        build.configure_preferred(self.path, self.pin, project)
        self.assertEqual((project / build.PREFERRED_CONFIG_NAME).read_bytes(), self.raw)
        self.assertEqual(
            (project / build.PREFERRED_CONFIG_NAME).stat().st_mode & 0o777, 0o600
        )
        self.assertEqual((project / "version.txt").read_bytes(), b"0.8.8.8\n")
        config = build.settings((ROOT / "sdkconfig.home-s3-n16r8").read_bytes())
        config.update(build.settings(self.raw))
        config.update(CONFIG_IDF_TARGET='"esp32s3"', CONFIG_ESP_WIFI_TX_BUFFER_TYPE="0")
        generated = project / "sdkconfig"

        def write():
            generated.write_text("\n".join(f"{k}={v}" for k, v in config.items()))

        write()
        build.verify_preferred(self.path, self.pin, generated)
        for key, bad in (
            ("CONFIG_HOME_WIFI_PREFERRED_NODE_ID", "1"),
            ("CONFIG_HOME_WIFI_PREFERRED_STA_MAC", '"02:00:00:00:00:03"'),
            ("CONFIG_HOME_WIFI_PREFERRED_BSSID", '"02:00:00:00:01:03"'),
            ("CONFIG_LED_GAMMA_VIZ", "y"),
            ("CONFIG_WASM_VERIFY_SIGNATURE", "n"),
            ("CONFIG_SPIRAM", "n"),
            ("CONFIG_HOME_CSI_ASSOCIATED_ONLY", "n"),
        ):
            with self.subTest(key=key):
                old = config[key]
                config[key] = bad
                write()
                with self.assertRaises(ValueError):
                    build.verify_preferred(self.path, self.pin, generated)
                config[key] = old
        write()
        self.path.write_bytes(self.raw + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "approval mismatch"):
            build.verify_preferred(self.path, self.pin, generated)

    def test_missing_mismatch_empty_oversize_and_unsafe_files(self):
        with self.assertRaises(ValueError):
            build.read_preferred_overlay(self.root / "missing", self.pin)
        for pin in (None, "", "a" * 64, self.pin.upper()):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                build.read_preferred_overlay(self.path, pin)
        for data in (b"", b"#" * 65537):
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):
                build.read_preferred_overlay(self.path, build.sha(data))
        self.path.write_bytes(self.raw)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            build.read_preferred_overlay(self.path, self.pin)
        self.path.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(self.path)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        for path in (link, fifo, self.root):
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                build.read_preferred_overlay(path, self.pin)

    def test_review_pin_does_not_override_radio_contract(self):
        for raw in (
            self.raw + b"CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE=y\n",
            self.raw + b'CONFIG_WIFI_PASSWORD="never_print_this"\n',
            self.raw.replace(b"NODE_ID=2", b"NODE_ID=1"),
            self.raw.replace(b"02:00:00:00:00:02", b"03:00:00:00:00:02"),
            self.raw.replace(
                b"# CONFIG_LED_GAMMA_VIZ is not set", b"CONFIG_LED_GAMMA_VIZ=y"
            ),
            self.raw + b"CONFIG_HOME_RUNTIME_RECOVERY_V1=y\n",
        ):
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError):
                build.read_preferred_overlay(self.path, build.sha(raw))

    def test_fetch_rejects_before_output_and_never_copies_secret(self):
        output = self.root / "context"
        for kwargs in (
            {"preferred_ap_overlay": self.path},
            {"preferred_ap_overlay_sha256": self.pin},
            {
                "preferred_ap_overlay": self.path,
                "preferred_ap_overlay_sha256": "f" * 64,
            },
        ):
            with self.assertRaises(ValueError):
                fetch.copy_build_inputs(output, **kwargs)
            self.assertFalse(output.exists())
        fetch.copy_build_inputs(
            output, preferred_ap_overlay=self.path, preferred_ap_overlay_sha256=self.pin
        )
        self.assertFalse((output / build.PREFERRED_CONFIG_NAME).exists())
        self.assertFalse(
            any(p.is_file() and p.read_bytes() == self.raw for p in output.rglob("*"))
        )
        stale = output / build.PREFERRED_CONFIG_NAME
        stale.write_bytes(self.raw)
        with self.assertRaisesRegex(ValueError, "fresh context"):
            fetch.copy_build_inputs(output)
        with self.assertRaisesRegex(ValueError, "outside the build context"):
            fetch.copy_build_inputs(
                self.root,
                preferred_ap_overlay=self.path,
                preferred_ap_overlay_sha256=self.pin,
            )

    def test_real_docker_prefetch_shell_blocks_bad_secret_without_git(self):
        docker = (ROOT / "Dockerfile").read_text()
        self.assertNotIn("COPY sdkconfig.home-node2-preferred-ap", docker)
        self.assertEqual(docker.count("--mount=type=secret,id=preferred_ap"), 2)
        instruction = docker.split("RUN --mount=", 1)[1].split("\nCOPY ", 1)[0]
        command = instruction.split("\n", 1)[1].replace("\\\n", "\n")
        command = command.replace(
            "/fleet-build/build_profile.py",
            shlex.quote(str(ROOT / "fleet/build_profile.py")),
        )
        command = command.replace(
            "/run/secrets/preferred_ap", shlex.quote(str(self.path))
        )
        fakebin = self.root / "bin"
        fakebin.mkdir()
        fakegit = fakebin / "git"
        fakegit.write_text('#!/bin/sh\nprintf "called\\n" >> "$CALLS"\n')
        fakegit.chmod(0o700)
        calls = self.root / "calls"
        for mode, data, pin, allowed in (
            ("node2-preferred-ap", None, self.pin, False),
            ("node2-preferred-ap", b"", self.pin, False),
            ("node2-preferred-ap", self.raw, "f" * 64, False),
            ("node2-preferred-ap", self.raw, "", False),
            ("node2-preferred-ap", self.raw, self.pin, True),
            ("home-s3-n16r8", None, "", True),
            ("fleet-reviewed", None, "", True),
            ("unknown", self.raw, self.pin, False),
        ):
            with self.subTest(mode=mode, allowed=allowed):
                calls.unlink(missing_ok=True)
                self.path.unlink(missing_ok=True)
                if data is not None:
                    self.path.write_bytes(data)
                    self.path.chmod(0o600)
                result = subprocess.run(
                    ["bash", "-c", command],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": str(fakebin) + os.pathsep + os.environ["PATH"],
                        "CALLS": str(calls),
                        "FIRMWARE_PROFILE": mode,
                        "PREFERRED_AP_SHA256": pin,
                    },
                    timeout=10,
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                self.assertEqual(calls.exists(), allowed)
                if allowed:
                    self.assertEqual(calls.read_text().splitlines(), ["called"] * 4)


if __name__ == "__main__":
    unittest.main()
