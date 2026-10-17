"""Every inventory consumer rejects unapproved context before device activity."""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import esptool
from site_fixture import site_fixture

ROOT = Path(__file__).resolve().parents[3]


def load(filename):
    path = ROOT / "firmware" / filename
    spec = importlib.util.spec_from_file_location("context_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(ROOT / "firmware/fleet"), *sys.path]):
        spec.loader.exec_module(module)
    return module


class FirmwareContextCommands(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.site, _ = site_fixture(self.parent)

    def commands(self):
        output = str(self.parent / "not-created")
        return [
            (
                "ota-update.py",
                [
                    "--node",
                    "1",
                    "--key-file",
                    "missing",
                    "--firmware",
                    "missing",
                    "--sha256",
                    "a" * 64,
                    "--version",
                    "test",
                    "--expect-current",
                    "old",
                ],
            ),
            (
                "fleet/prepare.py",
                [
                    "--backup",
                    "missing",
                    "--node",
                    "1",
                    "--firmware",
                    "missing",
                    "--sha256",
                    "a" * 64,
                    "--version",
                    "test",
                    "--output",
                    output,
                ],
            ),
            (
                "fleet/backup.py",
                [
                    "identify",
                    "--port",
                    "synthetic",
                    "--node",
                    "1",
                    "--allow-reset",
                    "--output",
                    output,
                ],
            ),
            (
                "fleet/install.py",
                [
                    "--reviewed-plan",
                    "missing",
                    "--port",
                    "synthetic",
                    "--output",
                    output,
                ],
            ),
            (
                "fleet/install_migration.py",
                ["check", "--reviewed-plan", "missing", "--output", output],
            ),
            (
                "fleet/plan_migration.py",
                [
                    "--backup",
                    "missing",
                    "--node",
                    "1",
                    "--build-manifest",
                    "missing",
                    "--bundle-sha256",
                    "a" * 64,
                    "--source-layout",
                    "two-ota-preserve-data",
                    "--output",
                    output,
                ],
            ),
            (
                "fleet/direct_usb.py",
                [
                    "prepare",
                    "--inspection",
                    "missing",
                    "--node",
                    "1",
                    "--expected-mac",
                    "02:00:00:00:00:01",
                    "--firmware",
                    "missing",
                    "--sha256",
                    "a" * 64,
                    "--version",
                    "test",
                    "--output",
                    output,
                ],
            ),
        ]

    def test_missing_or_bad_independent_pin_stops_all_seven_commands(self):
        for filename, arguments in self.commands():
            module = load(filename)
            with (
                self.subTest(command=filename),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with (
                    patch.object(sys, "argv", [filename, *arguments]),
                    self.assertRaises(SystemExit),
                ):
                    module.main()
                for site_pin, identity_pin in (
                    ("0" * 64, self.site["installation_identity_sha256"]),
                    ("invalid", self.site["installation_identity_sha256"]),
                    (self.site["site_context_sha256"], "0" * 64),
                    (self.site["site_context_sha256"], "invalid"),
                ):
                    argv = [
                        filename,
                        *arguments,
                        "--site-context",
                        str(self.site["site_context"]),
                        "--site-context-sha256",
                        site_pin,
                        "--installation-identity",
                        str(self.site["installation_identity"]),
                        "--installation-identity-sha256",
                        identity_pin,
                    ]
                    output = io.StringIO()
                    with (
                        patch.object(sys, "argv", argv),
                        patch.object(esptool, "detect_chip") as device,
                        patch("serial.tools.list_ports.comports") as ports,
                        patch("subprocess.check_output") as process,
                        patch("urllib.request.build_opener") as http,
                        contextlib.redirect_stdout(output),
                    ):
                        if filename.endswith("direct_usb.py"):
                            self.assertEqual(module.main(), 1)
                            self.assertEqual(
                                json.loads(output.getvalue())["error_type"],
                                "ValueError",
                            )
                        else:
                            with self.assertRaisesRegex(ValueError, "approved.*SHA256"):
                                module.main()
                        for operation in (device, ports, process, http):
                            operation.assert_not_called()
                    self.assertFalse((self.parent / "not-created").exists())

    def test_port_listing_keeps_its_inventory_free_behavior(self):
        module = load("fleet/backup.py")
        with (
            patch.object(sys, "argv", ["backup.py", "list-ports"]),
            patch.object(module, "load_installation_context") as context,
            patch.object(module, "usb_ports", return_value=[]) as ports,
            patch.object(esptool, "detect_chip") as device,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            module.main()
        context.assert_not_called()
        device.assert_not_called()
        ports.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
