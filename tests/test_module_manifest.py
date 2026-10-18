"""Approval boundaries use fictional identities and never contact a receiver."""

import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from installation_fixture import InstallationFixture
from module_manifest_fixture import FIXTURE, catalog, manifest_arguments
from test_evidence_context import record
from test_modules import modules

from scripts.module_manifest import load_module_manifest

ROOT = Path(__file__).resolve().parents[1]


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "manifest.json"
        self.raw = FIXTURE.read_bytes()
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.pin = hashlib.sha256(self.raw).hexdigest()

    def test_exact_private_bytes_and_pin_are_retained(self):
        value = load_module_manifest(self.path, self.pin)
        self.assertEqual(
            (value.raw, value.document, value.sha256), (self.raw, catalog(), self.pin)
        )
        self.assertEqual(modules.load_approved_manifest(self.path, self.pin), catalog())

    def test_wrong_or_missing_approval_does_not_open_runtime_file(self):
        for pin in (None, "", "x" * 64, self.pin.upper()):
            with self.subTest(pin=pin), patch.object(modules.os, "open") as opening:
                with self.assertRaises(ValueError):
                    modules.load_approved_manifest(self.path, pin)
                opening.assert_not_called()
        self.path.write_bytes(self.raw + b" ")
        for loader in (load_module_manifest, modules.load_approved_manifest):
            with self.subTest(loader=loader.__name__), self.assertRaises(ValueError):
                loader(self.path, self.pin)

    def test_bounded_duplicate_key_and_nonfinite_inputs_rejected(self):
        for raw in (
            b" " * 65537,
            b'{"packages":[],"packages":[]}',
            b'{"packages":[],"x":NaN}',
        ):
            self.path.write_bytes(raw)
            pin = hashlib.sha256(raw).hexdigest()
            for loader in (load_module_manifest, modules.load_approved_manifest):
                with (
                    self.subTest(raw_length=len(raw), loader=loader.__name__),
                    self.assertRaises(ValueError),
                ):
                    loader(self.path, pin)

    def test_private_catalog_schema_retains_existing_one_to_three_bound(self):
        for value in (
            {"schema_version": True, "packages": [{}]},
            {"schema_version": 1, "packages": []},
            {"schema_version": 1, "packages": [{}] * 4},
        ):
            raw = json.dumps(value).encode()
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError):
                load_module_manifest(self.path, hashlib.sha256(raw).hexdigest())

    def test_runtime_projection_symlink_hashes_opened_bytes_only(self):
        projection = self.root / "projection.json"
        projection.symlink_to(self.path)
        self.assertEqual(
            modules.load_approved_manifest(projection, self.pin), catalog()
        )
        original = modules.os.open
        calls = []

        def swapped(path, flags):
            fd = original(path, flags)
            calls.append(path)
            alternate = self.root / "other.json"
            alternate.write_bytes(b'{"packages":[]}')
            projection.unlink()
            projection.symlink_to(alternate)
            return fd

        with patch.object(modules.os, "open", side_effect=swapped):
            self.assertEqual(
                modules.load_approved_manifest(projection, self.pin), catalog()
            )
        self.assertEqual(len(calls), 1)
        with self.assertRaises(ValueError):
            modules.load_approved_manifest(projection, self.pin)
        with self.assertRaises(OSError):
            load_module_manifest(projection, self.pin)

    def test_runtime_fifo_is_rejected_without_blocking(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            modules.load_approved_manifest(fifo, self.pin)

    def test_cli_rejects_missing_or_changed_pin_before_packages_state_or_network(self):
        for extra in ([], ["--manifest-sha256", "0" * 64]):
            with (
                self.subTest(extra=extra),
                patch("sys.argv", ["reconcile", "--directory", str(self.root), *extra]),
                patch("sys.stderr", io.StringIO()),
                patch.object(modules, "package_bytes") as package,
                patch.object(modules, "make_request") as request,
                patch.object(modules, "reconcile") as reconcile,
            ):
                with self.assertRaises((ValueError, SystemExit)):
                    modules.main()
                package.assert_not_called()
                request.assert_not_called()
                reconcile.assert_not_called()
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_synthetic_catalog_does_not_authorize_another_installation(self):
        manifest = modules.load_approved_manifest(self.path, self.pin)
        packages = [
            (p, (ROOT / "tests/fixtures/modules" / p["file"]).read_bytes())
            for p in manifest["packages"]
        ]
        for package in manifest["packages"]:
            for binding in package["qualified_boot_restore_targets"]:
                target = binding | {
                    "enabled": True,
                    "package_sha256": package["sha256"],
                }
                modules.boot_binding(target, packages)
                for key, value in (("ip", "192.0.2.77"), ("mac", "02:00:00:77:77:77")):
                    changed = target | {key: value}
                    with self.assertRaisesRegex(
                        ValueError, "Exact boot target qualification"
                    ):
                        modules.boot_binding(changed, packages)


class CommandApprovalTests(InstallationFixture):
    def test_evidence_commands_reject_module_changes_before_credentials(self):
        flags = manifest_arguments(self.parent)
        Path(flags[1]).write_bytes(Path(flags[1]).read_bytes() + b" ")
        context = [
            "--site-context",
            str(self.context),
            "--site-context-sha256",
            self.pin,
        ]
        output = self.parent / "output"
        recorder = [
            "record",
            "--package-directory",
            str(Path(__file__).parent / "fixtures/modules"),
            "--consumer-metadata",
            "unused",
            "--output-directory",
            str(output),
            "--duration",
            "5",
            "--expected-image",
            "example@sha256:" + "a" * 64,
            "--url",
            "http://example.invalid",
            *context,
            *flags,
        ]

        class NoCredentials(dict):
            def get(self, key, *args):
                if key in ("RUVIEW_API_TOKEN", "HASS_SERVER", "HA_TOKEN"):
                    raise AssertionError("credentials read before approval")
                return super().get(key, *args)

        with (
            patch.object(record.os, "environ", NoCredentials()),
            patch.object(record, "ReadOnlyHTTP") as http,
            patch("sys.stderr", io.StringIO()),
        ):
            with patch("sys.argv", recorder), self.assertRaises(SystemExit):
                record.main()
            http.assert_not_called()
        self.assertFalse(output.exists())
