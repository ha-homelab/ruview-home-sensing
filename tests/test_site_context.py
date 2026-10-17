"""Offline private-context trust boundary and operator-command regressions."""

import argparse
import asyncio
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from test_dhcp import dhcp_arguments

from scripts import site_context

ROOT = Path(__file__).resolve().parents[1]


def load_script(filename, module_name):
    spec = importlib.util.spec_from_file_location(
        module_name, ROOT / "scripts" / filename
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dhcp = load_script("reserve-dhcp.py", "scripts.context_dhcp")
floorplan = load_script("sync-floorplan.py", "scripts.context_floorplan")


class ContextFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.context = self.parent / "context"
        self.context.mkdir(mode=0o700)
        self.documents = {
            name: {"schema": "independent-example"} for name in site_context.FILES
        }
        self.documents["nodes.json"] = {"nodes": [{"identity_verified": False}]}
        self.documents["placements.json"] = {
            "floor": "example",
            "items": [{"id": "ruview_example", "room": "lab"}],
        }
        for name, value in self.documents.items():
            self.write(name, json.dumps(value).encode())
        self.pin = self.manifest()

    def write(self, name, raw):
        path = self.context / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def manifest(self, transform=lambda value: value):
        value = {
            "schema": "ruview.private-site-context.v1",
            "files": {
                name: hashlib.sha256((self.context / name).read_bytes()).hexdigest()
                for name in site_context.FILES
            },
        }
        raw = json.dumps(transform(value), sort_keys=True).encode()
        self.write("manifest.json", raw)
        return hashlib.sha256(raw).hexdigest()

    def load(self):
        return site_context.load_site_context(self.context, self.pin)

    def args(self, **changes):
        values = {
            "site_context": self.context,
            "site_context_sha256": self.pin,
            "apply": False,
            "update_owned": False,
            "backup_dir": str(self.parent / "backup"),
        }
        values.update(changes)
        return argparse.Namespace(**values)


class LoaderTests(ContextFixture):
    def test_all_exact_bytes_and_parsed_documents_are_preserved(self):
        result = self.load()
        self.assertEqual(result.manifest_sha256, self.pin)
        self.assertEqual(result.documents, self.documents)
        for name in site_context.FILES:
            self.assertEqual(result.raw[name], (self.context / name).read_bytes())

    def test_manifest_pin_is_independent_and_checked_before_reading_inputs(self):
        original = site_context._read
        names = []

        def read(*args):
            names.append(args[1])
            return original(*args)

        with (
            patch.object(site_context, "_read", side_effect=read),
            self.assertRaisesRegex(ValueError, "approved SHA256"),
        ):
            site_context.load_site_context(self.context, "0" * 64)
        self.assertEqual(names, ["manifest.json"])

    def test_changed_document_or_manifest_cannot_authorize_itself(self):
        self.write("nodes.json", b'{"nodes": []}')
        with self.assertRaisesRegex(ValueError, "reviewed snapshot"):
            self.load()
        self.manifest()  # Attacker changes both content and its colocated manifest.
        with self.assertRaisesRegex(ValueError, "approved SHA256"):
            self.load()

    def test_invalid_pins_and_manifest_inventory_are_rejected(self):
        for pin in ("", "A" * 64, "x" * 64, None):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                site_context.load_site_context(self.context, pin)
        for change in (
            lambda m: {**m, "extra": True},
            lambda m: {**m, "schema": "wrong"},
            lambda m: {**m, "files": {**m["files"], "../outside.json": "a" * 64}},
            lambda m: {**m, "files": {}},
        ):
            self.pin = self.manifest(change)
            with self.assertRaises(ValueError):
                self.load()

    def test_duplicate_keys_nonfinite_and_nonobject_inputs_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b"[]"):
            with self.subTest(raw=raw):
                self.write("nodes.json", raw)
                self.pin = self.manifest()
                with self.assertRaises(ValueError):
                    self.load()

    def test_missing_file_and_symlink_inputs_are_rejected(self):
        path = self.context / "nodes.json"
        data = path.read_bytes()
        path.unlink()
        with self.assertRaises(OSError):
            self.load()
        outside = self.parent / "outside.json"
        outside.write_bytes(data)
        outside.chmod(0o600)
        path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.load()

    def test_symlink_context_and_parent_are_rejected(self):
        alias = self.parent / "alias"
        alias.symlink_to(self.context, target_is_directory=True)
        with self.assertRaises(OSError):
            site_context.load_site_context(alias, self.pin)
        parent_alias = self.parent / "parent-alias"
        parent_alias.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            site_context.load_site_context(parent_alias / "context", self.pin)

    def test_private_permissions_are_required(self):
        self.context.chmod(0o755)
        with self.assertRaises(ValueError):
            self.load()
        self.context.chmod(0o700)
        (self.context / "nodes.json").chmod(0o644)
        with self.assertRaises(ValueError):
            self.load()

    def test_manifest_and_file_size_bounds_and_fifo(self):
        self.write("manifest.json", b" " * (site_context.MAX_MANIFEST_BYTES + 1))
        with self.assertRaises(ValueError):
            self.load()
        self.pin = self.manifest()
        self.write("nodes.json", b" " * (site_context.MAX_INPUT_BYTES + 1))
        with self.assertRaises(ValueError):
            self.load()
        (self.context / "nodes.json").unlink()
        os.mkfifo(self.context / "nodes.json", mode=0o600)
        with self.assertRaises(ValueError):
            self.load()

    def test_directory_replacement_does_not_change_open_snapshot(self):
        original = site_context._read
        renamed = self.parent / "original"
        changed = False

        def read(*args):
            nonlocal changed
            if not changed:
                changed = True
                self.context.rename(renamed)
                self.context.mkdir(mode=0o700)
            return original(*args)

        with patch.object(site_context, "_read", side_effect=read):
            result = self.load()
        self.assertEqual(result.documents, self.documents)
        self.assertEqual(list(self.context.iterdir()), [])


class CommandTests(ContextFixture):
    def test_both_commands_require_explicit_context_and_independent_pin(self):
        for module in (dhcp, floorplan):
            with self.subTest(command=module.__name__), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    module.main([])
                self.assertEqual(error.exception.code, 2)
                with self.assertRaises(SystemExit) as error:
                    module.main(["--site-context", str(self.context)])
                self.assertEqual(error.exception.code, 2)

    def test_dhcp_invalid_context_or_inventory_never_calls_ssh(self):
        flags = dhcp_arguments(self.parent / "dhcp")
        with patch.object(
            dhcp, "ssh", side_effect=AssertionError("network forbidden")
        ) as ssh:
            invalid_pin = flags.copy()
            invalid_pin[3] = "0" * 64
            with self.assertRaises(ValueError):
                dhcp.main(invalid_pin)
            context = Path(flags[1])
            raw = b'{"nodes":[{"identity_verified":true,"mac":"invalid","name":"invalid","ip":"192.0.2.1"}]}'
            (context / "nodes.json").write_bytes(raw)
            manifest = json.loads((context / "manifest.json").read_text())
            manifest["files"]["nodes.json"] = hashlib.sha256(raw).hexdigest()
            raw = json.dumps(manifest).encode()
            (context / "manifest.json").write_bytes(raw)
            flags[3] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                dhcp.main(flags)
            ssh.assert_not_called()

    def test_dhcp_valid_snapshot_retains_read_only_default(self):
        flags = dhcp_arguments(self.parent / "dhcp")
        with (
            patch.object(dhcp, "ssh", side_effect=["", "config dhcp", ""]) as ssh,
            redirect_stdout(io.StringIO()),
        ):
            dhcp.main(flags)
        self.assertEqual(
            [c.args[0] for c in ssh.call_args_list],
            ["uci changes dhcp", "cat /etc/config/dhcp", "uci export dhcp"],
        )
        self.assertFalse((self.parent / "backup").exists())

    def test_floorplan_invalid_context_or_marker_never_reads_credentials_or_connects(
        self,
    ):
        with (
            patch.object(
                floorplan, "connect", side_effect=AssertionError("network forbidden")
            ) as connect,
            patch.dict(os.environ, {}, clear=True),
        ):
            with self.assertRaises(ValueError):
                asyncio.run(floorplan.run(self.args(site_context_sha256="0" * 64)))
            self.write(
                "placements.json", b'{"floor":"example","items":[{"id":"unowned"}]}'
            )
            self.pin = self.manifest()
            with self.assertRaises(ValueError):
                asyncio.run(floorplan.run(self.args()))
            connect.assert_not_called()

    def test_floorplan_preserves_revision_guard_unrelated_markers_and_private_backup(
        self,
    ):
        class Socket:
            def __init__(self):
                self.sent = []
                self.received = iter(
                    [
                        {"type": "auth_required"},
                        {"type": "auth_ok"},
                        {
                            "success": True,
                            "result": {
                                "revision": 7,
                                "items": [{"id": "unrelated", "room": "other"}],
                            },
                        },
                        {"success": True, "result": {"revision": 8}},
                    ]
                )

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return None

            async def recv(self):
                return json.dumps(next(self.received))

            async def send(self, raw):
                self.sent.append(json.loads(raw))

        socket = Socket()
        with (
            patch.object(floorplan, "connect", return_value=socket),
            patch.dict(
                os.environ,
                {
                    "HASS_SERVER": "https://example.invalid",
                    "HA_TOKEN": "synthetic-token",
                },
            ),
            redirect_stdout(io.StringIO()),
        ):
            asyncio.run(floorplan.run(self.args(apply=True)))
        request = socket.sent[-1]
        self.assertEqual(request["type"], "home_floorplan/save")
        self.assertEqual(request["revision"], 7)
        self.assertEqual(
            request["items"],
            [
                {"id": "unrelated", "room": "other"},
                *self.documents["placements.json"]["items"],
            ],
        )
        backup = self.parent / "backup" / "floorplan-example-revision-7.json"
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            json.loads(backup.read_text())["items"],
            [{"id": "unrelated", "room": "other"}],
        )


if __name__ == "__main__":
    unittest.main()
