"""Synthetic, offline coverage/release/UI boundaries; no devices or credentials."""

import copy
import hashlib
import importlib.util
import io
import json
import sys
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from module_manifest_fixture import manifest_arguments
from test_site_context import ContextFixture

from scripts import site_context

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
        spec.loader.exec_module(module)
    return module


record = load("scripts/record-coverage-producer.py", "record_context")
export = load("collector/ui/export-floor-config.py", "export_context")


class EvidenceFixture(ContextFixture):
    def setUp(self):
        super().setUp()
        self.module_flags = manifest_arguments(self.parent)
        self.documents["nodes.json"] = {
            "nodes": [
                {
                    "identity_verified": True,
                    "firmware_node_id": 1,
                    "ip": "192.0.2.1",
                    "mac": "02:00:00:00:00:01",
                    "room": "lab",
                    "floorplan_marker_id": "ruview_example",
                }
            ]
        }
        self.marker = {
            "id": "ruview_example",
            "entity_id": "binary_sensor.ruview_node1_presence",
            "name": "RuView — Bench",
            "room": "lab",
            "position_m": {"x": 1, "y": 2, "z": 3},
            "dimensions_m": {"height": 2},
        }
        self.documents["placements.json"] = {"floor": "example", "items": [self.marker]}
        self.documents["assumed-activity.json"] = {
            "coordinate_frame": "fictional-lab",
            "receivers": [{"node_id": 1, "position_xz_m": [1, 3]}],
            "zones": [
                {
                    "zone_id": "test-zone",
                    "room_id": "lab",
                    "polygon_xz_m": [[0, 0], [4, 0], [4, 4]],
                }
            ],
        }
        for name, value in self.documents.items():
            self.write(name, json.dumps(value).encode())
        self.pin = self.manifest()
        self.output = self.parent / "result.json"

    def context_args(self):
        return ["--site-context", str(self.context), "--site-context-sha256", self.pin]


class CommandBoundaryTests(EvidenceFixture):
    def test_recorder_rejects_changed_context_before_credentials_or_transport(self):
        command = [
            "record",
            "--package-directory",
            str(Path(__file__).parent / "fixtures/modules"),
            "--consumer-metadata",
            "unused",
            "--output-directory",
            str(self.output),
            "--duration",
            "5",
            "--expected-image",
            "example@sha256:" + "a" * 64,
            "--url",
            "http://example.invalid",
            *self.context_args(),
            *self.module_flags,
        ]
        self.write("nodes.json", b'{"nodes": []}')

        class NoCredentials(dict):
            def get(self, key, *args):
                if key in ("RUVIEW_API_TOKEN", "HASS_SERVER", "HA_TOKEN"):
                    raise AssertionError("Credentials read before context approval")
                return super().get(key, *args)

        with (
            patch.object(record, "ReadOnlyHTTP") as http,
            patch.object(record.os, "environ", NoCredentials()),
            redirect_stderr(io.StringIO()),
            patch.object(sys, "argv", command),
        ):
            with self.assertRaises(SystemExit):
                record.main()
            http.assert_not_called()
        self.assertFalse(self.output.exists())


class ExportFixture(EvidenceFixture):
    def setUp(self):
        super().setUp()
        self.model = {
            "id": "fictional-lab",
            "calibration": {
                "x_anchors": [[0, 0], [10, 20]],
                "z_anchors": [[0, 0], [10, 30]],
            },
            "rooms": [
                {
                    "id": "lab",
                    "name": "Lab",
                    "polygon": [[0, 0], [2, 0], [2, 2]],
                    "label": [1, 1],
                }
            ],
            "room_display_ids": {},
            "room_display_names": {},
        }
        self.profile = {
            "model_id": "fictional-lab",
            "floor": "example",
            "zone_labels": {"test-zone": "Test zone"},
        }
        self.model_path, self.model_pin = self.private_json("model.json", self.model)
        self.profile_path, self.profile_pin = self.private_json(
            "profile.json", self.profile
        )

    def private_json(self, name, value):
        path = self.parent / name
        raw = json.dumps(value).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return path, hashlib.sha256(raw).hexdigest()

    def command(self):
        return [
            str(self.model_path),
            "--model-sha256",
            self.model_pin,
            "--profile",
            str(self.profile_path),
            "--profile-sha256",
            self.profile_pin,
            "--source-revision",
            "a" * 40,
            "--output",
            str(self.output),
            *self.context_args(),
        ]


class ExportTests(ExportFixture):
    def test_real_cli_exports_reviewed_geometry_and_private_exclusive_output(self):
        export.main(self.command())
        raw = self.output.read_bytes()
        value = json.loads(raw.decode().split("export const FLOOR = ")[1][:-2])
        self.assertEqual(value["rooms"][0]["polygon"], [[0, 0], [4, 0], [4, 6]])
        self.assertEqual(value["rooms"][0]["label"], [2, 3])
        self.assertEqual(value["receivers"][0]["position"], [1, 3])
        self.assertEqual(value["receivers"][0]["height_m"], 3)
        self.assertEqual(value["zones"][0]["name"], "Test zone")
        self.assertEqual(value["model_sha256"], self.model_pin)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            export.main(self.command())
        self.assertEqual(self.output.read_bytes(), raw)

    def test_model_profile_and_context_pins_are_mandatory_and_independent(self):
        for option in ("--model-sha256", "--profile-sha256", "--site-context-sha256"):
            with self.subTest(option=option):
                command = self.command()
                command[command.index(option) + 1] = "0" * 64
                with self.assertRaises(ValueError):
                    export.main(command)
                self.assertFalse(self.output.exists())
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            export.main([str(self.model_path)])

    def test_model_and_profile_readers_reject_links_bounds_and_nonobjects(self):
        link = self.parent / "link.json"
        link.symlink_to(self.model_path)
        with self.assertRaises(OSError):
            site_context.load_pinned_json(link, self.model_pin)
        with self.assertRaises(ValueError):
            site_context.load_pinned_json(self.model_path, self.model_pin, 1)
        array, pin = self.private_json("array.json", [])
        with self.assertRaises(ValueError):
            site_context.load_pinned_json(array, pin)
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
            array.write_bytes(raw)
            with self.assertRaises(ValueError):
                site_context.load_pinned_json(array, hashlib.sha256(raw).hexdigest())

    def test_export_rechecks_all_inputs_before_publishing(self):
        original = export.render
        for target in (self.context / "nodes.json", self.model_path, self.profile_path):
            before = target.read_bytes()

            def changed(*args, target=target):
                result = original(*args)
                target.write_bytes(b"{}")
                return result

            with (
                self.subTest(target=target.name),
                patch.object(export, "render", changed),
            ):
                with self.assertRaises(ValueError):
                    export.main(self.command())
                self.assertFalse(self.output.exists())
            target.write_bytes(before)

    def test_wrong_identity_or_inconsistent_anchor_cannot_export(self):
        for kind in ("model", "floor", "anchor", "receiver"):
            model, profile, context = copy.deepcopy(
                (self.model, self.profile, self.load())
            )
            if kind == "model":
                model["id"] = "wrong"
            elif kind == "floor":
                profile["floor"] = "wrong"
            elif kind == "anchor":
                context.documents["placements.json"]["items"][0]["position_m"]["x"] = 99
            else:
                context.documents["placements.json"]["items"][0]["entity_id"] = "wrong"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                export.render(
                    model, self.model_path.read_bytes(), profile, context, "a" * 40
                )
