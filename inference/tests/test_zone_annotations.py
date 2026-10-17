"""Synthetic recorder-to-sidecar tests; no household labels or live calls."""

import argparse
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from inference import reference_session as ref
from inference import session_commands
from inference import zone_annotations as annotations
from inference.feature_contracts import FEATURE_CONTRACT
from inference.pipeline import digest
from inference.tests import test_reference_alignment
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.tests.test_pipeline import profile
from inference.tests.test_reference_alignment import (
    LOCAL,
    stamp,
)


class ZoneAnnotationTests(unittest.TestCase):
    def setUp(self):
        self.source = test_reference_alignment.ReferenceAlignmentTests()
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        capture = self.source.capture
        capture.rows = [row for row in capture.rows if row["node_id"] == 1]
        for index, row in enumerate(capture.rows, 1):
            row["capture_sequence"] = index
        capture.opening["node_ids"] = capture.terminal["node_ids"] = [1]
        capture.terminal["counters"].update(
            admitted=len(capture.rows),
            enqueued=len(capture.rows),
            written=len(capture.rows),
        )
        capture.terminal["raw"]["frames"] = len(capture.rows)
        capture.write_files()
        capture.prepare_context()
        self.root = self.source.capture.root
        self.serial = 0
        self.make()

    def make(self, count=1):
        self.serial += 1
        self.run = self.root / f"case-{self.serial}"
        self.run.mkdir()
        self.reference, self.export = self.run / "reference", self.run / "export"

        def observed_stamp(offset):
            return {
                **LOCAL,
                **stamp(self.source.capture.base + offset, 90_000_000_000 + offset),
            }

        ref.initialize(
            self.reference,
            self.source.capture.opening,
            [profile(1)],
            None,
            {
                "transition_margin_ns": 10_000_000,
                "max_clock_step_ns": 1_000_000,
                "max_stamp_bracket_ns": 1_000_000,
            },
            "synthetic observer",
            observed_stamp(9_100_000_000),
            opening_raw=(self.root / "opening.json").read_bytes(),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        observation = {
            "person_count": count,
            "posture": None,
            "point_id": None,
            "room_id": "K",
            "source": "manual_observation",
            "provenance": "synthetic only",
            "time_uncertainty_ns": 10_000_000,
            "truth_uncertainty": "",
            "frame_evidence_reference": None,
        }
        for trial, start, end in (
            ("first", 9_200_000_000, 11_600_000_000),
            ("no-window", 11_700_000_000, 11_950_000_000),
        ):
            for event, offset in (("begin", start), ("end", end)):
                ref.mark(
                    self.reference,
                    trial,
                    event,
                    observation,
                    stamp=observed_stamp(offset),
                    expected_coordinate_frame="example_lab_xz_metres",
                )
        ref.review(
            self.reference,
            "synthetic reviewer",
            "synthetic evidence",
            True,
            observed_stamp(13_000_000_000),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        ref.export(
            self.reference,
            self.export,
            [1],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.paired, self.report, self.definition = (
            self.run / name
            for name in ("paired.jsonl", "pair-report.json", "definition.json")
        )
        self.geometry = self.run / "geometry.json"
        self.write(
            self.geometry,
            {
                "schema": "home_floorplan.zone_geometry.v1",
                "node_id": 1,
                "room_id": "K",
                "zones": [
                    {"zone_id": "zone_a", "polygon_m": [[0, 0], [1, 0], [1, 1]]},
                    {"zone_id": "zone_b", "polygon_m": [[2, 0], [3, 0], [3, 1]]},
                ],
                "floorplan_sha256": "b" * 64,
                "status": "synthetic_unverified",
            },
        )
        scope = {
            "schema": "ruview.zone_definition.v1",
            "zone_ids": ["zone_a", "zone_b"],
            "room_id": "K",
            "floorplan_sha256": "b" * 64,
            "zone_geometry_sha256": ref.raw_hash(self.geometry.read_bytes()),
        }
        scope["definition_sha256"] = digest(scope)
        for name, value in (
            ("definition", scope),
            ("profiles", [profile(1)]),
            ("before", self.source.before),
            ("after", self.source.after),
        ):
            self.write(self.run / (name + ".json"), value)
        args = argparse.Namespace(
            expected_coordinate_frame="example_lab_xz_metres",
            command="pair-session",
            frames=self.root / "raw.jsonl",
            opening=self.root / "opening.json",
            terminal=self.root / "terminal.json",
            manifest=self.root / "manifest.json",
            capture_report=self.root / "report.json",
            profiles=self.run / "profiles.json",
            reference_directory=self.reference,
            reference_export=self.export,
            clock_before=self.run / "before.json",
            clock_after=self.run / "after.json",
            clock_assumption_reference="synthetic between-probe assumption",
            between_probe_allowance_ns=1_000_000,
            max_label_uncertainty_ns=100_000_000,
            window_ms=200,
            max_gap_ms=250,
            min_frames=3,
            feature_contract=FEATURE_CONTRACT,
            output=self.paired,
            report_output=self.report,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            session_commands.run(args)
        self.inputs = self.load()
        self.value = annotations.template(self.inputs)
        self.value["review"].update(
            reviewed=True,
            reviewer="synthetic reviewer",
            evidence="synthetic interval notes",
            observations_independent_of_csi=True,
        )
        for index, row in enumerate(self.value["intervals"]):
            row.update(
                reference_id=f"trial-{index}",
                room_id="K",
                person_count=count,
                source="manual_observation",
                zone_id="zone_a" if count == 1 else "unknown",
                condition="single_zone_movement"
                if count == 1
                else "empty"
                if count == 0
                else "simultaneous_zones",
                provenance="synthetic complete interval observation",
                observed_throughout_interval=True,
                truth_uncertainty="",
            )

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value) + "\n")

    def load(self):
        return annotations.load_inputs(
            self.reference,
            self.export,
            self.paired,
            self.report,
            self.definition,
            self.geometry,
            expected_coordinate_frame="example_lab_xz_metres",
        )

    def converted(self, value=None):
        return annotations.convert(
            self.inputs, self.value if value is None else value, "d" * 64
        )

    def test_actual_export_pair_import_preserves_data_and_zero_window_interval(self):
        path, output = self.run / "annotations.json", self.run / "imported"
        self.write(path, self.value)
        original = {p: p.read_bytes() for p in self.inputs["paths"].values()}
        receipt = annotations.import_annotations(self.inputs, path, output)
        records = json.loads((output / "records.json").read_bytes())
        self.assertEqual([r["paired"] for r in records], self.inputs["records"])
        self.assertEqual(receipt["intervals"], 2)
        self.assertIn(0, receipt["windows_per_original_label"].values())
        self.assertFalse(receipt["raw_capture_reverified"])
        self.assertFalse(receipt["observation_truth_authenticated"])
        self.assertFalse(receipt["recognition_validated"])
        self.assertTrue(receipt["geometry_identity_verified"])
        self.assertFalse(receipt["physical_geometry_verified"])
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for file in output.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(original, {p: p.read_bytes() for p in original})
        with self.assertRaises(FileExistsError):
            annotations.import_annotations(self.inputs, path, output)

    def test_unreviewed_template_is_never_accepted(self):
        value = annotations.template(self.inputs)
        self.assertIsNone(value["intervals"][0]["zone_id"])
        self.assertIsNone(value["intervals"][0]["person_count"])
        with self.assertRaisesRegex(ValueError, "review"):
            self.converted(value)
        for field, changed in (
            ("reviewed", False),
            ("reviewer", ""),
            ("evidence", None),
            ("observations_independent_of_csi", False),
        ):
            with self.subTest(field=field):
                value = copy.deepcopy(self.value)
                value["review"][field] = changed
                with self.assertRaises(ValueError):
                    self.converted(value)

    def test_partial_unsafe_or_contradictory_observations_are_rejected(self):
        row = self.value["intervals"][0]
        cases = [
            ("reference_id", "../escape"),
            ("reference_id", "а"),
            ("trial_id", "other"),
            ("original_label_sha256", "e" * 64),
            ("start_ns", row["start_ns"] + 1),
            ("end_ns", row["end_ns"] - 1),
            ("person_count", True),
            ("person_count", 2),
            ("room_id", "other"),
            ("source", "csi_prediction"),
            ("zone_id", "unknown"),
            ("condition", "empty"),
            ("provenance", ""),
            ("observed_throughout_interval", False),
            ("truth_uncertainty", "might have crossed zone boundary"),
        ]
        for field, changed in cases:
            with self.subTest(field=field):
                value = copy.deepcopy(self.value)
                value["intervals"][0][field] = changed
                with self.assertRaises(ValueError):
                    self.converted(value)
        for kind in ("missing", "duplicate_label", "duplicate_id", "contradictory"):
            with self.subTest(kind=kind):
                value = copy.deepcopy(self.value)
                if kind == "missing":
                    value["intervals"].pop()
                elif kind == "duplicate_id":
                    value["intervals"][1]["reference_id"] = value["intervals"][0][
                        "reference_id"
                    ]
                else:
                    value["intervals"][1] = {
                        **value["intervals"][0],
                        "reference_id": "other",
                    }
                    if kind == "contradictory":
                        value["intervals"][1]["zone_id"] = "zone_b"
                with self.assertRaises(ValueError):
                    self.converted(value)

    def test_all_five_negative_conditions_and_counts(self):
        for condition in ("stationary", "outside_zones", "transition"):
            value = copy.deepcopy(self.value)
            for interval in value["intervals"]:
                interval.update(zone_id="unknown", condition=condition)
            self.assertTrue(self.converted(value))
        for count in (0, 2):
            self.make(count)
            self.assertTrue(self.converted())
            value = copy.deepcopy(self.value)
            value["intervals"][0]["condition"] = "stationary"
            with self.assertRaisesRegex(ValueError, "count"):
                self.converted(value)

    def test_annotation_input_pins_and_geometry_are_required(self):
        for field, changed in (
            ("node_id", 2),
            ("node_id", True),
            ("definition_sha256", "e" * 64),
            ("input_sha256", {}),
        ):
            value = copy.deepcopy(self.value)
            value[field] = changed
            with self.assertRaises(ValueError):
                self.converted(value)
        definition = json.loads(self.definition.read_bytes())
        definition["floorplan_sha256"] = "e" * 64
        definition["definition_sha256"] = digest(
            {k: v for k, v in definition.items() if k != "definition_sha256"}
        )
        self.write(self.definition, definition)
        with self.assertRaisesRegex(ValueError, "floorplan"):
            self.load()

    def test_original_chain_and_export_cannot_be_replaced(self):
        for path in (
            self.reference / "events/000000.json",
            self.reference / "review.json",
            self.export / "labels.jsonl",
            self.export / "receipt.json",
        ):
            raw = path.read_bytes()
            try:
                value = json.loads(raw)
                value["tampered"] = True
                self.write(path, value)
                with self.assertRaises(ValueError):
                    self.load()
            except json.JSONDecodeError:
                path.write_bytes(raw.replace(b"synthetic", b"changed", 1))
                with self.assertRaises(ValueError):
                    self.load()
            finally:
                path.write_bytes(raw)

    def test_geometry_original_bytes_and_receiver_identity_are_required(self):
        geometry_raw, definition_raw = (
            self.geometry.read_bytes(),
            self.definition.read_bytes(),
        )
        for field, value in (
            ("node_id", 2),
            ("node_id", True),
            ("room_id", "L"),
            ("zones", [{"zone_id": "zone_b"}, {"zone_id": "zone_a"}]),
            ("zones", [{"zone_id": "zone_a"}]),
            ("floorplan_sha256", "e" * 64),
            ("schema", "unrecognized"),
        ):
            with self.subTest(field=field, value=value):
                geometry, definition = (
                    json.loads(geometry_raw),
                    json.loads(definition_raw),
                )
                geometry[field] = value
                self.write(self.geometry, geometry)
                definition["zone_geometry_sha256"] = ref.raw_hash(
                    self.geometry.read_bytes()
                )
                definition["definition_sha256"] = digest(
                    {k: v for k, v in definition.items() if k != "definition_sha256"}
                )
                self.write(self.definition, definition)
                with self.assertRaisesRegex(ValueError, "geometry"):
                    self.load()
        self.definition.write_bytes(definition_raw)
        self.geometry.write_bytes(geometry_raw + b"\n")
        with self.assertRaisesRegex(ValueError, "geometry bytes"):
            self.load()

    def test_changed_pair_records_fail_even_with_recomputed_report_hash(self):
        pair_raw, report_raw = self.paired.read_bytes(), self.report.read_bytes()
        for mutation in (
            "label",
            "partial_window",
            "header",
            "duplicate",
            "scope",
            "uncertainty",
            "count",
        ):
            with self.subTest(mutation=mutation):
                pairs = [json.loads(line) for line in pair_raw.splitlines()]
                report = json.loads(report_raw)
                if mutation == "label":
                    pairs[0]["original_label"]["person_count"] = 2
                elif mutation == "partial_window":
                    pairs[0]["label"]["end_ns"] = pairs[0]["window"]["timestamps_ns"][0]
                elif mutation == "header":
                    pairs[0]["window"]["flags"] = 20
                elif mutation == "duplicate":
                    pairs.append(copy.deepcopy(pairs[0]))
                elif mutation == "scope":
                    pairs[0]["window"]["node_id"] = 2
                elif mutation == "uncertainty":
                    pairs[0]["alignment"]["max_uncertainty_ns"] = 1
                else:
                    report["counts"]["paired_windows"] += 1
                changed = b"".join((json.dumps(p) + "\n").encode() for p in pairs)
                self.paired.write_bytes(changed)
                report["paired_sha256"] = ref.raw_hash(changed)
                self.write(self.report, report)
                with self.assertRaises(ValueError):
                    self.load()
                self.paired.write_bytes(pair_raw)
                self.report.write_bytes(report_raw)

    def test_strict_json_input_types_and_changed_input_before_publication(self):
        path = self.run / "annotations.json"
        for raw in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"x":1e999}'):
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                annotations.import_annotations(self.inputs, path, self.run / "invalid")
            self.assertFalse((self.run / "invalid").exists())
        self.write(path, self.value)
        link = self.run / "link.json"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            annotations.import_annotations(self.inputs, link, self.run / "invalid")
        fifo = self.run / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            annotations.import_annotations(self.inputs, fifo, self.run / "invalid")
        self.paired.write_bytes(self.paired.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "changed during import"):
            annotations.import_annotations(self.inputs, path, self.run / "invalid")
        self.assertFalse((self.run / "invalid").exists())

    def test_cli_template_and_explicit_import(self):
        common = [
            "--reference-directory",
            str(self.reference),
            "--reference-export",
            str(self.export),
            "--paired",
            str(self.paired),
            "--pair-report",
            str(self.report),
            "--definition",
            str(self.definition),
            "--geometry",
            str(self.geometry),
        ]

        def cli(*args):
            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "inference.zone_annotations",
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                    *args,
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )

        path, out = self.run / "draft.json", self.run / "cli-output"
        made = cli("template", *common, "--output", str(path))
        self.assertEqual(made.returncode, 0, made.stderr)
        self.assertEqual(
            json.loads(path.read_bytes()), annotations.template(self.inputs)
        )
        rejected = cli(
            "import", *common, "--annotations", str(path), "--output", str(out)
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(out.exists())
        self.write(path, self.value)
        accepted = cli(
            "import", *common, "--annotations", str(path), "--output", str(out)
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertTrue(json.loads((out / "receipt.json").read_bytes())["completed"])


if __name__ == "__main__":
    unittest.main()
