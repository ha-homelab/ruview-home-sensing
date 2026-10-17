"""Synthetic evidence binding only; no household labels, captures or models."""

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from inference.__main__ import read_jsonl
from inference.evidence import SCHEMA, verified_recording
from inference.model import predict, train, validate_model
from inference.pipeline import digest
from inference.tests import test_capture, test_pipeline
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_capture.CaptureTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.prepare()

    def prepare(self):
        manifest = json.dumps(self.fixture.manifest).encode()
        (self.root / "manifest.json").write_bytes(manifest)
        report = self.fixture.verify()
        report["manifest_original_sha256"] = hashlib.sha256(manifest).hexdigest()
        (self.root / "report.json").write_text(json.dumps(report))

    def context(self, node_ids=None):
        return verified_recording(
            self.root / "raw",
            self.root / "manifest.json",
            self.root / "report.json",
            self.root / "opening_snapshot",
            self.root / "closing_snapshot",
            [1, 2, 3] if node_ids is None else node_ids,
        )

    def pair_command(self, evidence=True):
        profiles = [test_pipeline.profile(n) for n in (1, 2, 3)]
        labels = []
        for profile in profiles:
            window = {
                "window_id": str(profile["node_id"]),
                "node_id": profile["node_id"],
                "session_id": "synthetic-run",
                "configuration_sha256": "a" * 64,
                "commissioning_sha256": digest(profile),
                "timestamps_ns": [self.fixture.base, self.fixture.base + 2_000_000_000],
            }
            labels.append(test_pipeline.label(window))
        (self.root / "profiles.json").write_text(json.dumps(profiles))
        (self.root / "labels.jsonl").write_text(
            "".join(json.dumps(v) + "\n" for v in labels)
        )
        command = [
            sys.executable,
            "-m",
            "inference",
            "pair",
            "--frames",
            str(self.root / "raw"),
            "--labels",
            str(self.root / "labels.jsonl"),
            "--profiles",
            str(self.root / "profiles.json"),
            "--label-clock-offset-ms",
            "0",
            "--window-ms",
            "200",
            "--min-frames",
            "3",
            "--output",
            str(self.root / "paired.jsonl"),
            "--expected-coordinate-frame",
            "example_lab_xz_metres",
        ]
        if evidence:
            for flag, name in (
                ("capture-manifest", "manifest.json"),
                ("capture-report", "report.json"),
                ("opening-snapshot", "opening_snapshot"),
                ("closing-snapshot", "closing_snapshot"),
            ):
                command.extend(["--" + flag, str(self.root / name)])
        return command

    def run_cli(self, command):
        return subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )

    def test_successful_pairing_binds_evidence_and_only_verified_interval(self):
        result = self.run_cli(self.pair_command())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["capture_verification"], "verified_recording"
        )
        records = list(read_jsonl(self.root / "paired.jsonl"))
        self.assertEqual({r["window"]["node_id"] for r in records}, {1, 2, 3})
        self.assertTrue(records)
        interval = self.fixture.manifest["planned_interval"]
        for record in records:
            self.assertEqual(
                record["capture_evidence"]["raw_sha256"],
                self.fixture.manifest["files"]["raw"]["sha256"],
            )
            self.assertTrue(record["capture_evidence"]["synthetic_only"])
            self.assertGreaterEqual(
                record["window"]["timestamps_ns"][0], interval["start_utc_ns"]
            )
            self.assertLessEqual(
                record["window"]["timestamps_ns"][-1], interval["end_utc_ns"]
            )
        self.assertEqual(os.stat(self.root / "paired.jsonl").st_mode & 0o777, 0o600)

    def test_legacy_is_explicitly_unverified_and_partial_bundle_fails(self):
        command = self.pair_command(False)
        result = self.run_cli(
            command + ["--capture-report", str(self.root / "report.json")]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "paired.jsonl").exists())
        result = self.run_cli(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = list(read_jsonl(self.root / "paired.jsonl"))
        self.assertTrue(records)
        self.assertTrue(
            all(
                r["capture_evidence"]["status"] == "unverified_research"
                for r in records
            )
        )

    def test_stable_private_copy_survives_original_replacement_and_cleans_up(self):
        with self.context() as (path, evidence):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(path.parent).st_mode & 0o777, 0o700)
            (self.root / "raw").write_text("replaced during pairing")
            self.assertEqual(len(list(read_jsonl(path))), 60)
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), evidence["raw_sha256"]
            )
        self.assertFalse(path.exists())
        self.fixture.write_files()
        with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
            with self.context() as (path, _):
                raise RuntimeError("synthetic failure")
        self.assertFalse(path.parent.exists())

    def test_raw_hash_report_identity_and_profile_coverage_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "node coverage"):
            with self.context([1, 2]):
                pass
        for change in (
            "raw",
            "report_identity",
            "failed_report",
            "manifest_bytes",
            "snapshot",
        ):
            with self.subTest(change=change):
                self.fixture.write_files()
                self.prepare()
                if change == "raw":
                    (self.root / "raw").write_bytes(
                        (self.root / "raw")
                        .read_bytes()
                        .replace(b'"flags": 16', b'"flags": 17', 1)
                    )
                elif change in ("report_identity", "failed_report"):
                    report = json.loads((self.root / "report.json").read_text())
                    if change == "report_identity":
                        report["session_id"] = "other-session"
                    else:
                        report["recording_complete"] = False
                    (self.root / "report.json").write_text(json.dumps(report))
                elif change == "manifest_bytes":
                    with (self.root / "manifest.json").open("a") as out:
                        out.write(" ")
                else:
                    (self.root / "opening_snapshot").write_text("{}")
                with self.assertRaises(ValueError):
                    with self.context():
                        pass

    def test_fake_success_cannot_override_recomputed_failed_capture(self):
        self.fixture.closing["counters"]["record_dropped"] = 1
        self.fixture.write_files()
        self.prepare()
        report = json.loads((self.root / "report.json").read_text())
        report["recording_complete"] = True
        report["findings"] = {}
        (self.root / "report.json").write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "completion"):
            with self.context():
                pass

    def test_wrong_label_identity_fails_before_output(self):
        command = self.pair_command()
        rows = list(read_jsonl(self.root / "labels.jsonl"))
        rows[0]["configuration_sha256"] = "f" * 64
        (self.root / "labels.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows)
        )
        result = self.run_cli(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("label differs", result.stderr)
        self.assertFalse((self.root / "paired.jsonl").exists())


def with_synthetic_lineage(records):
    """Metadata validator fixture, not a successful household capture report."""
    for record in records:
        window = record["window"]
        record["capture_evidence"] = {
            "schema": SCHEMA,
            "status": "verified_recording",
            "synthetic_only": True,
            "manifest_sha256": "a" * 64,
            "verification_report_sha256": "b" * 64,
            "raw_sha256": "c" * 64,
            "opening_snapshot_sha256": "d" * 64,
            "closing_snapshot_sha256": "e" * 64,
            **{
                key: window[key]
                for key in ("session_id", "clock_id", "configuration_sha256")
            },
            "expected_node_ids": [window["node_id"]],
            "planned_interval": {"start_utc_ns": 1, "end_utc_ns": 200_000_000_000},
        }
    return records


@unittest.skipUnless(
    importlib.util.find_spec("numpy"), "NumPy is required for model tests"
)
class ModelLineageTests(unittest.TestCase):
    def test_train_predict_retain_lineage_and_reject_mixed_modes(self):
        records = with_synthetic_lineage(test_pipeline.dataset())
        model = train(
            records,
            "posture",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(model["capture_lineage"]["status"], "verified_recording")
        self.assertEqual(len(model["capture_lineage"]["recordings"]), 2)
        record = records[-1]
        output = predict(
            model,
            record["window"],
            record["capture_evidence"],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(output["capture_evidence"], record["capture_evidence"])
        self.assertEqual(output["model_capture_lineage"], model["capture_lineage"])
        self.assertFalse(output["publish_to_ha"])
        with self.assertRaisesRegex(ValueError, "mix verified"):
            predict(
                model,
                record["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        wrong_classification = copy.deepcopy(record["capture_evidence"])
        wrong_classification["synthetic_only"] = False
        with self.assertRaisesRegex(ValueError, "classification"):
            predict(
                model,
                record["window"],
                wrong_classification,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        legacy = train(
            test_pipeline.dataset(),
            "posture",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        with self.assertRaisesRegex(ValueError, "mix verified"):
            predict(
                legacy,
                record["window"],
                record["capture_evidence"],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        del records[0]["capture_evidence"]
        with self.assertRaisesRegex(ValueError, "mix verified"):
            train(
                records,
                "posture",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_retained_identity_interval_and_classification_cannot_be_changed(self):
        records = with_synthetic_lineage(test_pipeline.dataset())
        for field, value in (
            ("session_id", "wrong"),
            ("clock_id", "wrong"),
            ("configuration_sha256", "f" * 64),
            ("expected_node_ids", [3]),
            ("planned_interval", {"start_utc_ns": 1, "end_utc_ns": 2}),
        ):
            changed = copy.deepcopy(records)
            changed[0]["capture_evidence"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "scope"):
                train(
                    changed,
                    "posture",
                    {"synthetic-eval"},
                    expected_coordinate_frame="example_lab_xz_metres",
                )
        for record in records:
            if record["window"]["session_id"] == "synthetic-eval":
                record["capture_evidence"]["synthetic_only"] = False
        with self.assertRaisesRegex(ValueError, "classifications"):
            train(
                records,
                "posture",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_checkpoint_cannot_drop_verified_session_lineage_with_new_checksum(self):
        model = train(
            with_synthetic_lineage(test_pipeline.dataset()),
            "posture",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        model["capture_lineage"]["recordings"].pop()
        model["model_sha256"] = digest(
            {k: v for k, v in model.items() if k != "model_sha256"}
        )
        with self.assertRaisesRegex(ValueError, "capture sessions"):
            validate_model(model, expected_coordinate_frame="example_lab_xz_metres")


if __name__ == "__main__":
    unittest.main()
