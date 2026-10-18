import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.fall_evaluation import canonical_sha, evaluate
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS

SECOND = 10**9


def fixture():
    policy = {
        "early_tolerance_ns": SECOND,
        "max_latency_ns": 5 * SECOND,
        "min_reference_hours": 1,
        "min_negative_reference_hours": 0.9,
        "min_fall_events": 1,
        "min_detector_coverage_fraction": 0.99,
        "min_recall": 0.9,
        "max_false_alerts_per_reference_hour": 0.1,
        "max_false_alerts_per_negative_hour": 0.1,
        "max_p95_latency_seconds": 5,
    }
    return {
        "schema": "ruview.fall-evaluation-input.v1",
        "classification": "synthetic",
        "candidate_sha256": "a" * 64,
        "training_session_ids": ["training"],
        "predeclared_policy_sha256": canonical_sha(policy),
        "reference_review_sha256": "b" * 64,
        "policy": policy,
        "sessions": [
            {
                "session_id": "held-out",
                "clock_id": "test-clock",
                "reference_independent": True,
                "reference_reviewed": True,
                "reference_sha256": "c" * 64,
                "detector_recording_sha256": "d" * 64,
                "start_ns": 0,
                "end_ns": 3600 * SECOND,
                "reference_coverage": [[0, 3600 * SECOND]],
                "detector_coverage": [[0, 3600 * SECOND]],
                "reference_events": [
                    {
                        "event_id": "fall-1",
                        "onset_ns": 1800 * SECOND,
                        "uncertainty_ns": SECOND // 2,
                    }
                ],
                "alerts": [{"alert_id": "alert-1", "at_ns": 1802 * SECOND}],
            }
        ],
    }


class FallEvaluationTests(unittest.TestCase):
    def test_cli_writes_private_report_and_refuses_evidence_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.json"
            output = Path(directory) / "report.json"
            source.write_text(json.dumps(fixture()))
            command = [
                sys.executable,
                "-m",
                "inference.fall_evaluation",
                "--input",
                str(source),
                "--output",
                str(output),
            ]
            first = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            original = output.read_bytes()
            report = json.loads(original)
            self.assertEqual(report["classification"], "synthetic")
            self.assertFalse(report["recognition_validated"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            second = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_metrics_and_conservative_latency_are_not_publication_permission(self):
        report = evaluate(fixture())
        self.assertTrue(report["numerical_gates_passed"])
        self.assertEqual(report["recall"], 1)
        self.assertEqual(report["reference_hours"], 1)
        self.assertEqual(report["p95_latency_upper_seconds"], 2.5)
        self.assertFalse(report["recognition_validated"])
        self.assertFalse(report["publish_to_ha"])
        self.assertFalse(report["policy_predeclaration_verified"])
        self.assertFalse(report["reference_review_verified"])

    def test_large_event_horizon_cannot_replace_negative_background(self):
        data = fixture()
        data["policy"]["early_tolerance_ns"] = 1799 * SECOND
        data["policy"]["max_latency_ns"] = 1799 * SECOND
        data["sessions"][0]["reference_events"][0]["uncertainty_ns"] = 0
        data["predeclared_policy_sha256"] = canonical_sha(data["policy"])
        report = evaluate(data)
        self.assertAlmostEqual(report["negative_reference_hours"], 2 / 3600)
        self.assertFalse(report["gates"]["negative_reference_duration"])

    def test_background_false_alarm_has_separate_negative_hour_rate(self):
        data = fixture()
        data["sessions"][0]["alerts"].append(
            {"alert_id": "background", "at_ns": 100 * SECOND}
        )
        report = evaluate(data)
        self.assertEqual(report["counts"]["negative_false_alerts"], 1)
        self.assertGreater(report["false_alerts_per_negative_hour"], 1)
        self.assertFalse(report["gates"]["negative_false_alert_rate"])

    def test_duplicate_alarm_is_false_positive_not_second_true_positive(self):
        data = fixture()
        data["sessions"][0]["alerts"].append(
            {"alert_id": "repeat", "at_ns": 1803 * SECOND}
        )
        report = evaluate(data)
        self.assertEqual(report["counts"]["tp"], 1)
        self.assertEqual(report["counts"]["fp"], 1)
        self.assertEqual(report["precision"], 0.5)
        self.assertEqual(report["false_alerts_per_reference_hour"], 1)
        self.assertFalse(report["numerical_gates_passed"])

    def test_fall_during_detector_outage_remains_in_recall_denominator(self):
        data = fixture()
        session = data["sessions"][0]
        session["alerts"] = []
        session["detector_coverage"] = [
            [0, 1000 * SECOND],
            [2000 * SECOND, 3600 * SECOND],
        ]
        report = evaluate(data)
        self.assertEqual(report["counts"]["fn"], 1)
        self.assertEqual(report["counts"]["events_during_detector_gaps"], 1)
        self.assertEqual(report["recall"], 0)
        self.assertFalse(report["gates"]["detector_coverage"])

    def test_alert_without_reference_is_unscored_never_true_or_false(self):
        data = fixture()
        session = data["sessions"][0]
        session["reference_coverage"] = [[1700 * SECOND, 1900 * SECOND]]
        session["alerts"].append({"alert_id": "unreviewed", "at_ns": 100 * SECOND})
        report = evaluate(data)
        self.assertEqual(report["counts"]["unscored_alerts"], 1)
        self.assertEqual(report["counts"]["fp"], 0)
        self.assertAlmostEqual(report["reference_hours"], 200 / 3600)

    def test_no_positive_events_cannot_pass(self):
        data = fixture()
        data["sessions"][0]["reference_events"] = []
        data["sessions"][0]["alerts"] = []
        report = evaluate(data)
        self.assertIsNone(report["recall"])
        self.assertIsNone(report["precision"])
        self.assertFalse(report["numerical_gates_passed"])

    def test_unobserved_or_ambiguous_event_horizons_are_rejected(self):
        for onset, reason in (
            (3599 * SECOND, "event_horizon_not_observed"),
            (1803 * SECOND, "ambiguous_overlapping_event_horizons"),
        ):
            data = fixture()
            data["sessions"][0]["reference_events"].append(
                {"event_id": "fall-2", "onset_ns": onset, "uncertainty_ns": 0}
            )
            with self.assertRaisesRegex(ValueError, reason):
                evaluate(data)

    def test_session_renaming_and_overlap_cannot_multiply_evidence(self):
        data = fixture()
        second = copy.deepcopy(data["sessions"][0])
        second["session_id"] = "renamed"
        data["sessions"].append(second)
        with self.assertRaisesRegex(ValueError, "repeated_recording"):
            evaluate(data)
        second["reference_sha256"], second["detector_recording_sha256"] = (
            "e" * 64,
            "f" * 64,
        )
        with self.assertRaisesRegex(ValueError, "overlapping_sessions"):
            evaluate(data)

    def test_training_leakage_and_unreviewed_labels_are_rejected(self):
        for change, reason in (
            ({"session_id": "training"}, "session_leakage"),
            ({"reference_reviewed": False}, "reviewed_reference"),
            ({"reference_independent": False}, "independent_reference"),
        ):
            data = fixture()
            data["sessions"][0].update(change)
            with self.assertRaisesRegex(ValueError, reason):
                evaluate(data)

    def test_policy_changes_and_nonfinite_values_cannot_pass(self):
        data = fixture()
        data["policy"]["min_recall"] = 0.5
        with self.assertRaisesRegex(ValueError, "policy_digest_mismatch"):
            evaluate(data)
        for bad in (True, float("nan"), float("inf")):
            data = fixture()
            data["policy"]["max_p95_latency_seconds"] = bad
            with self.assertRaises(ValueError):
                evaluate(data)

    def test_alert_must_be_inside_declared_detector_availability(self):
        data = fixture()
        data["sessions"][0]["detector_coverage"] = [[0, 1700 * SECOND]]
        with self.assertRaisesRegex(ValueError, "alert_outside_detector_coverage"):
            evaluate(data)


if __name__ == "__main__":
    unittest.main()
