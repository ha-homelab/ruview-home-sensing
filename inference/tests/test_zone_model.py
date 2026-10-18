"""Fitted synthetic fixtures test arithmetic only, never household accuracy."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.pipeline import digest
from inference.tests import test_zones
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.zone_model import evaluate, predict, score, train, validate_model


class ZoneModelTests(unittest.TestCase):
    def setUp(self):
        fixtures = test_zones.ZoneTests()
        fixtures.setUp()
        self.addCleanup(fixtures.doCleanups)
        self.settings = fixtures.settings
        self.rows = fixtures.rows
        self.policy = fixtures.policy
        for row in self.rows:
            label = row["zone_reference"]["zone_id"]
            window = row["paired"]["window"]
            # Synthetic separable feature patterns, not raw household frames.
            window["amplitudes"] = [
                [
                    10.0
                    + (
                        20
                        if label == "zone_a" and i < 32
                        else 20
                        if label == "zone_b" and i >= 32
                        else 0
                    )
                    for i in range(64)
                ]
                for _ in window["amplitudes"]
            ]
            test_zones.seal(window, "window_id")

    def fitted(self):
        return train(
            self.settings,
            self.rows,
            self.policy,
            expected_coordinate_frame="example_lab_xz_metres",
        )

    def test_actual_fit_reports_full_held_out_denominators(self):
        model, report = self.fitted()
        validate_model(model)
        self.assertEqual(model["training_windows"], 7)
        self.assertEqual(report["total_windows"], 7)
        self.assertEqual(
            sum(sum(r) for r in report["confusion_rows_truth_columns_prediction"]), 7
        )
        self.assertEqual(
            report["accepted_zone_predictions"] + report["unknown_predictions"], 7
        )
        self.assertFalse(report["ground_truth_used_to_gate_predictions"])
        self.assertFalse(report["thresholds_tuned_on_evaluation"])
        self.assertFalse(model["recognition_validated"])
        self.assertFalse(model["publish_to_ha"])
        self.assertEqual(model["data_classification"], "synthetic")
        self.assertEqual(
            {k: v["windows"] for k, v in report["negative_conditions"].items()},
            {k: 1 for k in test_zones.NEGATIVES},
        )
        self.assertTrue(any(abs(v) > 1e-6 for row in model["weights"] for v in row))

    def test_holdout_feature_changes_never_change_fit_or_thresholds(self):
        model, _ = self.fitted()
        altered = copy.deepcopy(self.rows)
        for row in altered[7:]:
            window = row["paired"]["window"]
            window["amplitudes"] = [
                [value * 100 + 99 for value in line] for line in window["amplitudes"]
            ]
            test_zones.seal(window, "window_id")
        second, report = train(
            self.settings,
            altered,
            self.policy,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(model, second)
        self.assertEqual(report["unknown_predictions"], 7)
        self.assertGreater(report["decision_reasons"].get("out_of_domain", 0), 0)

    def test_negative_false_acceptance_is_measured_not_oracle_gated(self):
        model, _ = self.fitted()
        changed = copy.deepcopy(self.rows)
        unknown = changed[-1]["paired"]["window"]
        unknown["amplitudes"] = copy.deepcopy(
            changed[0]["paired"]["window"]["amplitudes"]
        )
        test_zones.seal(unknown, "window_id")
        result = evaluate(
            model,
            self.settings,
            changed,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(
            result["negative_conditions"]["simultaneous_zones"][
                "false_zone_acceptances"
            ],
            1,
        )
        self.assertEqual(
            result["negative_conditions"]["simultaneous_zones"][
                "false_acceptance_rate"
            ],
            1.0,
        )

    def test_evaluate_rejects_changed_training_records(self):
        model, _ = self.fitted()
        changed = copy.deepcopy(self.rows)
        window = changed[0]["paired"]["window"]
        window["amplitudes"][0][0] += 1
        test_zones.seal(window, "window_id")
        with self.assertRaisesRegex(ValueError, "fitted dataset"):
            evaluate(
                model,
                self.settings,
                changed,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_missing_classes_and_same_capture_never_train(self):
        with self.assertRaisesRegex(ValueError, "not contract-ready"):
            train(
                self.settings,
                self.rows[:1],
                self.policy,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        changed = copy.deepcopy(self.settings)
        changed["evaluation_capture_ids"] = changed["training_capture_ids"]
        with self.assertRaisesRegex(ValueError, "same capture"):
            train(
                changed,
                self.rows,
                self.policy,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_score_uses_saved_coefficients_and_train_domain(self):
        import numpy as np

        model, _ = self.fitted()
        window = self.rows[7]["paired"]["window"]
        scores, distance = score(model, window)
        from inference.model import features

        expected = (
            (np.asarray(features(window)) - model["mean"]) / model["scale"]
        ) @ np.asarray(model["weights"]) + model["bias"]
        self.assertTrue(np.allclose(list(scores.values()), expected))
        self.assertAlmostEqual(distance, 0.0)
        self.assertEqual(set(scores), {"zone_a", "zone_b", "unknown"})

    def test_no_context_abstains_while_returning_actual_scores(self):
        model, _ = self.fitted()
        result = predict(model, self.rows[7]["paired"]["window"])
        self.assertEqual(result["zone"], "unknown")
        self.assertEqual(result["reason"], "input_context_unverified")
        self.assertIsNone(result["confidence"])
        self.assertFalse(result["publish_to_ha"])
        self.assertEqual(len(result["scores"]), 3)

    def test_valid_context_and_all_required_abstentions(self):
        model, _ = self.fitted()
        window = self.rows[7]["paired"]["window"]
        context = {
            "clock_id": window["clock_id"],
            "now_monotonic_ns": window["monotonic_ns"][-1],
            "signal_sufficient": True,
            "scope": "single_zone",
            "scope_evidence_reference": "synthetic-only",
        }
        self.assertEqual(predict(model, window, context)["zone"], "zone_a")
        for key, value in (
            ("scope", "simultaneous_zones"),
            ("scope", "unknown"),
            ("signal_sufficient", False),
            ("clock_id", "other"),
            ("now_monotonic_ns", 0),
            ("now_monotonic_ns", window["monotonic_ns"][-1] + 2_000_000_001),
        ):
            with self.subTest(key=key, value=value):
                self.assertEqual(
                    predict(model, window, dict(context, **{key: value}))["zone"],
                    "unknown",
                )

    def test_corrupt_and_rehashed_invalid_checkpoint_rejected(self):
        model, _ = self.fitted()
        for key, value in (
            ("scale", [0.0] * 192),
            ("weights", [[0.0] * 2] * 192),
            ("publish_to_ha", True),
            ("classes", ["zone_a", "zone_b"]),
            ("domain_metric", "invented"),
        ):
            bad = dict(model, **{key: value})
            test_zones.seal(bad, "model_sha256")
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_model(bad)
        bad = copy.deepcopy(model)
        bad["bias"][0] += 1
        with self.assertRaisesRegex(ValueError, "changed"):
            validate_model(bad)

    def test_no_qualified_flags_or_foreign_feature_contract(self):
        model, _ = self.fitted()
        window = copy.deepcopy(self.rows[7]["paired"]["window"])
        window["flags"] = 20
        test_zones.seal(window, "window_id")
        with self.assertRaisesRegex(ValueError, "header"):
            score(model, window)
        policy = copy.deepcopy(self.policy)
        policy["min_score"] = float("nan")
        with self.assertRaises(ValueError):
            train(
                self.settings,
                self.rows,
                policy,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_cli_train_evaluate_predict_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, obj in (
                ("plan", self.settings),
                ("records", self.rows),
                ("policy", self.policy),
                ("window", self.rows[7]["paired"]["window"]),
            ):
                (root / (name + ".json")).write_text(json.dumps(obj))
            base = [
                sys.executable,
                "-m",
                "inference.zone_model",
                "--expected-coordinate-frame",
                "example_lab_xz_metres",
            ]
            data = [
                "--plan",
                str(root / "plan.json"),
                "--records",
                str(root / "records.json"),
            ]
            cmd = base + [
                "train",
                *data,
                "--policy",
                str(root / "policy.json"),
                "--model-output",
                str(root / "model.json"),
                "--report-output",
                str(root / "report.json"),
            ]
            env = dict(os.environ, OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "model.json").stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(
                subprocess.run(
                    cmd, capture_output=True, env=env, timeout=PROCESS_TIMEOUT_SECONDS
                ).returncode,
                0,
            )
            result = subprocess.run(
                base
                + [
                    "evaluate",
                    *data,
                    "--model",
                    str(root / "model.json"),
                    "--output",
                    str(root / "evaluation.json"),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads((root / "report.json").read_text()),
                json.loads((root / "evaluation.json").read_text()),
            )
            result = subprocess.run(
                base
                + [
                    "predict",
                    "--model",
                    str(root / "model.json"),
                    "--window",
                    str(root / "window.json"),
                    "--output",
                    str(root / "prediction.json"),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            prediction = json.loads((root / "prediction.json").read_text())
            self.assertEqual(prediction["zone"], "unknown")
            self.assertEqual(prediction["reason"], "input_context_unverified")
            self.assertEqual(len(prediction["scores"]), 3)
            self.assertEqual(
                digest(json.loads((root / "model.json").read_text())),
                digest(self.fitted()[0]),
            )


if __name__ == "__main__":
    unittest.main()
