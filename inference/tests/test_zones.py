"""Synthetic protocol/score fixtures only; no trained model or household labels."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.feature_contracts import FEATURE_CONTRACT, PREFIX_FEATURE_CONTRACT
from inference.model import model_identity
from inference.pipeline import digest, pair_window
from inference.reference_alignment import align_label
from inference.tests import test_reference_alignment
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.zones import NEGATIVES, decision, readiness


def seal(value, name):
    value[name] = digest({k: v for k, v in value.items() if k != name})
    return value


class ZoneTests(unittest.TestCase):
    def setUp(self):
        source = test_reference_alignment.ReferenceAlignmentTests()
        source.setUp()
        self.addCleanup(source.doCleanups)
        self.base = source.paired()
        self.scope = seal(
            {
                "schema": "ruview.zone_definition.v1",
                "zone_ids": ["zone_a", "zone_b"],
                "room_id": "K",
                "floorplan_sha256": "b" * 64,
                "zone_geometry_sha256": "c" * 64,
            },
            "definition_sha256",
        )
        self.settings = {
            "schema": "ruview.zone_readiness_plan.v1",
            "definition": self.scope,
            "node_id": self.base["window"]["node_id"],
            "feature_contract": FEATURE_CONTRACT,
            "training_capture_ids": [],
            "evaluation_capture_ids": [],
            "min_windows_per_class": 1,
            "min_trials_per_class": 1,
            "max_label_uncertainty_ns": 100_000_000,
            "data_classification": "synthetic",
        }
        self.rows = []
        for split in ("training", "evaluation"):
            for name in ("zone_a", "zone_b", *NEGATIVES):
                row = self.row(len(self.rows) + 1, name)
                self.rows.append(row)
                self.settings[split + "_capture_ids"].append(
                    row["paired"]["window"]["capture_id"]
                )
        self.policy = seal(
            {
                "schema": "ruview.zone_decision_policy.v1",
                "definition": self.scope,
                "feature_contract": FEATURE_CONTRACT,
                "max_age_ns": 2_000_000_000,
                "min_score": 0.5,
                "min_margin": 0.1,
                "max_domain_distance": 3.0,
            },
            "policy_sha256",
        )
        self.artifact = b"synthetic external-model artifact; not fitted or deployable"
        self.artifact_sha = hashlib.sha256(self.artifact).hexdigest()
        self.review = seal(
            {
                "schema": "ruview.zone_model_review.v1",
                "status": "independently_reviewed_trained_candidate",
                "model_sha256": self.artifact_sha,
                "training_report_sha256": "d" * 64,
                "evaluation_report_sha256": "e" * 64,
                "independent_review_sha256": "f" * 64,
                "training_capture_ids": self.settings["training_capture_ids"],
                "evaluation_capture_ids": self.settings["evaluation_capture_ids"],
                "input_identity_sha256": digest(model_identity(self.base["window"])),
                "policy_sha256": self.policy["policy_sha256"],
                "definition_sha256": self.scope["definition_sha256"],
                "feature_contract": FEATURE_CONTRACT,
                "class_order": ["zone_a", "zone_b", "unknown"],
            },
            "review_sha256",
        )
        self.observation = {
            "schema": "ruview.zone_score_evidence.v1",
            "window": self.base["window"],
            "model_sha256": self.artifact_sha,
            "scores": {"zone_a": 0.9, "zone_b": 0.1, "unknown": 0.0},
            "domain_distance": 1.0,
            "signal_sufficient": True,
            "scope": "single_zone",
            "scope_evidence_reference": "synthetic-only scope fixture",
            "now_monotonic_ns": self.base["window"]["monotonic_ns"][-1] + 1000,
            "clock_id": self.base["window"]["clock_id"],
        }

    def row(self, index, category, shift=None):
        """Move a wholly synthetic closed-capture fixture to a separate interval."""
        capture = f"00000000-0000-4000-8000-{index:012d}"
        delta = index * 100_000_000_000 if shift is None else shift

        def moved(value, key=""):
            if key in ("capture_id", "session_id"):
                return capture
            if key in ("timestamps_ns", "monotonic_ns") and isinstance(value, list):
                return [v + delta for v in value]
            if key in ("start_ns", "end_ns", "utc_ns", "monotonic_ns"):
                return value + delta
            if key in ("label_interval_ns", "receiver_interval_ns"):
                return {k: v + delta for k, v in value.items()}
            if isinstance(value, dict):
                return {k: moved(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [moved(v) for v in value]
            return value

        prior = moved(copy.deepcopy(self.base))
        w, evidence, alignment, original = (
            prior[k]
            for k in ("window", "capture_evidence", "time_alignment", "original_label")
        )
        for key in ("raw_sha256", "opening_sha256", "terminal_sha256"):
            evidence[key] = digest([index, key])
        for key in ("opening_sha256", "terminal_sha256"):
            alignment[key] = evidence[key]
        original["reference_lineage"]["opening_sha256"] = evidence["opening_sha256"]
        original["label_id"] = "synthetic-label-" + str(index)
        original["trial_id"] = "synthetic-trial-" + str(index)
        original["person_count"] = (
            0 if category == "empty" else 2 if category == "simultaneous_zones" else 1
        )
        seal(w, "window_id")
        seal(alignment, "alignment_sha256")
        adjusted = align_label(
            original,
            alignment,
            evidence,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        paired = pair_window(
            w,
            [adjusted],
            alignment["label_to_csi_clock_offset_ns"],
            100_000_000,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        paired.update(
            capture_evidence=evidence, time_alignment=alignment, original_label=original
        )
        annotation = {
            "schema": "ruview.zone_reference.v1",
            "reference_id": "synthetic-zone-" + str(index),
            "original_label_sha256": digest(original),
            "definition_sha256": self.scope["definition_sha256"],
            "zone_id": category if category in self.scope["zone_ids"] else "unknown",
            "condition": "single_zone_movement"
            if category in self.scope["zone_ids"]
            else category,
            "source": "manual_observation",
            "reviewed": True,
            "provenance": "synthetic-only independent-reference fixture",
        }
        return {"paired": paired, "zone_reference": annotation}

    def admit(self):
        return decision(self.policy, self.observation, self.review, self.artifact_sha)

    def test_complete_synthetic_contract_never_claims_recorded_training(self):
        report = readiness(
            self.settings, self.rows, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertTrue(report["contract_ready"])
        self.assertFalse(report["recorded_data_ready"])
        self.assertFalse(report["model_fitted"])
        self.assertFalse(report["publish_to_ha"])
        self.assertEqual(
            report["windows"]["eval"], {"zone_a": 1, "zone_b": 1, "unknown": 5}
        )

    def test_missing_classes_and_negative_conditions_report_denominators(self):
        report = readiness(
            self.settings,
            self.rows[:1],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertFalse(report["contract_ready"])
        self.assertIn(
            "eval:missing_unknown_condition:simultaneous_zones", report["missing"]
        )
        self.assertEqual(report["windows"]["eval"]["zone_a"], 0)

    def test_same_capture_split_rejected(self):
        self.settings["evaluation_capture_ids"] = self.settings["training_capture_ids"]
        with self.assertRaisesRegex(ValueError, "same capture"):
            readiness(
                self.settings,
                self.rows,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_renamed_raw_capture_rejected(self):
        self.rows[-1]["paired"]["capture_evidence"]["raw_sha256"] = self.rows[0][
            "paired"
        ]["capture_evidence"]["raw_sha256"]
        with self.assertRaisesRegex(ValueError, "renamed raw"):
            readiness(
                self.settings,
                self.rows,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_overlapping_capture_interval_rejected(self):
        self.rows[-1] = self.row(14, "simultaneous_zones", shift=100_000_000_000)
        with self.assertRaisesRegex(ValueError, "intervals overlap"):
            readiness(
                self.settings,
                self.rows,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_synthetic_data_cannot_be_marked_recorded(self):
        self.settings["data_classification"] = "recorded"
        with self.assertRaisesRegex(ValueError, "classification mismatch"):
            readiness(
                self.settings,
                self.rows,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_feature_header_and_profile_changes_rejected(self):
        for kind in ("contract", "header", "floorplan"):
            settings, rows = copy.deepcopy(self.settings), copy.deepcopy(self.rows)
            if kind == "contract":
                settings["feature_contract"] = PREFIX_FEATURE_CONTRACT
            elif kind == "header":
                rows[0]["paired"]["window"]["flags"] = 20
            else:
                settings["definition"]["floorplan_sha256"] = "a" * 64
                seal(settings["definition"], "definition_sha256")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                readiness(
                    settings, rows, expected_coordinate_frame="example_lab_xz_metres"
                )

    def test_reference_source_interval_and_uncertainty_rejected(self):
        for kind in ("source", "alignment", "uncertainty"):
            settings, rows = copy.deepcopy(self.settings), copy.deepcopy(self.rows)
            if kind == "source":
                rows[0]["zone_reference"]["source"] = "csi_prediction"
            elif kind == "alignment":
                rows[0]["paired"]["alignment"]["label_to_csi_clock_offset_ns"] += 1
            else:
                settings["max_label_uncertainty_ns"] = 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                readiness(
                    settings, rows, expected_coordinate_frame="example_lab_xz_metres"
                )

    def test_simultaneous_zone_reference_cannot_be_positive(self):
        self.rows[6]["zone_reference"].update(
            zone_id="zone_a", condition="single_zone_movement"
        )
        with self.assertRaisesRegex(ValueError, "single-zone"):
            readiness(
                self.settings,
                self.rows,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_duplicate_windows_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate window"):
            readiness(
                self.settings,
                self.rows + [self.rows[0]],
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_untrained_missing_or_mismatched_artifact_abstains(self):
        self.assertEqual(decision(self.policy, None)["zone"], "unknown")
        self.assertEqual(
            decision(self.policy, self.observation, self.review, "a" * 64)["reason"],
            "model_artifact_mismatch",
        )
        self.review["status"] = "untrained"
        seal(self.review, "review_sha256")
        self.assertEqual(self.admit()["reason"], "model_not_reviewed_trained")

    def test_synthetic_score_contract_admits_only_private_candidate(self):
        result = self.admit()
        self.assertEqual(result["zone"], "zone_a")
        self.assertEqual(result["status"], "candidate_only")
        self.assertFalse(result["recognition_validated"])
        self.assertFalse(result["publish_to_ha"])
        self.assertIsNone(result["confidence"])

    def test_stale_future_clock_and_identity_abstain(self):
        for kind in ("stale", "future", "clock", "identity"):
            obs = copy.deepcopy(self.observation)
            if kind == "stale":
                obs["now_monotonic_ns"] += 3_000_000_000
            elif kind == "future":
                obs["now_monotonic_ns"] = 0
            elif kind == "clock":
                obs["clock_id"] = "other"
            else:
                obs["model_sha256"] = "0" * 64
            with self.subTest(kind=kind):
                self.assertEqual(
                    decision(self.policy, obs, self.review, self.artifact_sha)["zone"],
                    "unknown",
                )

    def test_simultaneous_unknown_weak_and_out_of_domain_abstain(self):
        for key, value in (
            ("scope", "simultaneous_zones"),
            ("scope", "unknown"),
            ("signal_sufficient", False),
            ("domain_distance", 4.0),
        ):
            obs = dict(self.observation, **{key: value})
            with self.subTest(key=key, value=value):
                self.assertEqual(
                    decision(self.policy, obs, self.review, self.artifact_sha)["zone"],
                    "unknown",
                )

    def test_ambiguous_unknown_or_insufficient_scores_abstain(self):
        for scores in (
            {"zone_a": 0.9, "zone_b": 0.9, "unknown": 0},
            {"zone_a": 0.9, "zone_b": 0, "unknown": 1},
            {"zone_a": 0.4, "zone_b": 0.2, "unknown": 0},
        ):
            obs = dict(self.observation, scores=scores)
            self.assertEqual(
                decision(self.policy, obs, self.review, self.artifact_sha)["zone"],
                "unknown",
            )

    def test_nonfinite_score_and_changed_policy_rejected(self):
        self.observation["scores"]["zone_a"] = float("nan")
        with self.assertRaises(ValueError):
            self.admit()
        self.policy["min_score"] = 0
        with self.assertRaisesRegex(ValueError, "changed"):
            self.admit()

    def test_cli_reproducible_private_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (
                ("plan", self.settings),
                ("records", self.rows),
                ("policy", self.policy),
            ):
                (root / (name + ".json")).write_text(json.dumps(value))
            cmd = [
                sys.executable,
                "-m",
                "inference.zones",
                "readiness",
                "--plan",
                str(root / "plan.json"),
                "--records",
                str(root / "records.json"),
                "--output",
                str(root / "out.json"),
                "--expected-coordinate-frame",
                "example_lab_xz_metres",
            ]
            run = subprocess.run(
                cmd, capture_output=True, text=True, timeout=PROCESS_TIMEOUT_SECONDS
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(
                json.loads((root / "out.json").read_text()),
                readiness(
                    self.settings,
                    self.rows,
                    expected_coordinate_frame="example_lab_xz_metres",
                ),
            )
            self.assertEqual((root / "out.json").stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(
                subprocess.run(
                    cmd, capture_output=True, timeout=PROCESS_TIMEOUT_SECONDS
                ).returncode,
                0,
            )
            run = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "inference.zones",
                    "decision",
                    "--policy",
                    str(root / "policy.json"),
                    "--output",
                    str(root / "decision.json"),
                ],
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertEqual(run.returncode, 0)
            self.assertEqual(
                json.loads((root / "decision.json").read_text())["reason"],
                "no_reviewed_trained_artifact",
            )


if __name__ == "__main__":
    unittest.main()
