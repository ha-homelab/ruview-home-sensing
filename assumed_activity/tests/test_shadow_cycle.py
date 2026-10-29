import copy
import json
import tempfile
import unittest
from pathlib import Path

from assumed_activity import shadow_cycle, shadow_model
from assumed_activity.tests.test_shadow_model import fixture, stamp


def setup():
    rows, fit = fixture()
    for key in ["schema", "validation_start_utc", "final_holdout_start_utc"]:
        fit.pop(key)
    policy = {
        "schema": shadow_cycle.SCHEMA,
        "capture_start_utc": stamp(0),
        "final_holdout_start_utc": stamp(600),
        "cycle_seconds": 60,
        "validation_seconds": 120,
        "fit_policy": fit,
    }
    return rows, policy


class CycleTests(unittest.TestCase):
    def test_anchors_completed_cutoff_before_inspecting_outcomes(self):
        rows, policy = setup()
        result = shadow_cycle.cycle(rows, policy, stamp(399))
        self.assertEqual(result["completed_cutoff_utc"], stamp(360))
        self.assertEqual(result["validation_start_utc"], stamp(240))
        self.assertEqual(result["status"], "passes")
        altered = copy.deepcopy(rows)
        for row in altered[72:]:
            row["references"] = None
            row["features"] = None
        other = shadow_cycle.cycle(altered, policy, stamp(399))
        self.assertEqual(result["candidate"], other["candidate"])

    def test_insufficient_history_has_real_pending_result(self):
        rows, policy = setup()
        result = shadow_cycle.cycle(rows, policy, stamp(119))
        self.assertEqual(result["status"], "fit_pending")
        self.assertIsNone(result["candidate"])

    def test_training_class_shortage_does_not_fake_candidate(self):
        rows, policy = setup()
        for row in rows[:48]:
            row["references"][0]["state"] = "off"
        result = shadow_cycle.cycle(rows, policy, stamp(399))
        self.assertEqual(result["status"], "fit_pending")
        self.assertIn("Insufficient train", result["reason"])

    def test_sparse_validation_retains_loadable_candidate(self):
        rows, policy = setup()
        result = shadow_cycle.cycle(rows[:50], policy, stamp(399))
        self.assertEqual(result["status"], "eval_pending")
        shadow_model.validate_artifact(result["candidate"])
        self.assertFalse(result["model_update_allowed"])

    def test_holdout_never_enters_cycle_even_when_running_late(self):
        rows, policy = setup()
        added = copy.deepcopy(rows[0])
        added.update(
            example_id="future",
            observed_at_utc=stamp(700),
            interval_start_utc=stamp(700),
            interval_end_utc=stamp(700),
            features=None,
            references=None,
        )
        result = shadow_cycle.cycle(rows + [added], policy, stamp(1200))
        self.assertEqual(result["completed_cutoff_utc"], stamp(600))
        self.assertEqual(result["outside_completed_development_examples"], 1)

    def test_previous_artifact_is_not_modified_and_can_be_compared(self):
        rows, policy = setup()
        previous = shadow_cycle.cycle(rows, policy, stamp(399))["candidate"]
        snapshot = copy.deepcopy(previous)
        result = shadow_cycle.cycle(rows, policy, stamp(459), previous)
        self.assertEqual(previous, snapshot)
        self.assertEqual(result["previous_comparison_status"], "compared")
        self.assertIn("improves_previous", result)
        self.assertFalse(result["model_update_allowed"])

    def test_immutable_manifest_and_artifacts(self):
        rows, policy = setup()
        result = shadow_cycle.cycle(rows, policy, stamp(399))
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "cycle"
            manifest = shadow_cycle.write_cycle(output, result)
            self.assertEqual(
                json.loads((output / "manifest.json").read_text()), manifest
            )
            self.assertIn("candidate.json", manifest["files_sha256"])
            self.assertEqual((output / "candidate.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                shadow_cycle.write_cycle(output, result)

    def test_invalid_input_is_not_silently_downgraded_to_pending(self):
        rows, policy = setup()
        with self.assertRaisesRegex(shadow_model.ShadowModelError, "Duplicate"):
            shadow_cycle.cycle(rows + [rows[0]], policy, stamp(399))


if __name__ == "__main__":
    unittest.main()
