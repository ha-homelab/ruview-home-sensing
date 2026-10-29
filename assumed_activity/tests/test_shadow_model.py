import copy
import datetime as dt
import hashlib
import json
import statistics
import tempfile
import unittest
from pathlib import Path

from assumed_activity import shadow_model as model


def stamp(seconds):
    return (
        dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=seconds)
    ).isoformat()


def fixture():
    contract = {
        "name": "example_signal",
        "version": 1,
        "features": ["signal"],
        "identity": {"node": "test-node", "profile": "example-v1"},
    }
    policy = {
        "schema": model.POLICY_SCHEMA,
        "feature_contract": contract,
        "reference_groups": ["independent-sensor"],
        "validation_start_utc": stamp(240),
        "final_holdout_start_utc": stamp(600),
        "split_gap_seconds": 10,
        "epochs": 100,
    }
    rows = []
    for i in range(80):
        on = i % 3 == 0
        rows.append(
            {
                "schema": model.SCHEMA,
                "example_id": str(i),
                "interval_start_utc": stamp(i * 5),
                "interval_end_utc": stamp(i * 5),
                "observed_at_utc": stamp(i * 5),
                "feature_contract": copy.deepcopy(contract),
                "features": {"signal": (2 if on else -2) + (i % 2) * 0.05},
                "quality": {"eligible": True},
                "maintenance_excluded": False,
                "references": [
                    {
                        "source_group": "independent-sensor",
                        "independent": True,
                        "derived_from_ruview": False,
                        "kind": "motion",
                        "available": True,
                        "state": "on" if on else "off",
                        "observed_at_utc": stamp(i * 5),
                    }
                ],
            }
        )
    return rows, policy


class ShadowModelTests(unittest.TestCase):
    def test_learns_and_loads_real_json_model(self):
        rows, policy = fixture()
        artifact, report = model.train(rows, policy)
        loaded = json.loads(json.dumps(artifact))
        prediction = model.predict(loaded, rows[-2:])
        self.assertTrue(report["passes_shadow_baseline"])
        self.assertGreater(report["candidate"]["balanced_accuracy"], 0.99)
        self.assertTrue(all(p["available"] for p in prediction))
        self.assertFalse(loaded["payload"]["publish_to_ha"])

    def test_validation_does_not_fit_preprocessing_or_coefficients(self):
        rows, policy = fixture()
        first, _ = model.train(rows, policy)
        for row in rows[48:]:
            row["features"]["signal"] = 10000
        second, report = model.train(rows, policy)
        self.assertEqual(
            first["payload"]["parameters"], second["payload"]["parameters"]
        )
        self.assertAlmostEqual(
            first["payload"]["parameters"]["mean"][0],
            statistics.fmean(r["features"]["signal"] for r in rows[:46]),
        )
        self.assertFalse(report["passes_shadow_baseline"])

    def test_holdout_features_and_targets_are_not_inspected(self):
        rows, policy = fixture()
        expected, _ = model.train(rows, policy)
        extra = copy.deepcopy(rows[0])
        extra.update(
            example_id="holdout",
            interval_start_utc=stamp(700),
            interval_end_utc=stamp(700),
            observed_at_utc=stamp(700),
            features=None,
            references=None,
        )
        actual, report = model.train([*rows, extra], policy)
        self.assertEqual(
            expected["payload"]["parameters"], actual["payload"]["parameters"]
        )
        self.assertEqual(report["skipped_examples"]["reserved_final_holdout"], 1)

    def test_split_gap_is_not_training_or_validation(self):
        rows, policy = fixture()
        partitions, skipped = model.prepare(rows, policy)
        self.assertEqual(skipped["split_gap"], 2)
        self.assertEqual(len(partitions["train"]), 46)
        self.assertEqual(len(partitions["validation"]), 32)

    def test_unknown_reference_cannot_be_negative(self):
        rows, policy = fixture()
        rows[1]["references"][0]["state"] = "unknown"
        rows[2]["references"][0]["available"] = False
        _, report = model.train(rows, policy)
        self.assertEqual(report["skipped_examples"]["reference_unavailable"], 2)

    def test_alias_conflict_and_derived_reference_are_not_labels(self):
        rows, policy = fixture()
        alias = copy.deepcopy(rows[0]["references"][0])
        alias["state"] = "off"
        rows[0]["references"].append(alias)
        rows[3]["references"][0]["derived_from_ruview"] = True
        _, report = model.train(rows, policy)
        self.assertEqual(report["skipped_examples"]["conflicting_reference_aliases"], 1)
        self.assertEqual(report["skipped_examples"]["reference_lineage_unverified"], 1)

    def test_matching_alias_does_not_duplicate_training(self):
        rows, policy = fixture()
        expected, _ = model.train(rows, policy)
        for row in rows:
            row["references"].append(copy.deepcopy(row["references"][0]))
        actual, report = model.train(rows, policy)
        self.assertEqual(
            expected["payload"]["parameters"], actual["payload"]["parameters"]
        )
        self.assertEqual(report["train_examples"], 46)

    def test_missing_reference_group_abstains(self):
        rows, policy = fixture()
        policy["reference_groups"].append("second-sensor")
        with self.assertRaisesRegex(model.ShadowModelError, "Insufficient train"):
            model.train(rows, policy)

    def test_stale_and_future_references_excluded(self):
        rows, policy = fixture()
        rows[3]["references"][0]["observed_at_utc"] = stamp(-100)
        rows[6]["references"][0]["observed_at_utc"] = stamp(1000)
        _, report = model.train(rows, policy)
        self.assertEqual(report["skipped_examples"]["reference_time_not_current"], 2)

    def test_features_missing_or_profile_changed_abstain(self):
        rows, policy = fixture()
        artifact, _ = model.train(rows, policy)
        probes = copy.deepcopy(rows[-3:])
        probes[0]["features"] = {}
        probes[1]["feature_contract"]["identity"]["profile"] = "changed"
        probes[2]["features"]["signal"] = float("nan")
        results = model.predict(artifact, probes)
        self.assertTrue(all(not x["available"] for x in results))
        self.assertTrue(all(x["probability_reference_active"] is None for x in results))

    def test_maintenance_does_not_become_training(self):
        rows, policy = fixture()
        rows[1]["maintenance_excluded"] = True
        _, report = model.train(rows, policy)
        self.assertEqual(
            report["skipped_examples"]["maintenance_or_exclusion_unknown"], 1
        )

    def test_duplicate_ids_and_overlaps_rejected(self):
        rows, policy = fixture()
        with self.assertRaisesRegex(model.ShadowModelError, "Duplicate"):
            model.train(rows + [rows[0]], policy)
        rows[1]["interval_start_utc"] = stamp(-1)
        with self.assertRaisesRegex(model.ShadowModelError, "Overlapping"):
            model.train(rows, policy)

    def test_too_few_training_classes_blocks_fit(self):
        rows, policy = fixture()
        for row in rows[:48]:
            row["references"][0]["state"] = "off"
        with self.assertRaisesRegex(model.ShadowModelError, "Insufficient train"):
            model.train(rows, policy)

    def test_insufficient_validation_still_saves_unaccepted_candidate(self):
        rows, policy = fixture()
        artifact, report = model.train(rows[:48], policy)
        model.validate_artifact(artifact)
        self.assertEqual(report["evaluation_status"], "pending_validation")
        self.assertIsNone(report["candidate"])
        self.assertFalse(report["passes_shadow_baseline"])
        self.assertFalse(report["production_promotion_allowed"])

    def test_integrity_and_promotion_flags_rejected(self):
        rows, policy = fixture()
        artifact, _ = model.train(rows, policy)
        artifact["payload"]["parameters"]["bias"] = 10
        with self.assertRaisesRegex(model.ShadowModelError, "integrity"):
            model.validate_artifact(artifact)
        artifact["payload"]["publish_to_ha"] = True
        artifact["payload_sha256"] = model.sha(artifact["payload"])
        with self.assertRaisesRegex(model.ShadowModelError, "shadow-only"):
            model.validate_artifact(artifact)

    def test_frozen_evaluation_cannot_overlap_fit(self):
        rows, policy = fixture()
        artifact, _ = model.train(rows, policy)
        with self.assertRaisesRegex(model.ShadowModelError, "overlaps"):
            model.evaluate(artifact, rows, stamp(0), stamp(400))
        report = model.evaluate(artifact, rows, stamp(240), stamp(400))
        self.assertEqual(report["candidate"]["examples"], 32)

    def test_frozen_evaluation_rejects_duplicate_intervals_and_purge_gap(self):
        rows, policy = fixture()
        artifact, _ = model.train(rows, policy)
        with self.assertRaisesRegex(model.ShadowModelError, "Duplicate"):
            model.evaluate(artifact, rows + [rows[-1]], stamp(240), stamp(400))
        with self.assertRaisesRegex(model.ShadowModelError, "purge"):
            model.evaluate(artifact, rows, stamp(230), stamp(400))
        report = model.evaluate(artifact, rows[-3:], stamp(380), stamp(400))
        self.assertFalse(report["validation_sufficient"])
        self.assertEqual(report["evaluation_status"], "pending_validation")

    def test_prediction_with_missing_timestamp_abstains(self):
        rows, policy = fixture()
        artifact, _ = model.train(rows, policy)
        del rows[0]["observed_at_utc"]
        result = model.predict(artifact, rows[:1])[0]
        self.assertFalse(result["available"])

    def test_cli_pin_and_exclusive_private_output(self):
        rows, policy = fixture()
        artifact, _ = model.train(rows, policy)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            model_path = directory / "model.json"
            model.write_new(model_path, artifact)
            self.assertEqual(model_path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(model.ShadowModelError, "already exists"):
                model.write_new(model_path, artifact)
            examples = directory / "examples.jsonl"
            examples.write_text("\n".join(json.dumps(row) for row in rows[-2:]) + "\n")
            args = [
                "predict",
                "--model",
                str(model_path),
                "--examples",
                str(examples),
                "--output",
                str(directory / "predictions.json"),
                "--expected-sha256",
            ]
            with self.assertRaisesRegex(model.ShadowModelError, "pinned"):
                model.main(args + ["0" * 64])
            model.main(args + [hashlib.sha256(model_path.read_bytes()).hexdigest()])
            self.assertEqual(
                len(json.loads((directory / "predictions.json").read_text())), 2
            )


if __name__ == "__main__":
    unittest.main()
