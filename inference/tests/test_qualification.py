"""Synthetic contract fixtures only; no original household evidence or approval.

Some cases deliberately simulate a household declaration to test the gate's
arithmetic. This is not data authentication, as every resulting report states.
"""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference import qualification as q
from inference.evidence import capture_lineage
from inference.feature_contracts import FEATURE_CONTRACT, MODEL_SCHEMAS
from inference.model import model_identity, target_identity
from inference.pipeline import digest, pair_window
from inference.tests import test_reference_alignment
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.tests.test_evidence import with_synthetic_lineage
from inference.tests.test_pipeline import label, window


def rehash(model):
    model["model_sha256"] = digest(
        {k: v for k, v in model.items() if k != "model_sha256"}
    )


def evidence(w, start, end):
    result = with_synthetic_lineage([{"window": w}])[0]["capture_evidence"]
    result.update(
        synthetic_only=False,
        raw_sha256=digest(w["session_id"]),
        planned_interval={"start_utc_ns": start, "end_utc_ns": end},
    )
    return result


def fixture(task="posture"):
    """A simulated declaration, never a report of a real reviewed recording."""
    records, sessions = [], []
    for sid, start in (("held-a", 100_000_000_000), ("held-b", 200_000_000_000)):
        trials = []
        for i in range(2):
            ids = []
            lo = start + i * 10_000_000_000
            for j in range(2):
                w = window(sid, lo + j * 2_000_000_000, amplitude=10 + 10 * i)
                lab = label(w, "seated" if i == 0 else "standing", 1 + i)
                lab["trial_id"] = f"trial-{i}"
                if task == "image_pose_2d":
                    lab.update(
                        source="camera_annotation",
                        image_pose_2d=[0.1, 0.2] * 17,
                        camera_id="synthetic-camera",
                        image_geometry_sha256="f" * 64,
                    )
                row = pair_window(
                    w, [lab], 0, expected_coordinate_frame="example_lab_xz_metres"
                )
                row["capture_evidence"] = evidence(w, start, start + 20_000_000_000)
                records.append(row)
                ids.append(w["window_id"])
            trials.append(
                {
                    "trial_id": f"trial-{i}",
                    "start_utc_ns": lo,
                    "end_utc_ns": lo + 3_000_000_000,
                    "window_ids": ids,
                }
            )
        sessions.append(
            {
                "session_id": sid,
                "capture_evidence": copy.deepcopy(records[-1]["capture_evidence"]),
                "reference_sha256": digest("reference-" + sid),
                "reference_review_sha256": digest("review-" + sid),
                "clock_review_sha256": digest("clock-" + sid),
                "reference_independent": True,
                "reference_reviewed": True,
                "trials": trials,
            }
        )
    history = []
    for sid, start in (("fit", 1_000_000_000), ("development", 10_000_000_000)):
        w = window(sid, start)
        history.append(
            {"window": w, "capture_evidence": evidence(w, start, start + 1_000_000_000)}
        )
    dims = 34 if task == "image_pose_2d" else 2
    weights = [[0.0] * dims for _ in range(192)]
    bias = [0.0] * dims
    if task == "posture":
        weights[0], bias = [-1.0, 1.0], [15.0, -15.0]
    elif task == "house_xy_m":
        weights[0] = [0.1, 0.05]
    else:
        bias = [0.1, 0.2] * 17
    model = {
        "schema": MODEL_SCHEMAS[FEATURE_CONTRACT],
        "feature_contract": FEATURE_CONTRACT,
        "task": task,
        "status": "candidate_unqualified",
        "publish_to_ha": False,
        "input_identity": model_identity(records[0]["window"]),
        "target_identity": target_identity(records[0]["label"], task),
        "classes": ["seated", "standing"] if task == "posture" else [],
        "mean": [0.0] * 192,
        "scale": [1.0] * 192,
        "weights": weights,
        "bias": bias,
        "regularization": 1.0,
        "training_sessions": ["fit"],
        "evaluation_sessions": ["development"],
        "training_windows": 20,
        "evaluation_windows": 5,
        "dataset_sha256": "d" * 64,
        "capture_lineage": capture_lineage(history),
        "metrics": {"accuracy": 1.0, "mean_error": 0.0},
    }
    rehash(model)
    policy = {
        "min_sessions": 2,
        "min_trials_per_session": 2,
        "min_windows_per_trial": 2,
        "max_time_uncertainty_ns": 0,
    }
    if task == "posture":
        policy.update(
            min_trials_per_class=2, min_trial_accuracy=1.0, min_class_trial_accuracy=1.0
        )
    else:
        policy.update(max_trial_mean_error=1e-10, max_trial_p95_error=1e-10)
        if task == "image_pose_2d":
            policy["max_joint_p95_error"] = 1e-10
    protocol = {
        "schema": q.PROTOCOL,
        "classification": "household_recording",
        "candidate_sha256": model["model_sha256"],
        "task": task,
        "author_id": "synthetic-author",
        "policy": policy,
        "predeclared_policy_sha256": digest(policy),
        "predeclaration_reference_sha256": "e" * 64,
        "sessions": sessions,
    }
    return model, records, protocol


def attestation(report):
    return {
        "schema": q.REVIEW,
        "status": "approved",
        "reviewer_id": "synthetic-independent-reviewer",
        "reviewed_at_ns": 400_000_000_000,
        **{
            k: report[k]
            for k in ("candidate_sha256", "protocol_sha256", "paired_sha256")
        },
        "evaluation_report_sha256": digest(report),
        "checks": dict.fromkeys(q.REVIEW_CHECKS, True),
    }


@unittest.skipUnless(importlib.util.find_spec("numpy"), "NumPy is required")
class QualificationTests(unittest.TestCase):
    def test_v2_replays_original_alignment_and_review_binding(self):
        source = test_reference_alignment.ReferenceAlignmentTests()
        source.setUp()
        self.addCleanup(source.doCleanups)
        row = source.paired()
        row["capture_evidence"]["synthetic_only"] = False
        w, ev = row["window"], row["capture_evidence"]
        model, _, protocol = fixture("house_xy_m")
        model["input_identity"] = model_identity(w)
        model["weights"] = [[0.0, 0.0] for _ in range(192)]
        model["bias"] = row["label"]["house_xy_m"]
        history = []
        ids = [
            "77777777-7777-4777-8777-777777777777",
            "88888888-8888-4888-8888-888888888888",
        ]
        for index, sid in enumerate(ids):
            e = copy.deepcopy(ev)
            e.update(session_id=sid, capture_id=sid, raw_sha256=digest(sid))
            e["start_boundary"]["clock"]["utc_ns"] -= (index + 1) * 10_000_000_000
            e["end_boundary"]["clock"]["utc_ns"] -= (index + 1) * 10_000_000_000
            history.append(e)
        model.update(training_sessions=ids[:1], evaluation_sessions=ids[1:])
        model["capture_lineage"] = {
            "schema": "ruview.csi.capture_lineage.v2",
            "status": "verified_closed_capture",
            "recordings": history,
        }
        rehash(model)
        protocol["candidate_sha256"] = model["model_sha256"]
        protocol["policy"].update(
            min_sessions=1,
            min_trials_per_session=1,
            min_windows_per_trial=1,
            max_time_uncertainty_ns=1_000_000_000,
        )
        protocol["predeclared_policy_sha256"] = digest(protocol["policy"])
        session = protocol["sessions"][0]
        session.update(
            session_id=w["session_id"],
            capture_evidence=copy.deepcopy(ev),
            reference_review_sha256=row["label"]["reference_lineage"]["review_sha256"],
            reference_metadata_sha256=row["label"]["reference_lineage"][
                "metadata_sha256"
            ],
            time_alignment_sha256=row["time_alignment"]["alignment_sha256"],
            trials=[
                {
                    "trial_id": row["label"]["trial_id"],
                    "start_utc_ns": w["timestamps_ns"][0],
                    "end_utc_ns": w["timestamps_ns"][-1],
                    "window_ids": [w["window_id"]],
                }
            ],
        )
        protocol["sessions"] = [session]
        self.assertTrue(
            q.evaluate(
                model,
                [row],
                protocol,
                expected_coordinate_frame="example_lab_xz_metres",
            )["passed_numerical_policy"]
        )
        bad = copy.deepcopy(row)
        bad["label"]["time_uncertainty_ns"] = 0
        with self.assertRaisesRegex(ValueError, "uncertainty"):
            q.evaluate(
                model,
                [bad],
                protocol,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        for field, reason in (
            ("reference_review_sha256", "reference_review_binding"),
            ("reference_metadata_sha256", "reference_metadata_binding"),
            ("time_alignment_sha256", "time_alignment_binding"),
        ):
            with self.subTest(field=field):
                original = session[field]
                session[field] = "0" * 64
                with self.assertRaisesRegex(ValueError, reason):
                    q.evaluate(
                        model,
                        [row],
                        protocol,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )
                session[field] = original
        for field in ("reference_metadata_sha256", "time_alignment_sha256"):
            altered = copy.deepcopy(protocol)
            del altered["sessions"][0][field]
            with (
                self.subTest(missing=field),
                self.assertRaisesRegex(ValueError, "unexpected_fields"),
            ):
                q.evaluate(
                    model,
                    [row],
                    altered,
                    expected_coordinate_frame="example_lab_xz_metres",
                )

    def test_all_three_tasks_recompute_exact_predictions_without_promotion(self):
        for task in ("posture", "house_xy_m", "image_pose_2d"):
            with self.subTest(task=task):
                model, records, protocol = fixture(task)
                before = digest([model, records, protocol])
                result = q.evaluate(
                    model,
                    records,
                    protocol,
                    expected_coordinate_frame="example_lab_xz_metres",
                )
                self.assertTrue(result["passed_numerical_policy"])
                self.assertEqual(result["window_count"], 8)
                self.assertEqual(len(result["trial_results"]), 4)
                self.assertEqual(digest([model, records, protocol]), before)
                reviewed = q.review(
                    model,
                    records,
                    protocol,
                    result,
                    attestation(result),
                    expected_coordinate_frame="example_lab_xz_metres",
                )
                self.assertTrue(reviewed["external_review_attested"])
                for key in (
                    "evidence_authenticated",
                    "model_qualified",
                    "runtime_qualified",
                    "publish_to_ha",
                ):
                    self.assertFalse(result[key])
                    self.assertFalse(reviewed[key])

    def test_checkpoint_metrics_do_not_override_trial_or_class_failure(self):
        model, records, protocol = fixture()
        model["weights"][0] = [1.0, -1.0]
        model["bias"] = [-15.0, 15.0]
        rehash(model)
        protocol["candidate_sha256"] = model["model_sha256"]
        result = q.evaluate(
            model, records, protocol, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertFalse(result["passed_numerical_policy"])
        self.assertTrue(
            all(t["metrics"]["accuracy"] == 0 for t in result["trial_results"])
        )
        self.assertEqual(len(result["failures"]), 6)
        with self.assertRaisesRegex(ValueError, "numerical_policy_failed"):
            q.review(
                model,
                records,
                protocol,
                result,
                attestation(result),
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_xy_units_and_pose_joint_tail_are_not_hidden_by_average(self):
        model, records, protocol = fixture("house_xy_m")
        model["bias"] = [3.0, 4.0]
        rehash(model)
        protocol["candidate_sha256"] = model["model_sha256"]
        result = q.evaluate(
            model, records, protocol, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertEqual(result["units"], "metres")
        self.assertEqual(result["trial_results"][0]["metrics"]["mean_error"], 5.0)
        model, records, protocol = fixture("image_pose_2d")
        model["bias"][:2] = [0.4, 0.6]
        rehash(model)
        protocol["candidate_sha256"] = model["model_sha256"]
        protocol["policy"].update(
            max_trial_mean_error=0.1, max_trial_p95_error=0.1, max_joint_p95_error=0.1
        )
        protocol["predeclared_policy_sha256"] = digest(protocol["policy"])
        result = q.evaluate(
            model, records, protocol, expected_coordinate_frame="example_lab_xz_metres"
        )
        metrics = result["trial_results"][0]["metrics"]
        self.assertLess(metrics["mean_error"], 0.1)
        self.assertAlmostEqual(metrics["joint_p95_errors"][0], 0.5)
        self.assertFalse(result["passed_numerical_policy"])

    def test_synthetic_and_unverified_evidence_is_rejected(self):
        for mode in (
            "synthetic_protocol",
            "synthetic_model",
            "synthetic_capture",
            "unverified",
        ):
            with self.subTest(mode=mode):
                model, records, protocol = fixture()
                if mode == "synthetic_protocol":
                    protocol["classification"] = "synthetic"
                elif mode == "synthetic_model":
                    for e in model["capture_lineage"]["recordings"]:
                        e["synthetic_only"] = True
                    rehash(model)
                    protocol["candidate_sha256"] = model["model_sha256"]
                elif mode == "synthetic_capture":
                    protocol["sessions"][0]["capture_evidence"]["synthetic_only"] = True
                else:
                    protocol["sessions"][0]["capture_evidence"] = {
                        "schema": "ruview.csi.pair_capture_evidence.v1",
                        "status": "unverified_research",
                    }
                with self.assertRaisesRegex(ValueError, "synthetic|unverified"):
                    q.evaluate(
                        model,
                        records,
                        protocol,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )

    def test_training_development_alias_time_and_reference_leakage_rejected(self):
        for mode in (
            "training",
            "development",
            "raw_alias",
            "time",
            "reference_alias",
            "model_alias",
            "model_time",
        ):
            with self.subTest(mode=mode):
                model, records, protocol = fixture()
                session = protocol["sessions"][0]
                if mode in ("training", "development"):
                    session["session_id"] = (
                        "fit" if mode == "training" else "development"
                    )
                elif mode == "raw_alias":
                    session["capture_evidence"]["raw_sha256"] = model[
                        "capture_lineage"
                    ]["recordings"][0]["raw_sha256"]
                elif mode == "time":
                    session["capture_evidence"]["planned_interval"]["start_utc_ns"] = 1
                elif mode == "reference_alias":
                    protocol["sessions"][1]["reference_sha256"] = session[
                        "reference_sha256"
                    ]
                else:
                    history = model["capture_lineage"]["recordings"]
                    if mode == "model_alias":
                        history[1]["raw_sha256"] = history[0]["raw_sha256"]
                    else:
                        history[1]["planned_interval"] = history[0]["planned_interval"]
                    rehash(model)
                    protocol["candidate_sha256"] = model["model_sha256"]
                with self.assertRaisesRegex(
                    ValueError, "training_development|renamed|overlap|aliased"
                ):
                    q.evaluate(
                        model,
                        records,
                        protocol,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )

    def test_explicit_coverage_limits_and_invalid_policy_values(self):
        model, records, protocol = fixture()
        protocol["policy"]["min_windows_per_trial"] = 3
        protocol["predeclared_policy_sha256"] = digest(protocol["policy"])
        result = q.evaluate(
            model, records, protocol, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertFalse(result["passed_numerical_policy"])
        self.assertTrue(all(not r["passed"] for r in result["trial_results"]))
        for field, value in (
            ("min_sessions", True),
            ("max_time_uncertainty_ns", -1),
            ("min_trial_accuracy", float("nan")),
            ("min_class_trial_accuracy", 1.01),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(protocol)
                changed["policy"][field] = value
                with self.assertRaises(ValueError):
                    q.evaluate(
                        model,
                        records,
                        changed,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )

    def test_missing_duplicate_partial_or_undeclared_windows_rejected(self):
        for mode in (
            "missing",
            "duplicate",
            "undeclared",
            "partial_label",
            "partial_trial",
        ):
            with self.subTest(mode=mode):
                model, records, protocol = fixture()
                if mode == "missing":
                    records.pop()
                elif mode == "duplicate":
                    records.append(copy.deepcopy(records[0]))
                elif mode == "undeclared":
                    protocol["sessions"][0]["trials"][0]["window_ids"].pop()
                elif mode == "partial_label":
                    records[0]["label"]["end_ns"] -= 1
                else:
                    protocol["sessions"][0]["trials"][0]["start_utc_ns"] += 1
                with self.assertRaisesRegex(
                    ValueError, "partial|duplicate|undeclared|incomplete"
                ):
                    q.evaluate(
                        model,
                        records,
                        protocol,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )

    def test_policy_candidate_identity_geometry_and_review_bindings(self):
        for mode in ("policy", "hash", "task", "unsafe_id", "target", "independence"):
            with self.subTest(mode=mode):
                model, records, protocol = fixture("house_xy_m")
                if mode == "policy":
                    protocol["policy"]["max_trial_mean_error"] = -1
                elif mode == "hash":
                    protocol["candidate_sha256"] = "0" * 64
                elif mode == "task":
                    protocol["task"] = "image_pose_2d"
                elif mode == "unsafe_id":
                    protocol["author_id"] = "../unsafe\n"
                elif mode == "target":
                    records[0]["label"]["coordinate_calibration_sha256"] = "0" * 64
                else:
                    protocol["sessions"][0]["reference_independent"] = False
                with self.assertRaises(ValueError):
                    q.evaluate(
                        model,
                        records,
                        protocol,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )
        model, records, protocol = fixture()
        report = q.evaluate(
            model, records, protocol, expected_coordinate_frame="example_lab_xz_metres"
        )
        for mode in (
            "same_reviewer",
            "missing_check",
            "forged_report",
            "wrong_hash",
            "pending",
        ):
            checked, approval = copy.deepcopy(report), attestation(report)
            if mode == "same_reviewer":
                approval["reviewer_id"] = protocol["author_id"]
            elif mode == "missing_check":
                approval["checks"]["reference_truth_reviewed"] = False
            elif mode == "forged_report":
                checked["trial_results"][0]["metrics"]["accuracy"] = 0.5
            elif mode == "wrong_hash":
                approval["paired_sha256"] = "0" * 64
            else:
                approval["status"] = "pending"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                q.review(
                    model,
                    records,
                    protocol,
                    checked,
                    approval,
                    expected_coordinate_frame="example_lab_xz_metres",
                )

    def test_cli_roundtrip_private_output_and_strict_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, records, protocol = fixture()
            for name, value in (("model", model), ("protocol", protocol)):
                (root / name).write_text(json.dumps(value))
            paired = root / "paired"
            paired.write_text("".join(json.dumps(r) + "\n" for r in records))
            base = [
                sys.executable,
                "-m",
                "inference.qualification",
                "--expected-coordinate-frame",
                "example_lab_xz_metres",
            ]
            common = [
                "--model",
                str(root / "model"),
                "--protocol",
                str(root / "protocol"),
                "--paired",
                str(paired),
            ]

            def run(extra):
                return subprocess.run(
                    base + extra,
                    cwd=Path(__file__).resolve().parents[2],
                    capture_output=True,
                    text=True,
                    timeout=PROCESS_TIMEOUT_SECONDS,
                )

            report = root / "report"
            result = run(["evaluate", *common, "--output", str(report)])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(os.stat(report).st_mode & 0o777, 0o600)
            approval = root / "approval"
            approval.write_text(json.dumps(attestation(json.loads(report.read_text()))))
            result = run(
                [
                    "review",
                    *common,
                    "--report",
                    str(report),
                    "--review",
                    str(approval),
                    "--output",
                    str(root / "reviewed"),
                ]
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(
                json.loads((root / "reviewed").read_text())["publish_to_ha"]
            )
            self.assertEqual(
                run(["evaluate", *common, "--output", str(report)]).returncode, 1
            )
            paired.write_bytes(paired.read_bytes().rstrip(b"\n"))
            self.assertEqual(
                run(
                    ["evaluate", *common, "--output", str(root / "partial")]
                ).returncode,
                1,
            )
            self.assertFalse((root / "partial").exists())


if __name__ == "__main__":
    unittest.main()
