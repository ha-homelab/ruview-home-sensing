"""Synthetic metric bodies only; these tests establish no detection accuracy."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.fall_detection import (
    CONFIG_SCHEMA,
    OBSERVATION_SCHEMA,
    REPLAY_SCHEMA,
    FallCandidateDetector,
    configuration,
    digest,
    main,
    replay,
)
from inference.fall_evaluation import evaluate
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS

MS = 1_000_000


def config():
    return {
        "schema": CONFIG_SCHEMA,
        "classification": "synthetic",
        "provenance": {
            "session_id": "synthetic-session",
            "source_id": "synthetic-depth",
            "clock_id": "synthetic-clock",
            "track_id": "synthetic-track",
            "body_model_sha256": "a" * 64,
            "transform_sha256": "b" * 64,
            "floor_reference_sha256": "c" * 64,
            "frame": "floor_local_xyz_m",
            "landmark": "pelvis_center",
        },
        "policy": {
            "max_source_age_ms": 300,
            "max_gap_ms": 250,
            "min_confidence": 0.8,
            "max_height_uncertainty_m": 0.05,
            "upright_min_height_m": 0.9,
            "lying_max_height_m": 0.4,
            "min_drop_m": 0.6,
            "min_upright_ms": 600,
            "min_upright_samples": 3,
            "max_descent_ms": 800,
            "min_lying_ms": 600,
            "min_lying_samples": 3,
            "cooldown_ms": 3000,
        },
    }


def observation(ms, *, height=1.1, posture="standing", seq=None):
    return {
        "schema": OBSERVATION_SCHEMA,
        "classification": "synthetic",
        "provenance": copy.deepcopy(config()["provenance"]),
        "epoch": "boot-one",
        "sequence": ms // 100 if seq is None else seq,
        "source_at_ns": ms * MS,
        "received_at_ns": ms * MS + 10 * MS,
        "person_count": 1,
        "association_unambiguous": True,
        "point_xyz_m": [1.5, 2.5, height],
        "height_uncertainty_m": 0.02,
        "body_confidence": 0.95,
        "posture": posture,
        "posture_confidence": 0.95,
    }


def scenario():
    return (
        [observation(ms) for ms in range(0, 900, 100)]
        + [observation(900, height=0.8, posture="seated")]
        + [
            observation(ms, height=0.25, posture="lying")
            for ms in range(1000, 2400, 100)
        ]
    )


def run(observations, detector=None):
    detector = detector or FallCandidateDetector(config())
    return [detector.update(o, now_ns=o["received_at_ns"]) for o in observations]


class FallCandidateTests(unittest.TestCase):
    def test_rapid_drop_and_sustained_lying_emit_one_delayed_candidate(self):
        results = run(scenario())
        events = [r["event"] for r in results if r["event"]]
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["at_ns"], 1610 * MS)
        self.assertEqual(e["source_onset_ns"], 900 * MS)
        self.assertAlmostEqual(e["evidence"]["drop_lower_bound_m"], 0.81)
        self.assertEqual(e["evidence"]["descent_duration_ms"], 200)
        self.assertEqual(e["evidence"]["lying_duration_ms"], 600)
        for r in [e, *results]:
            for key in (
                "confirmed",
                "recognition_validated",
                "provenance_verified",
                "publish_to_ha",
            ):
                self.assertIs(r[key], False)
        self.assertTrue(all(r["event"] is None for r in results[:16]))

    def test_lying_and_seated_alone_never_emit(self):
        for posture, height in [("lying", 0.25), ("seated", 0.6)]:
            results = run(
                [
                    observation(ms, height=height, posture=posture)
                    for ms in range(0, 10_000, 100)
                ]
            )
            self.assertFalse(any(r["event"] for r in results))

    def test_slow_descent_small_drop_and_brief_lying_never_emit(self):
        slow = (
            scenario()[:9]
            + [
                observation(ms, height=0.7, posture="seated")
                for ms in range(900, 2000, 100)
            ]
            + [
                observation(ms, height=0.25, posture="lying")
                for ms in range(2000, 3000, 100)
            ]
        )
        small = scenario()
        for o in small[10:]:
            o["point_xyz_m"][2] = 0.65
        brief = scenario()[:14] + [observation(ms) for ms in range(1400, 2200, 100)]
        for values in (slow, small, brief):
            self.assertFalse(any(r["event"] for r in run(values)))

    def test_uncertainty_is_subtracted_from_drop_not_a_confidence_label(self):
        c = config()
        c["policy"].update(
            max_height_uncertainty_m=0.3,
            upright_min_height_m=0.7,
            lying_max_height_m=0.6,
        )
        values = scenario()
        for o in values:
            o["height_uncertainty_m"] = 0.3
        self.assertFalse(any(r["event"] for r in run(values, FallCandidateDetector(c))))

    def test_unknown_low_quality_and_multiple_bodies_break_transition(self):
        for name, value in [
            ("posture", "unknown"),
            ("body_confidence", 0.2),
            ("posture_confidence", 0.2),
            ("height_uncertainty_m", 0.2),
            ("person_count", 2),
            ("association_unambiguous", False),
            ("point_xyz_m", None),
        ]:
            with self.subTest(name=name):
                values = scenario()
                values[12][name] = value
                result = run(values)
                self.assertEqual(result[12]["state"], "unavailable")
                self.assertFalse(any(r["event"] for r in result))

    def test_epoch_track_model_and_frame_changes_reset_evidence(self):
        for change in ("epoch", "track_id", "body_model_sha256", "frame"):
            with self.subTest(change=change):
                values = scenario()
                if change == "epoch":
                    for o in values[12:]:
                        o["epoch"] = "boot-two"
                else:
                    values[12]["provenance"][change] = "other"
                self.assertFalse(any(r["event"] for r in run(values)))

    def test_missing_sequence_duplicate_backward_and_time_gap_reset(self):
        for changed in (
            scenario()[:12] + scenario()[13:],
            scenario()[:12] + [scenario()[11]] + scenario()[12:],
            scenario()[:12] + [scenario()[10]] + scenario()[12:],
            scenario()[:12] + scenario()[16:],
        ):
            self.assertFalse(any(r["event"] for r in run(changed)))

    def test_stale_future_and_reversed_receipts_cannot_emit_late_alarm(self):
        for mode in ("stale", "future", "reversed"):
            d = FallCandidateDetector(config())
            events = []
            for index, o in enumerate(scenario()):
                now = o["received_at_ns"]
                if index == 12:
                    if mode == "stale":
                        now += 500 * MS
                    elif mode == "future":
                        o["source_at_ns"] = now + 1
                    else:
                        now = 1
                events.append(d.update(o, now_ns=now)["event"])
            self.assertFalse(any(events))

    def test_timer_withdraws_pending_event_and_does_not_emit(self):
        d = FallCandidateDetector(config())
        run(scenario()[:15], d)
        expired = d.advance(1900 * MS)
        self.assertEqual(expired["state"], "unavailable")
        self.assertIsNone(expired["event"])
        self.assertFalse(any(r["event"] for r in run(scenario()[19:], d)))

    def test_invalid_clock_resets_evidence_even_if_caller_recovers(self):
        for method in ("advance", "update"):
            for value in (float("nan"), True, -1, 2**63):
                with self.subTest(method=method, value=value):
                    d = FallCandidateDetector(config())
                    run(scenario()[:12], d)
                    highwater = d.last_now
                    d.cooldown_until = 1  # Retain independent state on failure.
                    with self.assertRaisesRegex(ValueError, "invalid_integer"):
                        if method == "advance":
                            d.advance(value)
                        else:
                            d.update(scenario()[12], now_ns=value)
                    self.assertEqual(d.last_now, highwater)
                    self.assertEqual(d.cooldown_until, 1)
                    self.assertFalse(any(r["event"] for r in run(scenario()[12:], d)))

    def test_cooldown_survives_bad_data_and_new_upright_required_after(self):
        d = FallCandidateDetector(config())
        events = [r["event"] for r in run(scenario(), d) if r["event"]]
        d.update({}, now_ns=2400 * MS)
        lying = [
            observation(ms, height=0.25, posture="lying")
            for ms in range(2500, 6000, 100)
        ]
        self.assertFalse(any(r["event"] for r in run(lying, d)))
        repeated = scenario()
        for o in repeated:
            o["source_at_ns"] += 6000 * MS
            o["received_at_ns"] += 6000 * MS
            o["sequence"] += 60
        events += [r["event"] for r in run(repeated, d) if r["event"]]
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["alert_id"], events[1]["alert_id"])

    def test_nonfinite_bool_2d_and_ld2450_like_inputs_are_rejected(self):
        for update in (
            {"point_xyz_m": [1, 2]},
            {"point_xyz_m": [1, 2, float("nan")]},
            {"point_xyz_m": [1, 2, True]},
            {"body_confidence": float("inf")},
            {"person_count": True},
            {"sequence": True},
        ):
            o = observation(0)
            o.update(update)
            self.assertEqual(run([o])[0]["state"], "unavailable")
        self.assertEqual(
            run([dict(observation(0), schema="ruview.ld2450.observation.v1")])[0][
                "state"
            ],
            "unavailable",
        )

    def test_configuration_is_explicit_bounded_and_copied(self):
        for mutate in (
            lambda c: c["policy"].pop("min_drop_m"),
            lambda c: c["policy"].update(min_gap_ms=1),
            lambda c: c["policy"].update(lying_max_height_m=2),
            lambda c: c["policy"].update(cooldown_ms=True),
            lambda c: c["provenance"].update(frame="example_lab_xz_metres"),
        ):
            c = config()
            mutate(c)
            with self.assertRaises(ValueError):
                configuration(c)
        c = config()
        d = FallCandidateDetector(c)
        c["policy"]["min_drop_m"] = 100
        self.assertTrue(any(r["event"] for r in run(scenario(), d)))

    def test_replay_exports_occurrences_for_existing_evaluator_without_reference(self):
        data = {
            "schema": REPLAY_SCHEMA,
            "configuration": config(),
            "records": [
                {"now_ns": o["received_at_ns"], "observation": o} for o in scenario()
            ],
        }
        report = replay(data)
        self.assertEqual(
            report["alerts"],
            [{"alert_id": report["events"][0]["alert_id"], "at_ns": 1610 * MS}],
        )
        self.assertNotIn("reference_events", report)
        policy = {
            "early_tolerance_ns": 0,
            "max_latency_ns": 1000 * MS,
            "min_reference_hours": 0.001,
            "min_negative_reference_hours": 0.001,
            "min_fall_events": 1,
            "min_detector_coverage_fraction": 1,
            "min_recall": 1,
            "max_false_alerts_per_reference_hour": 0,
            "max_false_alerts_per_negative_hour": 0,
            "max_p95_latency_seconds": 1,
        }
        evaluated = evaluate(
            {
                "schema": "ruview.fall-evaluation-input.v1",
                "classification": "synthetic",
                "candidate_sha256": report["candidate_sha256"],
                "training_session_ids": [],
                "policy": policy,
                "predeclared_policy_sha256": digest(policy),
                "reference_review_sha256": "d" * 64,
                "sessions": [
                    {
                        "session_id": "synthetic-reference",
                        "clock_id": "synthetic-clock",
                        "reference_independent": True,
                        "reference_reviewed": True,
                        "reference_sha256": "e" * 64,
                        "detector_recording_sha256": "f" * 64,
                        "start_ns": 0,
                        "end_ns": 10_000 * MS,
                        "reference_coverage": [[0, 10_000 * MS]],
                        "detector_coverage": [[0, 10_000 * MS]],
                        "reference_events": [
                            {
                                "event_id": "synthetic-only",
                                "onset_ns": 900 * MS,
                                "uncertainty_ns": 0,
                            }
                        ],
                        "alerts": report["alerts"],
                    }
                ],
            }
        )
        self.assertEqual(evaluated["counts"]["tp"], 1)
        self.assertFalse(evaluated["recognition_validated"])

    def test_cli_private_output_no_overwrite_and_no_fifo_reads(self):
        data = {
            "schema": REPLAY_SCHEMA,
            "configuration": config(),
            "records": [
                {"now_ns": o["received_at_ns"], "observation": o} for o in scenario()
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.json", root / "result.json"
            source.write_text(json.dumps(data))
            self.assertEqual(main(["--input", str(source), "--output", str(output)]), 0)
            previous = output.read_bytes()
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                main(["--input", str(source), "--output", str(output)])
            self.assertEqual(output.read_bytes(), previous)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "inference.fall_detection",
                    "--input",
                    str(fifo),
                    "--output",
                    str(root / "unused"),
                ],
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "unused").exists())

    def test_cli_duplicate_keys_and_bounded_record_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            source.write_text('{"schema": "x", "schema": "y"}')
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                main(["--input", str(source), "--output", str(root / "unused")])
        for records in ([], [None] * 10_001):
            with self.assertRaisesRegex(ValueError, "invalid_record_count"):
                replay(
                    {
                        "schema": REPLAY_SCHEMA,
                        "configuration": config(),
                        "records": records,
                    }
                )


if __name__ == "__main__":
    unittest.main()
