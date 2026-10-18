"""Synthetic-only v2 capture identities; never reference or household evidence."""

import copy
import unittest

from inference.model import features, model_identity, predict, train, validate_model
from inference.pipeline import (
    FRAME_SCHEMA_V2,
    LABEL_SCHEMA_V2,
    PAIR_SCHEMA_V2,
    WINDOW_SCHEMA_V2,
    WindowBuilder,
    digest,
    pair_window,
    validate_frame,
    validate_label,
)
from inference.tests.test_pipeline import dataset, frame, label, profile, window

CAPTURE_A = "11111111-1111-4111-8111-111111111111"
CAPTURE_B = "22222222-2222-4222-8222-222222222222"
WORKER = "33333333-3333-4333-8333-333333333333"
OTHER_WORKER = "44444444-4444-4444-8444-444444444444"
CLOCK = "55555555-5555-4555-8555-555555555555/" + WORKER


def v2_frame(index, capture=CAPTURE_A, base=1_000_000_000, amplitude=10):
    value = frame(index, capture, base, amplitude)
    value.update(
        schema=FRAME_SCHEMA_V2,
        capture_id=capture,
        worker_run_id=WORKER,
        clock_id=CLOCK,
        monotonic_origin="worker_start",
        ingress_sequence=10_001 + index * 3,
        capture_sequence=1 + index * 2,
    )
    return value


def v2_window(
    capture=CAPTURE_A,
    base=1_000_000_000,
    amplitude=10,
    admission_start=0,
    ingress_start=0,
):
    builder = WindowBuilder(profiles=[profile()])
    for index in range(11):
        item = v2_frame(index, capture, base, amplitude)
        item["sequence"] += admission_start
        item["capture_sequence"] += admission_start * 2
        item["ingress_sequence"] += ingress_start * 3
        result = builder.push(item)
    return result


def v2_label(value, posture="standing", coordinate=1):
    result = label(value, posture, coordinate)
    result.update(
        schema=LABEL_SCHEMA_V2,
        capture_id=value["capture_id"],
        worker_run_id=value["worker_run_id"],
        clock_id=value["clock_id"],
    )
    return result


def v2_dataset():
    result = []
    for capture_index, (capture, start) in enumerate(
        ((CAPTURE_A, 10_000_000_000), (CAPTURE_B, 100_000_000_000))
    ):
        for index in range(24):
            value = v2_window(
                capture,
                start + index * 2_000_000_000,
                10 + index,
                admission_start=index * 11,
                ingress_start=(capture_index * 24 + index) * 11,
            )
            truth = v2_label(value, "standing" if index % 2 else "seated", index)
            result.append(
                pair_window(
                    value, [truth], 0, expected_coordinate_frame="example_lab_xz_metres"
                )
            )
    return result


def rehash_window(value):
    value["window_id"] = digest({k: v for k, v in value.items() if k != "window_id"})


class CaptureIdentityTests(unittest.TestCase):
    def test_legacy_golden_outputs_unchanged(self):
        value = window()
        self.assertEqual(
            digest(value),
            "6032472cfa51474e023d08a0fc06c7d72d1d1b026fcd73506bcf8cb597fb46bf",
        )
        self.assertEqual(
            digest(
                pair_window(
                    value,
                    [label(value)],
                    0,
                    expected_coordinate_frame="example_lab_xz_metres",
                )
            ),
            "fe1b606217549ba58b82bd183b1f5551289aed397f00481847f8fcdcbe68c37b",
        )
        self.assertEqual(
            digest(model_identity(value)),
            "174533f672020032a02ec2d3697c8429fa1c3c03caea2640c38301dcb2f144a3",
        )
        self.assertEqual(
            digest(features(value)),
            "086b5315eacda12f63092c45a8a6b41d1c9956f9c4820971bcf19d6d5e6323a7",
        )

    def test_v2_preserves_clock_and_original_admission_ordinals(self):
        frames = [v2_frame(i) for i in range(11)]
        original = copy.deepcopy(frames)
        builder = WindowBuilder(profiles=[profile()])
        for item in frames:
            value = builder.push(item)
        self.assertEqual(frames, original)
        self.assertEqual(value["schema"], WINDOW_SCHEMA_V2)
        self.assertEqual(value["source_frame_schema"], FRAME_SCHEMA_V2)
        self.assertEqual(value["session_id"], CAPTURE_A)
        self.assertEqual(value["capture_id"], CAPTURE_A)
        self.assertEqual(value["worker_run_id"], WORKER)
        self.assertEqual(value["clock_id"], CLOCK)
        for frame_key, window_key in (
            ("received_at_ns", "timestamps_ns"),
            ("received_monotonic_ns", "monotonic_ns"),
            ("sequence", "sequences"),
            ("ingress_sequence", "ingress_sequences"),
            ("capture_sequence", "capture_sequences"),
        ):
            self.assertEqual(value[window_key], [f[frame_key] for f in original])
        self.assertEqual(features(value), features(window()))
        identity = model_identity(value)
        self.assertEqual(identity["source_frame_schema"], FRAME_SCHEMA_V2)
        for key in ("session_id", "capture_id", "worker_run_id", "clock_id"):
            self.assertNotIn(key, identity)

    def test_v2_frame_requires_explicit_canonical_distinct_identities_and_ordinals(
        self,
    ):
        for key, bad in (
            ("capture_id", CAPTURE_B),
            ("session_id", CAPTURE_B),
            ("worker_run_id", CAPTURE_A),
            ("worker_run_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".upper()),
            ("worker_run_id", WORKER.replace("-", "")),
            ("capture_id", None),
            ("clock_id", ""),
            ("capture_sequence", True),
            ("capture_sequence", 0),
            ("ingress_sequence", 2**64),
            ("ingress_sequence", None),
        ):
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                item = v2_frame(0)
                item[key] = bad
                validate_frame(item)

    def test_capture_worker_and_version_changes_reset_pending_window(self):
        for change in ("capture", "worker", "version"):
            with self.subTest(change=change):
                builder = WindowBuilder(profiles=[profile()])
                for index in range(6):
                    self.assertIsNone(builder.push(v2_frame(index)))
                for index in range(6, 17):
                    item = v2_frame(index)
                    if change == "capture":
                        item["session_id"] = item["capture_id"] = CAPTURE_B
                    elif change == "worker":
                        item["worker_run_id"] = OTHER_WORKER
                    else:
                        item["schema"] = "ruview.csi.frame.v1"
                    result = builder.push(item)
                self.assertEqual(builder.stats["identity_change"], 1)
                self.assertEqual(result["sequences"], list(range(6, 17)))

    def test_duplicate_or_backward_admission_never_seeds_new_window(self):
        for key in ("ingress_sequence", "capture_sequence"):
            for bad in (1, v2_frame(5)[key]):
                with self.subTest(key=key, bad=bad):
                    builder = WindowBuilder(profiles=[profile()])
                    for index in range(6):
                        builder.push(v2_frame(index))
                    item = v2_frame(6)
                    item[key] = bad
                    self.assertIsNone(builder.push(item))
                    self.assertEqual(builder.stats["nonmonotonic_admission"], 1)
                    self.assertNotIn(2, builder.pending)
                    self.assertEqual(builder.last[2]["sequence"], 5)

    def test_v2_feature_validation_rejects_forged_identity_even_with_new_hash(self):
        for key, bad in (
            ("capture_id", CAPTURE_B),
            ("worker_run_id", CAPTURE_A),
            ("source_frame_schema", "ruview.csi.frame.v1"),
            ("clock_id", ""),
            ("ingress_sequences", [1] * 11),
            ("capture_sequences", [True] + list(range(2, 12))),
            ("capture_sequences", list(range(1, 11))),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                value = v2_window()
                value[key] = bad
                rehash_window(value)
                features(value)

    def test_pairing_requires_matching_v2_capture_worker_clock_and_label_schema(self):
        value = v2_window()
        truth = v2_label(value)
        self.assertEqual(
            pair_window(
                value, [truth], 0, expected_coordinate_frame="example_lab_xz_metres"
            )["schema"],
            PAIR_SCHEMA_V2,
        )
        for change in ("capture", "worker", "clock", "version"):
            altered = copy.deepcopy(truth)
            if change == "capture":
                altered["session_id"] = altered["capture_id"] = CAPTURE_B
            elif change == "worker":
                altered["worker_run_id"] = OTHER_WORKER
            elif change == "clock":
                altered["clock_id"] = "another-original-clock"
            else:
                altered["schema"] = "ruview.ground_truth.v1"
            with self.subTest(change=change):
                self.assertIsNone(
                    pair_window(
                        value,
                        [altered],
                        0,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )
                )
        legacy = window(session=CAPTURE_A)
        self.assertIsNone(
            pair_window(
                legacy, [truth], 0, expected_coordinate_frame="example_lab_xz_metres"
            )
        )
        truth["worker_run_id"] = CAPTURE_A
        with self.assertRaises(ValueError):
            validate_label(truth, expected_coordinate_frame="example_lab_xz_metres")

    def test_two_captures_same_worker_train_and_hold_out_without_changing_features(
        self,
    ):
        records = v2_dataset()
        self.assertEqual({r["window"]["worker_run_id"] for r in records}, {WORKER})
        fitted = train(
            records,
            "posture",
            [CAPTURE_B],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(fitted["training_sessions"], [CAPTURE_A])
        self.assertEqual(fitted["evaluation_sessions"], [CAPTURE_B])
        self.assertEqual(
            fitted["input_identity"]["source_frame_schema"], FRAME_SCHEMA_V2
        )
        self.assertFalse(fitted["publish_to_ha"])
        self.assertEqual(fitted["status"], "candidate_unqualified")
        validate_model(fitted, expected_coordinate_frame="example_lab_xz_metres")
        prediction = predict(
            fitted,
            records[-1]["window"],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertFalse(prediction["publish_to_ha"])
        self.assertIsNone(prediction["confidence"])

    def test_mixed_source_versions_and_forged_pair_schema_rejected_even_for_negatives(
        self,
    ):
        for kind in ("mixed", "negative", "pair", "label", "wrong_worker"):
            records = v2_dataset()
            if kind in ("mixed", "negative"):
                legacy = dataset()[0]
                if kind == "negative":
                    legacy["label"]["person_count"] = 0
                records.append(legacy)
            elif kind == "pair":
                records[0]["schema"] = "ruview.csi.paired.v1"
            elif kind == "label":
                records[0]["label"]["schema"] = "ruview.ground_truth.v1"
            else:
                records[0]["label"]["worker_run_id"] = OTHER_WORKER
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                train(
                    records,
                    "posture",
                    [CAPTURE_B],
                    expected_coordinate_frame="example_lab_xz_metres",
                )

    def test_same_worker_capture_overlap_cannot_be_held_out(self):
        records = v2_dataset()
        value = v2_window(CAPTURE_B, 10_000_000_000)
        records[-1] = pair_window(
            value,
            [v2_label(value)],
            0,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        with self.assertRaisesRegex(ValueError, "overlap"):
            train(
                records,
                "posture",
                [CAPTURE_B],
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_legacy_checkpoint_rejects_new_source_and_unknown_source_marker(self):
        fitted = train(
            dataset(),
            "posture",
            ["synthetic-eval"],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            predict(
                fitted, v2_window(), expected_coordinate_frame="example_lab_xz_metres"
            )
        fitted["input_identity"]["source_frame_schema"] = "ruview.csi.frame.v9"
        fitted["model_sha256"] = digest(
            {k: v for k, v in fitted.items() if k != "model_sha256"}
        )
        with self.assertRaisesRegex(ValueError, "source frame schema"):
            validate_model(fitted, expected_coordinate_frame="example_lab_xz_metres")


if __name__ == "__main__":
    unittest.main()
