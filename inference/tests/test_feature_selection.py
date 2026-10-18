"""Synthetic-only prefix exclusion, contract separation and checkpoint regressions."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.feature_contracts import (
    FEATURE_CONTRACT,
    MODEL_SCHEMAS,
    PREFIX_FEATURE_CONTRACT,
    prefix_selection,
)
from inference.model import features, model_identity, predict, train, validate_model
from inference.pipeline import WindowBuilder, digest, pair_window
from inference.tests import test_evidence
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.tests.test_evidence import with_synthetic_lineage
from inference.tests.test_pipeline import dataset, frame, label, profile, window


def rehash(value, field):
    value[field] = digest({k: v for k, v in value.items() if k != field})


def selected_dataset():
    records = dataset()
    for record in records:
        record["window"]["feature_selection"] = prefix_selection()
        rehash(record["window"], "window_id")
    return records


def selected_window(mutate=None):
    builder = WindowBuilder(
        profiles=[profile()], feature_contract=PREFIX_FEATURE_CONTRACT
    )
    frames = [frame(i) for i in range(11)]
    if mutate:
        for item in frames:
            mutate(item)
    original = copy.deepcopy(frames)
    for item in frames:
        result = builder.push(item)
    if frames != original:
        raise AssertionError("window construction mutated raw frames")
    return result, frames


class SelectionTests(unittest.TestCase):
    def test_verified_raw_pairing_retains_original_hash_and_new_selection(self):
        fixture = test_evidence.EvidenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = (fixture.root / "raw").read_bytes()
        result = fixture.run_cli(
            fixture.pair_command() + ["--feature-contract", PREFIX_FEATURE_CONTRACT]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((fixture.root / "raw").read_bytes(), original)
        records = [
            json.loads(line)
            for line in (fixture.root / "paired.jsonl").read_text().splitlines()
        ]
        self.assertTrue(records)
        for record in records:
            self.assertEqual(record["capture_evidence"]["status"], "verified_recording")
            self.assertEqual(
                record["capture_evidence"]["raw_sha256"],
                fixture.fixture.manifest["files"]["raw"]["sha256"],
            )
            self.assertTrue(record["capture_evidence"]["synthetic_only"])
            self.assertEqual(record["window"]["feature_selection"], prefix_selection())
            self.assertEqual(
                len(features(record["window"], PREFIX_FEATURE_CONTRACT)), 186
            )

    def test_excluded_prefix_changes_no_selected_stat_but_originals_remain(self):
        original, original_frames = selected_window()

        def mutate(item):
            item["iq"][:4] = [127, -128, item["sequence"], -71]

        changed, changed_frames = selected_window(mutate)
        self.assertNotEqual(changed_frames, original_frames)
        self.assertEqual(len(changed_frames[0]["iq"]), 128)
        self.assertNotEqual(changed["amplitudes"], original["amplitudes"])
        self.assertEqual(len(changed["amplitudes"][0]), 64)
        self.assertNotEqual(changed["window_id"], original["window_id"])
        self.assertEqual(
            features(original, PREFIX_FEATURE_CONTRACT),
            features(changed, PREFIX_FEATURE_CONTRACT),
        )
        self.assertEqual(
            features(changed, PREFIX_FEATURE_CONTRACT), [10] * 62 + [0] * 124
        )
        self.assertEqual(changed["feature_selection"], prefix_selection())
        self.assertIsNone(changed["feature_selection"]["first_word_invalid"])

    def test_retained_pair_changes_features_in_original_order(self):
        original, _ = selected_window()
        changed, _ = selected_window(lambda f: f["iq"].__setitem__(4, 20))
        baseline = features(original, PREFIX_FEATURE_CONTRACT)
        actual = features(changed, PREFIX_FEATURE_CONTRACT)
        self.assertEqual(actual[0], 20)
        self.assertEqual(actual[1:], baseline[1:])
        self.assertEqual(model_identity(original), model_identity(changed))

    def test_legacy_window_and_features_have_identical_frozen_fingerprints(self):
        legacy = window()
        self.assertNotIn("feature_selection", legacy)
        self.assertEqual(
            digest(legacy),
            "6032472cfa51474e023d08a0fc06c7d72d1d1b026fcd73506bcf8cb597fb46bf",
        )
        self.assertEqual(
            digest(features(legacy)),
            "086b5315eacda12f63092c45a8a6b41d1c9956f9c4820971bcf19d6d5e6323a7",
        )
        self.assertEqual(
            digest(model_identity(legacy)),
            "174533f672020032a02ec2d3697c8429fa1c3c03caea2640c38301dcb2f144a3",
        )
        self.assertEqual(features(legacy), features(legacy, FEATURE_CONTRACT))

    def test_mask_contract_and_raw_scope_fail_closed(self):
        selected, _ = selected_window()
        with self.assertRaisesRegex(ValueError, "contract"):
            features(selected)
        with self.assertRaisesRegex(ValueError, "contract"):
            features(window(), PREFIX_FEATURE_CONTRACT)
        for change in (
            {"original_wire_pair_indices": list(range(3, 64))},
            {"original_wire_pair_indices": [2.0] + list(range(3, 64))},
            {"first_word_invalid": False},
            {"feature_contract": FEATURE_CONTRACT},
            {"extra": "not allowed"},
        ):
            altered = copy.deepcopy(selected)
            altered["feature_selection"].update(change)
            rehash(altered, "window_id")
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "selection"),
            ):
                features(altered, PREFIX_FEATURE_CONTRACT)
        for key, value in (
            ("flags", 0x20),
            ("flags", 1),
            ("ppdu_type", 1),
            ("first_word_invalid", False),
            ("first_word_sanitized", True),
            ("subcarriers", 62),
            ("iq", [10, 0] * 62),
        ):
            f = frame(0)
            f[key] = value
            builder = WindowBuilder(
                profiles=[profile()], feature_contract=PREFIX_FEATURE_CONTRACT
            )
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                builder.push(f)

    def test_new_contract_preserves_frame_reset_and_profile_requirements(self):
        builder = WindowBuilder(
            profiles=[profile()], feature_contract=PREFIX_FEATURE_CONTRACT
        )
        builder.push(frame(0))
        changed = frame(1)
        changed["configuration_sha256"] = "e" * 64
        builder.push(changed)
        self.assertEqual(builder.stats["identity_change"], 1)
        builder.push(frame(3))
        builder.push(frame(5))
        self.assertEqual(builder.stats["sequence_discontinuity"], 1)
        changed = frame(6)
        changed["frequency_mhz"] = 2412
        self.assertIsNone(builder.push(changed))
        self.assertEqual(builder.stats["profile_frequency_mismatch"], 1)
        with self.assertRaises(ValueError):
            WindowBuilder(feature_contract=PREFIX_FEATURE_CONTRACT)
        bad = profile()
        bad["placement_confirmed"] = False
        with self.assertRaises(ValueError):
            WindowBuilder(profiles=[bad], feature_contract=PREFIX_FEATURE_CONTRACT)


@unittest.skipUnless(
    importlib.util.find_spec("numpy"), "NumPy is required for model tests"
)
class SelectedModelTests(unittest.TestCase):
    def test_all_three_tasks_train_evaluate_and_predict_186_candidate_only(self):
        records = selected_dataset()
        for record in records:
            lab = record["label"]
            lab.update(
                source="camera_annotation",
                camera_id="synthetic-camera",
                image_geometry_sha256="f" * 64,
                image_pose_2d=[lab["house_xy_m"][0] / 24, 0.5] * 17,
            )
        for task, dimensions in (
            ("posture", None),
            ("house_xy_m", 2),
            ("image_pose_2d", 34),
        ):
            model = train(
                records,
                task,
                {"synthetic-eval"},
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )
            self.assertEqual(model["schema"], MODEL_SCHEMAS[PREFIX_FEATURE_CONTRACT])
            self.assertEqual(len(model["mean"]), 186)
            self.assertEqual(len(model["weights"]), 186)
            self.assertEqual(model["evaluation_windows"], 24)
            self.assertEqual(
                model["input_identity"]["feature_selection"], prefix_selection()
            )
            output = predict(
                model,
                records[-1]["window"],
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )
            self.assertEqual(output["feature_selection"], prefix_selection())
            self.assertEqual(output["feature_contract"], PREFIX_FEATURE_CONTRACT)
            self.assertIsNone(output["confidence"])
            self.assertFalse(output["publish_to_ha"])
            self.assertEqual(output["validation"], "unverified")
            self.assertEqual(model["status"], "candidate_unqualified")
            if dimensions:
                self.assertEqual(len(output["prediction"]), dimensions)

    def test_legacy_checkpoint_default_explicit_and_json_roundtrip_are_exact(self):
        records = dataset()
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        explicit = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            feature_contract=FEATURE_CONTRACT,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(model, explicit)
        self.assertEqual(model["schema"], MODEL_SCHEMAS[FEATURE_CONTRACT])
        self.assertEqual(len(model["weights"]), 192)
        roundtrip = json.loads(json.dumps(model, allow_nan=False))
        self.assertEqual(
            predict(
                model,
                records[-1]["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            ),
            predict(
                roundtrip,
                records[-1]["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            ),
        )
        self.assertNotIn("feature_selection", model["input_identity"])

    def test_cross_contract_and_out_of_task_mask_mixes_are_rejected(self):
        records = selected_dataset()
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            feature_contract=PREFIX_FEATURE_CONTRACT,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        with self.assertRaisesRegex(ValueError, "contract"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaisesRegex(ValueError, "contract"):
            predict(
                model,
                records[-1]["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            predict(
                model,
                window(),
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        legacy = dataset()[0]
        legacy["label"]["person_count"] = 0
        with self.assertRaisesRegex(ValueError, "contracts"):
            train(
                records + [legacy],
                "house_xy_m",
                {"synthetic-eval"},
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_rehashed_dimension_selection_schema_and_qualification_changes_fail(self):
        records = selected_dataset()
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            feature_contract=PREFIX_FEATURE_CONTRACT,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        for change in (
            {"mean": model["mean"] + [0] * 6},
            {"scale": model["scale"] + [1] * 6},
            {"weights": model["weights"] + [[0, 0]] * 6},
            {"schema": MODEL_SCHEMAS[FEATURE_CONTRACT]},
            {"feature_contract": FEATURE_CONTRACT},
            {"status": "qualified"},
            {"publish_to_ha": True},
        ):
            altered = copy.deepcopy(model)
            altered.update(change)
            rehash(altered, "model_sha256")
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                validate_model(
                    altered, expected_coordinate_frame="example_lab_xz_metres"
                )
        altered = copy.deepcopy(model)
        altered["input_identity"]["feature_selection"]["original_wire_pair_indices"][
            0
        ] = 1
        rehash(altered, "model_sha256")
        with self.assertRaisesRegex(ValueError, "selection"):
            validate_model(altered, expected_coordinate_frame="example_lab_xz_metres")

    def test_new_contract_keeps_capture_fingerprint_and_holdout_gates(self):
        records = with_synthetic_lineage(selected_dataset())
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            feature_contract=PREFIX_FEATURE_CONTRACT,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        record = records[-1]
        output = predict(
            model,
            record["window"],
            record["capture_evidence"],
            PREFIX_FEATURE_CONTRACT,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(output["capture_evidence"], record["capture_evidence"])
        with self.assertRaisesRegex(ValueError, "mix verified"):
            predict(
                model,
                record["window"],
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        records = selected_dataset()
        for key, value in (
            ("configuration_sha256", "f" * 64),
            ("source_pair_order", "changed"),
        ):
            changed = copy.deepcopy(records[-1]["window"])
            changed[key] = value
            rehash(changed, "window_id")
            unverified = train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "fingerprint"),
            ):
                predict(
                    unverified,
                    changed,
                    feature_contract=PREFIX_FEATURE_CONTRACT,
                    expected_coordinate_frame="example_lab_xz_metres",
                )
        overlapping = copy.deepcopy(records[0]["window"])
        overlapping["session_id"] = "synthetic-eval"
        rehash(overlapping, "window_id")
        records[-1] = pair_window(
            overlapping,
            [label(overlapping)],
            0,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        with self.assertRaisesRegex(ValueError, "overlap"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                feature_contract=PREFIX_FEATURE_CONTRACT,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_cli_requires_explicit_opt_in_at_all_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frames, labels = [], []
            for record in dataset():
                w = record["window"]
                frames.extend(
                    frame(
                        i, w["session_id"], w["timestamps_ns"][0], w["amplitudes"][0][0]
                    )
                    for i in range(11)
                )
                labels.append(record["label"])
            # The wire samples are signed integers, unlike amplitude magnitudes.
            for f in frames:
                f["iq"] = [int(v) for v in f["iq"]]
            for name, rows in (("frames", frames), ("labels", labels)):
                (root / f"{name}.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in rows)
                )
            (root / "profiles.json").write_text(json.dumps([profile()]))
            commands = [
                [
                    "pair",
                    "--frames",
                    str(root / "frames.jsonl"),
                    "--labels",
                    str(root / "labels.jsonl"),
                    "--profiles",
                    str(root / "profiles.json"),
                    "--label-clock-offset-ms",
                    "0",
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
                [
                    "train",
                    "--paired",
                    str(root / "paired.jsonl"),
                    "--task",
                    "house_xy_m",
                    "--eval-session",
                    "synthetic-eval",
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
                [
                    "predict-candidate",
                    "--paired",
                    str(root / "paired.jsonl"),
                    "--model",
                    str(root / "model.json"),
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
            ]
            outputs = ["paired.jsonl", "model.json", "prediction.jsonl"]
            for command, output in zip(commands, outputs, strict=True):
                if command[0] != "pair":
                    result = subprocess.run(
                        [sys.executable, "-m", "inference"]
                        + command
                        + ["--output", str(root / ("rejected-" + output))],
                        capture_output=True,
                        text=True,
                        timeout=PROCESS_TIMEOUT_SECONDS,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("contract", result.stderr)
                result = subprocess.run(
                    [sys.executable, "-m", "inference"]
                    + command
                    + [
                        "--feature-contract",
                        PREFIX_FEATURE_CONTRACT,
                        "--output",
                        str(root / output),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=PROCESS_TIMEOUT_SECONDS,
                    env=dict(os.environ, OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1"),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            paired = [
                json.loads(line)
                for line in (root / "paired.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(paired), 48)
            self.assertTrue(
                all(
                    p["window"]["feature_selection"] == prefix_selection()
                    for p in paired
                )
            )
            self.assertEqual(
                len(json.loads((root / "model.json").read_text())["weights"]), 186
            )


if __name__ == "__main__":
    unittest.main()
