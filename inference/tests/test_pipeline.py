import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.__main__ import private_output, select_node
from inference.model import features, model_identity, predict, train
from inference.pipeline import (
    WindowBuilder,
    digest,
    pair_window,
    validate_frame,
    validate_label,
)
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS


def profile(node=2):
    return {
        "schema": "ruview.commissioning.profile.v1",
        "node_id": node,
        "placement_revision": "synthetic-1",
        "room_id": "K",
        "orientation_reference": "synthetic fixture, not household measurement",
        "antenna_path": "internal",
        "ap_bssid": "00:00:00:00:00:01",
        "firmware_version": "synthetic",
        "inference_revision": "synthetic",
        "evidence_reference": "synthetic-test-only",
        "firmware_sha256": "a" * 64,
        "floorplan_sha256": "b" * 64,
        "receiver_position_ha_m": [1, 1.5, 2],
        "frequency_mhz": 2462,
        "module_sha256s": [],
        "placement_confirmed": True,
    }


def frame(index, session="synthetic-train", base=1_000_000_000, amplitude=10, node=2):
    return {
        "schema": "ruview.csi.frame.v1",
        "session_id": session,
        "node_id": node,
        "received_at_ns": base + index * 100_000_000,
        "received_monotonic_ns": base + index * 100_000_000,
        "clock_id": "synthetic-host-boot",
        "sequence": index,
        "antennas": 1,
        "subcarriers": 64,
        "frequency_mhz": 2462,
        "ppdu_type": 0,
        "flags": 0,
        "iq": [amplitude, 0] * 64,
        "configuration_sha256": "c" * 64,
        "device_boot_id": None,
    }


def window(session="synthetic-train", base=1_000_000_000, amplitude=10, node=2):
    builder = WindowBuilder(profiles=[profile(node)])
    output = None
    for i in range(11):
        output = builder.push(frame(i, session, base, amplitude, node))
    return output


def label(w, posture="standing", coordinate=1):
    return {
        "schema": "ruview.ground_truth.v1",
        "label_id": "synthetic-" + w["window_id"],
        "session_id": w["session_id"],
        "trial_id": "synthetic-only",
        "node_id": w["node_id"],
        "provenance": "synthetic-test-only",
        "source": "manual_observation",
        "room_id": "K",
        "reviewed": True,
        "start_ns": w["timestamps_ns"][0],
        "end_ns": w["timestamps_ns"][-1],
        "time_uncertainty_ns": 0,
        "person_count": 1,
        "posture": posture,
        "configuration_sha256": w["configuration_sha256"],
        "commissioning_sha256": w["commissioning_sha256"],
        "house_xy_m": [coordinate, coordinate / 2],
        "coordinate_frame": "example_lab_xz_metres",
        "coordinate_reference": "synthetic fixture",
        "coordinate_calibration_sha256": "d" * 64,
    }


def dataset(node=2):
    result = []
    for session, start in (
        ("synthetic-train", 10_000_000_000),
        ("synthetic-eval", 100_000_000_000),
    ):
        for i in range(24):
            w = window(session, start + i * 2_000_000_000, 10 + i, node)
            lab = label(w, "standing" if i % 2 else "seated", i)
            result.append(
                pair_window(
                    w, [lab], 0, expected_coordinate_frame="example_lab_xz_metres"
                )
            )
    return result


class PipelineTests(unittest.TestCase):
    def test_node_selection_is_explicit_and_rejects_absent_or_invalid_identity(self):
        records = [{"window": {"node_id": node}} for node in (1, 2, 3)]
        self.assertEqual(list(select_node(iter(records), None)), records)
        self.assertEqual(list(select_node(iter(records), 2)), [records[1]])
        for invalid in (0, True, 256, 4):
            with self.subTest(node_id=invalid), self.assertRaises(ValueError):
                list(select_node(iter(records), invalid))

    def test_wire_metadata_preserved_without_phase_assumptions(self):
        builder = WindowBuilder(profiles=[profile()])
        metadata = {
            "iq_order": "wire_byte_order",
            "source_pair_order": "esp_idf_imaginary_real",
            "worker_phase_convention": "ruview_legacy_atan2_byte1_byte0",
            "monotonic_origin": "worker_start",
        }
        for i in range(11):
            f = frame(i)
            f.update(metadata)
            f["iq"] = [0, 10] * 64
            result = builder.push(f)
        self.assertEqual(features(result), features(window()))
        for key, value in metadata.items():
            self.assertEqual(result[key], value)
            self.assertEqual(model_identity(result)[key], value)
        f = frame(11)
        f.update(metadata)
        builder.push(f)
        f = frame(12)
        f.update(metadata)
        f["worker_phase_convention"] = "changed_transform"
        builder.push(f)
        self.assertEqual(builder.stats["identity_change"], 1)
        f["iq_order"] = "interpolated"
        with self.assertRaisesRegex(ValueError, "wire-byte order"):
            validate_frame(f)

    def test_native_shape_features_and_time_preserved(self):
        w = window()
        self.assertEqual(len(w["amplitudes"]), 11)
        self.assertEqual(w["amplitudes"][0], [10] * 64)
        self.assertEqual(features(w), [10] * 64 + [0] * 128)
        self.assertEqual(w["time_basis"], "receiver_host_arrival_not_device_capture")

    def test_rejects_antenna_fabrication_and_nonfinite(self):
        for key, value in (
            ("antennas", 3),
            ("antennas", True),
            ("subcarriers", 114),
            ("iq", [float("nan")] * 128),
            ("iq", [0] * 127),
        ):
            f = frame(0)
            f[key] = value
            with self.assertRaises(ValueError):
                validate_frame(f)

    def test_profile_required_and_changed_frequency_dropped(self):
        with self.assertRaises(ValueError):
            WindowBuilder()
        builder = WindowBuilder(profiles=[profile()])
        f = frame(0)
        f["frequency_mhz"] = 2412
        self.assertIsNone(builder.push(f))
        self.assertEqual(builder.stats["profile_frequency_mismatch"], 1)

    def test_sequence_gap_starts_new_window(self):
        builder = WindowBuilder(profiles=[profile()])
        for i in range(6):
            self.assertIsNone(builder.push(frame(i)))
        for i in range(7, 17):
            self.assertIsNone(builder.push(frame(i)))
        w = builder.push(frame(17))
        self.assertEqual(w["sequences"][0], 7)
        self.assertEqual(builder.stats["sequence_discontinuity"], 1)

    def test_wrap_is_contiguous_but_duplicate_is_dropped(self):
        builder = WindowBuilder(profiles=[profile()])
        for i in range(11):
            f = frame(i)
            f["sequence"] = (2**32 - 5 + i) % 2**32
            result = builder.push(f)
        self.assertIsNotNone(result)
        f = frame(11)
        f["sequence"] = result["sequences"][-1]
        self.assertIsNone(builder.push(f))
        self.assertEqual(builder.stats["sequence_discontinuity"], 1)

    def test_clock_step_and_identity_change_reset(self):
        builder = WindowBuilder(profiles=[profile()])
        builder.push(frame(0))
        f = frame(1)
        f["received_at_ns"] += 50_000_000
        self.assertIsNone(builder.push(f))
        self.assertEqual(builder.stats["clock_step"], 1)
        f = frame(2)
        f["configuration_sha256"] = "e" * 64
        self.assertIsNone(builder.push(f))
        self.assertEqual(builder.stats["identity_change"], 1)

    def test_pairing_requires_whole_window_and_unique_label(self):
        w = window()
        lab = label(w)
        self.assertIsNotNone(
            pair_window(w, [lab], 0, expected_coordinate_frame="example_lab_xz_metres")
        )
        self.assertIsNone(
            pair_window(
                w, [lab, lab], 0, expected_coordinate_frame="example_lab_xz_metres"
            )
        )
        lab["time_uncertainty_ns"] = 1
        self.assertIsNone(
            pair_window(w, [lab], 0, expected_coordinate_frame="example_lab_xz_metres")
        )

    def test_pairing_offset_and_node_identity(self):
        w = window()
        lab = label(w)
        lab["start_ns"] -= 100_000_000
        lab["end_ns"] -= 100_000_000
        self.assertIsNotNone(
            pair_window(
                w, [lab], 100_000_000, expected_coordinate_frame="example_lab_xz_metres"
            )
        )
        lab["node_id"] = 3
        self.assertIsNone(
            pair_window(
                w, [lab], 100_000_000, expected_coordinate_frame="example_lab_xz_metres"
            )
        )

    def test_no_prediction_as_truth_or_unreviewed_label(self):
        for key, value in (
            ("source", "ruview"),
            ("reviewed", False),
            ("person_count", True),
            ("coordinate_frame", "normalized_image"),
        ):
            lab = label(window())
            lab[key] = value
            with self.assertRaises(ValueError):
                validate_label(lab, expected_coordinate_frame="example_lab_xz_metres")

    def test_missing_and_empty_truth_do_not_create_labels(self):
        w = window()
        self.assertIsNone(
            pair_window(w, [], 0, expected_coordinate_frame="example_lab_xz_metres")
        )
        lab = label(w)
        lab["person_count"] = 0
        record = pair_window(
            w, [lab], 0, expected_coordinate_frame="example_lab_xz_metres"
        )
        with self.assertRaisesRegex(ValueError, "no single-person"):
            train(
                [record],
                "posture",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_output_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evidence.json")
            with private_output(path) as stream:
                stream.write("{}")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                private_output(path)


@unittest.skipUnless(
    importlib.util.find_spec("numpy"), "offline training dependency missing"
)
class ModelTests(unittest.TestCase):
    def test_cli_pair_train_predict_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            frames = []
            labels = []
            for session, start in (
                ("synthetic-train", 10_000_000_000),
                ("synthetic-eval", 100_000_000_000),
            ):
                for i in range(24):
                    base = start + i * 2_000_000_000
                    frames.extend(frame(j, session, base, 10 + i) for j in range(11))
                    w = window(session, base, 10 + i)
                    labels.append(label(w, "standing" if i % 2 else "seated", i))
            for name, records in (("frames", frames), ("labels", labels)):
                (root / f"{name}.jsonl").write_text(
                    "\n".join(json.dumps(r) for r in records) + "\n"
                )
            (root / "profiles.json").write_text(json.dumps([profile()]))
            prefix = [sys.executable, "-m", "inference"]
            env = dict(os.environ, OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1")
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
                    "--output",
                    str(root / "paired.jsonl"),
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
                [
                    "train",
                    "--paired",
                    str(root / "paired.jsonl"),
                    "--task",
                    "house_xy_m",
                    "--node-id",
                    "2",
                    "--eval-session",
                    "synthetic-eval",
                    "--output",
                    str(root / "model.json"),
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
                [
                    "predict-candidate",
                    "--model",
                    str(root / "model.json"),
                    "--node-id",
                    "2",
                    "--paired",
                    str(root / "paired.jsonl"),
                    "--output",
                    str(root / "predictions.jsonl"),
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
            ]
            for command in commands:
                result = subprocess.run(
                    prefix + command,
                    capture_output=True,
                    text=True,
                    env=env,
                    cwd=Path(__file__).resolve().parents[2],
                    timeout=PROCESS_TIMEOUT_SECONDS,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            predictions = [
                json.loads(row)
                for row in (root / "predictions.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(predictions), 48)
            self.assertTrue(all(p["publish_to_ha"] is False for p in predictions))
            rejected = subprocess.run(
                prefix
                + [
                    "predict-candidate",
                    "--model",
                    str(root / "model.json"),
                    "--paired",
                    str(root / "paired.jsonl"),
                    "--node-id",
                    "1",
                    "--output",
                    str(root / "wrong-node.jsonl"),
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ],
                capture_output=True,
                text=True,
                env=env,
                cwd=Path(__file__).resolve().parents[2],
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("selected node differs", rejected.stderr)
            self.assertFalse((root / "wrong-node.jsonl").exists())

    def test_three_node_capture_trains_separate_explicit_models(self):
        records = dataset(1) + dataset(2) + dataset(3)
        with self.assertRaisesRegex(ValueError, "separate model"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )
        for node_id in (1, 2, 3):
            selected = list(select_node(iter(records), node_id))
            model = train(
                selected,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )
            self.assertEqual(model["input_identity"]["node_id"], node_id)
            self.assertEqual(model["training_windows"], 24)
            self.assertEqual(model["evaluation_windows"], 24)
            self.assertEqual(model["dataset_sha256"], digest(selected))
            self.assertEqual(
                predict(
                    model,
                    selected[-1]["window"],
                    expected_coordinate_frame="example_lab_xz_metres",
                )["node_id"],
                node_id,
            )

    def test_actual_fit_and_heldout_regression(self):
        records = dataset()
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(model["training_sessions"], ["synthetic-train"])
        self.assertEqual(model["evaluation_windows"], 24)
        self.assertLess(
            model["metrics"]["rmse"], model["metrics"]["mean_target_baseline_rmse"]
        )
        output = predict(
            model,
            records[-1]["window"],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertIsNone(output["confidence"])
        self.assertFalse(output["publish_to_ha"])
        self.assertEqual(output["target_identity"]["frame"], "example_lab_xz_metres")
        json.dumps(model, allow_nan=False)

    def test_posture_is_separate_classifier_not_coordinate_label(self):
        records = dataset()
        model = train(
            records,
            "posture",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(model["target_identity"]["frame"], "categorical_body_posture")
        self.assertIn(
            predict(
                model,
                records[-1]["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            )["prediction"],
            ["standing", "seated"],
        )
        self.assertEqual(model["status"], "candidate_unqualified")

    def test_tampered_and_mixed_fingerprint_rejected(self):
        records = dataset()
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        model["bias"][0] += 1
        with self.assertRaisesRegex(ValueError, "changed"):
            predict(
                model,
                records[0]["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        model = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        w = copy.deepcopy(records[0]["window"])
        w["configuration_sha256"] = "f" * 64
        w["window_id"] = digest({k: v for k, v in w.items() if k != "window_id"})
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            predict(model, w, expected_coordinate_frame="example_lab_xz_metres")

    def test_rehashed_malformed_checkpoint_still_fails_its_contract(self):
        records = dataset()
        original = train(
            records,
            "house_xy_m",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        changes = (
            {"task": "unknown"},
            {"weights": [[row[0]] for row in original["weights"]], "bias": [0.0]},
            {"weights": original["weights"][:-1]},
            {"scale": [0.0] + original["scale"][1:]},
            {"scale": [-1.0] + original["scale"][1:]},
            {"mean": original["mean"][:-1]},
            {"classes": ["standing", "seated"]},
            {"target_identity": {"frame": "normalized_camera_image"}},
            {"evaluation_sessions": original["training_sessions"]},
        )
        for changed in changes:
            with self.subTest(changed=list(changed)):
                model = copy.deepcopy(original)
                model.update(changed)
                model["model_sha256"] = digest(
                    {k: v for k, v in model.items() if k != "model_sha256"}
                )
                with self.assertRaises(ValueError):
                    predict(
                        model,
                        records[0]["window"],
                        expected_coordinate_frame="example_lab_xz_metres",
                    )
        model = train(
            records,
            "posture",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        model["classes"] = ["standing", "unknown"]
        model["model_sha256"] = digest(
            {k: v for k, v in model.items() if k != "model_sha256"}
        )
        with self.assertRaisesRegex(ValueError, "posture classes"):
            predict(
                model,
                records[0]["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_duplicate_and_mixed_target_calibration_rejected(self):
        records = dataset()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            train(
                records + [records[0]],
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )
        records[-1]["label"]["coordinate_calibration_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "mixed target"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )
        records = dataset()
        records[-1]["label"]["coordinate_reference"] = "different body reference"
        with self.assertRaisesRegex(ValueError, "mixed target"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_training_cannot_use_only_or_unknown_evaluation_session(self):
        records = dataset()
        with self.assertRaises(ValueError):
            train(
                records,
                "posture",
                {"synthetic-train", "synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaises(ValueError):
            train(
                records,
                "posture",
                {"synthetic-eval", "nonexistent"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_renamed_same_recording_is_not_held_out(self):
        records = dataset()
        w = window("synthetic-eval", 10_000_000_000)
        records[-1] = pair_window(
            w, [label(w)], 0, expected_coordinate_frame="example_lab_xz_metres"
        )
        with self.assertRaisesRegex(ValueError, "overlap in time"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_concurrent_other_worker_recording_is_not_held_out(self):
        records = dataset()
        w = window("synthetic-eval", 10_000_000_000)
        w["clock_id"] = "synthetic-concurrent-worker"
        w["window_id"] = digest({k: v for k, v in w.items() if k != "window_id"})
        records[-1] = pair_window(
            w, [label(w)], 0, expected_coordinate_frame="example_lab_xz_metres"
        )
        with self.assertRaisesRegex(ValueError, "overlap in time"):
            train(
                records,
                "house_xy_m",
                {"synthetic-eval"},
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_normalized_image_pose_keeps_its_own_frame(self):
        records = dataset()
        for i, record in enumerate(records):
            lab = record["label"]
            lab.update(
                {
                    "source": "camera_annotation",
                    "camera_id": "synthetic-camera",
                    "image_geometry_sha256": "f" * 64,
                    "image_pose_2d": [(i % 24) / 24] * 34,
                }
            )
        model = train(
            records,
            "image_pose_2d",
            {"synthetic-eval"},
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(model["target_identity"]["frame"], "normalized_camera_image")
        self.assertEqual(
            len(
                predict(
                    model,
                    records[0]["window"],
                    expected_coordinate_frame="example_lab_xz_metres",
                )["prediction"]
            ),
            34,
        )


if __name__ == "__main__":
    unittest.main()
