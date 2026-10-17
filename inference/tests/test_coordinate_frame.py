"""Independent spatial approval; candidates never choose their own trusted frame."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference import model, stream
from inference import reference_session as reference
from inference.pipeline import approved_coordinate_frame, digest, validate_label
from inference.tests.test_pipeline import dataset, label, window
from inference.tests.test_reference_session import binding, points, profile, stamp
from inference.tests.test_stream import config, model_fixture

FRAME = "example_lab_xz_metres"
OTHER = "independently_reviewed_second_lab"
ROOT = Path(__file__).resolve().parents[2]


class CoordinateFrameTests(unittest.TestCase):
    def test_approval_is_bounded_and_never_inferred_from_label(self):
        spatial = label(window())
        for expected in (None, "", 12, True, "a" * 129, "line\nbreak", " ", "a/b"):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                validate_label(spatial, expected_coordinate_frame=expected)
        for frame in (FRAME, OTHER):
            spatial["coordinate_frame"] = frame
            self.assertEqual(
                validate_label(spatial, expected_coordinate_frame=frame), spatial
            )
        with self.assertRaises(ValueError):
            validate_label(spatial, expected_coordinate_frame=FRAME)
        self.assertEqual(approved_coordinate_frame(OTHER), OTHER)

    def test_nonspatial_label_keeps_existing_no_approval_path(self):
        value = label(window())
        for key in (
            "house_xy_m",
            "coordinate_frame",
            "coordinate_calibration_sha256",
            "coordinate_reference",
        ):
            value.pop(key)
        self.assertEqual(validate_label(value), value)
        value.update(
            image_pose_2d=[0.5] * 34,
            camera_id="fictional-camera",
            image_geometry_sha256="a" * 64,
            source="camera_annotation",
        )
        self.assertEqual(validate_label(value), value)

    def test_rehashed_model_cannot_change_the_approved_frame(self):
        candidate = copy.deepcopy(model_fixture())
        model.validate_model(candidate, expected_coordinate_frame=FRAME)
        for expected in (None, OTHER):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                model.validate_model(candidate, expected_coordinate_frame=expected)
        candidate["target_identity"]["frame"] = OTHER
        candidate["model_sha256"] = digest(
            {k: v for k, v in candidate.items() if k != "model_sha256"}
        )
        with self.assertRaises(ValueError):
            model.validate_model(candidate, expected_coordinate_frame=FRAME)
        model.validate_model(candidate, expected_coordinate_frame=OTHER)

    def test_train_and_stream_require_independent_spatial_approval(self):
        records = dataset()
        with self.assertRaises(ValueError):
            model.train(records, "house_xy_m", {"synthetic-eval"})
        candidate = copy.deepcopy(model_fixture())
        configuration = config(models={"2": candidate})
        for expected in (None, OTHER):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                stream.ReplayRunner(configuration, expected_coordinate_frame=expected)
        stream.ReplayRunner(configuration, expected_coordinate_frame=FRAME)

    def test_reference_missing_or_wrong_approval_creates_no_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "session"
            for expected in (None, OTHER):
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    reference.initialize(
                        target,
                        binding(),
                        [profile(n) for n in (1, 2, 3)],
                        points(),
                        {},
                        "synthetic operator",
                        stamp(0),
                        expected_coordinate_frame=expected,
                    )
                self.assertFalse(target.exists())

    def test_reference_recheck_rejects_before_creating_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "session"
            reference.initialize(
                target,
                binding(),
                [profile(n) for n in (1, 2, 3)],
                points(),
                {
                    "transition_margin_ns": 5_000_000_000,
                    "max_clock_step_ns": 10_000_000,
                    "max_stamp_bracket_ns": 1_000_000,
                },
                "synthetic operator",
                stamp(0),
                expected_coordinate_frame=FRAME,
            )
            before = {
                p.relative_to(target): p.read_bytes()
                for p in target.rglob("*")
                if p.is_file()
            }
            actions = (
                lambda: reference.mark(
                    target, "trial", "interrupt", reason="synthetic", stamp=stamp(1)
                ),
                lambda: reference.review(target, "reviewer", "proof", True, stamp(2)),
                lambda: reference.export(target, Path(temporary) / "output", [1, 2, 3]),
            )
            for action in actions:
                with self.assertRaises(ValueError):
                    action()
                self.assertFalse((target / ".lock").exists())
                self.assertEqual(
                    before,
                    {
                        p.relative_to(target): p.read_bytes()
                        for p in target.rglob("*")
                        if p.is_file()
                    },
                )

    def test_prediction_cli_rejects_missing_approval_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "model.json").write_text(json.dumps(model_fixture()))
            # Empty input must not avoid model approval or create an output file.
            (root / "paired.jsonl").write_text("")
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "inference",
                    "predict-candidate",
                    "--model",
                    str(root / "model.json"),
                    "--paired",
                    str(root / "paired.jsonl"),
                    "--output",
                    str(root / "output"),
                ],
                cwd=ROOT,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "output").exists())
