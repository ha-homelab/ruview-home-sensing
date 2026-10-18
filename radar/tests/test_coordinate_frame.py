"""A radar candidate cannot approve its own coordinate frame."""

import unittest

from radar.config import inspect_document
from radar.ld2450 import ObservationAdapter
from radar.tests.test_ld2450 import synthetic_config

FRAME = "example_lab_xz_metres"
OTHER = "independently_reviewed_second_lab"


class CoordinateFrameTests(unittest.TestCase):
    def test_radar_approval_not_candidate_hash_and_missing_has_no_claim(self):
        value = synthetic_config()
        with self.assertRaises(ValueError):
            ObservationAdapter(value)
        value["coordinate_frame"] = OTHER
        self.assertEqual(
            inspect_document(value, expected_coordinate_frame=FRAME)["status"],
            "invalid",
        )
        with self.assertRaises(ValueError):
            ObservationAdapter(value, expected_coordinate_frame=FRAME)
        adapter = ObservationAdapter(value, expected_coordinate_frame=OTHER)
        self.assertEqual(
            adapter.snapshot(monotonic_ns=1, utc_ns=1)["coordinate_frame"], OTHER
        )
        self.assertIsNone(
            ObservationAdapter().snapshot(monotonic_ns=1, utc_ns=1)["coordinate_frame"]
        )
