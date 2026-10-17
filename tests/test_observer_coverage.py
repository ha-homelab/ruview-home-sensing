import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "observer", Path(__file__).resolve().parents[1] / "scripts/observe-collector.py"
)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class ObservationCoverageTests(unittest.TestCase):
    def test_normal_cadence_covers_full_qualification_window(self):
        coverage = observer.assess_coverage([i + 0.2 for i in range(615)], 615.0)
        self.assertTrue(coverage["passed"])
        self.assertEqual(coverage["sample_span_s"], 614)
        self.assertEqual(coverage["start_uncovered_s"], 0.2)
        self.assertEqual(coverage["end_uncovered_s"], 0.8)
        self.assertEqual(coverage["max_uncovered_s"], 1)

    def test_two_fresh_samples_cannot_hide_long_silent_gap(self):
        coverage = observer.assess_coverage([0.1, 614.1], 615)
        self.assertFalse(coverage["passed"])
        self.assertTrue(coverage["timestamps_valid"])
        self.assertEqual(coverage["max_uncovered_s"], 614)

    def test_dense_middle_samples_do_not_cover_missing_start_or_end(self):
        for times in ([6, 7, 8, 9], [0, 1, 2, 3]):
            with self.subTest(times=times):
                coverage = observer.assess_coverage(times, 10)
                self.assertFalse(coverage["passed"])
                self.assertGreater(coverage["max_uncovered_s"], 5)

    def test_internal_gap_is_checked_separately_from_endpoints(self):
        coverage = observer.assess_coverage([0.1, 1.1, 8.1, 9.1], 10)
        self.assertFalse(coverage["passed"])
        self.assertEqual(coverage["max_uncovered_s"], 7)

    def test_negative_duplicate_backwards_and_out_of_window_times_fail(self):
        for times in ([-1, 1], [0, 0], [2, 1], [0, 11], [0, float("nan")], [False, 1]):
            with self.subTest(times=times):
                coverage = observer.assess_coverage(times, 10)
                self.assertFalse(coverage["passed"])
                self.assertFalse(coverage["timestamps_valid"])

    def test_empty_single_sample_and_invalid_elapsed_time_fail(self):
        for times, elapsed in (([], 5), ([1], 5), ([0, 1], 0), ([0, 1], float("inf"))):
            with self.subTest(times=times, elapsed=elapsed):
                self.assertFalse(observer.assess_coverage(times, elapsed)["passed"])

    def test_five_second_bound_includes_endpoints_at_recorded_precision(self):
        coverage = observer.assess_coverage([5, 10, 15], 20)
        self.assertTrue(coverage["passed"])
        self.assertEqual(coverage["max_uncovered_s"], 5)
        self.assertTrue(observer.assess_coverage([0.1, 5.1, 10.1, 15.1], 20)["passed"])
        self.assertFalse(observer.assess_coverage([0, 5.001, 10], 10)["passed"])


class AcceptedCsiAgeTests(unittest.TestCase):
    def test_negative_and_invalid_ages_never_count_as_fresh(self):
        for age in (-1, -0.1, None, float("nan"), float("inf"), True, "1", 3001):
            with self.subTest(age=age):
                self.assertFalse(
                    observer.is_fresh_csi(
                        {"csi_status": "active", "csi_last_seen_ms": age}, 3000
                    )
                )

    def test_only_active_csi_with_nonnegative_bounded_age_is_fresh(self):
        for age in (0, 1, 3000):
            with self.subTest(age=age):
                self.assertTrue(
                    observer.is_fresh_csi(
                        {"csi_status": "active", "csi_last_seen_ms": age}, 3000
                    )
                )
        self.assertFalse(
            observer.is_fresh_csi({"csi_status": "stale", "csi_last_seen_ms": 1}, 3000)
        )


if __name__ == "__main__":
    unittest.main()
