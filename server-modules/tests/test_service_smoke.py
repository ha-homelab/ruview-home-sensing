import copy
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "service_smoke", Path(__file__).with_name("service_smoke.py")
)
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


def complete():
    return {
        "nodes": [
            {"node_id": 1, "sequence": 119, "frames": 120},
            {"node_id": 2, "sequence": 187, "frames": 188},
            {"node_id": 3, "sequence": None, "frames": 0},
        ],
        "counters": {"received": 309, "rejected": 1, "record_written": 308},
    }


class PublicationTests(unittest.TestCase):
    sequences = {1: 120, 2: 188}

    def test_async_recording_and_cached_processing_must_both_finish(self):
        good = complete()
        self.assertTrue(SMOKE.publication_complete(good, self.sequences))
        for field, value in (("sequence", 118), ("frames", 119)):
            partial = copy.deepcopy(good)
            partial["nodes"][0][field] = value
            self.assertFalse(SMOKE.publication_complete(partial, self.sequences))
        for field, value in (
            ("received", 308),
            ("rejected", 0),
            ("record_written", 307),
        ):
            partial = copy.deepcopy(good)
            partial["counters"][field] = value
            self.assertFalse(SMOKE.publication_complete(partial, self.sequences))

    def test_replay_barrier_requires_processing_and_recording_of_the_exact_tail(self):
        value = {
            "counters": {"received": 81, "record_written": 81},
            "nodes": [{"frames": 80, "duplicates": 1, "sequence_discontinuities": 0}],
        }
        self.assertTrue(SMOKE.duplicate_publication_complete(value, 81, 80, 1, 0))
        for group, field in (
            ("counters", "received"),
            ("counters", "record_written"),
            ("nodes", "frames"),
            ("nodes", "duplicates"),
            ("nodes", "sequence_discontinuities"),
        ):
            partial = copy.deepcopy(value)
            target = partial[group][0] if group == "nodes" else partial[group]
            target[field] += 1
            self.assertFalse(
                SMOKE.duplicate_publication_complete(partial, 81, 80, 1, 0)
            )

    def test_replay_cannot_change_evidence_identity_or_source_timestamps(self):
        before = {
            "nodes": [{"duplicates": 0, "age_ms": 10, "last_received_at_ns": "500"}],
            "events": [{"observed_at_ns": "490", "value": 2, "age_ms": 20}],
            "fleet": {"fleet_epoch": 1},
        }
        after = copy.deepcopy(before)
        after["nodes"][0].update(duplicates=1, age_ms=20)
        after["events"][0]["age_ms"] = 30
        SMOKE.check_duplicate_preserved(before, after)
        for field, replacement in (("observed_at_ns", "491"), ("value", 3)):
            changed = copy.deepcopy(after)
            changed["events"][0][field] = replacement
            with self.assertRaisesRegex(ValueError, "changed events"):
                SMOKE.check_duplicate_preserved(before, changed)

    def test_wait_retains_partial_then_returns_exact_completed_publication(self):
        partial = complete()
        partial["nodes"][1]["sequence"] = 186
        responses = iter((partial, complete()))
        observed = []
        timeouts = []

        def snapshot(timeout):
            timeouts.append(timeout)
            return next(responses)

        with (
            patch.object(SMOKE.time, "monotonic", return_value=0),
            patch.object(SMOKE.time, "sleep") as sleep,
        ):
            result = SMOKE.await_publication(snapshot, self.sequences, observed.append)
        self.assertEqual(result, complete())
        self.assertEqual(observed, [partial, complete()])
        self.assertEqual(timeouts, [1, 1])
        sleep.assert_called_once_with(0.05)

    def test_timeout_preserves_last_observation_and_does_not_poll_forever(self):
        partial = complete()
        partial["counters"]["record_written"] = 307
        observed = []
        with (
            patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 0, 0, 2]),
            patch.object(SMOKE.time, "sleep"),
            self.assertRaisesRegex(ValueError, "did not reach the sent tail"),
        ):
            SMOKE.await_publication(
                lambda timeout: partial, self.sequences, observed.append
            )
        self.assertEqual(observed, [partial])

    def test_late_completed_response_cannot_bypass_deadline(self):
        observed = []
        with (
            patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 2]),
            self.assertRaisesRegex(ValueError, "deadline exceeded"),
        ):
            SMOKE.await_publication(
                lambda timeout: complete(), self.sequences, observed.append
            )
        self.assertEqual(observed, [complete()])

    def test_http_timeout_is_limited_to_remaining_readiness_budget(self):
        timeouts = []

        def snapshot(timeout):
            timeouts.append(timeout)
            return complete()

        with patch.object(SMOKE.time, "monotonic", side_effect=[0, 1.25, 1.3]):
            SMOKE.await_publication(snapshot, self.sequences, lambda value: None)
        self.assertEqual(timeouts, [0.25])


if __name__ == "__main__":
    unittest.main()
