"""Temporal display filtering preserves raw signal scores and source leases."""

import copy
import unittest

from assumed_activity.core import Producer, configuration
from assumed_activity.tests.helpers import config, inputs


def gated_config():
    value = config()
    value["policy"].update(
        activity_min_samples=2,
        activity_min_seconds=1.0,
        activity_max_gap_seconds=2.5,
    )
    return value


class PersistenceIntegrationTests(unittest.TestCase):
    def ready(self):
        producer = Producer(
            gated_config(), expected_coordinate_frame=config()["coordinate_frame"]
        )
        for index in range(4):
            producer.update(*inputs(index))
        return producer

    def test_raw_values_and_expiry_unchanged_while_confirmation_waits(self):
        gated, legacy = (
            self.ready(),
            Producer(config(), expected_coordinate_frame=config()["coordinate_frame"]),
        )
        for index in range(4):
            legacy.update(*inputs(index))
        for index, state in ((4, "quiet"), (5, "active")):
            args = inputs(index, (10, 100, 10))
            actual, raw = gated.update(*args), legacy.update(*args)
            self.assertEqual(actual["state"], state)
            for field in ("nodes", "zones", "oldest_source_at_ns", "expires_at_ns"):
                self.assertEqual(actual[field], raw[field])
        self.assertEqual(actual["activity_gate"]["confirmed_nodes"], [2])
        expired = gated.snapshot(int(actual["expires_at_ns"]), 10)
        self.assertEqual(expired["state"], "unknown")
        self.assertEqual(expired["activity_gate"]["status"], "unavailable")
        self.assertEqual(expired["expires_at_ns"], actual["expires_at_ns"])

    def test_single_spike_and_alternating_receivers_never_confirm(self):
        producer = self.ready()
        for index, values in (
            (4, (10, 100, 10)),
            (5, (100, 10, 10)),
            (6, (10, 10, 100)),
            (7, (10, 10, 10)),
        ):
            result = producer.update(*inputs(index, values))
            self.assertEqual(result["state"], "quiet")
            self.assertFalse(result["activity_gate"]["confirmed_nodes"])

    def test_unknown_and_epoch_changes_break_confirmation(self):
        for change in ("unavailable", "epoch"):
            with self.subTest(change=change):
                producer = self.ready()
                producer.update(*inputs(4, (10, 100, 10)))
                args = list(inputs(5, (10, 100, 10)))
                if change == "unavailable":
                    args[0] = {}
                    self.assertEqual(producer.update(*args)["state"], "unknown")
                    result = producer.update(*inputs(6, (10, 100, 10)))
                else:
                    args[1]["nodes"][1].update(
                        node_epoch=2, epoch_reason="sequence_gap"
                    )
                    result = producer.update(*args)
                self.assertEqual(result["state"], "quiet")
                self.assertEqual(result["activity_gate"]["nodes"][1]["samples"], 1)

    def test_nonadvancing_clock_fails_closed_without_reusing_candidate(self):
        producer = self.ready()
        producer.update(*inputs(4, (10, 100, 10)))
        args = list(inputs(5, (10, 100, 10)))
        args[-1] = 4.0
        result = producer.update(*args)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["activity_gate"]["status"], "unavailable")
        self.assertEqual(producer.update(*inputs(6, (10, 100, 10)))["state"], "quiet")

    def test_configuration_requires_complete_explicit_persistence_policy(self):
        value = gated_config()
        for key in (
            "activity_min_samples",
            "activity_min_seconds",
            "activity_max_gap_seconds",
        ):
            partial = copy.deepcopy(value)
            del partial["policy"][key]
            with self.assertRaisesRegex(ValueError, "incomplete_activity_persistence"):
                configuration(
                    partial, expected_coordinate_frame=config()["coordinate_frame"]
                )
        value["policy"]["activity_min_samples"] = True
        with self.assertRaises(ValueError):
            configuration(value, expected_coordinate_frame=config()["coordinate_frame"])


if __name__ == "__main__":
    unittest.main()
