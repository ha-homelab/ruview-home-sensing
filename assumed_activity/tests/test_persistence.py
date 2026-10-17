import copy
import math
import unittest

from assumed_activity.persistence import Persistence

POLICY = {
    "activity_threshold": 3,
    "activity_min_samples": 2,
    "activity_min_seconds": 1.0,
    "activity_max_gap_seconds": 2.5,
}


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.gate = Persistence(POLICY)
        self.identities = {node: (1, 4, 0) for node in (1, 2, 3)}

    def update(self, mono, scores=(0, 8, 0), tokens=None):
        nodes = [
            {"node_id": node, "status": "ready", "score": score}
            for node, score in enumerate(scores, 1)
        ]
        if tokens is None:
            token = int(mono * 1_000_000) + 10
            tokens = {node: (token, token) for node in (1, 2, 3)}
        return self.gate.update(nodes, mono, self.identities, tokens)

    def test_isolated_spike_never_confirms_and_next_spike_starts_fresh(self):
        self.assertEqual(self.update(1)["status"], "pending")
        quiet = self.update(2, (0, 0, 0))
        self.assertEqual(quiet["status"], "idle")
        self.assertFalse(quiet["raw_active"])
        again = self.update(3)
        self.assertEqual(again["status"], "pending")
        self.assertEqual(again["nodes"][1]["samples"], 1)

    def test_persistent_anomaly_requires_count_and_elapsed_time(self):
        self.assertEqual(self.update(1)["status"], "pending")
        self.assertEqual(self.update(1.5)["status"], "pending")
        confirmed = self.update(2)
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["confirmed_nodes"], [2])
        self.assertEqual(confirmed["nodes"][1]["span_seconds"], 1.0)

    def test_different_nodes_cannot_confirm_each_others_spikes(self):
        for index in range(8):
            scores = (8, 0, 0) if index % 2 else (0, 8, 0)
            self.assertEqual(self.update(index, scores)["status"], "pending")

    def test_confirmation_releases_immediately_without_hold(self):
        self.update(1)
        self.assertEqual(self.update(2)["confirmed_nodes"], [2])
        released = self.update(3, (0, 2.99, 0))
        self.assertEqual(released["confirmed_nodes"], [])
        self.assertEqual(released["nodes"][1]["samples"], 0)
        self.assertEqual(released["nodes"][1]["span_seconds"], 0.0)

    def test_exact_gap_boundary_is_allowed_but_larger_gap_restarts(self):
        self.update(1)
        self.assertEqual(self.update(3.5)["status"], "confirmed")
        restarted = self.update(6.001)
        self.assertEqual(restarted["status"], "pending")
        self.assertEqual(restarted["nodes"][1]["samples"], 1)

    def test_identity_changes_reset_only_that_candidate(self):
        self.update(1, (8, 8, 0))
        self.identities[2] = (2, 4, 0)
        changed = self.update(2, (8, 8, 0))
        self.assertEqual(changed["confirmed_nodes"], [1])
        self.assertEqual(changed["nodes"][1]["samples"], 1)

    def test_repeated_or_backward_source_token_clears_all_candidates(self):
        for token in (
            (1_000_010, 2_000_010),
            (2_000_010, 1_000_010),
            (1, 2_000_010),
            (2_000_010, 1),
        ):
            with self.subTest(token=token):
                self.setUp()
                self.update(1)
                tokens = {node: (2_000_010, 2_000_010) for node in (1, 2, 3)}
                tokens[2] = token
                self.assertEqual(self.update(2, tokens=tokens)["status"], "unavailable")
                self.assertEqual(self.update(3)["status"], "pending")

    def test_invalid_or_backward_clock_clears_all_candidates(self):
        for mono in (0.5, 1, math.inf, math.nan, True):
            with self.subTest(mono=mono):
                self.setUp()
                self.update(1)
                tokens = {node: (20, 20) for node in (1, 2, 3)}
                self.assertEqual(
                    self.update(mono, tokens=tokens)["status"], "unavailable"
                )
                self.assertEqual(self.update(3)["status"], "pending")

    def test_explicit_unavailable_resets_and_has_no_evidence(self):
        self.update(1)
        self.assertEqual(
            self.gate.unavailable(),
            {
                "schema": "ruview.activity-persistence.v1",
                "status": "unavailable",
                "raw_active": None,
                "confirmed_nodes": [],
                "nodes": [],
            },
        )
        self.assertEqual(self.update(2)["status"], "pending")

    def test_partial_invalid_update_cannot_advance_other_nodes(self):
        self.update(1, (8, 8, 0))
        nodes = [{"node_id": node, "status": "ready", "score": 8} for node in (1, 2, 3)]
        nodes[2]["status"] = "unknown"
        tokens = {node: (2_000_010, 2_000_010) for node in (1, 2, 3)}
        self.assertEqual(
            self.gate.update(nodes, 2, self.identities, tokens)["status"], "unavailable"
        )
        self.assertEqual(self.update(3, (8, 8, 0))["status"], "pending")

    def test_changed_identity_can_restart_source_tokens_without_confirming(self):
        self.update(1)
        self.identities[2] = (2, 0, 0)
        tokens = {node: (2_000_010, 2_000_010) for node in (1, 2, 3)}
        tokens[2] = (1, 1)
        self.assertEqual(self.update(2, tokens=tokens)["status"], "pending")

    def test_threshold_is_inclusive(self):
        self.update(1, (0, 3, 0))
        self.assertEqual(self.update(2, (0, 3, 0))["confirmed_nodes"], [2])

    def test_snapshot_mutation_does_not_change_pending_evidence(self):
        first = self.update(1)
        original = copy.deepcopy(first)
        first["nodes"][1].update(samples=3000, confirmed=True)
        first["confirmed_nodes"].append(3)
        second = self.update(1.5)
        self.assertEqual(second["status"], "pending")
        self.assertEqual(second["nodes"][1]["samples"], 2)
        self.assertEqual(original["nodes"][1]["samples"], 1)

    def test_counter_is_bounded_without_losing_elapsed_span(self):
        for second in range(3602):
            result = self.update(second)
        self.assertEqual(result["nodes"][1]["samples"], 3600)
        self.assertEqual(result["nodes"][1]["span_seconds"], 3601.0)
        self.assertEqual(result["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
