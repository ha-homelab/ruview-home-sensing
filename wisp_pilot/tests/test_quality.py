import unittest

from wisp_pilot.quality import QualityObserver

A = "02:00:00:00:00:01"
B = "02:00:00:00:00:02"
C = "02:00:00:00:00:03"
SECOND = 1_000_000_000


def raw(sequence=1, channel=6, receiver=A):
    return {
        "packet_type": "raw_csi",
        "sequence": sequence,
        "receiver_mac": receiver,
        "channel": channel,
        "first_word_invalid": True,
    }


def report(sequence=1, uptime=100, frames=4, score=1.1, transmitter=B):
    return {
        "packet_type": "link_report",
        "sequence": sequence,
        "receiver_mac": A,
        "uptime_s": uptime,
        "pairs_truncated": False,
        "confirmed_pairs": [],
        "links": [
            {
                "transmitter_mac": transmitter,
                "kind": "node",
                "frames": frames,
                "rssi_dbm": -55 if frames else None,
                "motion_score": score,
                "spread_percent": 1.0,
                "motion": False,
                "confirmed_motion": False,
                "breathing": False,
            }
        ],
    }


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.observer = QualityObserver([A, B])

    def receiver(self, now=0):
        return self.observer.snapshot(now)["receivers"][A]

    def stream(self, kind="raw_csi", now=0):
        return self.receiver(now)["streams"][kind]

    def test_unseen_fresh_and_expired_are_distinct(self):
        self.assertEqual(self.receiver()["state"], "unknown")
        self.observer.ingest(raw(), 0)
        self.assertEqual(self.receiver(3 * SECOND)["state"], "fresh")
        self.assertEqual(self.receiver(3 * SECOND + 1)["state"], "unavailable")
        self.assertEqual(
            self.observer.snapshot(4 * SECOND)["receivers"][B]["state"], "unknown"
        )

    def test_sequence_domains_are_independent_and_wrap(self):
        self.observer.ingest(raw((1 << 32) - 1), 0)
        self.observer.ingest(report(200), 1)
        self.observer.ingest(raw(0), 2)
        self.assertEqual(self.stream(now=2)["accepted"], 2)
        self.assertEqual(self.stream(now=2)["gap_events"], 0)
        self.assertEqual(self.stream("link_report", 2)["last_sequence"], 200)

    def test_duplicate_reorder_and_half_range_never_refresh(self):
        self.observer.ingest(raw(10), 0)
        for sequence, now in (
            (10, SECOND),
            (9, 2 * SECOND),
            (10 + (1 << 31), 4 * SECOND),
        ):
            self.observer.ingest(raw(sequence), now)
        stream = self.stream(now=4 * SECOND)
        self.assertEqual(stream["age_ns"], 4 * SECOND)
        self.assertEqual(stream["state"], "unavailable")
        self.assertEqual(stream["duplicates"], 1)
        self.assertEqual(stream["out_of_order"], 2)
        self.assertEqual(self.observer.snapshot(4 * SECOND)["rejected_packets"], 3)

    def test_gap_and_channel_change_are_diagnostics_not_loss(self):
        self.observer.ingest(raw(1), 0)
        self.observer.ingest(raw(5, 11), 1)
        stream = self.stream(now=1)
        self.assertEqual(stream["gap_events"], 1)
        self.assertEqual(stream["channel_changes"], 1)
        self.assertEqual(stream["discontinuities"], 2)
        self.assertEqual(stream["first_word_invalid"], 2)
        self.assertNotIn("lost_packets", stream)

    def test_raw_progress_does_not_refresh_report_or_links(self):
        self.observer.ingest(report(), 0)
        self.observer.ingest(raw(), 4 * SECOND)
        receiver = self.receiver(4 * SECOND)
        self.assertEqual(receiver["state"], "fresh")
        self.assertEqual(receiver["streams"]["link_report"]["state"], "unavailable")
        self.assertEqual(receiver["links"][B]["state"], "unavailable")

    def test_no_frames_or_score_unknown_never_mean_empty(self):
        self.observer.ingest(report(frames=0), 0)
        self.assertEqual(self.receiver()["links"][B]["state"], "unknown")
        self.observer.ingest(report(2, score=None), 1)
        self.assertEqual(self.receiver(1)["links"][B]["state"], "unknown")
        self.observer.ingest(report(3, transmitter=C), 2)
        self.assertEqual(self.receiver(2)["links"][C]["state"], "fresh")
        self.assertNotIn(B, self.receiver(2)["links"])
        packet = report(4)
        packet["links"][0]["spread_percent"] = None
        self.observer.ingest(packet, 3)
        self.assertEqual(self.receiver(3)["links"][B]["state"], "unknown")

    def test_uptime_regression_quarantined_then_two_stale_candidates(self):
        self.observer.ingest(raw(200), 0)
        self.observer.ingest(report(100, 100), 0)
        self.observer.ingest(report(1, 1), SECOND)
        self.assertEqual(self.stream("link_report", SECOND)["last_sequence"], 100)
        self.observer.ingest(report(2, 2), 4 * SECOND)
        self.assertEqual(self.stream("link_report", 4 * SECOND)["state"], "unavailable")
        self.observer.ingest(report(3, 3), 5 * SECOND)
        state = self.receiver(5 * SECOND)
        self.assertEqual(state["streams"]["link_report"]["possible_restarts"], 1)
        self.assertEqual(state["streams"]["link_report"]["last_sequence"], 3)
        self.assertEqual(state["streams"]["raw_csi"]["state"], "unknown")
        self.observer.ingest(raw(1), 5 * SECOND + 1)
        self.assertEqual(self.stream(now=5 * SECOND + 1)["last_sequence"], 1)

    def test_repeated_reset_candidate_cannot_refresh(self):
        self.observer.ingest(report(100, 100), 0)
        for now in (4 * SECOND, 5 * SECOND, 6 * SECOND):
            self.observer.ingest(report(1, 1), now)
        stream = self.stream("link_report", 6 * SECOND)
        self.assertEqual(stream["possible_restarts"], 0)
        self.assertEqual(stream["last_sequence"], 100)
        self.assertEqual(stream["state"], "unavailable")

    def test_restart_candidates_must_form_a_fresh_sequence(self):
        self.observer.ingest(report(100, 100), 0)
        self.observer.ingest(report(1, 1), 4 * SECOND)
        self.observer.ingest(report(2, 10), 13 * SECOND)
        stream = self.stream("link_report", 13 * SECOND)
        self.assertEqual(stream["possible_restarts"], 0)
        self.assertEqual(stream["last_sequence"], 100)

    def test_novel_macs_never_create_unbounded_history(self):
        for number in range(1, 250):
            transmitter = f"02:00:00:00:01:{number:02x}"
            self.observer.ingest(report(number, transmitter=transmitter), number)
            self.observer.ingest(raw(receiver=transmitter), number)
        snapshot = self.observer.snapshot(250)
        self.assertEqual(len(snapshot["receivers"]), 2)
        self.assertEqual(len(snapshot["receivers"][A]["links"]), 1)
        self.assertEqual(snapshot["unexpected_receiver_packets"], 249)

    def test_oversized_report_api_input_is_rejected_without_mutation(self):
        packet = report()
        packet["links"] *= 21
        with self.assertRaisesRegex(ValueError, "invalid_report_bounds"):
            self.observer.ingest(packet, 0)
        self.assertEqual(self.observer.snapshot(0)["received_packets"], 0)

    def test_invalid_arguments_and_clock_reversal_do_not_mutate(self):
        for receivers, freshness in (
            ([], 1),
            ([A, A], 1),
            ([A], 0),
            ([A], True),
            (["bad"], 1),
        ):
            with (
                self.subTest(receivers=receivers, freshness=freshness),
                self.assertRaises(ValueError),
            ):
                QualityObserver(receivers, freshness)
        self.observer.ingest(raw(), 10)
        original = self.observer.snapshot(10)
        for packet, now in ((raw(2), 9), (raw(True), 11), (raw(2), True)):
            with self.assertRaises(ValueError):
                self.observer.ingest(packet, now)
            self.assertEqual(self.observer.snapshot(10), original)
        with self.assertRaises(ValueError):
            self.observer.snapshot(9)

    def test_unexpected_receiver_and_snapshots_are_detached(self):
        self.observer.ingest(raw(receiver=C), 0)
        self.assertEqual(self.observer.snapshot(0)["unexpected_receiver_packets"], 1)
        self.assertNotIn(C, self.observer.snapshot(0)["receivers"])
        packet = report()
        self.observer.ingest(packet, 1)
        packet["links"][0]["frames"] = 0
        snapshot = self.receiver(1)
        snapshot["links"][B]["frames"] = 999
        self.assertEqual(self.receiver(1)["links"][B]["frames"], 4)

    def test_replay_same_packets_and_times_is_deterministic(self):
        events = [(raw(), 0), (report(), 1), (raw(4), 5), (report(2), 8)]
        other = QualityObserver([A, B])
        for packet, now in events:
            self.observer.ingest(packet, now)
            other.ingest(packet, now)
        self.assertEqual(self.observer.snapshot(4 * SECOND), other.snapshot(4 * SECOND))
        self.assertTrue(self.observer.snapshot(4 * SECOND)["diagnostic_only"])


if __name__ == "__main__":
    unittest.main()
