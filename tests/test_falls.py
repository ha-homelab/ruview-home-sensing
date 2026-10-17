import unittest

from bridge import EdgeFalls, discovery


class FallTests(unittest.TestCase):
    def setUp(self):
        self.falls = EdgeFalls()

    def ingest(self, node_id, flag, now):
        self.falls.ingest(
            {"type": "edge_vitals", "node_id": node_id, "fall_detected": flag}, now
        )

    def test_short_fall_pulse_survives_poll_interval_without_cross_node_leak(self):
        self.ingest(3, True, 100)
        self.ingest(3, False, 101)
        self.ingest(1, False, 101)
        state = self.falls.observations({1, 3}, 102)
        self.assertEqual(state[3]["fall_detected"], "ON")
        self.assertEqual(state[1]["fall_detected"], "OFF")
        self.ingest(3, False, 110)
        self.assertEqual(self.falls.observations({3}, 111)[3]["fall_detected"], "OFF")

    def test_stale_or_missing_edge_packet_is_unavailable_not_no_fall(self):
        self.assertEqual(self.falls.observations({3}, 100), {})
        for flag in (True, False):
            self.ingest(3, flag, 100)
            self.assertEqual(self.falls.observations({3}, 111), {})

    def test_fresh_edge_packet_still_requires_fresh_real_csi_and_inference(self):
        self.ingest(3, True, 100)
        self.assertEqual(self.falls.observations({}, 101), {})
        self.assertEqual(self.falls.observations({1}, 101), {})

    def test_disconnect_drops_cached_flags_and_hold(self):
        self.ingest(3, True, 100)
        self.falls.clear()
        self.assertEqual(self.falls.observations({3}, 101), {})
        self.ingest(3, False, 102)
        self.assertEqual(self.falls.observations({3}, 103)[3]["fall_detected"], "OFF")

    def test_invalid_node_ids_and_non_boolean_flags_are_rejected(self):
        for node_id in (True, "3", 0, 256, None):
            self.ingest(node_id, True, 100)
        for flag in (0, 1, "false", None):
            self.ingest(3, flag, 100)
        self.assertEqual(self.falls.observations({1, 3}, 101), {})

    def test_other_messages_and_future_receipt_are_rejected(self):
        for message in ([], None, {"type": "sensing_update", "fall_detected": True}):
            self.falls.ingest(message, 100)
        self.assertEqual(self.falls.observations({3}, 101), {})
        self.ingest(3, True, 110)
        self.assertEqual(self.falls.observations({3}, 100), {})

    def test_discovery_requires_both_csi_and_edge_stream_availability(self):
        topic, config = discovery(3, "fall_detected")
        self.assertIn("binary_sensor/ruview_home_node3/fall_detected", topic)
        self.assertEqual(config["availability_mode"], "all")
        self.assertEqual(len(config["availability"]), 4)
        self.assertEqual(config["expire_after"], 15)
        self.assertEqual(config["state_topic"], "ruview/home/node3/fall/state")
        self.assertEqual(config["device_class"], "safety")


if __name__ == "__main__":
    unittest.main()
