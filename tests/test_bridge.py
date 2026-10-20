import copy
import http.client
import threading
import time
import unittest
from unittest.mock import Mock, patch

from bridge import Bridge, EdgeFalls, discovery, observations


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.health = {"source": "esp32"}
        self.latest = {
            "source": "esp32",
            "timestamp": 1000,
            "classification": {"presence": True},
            "nodes": [
                {
                    "node_id": 3,
                    "rssi_dbm": -65,
                    "node_inference": {
                        "age_ms": 100,
                        "classification": "absent",
                        "confidence": 0.8,
                    },
                }
            ],
        }
        self.fleet = {
            "nodes": [{"node_id": 3, "csi_status": "active", "csi_last_seen_ms": 100}]
        }

    def observe(self):
        return observations(self.health, self.latest, self.fleet, 1001)

    def test_uses_per_node_classification_not_aggregate(self):
        self.assertEqual(self.observe()[3]["presence"], "OFF")

    def test_preserves_different_nodes(self):
        other = copy.deepcopy(self.latest["nodes"][0])
        other["node_id"] = 2
        other["node_inference"]["classification"] = "present_moving"
        self.latest["nodes"].append(other)
        self.fleet["nodes"].append(
            {"node_id": 2, "csi_status": "active", "csi_last_seen_ms": 100}
        )
        self.assertEqual(self.observe()[2]["presence"], "ON")
        self.assertEqual(self.observe()[3]["presence"], "OFF")

    def test_active_maps_to_moving_and_publishes_true_edge_fall_for_only_its_node(self):
        for node_id, classification in ((1, "active"), (2, "present_still")):
            node = copy.deepcopy(self.latest["nodes"][0])
            node["node_id"] = node_id
            node["node_inference"]["classification"] = classification
            self.latest["nodes"].append(node)
            self.fleet["nodes"].append(
                {"node_id": node_id, "csi_status": "active", "csi_last_seen_ms": 47}
            )
        original = copy.deepcopy(self.latest)
        current = self.observe()
        self.assertEqual(current[1]["classification"], "present_moving")
        self.assertEqual(current[1]["classification_raw"], "active")
        self.assertEqual((current[1]["presence"], current[1]["motion"]), ("ON", "ON"))
        self.assertEqual(current[1]["calibration"], "unverified")
        self.assertEqual(current[2]["classification"], "present_still")
        self.assertEqual((current[2]["presence"], current[2]["motion"]), ("ON", "OFF"))
        self.assertEqual((current[3]["presence"], current[3]["motion"]), ("OFF", "OFF"))
        self.assertEqual(self.latest, original)

        bridge = Bridge.__new__(Bridge)
        bridge.known = {1, 2, 3}
        bridge.placements = {node: {"placement_valid": True} for node in bridge.known}
        bridge.rediscover = Mock()
        bridge.rediscover.is_set.return_value = False
        bridge.last_discovery = 100
        bridge.publish = Mock()
        bridge.edge_falls = EdgeFalls()
        for node in bridge.known:
            bridge.edge_falls.ingest(
                {"type": "edge_vitals", "node_id": node, "fall_detected": node == 1},
                101,
            )
        with patch("bridge.time.monotonic", return_value=102):
            bridge.update(current)
        published = {
            call.args[0]: call.args[1] for call in bridge.publish.call_args_list
        }
        for node in bridge.known:
            base = f"ruview/home/node{node}"
            self.assertEqual(published[base + "/availability"], "online")
            self.assertEqual(published[base + "/fall/availability"], "online")
            self.assertEqual(
                published[base + "/fall/state"],
                {"fall_detected": "ON" if node == 1 else "OFF"},
            )
        self.assertEqual(
            published["ruview/home/node1/attributes"]["classification_raw"], "active"
        )
        self.assertEqual(
            published["ruview/home/node1/state"]["classification"], "present_moving"
        )

    def test_active_preserves_all_freshness_and_edge_gates(self):
        self.latest["nodes"][0]["node_inference"]["classification"] = "active"
        falls = EdgeFalls()
        falls.ingest({"type": "edge_vitals", "node_id": 3, "fall_detected": True}, 100)
        for field, value in (
            ("csi_age", 10001),
            ("csi_age", -1),
            ("csi_status", "stale"),
            ("inference_age", 10001),
            ("inference_age", True),
            ("server_timestamp", 990),
            ("server_timestamp", 1002),
            ("source", "simulated"),
            ("fleet_delay", 10001),
            ("inference_delay", 10001),
        ):
            with self.subTest(field=field, value=value):
                latest, fleet = copy.deepcopy(self.latest), copy.deepcopy(self.fleet)
                fleet_delay = inference_delay = 0
                if field == "csi_age":
                    fleet["nodes"][0]["csi_last_seen_ms"] = value
                elif field == "csi_status":
                    fleet["nodes"][0]["csi_status"] = value
                elif field == "inference_age":
                    latest["nodes"][0]["node_inference"]["age_ms"] = value
                elif field == "server_timestamp":
                    latest["timestamp"] = value
                elif field == "source":
                    latest["source"] = value
                elif field == "fleet_delay":
                    fleet_delay = value
                else:
                    inference_delay = value
                current = observations(
                    self.health, latest, fleet, 1001, fleet_delay, inference_delay
                )
                self.assertEqual(current, {})
                self.assertEqual(falls.observations(current, 101), {})
        self.assertEqual(falls.observations(self.observe(), 111), {})

    def test_only_explicit_classification_alias_and_string_types_are_accepted(self):
        inference = self.latest["nodes"][0]["node_inference"]
        for value in (
            "unknown",
            "idle",
            "ACTIVE",
            " active",
            "",
            None,
            True,
            1,
            [],
            {},
        ):
            with self.subTest(value=value):
                inference["classification"] = value
                self.assertEqual(self.observe(), {})
        for value, presence, motion in (
            ("absent", "OFF", "OFF"),
            ("present_still", "ON", "OFF"),
            ("present_moving", "ON", "ON"),
        ):
            inference["classification"] = value
            state = self.observe()[3]
            self.assertEqual((state["presence"], state["motion"]), (presence, motion))
            self.assertEqual(state["classification"], value)
            self.assertEqual(state["classification_raw"], value)

    def test_rejects_simulated_data(self):
        for key in (self.health, self.latest):
            key["source"] = "simulated"
            self.assertEqual(self.observe(), {})
            key["source"] = "esp32"

    def test_rejects_stale_server(self):
        self.latest["timestamp"] = 900
        self.assertEqual(self.observe(), {})

    def test_rejects_stale_or_missing_csi(self):
        for age in (None, 10001, -1, float("nan"), True):
            self.fleet["nodes"][0]["csi_last_seen_ms"] = age
            self.assertEqual(self.observe(), {})

    def test_rejects_stale_inference(self):
        self.latest["nodes"][0]["node_inference"]["age_ms"] = 10001
        self.assertEqual(self.observe(), {})

    def test_request_latency_does_not_renew_core_observations(self):
        for fleet_delay, inference_delay in ((10001, 0), (0, 10001)):
            self.assertEqual(
                observations(
                    self.health,
                    self.latest,
                    self.fleet,
                    1001,
                    fleet_delay,
                    inference_delay,
                ),
                {},
            )
        result = observations(self.health, self.latest, self.fleet, 1001, 500, 200)[3]
        self.assertEqual(result["csi_age_ms"], 600)
        self.assertEqual(result["inference_age_ms"], 300)

    def test_truncated_collector_response_goes_offline_then_recovers_next_tick(self):
        payloads = {
            "/health": self.health,
            "/api/v1/nodes": self.fleet,
            "/api/v1/sensing/latest": self.latest,
        }
        for failed_path in payloads:
            with (
                self.subTest(failed_path=failed_path),
                patch.dict("os.environ", {"RUVIEW_API_TOKEN": "synthetic"}),
            ):
                bridge = Bridge(Mock())
                bridge.module_url = "http://worker.invalid"
                bridge.publish = Mock()
                bridge.update_observations = Mock()
                clock = [100.0]
                starts = []
                waits = []
                failed = [False]

                def get(
                    path,
                    *,
                    clock=clock,
                    starts=starts,
                    failed_path=failed_path,
                    failed=failed,
                ):
                    if path == "/health":
                        starts.append(clock[0])
                    clock[0] += 0.05
                    if path == failed_path and not failed[0]:
                        failed[0] = True
                        raise http.client.IncompleteRead(b"private response", 100)
                    return payloads[path]

                def wait(timeout, *, waits=waits, clock=clock, bridge=bridge):
                    waits.append(timeout)
                    clock[0] += timeout
                    if len(waits) == 1:
                        bridge.update_observations.assert_not_called()
                    else:
                        bridge.stopped.set()

                bridge.get = Mock(side_effect=get)
                with (
                    patch(
                        "bridge.time.monotonic",
                        side_effect=lambda clock=clock: clock[0],
                    ),
                    patch("bridge.time.time", return_value=1001),
                    patch.object(bridge.stopped, "wait", side_effect=wait),
                    self.assertLogs(level="WARNING") as logs,
                ):
                    bridge.run()
                bridge.publish.assert_called_once_with(
                    "ruview/home/availability", "offline", retain=True
                )
                bridge.update_observations.assert_called_once()
                self.assertEqual(starts, [100.0, 100.5])
                self.assertEqual(len(waits), 2)
                self.assertTrue(all(0 < delay <= 0.5 for delay in waits))
                current, observed_at = bridge.update_observations.call_args.args
                self.assertEqual(current[3]["classification"], "absent")
                self.assertAlmostEqual(observed_at, 100.65)
                self.assertAlmostEqual(current[3]["csi_age_ms"], 200)
                self.assertAlmostEqual(current[3]["inference_age_ms"], 150)
                self.assertEqual(
                    logs.output,
                    ["WARNING:root:Observation unavailable (IncompleteRead)"],
                )

    def test_unknown_is_not_empty_room(self):
        self.latest["nodes"][0]["node_inference"]["classification"] = "unknown"
        self.assertEqual(self.observe(), {})

    def test_never_invents_counts_or_coordinates(self):
        state = self.observe()[3]
        self.assertNotIn("person_count", state)
        self.assertNotIn("position", state)

    def test_restart_and_disconnect_expire_entities(self):
        _, payload = discovery(3, "presence")
        self.assertEqual(payload["expire_after"], 15)
        self.assertEqual(payload["availability_mode"], "all")
        self.assertEqual(len(payload["availability"]), 3)


class PublicationCadenceTests(unittest.TestCase):
    def test_fresh_module_ticks_preserve_ordinary_recorder_cadence(self):
        bridge = Bridge.__new__(Bridge)
        bridge.last_primary_update = None
        bridge.update = Mock()
        bridge.update_modules = Mock()
        snapshots = [{1: {"sequence": sequence}} for sequence in range(9)]
        for tick, current in enumerate(snapshots):
            with patch("bridge.time.monotonic", return_value=tick * 0.5):
                bridge.update_observations(current)
        self.assertEqual(
            [call.args[0] for call in bridge.update.call_args_list],
            snapshots[::4],
        )
        self.assertEqual(
            [call.args[0] for call in bridge.update_modules.call_args_list],
            snapshots,
        )

    def test_slow_module_work_does_not_shorten_ordinary_publication_interval(self):
        bridge = Bridge.__new__(Bridge)
        bridge.last_primary_update = None
        clock = [100.0]
        primary_times = []
        observation_times = []

        def slow_modules(*_):
            if clock[0] == 100.0:
                clock[0] += 1

        def record_primary(_, observed_at):
            primary_times.append(clock[0])
            observation_times.append(observed_at)

        bridge.update_modules = Mock(side_effect=slow_modules)
        bridge.update = Mock(side_effect=record_primary)
        with patch("bridge.time.monotonic", side_effect=lambda: clock[0]):
            for tick in (100.0, 101.5, 102.0, 102.5, 103.0):
                clock[0] = tick
                bridge.update_observations({})
        self.assertEqual(primary_times, [101.0, 103.0])
        self.assertEqual(observation_times, [100.0, 103.0])

    def test_poll_cadence_subtracts_work_and_skips_missed_ticks(self):
        bridge = Bridge.__new__(Bridge)
        bridge.stopped = Mock()
        previous = 100.0
        for now, expected in ((100.135, 100.5), (100.7, 101.0), (103.2, 103.5)):
            with (
                self.subTest(now=now),
                patch("bridge.time.monotonic", return_value=now),
            ):
                previous = bridge.wait_for_poll(previous, 0.5)
            self.assertEqual(previous, expected)
            delay = bridge.stopped.wait.call_args.args[0]
            self.assertGreater(delay, 0)
            self.assertLessEqual(delay, 0.5)
            self.assertAlmostEqual(delay, expected - now)

    def test_poll_cancellation_interrupts_wait(self):
        waiting = threading.Event()

        class StopSignal(threading.Event):
            def wait(self, timeout=None):
                waiting.set()
                return super().wait(timeout)

        bridge = Bridge.__new__(Bridge)
        bridge.stopped = StopSignal()
        thread = threading.Thread(
            target=bridge.wait_for_poll, args=(time.monotonic(), 2)
        )
        thread.start()
        try:
            self.assertTrue(waiting.wait(1))
        finally:
            bridge.stopped.set()
            thread.join(timeout=1)
        self.assertFalse(thread.is_alive())

    def test_core_loop_uses_absolute_module_ticks_without_catchup_requests(self):
        with patch.dict("os.environ", {"RUVIEW_API_TOKEN": "synthetic"}):
            bridge = Bridge(Mock())
        bridge.module_url = "http://worker.invalid"
        clock = [100.0]
        starts = []
        waits = []
        observations_seen = []
        durations = iter((0.1, 0.8, 0.1))
        bridge.update_observations = Mock(
            side_effect=lambda current, at: observations_seen.append(at)
        )

        def get(path):
            if path == "/health":
                starts.append(clock[0])
            elif path == "/api/v1/sensing/latest":
                clock[0] += next(durations)
            return {}

        def wait(timeout):
            waits.append(timeout)
            clock[0] += timeout
            if len(waits) == 3:
                bridge.stopped.set()

        bridge.get = Mock(side_effect=get)
        with (
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch.object(bridge.stopped, "wait", side_effect=wait),
        ):
            bridge.run()
        self.assertEqual(starts, [100.0, 100.5, 101.5])
        self.assertEqual(observations_seen, [100.1, 101.3, 101.6])
        for actual, expected in zip(waits, (0.4, 0.2, 0.4), strict=True):
            self.assertAlmostEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
