import copy
import gzip
import http.client
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import module_observations as modules
from bridge import Bridge, Config, module_discovery


class ModuleObservationsTests(unittest.TestCase):
    def setUp(self):
        self.payload = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "server-modules/fixtures/latest.synthetic.json"
            ).read_text()
        )
        self.now = int(self.payload["generated_at_ns"])
        self.core = {2: {"csi_age_ms": 100, "inference_age_ms": 120}}

    def decoded(self):
        return modules.decode(self.payload, self.now)

    def test_occurrences_and_full_event_id_preserved(self):
        event = self.payload["events"][0]
        event["event_id"] = str(2**32 - 1)
        current = modules.current(self.decoded(), 1000, self.core)[2]
        emitted = current["events"][0]
        self.assertEqual(emitted["event_id"], "4294967295")
        self.assertEqual(emitted["occurrence_seq"], event["occurrence_seq"])
        self.assertEqual(emitted["observed_at_ns"], event["observed_at_ns"])
        self.assertEqual(emitted["age_ms"], 1050)
        self.assertTrue(emitted["fresh"])

    def test_cached_http_cannot_renew_old_event(self):
        self.payload["generated_at_ns"] = str(self.now + 6_000_000_000)
        self.payload["nodes"][0]["last_received_at_ns"] = self.payload[
            "generated_at_ns"
        ]
        decoded = modules.decode(self.payload, self.now + 6_000_000_000)
        current = modules.current(decoded, 0, self.core)[2]
        self.assertEqual(current["events"][0]["age_ms"], 6050)
        self.assertFalse(current["events"][0]["fresh"])

    def test_snapshot_and_csi_expire_independently(self):
        self.assertEqual(modules.current(self.decoded(), 5001, self.core), {})
        self.payload["nodes"][0]["age_ms"] = 5001
        self.assertEqual(modules.current(self.decoded(), 0, self.core), {})

    def test_core_observation_required(self):
        self.assertEqual(modules.current(self.decoded(), 0, {}), {})
        for field in ("csi_age_ms", "inference_age_ms"):
            core = copy.deepcopy(self.core)
            core[2][field] = 5001
            self.assertEqual(modules.current(self.decoded(), 0, core), {})

    def test_clock_skew_bounded(self):
        modules.decode(self.payload, self.now - 250_000_000)
        for delta in (-251_000_000, 5_001_000_000):
            with self.assertRaises(ValueError):
                modules.decode(self.payload, self.now + delta)

    def test_provenance_must_match(self):
        original = copy.deepcopy(self.payload)
        for field, value in (
            ("node_id", 3),
            ("node_epoch", 2),
            ("worker_run_id", "other"),
            ("algorithm_version", "bad"),
            ("source_sha256", "f" * 64),
            ("source", "simulated"),
            ("recognition_validated", True),
        ):
            with self.subTest(field=field):
                self.payload = copy.deepcopy(original)
                self.payload["events"][0][field] = value
                with self.assertRaises(ValueError):
                    self.decoded()

    def test_rejects_nonfinite_or_boolean_values(self):
        for value in (float("nan"), float("inf"), True, None, {"count": 1}):
            self.payload["events"][0]["value"] = value
            with self.assertRaises(ValueError):
                self.decoded()

    def test_rejects_duplicate_occurrence(self):
        self.payload["events"].append(copy.deepcopy(self.payload["events"][0]))
        with self.assertRaises(ValueError):
            self.decoded()

    def test_event_bound_is_explicit(self):
        event = self.payload["events"][0]
        self.payload["events"] = [
            {**event, "occurrence_seq": str(i)} for i in range(70)
        ]
        node = self.decoded()[2]
        self.assertEqual(len(node["events"]), 64)
        self.assertEqual(node["omitted_events"], 6)
        self.assertEqual(node["events"][0]["occurrence_seq"], "69")

    def test_producer_and_bridge_omissions_are_combined(self):
        self.payload["nodes"][0]["omitted_events"] = 7
        event = self.payload["events"][0]
        self.payload["events"] = [
            {**event, "occurrence_seq": str(i)} for i in range(70)
        ]
        node = self.decoded()[2]
        self.assertEqual(node["producer_omitted_events"], 7)
        self.assertEqual(node["omitted_events"], 13)

    def test_ineligible_algorithm_never_fresh_event(self):
        self.payload["nodes"][0]["algorithms"][0]["availability"] = "ineligible"
        node = modules.current(self.decoded(), 0, self.core)[2]
        self.assertFalse(node["events"][0]["fresh"])
        self.assertEqual(node["state"], "waiting_for_eligible_input")

    def test_unobserved_node_does_not_hide_healthy_node(self):
        node = copy.deepcopy(self.payload["nodes"][0])
        node.update(
            node_id=1, fresh=False, sequence=None, last_received_at_ns=None, age_ms=None
        )
        self.payload["nodes"].append(node)
        self.assertEqual(set(self.decoded()), {2})

    def test_producer_stale_event_never_renewed(self):
        self.payload["events"][0]["fresh"] = False
        node = modules.current(self.decoded(), 0, self.core)[2]
        self.assertFalse(node["events"][0]["fresh"])

    def test_producer_lease_is_stricter_than_bridge_transport_limit(self):
        self.payload["events"][0]["age_ms"] = 2001
        node = modules.current(self.decoded(), 0, self.core)[2]
        self.assertFalse(node["events"][0]["fresh"])
        self.assertEqual(modules.current(self.decoded(), 2001, self.core), {})

    def test_discovery_is_separate_diagnostic(self):
        topic, payload = module_discovery(2)
        self.assertIn("server_modules/config", topic)
        self.assertEqual(payload["entity_category"], "diagnostic")
        self.assertEqual(payload["expire_after"], 7)
        self.assertNotIn("device_class", payload)

    def publication_bridge(self):
        bridge = Bridge.__new__(Bridge)
        bridge.config = Config()
        bridge.module_url = "http://worker.invalid"
        bridge.module_lock = threading.Lock()
        bridge.module_snapshot = (self.decoded(), 100)
        bridge.known = {2}
        bridge.placements = {
            2: {
                "placement_valid": True,
                "measurement_location": "synthetic position A",
                "configured_room": "zone_a",
                "room_id": "zone_a",
                "room_coverage_validation": "unverified",
            }
        }
        bridge.client = Mock()
        bridge.client.publish.return_value.rc = 0
        return bridge

    def test_discovery_migrates_existing_entity_to_one_observation_topic(self):
        bridge = self.publication_bridge()
        bridge.rediscover = threading.Event()
        bridge.announce()
        configs = [
            call
            for call in bridge.client.publish.call_args_list
            if call.args[0].endswith("/server_modules/config")
        ]
        self.assertEqual(len(configs), 1)
        call = configs[0]
        self.assertEqual(
            call.args[0], "homeassistant/sensor/ruview_home_node2/server_modules/config"
        )
        self.assertTrue(call.kwargs["retain"])
        config = json.loads(call.args[1])
        self.assertEqual(config["unique_id"], "ruview_home_node2_server_modules")
        self.assertEqual(
            config["default_entity_id"], "sensor.ruview_node2_server_modules"
        )
        self.assertEqual(config["state_topic"], "ruview/home/node2/modules/observation")
        self.assertEqual(config["json_attributes_topic"], config["state_topic"])
        self.assertEqual(config["value_template"], "{{ value_json.state }}")
        self.assertEqual(
            config["json_attributes_template"], "{{ value_json.attributes | tojson }}"
        )

    def test_running_waiting_transitions_publish_one_coherent_envelope(self):
        bridge = self.publication_bridge()
        # Exercise the real decoder, freshness calculation and JSON MQTT serializer.
        # This verifies the wire contract; HA subscription coalescing is a separate
        # integration check against its installed implementation.
        for availability, state, running in (
            ("running", "experimental", 1),
            ("ineligible", "waiting_for_eligible_input", 0),
            ("running", "experimental", 1),
        ):
            with self.subTest(availability=availability):
                self.payload["nodes"][0]["algorithms"][0]["availability"] = availability
                bridge.module_snapshot = (self.decoded(), 100)
                original = copy.deepcopy(bridge.module_snapshot)
                bridge.client.reset_mock()
                published_ns = self.now + 100_000_000
                with (
                    patch("bridge.time.monotonic", return_value=100.1),
                    patch("bridge.time.time_ns", return_value=published_ns),
                ):
                    bridge.update_modules(self.core)
                calls = bridge.client.publish.call_args_list
                self.assertEqual(
                    [call.args[0] for call in calls],
                    [
                        "ruview/home/node2/modules/observation",
                        "ruview/home/node2/modules/availability",
                    ],
                )
                self.assertEqual(calls[0].kwargs, {"qos": 1, "retain": False})
                envelope = json.loads(calls[0].args[1])
                self.assertEqual(set(envelope), {"state", "attributes"})
                self.assertEqual(envelope["state"], state)
                attrs = envelope["attributes"]
                self.assertEqual(attrs["schema"], "ruview.ha.server-modules.v1")
                self.assertEqual(attrs["running_algorithms"], running)
                self.assertEqual(attrs["fresh_event_count"], running)
                self.assertEqual(attrs["published_at_ns"], str(published_ns))
                self.assertEqual(attrs["room_id"], "zone_a")
                self.assertFalse(attrs["recognition_validated"])
                self.assertEqual(
                    attrs["events"][0]["observed_at_ns"],
                    self.payload["events"][0]["observed_at_ns"],
                )
                self.assertEqual(calls[1].args[1], "online")
                self.assertTrue(calls[1].kwargs["retain"])
                self.assertEqual(bridge.module_snapshot, original)

    def test_cache_republication_keeps_original_event_clock_then_goes_offline(self):
        bridge = self.publication_bridge()
        envelopes = []
        for delta in (0, 500):
            bridge.client.reset_mock()
            with (
                patch("bridge.time.monotonic", return_value=100 + delta / 1000),
                patch("bridge.time.time_ns", return_value=self.now + delta * 1_000_000),
            ):
                bridge.update_modules(self.core)
            envelopes.append(
                json.loads(bridge.client.publish.call_args_list[0].args[1])
            )
        before, after = [value["attributes"] for value in envelopes]
        self.assertNotEqual(before["published_at_ns"], after["published_at_ns"])
        self.assertEqual(
            before["events"][0]["occurrence_seq"], after["events"][0]["occurrence_seq"]
        )
        self.assertEqual(
            before["events"][0]["observed_at_ns"], after["events"][0]["observed_at_ns"]
        )
        self.assertEqual(
            after["events"][0]["age_ms"], before["events"][0]["age_ms"] + 500
        )
        for elapsed, core in ((2.001, self.core), (0, {})):
            bridge.client.reset_mock()
            with patch("bridge.time.monotonic", return_value=100 + elapsed):
                bridge.update_modules(core)
            bridge.client.publish.assert_called_once_with(
                "ruview/home/node2/modules/availability", "offline", qos=1, retain=True
            )

    def test_unavailable_worker_does_not_publish_an_empty_observation(self):
        bridge = self.publication_bridge()
        bridge.module_snapshot = ({}, 0)
        bridge.update_modules(self.core)
        bridge.client.publish.assert_called_once_with(
            "ruview/home/node2/modules/availability", "offline", qos=1, retain=True
        )

    def test_slow_json_and_decode_do_not_renew_receipt(self):
        bridge = self.publication_bridge()
        bridge.stopped = Mock()
        bridge.stopped.is_set.side_effect = [False, True]
        raw = json.dumps(self.payload).encode()
        clock = [100.0]
        original_loads, original_decode = json.loads, modules.decode

        def slow_loads(value, **kwargs):
            clock[0] += 0.6
            return original_loads(value, **kwargs)

        def slow_decode(value, received_wall_ns):
            clock[0] += 1.351
            return original_decode(value, received_wall_ns)

        with (
            patch("bridge.urllib.request.build_opener") as opener,
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "bridge.time.time_ns",
                side_effect=lambda: self.now + round((clock[0] - 100) * 1e9),
            ),
            patch("bridge.json.loads", side_effect=slow_loads),
            patch("bridge.module_observations.decode", side_effect=slow_decode),
        ):
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = raw
            response.headers.get.return_value = None
            bridge.listen_modules()
            self.assertEqual(bridge.module_snapshot[1], 100)
            bridge.update_modules(self.core)
        attrs = json.loads(bridge.client.publish.call_args_list[0].args[1])[
            "attributes"
        ]
        self.assertEqual(attrs["snapshot_age_ms"], 1951)
        self.assertEqual(attrs["worker_csi_age_ms"], 1971)
        event = attrs["events"][0]
        self.assertEqual(event["age_ms"], 2001)
        self.assertFalse(event["fresh"])
        self.assertEqual(
            event["observed_at_ns"], self.payload["events"][0]["observed_at_ns"]
        )
        bridge.client.reset_mock()
        with patch("bridge.time.monotonic", return_value=102.001):
            bridge.update_modules(self.core)
        bridge.client.publish.assert_called_once_with(
            "ruview/home/node2/modules/availability", "offline", qos=1, retain=True
        )

    def test_slow_preparation_and_three_publications_keep_one_age_reference(self):
        original_node, original_event = (
            self.payload["nodes"][0],
            self.payload["events"][0],
        )
        self.payload["nodes"] = [
            {**copy.deepcopy(original_node), "node_id": node} for node in (1, 2, 3)
        ]
        self.payload["events"] = [
            {**copy.deepcopy(original_event), "node_id": node} for node in (1, 2, 3)
        ]
        bridge = self.publication_bridge()
        bridge.known = {1, 2, 3}
        core = {node: dict(self.core[2]) for node in bridge.known}
        original_core = copy.deepcopy(core)
        clock = [101.8]
        deliveries = []
        original_current = modules.current

        def slow_current(*args):
            result = original_current(*args)
            clock[0] += 0.4
            return result

        def slow_publish(topic, payload, **kwargs):
            clock[0] += 0.4
            if topic.endswith("/observation"):
                deliveries.append(
                    (json.loads(payload), self.now + round((clock[0] - 100) * 1e9))
                )
            return Mock(rc=0)

        bridge.client.publish.side_effect = slow_publish
        with (
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "bridge.time.time_ns",
                side_effect=lambda: self.now + round((clock[0] - 100) * 1e9),
            ),
            patch("bridge.module_observations.current", side_effect=slow_current),
        ):
            bridge.update_modules(core)
        self.assertEqual(
            [item[0]["attributes"]["node_id"] for item in deliveries],
            list(bridge.known),
        )
        self.assertEqual(core, original_core)
        for envelope, delivered_ns in deliveries:
            attrs = envelope["attributes"]
            event = attrs["events"][0]
            self.assertEqual(attrs["published_at_ns"], str(self.now + 1_800_000_000))
            self.assertEqual(attrs["snapshot_age_ms"], 1800)
            self.assertEqual(event["age_ms"], 1850)
            self.assertTrue(event["fresh"])  # Fresh only at the declared reference.
            transit_ms = (delivered_ns - int(attrs["published_at_ns"])) / 1e6
            self.assertGreater(event["age_ms"] + transit_ms, 2000)
            self.assertAlmostEqual(
                event["age_ms"] + transit_ms,
                (delivered_ns - int(event["observed_at_ns"])) / 1e6,
            )
            self.assertEqual(event["occurrence_seq"], original_event["occurrence_seq"])

    def test_module_lease_publishes_before_slow_ordinary_work(self):
        bridge = self.publication_bridge()
        bridge.last_primary_update = None
        clock = [100.25]
        original_core = copy.deepcopy(self.core)
        ordinary_calls = []

        def ordinary(current, observed_at):
            self.assertEqual(observed_at, 100)
            ordinary_calls.append(copy.deepcopy(current))
            self.assertEqual(bridge.client.publish.call_count, 2)
            clock[0] += 1.7

        bridge.update = Mock(side_effect=ordinary)
        with (
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "bridge.time.time_ns",
                side_effect=lambda: self.now + round((clock[0] - 100) * 1e9),
            ),
        ):
            # Parsing already took 250ms. The next 1.7s of ordinary work must not
            # delay this fresh module envelope until its core lease has expired.
            bridge.update_observations(self.core, observed_at=100)
        self.assertEqual(ordinary_calls, [original_core])
        self.assertEqual(self.core, original_core)
        self.assertEqual(bridge.last_primary_update, 100.25)
        attrs = json.loads(bridge.client.publish.call_args_list[0].args[1])[
            "attributes"
        ]
        self.assertEqual(attrs["published_at_ns"], str(self.now + 250_000_000))
        self.assertEqual(attrs["snapshot_age_ms"], 250)
        self.assertEqual(attrs["csi_age_ms"], 350)
        self.assertEqual(attrs["inference_age_ms"], 370)
        self.assertEqual(attrs["worker_csi_age_ms"], 270)
        self.assertEqual(attrs["events"][0]["age_ms"], 300)
        self.assertEqual(
            attrs["events"][0]["observed_at_ns"],
            self.payload["events"][0]["observed_at_ns"],
        )
        self.assertTrue(attrs["events"][0]["fresh"])
        # The original source clocks still govern expiry after that work.
        bridge.client.reset_mock()
        with patch("bridge.time.monotonic", return_value=clock[0]):
            bridge.update_modules(self.core, core_observed_at=100)
        bridge.client.publish.assert_called_once_with(
            "ruview/home/node2/modules/availability", "offline", qos=1, retain=True
        )

    def test_failed_worker_request_withdraws_previous_cache(self):
        for failed_read in (OSError("unavailable"), b"not-json"):
            bridge = self.publication_bridge()
            bridge.stopped = Mock()
            bridge.stopped.is_set.side_effect = [False, True]
            with patch("bridge.urllib.request.build_opener") as opener:
                opener.return_value.open.return_value.__enter__.return_value.headers.get.return_value = None
                read = opener.return_value.open.return_value.__enter__.return_value.read
                if isinstance(failed_read, Exception):
                    read.side_effect = failed_read
                else:
                    read.return_value = failed_read
                with self.assertLogs(level="WARNING"):
                    bridge.listen_modules()
            self.assertEqual(bridge.module_snapshot, ({}, 0))
            bridge.update_modules(self.core)
            bridge.client.publish.assert_called_once_with(
                "ruview/home/node2/modules/availability", "offline", qos=1, retain=True
            )

    def test_worker_poll_cadence_subtracts_reads_and_skips_overrun(self):
        bridge = self.publication_bridge()
        bridge.stopped = threading.Event()
        raw = json.dumps(self.payload).encode()
        clock = [100.0]
        starts = []
        waits = []
        durations = iter((0.1, 0.8, 0.1))

        def read(_):
            starts.append(clock[0])
            clock[0] += next(durations)
            return raw

        def wait(timeout):
            waits.append(timeout)
            clock[0] += timeout
            if len(waits) == 3:
                bridge.stopped.set()

        with (
            patch("bridge.urllib.request.build_opener") as opener,
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "bridge.time.time_ns",
                side_effect=lambda: self.now + round((clock[0] - 100) * 1e9),
            ),
            patch.object(bridge.stopped, "wait", side_effect=wait),
        ):
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.side_effect = read
            response.headers.get.return_value = None
            bridge.listen_modules()
        self.assertEqual(starts, [100.0, 100.5, 101.5])
        self.assertEqual(bridge.module_snapshot[1], 101.6)
        self.assertEqual(
            bridge.module_snapshot[0][2]["snapshot_generated_at_ns"], str(self.now)
        )
        for actual, expected in zip(waits, (0.4, 0.2, 0.4), strict=True):
            self.assertAlmostEqual(actual, expected)

    def test_truncated_http_response_withdraws_cache_then_polling_recovers(self):
        bridge = self.publication_bridge()
        bridge.stopped = threading.Event()
        clock = [100.0]
        snapshots = []

        def wait(timeout):
            snapshots.append(bridge.module_snapshot)
            clock[0] += timeout
            if len(snapshots) == 2:
                bridge.stopped.set()

        with (
            patch("bridge.urllib.request.build_opener") as opener,
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch("bridge.time.time_ns", return_value=self.now),
            patch.object(bridge.stopped, "wait", side_effect=wait),
            self.assertLogs(level="WARNING") as logs,
        ):
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.side_effect = [
                http.client.IncompleteRead(b"private response", 100),
                json.dumps(self.payload).encode(),
            ]
            response.headers.get.return_value = None
            bridge.listen_modules()
        self.assertEqual(snapshots[0], ({}, 0))
        self.assertEqual(snapshots[1], (self.decoded(), 100.5))
        self.assertEqual(
            logs.output,
            ["WARNING:root:Module diagnostics unavailable (IncompleteRead)"],
        )

    def test_gzip_decode_does_not_renew_receipt(self):
        from ruview_http import decode_http_body

        bridge = self.publication_bridge()
        bridge.stopped = Mock()
        bridge.stopped.is_set.side_effect = [False, True]
        raw = json.dumps(self.payload).encode()
        clock = [100.0]

        def slow_inflate(*args):
            clock[0] += 0.5
            return decode_http_body(*args)

        with (
            patch("bridge.urllib.request.build_opener") as opener,
            patch("bridge.time.monotonic", side_effect=lambda: clock[0]),
            patch("bridge.time.time_ns", return_value=self.now),
            patch("bridge.decode_http_body", side_effect=slow_inflate),
        ):
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = gzip.compress(raw, mtime=0)
            response.headers.get.return_value = "gzip"
            bridge.listen_modules()
            self.assertEqual(bridge.module_snapshot[1], 100.0)
            self.assertEqual(bridge.module_snapshot[0], self.decoded())
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header("Accept-encoding"), "gzip")
            self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 2)

    def test_corrupt_gzip_withdraws_previous_cache(self):
        bridge = self.publication_bridge()
        bridge.stopped = Mock()
        bridge.stopped.is_set.side_effect = [False, True]
        with patch("bridge.urllib.request.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b"invalid gzip"
            response.headers.get.return_value = "gzip"
            with self.assertLogs(level="WARNING"):
                bridge.listen_modules()
        self.assertEqual(bridge.module_snapshot, ({}, 0))

    def test_future_core_anchor_cannot_reduce_age(self):
        bridge = self.publication_bridge()
        with patch("bridge.time.monotonic", return_value=100):
            with self.assertRaisesRegex(ValueError, "future"):
                bridge.update_modules(self.core, core_observed_at=101)
        bridge.client.publish.assert_not_called()

    def test_no_inferred_presence_or_position(self):
        node = modules.current(self.decoded(), 0, self.core)[2]
        for field in (
            "presence",
            "fall_detected",
            "position",
            "person_count",
            "posture",
        ):
            self.assertNotIn(field, node)


if __name__ == "__main__":
    unittest.main()
