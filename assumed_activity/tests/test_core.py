import copy
import json
import math
import unittest

from assumed_activity.core import Producer, centroid, configuration, digest
from assumed_activity.tests.helpers import BASE_NS, FIXTURES, config, inputs


class CoreTests(unittest.TestCase):
    def ready(self):
        producer = Producer(
            config(), expected_coordinate_frame=config()["coordinate_frame"]
        )
        for index in range(4):
            result = producer.update(*inputs(index))
        self.assertEqual(result["state"], "quiet")
        return producer

    def test_warmup_quiet_and_step_are_not_person_labels(self):
        producer = Producer(
            config(), expected_coordinate_frame=config()["coordinate_frame"]
        )
        first = producer.update(*inputs(0))
        self.assertEqual(first["state"], "warming_up")
        self.assertTrue(all(z["signal_score"] is None for z in first["zones"]))
        for index in range(1, 4):
            result = producer.update(*inputs(index))
        self.assertEqual(result["state"], "quiet")
        self.assertIn("not_empty", result["reason"])
        result = producer.update(*inputs(4, (10, 100, 10)))
        self.assertEqual(result["state"], "active")
        self.assertEqual(result["nodes"][1]["score"], 12)
        self.assertEqual(len(result["zones"]), 4)
        self.assertTrue(all(0 < z["signal_score"] < 12 for z in result["zones"]))
        self.assertFalse(result["recognition_validated"])
        self.assertFalse(result["supervised_training"])
        self.assertNotIn("persons", result)

    def test_known_geometry_weights_and_fixture(self):
        value = config(False)
        producer = Producer(
            value, expected_coordinate_frame=config()["coordinate_frame"]
        )
        self.assertEqual(
            producer.geometry_sha,
            "1dab31f1bf7f401cab441ed258453411e6eac94e9695ad45b0f55dfc02010655",
        )
        self.assertEqual(producer.config_sha, digest(value))
        self.assertEqual(producer.config_sha, digest(copy.deepcopy(value)))
        for weights in producer.weights.values():
            self.assertAlmostEqual(sum(weights.values()), 1)
            self.assertTrue(all(0 < w < 1 for w in weights.values()))
        self.assertGreater(
            producer.weights["lab_west"]["1"], producer.weights["lab_west"]["2"]
        )
        for index in range(32):
            producer.update(*inputs(index))
        result = producer.update(*inputs(32, (10, 100, 10)))
        fixture = json.loads((FIXTURES / "activity.synthetic.json").read_text())
        self.assertEqual(result, fixture)

    def test_no_renormalization_when_required_receiver_missing(self):
        producer = self.ready()
        health, worker, sensing, now, mono = inputs(4)
        sensing["node_features"].pop()
        result = producer.update(health, worker, sensing, now, mono)
        self.assertEqual(result["state"], "unknown")
        self.assertTrue(all(z["signal_score"] is None for z in result["zones"]))
        self.assertEqual(
            result["zones"][0]["receiver_weights"], producer.weights["lab_west"]
        )

    def test_fictional_rectangles_have_independent_analytic_weights(self):
        value = config(False)
        producer = Producer(value, expected_coordinate_frame="fictional_lab_xz_metres")
        # Hand-derived: radius^2 (16) plus squared distance to each centre.
        for zone, centre, denominators in zip(
            value["zones"],
            ([1, 3], [7, 3], [4, 6], [4, 3]),
            ((20, 56, 29), (56, 20, 29), (50, 50, 17), (29, 29, 20)),
            strict=True,
        ):
            self.assertEqual(centroid(zone["polygon_xz_m"]), centre)
            self.assertEqual(centroid(zone["polygon_xz_m"][::-1]), centre)
            inverse = [1 / d for d in denominators]
            for node, weight in enumerate(inverse, 1):
                self.assertAlmostEqual(
                    producer.weights[zone["zone_id"]][str(node)],
                    weight / sum(inverse),
                )

    def test_overlap_and_boundary_points_remain_weights_not_room_assignment(self):
        value = config(False)
        # A receiver on an edge is valid. Two distinct overlapping zones retain
        # their own results; the producer must not infer exclusive occupancy.
        value["receivers"][0]["position_xz_m"] = [0, 3]
        value["zones"][1]["polygon_xz_m"] = copy.deepcopy(
            value["zones"][0]["polygon_xz_m"]
        )
        producer = Producer(value, expected_coordinate_frame="fictional_lab_xz_metres")
        self.assertEqual(producer.weights["lab_west"], producer.weights["lab_east"])
        for index in range(32):
            producer.update(*inputs(index))
        result = producer.update(*inputs(32, (10, 100, 10)))
        self.assertEqual(
            result["zones"][0]["signal_score"], result["zones"][1]["signal_score"]
        )
        self.assertFalse(result["recognition_validated"])

    def test_repeated_snapshots_do_not_warm_or_refresh_signal(self):
        producer = Producer(
            config(), expected_coordinate_frame=config()["coordinate_frame"]
        )
        original = inputs(0)
        producer.update(*original)
        for _ in range(4):
            result = producer.update(*original)
            self.assertEqual(result["state"], "unknown")
        self.assertEqual(len(producer.history[1]["samples"]), 1)

    def test_bad_or_stale_inputs_fail_closed(self):
        mutations = [
            lambda h, w, s: h.update(status="stalled"),
            lambda h, w, s: w.update(generated_at_ns=str(BASE_NS)),
            lambda h, w, s: w.update(generated_at_ns=str(BASE_NS + 10**12)),
            lambda h, w, s: s.update(timestamp=math.nan),
            lambda h, w, s: w["nodes"][0]["grid"].update(flags=20),
            lambda h, w, s: w["nodes"][0]["grid"].update(antennas=True),
            lambda h, w, s: w["nodes"][0].update(fresh=False),
            lambda h, w, s: w["nodes"][0].update(node_epoch=True),
            lambda h, w, s: w["nodes"][0].update(age_ms=9999),
            lambda h, w, s: s["node_features"][0].update(stale=True),
            lambda h, w, s: s["node_features"][0]["features"].update(variance=-1),
            lambda h, w, s: s["node_features"][0]["features"].update(variance=True),
            lambda h, w, s: w["nodes"].append(copy.deepcopy(w["nodes"][0])),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                producer = self.ready()
                h, w, s, now, mono = inputs(4)
                mutation(h, w, s)
                result = producer.update(h, w, s, now, mono)
                self.assertEqual(result["state"], "unknown")

    def test_source_identity_and_epoch_reset(self):
        mutations = [
            lambda w: w.update(worker_run_id="another-run"),
            lambda w: w.update(configuration_sha256="b" * 64),
            lambda w: w.update(clock_id="another-clock"),
            lambda w: w["nodes"][0].update(node_epoch=2),
            lambda w: w["nodes"][0]["grid"].update(frequency_mhz=2437),
            lambda w: w["nodes"][0].update(sequence=1),
        ]
        for mutation in mutations:
            producer = self.ready()
            h, w, s, now, mono = inputs(4)
            mutation(w)
            result = producer.update(h, w, s, now, mono)
            self.assertEqual(result["state"], "warming_up")
        producer = self.ready()
        self.assertEqual(producer.update(*inputs(20))["state"], "warming_up")

    def test_expiry_preserves_original_timestamp_and_deadline(self):
        producer = self.ready()
        original = producer.snapshot(BASE_NS + 3 * 10**9, 3)
        expired = producer.snapshot(BASE_NS + 9 * 10**9, 9)
        self.assertEqual(expired["state"], "unknown")
        for key in ("generated_at_ns", "expires_at_ns"):
            self.assertEqual(original[key], expired[key])
        self.assertEqual(producer.snapshot(BASE_NS + 3 * 10**9, 1)["state"], "unknown")
        self.assertEqual(producer.snapshot(BASE_NS, 3)["state"], "unknown")

    def test_short_forward_gap_preserves_ambient_but_not_hidden_reboot(self):
        for reason in ("sequence_gap", "bounded_history_renewal"):
            producer = self.ready()
            h, w, s, now, mono = inputs(4)
            w["nodes"][0].update(node_epoch=4, epoch_reason=reason)
            result = producer.update(h, w, s, now, mono)
            self.assertEqual(result["state"], "quiet")
            self.assertEqual(result["nodes"][0]["node_epoch"], 4)
            h, w, s, now, mono = inputs(5)
            w["nodes"][0].update(
                node_epoch=6, epoch_reason=reason, sequence_discontinuities=1
            )
            self.assertEqual(producer.update(h, w, s, now, mono)["state"], "warming_up")

    def test_oldest_source_bounds_original_expiry(self):
        producer = self.ready()
        h, w, s, now, mono = inputs(4)
        w["nodes"][1]["last_received_at_ns"] = str(now - 2_000_000_000)
        result = producer.update(h, w, s, now, mono)
        self.assertEqual(result["oldest_source_at_ns"], str(now - 2_000_000_000))
        self.assertEqual(int(result["expires_at_ns"]) - now, 3_000_000_000)
        self.assertEqual(
            producer.snapshot(now + 3_000_000_000, mono + 3)["state"], "unknown"
        )

    def test_rolling_window_and_ambient_adaptation(self):
        value = config()
        value["policy"]["baseline_seconds"] = 4
        producer = Producer(
            value, expected_coordinate_frame=config()["coordinate_frame"]
        )
        for i in range(10):
            result = producer.update(*inputs(i, (100, 100, 100)))
        self.assertEqual(result["state"], "quiet")
        self.assertLessEqual(len(producer.history[1]["samples"]), 5)

    def test_config_rejects_bad_geometry_and_policy(self):
        for mutate in (
            lambda c: c.update(geometry_assumed=False),
            lambda c: c["policy"].update(max_score=math.inf),
            lambda c: c["policy"].update(unknown_option=1),
            lambda c: c["receivers"].append(c["receivers"][0]),
            lambda c: c["zones"][0].update(polygon_xz_m=[[0, 0], [1, 1], [2, 2]]),
            lambda c: c["zones"][0].update(zone_id="../unsafe"),
        ):
            value = config()
            mutate(value)
            with self.assertRaises(ValueError):
                configuration(
                    value, expected_coordinate_frame=config()["coordinate_frame"]
                )


if __name__ == "__main__":
    unittest.main()
