import copy
import datetime as dt
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from assumed_activity.shadow_legacy import extract

BASE = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)


def utc(seconds):
    return (BASE + dt.timedelta(seconds=seconds)).isoformat()


def state(entity, value="off"):
    return {
        "entity_id": entity,
        "state": value,
        "available": value in ("on", "off"),
        "last_updated": utc(0),
    }


def event(kind, seconds, **fields):
    return {
        "kind": kind,
        "run_id": "run-a",
        "received_at_utc": utc(seconds),
        "received_monotonic_ns": 1_000_000_000 + int(seconds * 1e9),
        **fields,
    }


def baseline(seconds=0, first="off", second="off", generation=1):
    return event(
        "ha_baseline",
        seconds,
        generation=generation,
        states=[
            state("binary_sensor.reference_a", first),
            state("binary_sensor.reference_b", second),
        ],
    )


def sample(seconds=5, age=20):
    return event(
        "ruview_sample",
        seconds,
        endpoint="nodes",
        data={
            "nodes": [
                {
                    "node_id": 1,
                    "rssi_dbm": -40,
                    "csi_status": "active",
                    "csi_last_seen_ms": age,
                },
                {
                    "node_id": 2,
                    "rssi_dbm": -60,
                    "csi_status": "active",
                    "csi_last_seen_ms": age,
                },
            ]
        },
    )


def confirmation(seconds=6, generation=1):
    return event(
        "ha_state_changed",
        seconds,
        generation=generation,
        entity_id="sensor.unrelated",
        new={"state": "active"},
    )


class ShadowLegacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.segment = self.root / "segment-001"
        self.segment.mkdir()
        (self.segment / "metadata.json").write_text(json.dumps({"run_id": "run-a"}))
        self.config = {
            "start_utc": utc(0),
            "end_utc": utc(60),
            "final_holdout_start_utc": utc(3600),
            "node_ids": [1, 2],
            "references": [
                {
                    "entity_id": "binary_sensor.reference_a",
                    "source_group": "source_a",
                    "derived_from_ruview": False,
                },
                {
                    "entity_id": "binary_sensor.reference_b",
                    "source_group": "source_b",
                    "derived_from_ruview": False,
                },
            ],
            "feature_contract": {
                "name": "legacy-rssi",
                "version": 1,
                "features": ["node_1_rssi_dbm", "node_2_rssi_dbm"],
                "identity": {"profile": "one"},
            },
            "exclusions": [],
        }

    def write(self, rows, tail=b""):
        raw = b"".join((json.dumps(x) + "\n").encode() for x in rows) + tail
        (self.segment / "events-0000.jsonl").write_bytes(raw)
        return raw

    def test_confirmed_off_is_sensor_state_not_empty_label(self):
        raw = self.write([baseline(), sample(), confirmation()])
        rows, receipt = extract(self.root, self.config)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["features"], {"node_1_rssi_dbm": -40, "node_2_rssi_dbm": -60}
        )
        self.assertEqual([r["state"] for r in rows[0]["references"]], ["off", "off"])
        self.assertFalse(rows[0]["provenance"]["native_profile_qualified"])
        self.assertEqual(
            receipt["prefixes"][0]["prefix_sha256"], hashlib.sha256(raw).hexdigest()
        )

    def test_initial_on_is_state_target_without_fake_onset(self):
        self.write([baseline(first="on"), sample(), confirmation()])
        rows, _ = extract(self.root, self.config)
        self.assertEqual(rows[0]["references"][0]["state"], "on")
        self.assertNotIn("onset", rows[0])

    def test_unconfirmed_tail_gap_and_generation_change_abstain(self):
        endings = [
            [],
            [event("ha_gap", 6)],
            [confirmation(generation=2)],
            [confirmation(seconds=15)],
        ]
        for end in endings:
            with self.subTest(ending=end):
                self.write([baseline(), sample(), *end])
                rows, receipt = extract(self.root, self.config)
                self.assertEqual(rows, [])
                self.assertGreater(receipt["discarded"]["unconfirmed_transport"], 0)

    def test_reconnect_uses_new_baseline_only(self):
        self.write(
            [
                baseline(),
                sample(),
                event("ha_gap", 6),
                baseline(7, "on", generation=2),
                sample(8),
                confirmation(9, 2),
            ]
        )
        rows, _ = extract(self.root, self.config)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["provenance"]["reference_generation"], 2)

    def test_unknown_reference_and_stale_csi_are_not_zero_imputed(self):
        for first, age in [("unavailable", 20), ("off", 1501), ("off", True)]:
            with self.subTest(first=first, age=age):
                self.write([baseline(first=first), sample(age=age), confirmation()])
                rows, _ = extract(self.root, self.config)
                self.assertEqual(rows, [])

    def test_exclusion_and_reserved_boundaries(self):
        self.config["exclusions"] = [{"start_utc": utc(4), "end_utc": utc(6)}]
        self.write([baseline(), sample(), confirmation(), sample(60), confirmation(61)])
        rows, receipt = extract(self.root, self.config)
        self.assertEqual(rows, [])
        self.assertEqual(receipt["discarded"]["maintenance"], 1)

    def test_clock_jump_requires_review(self):
        self.write([baseline(), sample(), event("clock_step", 6)])
        with self.assertRaisesRegex(ValueError, "clock_step_requires_review"):
            extract(self.root, self.config)

    def test_duplicate_node_rows_fail_closed(self):
        s = sample()
        s["data"]["nodes"].append(copy.deepcopy(s["data"]["nodes"][0]))
        self.write([baseline(), s, confirmation()])
        with self.assertRaisesRegex(ValueError, "duplicate_node_rows"):
            extract(self.root, self.config)

    def test_unfinished_tail_never_becomes_example(self):
        raw = self.write(
            [baseline(), sample(), confirmation()], b'{"kind":"ruview_sample"'
        )
        rows, receipt = extract(self.root, self.config)
        self.assertEqual(len(rows), 1)
        self.assertEqual(receipt["discarded"]["unfinished_tail"], 1)
        self.assertLess(receipt["prefixes"][0]["prefix_bytes"], len(raw))

    def test_derived_reference_aliases_and_duplicate_nodes_rejected(self):
        self.write([baseline(), sample(), confirmation()])
        configurations = []
        c = copy.deepcopy(self.config)
        c["references"][0]["derived_from_ruview"] = True
        configurations.append(c)
        c = copy.deepcopy(self.config)
        c["references"][1]["source_group"] = "source_a"
        configurations.append(c)
        c = copy.deepcopy(self.config)
        c["node_ids"] = [1, 1]
        configurations.append(c)
        for config in configurations:
            with self.subTest(config=config), self.assertRaises(ValueError):
                extract(self.root, config)

    def test_metadata_symlink_rejected(self):
        self.write([baseline(), sample(), confirmation()])
        path = self.segment / "metadata.json"
        path.rename(self.root / "source.json")
        path.symlink_to(self.root / "source.json")
        with self.assertRaisesRegex(ValueError, "unsafe_capture_metadata"):
            extract(self.root, self.config)

    def test_freshness_limits_must_be_finite_and_bounded(self):
        self.write([baseline(), sample(), confirmation()])
        for key, value in [
            ("max_transport_bracket_seconds", float("inf")),
            ("max_transport_bracket_seconds", 61),
            ("max_csi_age_ms", 0),
            ("max_csi_age_ms", True),
        ]:
            config = copy.deepcopy(self.config)
            config[key] = value
            with (
                self.subTest(key=key, value=value),
                self.assertRaisesRegex(ValueError, "invalid_"),
            ):
                extract(self.root, config)


if __name__ == "__main__":
    unittest.main()
