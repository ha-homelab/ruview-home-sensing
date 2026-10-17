import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from bridge import Bridge, discovery, node_placements


class RecordingClient:
    def __init__(self):
        self.messages = {}

    def publish(self, topic, payload, **_):
        self.messages[topic] = payload
        return SimpleNamespace(rc=0)


class PlacementTests(unittest.TestCase):
    def bridge(self, config):
        client = RecordingClient()
        with patch.dict(
            os.environ,
            {
                "RUVIEW_API_TOKEN": "test-token",
                "RUVIEW_NODE_IDS": "2",
                "RUVIEW_NODE_PLACEMENTS": json.dumps(config),
            },
        ):
            bridge = Bridge(client)
        return bridge, client.messages

    def test_workbench_blocks_room_entities_while_retaining_diagnostics(self):
        bridge, messages = self.bridge(
            {
                "2": {
                    "valid": False,
                    "measurement_location": "operator_usb_workbench",
                    "configured_room": "K",
                }
            }
        )
        bridge.update(
            {
                2: {
                    "presence": "ON",
                    "motion": "ON",
                    "signal": -64,
                    "classification": "present_moving",
                    "csi_age_ms": 40,
                }
            }
        )
        base = "ruview/home/node2"
        self.assertEqual(messages[base + "/availability"], "online")
        self.assertEqual(messages[base + "/placement/availability"], "offline")
        attributes = json.loads(messages[base + "/attributes"])
        self.assertFalse(attributes["placement_valid"])
        self.assertIsNone(attributes["room_id"])
        self.assertEqual(attributes["configured_room"], "K")
        for key in ("presence", "motion", "fall_detected", "signal", "classification"):
            _, config = discovery(2, key)
            topics = {entry["topic"] for entry in config["availability"]}
            self.assertEqual(
                base + "/placement/availability" in topics,
                key in ("presence", "motion", "fall_detected"),
            )

    def test_unknown_node_fails_closed_and_valid_placement_does_not_bypass_stale_csi(
        self,
    ):
        for config, expected in (
            ({}, "offline"),
            (
                {
                    "2": {
                        "valid": True,
                        "measurement_location": "configured_room",
                        "configured_room": "K",
                    }
                },
                "online",
            ),
        ):
            bridge, messages = self.bridge(config)
            bridge.update({})
            self.assertEqual(
                messages["ruview/home/node2/placement/availability"], expected
            )
            self.assertEqual(messages["ruview/home/node2/availability"], "offline")
            self.assertEqual(messages["ruview/home/node2/fall/availability"], "offline")

    def test_configuration_requires_explicit_boolean_and_room(self):
        for invalid in (
            [],
            {"2": {"valid": "false"}},
            {
                "2": {
                    "valid": True,
                    "measurement_location": "configured_room",
                }
            },
            {"256": {"valid": False}},
        ):
            with self.assertRaises(ValueError):
                node_placements(json.dumps(invalid))


if __name__ == "__main__":
    unittest.main()
