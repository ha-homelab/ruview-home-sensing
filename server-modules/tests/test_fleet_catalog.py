"""Offline catalog compatibility checks; native behavior is tested in Rust."""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FleetCatalogTests(unittest.TestCase):
    def test_fleet_selection_does_not_change_the_per_node_catalog(self):
        catalog = json.loads((ROOT / "algorithms.json").read_text())
        self.assertEqual(len(catalog), 64)
        self.assertEqual(len({entry["algorithm"] for entry in catalog}), 64)
        self.assertEqual(sum(entry["selected"] for entry in catalog), 21)
        selected = [entry for entry in catalog if entry.get("fleet_selected")]
        self.assertEqual(len(selected), 1)
        fleet = selected[0]
        self.assertEqual(fleet["algorithm"], "aut_self_healing_mesh")
        self.assertEqual(fleet["algorithm_version"], "0.3.0+home-fleet.1")
        self.assertFalse(fleet["selected"])
        self.assertEqual(fleet["execution_scope"], "fleet")
        self.assertEqual(fleet["reason"], "evaluated_only_in_fleet_scope")
        self.assertEqual(fleet["events"], {})
        self.assertEqual(set(fleet["fleet_events"]), {"885", "886", "887", "888"})
        for event in fleet["fleet_events"].values():
            for field in ("event_name", "value_type", "units", "meaning"):
                self.assertIsInstance(event[field], str)
                self.assertTrue(event[field].strip())
        self.assertIn("not physical", fleet["fleet_events"]["887"]["meaning"])
        self.assertIn("no routing", fleet["fleet_events"]["886"]["meaning"])
        self.assertIn("not evidence", fleet["fleet_events"]["888"]["meaning"])

    def test_fleet_source_and_tests_are_fingerprinted_without_release_evidence(self):
        spec = importlib.util.spec_from_file_location(
            "fleet_prepare", ROOT / "prepare.py"
        )
        prepare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prepare)
        inputs = prepare.worker_inputs()
        self.assertIn("src/fleet.rs", inputs)
        self.assertIn("tests/test_fleet_catalog.py", inputs)
        self.assertFalse(any("release-evidence" in name for name in inputs))


if __name__ == "__main__":
    unittest.main()
