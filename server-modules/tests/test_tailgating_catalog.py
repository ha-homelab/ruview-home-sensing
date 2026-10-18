"""Offline release/patch contracts; native behavior is tested by Rust."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tailgate_prepare", ROOT / "prepare.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class TailgatingCatalogTests(unittest.TestCase):
    def test_next_selection_requires_twenty_hz_and_labels_peaks_not_people(self):
        entries = json.loads((ROOT / "algorithms.json").read_text())
        catalog = {entry["algorithm"]: entry for entry in entries}
        self.assertEqual(len(catalog), 64)
        self.assertEqual(sum(entry["selected"] for entry in entries), 21)
        tailgate = catalog["sec_tailgating"]
        self.assertTrue(tailgate["selected"])
        self.assertEqual(tailgate["algorithm_version"], "0.3.0+home-server.2")
        self.assertEqual(tailgate["required_cadence_hz"], 20)
        self.assertEqual(set(tailgate["events"]), {"230", "231", "232"})
        for event_id in ("230", "232"):
            event = tailgate["events"][event_id]
            self.assertEqual(event["units"], "motion_peaks")
            self.assertIn("not", event["meaning"])
        self.assertEqual(tailgate["events"]["231"]["units"], "phase_variance_proxy")
        self.assertIn("same cluster", tailgate["events"]["232"]["meaning"])
        self.assertFalse(catalog["bld_elevator_count"]["selected"])
        self.assertIn("cabin_baseline", catalog["bld_elevator_count"]["reason"])
        self.assertFalse(catalog["lrn_ewc_lifelong"]["selected"])
        self.assertIn("target_zone_labels", catalog["lrn_ewc_lifelong"]["reason"])

    def test_patch_is_pinned_in_the_worker_input_fingerprint(self):
        inputs = prepare.worker_inputs()
        self.assertEqual(len(prepare.WORKER_PATCHES), 1)
        for name, expected in prepare.WORKER_PATCHES.items():
            self.assertEqual(
                prepare.sha((ROOT / "patches" / name).read_bytes()), expected
            )
            self.assertEqual(inputs["patches/" + name], expected)

    def test_tampered_patch_fails_before_any_git_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "patches").mkdir()
            name = next(iter(prepare.WORKER_PATCHES))
            (root / "patches" / name).write_bytes(b"unreviewed patch")
            with (
                patch.object(prepare, "HERE", root),
                patch.object(prepare.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(
                    ValueError, "Unreviewed worker module patch"
                ):
                    prepare.apply_worker_patches(root)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
