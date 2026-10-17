"""Independent acceptance of exported print artifacts, without physical-fit claims."""

import hashlib
import json
import sys
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path

import cadquery as cq
import numpy as np
import trimesh

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from model import Parameters  # noqa: E402


class PrintArtifacts(unittest.TestCase):
    def test_bundles_contain_exact_verified_print_files(self):
        for nominal in (50, 80, 100):
            name = f"pigtail-{nominal}"
            directory = ROOT / "generated" / name
            with zipfile.ZipFile(directory / "print-pack.zip") as bundle:
                self.assertEqual(len(bundle.namelist()), 11)
                for path in list(directory.glob("*.stl")) + [
                    directory / "assembly.step",
                    directory / "validation.json",
                ]:
                    self.assertEqual(
                        bundle.read(f"{name}/{path.name}"), path.read_bytes()
                    )
                self.assertIn(
                    b"FIRST-FIT PROTOTYPE", bundle.read(f"{name}/READ-FIRST.txt")
                )
                self.assertIn(
                    b"https://github.com/ha-homelab/ruview-home-sensing/blob/"
                    b"main/mechanical/enclosure/README.md",
                    bundle.read(f"{name}/READ-FIRST.txt"),
                )

    def test_all_three_profiles_have_closed_consistent_print_files(self):
        for nominal in (50, 80, 100):
            directory = ROOT / "generated" / f"pigtail-{nominal}"
            report = json.loads((directory / "validation.json").read_text())
            self.assertFalse(report["physical_fit_verified"])
            self.assertEqual(len(report["parts"]), 8)
            self.assertEqual(
                report["source_sha256"],
                hashlib.sha256((ROOT / "model.py").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                report["profile_sha256"],
                hashlib.sha256(
                    (ROOT / "profiles" / f"pigtail-{nominal}.json").read_bytes()
                ).hexdigest(),
            )
            for name, recorded in report["parts"].items():
                with self.subTest(profile=nominal, part=name):
                    stl = directory / f"{name}.stl"
                    mesh = trimesh.load_mesh(stl)
                    self.assertTrue(mesh.is_watertight)
                    self.assertTrue(mesh.is_winding_consistent)
                    self.assertEqual(mesh.body_count, 1)
                    self.assertGreater(mesh.volume, 0)
                    self.assertAlmostEqual(float(mesh.bounds[0, 2]), 0, places=4)
                    self.assertEqual(
                        hashlib.sha256(stl.read_bytes()).hexdigest(),
                        recorded["stl_sha256"],
                    )
                    np.testing.assert_allclose(
                        mesh.extents, recorded["bounds_mm"], atol=0.002
                    )
                    solid = cq.importers.importStep(str(directory / f"{name}.step"))
                    self.assertEqual(len(solid.solids().vals()), 1)
                    self.assertTrue(solid.val().isValid())
                    # Chordal tessellation may differ slightly from curved CAD volume.
                    self.assertLess(
                        abs(solid.val().Volume() - mesh.volume) / mesh.volume, 0.005
                    )

    def test_assembly_has_only_printed_parts_and_reference_pcb(self):
        for nominal in (50, 80, 100):
            directory = ROOT / "generated" / f"pigtail-{nominal}"
            assembly = cq.importers.importStep(str(directory / "assembly.step"))
            self.assertEqual(len(assembly.solids().vals()), 5)
            report = json.loads((directory / "validation.json").read_text())
            self.assertEqual(len(report["collision_volume_mm3"]), 10)
            self.assertTrue(
                all(abs(v) < 0.00001 for v in report["collision_volume_mm3"].values())
            )

    def test_printed_envelopes_match_variants(self):
        for nominal, length in ((50, 90), (80, 105), (100, 115)):
            directory = ROOT / "generated" / f"pigtail-{nominal}"
            base = trimesh.load_mesh(directory / "base.stl")
            wall = trimesh.load_mesh(directory / "base-wall.stl")
            np.testing.assert_allclose(base.extents, (length, 58, 24), atol=0.002)
            np.testing.assert_allclose(wall.extents, (length, 68, 24), atol=0.002)

    def test_unsafe_parameter_combinations_are_rejected(self):
        p = Parameters(**json.loads((ROOT / "profiles/pigtail-80.json").read_text()))
        p.validate()
        for change in (
            {"board_width": 50},
            {"sma_hole": 12},
            {"fit_clearance": -0.2},
            {"height": 12},
            {"length": 85, "board_length": 68},
            {"height": 22, "board_clearance_below": 5},
            {"screw_pilot": float("nan")},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(p, **change).validate()


if __name__ == "__main__":
    unittest.main()
