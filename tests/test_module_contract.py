import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from module_manifest_fixture import catalog
from module_package_fixture import DIRECTORY

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "module_contract", ROOT / "firmware/validate-module-contract.py"
)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class ModuleContractTests(unittest.TestCase):
    def setUp(self):
        self.manifest = catalog()
        self.manifest["packages"] = self.manifest["packages"][:1]
        self.catalog = json.loads((ROOT / "config/plugin-catalog.json").read_text())
        self.sources = {m["name"]: m["event_ids"] for m in self.catalog["modules"]}
        self.package = self.manifest["packages"][0]

    def validate(self):
        return contract.validate_contracts(
            self.manifest, self.catalog, ROOT / "tests/fixtures/modules"
        )

    def test_repository_signed_artifact_has_exact_reviewed_contract(self):
        report = self.validate()
        self.assertTrue(report["structural_validation_passed"])
        self.assertEqual(report["packages"][0]["event_map"], self.package["event_map"])
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["actual_emit_behavior_verified"])
        self.assertFalse(report["runtime_or_accuracy_qualified"])

    def test_explicit_synthetic_selection_is_structural_only(self):
        manifest = catalog()
        report = contract.validate_contracts(manifest, self.catalog, DIRECTORY)
        self.assertTrue(report["structural_validation_passed"])
        self.assertFalse(report["runtime_or_accuracy_qualified"])
        self.assertTrue(
            all(p["mapping_evidence"] == "declaration_only" for p in report["packages"])
        )

    def test_incomplete_or_conflicting_event_declarations_are_rejected(self):
        for change in (
            {"algorithms": ["intrusion"]},
            {"package_event_ids": []},
            {"wire_event_ids": [1, 2, 3, 11]},
            {
                "event_map": [
                    dict(r, wire_event_id=r["wire_event_id"] + 16)
                    for r in self.package["event_map"]
                ]
            },
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.validate_event_map(dict(self.package, **change), self.sources)

    def test_new_binary_requires_explicit_mapping_even_for_byte_ids(self):
        self.package["wasm_sha256"] = "0" * 64
        self.package["name"] = "new-signal"
        self.package.pop("event_map")
        with self.assertRaisesRegex(ValueError, "Explicit event_map"):
            contract.validate_event_map(self.package, self.sources)

    def occupancy(self):
        return {
            "name": "occupancy-example-not-built",
            "wasm_sha256": "0" * 64,
            "algorithms": ["occupancy"],
            "wire_event_ids": [16, 17, 18],
            "event_map": [
                {"algorithm": "occupancy", "event_id": event, "wire_event_id": wire}
                for event, wire in [(300, 16), (301, 17), (302, 18)]
            ],
        }

    def test_wide_source_ids_require_reversible_byte_mapping(self):
        package = self.occupancy()
        mapping, evidence = contract.validate_event_map(package, self.sources)
        self.assertEqual(mapping, package["event_map"])
        self.assertEqual(evidence, "declaration_only")
        package["event_map"][0]["wire_event_id"] = 300
        with self.assertRaisesRegex(ValueError, "wire event ID"):
            contract.validate_event_map(package, self.sources)

    def test_unknown_missing_duplicate_and_boolean_ids_fail_closed(self):
        mutations = [
            lambda p: p["event_map"].pop(),
            lambda p: p["event_map"].append(p["event_map"][0]),
            lambda p: p["event_map"][0].update(event_id=999),
            lambda p: p["event_map"][0].update(algorithm="unknown"),
            lambda p: p["event_map"][0].update(wire_event_id=True),
            lambda p: p["event_map"][0].update(wire_event_id=-1),
            lambda p: p["wire_event_ids"].append(16),
            lambda p: p.update(wire_event_ids=[44, 45, 46]),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                package = self.occupancy()
                mutate(package)
                with self.assertRaises(ValueError):
                    contract.validate_event_map(package, self.sources)

    def test_colliding_upstream_ids_need_distinct_wire_ids(self):
        algorithms = ["vital_trend", "med_sleep_apnea"]
        rows = [
            {"algorithm": a, "event_id": e, "wire_event_id": e}
            for a in algorithms
            for e in self.sources[a]
        ]
        package = {
            "name": "collision-fixture-not-built",
            "wasm_sha256": "0" * 64,
            "algorithms": algorithms,
            "wire_event_ids": [r["wire_event_id"] for r in rows],
            "event_map": rows,
        }
        with self.assertRaisesRegex(ValueError, "aliases are forbidden"):
            contract.validate_event_map(package, self.sources)
        for wire, row in enumerate(rows, 16):
            row["wire_event_id"] = wire
        package["wire_event_ids"] = [r["wire_event_id"] for r in rows]
        self.assertEqual(
            contract.validate_event_map(package, self.sources)[1], "declaration_only"
        )

    def test_duplicate_packages_and_too_many_slots_are_rejected(self):
        self.manifest["packages"].append(copy.deepcopy(self.package))
        with self.assertRaisesRegex(ValueError, "Duplicate immutable package name"):
            self.validate()
        self.manifest["packages"] *= 3
        with self.assertRaisesRegex(ValueError, "four runtime slots"):
            self.validate()

    def test_source_revision_must_match(self):
        self.catalog["upstream_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "revision mismatch"):
            self.validate()

    def test_actual_rvf_bytes_and_embedded_metadata_are_checked(self):
        original = (DIRECTORY / self.package["file"]).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / self.package["file"]).write_bytes(original[:-1])
            with self.assertRaisesRegex(ValueError, "RVF hash mismatch"):
                contract.validate_artifact(self.package, directory)
        for changes in (
            {"wasm_sha256": "0" * 64},
            {"wasm_bytes": self.package["wasm_bytes"] + 1},
            {"max_frame_us": 9999},
            {"capabilities": "0x01"},
            {"name": "renamed"},
            {"file": "../modules/../home-signal.rvf"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                contract.validate_artifact(
                    dict(self.package, **changes), ROOT / "tests/fixtures/modules"
                )

    def test_outer_hash_does_not_hide_bad_header_or_embedded_payload_hash(self):
        original = (DIRECTORY / self.package["file"]).read_bytes()
        for offset, message in [
            (0, "header"),
            (24, "length"),
            (80, "embedded payload"),
        ]:
            with (
                self.subTest(offset=offset),
                tempfile.TemporaryDirectory() as temporary,
            ):
                data = bytearray(original)
                data[offset] ^= 1
                package = dict(self.package, sha256=hashlib.sha256(data).hexdigest())
                directory = Path(temporary)
                (directory / package["file"]).write_bytes(data)
                with self.assertRaisesRegex(ValueError, message):
                    contract.validate_artifact(package, directory)


if __name__ == "__main__":
    unittest.main()
