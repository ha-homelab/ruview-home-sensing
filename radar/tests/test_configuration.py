import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from radar.__main__ import MAX_CONFIG_BYTES, main, read_configuration
from radar.config import FLEET_SCHEMA, inspect_document
from radar.ld2450 import Configuration, ObservationAdapter
from radar.tests.test_ld2450 import synthetic_config

ROOT = Path(__file__).resolve().parents[1]


def fleet(count=5):
    records = []
    for index in range(count):
        record = synthetic_config()
        for key in ["sensor_id", "hardware_identity", "serial_endpoint_id"]:
            record[key] += f"-{index}"
        records.append(record)
    return {"schema": FLEET_SCHEMA, "radars": records}


class ConfigurationTests(unittest.TestCase):
    def run_cli(self, raw, *args):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_bytes(raw)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = main(
                    [
                        "validate-config",
                        str(path),
                        "--format",
                        "json",
                        "--expected-coordinate-frame",
                        "example_lab_xz_metres",
                        *args,
                    ]
                )
        return code, json.loads(out.getvalue())

    def test_existing_profile_complete_matches_runtime_hash_not_validation(self):
        profile = synthetic_config()
        result = inspect_document(
            profile, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertEqual(result["status"], "config_complete")
        self.assertTrue(result["declared_config_complete"])
        self.assertFalse(result["hardware_observed"])
        self.assertFalse(result["survey_evidence_verified"])
        self.assertFalse(result["recognition_validated"])
        self.assertEqual(
            result["configuration_sha256"],
            Configuration.load(
                profile, expected_coordinate_frame="example_lab_xz_metres"
            ).sha256,
        )
        adapter = ObservationAdapter(
            profile, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertEqual(
            adapter.snapshot(monotonic_ns=1, utc_ns=1)["status"], "unavailable"
        )

    def test_single_and_five_slot_templates_remain_draft(self):
        for name, count in [
            ("configuration.template.json", 1),
            ("fleet.template.json", 5),
        ]:
            raw = (ROOT / name).read_bytes()
            code, result = self.run_cli(raw)
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "draft")
            self.assertEqual(result["counts"]["draft"], count)
            self.assertTrue(result["structurally_valid"])
            self.assertFalse(result["declared_config_complete"])
            self.assertEqual(self.run_cli(raw, "--require-complete")[0], 3)
            paths = {issue["path"] for issue in result["profiles"][0]["pending"]}
            self.assertTrue(any(p.endswith("hardware_confirmed") for p in paths))
            self.assertTrue(any(p.endswith("survey.status") for p in paths))

    def test_fleet_limits_and_complete_profile_configuration_only(self):
        for count in [1, 5]:
            result = inspect_document(
                fleet(count), expected_coordinate_frame="example_lab_xz_metres"
            )
            self.assertTrue(result["declared_config_complete"])
            self.assertEqual(result["counts"]["config_complete"], count)
        for count in [0, 6]:
            self.assertEqual(
                inspect_document(
                    fleet(count), expected_coordinate_frame="example_lab_xz_metres"
                )["status"],
                "invalid",
            )

    def test_unique_bindings_and_matching_floorplan(self):
        for key in ["sensor_id", "hardware_identity", "serial_endpoint_id"]:
            config = fleet(2)
            config["radars"][1][key] = config["radars"][0][key].upper()
            result = inspect_document(
                config, expected_coordinate_frame="example_lab_xz_metres"
            )
            self.assertFalse(result["structurally_valid"])
            self.assertEqual(result["errors"][0]["code"], "duplicate_binding")
        config = fleet(2)
        config["radars"][1]["floorplan_sha256"] = "c" * 64
        self.assertEqual(
            inspect_document(config, expected_coordinate_frame="example_lab_xz_metres")[
                "errors"
            ][0]["code"],
            "mixed_floorplans",
        )

    def test_pending_null_bindings_do_not_count_as_duplicates(self):
        config = json.loads((ROOT / "fleet.template.json").read_text())
        self.assertEqual(
            inspect_document(config, expected_coordinate_frame="example_lab_xz_metres")[
                "errors"
            ],
            [],
        )
        config["radars"][0]["sensor_id"] = None
        self.assertEqual(
            inspect_document(config, expected_coordinate_frame="example_lab_xz_metres")[
                "status"
            ],
            "draft",
        )

    def test_typos_are_invalid_in_cli_and_runtime(self):
        for nested in [False, True]:
            config = synthetic_config()
            (config["survey"] if nested else config)["misspelled_field"] = True
            self.assertEqual(
                inspect_document(
                    config, expected_coordinate_frame="example_lab_xz_metres"
                )["status"],
                "invalid",
            )
            with self.assertRaises(ValueError):
                Configuration.load(
                    config, expected_coordinate_frame="example_lab_xz_metres"
                )
        config = fleet(1)
        config["enable_transport"] = True
        self.assertEqual(
            inspect_document(config, expected_coordinate_frame="example_lab_xz_metres")[
                "status"
            ],
            "invalid",
        )

    def test_types_nonfinite_values_and_other_model_rejected(self):
        for value in [True, "90", [], {}, float("nan"), float("inf"), 10**400]:
            config = synthetic_config()
            config["survey"]["yaw_deg"] = value
            self.assertEqual(
                inspect_document(
                    config, expected_coordinate_frame="example_lab_xz_metres"
                )["status"],
                "invalid",
            )
            with self.assertRaises(ValueError):
                Configuration.load(
                    config, expected_coordinate_frame="example_lab_xz_metres"
                )
        config = synthetic_config()
        config["model"] = "other-radar"
        self.assertEqual(
            inspect_document(config, expected_coordinate_frame="example_lab_xz_metres")[
                "status"
            ],
            "invalid",
        )
        for value in [True, "true", 1]:
            config = synthetic_config()
            config["hardware_confirmed"] = value
            if value is True:
                continue
            self.assertEqual(
                inspect_document(
                    config, expected_coordinate_frame="example_lab_xz_metres"
                )["status"],
                "invalid",
            )

    def test_invalid_json_size_and_duplicate_keys_never_load(self):
        for raw in [
            b"{",
            b'{"schema":1,"schema":2}',
            b'{"v":NaN}',
            b'{"v":Infinity}',
            b"\xff",
            b" " * (MAX_CONFIG_BYTES + 1),
        ]:
            code, result = self.run_cli(raw)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(result["errors"][0]["code"], "unreadable_or_invalid_json")

    def test_non_regular_and_symlink_files_are_not_opened(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "regular.json"
            target.write_text("{}")
            link = base / "link"
            link.symlink_to(target)
            fifo = base / "pipe"
            os.mkfifo(fifo)
            for path in [base, link, fifo]:
                with patch(
                    "radar.__main__.os.open",
                    side_effect=AssertionError("must not open"),
                ):
                    with self.assertRaises(ValueError):
                        read_configuration(path)

    def test_cli_never_connects_and_reports_complete_without_live_claim(self):
        raw = json.dumps(fleet()).encode()
        with patch.object(
            ObservationAdapter, "connect", side_effect=AssertionError("no UART")
        ):
            code, result = self.run_cli(raw, "--require-complete")
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "config_complete")
        self.assertFalse(result["transport_started"])
        self.assertEqual(len(result["source_sha256"]), 64)

    def test_inspection_does_not_mutate_input_and_hash_binds_each_profile(self):
        value = fleet(2)
        before = copy.deepcopy(value)
        original = inspect_document(
            value, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertEqual(value, before)
        value["radars"][1]["survey"]["origin_xz_m"][0] += 1
        changed = inspect_document(
            value, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertNotEqual(
            original["configuration_sha256"], changed["configuration_sha256"]
        )
        self.assertEqual(
            original["profiles"][0]["configuration_sha256"],
            changed["profiles"][0]["configuration_sha256"],
        )
        self.assertNotEqual(
            original["profiles"][1]["configuration_sha256"],
            changed["profiles"][1]["configuration_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
