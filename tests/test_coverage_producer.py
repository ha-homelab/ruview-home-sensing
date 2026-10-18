"""No sockets/devices: deterministic producer capture and failure injection."""

import copy
import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from module_manifest_fixture import manifest_arguments, manifest_value
from module_package_fixture import DIRECTORY
from test_site_context import ContextFixture

from scripts import coverage_producer as producer

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "collector@sha256:" + "a" * 64
IDENTITY = {"host_id": "b" * 64, "boot_id": "same-boot"}


class FakeClock:
    def __init__(self):
        self.ns = 100_000_000_000
        self.jump = 0

    def stamp(self):
        return {
            "monotonic_ns": self.ns,
            "observed_utc": datetime.fromtimestamp(
                1_700_000_000 + self.ns / 1e9 + self.jump, timezone.utc
            ).isoformat(),
        }

    def sleep(self, seconds):
        self.ns += round(seconds * 1e9)


def runtime(clock):
    slots = [
        {
            "id": i,
            "state": "empty",
            "name": "",
            "caps": "0x0000",
            **dict.fromkeys(
                (
                    "binary_size",
                    "budget_us",
                    "frame_count",
                    "event_count",
                    "error_count",
                    "budget_faults",
                    "mean_us",
                    "max_us",
                    "max_frame_us",
                    "max_timer_us",
                    "frame_overruns",
                    "timer_overruns",
                ),
                0,
            ),
        }
        for i in range(4)
    ]
    return {
        "modules": slots,
        "loaded": 0,
        "max": 4,
        "runtime": {
            "uptime_ms": clock.ns // 1_000_000,
            "worker_stack_bytes": 32768,
            "worker_stack_min_free_bytes": 16000,
            "internal_free_bytes": 80000,
            "internal_min_free_bytes": 70000,
            "internal_largest_free_block": 40000,
        },
        "wifi": {
            "associated": True,
            "bssid": "02:ac:de:77:00:03",
            "channel": 11,
            "rssi_dbm": -55,
            "ap_info_error": 0,
        },
    }


class FakeHTTP:
    def __init__(self, clock):
        self.clock, self.calls = clock, []
        self.hook = lambda endpoint, value: value

    def get(self, endpoint, timeout):
        self.calls.append((endpoint, timeout))
        self.clock.sleep(0.01)
        if endpoint.endswith("_status"):
            value = {
                "version": "0.8.8.8",
                "running_partition": "ota_1",
                "date": "Oct 5 2026",
                "time": "21:34:00",
            }
        elif endpoint.endswith("_runtime"):
            value = runtime(self.clock)
        elif endpoint == "collector_nodes":
            value = {
                "nodes": [
                    {
                        "node_id": i,
                        "csi_status": "active",
                        "csi_last_seen_ms": 5,
                        "csi_sequence": self.clock.ns // 1_000_000,
                        "person_count": 42,
                    }
                    for i in producer.NODE_IDS
                ]
            }
        else:
            value = {
                "source": "esp32",
                "type": "sensing_update",
                "tick": self.clock.ns // 1_000_000,
                "timestamp": producer.parse_time(
                    self.clock.stamp()["observed_utc"]
                ).timestamp(),
                "nodes": [
                    {
                        "node_id": i,
                        "rssi_dbm": -55,
                        "subcarrier_count": 0,
                        "amplitude": ["PRIVATE_PAYLOAD"],
                        "position": [1, 2, 3],
                        "node_inference": {
                            "classification": "absent",
                            "age_ms": 10,
                            "confidence": 0.5,
                        },
                    }
                    for i in producer.NODE_IDS
                ],
                "persons": ["PRIVATE_PAYLOAD"],
            }
        return self.hook(endpoint, value)


class CoverageProducerTests(ContextFixture):
    def setUp(self):
        super().setUp()
        self.module_flags = manifest_arguments(self.parent)
        self.documents["nodes.json"] = {
            "nodes": [
                {
                    "identity_verified": n < 4,
                    "firmware_node_id": n,
                    "ip": f"192.0.2.{n}",
                    "mac": f"02:00:00:00:00:{n:02d}",
                    "room": f"lab{n}",
                    "floorplan_marker_id": f"ruview_example{n}",
                }
                for n in range(1, 5)
            ]
        }
        self.write("nodes.json", json.dumps(self.documents["nodes.json"]).encode())
        self.pin = self.manifest()
        self.output = self.parent / "producer"
        self.consumer = self.parent / "consumer.json"
        self.clock = FakeClock()
        self.anchor = {
            "schema_version": 1,
            "session_id": "shared-session",
            **IDENTITY,
            **self.clock.stamp(),
            "clock_tolerance_seconds": 2,
        }
        self.consumer.write_text(json.dumps(self.anchor))
        self.http = FakeHTTP(self.clock)
        self.configured = {
            "repository_files_sha256": {"config/placements.json": "fixed"},
            "collector_expected_image": IMAGE,
            "actual_model_hash": None,
            "actual_calibration_receipt": None,
            "raw_csi_grid": None,
            "fingerprint_complete": False,
        }

    def run_capture(self, fingerprint=None, node_ids=producer.NODE_IDS):
        with patch.object(
            producer,
            "repository_fingerprint",
            side_effect=fingerprint
            or (lambda *_, **__: copy.deepcopy(self.configured)),
        ):
            return producer.record(
                ROOT,
                self.consumer,
                self.output,
                5,
                IMAGE,
                self.http,
                clock=self.clock,
                identity=IDENTITY,
                node_ids=node_ids,
                site_context=self.context,
                site_context_sha256=self.pin,
                module_manifest=self.module_flags[1],
                module_manifest_sha256=self.module_flags[3],
                package_directory=DIRECTORY,
            )

    def rows(self):
        return [
            json.loads(line)
            for line in (self.output / "capture.jsonl").read_text().splitlines()
        ]

    def test_complete_capture_is_private_whitelisted_and_never_promotes(self):
        before = self.consumer.read_bytes()
        summary = self.run_capture()
        self.assertTrue(summary["recording_complete"])
        self.assertEqual(summary["evidence_integrity"], "valid")
        self.assertEqual(summary["sample_count"], 5)
        self.assertEqual(summary["validation_decision"], "not_evaluated")
        self.assertFalse(summary["coverage_validated"])
        self.assertFalse(summary["fingerprint"]["fingerprint_complete"])
        self.assertEqual(self.consumer.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            text = path.read_text()
            self.assertNotIn("PRIVATE_PAYLOAD", text)
            self.assertNotIn('"person_count"', text)
            self.assertNotIn('"amplitude"', text)
        for row in self.rows():
            self.assertEqual(row["session_id"], "shared-session")
            self.assertEqual(row["host_id"], IDENTITY["host_id"])
            producer.check_stamp(row, self.anchor)
        self.assertTrue(all(0 < timeout <= 5 for _, timeout in self.http.calls))
        samples = [row for row in self.rows() if row["kind"] == "sample"]
        self.assertEqual(samples[0]["nodes"][0]["published_subcarrier_count"], 0)
        self.assertIsNone(samples[0]["nodes"][0]["raw_csi_grid"])
        self.assertIsNone(samples[0]["nodes"][0]["vitals"])
        with self.assertRaises(FileExistsError):
            self.run_capture()

    def test_host_boot_clock_and_schema_fail_before_output_or_requests(self):
        for key, value in (
            ("host_id", "elsewhere"),
            ("boot_id", "other-boot"),
            ("schema_version", 2),
            ("schema_version", True),
            ("monotonic_ns", True),
            ("observed_utc", "2026-01-01T00:00:00"),
        ):
            with self.subTest(key=key):
                self.consumer.write_text(json.dumps({**self.anchor, key: value}))
                with self.assertRaises(producer.EvidenceError):
                    self.run_capture()
                self.assertFalse(self.output.exists())
                self.assertFalse(self.http.calls)

    def test_source_duplicate_ids_and_malformed_fields_are_not_silently_accepted(self):
        for variant in ("source", "duplicate", "boolean_id", "malformed"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as folder:
                self.output = Path(folder) / "producer"

                def change(endpoint, value, variant=variant):
                    if endpoint == "collector_sensing":
                        if variant == "source":
                            value["source"] = "simulated"
                        elif variant == "duplicate":
                            value["nodes"][1]["node_id"] = 1
                        elif variant == "boolean_id":
                            value["nodes"][0]["node_id"] = True
                        else:
                            value["nodes"][0]["node_inference"]["confidence"] = "secret"
                    return value

                self.http.hook = change
                summary = self.run_capture()
                self.assertEqual(summary["capture_status"], "invalid")
                self.assertFalse(summary["recording_complete"])
                self.assertEqual(summary["sample_count"], 0)
                self.assertTrue(summary["stream_complete"])

    def test_legacy_boundary_keeps_firmware_and_duplicate_ids_but_is_invalid(self):
        def legacy(endpoint, value):
            if endpoint == "node1_runtime":
                value.pop("runtime")
                value.pop("wifi")
                for slot in value["modules"]:
                    slot["id"] = 0
            if endpoint == "node3_runtime":
                raise TimeoutError("TOKEN_MUST_NOT_BE_WRITTEN")
            return value

        self.http.hook = legacy
        summary = self.run_capture()
        self.assertTrue(summary["recording_complete"])
        self.assertEqual(summary["sample_count"], 5)
        self.assertEqual(summary["evidence_integrity"], "invalid")
        rows = self.rows()
        self.assertTrue(
            any(
                row["kind"] == "firmware_boundary" and row["node_id"] == 3
                for row in rows
            )
        )
        legacy_row = next(
            row
            for row in rows
            if row["kind"] == "runtime_boundary" and row["node_id"] == 1
        )
        self.assertEqual(
            [slot["id"] for slot in legacy_row["diagnostics"]["modules"]], [0, 0, 0, 0]
        )
        self.assertFalse(legacy_row["diagnostics"]["runtime_identity_valid"])
        self.assertNotIn(
            "TOKEN_MUST_NOT_BE_WRITTEN", (self.output / "capture.jsonl").read_text()
        )

    def test_unreviewed_firmware_never_receives_runtime_get(self):
        def unreviewed(endpoint, value):
            if endpoint == "node1_status":
                value["version"] = "0.7.0"
            elif endpoint == "node3_status":
                value["version"] = "0.9.0"
            return value

        self.http.hook = unreviewed
        summary = self.run_capture()
        endpoints = [endpoint for endpoint, _ in self.http.calls]
        self.assertNotIn("node1_runtime", endpoints)
        self.assertNotIn("node3_runtime", endpoints)
        self.assertEqual(endpoints.count("node2_runtime"), 2)
        self.assertEqual(endpoints.count("node1_status"), 2)
        self.assertEqual(endpoints.count("node3_status"), 2)
        self.assertEqual(summary["sample_count"], 5)
        self.assertTrue(summary["recording_complete"])
        self.assertEqual(summary["evidence_integrity"], "invalid")
        rows = self.rows()
        firmware = [row for row in rows if row["kind"] == "firmware_boundary"]
        self.assertEqual(len(firmware), 6)
        skipped = [row for row in rows if row["kind"] == "runtime_probe_skipped"]
        self.assertEqual(len(skipped), 4)
        self.assertEqual(
            {row["firmware_version"] for row in skipped}, {"0.7.0", "0.9.0"}
        )
        self.assertTrue(
            all(row["reason"] == "runtime_probe_not_qualified" for row in skipped)
        )
        self.assertFalse(
            any(
                row["kind"] == "runtime_boundary" and row["node_id"] in (1, 3)
                for row in rows
            )
        )

    def test_stale_accepted_csi_at_observation_and_source_clock_are_explicit(self):
        fleet = self.http.get("collector_nodes", 5)
        sensing = self.http.get("collector_sensing", 5)
        sample = producer.select_sample(
            fleet, sensing, self.clock.stamp()["observed_utc"], 4000
        )
        self.assertIn("node1_stale_accepted_csi", sample["issues"])
        self.assertEqual(sample["nodes"][0]["accepted_csi"]["age_ms"], 5)
        self.assertEqual(
            sample["nodes"][0]["accepted_csi"]["age_at_observation_ms"], 4005
        )
        sensing["timestamp"] -= 11
        self.assertIn(
            "stale_or_future_collector_timestamp",
            producer.select_sample(fleet, sensing, self.clock.stamp()["observed_utc"])[
                "issues"
            ],
        )

    def test_active_classification_is_canonical_with_original_label_and_node_isolation(
        self,
    ):
        fleet = self.http.get("collector_nodes", 5)
        sensing = self.http.get("collector_sensing", 5)
        labels = ("active", "present_still", "absent")
        for node, label in zip(sensing["nodes"], labels, strict=True):
            node["node_inference"]["classification"] = label
        original = copy.deepcopy(sensing)
        sample = producer.select_sample(
            fleet, sensing, self.clock.stamp()["observed_utc"]
        )
        self.assertEqual(sample["issues"], [])
        self.assertEqual(sensing, original)
        for node, raw, canonical in zip(
            sample["nodes"],
            labels,
            ("present_moving", "present_still", "absent"),
            strict=True,
        ):
            self.assertEqual(node["inference"]["classification"], canonical)
            self.assertEqual(node["inference"]["classification_raw"], raw)
            self.assertEqual(node["inference"]["validation"], "unverified")

    def test_active_capture_remains_unverified_and_keeps_source_label(self):
        def active(endpoint, value):
            if endpoint == "collector_sensing":
                value["nodes"][0]["node_inference"]["classification"] = "active"
            return value

        self.http.hook = active
        summary = self.run_capture()
        self.assertTrue(summary["recording_complete"])
        self.assertEqual(summary["evidence_integrity"], "valid")
        self.assertFalse(summary["coverage_validated"])
        self.assertEqual(summary["validation_decision"], "not_evaluated")
        samples = [row for row in self.rows() if row["kind"] == "sample"]
        self.assertEqual(len(samples), 5)
        for sample in samples:
            self.assertEqual(
                sample["nodes"][0]["inference"]["classification"], "present_moving"
            )
            self.assertEqual(
                sample["nodes"][0]["inference"]["classification_raw"], "active"
            )

    def test_classification_alias_does_not_bypass_producer_invalid_or_stale_evidence(
        self,
    ):
        fleet = self.http.get("collector_nodes", 5)
        sensing = self.http.get("collector_sensing", 5)
        utc = self.clock.stamp()["observed_utc"]
        inference = sensing["nodes"][0]["node_inference"]
        for value in ("idle", "ACTIVE", " active", "", None, True, 1, [], {}):
            with self.subTest(value=value):
                inference["classification"] = value
                with self.assertRaisesRegex(
                    producer.EvidenceError, "malformed_node_inference"
                ):
                    producer.select_sample(fleet, sensing, utc)
        inference["classification"] = "unknown"
        sample = producer.select_sample(fleet, sensing, utc)
        self.assertIn("node1_unknown_or_stale_inference", sample["issues"])
        self.assertEqual(
            sample["nodes"][0]["inference"]["classification_raw"], "unknown"
        )
        inference["classification"] = "active"
        sample = producer.select_sample(fleet, sensing, utc, 3001)
        self.assertIn("node1_stale_accepted_csi", sample["issues"])
        inference["age_ms"] = 10001
        sample = producer.select_sample(fleet, sensing, utc)
        self.assertIn("node1_unknown_or_stale_inference", sample["issues"])
        inference["age_ms"] = 10
        sensing["timestamp"] -= 11
        sample = producer.select_sample(fleet, sensing, utc)
        self.assertIn("stale_or_future_collector_timestamp", sample["issues"])
        self.assertIn("node1_unknown_or_stale_inference", sample["issues"])

    def test_runtime_identity_config_changes_and_clock_jumps_invalidate(self):
        for variant in ("ap", "config", "clock", "reset", "fault"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as folder:
                self.output = Path(folder) / "producer"
                self.clock = FakeClock()
                self.http = FakeHTTP(self.clock)
                counts = {}

                def change(endpoint, value, variant=variant, counts=counts):
                    counts[endpoint] = counts.get(endpoint, 0) + 1
                    if variant == "clock" and endpoint == "collector_nodes":
                        self.clock.jump = 3
                    if endpoint == "node2_runtime" and counts[endpoint] == 2:
                        if variant == "ap":
                            value["wifi"]["channel"] = 1
                        if variant == "reset":
                            value["runtime"]["uptime_ms"] = 1
                        if variant == "fault":
                            value["modules"][0]["error_count"] = 1
                    return value

                self.http.hook = change
                fingerprints = iter(
                    [self.configured, {**self.configured, "changed": True}]
                )
                summary = self.run_capture(
                    (lambda *_, values=fingerprints, **__: next(values))
                    if variant == "config"
                    else None
                )
                self.assertEqual(summary["evidence_integrity"], "invalid")
                self.assertFalse(summary["coverage_validated"])

    def test_short_uptime_restart_is_rejected_by_boot_intervals(self):
        status = {"version": "0.8.8.8", "running_partition": "ota_1"}
        first = producer.select_boundary(status, runtime(self.clock))
        first["runtime"]["uptime_ms"] = 100
        second = copy.deepcopy(first)
        second["runtime"]["uptime_ms"] = (
            5100  # Device rebooted five seconds into a 10s gap.
        )

        def stamp(ns):
            return {"monotonic_ns": ns}

        timings = [
            {"request_started": stamp(n), "received": stamp(n + 10_000_000)}
            for n in (100_000_000_000, 110_000_000_000)
        ]
        self.assertIn(
            "runtime_reboot_or_clock_mismatch",
            producer.boundary_issues(first, second, *timings),
        )

    def test_missing_runtime_reset_and_fault_diagnostics_remain_unknown(self):
        def missing(endpoint, value):
            if endpoint.endswith("_runtime"):
                value["runtime"].pop("uptime_ms")
                for slot in value["modules"]:
                    slot["frame_overruns"] = None
                    slot.pop("timer_overruns")
            return value

        self.http.hook = missing
        summary = self.run_capture()
        self.assertTrue(summary["recording_complete"])
        self.assertEqual(summary["evidence_integrity"], "invalid")
        reasons = {reason["code"] for reason in summary["reasons"]}
        self.assertIn("runtime_resource_diagnostics_unavailable", reasons)
        self.assertIn("module_diagnostics_unavailable", reasons)

    def test_transport_failure_stops_sampling_without_retry_or_secret_log(self):
        def fail(endpoint, value):
            if endpoint == "collector_nodes":
                raise RuntimeError("Authorization: Bearer PRIVATE_SECRET")
            return value

        self.http.hook = fail
        summary = self.run_capture()
        self.assertFalse(summary["recording_complete"])
        self.assertEqual(
            sum(endpoint == "collector_nodes" for endpoint, _ in self.http.calls), 1
        )
        self.assertNotIn("PRIVATE_SECRET", (self.output / "capture.jsonl").read_text())
        path = self.output / "capture.jsonl"
        original = path.read_text()
        path.write_text(original[:-2])
        self.assertFalse(producer.inspect_capture(path)["stream_complete"])

    def test_mid_loop_failure_retains_elapsed_sampling_duration(self):
        calls = 0

        def fail_third_sample(endpoint, value):
            nonlocal calls
            if endpoint == "collector_nodes":
                calls += 1
                if calls == 3:
                    raise TimeoutError("interrupted third sample")
            return value

        self.http.hook = fail_third_sample
        summary = self.run_capture()
        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(calls, 3)
        self.assertAlmostEqual(summary["sampled_duration_s"], 2.01)
        self.assertFalse(summary["recording_complete"])
        self.assertEqual(summary["evidence_integrity"], "invalid")
        self.assertEqual(summary["validation_decision"], "not_evaluated")

    def test_interrupted_closing_does_not_extend_sampling_duration(self):
        calls = 0

        def interrupt_closing(endpoint, value):
            nonlocal calls
            if endpoint == "node1_status":
                calls += 1
                if calls == 2:
                    self.clock.sleep(2)
                    raise KeyboardInterrupt()
            return value

        self.http.hook = interrupt_closing
        summary = self.run_capture()
        self.assertEqual(summary["sample_count"], 5)
        self.assertEqual(summary["sampled_duration_s"], 5)
        self.assertFalse(summary["recording_complete"])
        self.assertEqual(summary["evidence_integrity"], "invalid")

    def test_strict_json_and_partial_repository_fingerprint(self):
        for text in (
            '{"nodes": [], "nodes": []}',
            '{"value":NaN}',
            '{"value":Infinity}',
        ):
            with self.assertRaises(ValueError):
                producer.json_load(text)
        value = producer.repository_fingerprint(
            ROOT, IMAGE, self.load(), manifest_value(), package_directory=DIRECTORY
        )
        self.assertFalse(value["fingerprint_complete"])
        self.assertIsNone(value["actual_model_hash"])
        self.assertIsNone(value["collector_observed_image"])
        self.assertIn("scripts/coverage_producer.py", value["repository_files_sha256"])
        self.assertIn("config/placements.json", value["repository_files_sha256"])

    def test_private_context_is_not_replaced_by_tracked_configuration(self):
        original = Path.read_bytes

        def read(path):
            if path.parent == ROOT / "config" and path.name in producer.FILES:
                raise AssertionError("Tracked private input must not be read")
            return original(path)

        with patch.object(Path, "read_bytes", read):
            result = producer.repository_fingerprint(
                ROOT, IMAGE, self.load(), manifest_value(), package_directory=DIRECTORY
            )
        for name, raw in self.load().raw.items():
            self.assertEqual(
                result["repository_files_sha256"]["config/" + name],
                producer.digest(raw),
            )
        self.assertEqual(result["site_context_manifest_sha256"], self.pin)

    def fingerprint_repository(self):
        root = self.parent / "fingerprint-repository"
        root.mkdir()
        fingerprint = producer.repository_fingerprint(
            ROOT, IMAGE, self.load(), manifest_value(), package_directory=DIRECTORY
        )
        for name in fingerprint["repository_files_sha256"]:
            source = ROOT / name
            if source.is_file():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
        snapshots = [
            root / "config/aidot-candidates.json",
            root / "config/observed-nodes.json",
        ]
        for path in snapshots:
            path.write_text('{"unverified_discovery": "synthetic-only"}\n')
        return root, snapshots

    @staticmethod
    def fingerprint_git(command, **kwargs):
        if command == ["git", "rev-parse", "HEAD"]:
            return "a" * 40 + "\n"
        if command[:5] == [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--",
        ]:
            return ""
        raise AssertionError("Unexpected external command")

    def test_retired_discovery_changes_fingerprint_without_changing_private_inputs(
        self,
    ):
        root, snapshots = self.fingerprint_repository()
        with patch.object(
            producer.subprocess, "check_output", side_effect=self.fingerprint_git
        ):
            before = producer.repository_fingerprint(
                root, IMAGE, self.load(), manifest_value(), package_directory=DIRECTORY
            )
            for path in snapshots:
                path.unlink()
            after = producer.repository_fingerprint(
                root, IMAGE, self.load(), manifest_value(), package_directory=DIRECTORY
            )
        self.assertNotEqual(before, after)
        expected = copy.deepcopy(before)
        for path in snapshots:
            del expected["repository_files_sha256"][str(path.relative_to(root))]
        self.assertEqual(after, expected)
        self.assertFalse(after["fingerprint_complete"])

    def test_removing_discovery_during_capture_invalidates_real_fingerprint(self):
        root, snapshots = self.fingerprint_repository()

        def remove_during_capture(endpoint, value):
            if endpoint == "collector_nodes":
                for path in snapshots:
                    path.unlink(missing_ok=True)
            return value

        self.http.hook = remove_during_capture
        with patch.object(
            producer.subprocess, "check_output", side_effect=self.fingerprint_git
        ):
            result = producer.record(
                root,
                self.consumer,
                self.output,
                5,
                IMAGE,
                self.http,
                clock=self.clock,
                identity=IDENTITY,
                site_context=self.context,
                site_context_sha256=self.pin,
                module_manifest=self.module_flags[1],
                module_manifest_sha256=self.module_flags[3],
                package_directory=DIRECTORY,
            )
        self.assertEqual(result["evidence_integrity"], "invalid")
        self.assertFalse(result["coverage_validated"])
        self.assertIn("repository_configuration_changed", json.dumps(self.rows()))

    def test_fresh_capture_without_retired_discovery_remains_unqualified(self):
        root, snapshots = self.fingerprint_repository()
        for path in snapshots:
            path.unlink()
        with patch.object(
            producer.subprocess, "check_output", side_effect=self.fingerprint_git
        ):
            result = producer.record(
                root,
                self.consumer,
                self.output,
                5,
                IMAGE,
                self.http,
                clock=self.clock,
                identity=IDENTITY,
                site_context=self.context,
                site_context_sha256=self.pin,
                module_manifest=self.module_flags[1],
                module_manifest_sha256=self.module_flags[3],
                package_directory=DIRECTORY,
            )
        self.assertEqual(result["evidence_integrity"], "valid")
        self.assertFalse(result["coverage_validated"])
        self.assertFalse(result["fingerprint"]["fingerprint_complete"])
        self.assertEqual(result["validation_decision"], "not_evaluated")

    def test_bad_context_fails_before_clock_output_or_http(self):
        self.write("nodes.json", b'{"nodes": []}')
        with (
            self.assertRaises(ValueError),
            patch.object(producer, "clock_identity") as clock,
        ):
            self.run_capture()
        clock.assert_not_called()
        self.assertEqual(self.http.calls, [])
        self.assertFalse(self.output.exists())

    def test_context_mutation_during_capture_invalidates_terminal(self):
        def change(endpoint, value):
            if endpoint == "collector_nodes":
                self.write("placements.json", b'{"items": []}')
            return value

        self.http.hook = change
        result = self.run_capture()
        self.assertEqual(result["capture_status"], "invalid")
        self.assertIn({"code": "capture_interrupted"}, self.rows()[-1]["reasons"])

    def test_module_approval_mutation_during_capture_invalidates_terminal(self):
        def change(endpoint, value):
            if endpoint == "collector_nodes":
                path = Path(self.module_flags[1])
                path.write_bytes(path.read_bytes() + b" ")
            return value

        self.http.hook = change
        result = self.run_capture()
        self.assertEqual(result["capture_status"], "invalid")
        self.assertIn({"code": "capture_interrupted"}, self.rows()[-1]["reasons"])

    def test_explicit_verified_bench_scope_records_only_selected_device(self):
        inventory = producer.inventory_nodes(self.load())
        inventory[4] = {
            **copy.deepcopy(inventory[3]),
            "firmware_node_id": 4,
            "mac": "02:00:00:00:00:04",
            "ip": "192.168.77.124",
            "room": None,
            "floorplan_marker_id": None,
            "current_placement": {
                "valid": False,
                "measurement_location": "operator_usb_workbench",
            },
        }

        def fourth(endpoint, value):
            if endpoint in ("collector_nodes", "collector_sensing"):
                value["nodes"].append(
                    {**copy.deepcopy(value["nodes"][-1]), "node_id": 4}
                )
            return value

        self.http.hook = fourth
        with patch.object(producer, "inventory_nodes", return_value=inventory):
            summary = self.run_capture(node_ids=[4])
        self.assertTrue(summary["recording_complete"])
        self.assertEqual(summary["selected_node_ids"], [4])
        self.assertFalse(summary["coverage_validated"])
        metadata = json.loads((self.output / "metadata.json").read_text())
        self.assertEqual(metadata["configured_verified_node_ids"], [1, 2, 3, 4])
        self.assertIsNone(metadata["node_bindings"]["4"]["room"])
        boundaries = {
            endpoint for endpoint, _ in self.http.calls if endpoint.startswith("node")
        }
        self.assertEqual(boundaries, {"node4_status", "node4_runtime"})
        for row in self.rows():
            if row["kind"] == "sample":
                self.assertEqual([n["node_id"] for n in row["nodes"]], [4])
                self.assertEqual(row["unselected_verified_node_ids_seen"], [1, 2, 3])

    def test_scope_never_hides_unknown_duplicate_or_missing_collector_nodes(self):
        for value, selected, allowed in (
            ({"nodes": [{"node_id": 4}, {"node_id": 99}]}, [4], [1, 2, 3, 4]),
            (
                {"nodes": [{"node_id": 4}, {"node_id": 1}, {"node_id": 1}]},
                [4],
                [1, 2, 3, 4],
            ),
            ({"nodes": [{"node_id": 1}]}, [4], [1, 2, 3, 4]),
        ):
            with self.assertRaises(producer.EvidenceError):
                producer.indexed_nodes(value, selected, allowed)
        for selection in ([4], [1, 1], [True], []):
            with self.assertRaises(producer.EvidenceError):
                producer.node_scope(selection, {1: {}, 2: {}, 3: {}})

    def test_inventory_allows_verified_bench_but_rejects_duplicate_identity(self):
        inventory = self.documents["nodes.json"]
        node = inventory["nodes"][3]
        node.update(identity_verified=True, firmware_node_id=4, mac="02:00:00:00:00:04")
        self.write("nodes.json", json.dumps(inventory).encode())
        self.pin = self.manifest()
        self.assertEqual(set(producer.inventory_nodes(self.load())), {1, 2, 3, 4})
        node["mac"] = inventory["nodes"][0]["mac"]
        self.write("nodes.json", json.dumps(inventory).encode())
        self.pin = self.manifest()
        with self.assertRaisesRegex(producer.EvidenceError, "duplicate_inventory_mac"):
            producer.inventory_nodes(self.load())

    def test_http_adapter_limits_bench_requests_to_selected_ids_and_strips_auth(self):
        http = producer.ReadOnlyHTTP(
            "http://collector.invalid",
            "PRIVATE_TEST_TOKEN",
            {4: {"ip": "192.0.2.4"}, 10: {"ip": "192.0.2.10"}},
        )
        reply = MagicMock()
        reply.status = 200
        reply.read.return_value = b"{}"
        http.opener = MagicMock()
        http.opener.open.return_value.__enter__.return_value = reply
        for node_id in (4, 10):
            for endpoint, path in (
                ("status", "/ota/status"),
                ("runtime", "/wasm/list"),
            ):
                self.assertEqual(http.get(f"node{node_id}_{endpoint}", 1), {})
                request = http.opener.open.call_args.args[0]
                self.assertEqual(
                    request.full_url, f"http://192.0.2.{node_id}:8032{path}"
                )
                self.assertEqual(request.get_method(), "GET")
                self.assertIsNone(request.get_header("Authorization"))
        calls = http.opener.open.call_count
        for endpoint in (
            "node1_status",
            "node99_runtime",
            "node04_status",
            "node4_upload",
        ):
            with self.assertRaises(producer.EvidenceError):
                http.get(endpoint, 1)
        self.assertEqual(http.opener.open.call_count, calls)
        http.get("collector_nodes", 1)
        request = http.opener.open.call_args.args[0]
        self.assertEqual(
            request.get_header("Authorization"), "Bearer PRIVATE_TEST_TOKEN"
        )


if __name__ == "__main__":
    unittest.main()
