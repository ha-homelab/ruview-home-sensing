"""Offline failure-injection checks. Never invokes the live observer."""

import asyncio
import copy
import importlib.util
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from collector_fixture import COLLECTOR
from module_package_fixture import bind_module
from qualification_fixture import RECEIVER, run_cli

SPEC = importlib.util.spec_from_file_location(
    "node2_observer",
    Path(__file__).resolve().parents[1] / "firmware/observe-runtime.py",
)
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
bind_module(OBSERVER)


def fixture(mode="module", version=None):
    report = {
        "receiver": RECEIVER.metadata(),
        "mode": mode,
        "module_id": 0,
        "expected_partition": "ota_0",
        "elapsed_s": 305,
        "local_package_sha256": OBSERVER.PACKAGE_SHA,
        "errors": [],
        "ws_opened_s": 0.1,
        "ws_closed_s": 305,
        "samples": [],
        "ws_updates": [],
        "wasm_packets": [],
    }
    for i in range(153):
        received = 0.4 + i * 2
        slots = [{"id": j, "state": "empty"} for j in range(4)]
        if mode == "module":
            slots[0].update(
                name="home-signal",
                state="running",
                binary_size=14783,
                caps="0x006b",
                budget_us=10000,
                frame_count=100 + i * 24,
                event_count=10 + i,
                error_count=0,
                budget_faults=0,
                max_us=500,
                mean_us=300,
            )
        if version in ("0.8.8.7", "0.8.8.8", "0.8.8.10", "0.8.8.11", "0.8.8.12"):
            for slot in slots:
                slot.update(
                    max_us=slot.get("max_us", 0),
                    max_frame_us=slot.get("max_us", 0),
                    max_timer_us=0,
                    frame_overruns=0,
                    timer_overruns=0,
                )
        report["samples"].append(
            {
                "request_start_s": received - 0.2,
                "received_s": received,
                "csi_received_s": received + 0.1,
                "status": {
                    "version": version or "0.8.8.5",
                    "running_partition": "ota_0",
                },
                "listing": {
                    "max": 4,
                    "loaded": int(mode == "module"),
                    "modules": slots,
                    "runtime": {
                        "uptime_ms": 100000 + i * 2000,
                        "worker_stack_bytes": 32768,
                        "worker_stack_min_free_bytes": 16000,
                        "internal_free_bytes": 80000,
                        "internal_min_free_bytes": 70000,
                        "internal_largest_free_block": 40000,
                    },
                },
                "csi": {
                    "node_id": 2,
                    "csi_status": "active",
                    "csi_last_seen_ms": 100,
                    "csi_sequence": 1000 + i * 24,
                },
            }
        )
        report["ws_updates"].append(
            {
                "received_s": received,
                "source": "esp32",
                "tick": i,
                "wall_clock_age_s": -0.002,
            }
        )
    if mode == "module":
        report["wasm_packets"] = [
            {
                "received_s": t,
                "node_id": 2,
                "module_id": 0,
                "events": [{"event_type": 2, "value": 0.5}],
            }
            for t in (10, 200)
        ]
    if version in ("0.8.8.10", "0.8.8.11", "0.8.8.12"):
        for i, row in enumerate(report["samples"]):
            identity = {
                "boot_nonce_schema": OBSERVER.BOOT_SCHEMA,
                "boot_nonce": "1" * 32,
                "station_mac": RECEIVER.station_mac,
            }
            row["status"].update(identity)
            row["listing"]["runtime"].update(identity)
            row["listing"]["runtime"]["self_ping"] = {
                "state": "running",
                "supervisor_started": True,
                **{k: 0 for k in OBSERVER.PING_STABLE_COUNTERS},
                "attempts": 2,
                "starts": 1,
                "create_failures": 1,
                "successes": i * 80,
                "timeouts": i,
                "last_error": 0,
                "last_progress_age_ms": 20,
                "last_progress_age_basis": "session_start_or_ping_callback",
            }
    if version is not None:
        report["expected_version"] = version
    return report


class QualificationTests(unittest.TestCase):
    def test_11_uses_same_boot_identity_ping_and_package_gates(self):
        for mode in ("baseline", "module"):
            report = fixture(mode, "0.8.8.11")
            result = OBSERVER.evaluate(
                report, expected_version="0.8.8.11", receiver=RECEIVER
            )
            self.assertTrue(result["passed"], result)
            self.assertEqual(result["metrics"]["boot_nonce"], "1" * 32)
            self.assertTrue(result["metrics"]["self_ping_callback_coverage"]["passed"])
        mutations = (
            lambda r: r["samples"][50]["status"].update(version="0.8.8.10"),
            lambda r: r["samples"][50]["status"].update(boot_nonce_schema="unknown"),
            lambda r: r["samples"][50]["status"].update(
                station_mac="02:ac:de:77:00:01"
            ),
            lambda r: r["samples"][50]["listing"]["runtime"].update(
                boot_nonce="2" * 32
            ),
            lambda r: r["samples"][50]["listing"]["runtime"]["self_ping"].update(
                last_progress_age_ms=3001
            ),
            lambda r: r["samples"][50]["listing"]["modules"][0].update(
                frame_overruns=1
            ),
            lambda r: r["samples"][50]["csi"].update(node_id=1),
            lambda r: r.update(local_package_sha256="0" * 64),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                report = fixture(version="0.8.8.11")
                mutate(report)
                self.assertFalse(
                    OBSERVER.evaluate(
                        report, expected_version="0.8.8.11", receiver=RECEIVER
                    )["passed"]
                )

    def test_11_read_sample_requires_exact_version_and_keeps_boot_fields(self):
        sample = fixture("baseline", "0.8.8.11")["samples"][0]
        calls = []

        def get(url, auth=False):
            calls.append((url, auth))
            if url.endswith("/ota/status"):
                return copy.deepcopy(sample["status"])
            if url.endswith("/wasm/list"):
                return copy.deepcopy(sample["listing"])
            return {"nodes": [copy.deepcopy(sample["csi"])]}

        result = OBSERVER.read_sample(
            get,
            lambda: 0.5,
            "ota_0",
            expected_version="0.8.8.11",
            expected_nonce="1" * 32,
            receiver=RECEIVER,
            collector=COLLECTOR,
        )
        self.assertEqual(result["status"], sample["status"])
        self.assertEqual(
            calls[:2],
            [
                ("http://10.77.0.121:8032/ota/status", False),
                ("http://10.77.0.121:8032/wasm/list", False),
            ],
        )
        for actual_version in ("0.8.8.10", "0.8.8.12"):
            calls.clear()
            sample["status"]["version"] = actual_version
            with self.assertRaisesRegex(ValueError, "firmware_or_partition_mismatch"):
                OBSERVER.read_sample(
                    get,
                    lambda: 0.5,
                    "ota_0",
                    expected_version="0.8.8.11",
                    receiver=RECEIVER,
                    collector=COLLECTOR,
                )
            self.assertEqual(len(calls), 1)
        calls.clear()
        with self.assertRaisesRegex(ValueError, "invalid_expected_identity"):
            OBSERVER.read_sample(
                get,
                lambda: 0.5,
                "ota_0",
                expected_version="0.8.8.13",
                receiver=RECEIVER,
                collector=COLLECTOR,
            )
        self.assertEqual(calls, [])

    def test_10_boot_identity_and_independent_ping_progress(self):
        for mode in ("baseline", "module"):
            good = fixture(mode, "0.8.8.10")
            result = OBSERVER.evaluate(
                good, expected_version="0.8.8.10", receiver=RECEIVER
            )
            self.assertTrue(result["passed"], result)
            self.assertTrue(result["metrics"]["self_ping_callback_coverage"]["passed"])
            self.assertTrue(result["metrics"]["self_ping_progress_is_not_csi_evidence"])
            # Timeout-only ping progress is valid only with independent live CSI.
            for i, row in enumerate(good["samples"]):
                row["listing"]["runtime"]["self_ping"].update(
                    successes=0, timeouts=i * 2
                )
            self.assertTrue(
                OBSERVER.evaluate(good, expected_version="0.8.8.10", receiver=RECEIVER)[
                    "passed"
                ]
            )
            good["samples"][50]["csi"]["csi_last_seen_ms"] = 3001
            result = OBSERVER.evaluate(
                good, expected_version="0.8.8.10", receiver=RECEIVER
            )
            self.assertIn("csi_not_fresh", result["failures"])

    def test_10_boot_schema_mac_nonce_and_slot_counter_fail_closed(self):
        for where in ("status", "runtime"):
            for key, value in (
                ("boot_nonce_schema", None),
                ("boot_nonce", None),
                ("boot_nonce", "0" * 32),
                ("boot_nonce", "A" * 32),
                ("boot_nonce", "2" * 32),
                ("station_mac", "02:ac:de:77:00:01"),
            ):
                report = fixture(version="0.8.8.10")
                row = report["samples"][50]
                target = (
                    row["status"] if where == "status" else row["listing"]["runtime"]
                )
                target[key] = value
                self.assertFalse(
                    OBSERVER.evaluate(
                        report, expected_version="0.8.8.10", receiver=RECEIVER
                    )["passed"],
                    (where, key, value),
                )
        report = fixture(version="0.8.8.10")
        report["samples"][50]["listing"]["modules"][0]["frame_overruns"] = 1
        self.assertIn(
            "callback_overrun_recorded",
            OBSERVER.evaluate(report, expected_version="0.8.8.10", receiver=RECEIVER)[
                "failures"
            ],
        )
        # A reboot cannot hide behind plausible uptime and simultaneous matching nonce fields.
        report = fixture(version="0.8.8.10")
        for row in report["samples"][50:]:
            row["status"]["boot_nonce"] = row["listing"]["runtime"]["boot_nonce"] = (
                "2" * 32
            )
        self.assertIn(
            "boot_nonce_changed",
            OBSERVER.evaluate(report, expected_version="0.8.8.10", receiver=RECEIVER)[
                "failures"
            ],
        )

    def test_10_ping_missing_stalled_reset_and_restarted_are_not_qualified(self):
        for key, value in (
            ("state", "wait_ip"),
            ("supervisor_started", 1),
            ("last_progress_age_ms", 3001),
            ("last_progress_age_ms", None),
            ("last_progress_age_ms", True),
            ("last_error", False),
            ("last_progress_age_basis", "echo"),
            ("timeouts", -1),
        ):
            report = fixture(version="0.8.8.10")
            report["samples"][50]["listing"]["runtime"]["self_ping"][key] = value
            self.assertIn(
                "self_ping_not_healthy",
                OBSERVER.evaluate(
                    report, expected_version="0.8.8.10", receiver=RECEIVER
                )["failures"],
            )
        for key in OBSERVER.PING_STABLE_COUNTERS:
            report = fixture(version="0.8.8.10")
            report["samples"][50]["listing"]["runtime"]["self_ping"][key] += 1
            self.assertFalse(
                OBSERVER.evaluate(
                    report, expected_version="0.8.8.10", receiver=RECEIVER
                )["passed"],
                key,
            )
        report = fixture(version="0.8.8.10")
        for row in report["samples"]:
            row["listing"]["runtime"]["self_ping"].update(successes=10, timeouts=0)
        self.assertIn(
            "self_ping_callbacks_not_advancing",
            OBSERVER.evaluate(report, expected_version="0.8.8.10", receiver=RECEIVER)[
                "failures"
            ],
        )
        report = fixture(version="0.8.8.10")
        report["samples"][50]["listing"]["runtime"]["self_ping"]["successes"] = 0
        self.assertIn(
            "self_ping_lifecycle_changed",
            OBSERVER.evaluate(report, expected_version="0.8.8.10", receiver=RECEIVER)[
                "failures"
            ],
        )

    def test_10_read_sample_checks_identity_before_runtime_and_collector(self):
        original = fixture("baseline", "0.8.8.10")["samples"][0]
        calls = []

        def get(url, auth=False):
            calls.append((url, auth))
            if url.endswith("/ota/status"):
                return copy.deepcopy(original["status"])
            if url.endswith("/wasm/list"):
                return copy.deepcopy(original["listing"])
            return {"nodes": [copy.deepcopy(original["csi"])]}

        result = OBSERVER.read_sample(
            get,
            lambda: 0.5,
            "ota_0",
            expected_version="0.8.8.10",
            expected_nonce="1" * 32,
            receiver=RECEIVER,
            collector=COLLECTOR,
        )
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["status"]["boot_nonce"], "1" * 32)
        for changes in (
            {"version": "0.7.0"},
            {"station_mac": "wrong"},
            {"boot_nonce": "2" * 32},
        ):
            calls.clear()
            original["status"] = fixture("baseline", "0.8.8.10")["samples"][0]["status"]
            original["status"].update(changes)
            with self.assertRaises(ValueError):
                OBSERVER.read_sample(
                    get,
                    lambda: 0.5,
                    "ota_0",
                    expected_version="0.8.8.10",
                    expected_nonce="1" * 32,
                    receiver=RECEIVER,
                    collector=COLLECTOR,
                )
            self.assertEqual(len(calls), 1)
        original["status"] = fixture("baseline", "0.8.8.10")["samples"][0]["status"]
        original["listing"]["runtime"]["boot_nonce"] = "2" * 32
        calls.clear()
        with self.assertRaisesRegex(ValueError, "boot_nonce_status_list_mismatch"):
            OBSERVER.read_sample(
                get,
                lambda: 0.5,
                "ota_0",
                expected_version="0.8.8.10",
                receiver=RECEIVER,
                collector=COLLECTOR,
            )
        self.assertEqual(len(calls), 2)

    def test_selected_legacy_version_gate_precedes_runtime_read(self):
        for version in ("0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8"):
            calls = []

            def get(url, auth=False, calls=calls):
                calls.append(url)
                return {"version": "0.7.0", "running_partition": "ota_0"}

            with self.assertRaisesRegex(ValueError, "firmware_or_partition_mismatch"):
                OBSERVER.read_sample(
                    get,
                    lambda: 0.0,
                    "ota_0",
                    expected_version=version,
                    receiver=RECEIVER,
                    collector=COLLECTOR,
                )
            self.assertEqual(calls, ["http://10.77.0.121:8032/ota/status"])
        with self.assertRaisesRegex(ValueError, "invalid_expected_identity"):
            OBSERVER.read_sample(
                lambda *a: self.fail("Unexpected request"),
                lambda: 0.0,
                "ota_0",
                expected_version="0.7.0",
                receiver=RECEIVER,
                collector=COLLECTOR,
            )

    def test_8_keeps_callback_evidence_required(self):
        for mode in ("baseline", "module"):
            good = fixture(mode, "0.8.8.8")
            self.assertTrue(
                OBSERVER.evaluate(good, expected_version="0.8.8.8", receiver=RECEIVER)[
                    "passed"
                ]
            )
            for key, value in (("frame_overruns", 1), ("max_timer_us", None)):
                with self.subTest(mode=mode, key=key):
                    bad = copy.deepcopy(good)
                    bad["samples"][50]["listing"]["modules"][0][key] = value
                    self.assertFalse(
                        OBSERVER.evaluate(
                            bad, expected_version="0.8.8.8", receiver=RECEIVER
                        )["passed"]
                    )
            self.assertFalse(
                OBSERVER.evaluate(good, expected_version="0.8.8.7", receiver=RECEIVER)[
                    "passed"
                ]
            )

    def reject(self, report, reason):
        result = OBSERVER.evaluate(report, receiver=RECEIVER)
        self.assertFalse(result["passed"], result)
        self.assertIn(reason, result["failures"])

    def test_valid_modes_and_measured_results(self):
        for mode in ("module", "baseline"):
            with self.subTest(mode=mode):
                result = OBSERVER.evaluate(fixture(mode), receiver=RECEIVER)
                self.assertTrue(result["passed"], result)
                self.assertAlmostEqual(
                    result["metrics"]["http_coverage"]["max_uncovered_s"], 2
                )

    def test_declared_resource_boundaries_are_inclusive(self):
        report = fixture()
        for row in report["samples"]:
            runtime = row["listing"]["runtime"]
            runtime.update(
                worker_stack_min_free_bytes=4096,
                internal_min_free_bytes=16384,
                internal_largest_free_block=8192,
            )
            row["listing"]["modules"][0]["max_us"] = 10000
        self.assertTrue(OBSERVER.evaluate(report, receiver=RECEIVER)["passed"])

    def test_nonfinite_network_json_is_rejected_before_recording(self):
        for raw in ('{"value": NaN}', '{"value": Infinity}', '{"value": 1e309}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                json.loads(
                    raw,
                    parse_constant=OBSERVER.reject_json_constant,
                    parse_float=OBSERVER.finite_json_float,
                )

    def test_http_redirect_is_never_followed(self):
        handler = OBSERVER.NoRedirect()
        self.assertIsNone(
            handler.redirect_request(None, None, 302, "", {}, "http://example.invalid/")
        )

    def test_explicit_partition_allows_application_only_recovery(self):
        report = fixture("baseline")
        report["expected_partition"] = "ota_1"
        for row in report["samples"]:
            row["status"]["running_partition"] = "ota_1"
        self.assertTrue(OBSERVER.evaluate(report, receiver=RECEIVER)["passed"])
        report["samples"][50]["status"]["running_partition"] = "ota_0"
        self.reject(report, "firmware_or_slot_changed")

    def test_version_selection_is_exact_and_historical_reports_remain_5(self):
        legacy = fixture()
        self.assertNotIn("expected_version", legacy)
        self.assertTrue(OBSERVER.evaluate(legacy, receiver=RECEIVER)["passed"])
        self.assertFalse(
            OBSERVER.evaluate(legacy, expected_version="0.8.8.6", receiver=RECEIVER)[
                "passed"
            ]
        )
        for mode in ("baseline", "module"):
            for version in ("0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8"):
                with self.subTest(mode=mode, version=version):
                    report = fixture(mode, version)
                    report["expected_version"] = version
                    for row in report["samples"]:
                        row["status"]["version"] = version
                    self.assertTrue(
                        OBSERVER.evaluate(
                            report, expected_version=version, receiver=RECEIVER
                        )["passed"]
                    )
                    other = "0.8.8.6" if version == "0.8.8.5" else "0.8.8.5"
                    mismatch = OBSERVER.evaluate(
                        report, expected_version=other, receiver=RECEIVER
                    )
                    self.assertFalse(mismatch["passed"])
                    self.assertIn("expected_version_mismatch", mismatch["failures"])
                    self.assertIn("firmware_or_slot_changed", mismatch["failures"])
                    report["samples"][50]["status"]["version"] = other
                    drift = OBSERVER.evaluate(
                        report, expected_version=version, receiver=RECEIVER
                    )
                    self.assertFalse(drift["passed"])
                    self.assertIn("firmware_or_slot_changed", drift["failures"])
        report = fixture()
        for row in report["samples"]:
            row["status"]["version"] = "0.8.8.6"
        self.assertIn(
            "expected_version_mismatch",
            OBSERVER.evaluate(report, expected_version="0.8.8.6", receiver=RECEIVER)[
                "failures"
            ],
        )
        self.reject(report, "firmware_or_slot_changed")

    def test_unlisted_expected_version_cannot_evaluate_or_observe(self):
        for version in ("0.8.8.4", "0.8.8.9", "0.8.8.60", "latest", None, True):
            with self.subTest(version=version):
                report = fixture()
                report["expected_version"] = version
                for row in report["samples"]:
                    row["status"]["version"] = version
                result = OBSERVER.evaluate(
                    report, expected_version=version, receiver=RECEIVER
                )
                self.assertFalse(result["passed"])
                self.assertIn("invalid_expected_version", result["failures"])
                with self.assertRaisesRegex(ValueError, "invalid_expected_version"):
                    asyncio.run(
                        OBSERVER.observe(
                            315,
                            "baseline",
                            0,
                            "ota_0",
                            "unused",
                            expected_version=version,
                            receiver=RECEIVER,
                            revalidate=lambda: None,
                            collector=COLLECTOR,
                        )
                    )

    def test_7_callback_maxima_are_bounded_and_match_shared_maximum(self):
        for field in ("max_frame_us", "max_timer_us"):
            with self.subTest(field=field):
                report = fixture(version="0.8.8.7")
                for row in report["samples"]:
                    row["listing"]["modules"][0].update({field: 10000, "max_us": 10000})
                self.assertTrue(
                    OBSERVER.evaluate(
                        report, expected_version="0.8.8.7", receiver=RECEIVER
                    )["passed"]
                )
                report["samples"][50]["listing"]["modules"][0].update(
                    {field: 10001, "max_us": 10001}
                )
                result = OBSERVER.evaluate(
                    report, expected_version="0.8.8.7", receiver=RECEIVER
                )
                self.assertFalse(result["passed"])
                self.assertIn("callback_budget_exceeded", result["failures"])
        report = fixture(version="0.8.8.7")
        report["samples"][50]["listing"]["modules"][0]["max_frame_us"] = 499
        self.assertIn(
            "callback_maximum_mismatch",
            OBSERVER.evaluate(report, expected_version="0.8.8.7", receiver=RECEIVER)[
                "failures"
            ],
        )

    def test_7_requires_complete_typed_callback_metrics_in_every_slot(self):
        for mode in ("baseline", "module"):
            for field in (*OBSERVER.CALLBACK_KEYS, "max_us"):
                for value in (None, -1, False, True, 0.0, "0", 1 << 32, "missing"):
                    with self.subTest(mode=mode, field=field, value=value):
                        report = fixture(mode, "0.8.8.7")
                        slot = report["samples"][50]["listing"]["modules"][0]
                        if value == "missing":
                            del slot[field]
                        else:
                            slot[field] = value
                        result = OBSERVER.evaluate(
                            report, expected_version="0.8.8.7", receiver=RECEIVER
                        )
                        self.assertFalse(result["passed"])
                        self.assertIn("callback_metrics_invalid", result["failures"])

    def test_7_cumulative_overrun_cannot_hide_behind_cleared_faults_or_maxima(self):
        for field in ("frame_overruns", "timer_overruns"):
            with self.subTest(field=field):
                report = fixture(version="0.8.8.7")
                report["samples"][50]["listing"]["modules"][0][field] = 1
                result = OBSERVER.evaluate(
                    report, expected_version="0.8.8.7", receiver=RECEIVER
                )
                self.assertFalse(result["passed"])
                self.assertIn("callback_overrun_recorded", result["failures"])

    def test_7_empty_slot_metrics_must_be_zero_in_both_modes(self):
        for mode in ("baseline", "module"):
            with self.subTest(mode=mode):
                report = fixture(mode, "0.8.8.7")
                report["samples"][50]["listing"]["modules"][3].update(
                    max_timer_us=1, max_us=1
                )
                result = OBSERVER.evaluate(
                    report, expected_version="0.8.8.7", receiver=RECEIVER
                )
                self.assertFalse(result["passed"])
                self.assertIn("empty_callback_metrics_nonzero", result["failures"])

    def test_7_detects_split_maximum_reset_hidden_by_shared_maximum(self):
        report = fixture(version="0.8.8.7")
        for row in report["samples"]:
            row["listing"]["modules"][0].update(max_frame_us=400, max_timer_us=500)
        report["samples"][50]["listing"]["modules"][0]["max_frame_us"] = 399
        self.assertIn(
            "callback_telemetry_reset",
            OBSERVER.evaluate(report, expected_version="0.8.8.7", receiver=RECEIVER)[
                "failures"
            ],
        )

    def test_legacy_versions_ignore_new_fields_and_cannot_be_reinterpreted_as_7(self):
        for version in ("0.8.8.5", "0.8.8.6"):
            with self.subTest(version=version):
                report = fixture(version=version)
                original = OBSERVER.evaluate(
                    report, expected_version=version, receiver=RECEIVER
                )
                for row in report["samples"]:
                    row["listing"]["modules"][0].update(
                        max_frame_us=None,
                        max_timer_us=-1,
                        frame_overruns=1,
                        timer_overruns=True,
                    )
                self.assertEqual(
                    OBSERVER.evaluate(
                        report, expected_version=version, receiver=RECEIVER
                    ),
                    original,
                )
                result = OBSERVER.evaluate(
                    report, expected_version="0.8.8.7", receiver=RECEIVER
                )
                self.assertFalse(result["passed"])
                self.assertIn("expected_version_mismatch", result["failures"])
        report = fixture(version="0.8.8.7")
        del report["expected_version"]
        self.assertIn(
            "expected_version_mismatch",
            OBSERVER.evaluate(report, expected_version="0.8.8.7", receiver=RECEIVER)[
                "failures"
            ],
        )

    def test_long_gap_or_missing_endpoints_fail(self):
        for rows in (slice(5, None), slice(None, -5)):
            report = fixture()
            report["samples"] = report["samples"][rows]
            self.reject(report, "http_coverage")
        report = fixture()
        del report["samples"][50:60]
        self.reject(report, "http_coverage")

    def test_short_empty_missing_or_malformed_evidence_fails(self):
        report = fixture()
        report["elapsed_s"] = 304
        self.reject(report, "short_duration")
        report = fixture()
        report["samples"] = []
        self.reject(report, "no_runtime_samples")
        self.assertFalse(OBSERVER.evaluate({}, receiver=RECEIVER)["passed"])

    def test_errors_never_turn_into_success_after_recovery(self):
        for stage in ("http", "websocket_silence", "websocket_connect_or_close"):
            report = fixture()
            report["errors"].append({"stage": stage, "type": "TimeoutError"})
            self.reject(report, "transport_or_capture_error")

    def test_reset_stall_and_false_clock_progression_fail(self):
        for field, value, reason in (
            ("uptime_ms", 1, "uptime_reset_or_stall"),
            ("worker_stack_min_free_bytes", 17000, "low_watermark_reset"),
        ):
            report = fixture()
            report["samples"][60]["listing"]["runtime"][field] = value
            self.reject(report, reason)
        report = fixture()
        for i, row in enumerate(report["samples"]):
            row["listing"]["runtime"]["uptime_ms"] = 100000 + i * 2100
        self.reject(report, "uptime_disagrees_with_elapsed")

    def test_frames_must_advance_and_budget_fault_cannot_hide(self):
        report = fixture()
        report["samples"][60]["listing"]["modules"][0]["frame_count"] = 100
        self.reject(report, "module_frames_reset_or_stall")
        report = fixture()
        # A subsequent frame below 5 ms cleared budget_faults; max_us persists.
        report["samples"][60]["listing"]["modules"][0]["max_us"] = 10001
        self.reject(report, "module_budget_exceeded")

    def test_stack_heap_and_metadata_fail_closed(self):
        for field, value, reason in (
            ("worker_stack_min_free_bytes", 4095, "worker_stack_margin"),
            ("internal_min_free_bytes", 16383, "internal_heap_margin"),
            ("internal_largest_free_block", 8191, "internal_heap_shape_or_block"),
        ):
            report = fixture()
            report["samples"][50]["listing"]["runtime"][field] = value
            self.reject(report, reason)
        report = fixture()
        report["samples"][10]["listing"]["modules"][0]["caps"] = "0x0000"
        self.reject(report, "module_metadata_or_state")
        report = fixture()
        report["samples"][10]["status"]["version"] = "0.8.8.4"
        self.reject(report, "firmware_or_slot_changed")

    def test_negative_stale_nonfinite_boolean_ages_rejected(self):
        for age in (-1, 3001, float("nan"), float("inf"), True):
            report = fixture()
            report["samples"][5]["csi"]["csi_last_seen_ms"] = age
            self.reject(report, "csi_not_fresh")

    def test_csi_u32_wrap_is_forward_but_reset_or_stall_fails(self):
        report = fixture()
        for i, row in enumerate(report["samples"]):
            row["csi"]["csi_sequence"] = (0xFFFFFFF0 + i * 24) & 0xFFFFFFFF
        self.assertTrue(OBSERVER.evaluate(report, receiver=RECEIVER)["passed"])
        report["samples"][20]["csi"]["csi_sequence"] = report["samples"][19]["csi"][
            "csi_sequence"
        ]
        self.reject(report, "csi_sequence_reset_or_stall")

    def test_ws_must_be_live_and_time_bounded(self):
        report = fixture()
        report["ws_updates"] = report["ws_updates"][:10]
        self.reject(report, "ws_coverage")
        for age in (-0.251, 10.001, None, True):
            report = fixture()
            report["ws_updates"][10]["wall_clock_age_s"] = age
            self.reject(report, "ws_timestamp_not_fresh")
        report = fixture()
        report["ws_updates"][10]["tick"] = 0
        self.reject(report, "ws_ticks_reset_or_stall")

    def test_packet_metadata_value_and_time_gate(self):
        report = fixture()
        report["wasm_packets"] = report["wasm_packets"][:1]
        self.reject(report, "wasm_packets_not_observed_in_both_halves")
        for field, value in (("node_id", 1), ("module_id", 3)):
            report = fixture()
            report["wasm_packets"][1][field] = value
            self.reject(report, "wasm_packet_identity")
        for event in (
            {"event_type": 256, "value": 1},
            {"event_type": 2, "value": float("nan")},
        ):
            report = fixture()
            report["wasm_packets"][1]["events"] = [event]
            self.reject(report, "wasm_event_contract")

    def test_baseline_does_not_accept_loaded_module_or_packets(self):
        report = fixture("baseline")
        report["samples"][50]["listing"]["loaded"] = 1
        self.reject(report, "baseline_not_empty")
        report = fixture("baseline")
        report["wasm_packets"] = copy.deepcopy(fixture()["wasm_packets"])
        self.reject(report, "unexpected_wasm_packets_during_baseline")

    def test_nonmonotonic_or_invalid_sample_times_fail(self):
        for t in (-1, 0, float("nan"), True):
            report = fixture()
            report["samples"][10]["received_s"] = t
            self.reject(report, "http_coverage")

    def test_profiles_are_explicit_and_old_reports_keep_original_meaning(self):
        original = fixture()
        self.assertNotIn("package_profile", original)
        self.assertTrue(OBSERVER.evaluate(original, receiver=RECEIVER)["passed"])
        for name in ("home-signal-v2", "home-signal-v3"):
            profile = OBSERVER.get_package(name)
            report = fixture()
            report["package_profile"] = profile.profile
            report["local_package_sha256"] = profile.package_sha256
            for row in report["samples"]:
                row["listing"]["modules"][0].update(
                    name=profile.name, binary_size=profile.wasm_bytes
                )
            self.assertTrue(
                OBSERVER.evaluate(report, profile, receiver=RECEIVER)["passed"]
            )
            self.reject(report, "package_profile_mismatch")
            self.assertFalse(
                OBSERVER.evaluate(original, profile, receiver=RECEIVER)["passed"]
            )
            del report["package_profile"]
            self.assertIn(
                "package_profile_mismatch",
                OBSERVER.evaluate(report, profile, receiver=RECEIVER)["failures"],
            )
            report["package_profile"] = profile.profile
            report["samples"][20]["listing"]["modules"][0]["binary_size"] = 14783
            self.assertIn(
                "module_metadata_or_state",
                OBSERVER.evaluate(report, profile, receiver=RECEIVER)["failures"],
            )
            self.assertTrue(OBSERVER.evaluate(fixture(), receiver=RECEIVER)["passed"])

    def test_disabled_profile_cannot_evaluate_or_start_live_observation(self):
        disabled = replace(OBSERVER.HOME_SIGNAL, package_sha256=None)
        result = OBSERVER.evaluate(fixture(), disabled, receiver=RECEIVER)
        self.assertFalse(result["passed"])
        self.assertIn("package_profile_unavailable", result["failures"])
        with self.assertRaisesRegex(ValueError, "package_profile_unavailable"):
            asyncio.run(
                OBSERVER.observe(
                    315,
                    "module",
                    0,
                    "ota_1",
                    "unused",
                    disabled,
                    receiver=RECEIVER,
                    revalidate=lambda: None,
                    collector=COLLECTOR,
                )
            )

    def test_unavailable_cli_profile_prevents_observation(self):
        argv = [
            "observe",
            "--mode",
            "module",
            "--expect-partition",
            "ota_1",
            "--output",
            "unused-report.json",
            "--package-profile",
            "home-signal-v2",
        ]
        with (
            patch("sys.argv", argv),
            patch.object(
                OBSERVER,
                "load_package",
                side_effect=ValueError("package_profile_unavailable"),
            ),
            patch.object(OBSERVER, "observe") as network,
            patch("sys.stderr"),
        ):
            with self.assertRaises(SystemExit) as exc:
                run_cli(OBSERVER)
            self.assertEqual(exc.exception.code, 2)
            network.assert_not_called()

    def test_cli_default_5_and_explicit_6_reach_observer_and_evaluator(self):
        for version, options in (
            ("0.8.8.5", []),
            ("0.8.8.6", ["--expected-version", "0.8.8.6"]),
            ("0.8.8.7", ["--expected-version", "0.8.8.7"]),
            ("0.8.8.8", ["--expected-version", "0.8.8.8"]),
            ("0.8.8.10", ["--expected-version", "0.8.8.10"]),
            ("0.8.8.11", ["--expected-version", "0.8.8.11"]),
        ):
            with (
                self.subTest(version=version),
                tempfile.TemporaryDirectory() as directory,
            ):
                output = Path(directory) / "report.json"
                report = fixture("baseline", version)
                report["expected_version"] = version
                for row in report["samples"]:
                    row["status"]["version"] = version
                argv = [
                    "observe",
                    "--mode",
                    "baseline",
                    "--expect-partition",
                    "ota_0",
                    "--output",
                    str(output),
                ]
                with (
                    patch("sys.argv", argv + options),
                    patch.dict(os.environ, {"RUVIEW_API_TOKEN": "offline-test-only"}),
                    patch.object(
                        OBSERVER, "observe", new_callable=AsyncMock, return_value=report
                    ) as network,
                    patch("builtins.print"),
                ):
                    self.assertEqual(run_cli(OBSERVER), 0)
                    network.assert_awaited_once()
                    self.assertEqual(
                        network.call_args.kwargs["expected_version"], version
                    )
                saved = json.loads(output.read_text())
                self.assertEqual(saved["expected_version"], version)
                self.assertTrue(saved["assessment"]["passed"])

    def test_cli_unlisted_version_prevents_output_and_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            argv = [
                "observe",
                "--mode",
                "baseline",
                "--expect-partition",
                "ota_0",
                "--output",
                str(output),
                "--expected-version",
                "0.8.8.13",
            ]
            with (
                patch("sys.argv", argv),
                patch.object(OBSERVER, "observe") as network,
                patch("sys.stderr"),
            ):
                with self.assertRaises(SystemExit) as exc:
                    run_cli(OBSERVER)
                self.assertEqual(exc.exception.code, 2)
                network.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
