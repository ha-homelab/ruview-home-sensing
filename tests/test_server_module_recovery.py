"""Synthetic recovery observations only; no worker, sockets, MQTT or devices."""

import copy
import gzip
import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import module_observations as modules

SPEC = importlib.util.spec_from_file_location(
    "recovery_observer",
    Path(__file__).resolve().parents[1] / "scripts/observe-server-modules.py",
)
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


def snapshot(index, *, epoch=1, reason="first_frame", running=True, missing=0):
    mono = 10_000_000_000 + index * 1_000_000_000
    utc = 1_790_000_000_000_000_000 + mono
    return {
        "schema": "ruview.server-modules.v1",
        "worker_run_id": "synthetic-run",
        "clock_id": "synthetic-boot/synthetic-run",
        "configuration_sha256": "a" * 64,
        "generated_at_ns": str(utc + 10_000_000),
        "monotonic_origin": "worker_start",
        "recognition_validated": False,
        "freshness_limit_ms": 2000,
        "catalog_count": 64,
        "selected_algorithm_count": 20,
        "events": [],
        "counters": {
            **dict.fromkeys(observer.COUNTERS, 0),
            "received": 3 * (100 + index * 32),
        },
        "nodes": [
            {
                "node_id": n,
                "node_epoch": epoch,
                "epoch_reason": reason,
                "sequence": 100 + index * 32,
                "fresh": True,
                "age_ms": 10,
                "last_received_monotonic_ns": str(mono),
                "last_received_at_ns": str(utc),
                "grid": {
                    "antennas": 1,
                    "subcarriers": 64,
                    "frequency_mhz": 2462,
                    "ppdu_type": 0,
                    "flags": 16,
                },
                "frames": 100 + index * 32 - missing,
                "duplicates": 0,
                "missing_sequences": missing,
                "sequence_discontinuities": 0,
                "algorithms": [
                    {
                        "algorithm": f"synthetic-{a}",
                        "algorithm_version": "synthetic1",
                        "source_sha256": "b" * 64,
                        "availability": ("running" if running else "warming_up")
                        if a < 20
                        else "unavailable",
                        "reason": "synthetic_fixture_only",
                        "processed_frames": index + 1,
                        "emitted_events": 0,
                        "max_execution_us": 5,
                    }
                    for a in range(64)
                ],
            }
            for n in (1, 2, 3)
        ],
    }


def current(value):
    return modules.current(
        modules.decode(value, int(value["generated_at_ns"])),
        0,
        {n: {"csi_age_ms": 10, "inference_age_ms": 10} for n in (1, 2, 3)},
    )


class RecoveryTests(unittest.TestCase):
    def push(self, assessment, value):
        return assessment.push(value, current(value))

    def test_next_selection_is_explicit_and_current_twenty_remains_default(self):
        self.push(observer.Assessment([1, 2, 3]), snapshot(0))
        next_snapshot = snapshot(0)
        next_snapshot["selected_algorithm_count"] = 21
        with self.assertRaisesRegex(observer.GateError, "Wrong adapters"):
            self.push(observer.Assessment([1, 2, 3]), next_snapshot)
        assessment = observer.Assessment([1, 2, 3], expected_selected_count=21)
        self.push(assessment, next_snapshot)
        with self.assertRaisesRegex(observer.GateError, "Wrong adapters"):
            self.push(assessment, snapshot(1))
        for bad in (True, 0, 22):
            with self.subTest(expected=bad), self.assertRaises(observer.GateError):
                observer.Assessment([1, 2, 3], expected_selected_count=bad)

    def test_stable_fleet_and_sequence_wrap_preserve_sync_metadata(self):
        assessment = observer.Assessment([1, 2, 3])
        for index in range(3):
            value = snapshot(index)
            for node in value["nodes"]:
                node["sequence"] = (2**32 - 10 + index * 32) % 2**32
                node["grid"]["flags"] = 0 if index % 2 else 16
            self.push(assessment, value)
        report = assessment.finish()
        self.assertTrue(report["operational_readiness_observed"])
        self.assertFalse(report["operational_recovery_observed"])
        self.assertTrue(report["continuity_passed"])
        self.assertFalse(report["recognition_validated"])
        self.assertFalse(report["unobserved_transitions_verified"])

    def test_allowed_gap_recovers_but_never_becomes_continuous(self):
        assessment = observer.Assessment([1, 2, 3])
        self.push(assessment, snapshot(0))
        row = self.push(
            assessment,
            snapshot(1, epoch=2, reason="sequence_gap", running=False, missing=1),
        )
        self.assertEqual(
            row["nodes"]["2"]["observed_recovery_transition"], "sequence_gap"
        )
        self.push(assessment, snapshot(2, epoch=2, reason="sequence_gap", missing=1))
        with self.assertRaisesRegex(observer.GateError, "two advancing"):
            assessment.finish()
        self.push(assessment, snapshot(3, epoch=2, reason="sequence_gap", missing=1))
        report = assessment.finish()
        self.assertTrue(report["operational_recovery_observed"])
        self.assertFalse(report["continuity_passed"])
        self.assertEqual(report["observed_gap_recoveries"], {"1": 1, "2": 1, "3": 1})

    def test_receipt_gap_requires_new_running_evidence(self):
        assessment = observer.Assessment([1, 2, 3])
        self.push(assessment, snapshot(0))
        self.push(assessment, snapshot(4, epoch=2, reason="receipt_gap", running=False))
        self.push(assessment, snapshot(5, epoch=2, reason="receipt_gap"))
        self.push(assessment, snapshot(6, epoch=2, reason="receipt_gap"))
        self.assertFalse(assessment.finish()["continuity_passed"])

    def test_duplicate_growth_preserves_readiness_but_never_continuity(self):
        assessment = observer.Assessment([1, 2, 3])
        self.push(assessment, snapshot(0))
        for index in (1, 2):
            value = snapshot(index)
            value["nodes"][0]["duplicates"] = 1
            self.push(assessment, value)
        report = assessment.finish()
        self.assertTrue(report["operational_readiness_observed"])
        self.assertFalse(report["operational_recovery_observed"])
        self.assertFalse(report["continuity_passed"])
        self.assertFalse(report["recognition_validated"])

    def test_clock_grid_backwards_hidden_epochs_and_worker_change_fail(self):
        base = snapshot(1)
        variants = []
        for reason in (
            "receipt_clock_discontinuity",
            "grid_changed",
            "sequence_backwards_boot_unknown",
            "sequence_conflict_boot_unknown",
        ):
            item = copy.deepcopy(base)
            item["nodes"][0].update(node_epoch=2, epoch_reason=reason)
            variants.append(item)
        item = copy.deepcopy(base)
        item["nodes"][0].update(
            node_epoch=3, epoch_reason="sequence_gap", missing_sequences=1
        )
        variants.append(item)
        item = copy.deepcopy(base)
        item["nodes"][0]["sequence"] = 99
        variants.append(item)
        item = copy.deepcopy(base)
        item["nodes"][0]["grid"]["frequency_mhz"] = 2412
        variants.append(item)
        for key in ("worker_run_id", "clock_id", "configuration_sha256"):
            item = copy.deepcopy(base)
            item[key] = "c" * 64
            variants.append(item)
        for index, value in enumerate(variants):
            with self.subTest(variant=index):
                assessment = observer.Assessment([1, 2, 3])
                self.push(assessment, snapshot(0))
                with self.assertRaises(observer.GateError):
                    self.push(assessment, value)

    def test_stale_fault_and_closing_warmup_cannot_pass(self):
        for change in ("stale", "fault", "missing", "duplicate"):
            with self.subTest(change=change):
                assessment = observer.Assessment([1, 2, 3])
                value = snapshot(0)
                if change == "stale":
                    value["nodes"][0]["age_ms"] = 2001
                elif change == "fault":
                    value["nodes"][0]["algorithms"][0]["availability"] = "faulted"
                elif change == "missing":
                    value["nodes"].pop()
                else:
                    value["nodes"].append(copy.deepcopy(value["nodes"][0]))
                with self.assertRaises(ValueError):
                    self.push(assessment, value)
        assessment = observer.Assessment([1, 2, 3])
        for index in range(2):
            self.push(assessment, snapshot(index))
        self.push(assessment, snapshot(2, running=False))
        with self.assertRaisesRegex(observer.GateError, "closing running"):
            assessment.finish()

    def test_repeated_cached_sample_is_not_new_running_evidence(self):
        assessment = observer.Assessment([1, 2, 3])
        value = snapshot(0)
        self.push(assessment, value)
        self.push(assessment, value)
        with self.assertRaisesRegex(observer.GateError, "two advancing"):
            assessment.finish()

    def test_unexplained_lost_frames_and_inconsistent_receipt_gap_fail(self):
        for mismatch in ("frame_count", "receipt_gap_missing"):
            with self.subTest(mismatch=mismatch):
                assessment = observer.Assessment([1, 2, 3])
                self.push(assessment, snapshot(0))
                value = (
                    snapshot(4, epoch=2, reason="receipt_gap", missing=1)
                    if mismatch == "receipt_gap_missing"
                    else snapshot(1)
                )
                if mismatch == "frame_count":
                    value["nodes"][1]["frames"] = 101
                with self.assertRaises(observer.GateError):
                    self.push(assessment, value)

    def test_failed_preflight_emits_safe_report(self):
        out = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.argv", ["observe"]),
            redirect_stdout(out),
        ):
            code = observer.main()
        report = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertFalse(report["operational_recovery_observed"])
        self.assertFalse(report["recognition_validated"])
        self.assertEqual(report["samples"], [])


class HTTPTests(unittest.TestCase):
    def test_get_is_bounded_get_only_no_redirect_and_token_is_scoped(self):
        instances = []

        class Response:
            status = 200
            length = len(b'{"status":"ok"}')

            def read1(self, _limit):
                return b'{"status":"ok"}'

            def isclosed(self):
                return True

            def getheader(self, _name):
                return None

        class Connection:
            def __init__(self, host, port, timeout):
                self.host, self.timeout = host, timeout
                self.sock = self
                self.response = Response()
                self.requests = []
                instances.append(self)

            def connect(self):
                pass

            def settimeout(self, timeout):
                assert 0 < timeout <= 3

            def request(self, method, path, headers):
                self.requests.append((method, path, headers))

            def getresponse(self):
                return self.response

            def close(self):
                self.closed = True

        with patch.object(observer.http.client, "HTTPConnection", Connection):
            for token in ("synthetic-secret", None):
                stamps = []
                result = observer.get(
                    "http://worker:5016",
                    "/v1/latest",
                    token,
                    observer.time.monotonic() + 10,
                    stamps,
                )
                self.assertEqual(result["status"], "ok")
                self.assertEqual(stamps[0]["endpoint"], "/v1/latest")
            self.assertEqual(
                instances[0].requests,
                [("GET", "/v1/latest", {"Authorization": "Bearer synthetic-secret"})],
            )
            self.assertEqual(instances[1].requests, [("GET", "/v1/latest", {})])
            self.assertTrue(all(x.closed for x in instances))
            Response.length += 1
            truncated_stamps = []
            with self.assertRaisesRegex(observer.GateError, "truncated"):
                observer.get(
                    "http://worker",
                    "/v1/latest",
                    None,
                    observer.time.monotonic() + 10,
                    truncated_stamps,
                )
            self.assertEqual(truncated_stamps[0]["response_bytes"], Response.length - 1)
            self.assertEqual(
                truncated_stamps[0]["declared_response_bytes"], Response.length
            )
            self.assertTrue(instances[-1].closed)
            Response.status = 302
            with self.assertRaisesRegex(observer.GateError, "not 200"):
                observer.get(
                    "http://worker",
                    "/v1/latest",
                    None,
                    observer.time.monotonic() + 10,
                    [],
                )
            self.assertEqual(len(instances[-1].requests), 1)
            self.assertTrue(instances[-1].closed)

    @staticmethod
    def encoded_connection(raw, encoding, declared=None):
        response = Mock(status=200, length=len(raw) if declared is None else declared)
        response.read1.return_value = raw
        response.isclosed.return_value = True
        response.getheader.return_value = encoding
        connection = Mock()
        connection.getresponse.return_value = response
        return connection

    def test_optional_gzip_preserves_wire_length_and_reports_decoded_length(self):
        raw = gzip.compress(b'{"status":"ok"}', mtime=0)
        connection = self.encoded_connection(raw, "gzip")
        stamps = []
        with patch.object(
            observer.http.client, "HTTPConnection", return_value=connection
        ):
            result = observer.get(
                "http://worker:5016",
                "/health",
                None,
                observer.time.monotonic() + 10,
                stamps,
                accept_gzip=True,
            )
        self.assertEqual(result, {"status": "ok"})
        connection.request.assert_called_once_with(
            "GET", "/health", headers={"Accept-Encoding": "gzip"}
        )
        self.assertEqual(stamps[0]["declared_response_bytes"], len(raw))
        self.assertEqual(stamps[0]["response_bytes"], len(raw))
        self.assertEqual(stamps[0]["decoded_response_bytes"], len(b'{"status":"ok"}'))
        self.assertEqual(stamps[0]["content_encoding"], "gzip")
        connection.close.assert_called_once()

    def test_wire_truncation_fails_before_gzip_decode(self):
        raw = gzip.compress(b'{"status":"ok"}', mtime=0)
        connection = self.encoded_connection(raw, "gzip", declared=len(raw) + 1)
        with (
            patch.object(
                observer.http.client, "HTTPConnection", return_value=connection
            ),
            patch.object(observer, "decode_http_body") as decode,
            self.assertRaisesRegex(observer.GateError, "truncated"),
        ):
            observer.get(
                "http://worker", "/health", None, observer.time.monotonic() + 10, []
            )
        decode.assert_not_called()
        connection.close.assert_called_once()

    def test_gzip_decode_cannot_bypass_body_limit_or_strict_json(self):
        cases = [
            (gzip.compress(b'"' + b"x" * 1000 + b'"'), "gzip", "compressed body"),
            (gzip.compress(b"{}")[:-1], "gzip", "compressed body"),
            (gzip.compress(b"{}") + b"trailing", "gzip", "compressed body"),
            (b"{}", "br", "compressed body"),
            (gzip.compress(b'{"x":1,"x":2}'), "gzip", "Duplicate JSON key"),
        ]
        for raw, encoding, error in cases:
            with self.subTest(encoding=encoding, error=error):
                connection = self.encoded_connection(raw, encoding)
                with (
                    patch.object(
                        observer.http.client, "HTTPConnection", return_value=connection
                    ),
                    patch.object(observer.modules, "MAX_RESPONSE_BYTES", 64),
                    self.assertRaisesRegex(observer.GateError, error),
                ):
                    observer.get(
                        "http://worker",
                        "/health",
                        None,
                        observer.time.monotonic() + 10,
                        [],
                        accept_gzip=True,
                    )
                connection.close.assert_called_once()

    def test_decode_time_remains_inside_original_request_deadline(self):
        connection = self.encoded_connection(b"{}", None)
        clock = [0.0]

        def delayed_decode(*_args):
            clock[0] = 3.1
            return b"{}"

        with (
            patch.object(
                observer.http.client, "HTTPConnection", return_value=connection
            ),
            patch.object(observer.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(observer, "decode_http_body", side_effect=delayed_decode),
            self.assertRaisesRegex(observer.GateError, "deadline exceeded"),
        ):
            observer.get("http://worker", "/health", None, 10, [])
        connection.close.assert_called_once()

    def test_nonfinite_json_including_exponent_overflow_is_rejected(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e309}'):
            with self.subTest(raw=raw), self.assertRaises(observer.GateError):
                observer.strict_json(raw)


if __name__ == "__main__":
    unittest.main()
