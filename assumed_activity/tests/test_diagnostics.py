"""Synthetic diagnostic failures; no live requests or recording operations."""

import io
import json
import socket
import unittest
import urllib.error
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from assumed_activity import core, service
from assumed_activity.polling import ReceiverReads, SourceReads
from assumed_activity.tests.helpers import BASE_NS, config, inputs
from assumed_activity.tests.test_polling import ControlledExecutor


class ImmediateExecutor:
    def submit(self, function, *args):
        future = Future()
        try:
            future.set_result(function(*args))
        except Exception as error:
            future.set_exception(error)
        return future


class DiagnosticTests(unittest.TestCase):
    def instance(self, data=None):
        data = data or inputs(0)

        def reader(url, timeout, token):
            index = (
                0 if url.endswith("/health") else 1 if url.endswith("/v1/latest") else 2
            )
            return data[index]

        return service.Service(
            config(),
            "http://collector",
            "http://worker",
            "synthetic-secret",
            MagicMock(connected=True),
            reader,
            source_executor=ImmediateExecutor(),
            expected_coordinate_frame=config()["coordinate_frame"],
        )

    def test_error_classification_never_retains_exception_content(self):
        secret = "DO_NOT_RETAIN_synthetic_token_url_body"
        cases = [
            (TimeoutError(secret), "transport", "timeout"),
            (urllib.error.URLError(TimeoutError(secret)), "transport", "timeout"),
            (socket.gaierror(socket.EAI_AGAIN, secret), "transport", "dns_error"),
            (
                urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, secret)),
                "transport",
                "dns_error",
            ),
            (urllib.error.URLError(secret), "transport", "network_error"),
            (urllib.error.URLError("DNS " + secret), "transport", "network_error"),
            (
                urllib.error.HTTPError("http://" + secret, 403, secret, {}, None),
                "http",
                "http_status",
            ),
            (json.JSONDecodeError(secret, secret, 0), "decode", "invalid_json"),
            (
                UnicodeDecodeError("utf-8", secret.encode(), 0, 1, secret),
                "decode",
                "invalid_encoding",
            ),
            (ValueError("document_too_large"), "body", "document_too_large"),
            (ValueError("duplicate_json_key"), "decode", "duplicate_json_key"),
            (ValueError("source_redirect_refused"), "http", "source_redirect_refused"),
            (ValueError(secret), "read", "unclassified_read_error"),
            (RuntimeError(secret), "read", "unclassified_read_error"),
        ]
        for error, stage, reason in cases:
            with (
                self.subTest(reason=reason),
                patch.object(service.time, "monotonic", side_effect=[2.0, 2.3]),
            ):
                value, detail = service.observed_read(
                    MagicMock(side_effect=error), (), 1.9
                )
            self.assertEqual(value, {})
            self.assertEqual((detail["stage"], detail["reason"]), (stage, reason))
            self.assertEqual(detail["queue_ms"], 100)
            self.assertEqual(detail["request_ms"], 300)
            self.assertNotIn(secret, json.dumps(detail))
            if isinstance(error, urllib.error.HTTPError):
                self.assertEqual(detail["http_status"], 403)

    def test_core_reason_is_exact_private_reset_and_redacted(self):
        producer = core.Producer(
            config(), expected_coordinate_frame=config()["coordinate_frame"]
        )
        bad = inputs(0)
        bad[1]["generated_at_ns"] = str(BASE_NS - 3_000_000_000)
        result = producer.update(*bad)
        self.assertEqual(producer.last_rejection, "stale_or_future_snapshot")
        self.assertEqual(result["reason"], "invalid_or_unavailable_inputs")
        self.assertNotIn("last_rejection", result)
        good = producer.update(*inputs(1))
        self.assertIsNone(producer.last_rejection)
        self.assertEqual(
            good,
            core.Producer(
                config(), expected_coordinate_frame=config()["coordinate_frame"]
            ).update(*inputs(1)),
        )
        for error, expected in [
            (ValueError("secret-input"), "invalid_input_value"),
            (KeyError("secret-key"), "missing_input_field"),
            (TypeError("secret-type"), "invalid_input_type"),
        ]:
            with patch.object(core, "indexed", side_effect=error):
                result = producer.update(*inputs(2))
            self.assertEqual(producer.last_rejection, expected)
            self.assertNotIn("secret", json.dumps(result))

    def test_transport_stage_and_core_rejection_both_preserved(self):
        instance = self.instance()
        original = instance.reader
        instance.reader = lambda url, timeout, token: (
            original(url, timeout, token)
            if not url.endswith("/health")
            else (_ for _ in ()).throw(TimeoutError("synthetic-secret"))
        )
        result = instance.poll_once()
        detail = instance.response("/internal/diagnostics", local=True)[1]["polls"][-1]
        self.assertEqual(result["reason"], "invalid_or_unavailable_inputs")
        self.assertEqual(detail["source_reads"]["worker_health"]["reason"], "timeout")
        self.assertEqual(detail["core_rejection"], "worker_unhealthy")
        self.assertNotIn("synthetic-secret", json.dumps(detail))

    def test_dns_failure_invalidates_source_without_changing_public_contract(self):
        instance = self.instance()
        self.addCleanup(instance.close)
        original = instance.reader

        def reader(url, timeout, token):
            if url.endswith("/health"):
                raise urllib.error.URLError(
                    socket.gaierror(socket.EAI_AGAIN, "synthetic-secret-host")
                )
            return original(url, timeout, token)

        instance.reader = reader
        result = instance.poll_once()
        detail = instance.response("/internal/diagnostics", local=True)[1]["polls"][-1]
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "invalid_or_unavailable_inputs")
        self.assertEqual(detail["source_reads"]["worker_health"]["reason"], "dns_error")
        self.assertEqual(detail["core_rejection"], "worker_unhealthy")
        self.assertEqual(instance.response("/internal/diagnostics")[0], 404)
        self.assertNotIn("dns_error", json.dumps(result))
        self.assertNotIn("synthetic-secret-host", json.dumps(detail))

    def test_late_dns_failure_is_diagnostic_only_and_next_read_can_recover(self):
        for completes_during_wait in (False, True):
            with self.subTest(completes_during_wait=completes_during_wait):
                clock = SimpleNamespace(now=0.0)
                executor = ControlledExecutor()
                failed_reader = MagicMock(
                    side_effect=urllib.error.URLError(
                        socket.gaierror(socket.EAI_AGAIN, "synthetic-secret-host")
                    )
                )

                def wait(
                    _futures,
                    timeout,
                    clock=clock,
                    completes_during_wait=completes_during_wait,
                    executor=executor,
                ):
                    clock.now += timeout
                    if completes_during_wait:
                        clock.now += 0.1
                        executor.finish(0)

                pool = SourceReads(
                    (1,),
                    lambda _url, _timeout, submitted, reader=failed_reader: (
                        service.observed_read(reader, (), submitted)
                    ),
                    executor=executor,
                    clock=lambda clock=clock: clock.now,
                    waiter=wait,
                )
                self.addCleanup(pool.close)
                with patch.object(
                    service.time, "monotonic", side_effect=lambda clock=clock: clock.now
                ):
                    readings, detail = pool.collect({1: "old"}, 2.0, 2.0)
                    self.assertEqual(readings, {1: {}})
                    self.assertEqual(detail["1"]["reason"], "source_phase_deadline")
                    if completes_during_wait:
                        self.assertEqual(
                            detail["1"]["discarded_outcome"],
                            {"outcome": "error", "reason": "dns_error"},
                        )
                    else:
                        clock.now += 0.1
                        executor.finish(0)
                    pool.read = lambda *_args: ({"fresh": True}, {"outcome": "ok"})
                    pool.waiter = lambda *_args, executor=executor, **_kwargs: (
                        executor.finish(1)
                    )
                    readings, detail = pool.collect({1: "new"}, 2.0, 2.0)
                self.assertEqual(readings, {1: {"fresh": True}})
                if not completes_during_wait:
                    self.assertEqual(
                        detail["1"]["discarded_previous_read"]["reason"], "dns_error"
                    )
                self.assertNotIn("synthetic-secret-host", json.dumps(detail))
                self.assertFalse(pool.inflight)

    def test_conflicting_sequence_epoch_reason_is_retained_in_private_diagnostics(self):
        data = inputs(0)
        data[1]["nodes"][0].update(
            node_epoch=2, epoch_reason="sequence_conflict_boot_unknown"
        )
        instance = self.instance(data)
        self.addCleanup(instance.close)
        with (
            patch.object(service.time, "monotonic", return_value=0),
            patch.object(service.time, "time_ns", return_value=BASE_NS),
        ):
            instance.poll_once()
        detail = instance.response("/internal/diagnostics", local=True)[1]["polls"][-1]
        self.assertEqual(
            detail["nodes"][0]["epoch_reason"], "sequence_conflict_boot_unknown"
        )
        self.assertEqual(instance.response("/internal/diagnostics")[0], 404)

    def test_injected_overrun_exposes_age_growth_without_relaxing_expiry(self):
        clock = SimpleNamespace(now=0.0)
        instance = self.instance()
        original = instance.reader

        def reader(*args):
            clock.now += 0.1
            return original(*args)

        def proof_reader(*_args):
            clock.now += 2.3
            return {"not_retained": "synthetic-secret"}

        instance.reader, instance.proof_reader = reader, proof_reader
        # Force a hypothetical scheduler overrun; this tests the final age guard,
        # not the production pool deadline (covered by test_polling).
        instance.receiver_reads.close()

        def overrun(*_args):
            reading, detail = service.observed_read(
                service.timed_receiver, (proof_reader, "http://receiver", 1), clock.now
            )
            return {1: reading}, {"1": detail}

        instance.receiver_reads = SimpleNamespace(collect=overrun)
        instance.proofs = SimpleNamespace(
            requests=lambda *_: {1: "http://receiver"}, resolve=lambda *_: {}
        )
        with (
            patch.object(service.time, "monotonic", side_effect=lambda: clock.now),
            patch.object(
                service.time,
                "time_ns",
                side_effect=lambda: BASE_NS + int(clock.now * 1e9),
            ),
        ):
            result = instance.poll_once()
        detail = instance.response("/internal/diagnostics", local=True)[1]["polls"][-1]
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(detail["core_rejection"], "stale_or_future_snapshot")
        self.assertAlmostEqual(detail["source_age_before_proofs_ms"]["worker_ms"], 300)
        self.assertAlmostEqual(
            detail["source_age_at_evaluation_ms"]["worker_ms"], 2600, places=5
        )
        self.assertAlmostEqual(detail["proof_reads"]["1"]["request_ms"], 2300)
        self.assertEqual(detail["source_reads"]["worker_latest"]["outcome"], "ok")
        self.assertEqual(instance.producer.policy["max_source_age_ms"], 2500)
        self.assertFalse(instance.producer.history)

    def test_bounded_history_local_only_and_no_public_payload_change(self):
        data = inputs(0)
        data[1]["clock_id"] = "synthetic-secret-context"
        instance = self.instance(data)
        for _ in range(40):
            with (
                patch.object(service.time, "monotonic", return_value=0),
                patch.object(service.time, "time_ns", return_value=BASE_NS),
            ):
                instance.poll_once()
        status, detail = instance.response("/internal/diagnostics", local=True)
        self.assertEqual(status, 200)
        self.assertEqual(len(detail["polls"]), 32)
        self.assertEqual(detail["counters"]["polls"], 40)
        self.assertEqual(detail["polls"][0]["poll_count"], 9)
        self.assertEqual(instance.response("/internal/diagnostics")[0], 404)
        self.assertNotIn("synthetic-secret", json.dumps(detail))
        self.assertLess(len(json.dumps(detail)), 100_000)
        detail["polls"].clear()
        self.assertEqual(len(instance.diagnostic_history), 32)
        self.assertNotIn("diagnostics", instance.publisher.publish.call_args.args[0])
        self.assertEqual(
            set(instance.response("/health")[1]),
            {
                "status",
                "poll_count",
                "poll_age_seconds",
                "mqtt_connected",
                "recognition_validated",
            },
        )
        instance.diagnostic_counts["polls"] = service.MAX_COUNTER
        with (
            patch.object(service.time, "monotonic", return_value=0),
            patch.object(service.time, "time_ns", return_value=BASE_NS),
        ):
            instance.poll_once()
        self.assertEqual(instance.diagnostic_counts["polls"], service.MAX_COUNTER)

    def test_full_deadline_history_with_maximum_pool_sizes_fits_document_cap(self):
        clock = SimpleNamespace(now=0.0)
        executor = ControlledExecutor()
        pool = ReceiverReads(
            range(16),
            lambda *_: (
                {"payload": "synthetic-secret"},
                {"outcome": "error", "reason": "timeout", "url": "synthetic-secret"},
            ),
            executor=executor,
            clock=lambda: clock.now,
            waiter=lambda _futures, timeout: setattr(clock, "now", clock.now + timeout),
        )
        self.addCleanup(pool.close)
        requests = {i: "http://synthetic-secret/" for i in range(16)}
        pool.collect(requests, 1.0, 1.2)
        clock.now += 0.1
        for index in range(16):
            executor.finish(index)
        readings, detail = pool.collect(requests, 1.0, 1.2)
        self.assertTrue(all(value == {} for value in readings.values()))
        self.assertEqual(len(detail), 16)
        self.assertTrue(all("deadline_progress" in row for row in detail.values()))
        self.assertTrue(
            all("discarded_previous_read" in row for row in detail.values())
        )
        self.assertTrue(
            all(
                row["discarded_previous_read"]["reason"] == "timeout"
                for row in detail.values()
            )
        )

        instance = self.instance()
        self.addCleanup(instance.close)
        # Both pools at their generic 16-endpoint maximum is more conservative
        # than the deployed three source plus three receiver endpoints.
        for index in range(40):
            values = inputs(index)
            result = instance.producer.update(*values)
            instance.poll_count += 1
            with patch.object(service.time, "monotonic", return_value=float(index)):
                instance.record_diagnostics(
                    result,
                    detail,
                    detail,
                    {},
                    values[:3],
                    index,
                    index,
                    index,
                    index,
                )
        status, body = instance.response("/internal/diagnostics", local=True)
        encoded = json.dumps(body).encode()
        self.assertEqual(status, 200)
        self.assertEqual(len(body["polls"]), service.DIAGNOSTIC_HISTORY)
        self.assertLess(len(encoded), service.MAX_DOCUMENT)
        self.assertNotIn(b"synthetic-secret", encoded)
        self.assertEqual(instance.response("/internal/diagnostics")[0], 404)

    def test_gap_rebuild_has_bounded_diagnostic_context(self):
        instance = self.instance()
        for index in (0, 1, 2, 3, 20):
            instance.reader = self.instance(inputs(index)).reader
            with (
                patch.object(service.time, "monotonic", return_value=float(index)),
                patch.object(
                    service.time, "time_ns", return_value=BASE_NS + index * 10**9
                ),
            ):
                result = instance.poll_once()
        detail = instance.response("/internal/diagnostics", local=True)[1]["polls"][-1]
        self.assertEqual(result["state"], "warming_up")
        for node in detail["nodes"]:
            self.assertEqual(node["accepted_gap_ms"], 17000)
            self.assertTrue(node["history_rebuilt"])
            self.assertEqual(node["baseline_samples"], 0)
        self.assertEqual(len(detail["worker_context_sha256"]), 64)

    def test_http_handler_does_not_trust_forwarded_loopback_identity(self):
        instance = self.instance()
        handler_class = service.handler_for(instance)
        for peer, expected in (("10.42.1.7", 404), ("127.0.0.1", 200), ("::1", 200)):
            handler = object.__new__(handler_class)
            handler.path = "/internal/diagnostics"
            handler.client_address = (peer, 1234)
            handler.headers = {"X-Forwarded-For": "127.0.0.1"}
            handler.wfile = io.BytesIO()
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            handler.do_GET()
            handler.send_response.assert_called_once_with(expected)
            if expected == 404:
                self.assertEqual(
                    json.loads(handler.wfile.getvalue()), {"error": "not_found"}
                )


if __name__ == "__main__":
    unittest.main()
