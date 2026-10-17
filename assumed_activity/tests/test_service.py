import gzip
import json
import os
import threading
import unittest
from unittest.mock import MagicMock, patch

from assumed_activity import service
from assumed_activity.core import Producer
from assumed_activity.tests.helpers import BASE_NS, config, inputs
from assumed_activity.tests.test_polling import ControlledExecutor


class ResponseClockTests(unittest.TestCase):
    def ready_service(self):
        # Exercise the real response/core path without starting I/O executors.
        instance = object.__new__(service.Service)
        instance.producer = Producer(
            config(), expected_coordinate_frame=config()["coordinate_frame"]
        )
        for index in range(4):
            instance.producer.update(*inputs(index))
        instance.lock = threading.Lock()
        instance.last_completed = 3.0
        instance.started = 0.0
        instance.stop = threading.Event()
        instance.poll_count = 4
        instance.publisher = MagicMock(connected=True)
        return instance

    def test_reader_uses_clock_after_concurrent_publication_before_lock_entry(self):
        class PublishBeforeEntry:
            def __init__(self, instance, clock):
                self.instance = instance
                self.clock = clock

            def __enter__(self):
                # The poller finishes after the reader starts but before
                # it acquires the lock. New state has a newer timestamp.
                self.clock[0] = 4.0
                self.instance.producer.update(*inputs(4))
                self.instance.last_completed = 4.0
                self.instance.poll_count = 5

            def __exit__(self, *_args):
                return False

        for path in ("/health", "/v1/activity"):
            with self.subTest(path=path):
                instance = self.ready_service()
                clock = [3.0]
                instance.lock = PublishBeforeEntry(instance, clock)
                with (
                    patch.object(
                        service.time,
                        "monotonic",
                        side_effect=lambda value=clock: value[0],
                    ),
                    patch.object(
                        service.time,
                        "time_ns",
                        side_effect=lambda value=clock: BASE_NS + int(value[0] * 1e9),
                    ),
                ):
                    status, body = instance.response(path)
                self.assertEqual(status, 200)
                if path == "/health":
                    self.assertEqual(body["status"], "ok")
                    self.assertEqual(body["poll_age_seconds"], 0)
                    self.assertEqual(body["poll_count"], 5)
                else:
                    self.assertEqual(body["state"], "quiet")
                    self.assertEqual(body, instance.producer.last)

    def test_health_keeps_exact_stall_limit_and_rejects_backward_clock(self):
        instance = self.ready_service()
        for mono, expected in ((33.0, 200), (33.000001, 503), (2.999, 503)):
            with (
                self.subTest(mono=mono),
                patch.object(service.time, "monotonic", return_value=mono),
                patch.object(
                    service.time, "time_ns", return_value=BASE_NS + int(mono * 1e9)
                ),
            ):
                self.assertEqual(instance.response("/health")[0], expected)
        self.assertEqual(instance.last_completed, 3.0)

    def test_activity_keeps_source_expiry_and_backward_clock_checks(self):
        instance = self.ready_service()
        original = instance.producer.last
        expires = int(original["expires_at_ns"])
        before = expires - 1
        for wall, mono, expected in (
            (before, (before - BASE_NS) / 1e9, "quiet"),
            (expires, (expires - BASE_NS) / 1e9, "unknown"),
            (int(original["generated_at_ns"]) - 1, 3.0, "unknown"),
            (int(original["generated_at_ns"]), 2.999, "unknown"),
        ):
            with (
                self.subTest(wall=wall, mono=mono),
                patch.object(service.time, "time_ns", return_value=wall),
                patch.object(service.time, "monotonic", return_value=mono),
            ):
                status, body = instance.response("/v1/activity")
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], expected)
            self.assertEqual(body["expires_at_ns"], original["expires_at_ns"])
        self.assertEqual(instance.producer.last, original)


class ServiceTests(unittest.TestCase):
    def test_http_bind_preserves_default_and_accepts_explicit_loopback(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(service.http_bind(), ("0.0.0.0", 5017))
        with patch.dict(
            os.environ,
            {
                "ASSUMED_ACTIVITY_BIND_ADDRESS": "127.0.0.1",
                "ASSUMED_ACTIVITY_HTTP_PORT": "15017",
            },
            clear=True,
        ):
            self.assertEqual(service.http_bind(), ("127.0.0.1", 15017))

    def test_invalid_bind_is_rejected_before_clients_or_network_are_created(self):
        for address in (
            "localhost",
            "::1",
            "127.0.0.1/8",
            "127.1",
            "127.000.0.1",
            " 127.0.0.1",
            "239.1.2.3",
            "255.255.255.255",
            "",
        ):
            with (
                self.subTest(address=address),
                patch.dict(
                    os.environ, {"ASSUMED_ACTIVITY_BIND_ADDRESS": address}, clear=True
                ),
                patch.object(service, "Service") as producer,
                patch.object(service, "ThreadingHTTPServer") as server,
                self.assertRaisesRegex(ValueError, "^invalid_http_bind_address$"),
            ):
                try:
                    service.main()
                finally:
                    producer.assert_not_called()
                    server.assert_not_called()
        for port in ("0", "65536", "-1", "not-a-port"):
            with (
                self.subTest(port=port),
                patch.dict(
                    os.environ, {"ASSUMED_ACTIVITY_HTTP_PORT": port}, clear=True
                ),
                self.assertRaises(ValueError),
            ):
                service.http_bind()

    def test_stalled_source_does_not_stall_publication_or_queue_new_reads(self):
        clock = [0.0]
        executor = ControlledExecutor()
        data = inputs(0)

        def reader(url, *_):
            return data[
                0 if url.endswith("/health") else 1 if url.endswith("/v1/latest") else 2
            ]

        publisher = MagicMock(connected=True)
        instance = service.Service(
            config(),
            "http://collector",
            "http://worker",
            "synthetic-token",
            publisher,
            reader,
            source_executor=executor,
            expected_coordinate_frame=config()["coordinate_frame"],
        )
        self.addCleanup(instance.close)
        instance.source_reads.clock = lambda: clock[0]

        def finish_healthy(_futures, timeout):
            for index, (future, _fn, args) in enumerate(executor.jobs):
                if not future.done() and not args[0][0].endswith("/v1/latest"):
                    executor.finish(index)
            clock[0] += timeout

        instance.source_reads.waiter = finish_healthy
        with (
            patch.object(service.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                service.time,
                "time_ns",
                side_effect=lambda: BASE_NS + int(clock[0] * 1e9),
            ),
        ):
            for _ in range(3):
                result = instance.poll_once()
                self.assertEqual(result["state"], "unknown")
                self.assertEqual(instance.response("/health")[0], 200)
            self.assertEqual(instance.poll_count, 3)
            self.assertEqual(publisher.publish.call_count, 3)
            self.assertEqual(
                len(executor.jobs), 7
            )  # 3 initially, then 2 healthy sources per poll.
            detail = instance.diagnostic_history[-1]
            self.assertEqual(
                detail["source_reads"]["worker_latest"]["reason"],
                "previous_source_request_pending",
            )
            self.assertEqual(set(instance.source_reads.inflight), {"worker_latest"})
            # Completing the old read must not make a new poll consume stale data.
            executor.jobs[1][0].set_result(
                ({"stale_marker": True}, {"outcome": "ok"}, 0.0)
            )
            result = instance.poll_once()
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(len(executor.jobs), 10)
            self.assertEqual(
                instance.diagnostic_history[-1]["source_reads"]["worker_latest"][
                    "reason"
                ],
                "source_phase_deadline",
            )
        self.assertFalse(instance.producer.history)
        self.assertEqual(instance.producer.policy["max_source_age_ms"], 2500)

    def test_strict_bounded_json_and_urls(self):
        for raw in (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b"[]",
            b" " * (service.MAX_DOCUMENT + 1),
        ):
            with self.assertRaises(ValueError):
                service.document(raw)
        for url in (
            "http://user:key@host",
            "http://host/path",
            "file:///etc/passwd",
            "http://host#x",
        ):
            with self.assertRaises(ValueError):
                service.base_url(url)
        self.assertEqual(
            service.base_url("http://collector:3000/"), "http://collector:3000"
        )
        with self.assertRaises(ValueError):
            service.NoRedirect().redirect_request(
                None, None, 302, "", {}, "http://other"
            )

    def test_get_auth_shape_bounded_response(self):
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = b'{"status":"ok"}'
        response.getheader.return_value = None
        with patch.object(service.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(
                service.read_json(
                    "http://collector/api/v1/sensing/latest", 2, "synthetic-token"
                ),
                {"status": "ok"},
            )
        request = opener.open.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")
        self.assertEqual(request.get_header("Accept-encoding"), "gzip")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 2})
        response.read.assert_called_once_with(service.MAX_DOCUMENT + 1)

    def test_get_decodes_gzip_with_existing_bound_and_strict_json(self):
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.getheader.return_value = "gzip"
        with patch.object(service.urllib.request, "build_opener", return_value=opener):
            response.read.return_value = gzip.compress(b' {"status":"ok"}\n')
            self.assertEqual(
                service.read_json("http://worker/v1/latest", 2, max_document=64),
                {"status": "ok"},
            )
            response.read.assert_called_with(65)
            response.read.return_value = gzip.compress(b" " * 65)
            with self.assertRaisesRegex(ValueError, "^document_too_large$"):
                service.read_json("http://worker/v1/latest", 2, max_document=64)
            response.read.return_value = gzip.compress(b'{"x":1,"x":2}')
            with self.assertRaisesRegex(ValueError, "^duplicate_json_key$"):
                service.read_json("http://worker/v1/latest", 2, max_document=64)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Accept-encoding"), "gzip")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 2})

    def test_gzip_failures_remain_fixed_diagnostic_codes(self):
        for reason in ("unsupported_content_encoding", "invalid_gzip_body"):
            with self.subTest(reason=reason):
                self.assertEqual(
                    service.read_failure(ValueError(reason)), ("decode", reason)
                )

    def test_poll_endpoints_token_separation_and_liveness(self):
        data = inputs(0)
        seen = []

        def reader(url, timeout, token):
            seen.append((url, token))
            return (
                data[0]
                if url.endswith("/health")
                else data[1]
                if url.endswith("/v1/latest")
                else data[2]
            )

        publisher = MagicMock(connected=True)
        instance = service.Service(
            config(),
            "http://collector:3000",
            "http://worker:5016",
            "synthetic-token",
            publisher,
            reader,
            expected_coordinate_frame=config()["coordinate_frame"],
        )
        self.addCleanup(instance.close)
        with (
            patch.object(service.time, "time_ns", return_value=BASE_NS),
            patch.object(service.time, "monotonic", return_value=0),
        ):
            result = instance.poll_once()
            self.assertEqual(result["state"], "warming_up")
            self.assertEqual(instance.response("/health")[0], 200)
            self.assertEqual(instance.response("/v1/activity")[1], result)
        self.assertCountEqual(
            seen,
            [
                ("http://worker:5016/health", None),
                ("http://worker:5016/v1/latest", None),
                ("http://collector:3000/api/v1/sensing/latest", "synthetic-token"),
            ],
        )
        instance.reader = MagicMock(side_effect=TimeoutError("not logged"))
        result = instance.poll_once()
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(instance.response("/health")[0], 200)
        publisher.publish.assert_called()
        with patch.object(
            service.time, "monotonic", return_value=instance.last_completed + 31
        ):
            self.assertEqual(instance.response("/health")[0], 503)

    def test_mqtt_coherence_retention_and_disconnect(self):
        client = MagicMock()
        publisher = service.Publisher(
            client,
            Producer(
                config(), expected_coordinate_frame=config()["coordinate_frame"]
            ).policy,
        )
        client.will_set.assert_called_once_with(
            service.AVAILABILITY, "offline", qos=1, retain=True
        )
        publisher.on_connect(client, None, None, 0)
        configuration = json.loads(client.publish.call_args_list[0].args[1])
        self.assertEqual(
            configuration["state_topic"], configuration["json_attributes_topic"]
        )
        self.assertIn("expires_at_ns", configuration["value_template"])
        self.assertEqual(configuration["unique_id"], "ruview_assumed_zone_activity")
        self.assertEqual(
            configuration["default_entity_id"], "sensor.ruview_assumed_zone_activity"
        )
        self.assertNotIn("object_id", configuration)
        client.publish.reset_mock()
        envelope = Producer(
            config(), expected_coordinate_frame=config()["coordinate_frame"]
        ).update(*inputs(0))
        publisher.publish(envelope)
        calls = client.publish.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].args[1], calls[1].args[1])
        self.assertTrue(all(c.kwargs == {"qos": 0, "retain": False} for c in calls))
        publisher.on_disconnect(client, None, None, 1)
        client.publish.reset_mock()
        publisher.publish(envelope)
        client.publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
