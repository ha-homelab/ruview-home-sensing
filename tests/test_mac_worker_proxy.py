"""Synthetic loopback sockets only; no worker, device, or production network calls."""

import argparse
import contextlib
import gzip
import http.client
import http.server
import importlib.util
import io
import json
import os
import select
import socket
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location(
    "mac_worker_proxy",
    Path(__file__).resolve().parents[1] / "scripts/mac-worker-proxy.py",
)
PROXY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROXY)


@contextlib.contextmanager
def serving(server):
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        if thread.is_alive():
            raise AssertionError("Synthetic HTTP server did not stop")


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append((self.path, dict(self.headers)))
        time.sleep(self.server.delay)
        try:
            self.send_response(self.server.status)
            self.send_header("Content-Type", "application/json")
            if self.server.length is not None:
                self.send_header("Content-Length", str(self.server.length))
            self.end_headers()
            if self.server.drip:
                for byte in self.server.body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(self.server.drip)
            else:
                self.wfile.write(self.server.body)
        except OSError:
            pass


def upstream(body=b'{"ok": true}\n', status=200, length="automatic", delay=0, drip=0):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    server.daemon_threads = True
    server.body = body
    server.status = status
    server.length = len(body) if length == "automatic" else length
    server.delay = delay
    server.drip = drip
    server.requests = []
    return server


class MacWorkerProxyTests(unittest.TestCase):
    def test_exact_peer_configuration_rejects_ranges_names_and_wildcards(self):
        self.assertEqual(PROXY.exact_ipv4("10.77.0.58"), "10.77.0.58")
        for value in [
            "0.0.0.0",
            "10.0.0.0/24",
            "localhost",
            "::1",
            "239.1.2.3",
            "255.255.255.255",
        ]:
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                PROXY.exact_ipv4(value)

    def test_udp_preserves_bytes_and_drops_denied_or_truncated_datagrams(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(0.03)
            for allowed, payload, counter in [
                ({"127.0.0.1"}, bytes(range(256)) * 4, "udp_forwarded"),
                ({"10.77.0.58"}, b"denied", "udp_rejected"),
                ({"127.0.0.1"}, b"x" * (PROXY.MAX_DATAGRAM + 1), "udp_truncated"),
            ]:
                with self.subTest(counter=counter):
                    counts = PROXY.Counters()
                    forwarder = PROXY.UDPForwarder(
                        ("127.0.0.1", 0), allowed, counts, sink.getsockname()[1]
                    )
                    try:
                        self.assertEqual(forwarder.incoming.gettimeout(), 0)
                        self.assertEqual(forwarder.outgoing.gettimeout(), 0)
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                            sender.sendto(payload, forwarder.incoming.getsockname())
                        self.assertTrue(
                            select.select([forwarder.incoming], [], [], 1)[0]
                        )
                        forwarder.forward_one()
                        if counter == "udp_forwarded":
                            self.assertEqual(sink.recvfrom(2048)[0], payload)
                        else:
                            with self.assertRaises(TimeoutError):
                                sink.recvfrom(2048)
                            self.assertEqual(
                                counts.snapshot()["counters"]["udp_dropped"], 1
                            )
                        self.assertEqual(counts.snapshot()["counters"][counter], 1)
                    finally:
                        forwarder.close()

    def response(self, server, path="/health", method="GET", headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=2
        )
        try:
            connection.request(
                method, path, headers={"Host": "untrusted.example", **(headers or {})}
            )
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def request(self, server, path="/health", method="GET", headers=None):
        status, _, body = self.response(server, path, method, headers)
        return status, body

    def test_udp_scheduler_gap_drains_bounded_batches_before_fresh_forwarding(self):
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender,
            patch.object(PROXY.time, "monotonic", return_value=100.0) as clock,
            patch.object(PROXY, "MAX_PAUSE_DRAIN_PACKETS", 2),
        ):
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(0.03)
            counts = PROXY.Counters()
            forwarder = PROXY.UDPForwarder(
                ("127.0.0.1", 0), {"127.0.0.1"}, counts, sink.getsockname()[1]
            )
            try:
                for payload in (b"old one", b"old two", b"old three"):
                    sender.sendto(payload, forwarder.incoming.getsockname())
                self.assertTrue(select.select([forwarder.incoming], [], [], 1)[0])
                clock.return_value = 103.0
                forwarder.forward_one()
                self.assertTrue(forwarder.draining_after_pause)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_dropped"], 2)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_flushes"], 0)
                clock.return_value = 103.2
                forwarder.forward_one()
                self.assertFalse(forwarder.draining_after_pause)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_dropped"], 3)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_events"], 1)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_flushes"], 1)
                with self.assertRaises(TimeoutError):
                    sink.recvfrom(2048)
                sender.sendto(b"fresh after flush", forwarder.incoming.getsockname())
                self.assertTrue(select.select([forwarder.incoming], [], [], 1)[0])
                clock.return_value = 103.4
                forwarder.forward_one()
                self.assertEqual(sink.recvfrom(2048)[0], b"fresh after flush")
                self.assertEqual(counts.snapshot()["counters"]["udp_forwarded"], 1)
            finally:
                forwarder.close()

    def test_udp_regular_idle_polls_do_not_trigger_a_pause_flush(self):
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender,
            patch.object(PROXY.time, "monotonic", return_value=100.0) as clock,
        ):
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(0.1)
            counts = PROXY.Counters()
            forwarder = PROXY.UDPForwarder(
                ("127.0.0.1", 0), {"127.0.0.1"}, counts, sink.getsockname()[1]
            )
            try:
                for index in range(1, 11):
                    clock.return_value = 100.0 + index * 0.2
                    forwarder.forward_one()
                sender.sendto(
                    b"after ordinary silence", forwarder.incoming.getsockname()
                )
                self.assertTrue(select.select([forwarder.incoming], [], [], 1)[0])
                clock.return_value = 102.2
                forwarder.forward_one()
                self.assertEqual(sink.recvfrom(2048)[0], b"after ordinary silence")
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_events"], 0)
            finally:
                forwarder.close()

    def test_udp_pause_after_receive_also_drops_the_in_hand_packet(self):
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender,
            patch.object(PROXY.time, "monotonic", side_effect=[100.0, 100.1, 103.1]),
        ):
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(0.03)
            counts = PROXY.Counters()
            forwarder = PROXY.UDPForwarder(
                ("127.0.0.1", 0), {"127.0.0.1"}, counts, sink.getsockname()[1]
            )
            try:
                sender.sendto(b"paused after receipt", forwarder.incoming.getsockname())
                self.assertTrue(select.select([forwarder.incoming], [], [], 1)[0])
                forwarder.forward_one()
                with self.assertRaises(TimeoutError):
                    sink.recvfrom(2048)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_dropped"], 1)
                self.assertEqual(counts.snapshot()["counters"]["udp_pause_events"], 1)
            finally:
                forwarder.close()

    def proxy(self, origin, allowed=("127.0.0.1",)):
        return PROXY.WorkerHTTPServer(
            ("127.0.0.1", 0), allowed, PROXY.Counters(), origin.server_port
        )

    def test_http_preserves_worker_status_and_json_bytes_without_environment_proxy(
        self,
    ):
        body = b'{ "message" : "unchanged \\u2603", "n": 1.00 }\n'
        for status in (207, 503):
            with self.subTest(status=status), serving(upstream(body, status)) as origin:
                with serving(self.proxy(origin)) as proxy:
                    with patch.dict(
                        os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}
                    ):
                        self.assertEqual(
                            self.request(proxy, "/v1/latest"), (status, body)
                        )
                    self.assertEqual(origin.requests[0][0], "/v1/latest")
                    self.assertNotEqual(
                        origin.requests[0][1]["Host"], "untrusted.example"
                    )

    def test_http_denies_peer_and_non_allowlisted_methods_or_paths(self):
        with serving(upstream()) as origin:
            with serving(self.proxy(origin, allowed=("10.77.0.58",))) as proxy:
                self.assertEqual(self.request(proxy)[0], 403)
                self.assertEqual(
                    proxy.counters.snapshot()["counters"]["http_peer_rejected"], 1
                )
            with serving(self.proxy(origin)) as proxy:
                for method, path in [
                    ("GET", "/"),
                    ("GET", "/health?url=http://evil"),
                    ("GET", "http://127.0.0.1:1/health"),
                    ("POST", "/health"),
                    ("CONNECT", "/health"),
                    ("UNKNOWN", "/health"),
                ]:
                    with self.subTest(method=method, path=path):
                        self.assertEqual(self.request(proxy, path, method)[0], 403)
            self.assertEqual(origin.requests, [])

    def test_prehandler_request_line_and_header_timeouts_are_counted_silently(self):
        with serving(upstream()) as origin, serving(self.proxy(origin)) as proxy:
            get_request = proxy.get_request

            def short_test_deadline():
                request, address = get_request()
                request.set_deadline(time.monotonic() + 0.05)
                return request, address

            with (
                patch.object(proxy, "get_request", side_effect=short_test_deadline),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                for expected, payload in enumerate(
                    (b"", b"GET /health HTTP/1.1\r\nX-Private: untrusted"), 1
                ):
                    with (
                        self.subTest(payload=payload),
                        socket.create_connection(
                            proxy.server_address, timeout=1
                        ) as client,
                    ):
                        client.sendall(payload)
                        self.assertEqual(client.recv(4096), b"")
                        counts = proxy.counters.snapshot()["counters"]
                        self.assertEqual(counts["http_prehandler_timeouts"], expected)
                        self.assertEqual(counts["http_prehandler_empty_closes"], 0)
                        self.assertEqual(counts["http_prehandler_protocol_errors"], 0)
                        self.assertEqual(counts["http_requests"], 0)
                        self.assertEqual(counts["http_client_errors"], 0)
                        self.assertEqual(counts["http_upstream_errors"], 0)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(origin.requests, [])
            self.assertEqual(self.request(proxy)[0], 200)
            self.assertEqual(
                proxy.counters.snapshot()["counters"]["http_prehandler_timeouts"], 2
            )

    def test_prehandler_empty_client_close_is_counted_without_forwarding(self):
        with serving(upstream()) as origin, serving(self.proxy(origin)) as proxy:
            with socket.create_connection(proxy.server_address, timeout=1) as client:
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(client.recv(4096), b"")
            counts = proxy.counters.snapshot()["counters"]
            self.assertEqual(counts["http_prehandler_empty_closes"], 1)
            self.assertEqual(counts["http_prehandler_timeouts"], 0)
            self.assertEqual(counts["http_prehandler_protocol_errors"], 0)
            self.assertEqual(counts["http_requests"], 0)
            self.assertEqual(origin.requests, [])

    def test_prehandler_protocol_errors_are_counted_once_without_untrusted_logs(
        self,
    ):
        cases = (
            (b"GET /private-value HTTP/wrong\r\n\r\n", b"HTTP/1.0 400"),
            (b"\r\n", b""),
            (b"GET /" + b"x" * 65536 + b" HTTP/1.1\r\n\r\n", b"HTTP/1.0 414"),
            (
                b"GET /health HTTP/1.1\r\n" + b"X-Private: value\r\n" * 101 + b"\r\n",
                b"HTTP/1.0 431",
            ),
        )
        with serving(upstream()) as origin, serving(self.proxy(origin)) as proxy:
            with (
                contextlib.redirect_stdout(io.StringIO()) as stdout,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                for expected, (payload, status) in enumerate(cases, 1):
                    with (
                        self.subTest(status=status),
                        socket.create_connection(
                            proxy.server_address, timeout=1
                        ) as client,
                    ):
                        client.sendall(payload)
                        received = bytearray()
                        while chunk := client.recv(4096):
                            received.extend(chunk)
                        if status:
                            self.assertTrue(received.startswith(status), received)
                        else:
                            self.assertEqual(received, b"")
                        counts = proxy.counters.snapshot()["counters"]
                        self.assertEqual(
                            counts["http_prehandler_protocol_errors"], expected
                        )
                        self.assertEqual(counts["http_prehandler_empty_closes"], 0)
                        self.assertEqual(counts["http_prehandler_timeouts"], 0)
                        self.assertEqual(counts["http_requests"], 0)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(origin.requests, [])
            # A valid but denied method or path is not a protocol parsing failure.
            self.assertEqual(self.request(proxy, method="UNKNOWN")[0], 403)
            self.assertEqual(self.request(proxy, path="/private-value")[0], 403)
            self.assertEqual(self.request(proxy)[0], 200)
            self.assertEqual(
                proxy.counters.snapshot()["counters"][
                    "http_prehandler_protocol_errors"
                ],
                len(cases),
            )

    def test_gzip_preserves_exact_bytes_status_and_fetches_each_response(self):
        body = b' { "expires_at_ns": 1234, "n": 1.00, "text": "\\u2603" }\n'
        for status in (207, 503):
            with self.subTest(status=status), serving(upstream(body, status)) as origin:
                with serving(self.proxy(origin)) as proxy:
                    for current in (body, body + b" \n"):
                        origin.body = current
                        origin.length = len(current)
                        actual_status, headers, encoded = self.response(
                            proxy, "/v1/latest", headers={"Accept-Encoding": "gzip"}
                        )
                        self.assertEqual(actual_status, status)
                        self.assertEqual(headers["Content-Encoding"], "gzip")
                        self.assertEqual(headers["Vary"], "Accept-Encoding")
                        self.assertEqual(int(headers["Content-Length"]), len(encoded))
                        self.assertEqual(gzip.decompress(encoded), current)
                        self.assertEqual(encoded[4:8], b"\0" * 4)
                    self.assertEqual(len(origin.requests), 2)

    def test_gzip_requires_explicit_positive_well_formed_permission(self):
        for value in ("gzip", "br, gzip;q=0.5", "GZip ; Q=1.000", "gzip;q=0.001"):
            with self.subTest(accepted=value):
                self.assertTrue(PROXY.accepts_gzip(value))
        for value in (
            "",
            "identity",
            "*",
            "br, *;q=1",
            "gzip;q=0",
            "gzip;q=0.000",
            "gzip;q=0, *;q=1",
            "gzip;q=0, gzip;q=1",
            "gzip;q=nan",
            "gzip;q=-1",
            "gzip;q=2",
            "gzip;q=1.001",
            "gzip;q=0.1234",
            "gzip;q=1;q=0",
        ):
            with self.subTest(declined=value):
                self.assertFalse(PROXY.accepts_gzip(value))

    def test_identity_clients_and_zero_gzip_weight_keep_original_body(self):
        body = b'{ "unchanged": 1.00 }\n'
        with serving(upstream(body)) as origin, serving(self.proxy(origin)) as proxy:
            for permission in (None, "identity", "gzip;q=0, *;q=1"):
                with self.subTest(permission=permission):
                    request_headers = (
                        {} if permission is None else {"Accept-Encoding": permission}
                    )
                    status, headers, actual = self.response(
                        proxy, headers=request_headers
                    )
                    self.assertEqual((status, actual), (200, body))
                    self.assertNotIn("Content-Encoding", headers)
                    self.assertEqual(headers["Vary"], "Accept-Encoding")
                    self.assertEqual(int(headers["Content-Length"]), len(body))

    def test_gzip_keeps_wire_body_bound_for_incompressible_input(self):
        body = bytes(range(128))
        self.assertGreater(
            len(gzip.compress(body, compresslevel=1, mtime=0)), len(body)
        )
        with (
            serving(upstream(body)) as origin,
            serving(self.proxy(origin)) as proxy,
            patch.object(PROXY, "MAX_BODY", len(body)),
        ):
            status, headers, actual = self.response(
                proxy, headers={"Accept-Encoding": "gzip"}
            )
            self.assertEqual((status, actual), (200, body))
            self.assertNotIn("Content-Encoding", headers)
            self.assertEqual(int(headers["Content-Length"]), len(body))

    def test_upstream_timeout_returns_503(self):
        with (
            serving(upstream(delay=0.15)) as origin,
            serving(self.proxy(origin)) as proxy,
        ):
            with patch.object(PROXY, "UPSTREAM_TIMEOUT", 0.03):
                started = time.monotonic()
                self.assertEqual(self.request(proxy)[0], 503)
                self.assertLess(time.monotonic() - started, 0.3)
            self.assertEqual(
                proxy.counters.snapshot()["counters"]["http_upstream_errors"], 1
            )

    def test_upstream_connection_failure_returns_503(self):
        origin = upstream()
        origin.server_close()
        with serving(self.proxy(origin)) as proxy:
            self.assertEqual(self.request(proxy)[0], 503)

    def test_total_deadline_stops_continuously_arriving_body(self):
        with serving(upstream(body=b"123456789", drip=0.02)) as origin:
            with patch.object(PROXY, "UPSTREAM_TIMEOUT", 0.05):
                started = time.monotonic()
                with self.assertRaises(TimeoutError):
                    PROXY.fetch_worker("/health", origin.server_port)
                self.assertLess(time.monotonic() - started, 0.15)

    def test_body_limit_and_truncated_http_body_return_503(self):
        self.assertEqual(PROXY.MAX_BODY, 2 * 1024 * 1024)
        cases = [
            {"body": b"x" * 17},
            {"body": b"x" * 17, "length": None},
            {"body": b"short", "length": 10},
        ]
        for case in cases:
            with self.subTest(case=case), serving(upstream(**case)) as origin:
                with (
                    serving(self.proxy(origin)) as proxy,
                    patch.object(PROXY, "MAX_BODY", 16),
                ):
                    self.assertEqual(self.request(proxy)[0], 503)

    def test_eight_connection_limit_rejects_without_creating_more_work(self):
        self.assertEqual(PROXY.MAX_CONNECTIONS, 8)
        with serving(upstream()) as origin, serving(self.proxy(origin)) as proxy:
            for _ in range(8):
                self.assertTrue(proxy.slots.acquire(blocking=False))
            try:
                self.assertEqual(self.request(proxy)[0], 503)
                self.assertEqual(origin.requests, [])
                self.assertEqual(proxy.counters.snapshot()["counters"]["http_busy"], 1)
            finally:
                for _ in range(8):
                    proxy.slots.release()
            self.assertEqual(self.request(proxy)[0], 200)


class MacActivityProxyTests(unittest.TestCase):
    response = MacWorkerProxyTests.response
    request = MacWorkerProxyTests.request

    def proxy(self, origin, allowed=("127.0.0.1",)):
        return PROXY.WorkerHTTPServer(
            ("127.0.0.1", 0),
            allowed,
            PROXY.Counters("activity"),
            origin.server_port,
            allowed_paths=PROXY.ACTIVITY_PATHS,
        )

    def test_only_activity_paths_preserve_status_and_exact_bytes(self):
        body = b' {"expires_at_ns": "12345", "activity": "unknown"}\n'
        with (
            serving(upstream(body, 503)) as origin,
            serving(self.proxy(origin)) as proxy,
        ):
            for path in ("/health", "/v1/activity"):
                self.assertEqual(self.request(proxy, path), (503, body))
                status, headers, raw = self.response(
                    proxy, path, headers={"Accept-Encoding": "gzip"}
                )
                self.assertEqual(status, 503)
                self.assertEqual(headers["Content-Encoding"], "gzip")
                self.assertEqual(gzip.decompress(raw), body)
            self.assertEqual(len(origin.requests), 4)
            for path in (
                "/v1/latest",
                "/internal/diagnostics",
                "/v1/activity?url=http://127.0.0.1",
                "http://127.0.0.1/v1/activity",
            ):
                self.assertEqual(self.request(proxy, path)[0], 403)
            self.assertEqual(self.request(proxy, "/v1/activity", "POST")[0], 403)
            self.assertEqual(len(origin.requests), 4)

    # The same handler must retain every transport limit in HTTP-only mode.
    test_peer_and_method_rejection = (
        MacWorkerProxyTests.test_http_denies_peer_and_non_allowlisted_methods_or_paths
    )
    test_timeout = MacWorkerProxyTests.test_upstream_timeout_returns_503
    test_connection_failure = (
        MacWorkerProxyTests.test_upstream_connection_failure_returns_503
    )
    test_body_bounds = (
        MacWorkerProxyTests.test_body_limit_and_truncated_http_body_return_503
    )
    test_concurrency_bound = MacWorkerProxyTests.test_eight_connection_limit_rejects_without_creating_more_work

    def test_arbitrary_allowlist_cannot_expose_local_diagnostics(self):
        with self.assertRaises(ValueError):
            PROXY.WorkerHTTPServer(
                ("127.0.0.1", 0),
                ("127.0.0.1",),
                PROXY.Counters(),
                allowed_paths={"/internal/diagnostics"},
            )
        with patch.object(PROXY, "DeadlineSocket") as socket_type:
            with self.assertRaises(ValueError):
                PROXY.fetch_worker(
                    "/internal/diagnostics", 15017, {"/internal/diagnostics"}
                )
            socket_type.assert_not_called()

    def test_activity_lifecycle_has_no_udp_and_keeps_fixed_loopback_destination(self):
        stop = MagicMock()
        stop.wait.return_value = True
        with (
            patch.object(PROXY, "UDPForwarder", side_effect=AssertionError("UDP")),
            patch.object(PROXY, "WorkerHTTPServer") as server_type,
            patch.object(PROXY.threading, "Event", return_value=stop),
            patch.object(PROXY.threading, "Thread") as thread_type,
            patch.object(PROXY.signal, "signal"),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            PROXY.main(
                [
                    "--mode",
                    "activity",
                    "--bind-address",
                    "192.0.2.10",
                    "--allow-peer",
                    "10.77.0.58",
                ]
            )
        call = server_type.call_args
        self.assertEqual(call.args[0:2], (("192.0.2.10", 5017), ["10.77.0.58"]))
        self.assertEqual(call.args[3], 15017)
        self.assertEqual(call.kwargs["allowed_paths"], PROXY.ACTIVITY_PATHS)
        self.assertEqual(thread_type.call_count, 1)
        server_type.return_value.shutdown.assert_called_once()
        server_type.return_value.server_close.assert_called_once()
        started, stopped = map(json.loads, output.getvalue().splitlines())
        self.assertFalse(started["udp_enabled"])
        self.assertEqual(started["upstream"], "127.0.0.1")
        self.assertEqual(started["upstream_ports"], [15017])
        self.assertEqual(stopped["mode"], "activity")

    def test_both_modes_require_bind_address_before_opening_sockets(self):
        with (
            patch.object(PROXY, "WorkerHTTPServer") as server_type,
            patch.object(PROXY, "UDPForwarder") as udp_type,
            patch.object(PROXY, "Counters") as counters,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            for mode in ("worker", "activity"):
                with self.subTest(mode=mode), self.assertRaises(SystemExit) as error:
                    PROXY.main(["--mode", mode, "--allow-peer", "192.0.2.11"])
                self.assertEqual(error.exception.code, 2)
            server_type.assert_not_called()
            udp_type.assert_not_called()
            counters.assert_not_called()

    def test_activity_requires_explicit_peers_and_offers_no_destination_override(self):
        with (
            patch.object(PROXY, "WorkerHTTPServer") as server_type,
            patch.object(PROXY, "UDPForwarder") as udp_type,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            for args in (
                ["--mode", "activity"],
                ["--mode", "activity", "--allow-peer", "0.0.0.0"],
                [
                    "--mode",
                    "activity",
                    "--allow-peer",
                    "10.77.0.58",
                    "--upstream",
                    "evil",
                ],
            ):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    PROXY.main(["--bind-address", "192.0.2.10", *args])
            server_type.assert_not_called()
            udp_type.assert_not_called()


if __name__ == "__main__":
    unittest.main()
