#!/usr/bin/env python3
"""Forward explicitly allowed peers to a loopback-only worker or activity service.

The default worker mode forwards CSI UDP and read-only worker HTTP. Activity mode
forwards only HTTP GET /health and /v1/activity; it never opens a UDP socket.

The Mac must remain awake. The scheduler-gap guard discards this proxy's UDP
receive backlog; it does not prove packet freshness in kernel, VM, or downstream
buffers, and is not a substitute for end-to-end timestamped freshness evidence.
"""

import argparse
import collections
import gzip
import http.client
import http.server
import ipaddress
import json
import re
import select
import signal
import socket
import socketserver
import threading
import time

UDP_PORT = 5015
HTTP_PORT = 5016
UPSTREAM_UDP_PORT = 15015
UPSTREAM_HTTP_PORT = 15016
ACTIVITY_HTTP_PORT = 5017
ACTIVITY_UPSTREAM_HTTP_PORT = 15017
MAX_DATAGRAM = 1044  # server-modules/src/packet.rs::MAX_PACKET
RECEIVE_BUFFER = 16 * 1024
MAX_SCHEDULER_GAP = 0.5
MAX_PAUSE_DRAIN_PACKETS = 64
MAX_BODY = 2 * 1024 * 1024
UPSTREAM_TIMEOUT = 2.0
MAX_CONNECTIONS = 8
PATHS = frozenset(("/health", "/v1/latest"))
ACTIVITY_PATHS = frozenset(("/health", "/v1/activity"))


def exact_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError("An exact IPv4 address is required") from error
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("A specific unicast IPv4 address is required")
    return str(address)


class Counters:
    def __init__(self, mode="worker"):
        self.mode = mode
        self.lock = threading.Lock()
        self.values = collections.Counter(
            dict.fromkeys(
                (
                    "udp_received",
                    "udp_forwarded",
                    "udp_rejected",
                    "udp_truncated",
                    "udp_dropped",
                    "udp_receive_errors",
                    "udp_send_errors",
                    "udp_pause_events",
                    "udp_pause_dropped",
                    "udp_pause_flushes",
                    "http_requests",
                    "http_forwarded",
                    "http_rejected",
                    "http_peer_rejected",
                    "http_upstream_errors",
                    "http_client_errors",
                    "http_prehandler_timeouts",
                    "http_prehandler_empty_closes",
                    "http_prehandler_protocol_errors",
                    "http_busy",
                    "http_active",
                ),
                0,
            )
        )

    def add(self, key, amount=1):
        with self.lock:
            self.values[key] += amount

    def snapshot(self):
        with self.lock:
            values = dict(self.values)
        return {
            "schema": "ruview.mac-worker-proxy.v1",
            "mode": self.mode,
            "counters": values,
            "udp_kernel_drops": None,
            "udp_kernel_drops_note": "Not observable here; counters cover application drops only",
            "freshness_note": "Mac must remain awake; kernel/VM/downstream buffering is unproven",
        }


class UDPForwarder:
    def __init__(self, bind, allowed_peers, counters, upstream_port=UPSTREAM_UDP_PORT):
        self.allowed_peers = frozenset(allowed_peers)
        self.counters = counters
        self.last_poll = time.monotonic()
        self.draining_after_pause = False
        self.incoming = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.outgoing = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.incoming.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER
            )
            self.incoming.bind(bind)
            self.incoming.setblocking(False)
            self.outgoing.setblocking(False)
            self.outgoing.connect(("127.0.0.1", upstream_port))
        except BaseException:
            self.close()
            raise

    def observe_scheduler_gap(self):
        now = time.monotonic()
        if now - self.last_poll > MAX_SCHEDULER_GAP:
            self.counters.add("udp_pause_events")
            self.draining_after_pause = True
        self.last_poll = now

    def drain_after_pause(self):
        # A full batch stays fail-closed. Only EAGAIN permits later forwarding.
        for _ in range(MAX_PAUSE_DRAIN_PACKETS):
            try:
                _, _, flags, peer = self.incoming.recvmsg(MAX_DATAGRAM)
            except BlockingIOError:
                self.draining_after_pause = False
                self.counters.add("udp_pause_flushes")
                return
            except OSError:
                self.counters.add("udp_receive_errors")
                return
            self.counters.add("udp_received")
            self.counters.add("udp_pause_dropped")
            self.counters.add("udp_dropped")
            if peer[0] not in self.allowed_peers:
                self.counters.add("udp_rejected")
            if flags & socket.MSG_TRUNC:
                self.counters.add("udp_truncated")

    def forward_one(self):
        self.observe_scheduler_gap()
        if self.draining_after_pause:
            self.drain_after_pause()
            return
        try:
            data, _, flags, peer = self.incoming.recvmsg(MAX_DATAGRAM)
        except BlockingIOError:
            return
        except OSError:
            self.counters.add("udp_receive_errors")
            return
        self.counters.add("udp_received")
        if peer[0] not in self.allowed_peers:
            self.counters.add("udp_rejected")
            self.counters.add("udp_dropped")
            return
        if flags & socket.MSG_TRUNC:
            self.counters.add("udp_truncated")
            self.counters.add("udp_dropped")
            return
        # Also cover a scheduling pause after receiving this packet.
        self.observe_scheduler_gap()
        if self.draining_after_pause:
            self.counters.add("udp_pause_dropped")
            self.counters.add("udp_dropped")
            self.drain_after_pause()
            return
        try:
            if self.outgoing.send(data) != len(data):
                raise OSError("Incomplete UDP send")
        except OSError:
            self.counters.add("udp_send_errors")
            self.counters.add("udp_dropped")
            return
        self.counters.add("udp_forwarded")

    def serve(self, stop):
        while not stop.is_set():
            select.select([self.incoming], [], [], 0.2)
            # Update the scheduler clock on idle polls too; ordinary silence
            # must not be mistaken for a paused process.
            self.forward_one()

    def close(self):
        self.incoming.close()
        self.outgoing.close()


class DeadlineSocket(socket.socket):
    """Apply an absolute deadline to buffered HTTP reads, including slow headers."""

    def set_deadline(self, deadline):
        self.deadline = deadline
        self._remaining()

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP deadline exceeded")
        self.settimeout(remaining)

    def recv_into(self, *args, **kwargs):
        self._remaining()
        return super().recv_into(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        self._remaining()
        return super().sendall(*args, **kwargs)


def fetch_worker(path, upstream_port, allowed_paths=PATHS):
    if allowed_paths not in (PATHS, ACTIVITY_PATHS) or path not in allowed_paths:
        raise ValueError("Unsupported upstream path")
    deadline = time.monotonic() + UPSTREAM_TIMEOUT
    connection = http.client.HTTPConnection("127.0.0.1", upstream_port)
    upstream = DeadlineSocket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        upstream.set_deadline(deadline)
        upstream.connect(("127.0.0.1", upstream_port))
        connection.sock = upstream
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        if response.length is not None and response.length > MAX_BODY:
            raise ValueError("Worker response exceeds body limit")
        body = bytearray()
        while not response.isclosed():
            upstream._remaining()
            part = response.read1(min(64 * 1024, MAX_BODY + 1 - len(body)))
            if not part:
                break
            body.extend(part)
            if len(body) > MAX_BODY:
                raise ValueError("Worker response exceeds body limit")
        if response.length not in (None, 0):
            raise ValueError("Incomplete worker response")
        return response.status, bytes(body)
    finally:
        connection.close()
        upstream.close()


def send_socket_error(request, status):
    body = b'{"error":"proxy request rejected"}\n'
    reason = "Forbidden" if status == 403 else "Service Unavailable"
    response = (
        f"HTTP/1.0 {status} {reason}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    try:
        request.sendall(response)
    except OSError:
        pass


def accepts_gzip(value):
    """Require explicit gzip permission; ambiguous or zero weights decline it."""
    accepted = False
    for item in value.split(","):
        coding, *parameters = item.strip().split(";")
        if coding.strip().lower() != "gzip":
            continue
        if parameters:
            if len(parameters) != 1:
                return False
            weight = re.fullmatch(
                r"\s*q\s*=\s*(0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?)\s*",
                parameters[0],
                re.IGNORECASE,
            )
            if weight is None or float(weight[1]) == 0:
                return False
        accepted = True
    return accepted


class WorkerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass  # Only bounded aggregate logs; no untrusted URL/header logging.

    def record_prehandler_failure(self, counter):
        # Count only the first outcome, including when an error response times out.
        if not self.request_parsed and not self.prehandler_failure_recorded:
            self.server.counters.add(counter)
            self.prehandler_failure_recorded = True

    def handle_one_request(self):
        self.request_parsed = False
        self.prehandler_failure_recorded = False
        self.raw_requestline = None
        try:
            super().handle_one_request()
        finally:
            if self.raw_requestline == b"":
                self.record_prehandler_failure("http_prehandler_empty_closes")

    def parse_request(self):
        parsed = super().parse_request()
        if parsed:
            self.request_parsed = True
        else:
            self.record_prehandler_failure("http_prehandler_protocol_errors")
        return parsed

    def log_error(self, format, *args):
        # stdlib catches this timeout internally and closes without a response.
        # Inspect only its fixed event and exception type, never client text.
        if (
            format == "Request timed out: %r"
            and len(args) == 1
            and isinstance(args[0], TimeoutError)
        ):
            self.record_prehandler_failure("http_prehandler_timeouts")

    def reply(self, status, body, *, negotiate_encoding=False):
        encoded = False
        if negotiate_encoding and accepts_gzip(
            ",".join(self.headers.get_all("Accept-Encoding", []))
        ):
            compressed = gzip.compress(body, compresslevel=1, mtime=0)
            # Keep the wire-body bound even for incompressible maximum-size input.
            if len(compressed) <= MAX_BODY:
                body = compressed
                encoded = True
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if negotiate_encoding:
            self.send_header("Vary", "Accept-Encoding")
        if encoded:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def denied(self):
        self.server.counters.add("http_rejected")
        self.reply(403, b'{"error":"method or path denied"}\n')

    def send_error(self, code, message=None, explain=None):
        if code == 501:  # BaseHTTPRequestHandler rejects unrecognized methods here.
            self.denied()
        else:
            # Includes an oversized request line, rejected before parse_request.
            self.record_prehandler_failure("http_prehandler_protocol_errors")
            super().send_error(code, message, explain)

    def do_GET(self):
        if self.path not in self.server.allowed_paths:
            self.denied()
            return
        self.connection.set_deadline(time.monotonic() + UPSTREAM_TIMEOUT + 2)
        self.server.counters.add("http_requests")
        try:
            status, body = fetch_worker(
                self.path, self.server.upstream_port, self.server.allowed_paths
            )
        except (OSError, ValueError, http.client.HTTPException):
            self.server.counters.add("http_upstream_errors")
            status, body = 503, b'{"error":"worker unavailable"}\n'
        else:
            self.server.counters.add("http_forwarded")
        try:
            self.reply(status, body, negotiate_encoding=True)
        except OSError:
            self.server.counters.add("http_client_errors")

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = denied
    do_OPTIONS = do_TRACE = do_CONNECT = denied


class WorkerHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    request_queue_size = MAX_CONNECTIONS
    allow_reuse_address = True

    def __init__(
        self,
        bind,
        allowed_peers,
        counters,
        upstream_port=UPSTREAM_HTTP_PORT,
        *,
        allowed_paths=PATHS,
    ):
        self.allowed_paths = frozenset(allowed_paths)
        if self.allowed_paths not in (PATHS, ACTIVITY_PATHS):
            raise ValueError("Unsupported upstream paths")
        self.allowed_peers = frozenset(allowed_peers)
        self.counters = counters
        self.upstream_port = upstream_port
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(bind, WorkerHandler)

    def get_request(self):
        request, address = super().get_request()
        bounded = DeadlineSocket(fileno=request.detach())
        bounded.set_deadline(time.monotonic() + 2)
        return bounded, address

    def verify_request(self, request, client_address):
        if client_address[0] in self.allowed_peers:
            return True
        self.counters.add("http_peer_rejected")
        send_socket_error(request, 403)
        return False

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.counters.add("http_busy")
            send_socket_error(request, 503)
            self.shutdown_request(request)
            return
        self.counters.add("http_active")
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.counters.add("http_active", -1)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.counters.add("http_active", -1)
            self.slots.release()

    def handle_error(self, request, client_address):
        self.counters.add("http_client_errors")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("worker", "activity"), default="worker")
    parser.add_argument("--bind-address", type=exact_ipv4, required=True)
    parser.add_argument("--allow-peer", type=exact_ipv4, action="append", required=True)
    args = parser.parse_args(argv)
    counters = Counters(args.mode)
    stop = threading.Event()
    activity = args.mode == "activity"
    http_port = ACTIVITY_HTTP_PORT if activity else HTTP_PORT
    upstream_port = ACTIVITY_UPSTREAM_HTTP_PORT if activity else UPSTREAM_HTTP_PORT
    allowed_paths = ACTIVITY_PATHS if activity else PATHS
    udp = (
        None
        if activity
        else UDPForwarder((args.bind_address, UDP_PORT), args.allow_peer, counters)
    )
    try:
        server = WorkerHTTPServer(
            (args.bind_address, http_port),
            args.allow_peer,
            counters,
            upstream_port,
            allowed_paths=allowed_paths,
        )
    except BaseException:
        if udp is not None:
            udp.close()
        raise
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    udp_thread = (
        None if udp is None else threading.Thread(target=udp.serve, args=(stop,))
    )
    http_thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.2}
    )
    if udp_thread is not None:
        udp_thread.start()
    http_thread.start()
    print(
        json.dumps(
            {
                "event": "started",
                "mode": args.mode,
                "bind_address": args.bind_address,
                "http_port": http_port,
                "allowed_paths": sorted(allowed_paths),
                "allowed_peers": sorted(set(args.allow_peer)),
                "upstream": "127.0.0.1",
                "upstream_ports": (
                    [upstream_port] if activity else [UPSTREAM_UDP_PORT, upstream_port]
                ),
                "udp_enabled": udp is not None,
                **(
                    {
                        "udp_receive_buffer": udp.incoming.getsockopt(
                            socket.SOL_SOCKET, socket.SO_RCVBUF
                        ),
                        "udp_scheduler_gap_seconds": MAX_SCHEDULER_GAP,
                        "udp_pause_drain_batch_packets": MAX_PAUSE_DRAIN_PACKETS,
                    }
                    if udp is not None
                    else {}
                ),
            }
        ),
        flush=True,
    )
    try:
        while not stop.wait(5):
            print(json.dumps(counters.snapshot()), flush=True)
    finally:
        stop.set()
        server.shutdown()
        if udp_thread is not None:
            udp_thread.join()
        http_thread.join()
        server.server_close()
        if udp is not None:
            udp.close()
        print(json.dumps({"event": "stopped", **counters.snapshot()}), flush=True)


if __name__ == "__main__":
    main()
