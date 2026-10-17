"""Fake-clock/socket capture tests: these never send a packet."""

import json
import socket
import struct
from unittest.mock import patch

from test_config import IP, MAC, ProfileFixture

from wisp_pilot import capture as capture_module
from wisp_pilot.capture import capture


def raw_packet(sequence=1, receiver=MAC):
    return (
        struct.pack("<4sBBH", b"WISP", 1, 1, 38)
        + struct.pack(
            "<I6s6sIbbBBBBBBH",
            sequence,
            bytes.fromhex(receiver.replace(":", "")),
            bytes.fromhex("020000000002"),
            100,
            -50,
            -90,
            6,
            0,
            1,
            0,
            0,
            0,
            4,
        )
        + b"\x01\xff\x02\xfe"
    )


class Clock:
    def __init__(self):
        self.now = 1_000_000_000

    def monotonic(self):
        return self.now

    def wall(self):
        return self.now + 1700000000 * 10**9


class FakeSocket:
    def __init__(self, clock, events=(), send_error=False):
        self.clock, self.events = clock, list(events)
        self.sent = []
        self.closed = False
        self.send_error = send_error

    def bind(self, endpoint):
        self.bound = endpoint

    def settimeout(self, seconds):
        self.timeout = seconds

    def recvmsg(self, size):
        if self.events:
            data, origin, flags = self.events.pop(0)
            self.clock.now += 100_000_000
            return data, [], flags, origin
        self.clock.now += int(self.timeout * 1e9)
        raise socket.timeout

    def sendto(self, data, target):
        if self.send_error:
            raise OSError("injected send error")
        self.sent.append((data, target))
        return len(data)

    def close(self):
        self.closed = True


class CaptureFixture(ProfileFixture):
    def run_capture(self, events=(), seconds=1, **kwargs):
        self.clock = Clock()
        self.sock = FakeSocket(self.clock, events, **kwargs)
        self.output = self.root / "capture"
        return capture(
            self.config,
            self.output,
            seconds,
            socket_factory=lambda *_: self.sock,
            monotonic_ns=self.clock.monotonic,
            wall_ns=self.clock.wall,
        )


class CaptureTests(CaptureFixture):
    def test_bounded_silence_is_unknown_and_subscription_renews(self):
        result = self.run_capture(seconds=5)
        self.assertTrue(result["manifest"]["complete"])
        self.assertEqual(result["manifest"]["records"], 0)
        self.assertEqual(len(self.sock.sent), 2)
        self.assertEqual(self.sock.sent[0], (b"WSUB\x01\x03", (IP, 47010)))
        self.assertEqual(result["quality"]["receivers"][MAC]["state"], "unknown")
        self.assertTrue(self.sock.closed)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (self.output / "datagrams.jsonl").stat().st_mode & 0o777, 0o600
        )

    def test_all_datagrams_saved_with_explicit_gates(self):
        data = raw_packet()
        events = [
            (data, (IP, 47010), 0),
            (data, (IP, 1), 0),
            (data, ("192.0.2.99", 47010), 0),
            (raw_packet(receiver="02:00:00:00:00:03"), (IP, 47010), 0),
            (b"garbage", (IP, 47010), 0),
            (b"x" * 4097, (IP, 47010), 0),
        ]
        result = self.run_capture(events)
        rows = [
            json.loads(line)
            for line in (self.output / "datagrams.jsonl").read_text().splitlines()
        ]
        self.assertEqual(
            [bytes.fromhex(row["raw_hex"]) for row in rows], [e[0] for e in events]
        )
        self.assertEqual(
            [r["rejection"] for r in rows],
            [
                None,
                "unexpected_source_port",
                "unlisted_source_ip",
                "receiver_mac_mismatch",
                "invalid_protocol",
                "oversize_datagram",
            ],
        )
        self.assertEqual(result["manifest"]["accepted"], 1)

    def test_record_and_byte_limits_report_incomplete(self):
        for kind in ("records", "bytes"):
            with self.subTest(kind=kind):
                self.profile["max_records"] = 1 if kind == "records" else 100
                self.profile["max_bytes"] = 1024 if kind == "bytes" else 1000000
                self.save_profile()
                self.output = self.root / kind
                clock = Clock()
                sock = FakeSocket(clock, [(b"x" * 1024, (IP, 47010), 0)] * 3)
                result = capture(
                    self.config,
                    self.output,
                    1,
                    socket_factory=lambda *_, sock=sock: sock,
                    monotonic_ns=clock.monotonic,
                    wall_ns=clock.wall,
                )
                self.assertFalse(result["manifest"]["complete"])
                self.assertEqual(result["manifest"]["unrecorded_datagrams"], 1)
                self.assertLessEqual(
                    result["manifest"]["bytes"], self.profile["max_bytes"]
                )

    def test_truncation_and_socket_failure_are_incomplete(self):
        result = self.run_capture([(b"x", (IP, 47010), socket.MSG_TRUNC)])
        self.assertFalse(result["manifest"]["complete"])
        self.assertEqual(result["manifest"]["truncated_datagrams"], 1)

    def test_send_failure_reports_incomplete(self):
        result = self.run_capture(send_error=True)
        self.assertFalse(result["manifest"]["complete"])
        self.assertEqual(result["manifest"]["completion"], "io_or_processing_error")
        self.assertTrue(self.sock.closed)

    def test_unexpected_processing_failure_preserves_error_and_incomplete_evidence(self):
        with patch.object(
            capture_module.QualityObserver,
            "ingest",
            side_effect=RuntimeError("injected processing failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected processing failure"):
                self.run_capture([(raw_packet(), (IP, 47010), 0)])
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertFalse(manifest["complete"])
        self.assertEqual(manifest["completion"], "io_or_processing_error")
        self.assertEqual(manifest["errors"], ["RuntimeError"])
        self.assertEqual(manifest["records"], 1)
        self.assertEqual(manifest["ended_monotonic_ns"], self.clock.now)
        self.assertTrue(self.sock.closed)

    def test_existing_destination_refused_before_socket(self):
        output = self.root / "existing"
        output.mkdir()
        with patch("wisp_pilot.capture.socket.socket") as factory:
            with self.assertRaises(FileExistsError):
                capture(self.config, output, 1, socket_factory=factory)
            factory.assert_not_called()

    def test_duration_validation_precedes_output(self):
        for seconds in (0, 2401, True):
            with self.assertRaises(ValueError):
                capture(self.config, self.root / "never-created", seconds)
        self.assertFalse((self.root / "never-created").exists())

    def test_no_subscription_after_deadline(self):
        self.profile["receivers"].append(
            {"ip": "192.0.2.12", "mac": "02:00:00:00:00:02"}
        )
        self.save_profile()
        clock = Clock()
        sock = FakeSocket(clock)
        original_send = sock.sendto

        def slow_send(data, target):
            self.assertLessEqual(sock.timeout, 0.25)
            original_send(data, target)
            clock.now += 1_000_000_000

        sock.sendto = slow_send
        result = capture(
            self.config,
            self.root / "deadline",
            1,
            socket_factory=lambda *_: sock,
            monotonic_ns=clock.monotonic,
            wall_ns=clock.wall,
        )
        self.assertEqual(len(sock.sent), 1)
        self.assertTrue(result["manifest"]["complete"])

    def test_failed_record_write_counts_unrecorded_datagram(self):
        original_file = capture_module._file

        class WriteFailure:
            def __init__(self, handle):
                self.handle = handle

            def write(self, data):
                raise OSError("injected disk failure")

            def __getattr__(self, key):
                return getattr(self.handle, key)

        def open_file(directory, name):
            handle = original_file(directory, name)
            return WriteFailure(handle) if name == "datagrams.jsonl" else handle

        with patch.object(capture_module, "_file", open_file):
            result = self.run_capture([(raw_packet(), (IP, 47010), 0)])
        self.assertFalse(result["manifest"]["complete"])
        self.assertEqual(result["manifest"]["received_datagrams"], 1)
        self.assertEqual(result["manifest"]["records"], 0)
        self.assertEqual(result["manifest"]["unrecorded_datagrams"], 1)
