"""Exercise the real UDP boundary; all traffic stays on IPv4 loopback."""

import hashlib
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from wisp_pilot.capture import capture
from wisp_pilot.config import load_config
from wisp_pilot.replay import replay


class LoopbackTests(unittest.TestCase):
    def test_original_packets_survive_capture_replay_and_final_silence_expires(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            server.bind(("127.0.0.1", 47010))
        except OSError:
            server.close()
            self.skipTest("Loopback UDP 47010 is already in use")
        server.settimeout(0.2)
        receiver = bytes.fromhex("020000000001")
        transmitter = bytes.fromhex("020000000002")
        raw = struct.pack(
            "<4sBBHI6s6sIbbBBBBBBH",
            b"WISP",
            1,
            1,
            38,
            7,
            receiver,
            transmitter,
            123456,
            -51,
            -95,
            6,
            0,
            1,
            2,
            0,
            2,
            128,
        ) + bytes(range(128))
        report = struct.pack(
            "<4sBBHI6sBBI",
            b"WISP",
            1,
            2,
            24,
            7,
            receiver,
            1,
            0,
            100,
        ) + struct.pack("<6sBbHHBB", transmitter, 0, -51, 100, 240, 4, 0)
        wrong_receiver = raw[:12] + transmitter + raw[18:]
        packets = [raw, raw, wrong_receiver, report, b"invalid"]
        stop = threading.Event()
        sent = threading.Event()
        failures = []

        def node():
            try:
                while not stop.is_set():
                    try:
                        subscription, address = server.recvfrom(64)
                    except socket.timeout:
                        continue
                    if subscription != b"WSUB\x01\x03":
                        failures.append("Unexpected subscription bytes")
                    if not sent.is_set():
                        for packet in packets:
                            server.sendto(packet, address)
                        sent.set()
            except OSError as error:
                if not stop.is_set():
                    failures.append(type(error).__name__)

        worker = threading.Thread(target=node, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                private = Path(temporary).resolve()
                private.chmod(0o700)
                profile = private / "profile.json"
                document = {
                    "schema": "wisp.pilot-config.v1",
                    "bind_ip": "127.0.0.1",
                    "source_port": 47010,
                    "streams": 3,
                    "receivers": [{"ip": "127.0.0.1", "mac": "02:00:00:00:00:01"}],
                    "max_records": 100,
                    "max_bytes": 100000,
                }
                original = json.dumps(document).encode()
                profile.write_bytes(original)
                profile.chmod(0o600)
                config = load_config(profile, hashlib.sha256(original).hexdigest())
                output = private / "recording"
                result = capture(config, output, 4)
                self.assertTrue(sent.is_set())
                self.assertEqual(failures, [])
                self.assertTrue(result["manifest"]["complete"])
                self.assertEqual(result["manifest"]["records"], 5)
                self.assertEqual(result["manifest"]["accepted"], 3)
                self.assertEqual(result["quality"]["accepted_packets"], 2)
                node_state = result["quality"]["receivers"]["02:00:00:00:00:01"]
                self.assertEqual(node_state["state"], "unavailable")
                self.assertEqual(node_state["streams"]["raw_csi"]["duplicates"], 1)
                rows = [
                    json.loads(row)
                    for row in (output / "datagrams.jsonl").read_bytes().splitlines()
                ]
                self.assertEqual(
                    [bytes.fromhex(row["raw_hex"]) for row in rows], packets
                )
                replayed = replay(output, private / "replayed.json")
                self.assertEqual(replayed["result"], result)
        finally:
            stop.set()
            worker.join(timeout=2)
            server.close()
        self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
