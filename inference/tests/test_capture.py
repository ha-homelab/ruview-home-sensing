"""Synthetic capture-evidence fixtures; no device, HA, labels or model calls."""

import copy
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference.capture import strict_json, verify_capture
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = 1_000_000_000_000
        self.rows = []
        for index in range(60):
            row = {
                "schema": "ruview.csi.frame.v1",
                "session_id": "synthetic-run",
                "clock_id": "synthetic-boot/synthetic-run",
                "configuration_sha256": "a" * 64,
                "node_id": index % 3 + 1,
                "sequence": index // 3,
                "received_at_ns": self.base + (index + 1) * 20_000_000,
                "received_monotonic_ns": (index + 1) * 20_000_000,
                "antennas": 1,
                "subcarriers": 64,
                "frequency_mhz": 2462,
                "ppdu_type": 0,
                "flags": 0x10,
                "iq": [-3, 15] * 64,
                "rssi_dbm": -50,
                "noise_floor_dbm": -90,
                "iq_order": "wire_byte_order",
                "source_pair_order": "esp_idf_imaginary_real",
                "worker_phase_convention": "ruview_legacy_atan2_byte1_byte0",
                "monotonic_origin": "worker_start",
                "device_boot_id": None,
                "device_timestamp": None,
            }
            self.rehash_row(row)
            self.rows.append(row)
        self.manifest = {
            "schema": "ruview.csi.capture_manifest.v1",
            "session_id": "synthetic-run",
            "worker_run_id": "synthetic-run",
            "clock_id": "synthetic-boot/synthetic-run",
            "configuration_sha256": "a" * 64,
            "provenance_reference": "synthetic test only",
            "synthetic_only": True,
            "expected_node_ids": [1, 2, 3],
            "recording_limits": {"record_seconds": 2, "record_max_bytes": 1_000_000},
            "planned_interval": {
                "start_utc_ns": self.base + 100_000_000,
                "end_utc_ns": self.base + 1_000_000_000,
            },
            "policy": {
                "max_receipt_gap_ns": 70_000_000,
                "max_boundary_gap_ns": 60_000_000,
                "max_clock_step_ns": 1_000_000,
                "max_snapshot_counter_skew_ns": 5_000_000,
            },
            "files": {},
        }
        counters = {
            key: 0
            for key in (
                "received",
                "rejected",
                "source_rejected",
                "queue_dropped",
                "processing_stale",
                "record_dropped",
                "record_written",
                "record_error",
                "record_limit_reached",
            )
        }
        self.opening = {
            "schema": "ruview.server-modules.v1",
            "recognition_validated": False,
            "worker_run_id": "synthetic-run",
            "clock_id": "synthetic-boot/synthetic-run",
            "configuration_sha256": "a" * 64,
            "monotonic_origin": "worker_start",
            "generated_at_ns": str(self.base + 50_000_000),
            "counters": counters,
        }
        self.opening["counters"].update(received=2, record_written=2)
        self.closing = copy.deepcopy(self.opening)
        self.closing["generated_at_ns"] = str(self.base + 1_300_000_000)
        self.closing["counters"].update(received=60, record_written=60)
        self.write_files()

    @staticmethod
    def rehash_row(row):
        header = struct.pack(
            "<IBBHIIbbBB",
            0xC5110001,
            row["node_id"],
            1,
            64,
            row["frequency_mhz"],
            row["sequence"],
            -50,
            -90,
            0,
            row["flags"],
        )
        row["raw_datagram_sha256"] = hashlib.sha256(
            header + bytes(value & 255 for value in row["iq"])
        ).hexdigest()

    def write(self, name, data):
        (self.root / name).write_bytes(data)
        self.manifest["files"][name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def write_files(self):
        self.write(
            "raw", b"".join(json.dumps(row).encode() + b"\n" for row in self.rows)
        )
        self.write("opening_snapshot", json.dumps(self.opening).encode())
        self.write("closing_snapshot", json.dumps(self.closing).encode())

    def verify(self):
        return verify_capture(
            self.manifest,
            self.root / "raw",
            self.root / "opening_snapshot",
            self.root / "closing_snapshot",
        )

    def test_complete_original_three_node_capture_and_sync_metadata(self):
        self.rows[12]["flags"] = 0
        self.rehash_row(self.rows[12])
        self.write_files()
        report = self.verify()
        self.assertTrue(report["recording_complete"])
        self.assertEqual(report["frames"], 60)
        self.assertEqual([n["frames"] for n in report["nodes"]], [20, 20, 20])
        self.assertEqual(report["findings"], {})
        self.assertFalse(report["worker_file_closed_verified"])
        self.assertFalse(report["cross_host_alignment_verified"])
        self.assertFalse(report["recognition_validated"])
        self.assertFalse(report["publish_to_ha"])

    def test_jsonl_truncation_ambiguity_and_bounded_lines(self):
        original = (self.root / "raw").read_bytes()
        for data in (
            original[:-1],
            b"\n" + original,
            original.replace(b'"node_id": 1', b'"node_id": 1, "node_id": 2', 1),
            b" " * 16385 + b"\n",
        ):
            with self.subTest(size=len(data)):
                self.write("raw", data)
                with self.assertRaises(ValueError):
                    self.verify()
        for data in (b'{"x":NaN}', b'{"x":1,"x":2}'):
            with self.assertRaises(ValueError):
                strict_json(data)

    def test_original_hash_and_packet_provenance_are_both_required(self):
        (self.root / "raw").write_bytes((self.root / "raw").read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.verify()
        self.rows[2]["iq"][0] = 99
        self.write_files()
        with self.assertRaisesRegex(ValueError, "datagram"):
            self.verify()
        self.rehash_row(self.rows[2])
        self.rows[2]["clock_id"] = "different-worker"
        self.write_files()
        with self.assertRaisesRegex(ValueError, "worker contract"):
            self.verify()

    def test_numeric_overflow_in_unknown_fields_cannot_enter_evidence(self):
        for value in ("1e309", "-1e309", "NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    strict_json('{"unused":{"extra":' + value + "}}")
        self.assertEqual(strict_json('{"extra":1e3}'), {"extra": 1000.0})

    def test_sequence_discontinuity_preserved_and_wrap_allowed(self):
        for row in self.rows:
            row["sequence"] = (row["sequence"] + 2**32 - 5) % 2**32
            self.rehash_row(row)
        self.write_files()
        self.assertTrue(self.verify()["recording_complete"])
        self.rows[12]["sequence"] -= 1
        self.rehash_row(self.rows[12])
        self.write_files()
        report = self.verify()
        self.assertFalse(report["recording_complete"])
        self.assertIn("sequence_gap_duplicate_or_reset", report["findings"])

    def test_missing_node_gap_clock_and_interval_never_complete(self):
        self.manifest["expected_node_ids"].append(4)
        self.manifest["policy"]["max_receipt_gap_ns"] = 30_000_000
        self.manifest["planned_interval"]["end_utc_ns"] = self.base + 1_290_000_000
        self.rows[30]["received_at_ns"] += 2_000_000
        self.write_files()
        report = self.verify()
        self.assertFalse(report["recording_complete"])
        for key in (
            "expected_node_missing",
            "receipt_gap",
            "planned_interval_not_covered",
            "receipt_clock_discontinuity",
        ):
            self.assertIn(key, report["findings"])

    def test_counters_and_recording_limits_cannot_be_hidden(self):
        self.closing["counters"].update(
            record_dropped=3, record_written=59, record_limit_reached=1, queue_dropped=2
        )
        self.write_files()
        report = self.verify()
        self.assertFalse(report["recording_complete"])
        for key in (
            "record_dropped",
            "record_written_count_mismatch",
            "record_limit_reached",
            "queue_dropped",
        ):
            self.assertIn(key, report["findings"])
        self.closing["counters"]["record_written"] = 1
        self.write_files()
        with self.assertRaisesRegex(ValueError, "backwards"):
            self.verify()

    def test_wrong_boundaries_and_unsupported_raw_flags_fail_closed(self):
        self.opening["generated_at_ns"] = str(self.base + 200_000_000)
        self.write_files()
        with self.assertRaisesRegex(ValueError, "bracket"):
            self.verify()
        self.opening["generated_at_ns"] = str(self.base + 50_000_000)
        self.rows[0]["flags"] = 0x11
        self.rehash_row(self.rows[0])
        self.write_files()
        with self.assertRaisesRegex(ValueError, "grid"):
            self.verify()

    def test_opening_counters_cannot_claim_receipts_from_future(self):
        self.opening["counters"].update(received=60, record_written=60)
        self.write_files()
        report = self.verify()
        self.assertFalse(report["recording_complete"])
        self.assertEqual(report["opening_receipt_prefix_frames"], 2)
        self.assertIn("opening_written_exceeds_receipt_prefix", report["findings"])
        self.assertIn(
            "opening_received_exceeds_receipt_upper_bound", report["findings"]
        )

    def test_opening_counter_skew_and_writer_lag_are_explicit(self):
        # The next packet arrives 10 ms after the response UTC timestamp.
        self.opening["counters"].update(received=3, record_written=3)
        self.write_files()
        self.assertFalse(self.verify()["recording_complete"])
        self.manifest["policy"]["max_snapshot_counter_skew_ns"] = 10_000_000
        self.assertTrue(self.verify()["recording_complete"])
        self.opening["counters"]["record_written"] = 0
        self.write_files()
        self.assertTrue(self.verify()["recording_complete"])
        # Rejected receipts have no raw timestamp; total rejection counts
        # provide a conservative upper bound, not an invented packet timeline.
        self.opening["counters"].update(received=4, rejected=1)
        self.closing["counters"].update(received=61, rejected=1)
        self.write_files()
        self.assertTrue(self.verify()["recording_complete"])
        del self.manifest["policy"]["max_snapshot_counter_skew_ns"]
        with self.assertRaises(KeyError):
            self.verify()

    def test_cli_writes_private_bound_report_without_promotion(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(self.manifest))
        output = self.root / "verification.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "inference",
                "verify-capture",
                "--manifest",
                str(manifest),
                "--frames",
                str(self.root / "raw"),
                "--opening-snapshot",
                str(self.root / "opening_snapshot"),
                "--closing-snapshot",
                str(self.root / "closing_snapshot"),
                "--output",
                str(output),
            ],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertTrue(report["recording_complete"])
        self.assertFalse(report["publish_to_ha"])
        self.assertEqual(
            report["manifest_original_sha256"],
            hashlib.sha256(manifest.read_bytes()).hexdigest(),
        )
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
