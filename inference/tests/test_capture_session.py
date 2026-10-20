"""Synthetic closed-capture evidence only; no worker, labels or network calls."""

import copy
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from inference.capture import datagram
from inference.capture_session import verified_session, verify_session
from inference.tests import test_capture
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def file_identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class CaptureSessionTests(unittest.TestCase):
    def setUp(self):
        legacy = test_capture.CaptureTests()
        legacy.setUp()
        self.addCleanup(legacy.doCleanups)
        self.root = legacy.root
        guide = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "server-modules/tests/fixtures/capture-v2.synthetic.json"
            ).read_text()
        )
        self.base = legacy.base
        self.start = 10_000_000_000
        self.rows = copy.deepcopy(legacy.rows)
        self.opening = copy.deepcopy(guide["opening"])
        self.opening["configuration_sha256"] = "a" * 64
        self.opening["node_ids"] = [1, 2, 3]
        self.opening["limits"] = {"duration_ms": 2000, "max_bytes": 1_000_000}
        self.opening["start_boundary"] = self.boundary(self.start, 120)
        self.opening["worker_start_clock"] = self.clock(0)
        self.opening["deadline_monotonic_ns"] = self.start + 2_000_000_000
        self.terminal = copy.deepcopy(guide["terminal"])
        for key in (
            "session_id",
            "capture_id",
            "worker_run_id",
            "clock_id",
            "configuration_sha256",
            "worker_start_clock",
            "frame_schema",
            "node_ids",
            "limits",
            "start_boundary",
            "deadline_monotonic_ns",
        ):
            self.terminal[key] = copy.deepcopy(self.opening[key])
        self.terminal["end_reason"] = "manual_stop"
        self.terminal["end_boundary"] = self.boundary(self.start + 1_300_000_000, 180)
        self.terminal["writer_finished_clock"] = self.clock(self.start + 1_310_000_000)
        self.terminal["counters"].update(admitted=60, enqueued=60, written=60)
        self.terminal["raw"]["frames"] = 60
        for index, row in enumerate(self.rows):
            row.update(
                schema="ruview.csi.frame.v2",
                **{
                    key: self.opening[key]
                    for key in (
                        "session_id",
                        "capture_id",
                        "worker_run_id",
                        "clock_id",
                        "configuration_sha256",
                    )
                },
                ingress_sequence=121 + index,
                capture_sequence=1 + index,
            )
            row["received_monotonic_ns"] += self.start
            row["received_at_ns"] += self.start
            self.rehash_packet(row)
        self.manifest = {
            "schema": "ruview.csi.capture_manifest.v2",
            **{
                key: self.opening[key]
                for key in (
                    "session_id",
                    "capture_id",
                    "worker_run_id",
                    "clock_id",
                    "configuration_sha256",
                )
            },
            "provenance_reference": "synthetic test only; no household qualification",
            "synthetic_only": True,
            "policy": {
                "max_receipt_gap_ns": 70_000_000,
                "max_clock_step_ns": 1_000_000,
            },
            "files": {},
        }
        self.write_files()

    def clock(self, mono):
        return {"utc_ns": self.base + mono, "monotonic_ns": mono}

    def boundary(self, mono, ingress):
        return {"clock": self.clock(mono), "ingress_sequence": ingress}

    @staticmethod
    def rehash_packet(row):
        packet = datagram(row)
        row["raw_datagram_hex"] = packet.hex()
        row["raw_datagram_sha256"] = hashlib.sha256(packet).hexdigest()

    def write_files(self, raw=None):
        if raw is None:
            raw = b"".join(encoded(row) + b"\n" for row in self.rows)
        opening = encoded(self.opening)
        self.terminal["opening_sha256"] = hashlib.sha256(opening).hexdigest()
        self.terminal["raw"].update(file_identity(raw))
        terminal = encoded(self.terminal)
        for name, data in (("raw", raw), ("opening", opening), ("terminal", terminal)):
            (self.root / (name + (".jsonl" if name == "raw" else ".json"))).write_bytes(
                data
            )
            self.manifest["files"][name] = file_identity(data)

    def verify(self):
        return verify_session(
            self.manifest,
            self.root / "raw.jsonl",
            self.root / "opening.json",
            self.root / "terminal.json",
        )

    def prepare_context(self):
        manifest = encoded(self.manifest)
        (self.root / "manifest.json").write_bytes(manifest)
        report = self.verify()
        report["manifest_original_sha256"] = hashlib.sha256(manifest).hexdigest()
        (self.root / "report.json").write_bytes(encoded(report))
        return report

    def context(self, nodes=None):
        return verified_session(
            self.root / "raw.jsonl",
            self.root / "manifest.json",
            self.root / "report.json",
            self.root / "opening.json",
            self.root / "terminal.json",
            [1, 2, 3] if nodes is None else nodes,
        )

    def test_original_rows_and_manual_closure_verified_without_rf_claim(self):
        report = self.verify()
        self.assertTrue(report["capture_closed_verified"])
        self.assertEqual(report["frames"], 60)
        self.assertEqual([node["frames"] for node in report["nodes"]], [20, 20, 20])
        self.assertEqual(report["findings"], {})
        self.assertEqual(report["observations"], {})
        for key in (
            "cross_host_alignment_verified",
            "recognition_validated",
            "publish_to_ha",
        ):
            self.assertFalse(report[key])
        self.assertIn("not RF completeness", report["scope"])

    def test_first_observed_worker_stamp_retains_real_nonzero_elapsed_time(self):
        self.opening["worker_start_clock"] = self.clock(37_123)
        self.terminal["worker_start_clock"] = self.clock(37_123)
        self.write_files()
        self.assertTrue(self.verify()["capture_closed_verified"])
        self.opening["worker_start_clock"] = self.clock(self.start + 1)
        self.terminal["worker_start_clock"] = self.clock(self.start + 1)
        self.write_files()
        with self.assertRaises(ValueError):
            self.verify()

    def test_fifo_evidence_is_rejected_before_read_without_blocking(self):
        fifo = self.root / "synthetic-evidence.fifo"
        os.mkfifo(fifo, 0o600)
        script = """
from inference.capture import file_bytes
import sys
try:
    file_bytes(sys.argv[1], 1024)
except ValueError:
    raise SystemExit(0)
raise SystemExit(2)
"""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(fifo),
            ],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_raw_tamper_and_file_truncation_cannot_pass_even_with_updated_outer_hash(
        self,
    ):
        original = (self.root / "raw.jsonl").read_bytes()
        (self.root / "raw.jsonl").write_bytes(original[:-1])
        with self.assertRaises(ValueError):
            self.verify()
        for raw in (
            original[:-1],
            b"\n" + original,
            original.replace(b'"node_id":1', b'"node_id":1,"node_id":2', 1),
            b" " * 16_385 + b"\n",
        ):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError):
                self.write_files(raw)
                self.verify()

    def test_both_exact_datagram_hex_and_digest_required(self):
        original = copy.deepcopy(self.rows[2])
        for field, change in (
            ("raw_datagram_hex", original["raw_datagram_hex"].upper()),
            ("raw_datagram_sha256", "f" * 64),
            ("iq", [99] + original["iq"][1:]),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "datagram"),
            ):
                self.rows[2] = copy.deepcopy(original)
                self.rows[2][field] = change
                self.write_files()
                self.verify()

    def test_original_opening_hash_bound_and_each_identity_checked(self):
        self.terminal["opening_sha256"] = "f" * 64
        terminal = encoded(self.terminal)
        (self.root / "terminal.json").write_bytes(terminal)
        self.manifest["files"]["terminal"] = file_identity(terminal)
        with self.assertRaisesRegex(ValueError, "original opening"):
            self.verify()
        original = copy.deepcopy(self.rows[0])
        for key, value in (
            ("worker_run_id", "33333333-3333-4333-8333-333333333333"),
            ("clock_id", "another-worker-clock"),
            ("configuration_sha256", "f" * 64),
            ("capture_id", "33333333-3333-4333-8333-333333333333"),
            ("schema", "ruview.csi.frame.v1"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.rows[0] = copy.deepcopy(original)
                self.rows[0][key] = value
                self.write_files()
                self.verify()

    def test_start_stop_and_deadline_packet_barriers(self):
        original = copy.deepcopy(self.rows)
        for row_index, key, value in (
            (0, "ingress_sequence", 120),
            (-1, "ingress_sequence", 181),
            (0, "received_monotonic_ns", self.start - 1),
            (-1, "received_monotonic_ns", self.start + 1_300_000_001),
            (-1, "received_monotonic_ns", self.opening["deadline_monotonic_ns"]),
            (1, "ingress_sequence", 121),
            (1, "capture_sequence", 1),
        ):
            with self.subTest(index=row_index, key=key), self.assertRaises(ValueError):
                self.rows = copy.deepcopy(original)
                self.rows[row_index][key] = value
                self.write_files()
                self.verify()

    def test_capture_queue_loss_distinct_from_original_sequence_gaps(self):
        del self.rows[12]
        self.terminal["counters"].update(
            admitted=60, enqueued=59, written=59, queue_dropped=1
        )
        self.terminal["raw"]["frames"] = 59
        self.terminal["complete"] = False
        self.terminal["failures"] = ["capture queue full"]
        self.write_files()
        report = self.verify()
        self.assertFalse(report["capture_closed_verified"])
        self.assertIn("missing_capture_admission", report["findings"])
        self.assertIn("capture_writer_loss_or_error", report["findings"])

    def test_inconsistent_counter_totals_and_missing_tail_rejected(self):
        self.terminal["counters"]["admitted"] = 61
        self.write_files()
        with self.assertRaisesRegex(ValueError, "accounting"):
            self.verify()
        self.terminal["counters"].update(admitted=60, enqueued=60, written=59)
        self.rows.pop()
        self.terminal["raw"]["frames"] = 59
        self.write_files()
        report = self.verify()
        self.assertFalse(report["capture_closed_verified"])
        self.assertIn("missing_final_admission", report["findings"])

    def test_terminal_failure_drain_io_and_durability_states_stay_incomplete(self):
        original = copy.deepcopy(self.terminal)
        for changed in (
            {"end_reason": "byte_limit"},
            {"end_reason": "drain_timeout"},
            {"complete": False},
            {"failures": ["writer fsync error"]},
            {"raw": {**original["raw"], "fsynced": False}},
            {"raw": {**original["raw"], "closed": False}},
            {"counters": {**original["counters"], "write_errors": 1}},
            {"counters": {**original["counters"], "byte_limit_rejected": 1}},
        ):
            with self.subTest(changed=changed):
                self.terminal = copy.deepcopy(original)
                self.terminal.update(changed)
                self.write_files()
                self.assertFalse(self.verify()["capture_closed_verified"])

    def test_failed_writer_can_close_before_receiver_stop_but_never_verify_success(
        self,
    ):
        self.terminal.update(
            complete=False, end_reason="writer_error", failures=["write_error"]
        )
        self.terminal["counters"]["write_errors"] = 1
        self.terminal["writer_finished_clock"] = self.clock(self.start + 1_210_000_000)
        self.write_files()
        report = self.verify()
        self.assertFalse(report["capture_closed_verified"])
        self.assertIn("capture_writer_loss_or_error", report["findings"])

    def test_native_rf_discontinuity_and_gaps_reported_without_invented_wire_loss(self):
        for row in self.rows:
            row["sequence"] = (row["sequence"] + 2**32 - 5) % 2**32
            self.rehash_packet(row)
        self.write_files()
        self.assertTrue(self.verify()["capture_closed_verified"])
        self.rows[12]["sequence"] = self.rows[9]["sequence"]
        self.rehash_packet(self.rows[12])
        self.manifest["policy"]["max_receipt_gap_ns"] = 30_000_000
        self.write_files()
        report = self.verify()
        self.assertTrue(report["capture_closed_verified"])
        self.assertGreater(report["nodes"][0]["sequence_discontinuities"], 0)
        self.assertGreater(report["nodes"][0]["receipt_gaps"], 0)
        self.assertEqual(report["findings"], {})

    def test_worker_clock_step_is_reported_and_cannot_enter_pairing_context(self):
        self.rows[30]["received_at_ns"] += 2_000_000
        self.write_files()
        report = self.prepare_context()
        self.assertTrue(report["capture_closed_verified"])
        self.assertGreater(report["observations"]["worker_clock_discontinuities"], 0)
        with self.assertRaisesRegex(ValueError, "worker clock discontinuity"):
            with self.context():
                self.fail("discontinuous clock unexpectedly available to pairing")

    def test_duration_auto_stop_is_clean_only_at_or_after_declared_deadline(self):
        self.terminal["end_reason"] = "duration_elapsed"
        self.write_files()
        report = self.verify()
        self.assertFalse(report["capture_closed_verified"])
        self.assertIn("duration_closed_early", report["findings"])
        self.terminal["end_boundary"] = self.boundary(
            self.opening["deadline_monotonic_ns"], 180
        )
        self.terminal["writer_finished_clock"] = self.clock(
            self.opening["deadline_monotonic_ns"] + 1_000_000
        )
        self.write_files()
        self.assertTrue(self.verify()["capture_closed_verified"])

    def test_deadline_limits_and_writer_finish_cannot_be_forged(self):
        original_opening, original_terminal = (
            copy.deepcopy(self.opening),
            copy.deepcopy(self.terminal),
        )
        for kind in (
            "deadline",
            "byte_limit",
            "over_worker_byte_limit",
            "writer_before_end",
            "negative_counter",
        ):
            self.opening, self.terminal = (
                copy.deepcopy(original_opening),
                copy.deepcopy(original_terminal),
            )
            if kind == "deadline":
                self.opening["deadline_monotonic_ns"] += 1
                self.terminal["deadline_monotonic_ns"] += 1
            elif kind == "byte_limit":
                self.opening["limits"]["max_bytes"] = 1024
                self.terminal["limits"]["max_bytes"] = 1024
            elif kind == "over_worker_byte_limit":
                self.opening["limits"]["max_bytes"] = 100 * 1024 * 1024 + 1
                self.terminal["limits"]["max_bytes"] = 100 * 1024 * 1024 + 1
            elif kind == "writer_before_end":
                self.terminal["writer_finished_clock"] = self.clock(self.start)
            else:
                self.terminal["counters"]["written"] = -1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.write_files()
                self.verify()

    def test_empty_or_missing_node_can_close_but_never_be_paired_as_complete_scope(
        self,
    ):
        original_rows = copy.deepcopy(self.rows)
        for wanted in ((), (1, 2)):
            with self.subTest(wanted=wanted):
                self.rows = [
                    copy.deepcopy(row)
                    for row in original_rows
                    if row["node_id"] in wanted
                ]
                for index, row in enumerate(self.rows):
                    row["capture_sequence"] = index + 1
                count = len(self.rows)
                self.terminal["counters"].update(
                    admitted=count, enqueued=count, written=count
                )
                self.terminal["raw"]["frames"] = count
                self.write_files()
                report = self.prepare_context()
                self.assertTrue(report["capture_closed_verified"])
                self.assertEqual(report["nodes"][2]["frames"], 0)
                with self.assertRaisesRegex(ValueError, "no recorded frames"):
                    with self.context():
                        self.fail("missing selected node allowed into pairing")

    def test_terminal_boolean_integer_aliases_rejected(self):
        original = copy.deepcopy(self.terminal)
        for field, value in (
            ("node_ids", [True, 2, 3]),
            ("limits", {"duration_ms": 2000.0, "max_bytes": 1_000_000}),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.terminal = copy.deepcopy(original)
                self.terminal[field] = value
                self.write_files()
                self.verify()

    def test_terminal_cannot_change_or_omit_original_worker_clock(self):
        original = copy.deepcopy(self.terminal)
        for value in (self.clock(1), None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.terminal = copy.deepcopy(original)
                if value is None:
                    del self.terminal["worker_start_clock"]
                else:
                    self.terminal["worker_start_clock"] = value
                self.write_files()
                self.verify()

    def test_verified_context_recomputes_report_and_private_bytes(self):
        self.prepare_context()
        original = (self.root / "raw.jsonl").read_bytes()
        with self.context() as (retained, evidence):
            self.assertNotEqual(retained, self.root / "raw.jsonl")
            self.assertEqual(retained.read_bytes(), original)
            self.assertEqual(os.stat(retained).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(retained.parent).st_mode & 0o777, 0o700)
            self.assertEqual(evidence["status"], "verified_closed_capture")
            self.assertEqual(evidence["capture_id"], self.opening["capture_id"])
        self.assertFalse(retained.exists())
        report = json.loads((self.root / "report.json").read_bytes())
        report["frames"] += 1
        (self.root / "report.json").write_bytes(encoded(report))
        with self.assertRaisesRegex(ValueError, "saved report differs"):
            with self.context():
                self.fail("tampered saved report passed")


if __name__ == "__main__":
    unittest.main()
