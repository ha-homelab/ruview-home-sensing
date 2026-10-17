"""Offline smoke-harness checks; no worker binary or sockets are opened."""

import copy
import importlib.util
import io
import json
import signal
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(f"{name}.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


with patch.dict(sys.modules, {"service_smoke": load("service_smoke")}):
    SMOKE = load("fleet_service_smoke")


def complete():
    return {
        "nodes": [
            {"node_id": node, "sequence": 95, "frames": 96} for node in (1, 2, 3)
        ],
        "counters": {"received": 288, "record_written": 288},
    }


def raw_rows(sequences):
    return [
        {
            "node_id": node,
            "sequence": sequence,
            "received_at_ns": 1_700_000_000_000_000_000 + sequence,
            "received_monotonic_ns": sequence,
            "antennas": 1,
            "subcarriers": 64,
            "frequency_mhz": 2462,
            "ppdu_type": 0,
            "flags": 16,
            "iq": [15 + sequence % 3, -3] * 64,
            "session_id": "synthetic-worker",
        }
        for node, count in sequences.items()
        for sequence in range(count)
    ]


class FleetHarnessTests(unittest.TestCase):
    sequences = {1: 96, 2: 96, 3: 96}

    def test_packet_retains_full_native_shape_and_sync_metadata(self):
        data = SMOKE.packet(3, 0xFFFFFFFF)
        self.assertEqual(len(data), 148)
        self.assertEqual(
            struct.unpack("<IBBHIIbbBB", data[:20]),
            (0xC5110001, 3, 1, 64, 2462, 0xFFFFFFFF, -50, -90, 0, 16),
        )
        self.assertEqual(struct.unpack("128b", data[20:]), (15, -3) * 64)

    def test_all_nodes_processing_and_recording_must_reach_exact_tail(self):
        self.assertTrue(SMOKE.complete(complete(), self.sequences))
        for key in ("sequence", "frames"):
            value = complete()
            value["nodes"][2][key] -= 1
            self.assertFalse(SMOKE.complete(value, self.sequences))
        for key in ("received", "record_written"):
            value = complete()
            value["counters"][key] -= 1
            self.assertFalse(SMOKE.complete(value, self.sequences))
        for nodes in (
            complete()["nodes"][:2],
            complete()["nodes"] + [complete()["nodes"][0]],
        ):
            value = complete()
            value["nodes"] = nodes
            self.assertFalse(SMOKE.complete(value, self.sequences))

    def test_tail_retains_partial_before_success(self):
        partial = complete()
        partial["counters"]["record_written"] = 287
        responses = iter((partial, complete()))
        observed = []

        def snapshot(timeout):
            observed.append(next(responses))
            return observed[-1]

        with (
            patch.object(SMOKE.time, "monotonic", return_value=0),
            patch.object(SMOKE.time, "sleep"),
        ):
            self.assertEqual(SMOKE.await_tail(snapshot, self.sequences, 45), complete())
        self.assertEqual(observed, [partial, complete()])

    def test_late_complete_response_still_fails_and_remains_observed(self):
        observed = []

        def snapshot(timeout):
            observed.append(complete())
            return observed[-1]

        with (
            patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 2]),
            self.assertRaisesRegex(ValueError, "deadline exceeded"),
        ):
            SMOKE.await_tail(snapshot, self.sequences, 45)
        self.assertEqual(observed, [complete()])

    def test_overall_deadline_caps_readiness_timeout(self):
        timeouts = []

        def snapshot(timeout):
            timeouts.append(timeout)
            return complete()

        with patch.object(SMOKE.time, "monotonic", side_effect=[0, 0.3, 0.4]):
            SMOKE.await_tail(snapshot, self.sequences, 0.5)
        self.assertEqual(timeouts, [0.2])

    def test_cleanup_kills_owned_surviving_group_even_if_leader_already_exited(self):
        process = Mock(pid=123, returncode=0)
        process.poll.return_value = 0
        alive = True
        signals = []

        def killpg(pid, sig):
            nonlocal alive
            self.assertEqual(pid, process.pid)
            if not alive:
                raise ProcessLookupError
            if sig:
                signals.append(sig)
                if sig == signal.SIGKILL:
                    alive = False

        with (
            patch.object(SMOKE.os, "killpg", side_effect=killpg),
            patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 0.6, 0.6, 0.7]),
            patch.object(SMOKE.time, "sleep"),
        ):
            result = SMOKE.close_process_group(process)
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(result["group_gone"])
        self.assertTrue(result["sigkill_required"])
        process.wait.assert_called_once()

    def test_surviving_group_cannot_report_cleanup_success(self):
        process = Mock(pid=123)
        with (
            patch.object(SMOKE.os, "killpg"),
            patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 3, 3]),
            self.assertRaisesRegex(ValueError, "cleanup deadline"),
        ):
            SMOKE.close_process_group(process)

    def test_missing_raw_after_otherwise_successful_run_leaves_failed_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            failure = SMOKE.save_completion(
                output,
                output / "missing.jsonl",
                {1: 1, 2: 1, 3: 1},
                {},
                {"group_gone": True},
                None,
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertIn("FileNotFoundError", failure)
            self.assertFalse(summary["passed"])
            self.assertFalse(summary["raw_recording"]["retained"])
            self.assertTrue(summary["cleanup"]["group_gone"])

    def test_truncated_raw_is_retained_but_cannot_pass(self):
        sequences = {1: 1, 2: 1, 3: 1}
        good = "".join(json.dumps(row) + "\n" for row in raw_rows(sequences))
        for data in (good.rsplit("\n", 2)[0] + "\n", good[:-10]):
            with (
                self.subTest(data_length=len(data)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary)
                raw = output / "source.jsonl"
                raw.write_text(data)
                failure = SMOKE.save_completion(
                    output, raw, sequences, {}, {"group_gone": True}, None
                )
                summary = json.loads((output / "summary.json").read_text())
                self.assertIsNotNone(failure)
                self.assertFalse(summary["passed"])
                self.assertFalse(summary["raw_recording"]["validated"])
                self.assertTrue(summary["raw_recording"]["retained"])
                self.assertEqual((output / "raw.synthetic.jsonl").read_text(), data)

    def test_copy_failure_preserves_partial_raw_and_failed_summary(self):
        def copy_failure(source, destination, length):
            destination.write(b"partial")
            raise OSError("synthetic copy failure")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            raw = output / "source.jsonl"
            raw.write_text("{}\n")
            with patch.object(SMOKE.shutil, "copyfileobj", side_effect=copy_failure):
                failure = SMOKE.save_completion(
                    output, raw, {1: 1}, {}, {"group_gone": True}, None
                )
            summary = json.loads((output / "summary.json").read_text())
            self.assertIn("synthetic copy failure", failure)
            self.assertFalse(summary["passed"])
            self.assertFalse(summary["raw_recording"]["retained"])
            self.assertEqual((output / "raw.synthetic.jsonl").read_bytes(), b"partial")

    def test_complete_777_rows_pass_but_same_count_bad_data_does_not(self):
        sequences = {1: 292, 2: 292, 3: 193}
        for corrupt in (None, "signed_pair", "session", "sequence", "timestamp"):
            with (
                self.subTest(corrupt=corrupt),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary)
                raw = output / "source.jsonl"
                rows = raw_rows(sequences)
                if corrupt == "signed_pair":
                    rows[0]["iq"][1] = 253
                elif corrupt == "session":
                    rows[0]["session_id"] = "other-worker"
                elif corrupt == "sequence":
                    rows[-1]["sequence"] -= 1
                elif corrupt == "timestamp":
                    rows[0]["received_at_ns"] = "1700000000000000000"
                raw.write_text("".join(json.dumps(row) + "\n" for row in rows))
                failure = SMOKE.save_completion(
                    output,
                    raw,
                    sequences,
                    {"worker_run_id": "synthetic-worker"},
                    {"group_gone": True},
                    None,
                )
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["passed"], corrupt is None)
                self.assertEqual(summary["raw_recording"]["validated"], corrupt is None)
                self.assertEqual(failure is None, corrupt is None)
                self.assertEqual(summary["raw_recording"]["rows"], 777)

    def test_failed_assertion_preserves_snapshot_raw_and_cleanup_result(self):
        value = complete()
        value["catalog_count"] = 63  # Fail after the exact-tail snapshot is saved.
        response = io.BytesIO(json.dumps(value).encode())
        response.status = 200
        health = io.BytesIO(b"{}")
        health.status = 200
        opener = Mock()
        opener.open.side_effect = [health, response]
        process = Mock(pid=123)
        process.poll.return_value = None
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        sock.sendto.side_effect = lambda data, address: len(data)

        def popen(command, **kwargs):
            raw = Path(command[command.index("--record-jsonl") + 1])
            raw.write_text('{"synthetic_fixture":true}\n')
            return process

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "retained"
            with (
                patch.object(SMOKE, "port", side_effect=[12345, 12346]),
                patch.object(SMOKE.urllib.request, "build_opener", return_value=opener),
                patch.object(SMOKE.subprocess, "Popen", side_effect=popen),
                patch.object(SMOKE.socket, "socket", return_value=sock),
                patch.object(SMOKE.time, "sleep"),
                patch.object(SMOKE.signal, "setitimer"),
                patch.object(
                    SMOKE, "close_process_group", return_value={"group_gone": True}
                ) as cleanup,
                self.assertRaisesRegex(ValueError, "catalog count changed"),
            ):
                SMOKE.main(Path("/synthetic/worker"), output)
            self.assertEqual(json.loads((output / "running.json").read_text()), value)
            trace = json.loads((output / "observations.jsonl").read_text())
            self.assertEqual(trace["snapshot"], value)
            self.assertEqual(trace["phase"], "warmup")
            self.assertEqual(
                (output / "raw.synthetic.jsonl").read_text(),
                '{"synthetic_fixture":true}\n',
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertTrue(summary["cleanup"]["group_gone"])
            cleanup.assert_called_once_with(process)
            prior = copy.deepcopy(summary)
            with self.assertRaises(FileExistsError):
                SMOKE.main(Path("/synthetic/worker"), output)
            self.assertEqual(json.loads((output / "summary.json").read_text()), prior)


if __name__ == "__main__":
    unittest.main()
