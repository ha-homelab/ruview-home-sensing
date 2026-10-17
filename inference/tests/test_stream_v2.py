"""Synthetic-only verified-session replay; no household data, labels or sockets."""

import copy
import functools
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from inference import stream
from inference.capture_session import IDENTITY
from inference.feature_contracts import FEATURE_CONTRACT, PREFIX_FEATURE_CONTRACT
from inference.model import evaluate_candidate_values, train
from inference.pipeline import WindowBuilder, digest
from inference.tests import test_capture_identity, test_capture_session
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.tests.test_pipeline import profile
from inference.tests.test_stream import Clock, model_fixture


@functools.lru_cache
def synthetic_model():
    records = test_capture_identity.v2_dataset()
    for record in records:
        window = record["window"]
        window.update(stream.WIRE, configuration_sha256="a" * 64, flags=16)
        window["window_id"] = digest(
            {k: v for k, v in window.items() if k != "window_id"}
        )
        record["label"].update(configuration_sha256="a" * 64)
    return train(
        records,
        "house_xy_m",
        {test_capture_identity.CAPTURE_B},
        expected_coordinate_frame="example_lab_xz_metres",
    )


class StreamV2Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_capture_session.CaptureSessionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.prepare_context()
        self.root = self.fixture.root
        self.config = {
            "schema": stream.CONFIG_SCHEMA_V2,
            "source": {k: self.fixture.opening[k] for k in IDENTITY},
            "classification": "synthetic",
            "feature_contract": FEATURE_CONTRACT,
            "profiles": [profile(n) for n in (1, 2, 3)],
            "models": {},
            "policy": dict(stream.DEFAULT_POLICY),
        }
        self.paths = {
            "manifest": self.root / "manifest.json",
            "capture_report": self.root / "report.json",
            "opening": self.root / "opening.json",
            "terminal": self.root / "terminal.json",
        }

    def opened(self, config=None, **kwargs):
        return stream.open_replay(
            self.config if config is None else config,
            self.root / "raw.jsonl",
            **self.paths,
            clock=Clock(),
            **kwargs,
            expected_coordinate_frame="example_lab_xz_metres",
        )

    def read(self, runner, spool):
        output = []
        with os.fdopen(stream.open_regular(spool), "rb") as source:
            proof = stream.run_input(source.fileno(), runner, output.append)
        return output, proof

    def test_complete_replay_preserves_original_timeline_and_unknown_boot(self):
        original = (self.root / "raw.jsonl").read_bytes()
        for contract, count in (
            (FEATURE_CONTRACT, 192),
            (PREFIX_FEATURE_CONTRACT, 186),
        ):
            self.config["feature_contract"] = contract
            with self.opened() as (runner, spool):
                self.assertNotEqual(spool, self.root / "raw.jsonl")
                self.assertEqual(spool.stat().st_mode & 0o777, 0o600)
                start = runner.start_record()
                output, proof = self.read(runner, spool)
                self.assertEqual(proof["sha256"], hashlib.sha256(original).hexdigest())
                self.assertEqual(proof["lines"], 60)
                self.assertEqual(
                    runner.replay_at,
                    self.fixture.terminal["end_boundary"]["clock"]["monotonic_ns"],
                )
                self.assertEqual(
                    start["recording_verification"], "verified_closed_capture"
                )
                builder = WindowBuilder(
                    profiles=self.config["profiles"], feature_contract=contract
                )
                expected = [
                    w
                    for row in self.fixture.rows
                    if (w := builder.push(row)) is not None
                ]
                windows = [r for r in output if r["kind"] == "window_diagnostic"]
                self.assertEqual(len(windows), 3)
                for event, window in zip(windows, expected, strict=True):
                    provenance = event["current_input_provenance"]
                    self.assertEqual(provenance["window_id"], window["window_id"])
                    self.assertEqual(event["feature_count"], count)
                    self.assertEqual(
                        provenance["capture_evidence"]["raw_sha256"], proof["sha256"]
                    )
                    for key, values in provenance["original_window_timeline"].items():
                        self.assertEqual(values, window[key])
                    self.assertIsNone(provenance["device_boot_id"])
                    self.assertFalse(provenance["device_boot_identity_verified"])
                    self.assertIsNone(event["research_candidate"])
                    self.assertEqual(event["status"], "unavailable")
                    self.assertFalse(event["publish_to_ha"])
                    self.assertFalse(event["qualified"])
                self.assertEqual(len(runner.close("input_ended")), 3)
            self.assertFalse(spool.exists())
        self.assertEqual((self.root / "raw.jsonl").read_bytes(), original)

    def test_all_originals_and_saved_report_reverified_before_yield(self):
        for name in (
            "raw.jsonl",
            "opening.json",
            "terminal.json",
            "manifest.json",
            "report.json",
        ):
            path = self.root / name
            original = path.read_bytes()
            # Valid JSON whitespace changes must still break pinned originals;
            # report is compared semantically, so change one actual report field.
            if name == "report.json":
                report = json.loads(original)
                report["frames"] += 1
                path.write_text(json.dumps(report))
            else:
                path.write_bytes(original + b" ")
            with self.subTest(name=name), self.assertRaises(ValueError):
                with self.opened():
                    self.fail("changed evidence yielded a replay")
            path.write_bytes(original)

    def test_mutable_original_is_never_consumed_after_verification(self):
        with self.opened() as (runner, spool):
            (self.root / "raw.jsonl").write_bytes(b"replaced after verification")
            output, proof = self.read(runner, spool)
            self.assertEqual(proof["lines"], 60)
            self.assertEqual(len(output), 3)

    def test_spool_hash_rechecked_even_for_semantically_equal_rows(self):
        with self.opened() as (runner, spool):
            spool.write_text(
                "".join(json.dumps(row) + "\n" for row in self.fixture.rows)
            )
            with self.assertRaisesRegex(ValueError, "spool bytes changed"):
                self.read(runner, spool)

    def test_source_scope_classification_and_missing_proof_rejected(self):
        with self.assertRaisesRegex(ValueError, "verified closed session"):
            stream.ReplayRunner(
                self.config, expected_coordinate_frame="example_lab_xz_metres"
            )
        for key in IDENTITY:
            config = copy.deepcopy(self.config)
            config["source"][key] = (
                "f" * 64 if key.endswith("sha256") else "another-identity"
            )
            with self.subTest(key=key), self.assertRaises(ValueError):
                with self.opened(config):
                    pass
        for changes in (
            {"classification": "household_recording"},
            {"profiles": [profile(1)]},
        ):
            with self.assertRaises(ValueError):
                with self.opened({**self.config, **changes}):
                    pass
        with self.assertRaises(ValueError):
            with stream.open_replay(
                self.config,
                "-",
                **self.paths,
                expected_coordinate_frame="example_lab_xz_metres",
            ):
                pass

    def test_profile_frequency_mismatch_blocks_without_windows(self):
        self.config["profiles"][0]["frequency_mhz"] = 2412
        with self.opened() as (runner, spool):
            output, _ = self.read(runner, spool)
            self.assertTrue(runner.nodes[1]["blocked"])
            self.assertFalse(
                any(
                    r["kind"] == "window_diagnostic" and r["node_id"] == 1
                    for r in output
                )
            )

    def test_wire_loss_is_preserved_and_prevents_cross_gap_window(self):
        for row in self.fixture.rows[15:]:
            if row["node_id"] == 1:
                row["sequence"] += 3
                self.fixture.rehash_packet(row)
        self.fixture.write_files()
        report = self.fixture.prepare_context()
        self.assertTrue(report["capture_closed_verified"])
        self.assertEqual(report["nodes"][0]["sequence_discontinuities"], 1)
        with self.opened() as (runner, spool):
            output, _ = self.read(runner, spool)
            affected = [r for r in output if r["node_id"] == 1]
            self.assertEqual([r["reason"] for r in affected], ["input_discontinuity"])
            self.assertEqual(sum(r["kind"] == "window_diagnostic" for r in output), 2)

    def test_terminal_silence_uses_actual_boundary_and_withdraws_all_nodes(self):
        self.fixture.opening["limits"]["duration_ms"] = 6000
        self.fixture.opening["deadline_monotonic_ns"] = (
            self.fixture.start + 6_000_000_000
        )
        self.fixture.terminal["limits"] = copy.deepcopy(self.fixture.opening["limits"])
        self.fixture.terminal["deadline_monotonic_ns"] = self.fixture.opening[
            "deadline_monotonic_ns"
        ]
        end = self.fixture.start + 5_000_000_000
        self.fixture.terminal["end_boundary"] = self.fixture.boundary(end, 180)
        self.fixture.terminal["writer_finished_clock"] = self.fixture.clock(end + 1)
        self.fixture.write_files()
        self.fixture.prepare_context()
        with self.opened() as (runner, spool):
            output, _ = self.read(runner, spool)
            expired = [r for r in output if r.get("reason") == "source_expired"]
            self.assertEqual([r["node_id"] for r in expired], [1, 2, 3])
            self.assertTrue(all(r["replay_at_ns"] == end for r in expired))

    def test_recomputed_but_incomplete_capture_is_still_rejected(self):
        self.fixture.terminal["raw"]["fsynced"] = False
        self.fixture.write_files()
        report = self.fixture.prepare_context()
        self.assertFalse(report["capture_closed_verified"])
        with self.assertRaisesRegex(ValueError, "not verified closed"):
            with self.opened():
                pass

    def test_recomputed_capture_with_clock_step_is_rejected(self):
        for row in self.fixture.rows[20:]:
            row["received_at_ns"] += 40_000_000
        self.fixture.write_files()
        report = self.fixture.prepare_context()
        self.assertTrue(report["capture_closed_verified"])
        self.assertGreater(report["observations"]["worker_clock_discontinuities"], 0)
        with self.assertRaisesRegex(ValueError, "clock discontinuity"):
            with self.opened():
                pass

    def test_mixed_admission_or_worker_identity_never_produces_window(self):
        for key, value in (
            ("capture_sequence", 1),
            ("worker_run_id", test_capture_identity.OTHER_WORKER),
        ):
            with self.opened() as (runner, _):
                runner.consume_input(self.fixture.rows[0])
                row = copy.deepcopy(self.fixture.rows[1])
                row[key] = value
                if key == "capture_sequence":
                    with self.assertRaisesRegex(ValueError, "admission timeline"):
                        runner.consume_input(row)
                else:
                    row["clock_id"] = row["clock_id"].split("/")[0] + "/" + value
                    result = runner.consume_input(row)
                    self.assertEqual(result[-1]["reason"], "source_identity_mismatch")

    @unittest.skipUnless(importlib.util.find_spec("numpy"), "NumPy numerical extra")
    def test_real_v2_candidate_arithmetic_and_v1_model_rejection(self):
        self.config["models"] = {"2": synthetic_model()}
        with self.opened(emit_candidates=True) as (runner, spool):
            output, _ = self.read(runner, spool)
            event = next(r for r in output if r["node_id"] == 2)
            builder = WindowBuilder(profiles=[profile(2)])
            windows = [
                w
                for row in self.fixture.rows
                if row["node_id"] == 2 and (w := builder.push(row)) is not None
            ]
            self.assertEqual(
                event["research_candidate"]["prediction"],
                evaluate_candidate_values(
                    synthetic_model(),
                    windows[0],
                    expected_coordinate_frame="example_lab_xz_metres",
                ),
            )
            self.assertEqual(event["research_candidate"]["validation"], "unverified")
            self.assertFalse(event["qualified"])
        self.config["models"] = {"2": model_fixture()}
        with self.assertRaisesRegex(ValueError, "v2 model inputs"):
            with self.opened():
                pass

    def test_cli_closes_success_and_refuses_altered_evidence_before_output(self):
        config = self.root / "config.json"
        config.write_text(json.dumps(self.config))
        output = self.root / "out.jsonl"
        command = [
            sys.executable,
            "-m",
            "inference.stream",
            "--config",
            str(config),
            "--input",
            str(self.root / "raw.jsonl"),
            "--output",
            str(output),
        ]
        for key, path in self.paths.items():
            command += ["--" + key.replace("_", "-"), str(path)]
        done = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        events = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertTrue(events[-1]["completed"])
        self.assertEqual(events[-1]["original_input"]["lines"], 60)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        output.unlink()
        (self.root / "terminal.json").write_bytes(b"{}")
        done = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
        self.assertEqual(done.returncode, 1)
        self.assertFalse(output.exists())
        self.assertNotIn(str(self.root), done.stdout + done.stderr)

    @unittest.skipUnless(importlib.util.find_spec("numpy"), "NumPy numerical extra")
    def test_v2_lineage_classification_cannot_cross_synthetic_household_boundary(self):
        # Synthetic mutation of untrusted checkpoint metadata, not real evidence.
        with self.opened() as (runner, _):
            evidence = copy.deepcopy(runner.capture_evidence)
        model = copy.deepcopy(synthetic_model())
        model["capture_lineage"] = {
            "schema": "ruview.csi.capture_lineage.v2",
            "status": "verified_closed_capture",
            "recordings": [
                {
                    **evidence,
                    "session_id": session,
                    "capture_id": session,
                    "worker_run_id": test_capture_identity.WORKER,
                    "clock_id": test_capture_identity.CLOCK,
                    "synthetic_only": False,
                }
                for session in model["training_sessions"] + model["evaluation_sessions"]
            ],
        }
        model["model_sha256"] = digest(
            {k: v for k, v in model.items() if k != "model_sha256"}
        )
        self.config["models"] = {"2": model}
        with self.assertRaisesRegex(ValueError, "classification mismatch"):
            with self.opened():
                pass

    def test_v2_input_bound_is_checked_before_yield(self):
        with (
            patch.object(stream, "MAX_INPUT", 1),
            self.assertRaisesRegex(ValueError, "input byte bound"),
        ):
            with self.opened():
                pass


if __name__ == "__main__":
    unittest.main()
