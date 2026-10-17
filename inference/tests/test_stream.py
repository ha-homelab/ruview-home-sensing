"""Synthetic offline replay only; no household models, sockets or promotion."""

import copy
import functools
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from inference import stream
from inference.capture import datagram
from inference.feature_contracts import (
    FEATURE_CONTRACT,
    PREFIX_FEATURE_CONTRACT,
    prefix_selection,
)
from inference.model import predict, train
from inference.pipeline import WindowBuilder, digest
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.tests.test_evidence import with_synthetic_lineage
from inference.tests.test_pipeline import dataset, frame, profile


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


def raw(index, node=2, **changes):
    value = frame(index, session="synthetic-replay", node=node)
    value.update(stream.WIRE, rssi_dbm=-50, noise_floor_dbm=-90)
    value.update(changes)
    value["raw_datagram_sha256"] = hashlib.sha256(datagram(value)).hexdigest()
    return value


def envelope(value, at=None):
    return {
        "schema": stream.EVENT_SCHEMA,
        "kind": "frame",
        "at_ns": value["received_monotonic_ns"] if at is None else at,
        "clock_id": "synthetic-host-boot",
        "frame": value,
    }


def config(nodes=(2,), models=None, contract=FEATURE_CONTRACT):
    return {
        "schema": stream.CONFIG_SCHEMA,
        "source": {
            "session_id": "synthetic-replay",
            "clock_id": "synthetic-host-boot",
            "configuration_sha256": "c" * 64,
        },
        "classification": "synthetic",
        "feature_contract": contract,
        "profiles": [profile(n) for n in nodes],
        "models": models or {},
        "policy": dict(stream.DEFAULT_POLICY),
    }


def feed(runner, start=0, count=11, node=2):
    return [
        event
        for i in range(start, start + count)
        for event in runner.consume(envelope(raw(i, node)))
    ]


@functools.lru_cache
def model_fixture(node=2, contract=FEATURE_CONTRACT, verified=False, task="house_xy_m"):
    records = dataset(node)
    for record in records:
        window = record["window"]
        window.update(stream.WIRE)
        if contract == PREFIX_FEATURE_CONTRACT:
            window["feature_selection"] = prefix_selection()
        window["window_id"] = digest(
            {k: v for k, v in window.items() if k != "window_id"}
        )
    if verified:
        with_synthetic_lineage(records)
    return train(
        records,
        task,
        {"synthetic-eval"},
        feature_contract=contract,
        expected_coordinate_frame="example_lab_xz_metres",
    )


class StreamStateTests(unittest.TestCase):
    def test_missing_model_and_permit_never_make_qualified_observation(self):
        runner = stream.ReplayRunner(
            config(), clock=Clock(), expected_coordinate_frame="example_lab_xz_metres"
        )
        records = feed(runner)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["reason"], "missing_candidate_model")
        self.assertIsNone(records[0]["research_candidate"])
        self.assertEqual(records[0]["feature_count"], 192)
        self.assertEqual(records[0]["status"], "unavailable")
        self.assertFalse(records[0]["qualified"])
        self.assertFalse(records[0]["publish_to_ha"])
        self.assertEqual(
            records[0]["current_input_provenance"]["recording_verification"],
            "not_supplied",
        )

    def test_independent_silence_timeout_and_new_contiguous_warmup(self):
        clock = Clock()
        runner = stream.ReplayRunner(
            config(), clock=clock, expected_coordinate_frame="example_lab_xz_metres"
        )
        feed(runner, count=6)
        clock.now = 1_999_999_999
        self.assertEqual(runner.poll(), [])
        clock.now += 1
        self.assertEqual(runner.poll()[0]["reason"], "no_input_timeout")
        self.assertEqual(runner.poll(), [])
        self.assertEqual(feed(runner, start=6, count=10), [])
        self.assertEqual(feed(runner, start=16, count=1)[0]["node_epoch"], 2)

    def test_expiry_uses_explicit_replay_clock_not_local_or_utc_now(self):
        runner = stream.ReplayRunner(
            config(), clock=Clock(), expected_coordinate_frame="example_lab_xz_metres"
        )
        feed(runner)
        tick = {
            "schema": stream.EVENT_SCHEMA,
            "kind": "tick",
            "clock_id": "synthetic-host-boot",
            "at_ns": 4_000_000_000,
        }
        self.assertEqual(runner.consume(tick), [])  # Inclusive two-second source lease.
        tick["at_ns"] += 1
        self.assertEqual(runner.consume(tick)[0]["reason"], "source_expired")
        self.assertEqual(runner.consume(tick), [])

    def test_nodes_never_share_windows_or_withdrawal_state(self):
        clock = Clock()
        runner = stream.ReplayRunner(
            config(nodes=(1, 2)),
            clock=clock,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        records = []
        for i in range(11):
            records += runner.consume(envelope(raw(i, 1)))
            clock.now += 10
            records += runner.consume(envelope(raw(i, 2)))
        self.assertEqual([r["node_id"] for r in records], [1, 2])
        bad = raw(11, 1, sequence=20)
        self.assertEqual(runner.consume(envelope(bad))[0]["node_id"], 1)
        self.assertIsNotNone(runner.nodes[2]["last"])
        self.assertEqual(runner.nodes[2]["epoch"], 1)
        with self.assertRaisesRegex(ValueError, "node scope"):
            runner.consume(envelope(raw(12, 3)))

    def test_duplicate_backwards_gap_and_clock_step_discard_boundary(self):
        for changes in (
            {"sequence": 10},
            {"sequence": 9},
            {"sequence": 99},
            {"received_at_ns": 2_200_000_000},
            {"received_monotonic_ns": 2_500_000_000, "received_at_ns": 2_500_000_000},
        ):
            with self.subTest(changes=changes):
                runner = stream.ReplayRunner(
                    config(),
                    clock=Clock(),
                    expected_coordinate_frame="example_lab_xz_metres",
                )
                feed(runner)
                records = runner.consume(envelope(raw(11, **changes)))
                self.assertEqual(records[-1]["reason"], "input_discontinuity")
                self.assertIsNone(runner.nodes[2]["last"])
                self.assertEqual(runner.nodes[2]["builder"].pending, {})

    def test_restart_config_profile_and_raw_identity_fail_closed(self):
        for changes, reason in (
            ({"session_id": "another-run"}, "source_identity_mismatch"),
            ({"clock_id": "another-clock"}, "source_identity_mismatch"),
            ({"configuration_sha256": "d" * 64}, "source_identity_mismatch"),
            ({"frequency_mhz": 2412}, "profile_frequency_mismatch"),
            ({"flags": 32}, "raw_contract_mismatch"),
            ({"source_pair_order": "invented"}, "raw_contract_mismatch"),
        ):
            runner = stream.ReplayRunner(
                config(),
                clock=Clock(),
                expected_coordinate_frame="example_lab_xz_metres",
            )
            feed(runner)
            result = runner.consume(envelope(raw(11, **changes)))
            self.assertEqual(result[-1]["reason"], reason)
            self.assertTrue(runner.nodes[2]["blocked"])
            self.assertEqual(feed(runner, 12), [])

    def test_future_stale_and_clock_regression_rejected(self):
        for at in (999_999_999, 3_000_000_001):
            runner = stream.ReplayRunner(
                config(),
                clock=Clock(),
                expected_coordinate_frame="example_lab_xz_metres",
            )
            self.assertEqual(
                runner.consume(envelope(raw(0), at))[-1]["reason"],
                "future_or_stale_frame",
            )
            self.assertIsNone(runner.nodes[2]["last"])
        clock = Clock()
        runner = stream.ReplayRunner(
            config(), clock=clock, expected_coordinate_frame="example_lab_xz_metres"
        )
        feed(runner, count=1)
        with self.assertRaisesRegex(ValueError, "replay clock regressed"):
            runner.consume(envelope(raw(1), 999_999_999))
        clock.now = 10
        runner.poll()
        clock.now = 9
        with self.assertRaisesRegex(ValueError, "local monotonic"):
            runner.poll()

    def test_config_and_report_mutation_cannot_change_pins(self):
        cfg = config()
        runner = stream.ReplayRunner(
            cfg, clock=Clock(), expected_coordinate_frame="example_lab_xz_metres"
        )
        cfg["source"]["session_id"] = "changed"
        report = runner.start_record()
        report["source_stream"]["session_id"] = "changed"
        self.assertEqual(runner.source["session_id"], "synthetic-replay")
        self.assertEqual(len(feed(runner)), 1)
        for policy in (
            {"duration_ms": False},
            {"min_frames": 4097},
            {"no_input_timeout_ms": 0},
        ):
            bad = config()
            bad["policy"].update(policy)
            with self.assertRaises(ValueError):
                stream.ReplayRunner(
                    bad,
                    clock=Clock(),
                    expected_coordinate_frame="example_lab_xz_metres",
                )

    def test_discarded_boundary_receipt_cannot_seed_a_later_epoch(self):
        runner = stream.ReplayRunner(
            config(), clock=Clock(), expected_coordinate_frame="example_lab_xz_metres"
        )
        feed(runner)
        boundary = envelope(raw(11, sequence=99))
        self.assertEqual(runner.consume(boundary)[-1]["reason"], "input_discontinuity")
        self.assertEqual(
            runner.consume(boundary)[-1]["reason"], "replayed_or_regressed_receipt"
        )
        self.assertIsNone(runner.nodes[2]["last"])

    def test_caller_frame_mutation_cannot_change_already_validated_window(self):
        original = raw(0)
        runner = stream.ReplayRunner(
            config(), clock=Clock(), expected_coordinate_frame="example_lab_xz_metres"
        )
        runner.consume(envelope(original))
        original["iq"][0] = 127
        original["session_id"] = "changed-after-admission"
        actual = feed(runner, start=1, count=10)[-1]
        expected = feed(
            stream.ReplayRunner(
                config(),
                clock=Clock(),
                expected_coordinate_frame="example_lab_xz_metres",
            )
        )[-1]
        self.assertEqual(actual["feature_sha256"], expected["feature_sha256"])
        self.assertEqual(
            actual["current_input_provenance"], expected["current_input_provenance"]
        )


@unittest.skipUnless(
    importlib.util.find_spec("numpy"), "NumPy needed for synthetic models"
)
class CandidateTests(unittest.TestCase):
    def test_consumed_window_cannot_be_replayed_after_local_silence(self):
        clock = Clock()
        runner = stream.ReplayRunner(
            config(models={"2": model_fixture()}),
            emit_candidates=True,
            clock=clock,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        original = feed(runner)[-1]
        clock.now = 2_000_000_000
        self.assertEqual(
            runner.poll()[0]["withdrawn_window_id"],
            original["current_input_provenance"]["window_id"],
        )
        for i in range(11):
            result = runner.consume(envelope(raw(i), 2_000_000_000))
            self.assertEqual(result[-1]["reason"], "replayed_or_regressed_receipt")
            self.assertFalse(any(r.get("research_candidate") for r in result))
        self.assertEqual(feed(runner, start=11, count=10), [])
        self.assertIsNotNone(feed(runner, start=21, count=1)[-1]["research_candidate"])

    def test_partial_fresh_input_does_not_renew_candidate_source_or_local_lease(self):
        for expiry_clock in ("source", "local"):
            with self.subTest(expiry_clock=expiry_clock):
                clock = Clock()
                cfg = config(models={"2": model_fixture()})
                cfg["policy"]["max_source_age_ms"] = 150
                runner = stream.ReplayRunner(
                    cfg,
                    emit_candidates=True,
                    clock=clock,
                    expected_coordinate_frame="example_lab_xz_metres",
                )
                original = feed(runner)[-1]
                self.assertEqual(feed(runner, start=11, count=1), [])
                builder = runner.nodes[2]["builder"]
                if expiry_clock == "source":
                    result = feed(runner, start=12, count=1)
                else:
                    clock.now = 150_000_000
                    self.assertEqual(runner.poll(), [])
                    clock.now += 1
                    result = runner.poll()
                self.assertEqual(
                    result[-1]["reason"], f"candidate_{expiry_clock}_expired"
                )
                self.assertEqual(
                    result[-1]["withdrawn_window_id"],
                    original["current_input_provenance"]["window_id"],
                )
                self.assertEqual(result[-1]["node_epoch"], 1)
                self.assertIs(runner.nodes[2]["builder"], builder)
                self.assertTrue(runner.nodes[2]["active"])
                self.assertIsNone(runner.nodes[2]["candidate_window_id"])
                self.assertEqual(runner.poll(), [])

    def test_numeric_values_exactly_match_existing_predict_both_contracts(self):
        for contract in (FEATURE_CONTRACT, PREFIX_FEATURE_CONTRACT):
            model = model_fixture(contract=contract)
            runner = stream.ReplayRunner(
                config(models={"2": model}, contract=contract),
                emit_candidates=True,
                clock=Clock(),
                expected_coordinate_frame="example_lab_xz_metres",
            )
            result = feed(runner)[-1]
            builder = WindowBuilder(profiles=[profile()], feature_contract=contract)
            for i in range(11):
                window = builder.push(raw(i))
            expected = predict(
                model,
                window,
                feature_contract=contract,
                expected_coordinate_frame="example_lab_xz_metres",
            )
            self.assertEqual(
                result["research_candidate"]["prediction"], expected["prediction"]
            )
            self.assertEqual(
                result["current_input_provenance"]["window_id"], expected["window_id"]
            )
            self.assertEqual(
                result["feature_count"], 192 if contract == FEATURE_CONTRACT else 186
            )
            self.assertEqual(result["status"], "unavailable")
            self.assertIsNone(result["research_candidate"]["confidence"])
            withdrawn = runner.close("input_ended")[0]
            self.assertEqual(withdrawn["withdrawn_window_id"], window["window_id"])

    def test_verified_training_lineage_is_not_reused_as_current_input_proof(self):
        model = model_fixture(verified=True)
        runner = stream.ReplayRunner(
            config(models={"2": model}),
            emit_candidates=True,
            clock=Clock(),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        start = runner.start_record()
        self.assertEqual(
            start["models"]["2"]["model_capture_lineage"], model["capture_lineage"]
        )
        result = feed(runner)[-1]
        self.assertEqual(
            result["current_input_provenance"]["recording_verification"], "not_supplied"
        )
        self.assertNotIn("capture_evidence", result)
        self.assertNotIn("capture_lineage", result["current_input_provenance"])
        cfg = config(models={"2": model})
        cfg["classification"] = "household_recording"
        with self.assertRaisesRegex(ValueError, "classification mismatch"):
            stream.ReplayRunner(
                cfg, clock=Clock(), expected_coordinate_frame="example_lab_xz_metres"
            )

    def test_candidate_opt_in_and_model_task_shape_profile_contract_binding(self):
        original = model_fixture()
        runner = stream.ReplayRunner(
            config(models={"2": original}),
            clock=Clock(),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertIsNone(feed(runner)[-1]["research_candidate"])
        for mutate in (
            lambda c: c["profiles"][0].update(placement_revision="changed"),
            lambda c: c["source"].update(configuration_sha256="d" * 64),
            lambda c: c["policy"].update(duration_ms=500),
            lambda c: c.update(feature_contract=PREFIX_FEATURE_CONTRACT),
            lambda c: c["models"]["2"].update(task="made_up"),
            lambda c: c["models"]["2"].update(weights=[[1]] * 192),
        ):
            cfg = config(models={"2": copy.deepcopy(original)})
            mutate(cfg)
            with self.assertRaises(ValueError):
                stream.ReplayRunner(
                    cfg,
                    clock=Clock(),
                    expected_coordinate_frame="example_lab_xz_metres",
                )
        runner = stream.ReplayRunner(
            config(models={"2": original}),
            clock=Clock(),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(
            runner.consume(envelope(raw(0, flags=16)))[-1]["reason"],
            "model_input_mismatch",
        )

    def test_slow_candidate_computation_cannot_extend_silence_lease(self):
        clock = Clock()
        runner = stream.ReplayRunner(
            config(models={"2": model_fixture()}),
            emit_candidates=True,
            clock=clock,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        feed(runner, count=10)

        def slow(*args, expected_coordinate_frame):
            self.assertEqual(expected_coordinate_frame, "example_lab_xz_metres")
            clock.now = 2_000_000_000
            return [1, 2]

        with patch.object(stream, "evaluate_candidate_values", side_effect=slow):
            records = feed(runner, start=10, count=1)
        self.assertEqual([r["reason"] for r in records], ["no_input_timeout"])
        self.assertFalse(any("research_candidate" in r for r in records))

    def test_candidate_computation_cannot_extend_source_age_lease(self):
        clock = Clock()
        cfg = config(models={"2": model_fixture()})
        cfg["policy"]["max_source_age_ms"] = 150
        runner = stream.ReplayRunner(
            cfg,
            emit_candidates=True,
            clock=clock,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        feed(runner, count=10)

        def slow(*args, expected_coordinate_frame):
            self.assertEqual(expected_coordinate_frame, "example_lab_xz_metres")
            clock.now = 100_000_001
            return [1, 2]

        with patch.object(stream, "evaluate_candidate_values", side_effect=slow):
            records = runner.consume(envelope(raw(10), 2_050_000_000))
        self.assertEqual(records[-1]["reason"], "candidate_expired_before_emission")
        self.assertTrue(runner.nodes[2]["active"])
        self.assertIsNone(runner.nodes[2]["candidate_window_id"])
        self.assertFalse(any("research_candidate" in r for r in records))


class StreamIOTests(unittest.TestCase):
    def test_named_fifo_without_writer_fails_promptly_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").write_text(json.dumps(config()))
            os.mkfifo(root / "input")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "inference.stream",
                    "--config",
                    str(root / "config"),
                    "--input",
                    str(root / "input"),
                    "--output",
                    str(root / "out"),
                ],
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(result.returncode, 0)
            records = [
                json.loads(line) for line in (root / "out").read_text().splitlines()
            ]
            self.assertFalse(records[-1]["completed"])
            self.assertEqual(records[-2]["reason"], "input_failed")
            failed_config = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "inference.stream",
                    "--config",
                    str(root / "input"),
                    "--input",
                    str(root / "config"),
                    "--output",
                    str(root / "unopened"),
                ],
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(failed_config.returncode, 0)
            self.assertFalse((root / "unopened").exists())

    def test_pipe_silence_polls_before_bounded_deadline_without_new_input(self):
        read_fd, write_fd = os.pipe()
        clock = Clock()
        runner = stream.ReplayRunner(
            config(), clock=clock, expected_coordinate_frame="example_lab_xz_metres"
        )
        records = []

        def ticks():
            clock.now += 300_000_000
            return clock.now / 1e9

        try:
            with self.assertRaisesRegex(ValueError, "deadline"):
                stream.run_input(
                    read_fd, runner, records.append, max_seconds=3, clock=ticks
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertIn("no_input_timeout", [r["reason"] for r in records])

    def test_strict_input_bounds_and_original_hash(self):
        with tempfile.TemporaryFile() as file:
            payload = (json.dumps(envelope(raw(0))) + "\n").encode()
            file.write(payload)
            file.seek(0)
            proof = stream.run_input(
                file.fileno(),
                stream.ReplayRunner(
                    config(),
                    clock=Clock(),
                    expected_coordinate_frame="example_lab_xz_metres",
                ),
                lambda _: None,
            )
            self.assertEqual(proof["sha256"], hashlib.sha256(payload).hexdigest())
            for data, limits in (
                (payload[:-1], {}),
                (b'{"x":1e309}\n', {}),
                (b"{}\n", {"MAX_LINE": 1}),
                (payload, {"MAX_INPUT": 10}),
                (payload, {"MAX_LINES": 0}),
            ):
                file.seek(0)
                file.truncate()
                file.write(data)
                file.seek(0)
                with (
                    patch.multiple(stream, **limits) if limits else nullcontext(),
                    self.assertRaises(ValueError),
                ):
                    stream.run_input(
                        file.fileno(),
                        stream.ReplayRunner(
                            config(),
                            clock=Clock(),
                            expected_coordinate_frame="example_lab_xz_metres",
                        ),
                        lambda _: None,
                    )

    def test_cli_private_new_output_and_failure_withdrawal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").write_text(json.dumps(config()))
            payload = b"".join(
                (json.dumps(envelope(raw(i))) + "\n").encode() for i in range(11)
            )
            command = [
                sys.executable,
                "-m",
                "inference.stream",
                "--config",
                str(root / "config"),
                "--input",
                "-",
                "--output",
                str(root / "out"),
            ]
            result = subprocess.run(
                command,
                input=payload,
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "out").stat().st_mode & 0o777, 0o600)
            original = (root / "out").read_bytes()
            self.assertTrue(json.loads(original.splitlines()[-1])["completed"])
            again = subprocess.run(
                command,
                input=payload,
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((root / "out").read_bytes(), original)
            command[-1] = str(root / "failed")
            result = subprocess.run(
                command,
                input=payload + b"bad-json\n",
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(result.returncode, 0)
            saved = [
                json.loads(line) for line in (root / "failed").read_text().splitlines()
            ]
            self.assertFalse(saved[-1]["completed"])
            self.assertEqual(saved[-2]["reason"], "input_failed")
            self.assertNotIn(str(root), result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
