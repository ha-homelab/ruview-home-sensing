"""Synthetic clock exchanges and local child pipes; never SSH or network."""

import argparse
import copy
import importlib.util
import io
import json
import os
import select
import shlex
import signal
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import reference_clock as clock

SPEC = importlib.util.spec_from_file_location(
    "measure_clock",
    Path(__file__).resolve().parents[1] / "scripts/measure-reference-clock.py",
)
cli = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"reference_clock": clock}):
    SPEC.loader.exec_module(cli)

IDENTITY = {"host_id": "a" * 64, "boot_id": "synthetic-linux-boot"}
NONCE = "b" * 32
BASE = 1_000_000_000_000


def stamp(utc, mono):
    return {"utc_before_ns": utc, "utc_after_ns": utc + 2, "monotonic_ns": mono}


def ready():
    return {
        "schema": clock.READY_SCHEMA,
        "identity": dict(IDENTITY),
        "monotonic_domain": clock.REMOTE_MONOTONIC_DOMAIN,
    }


def sample(index=0, offset=50_000_000, forward=9_000_000, reverse=1_000_000, drift=0):
    utc = BASE + index * 1_000_000_000
    mono = 10_000_000_000 + index * 1_000_000_000
    return {
        "nonce": NONCE,
        "local_send": stamp(utc, mono),
        "local_receive": stamp(utc + forward + reverse, mono + forward + reverse),
        "remote": {
            "schema": clock.SCHEMA,
            "nonce": NONCE,
            "identity": dict(IDENTITY),
            "monotonic_domain": "python_time_monotonic_linux_host_not_worker_start",
            "stamp": stamp(
                utc + forward + offset + drift, mono + forward + 123_000_000
            ),
        },
    }


class ClockMathTests(unittest.TestCase):
    def test_offset_sign_and_asymmetric_network_are_conservative(self):
        for offset in (50_000_000, -50_000_000):
            assessment = clock.Assessment(1000)
            value = sample(offset=offset)
            assessment.push(value)
            interval = value["remote_minus_local_offset_ns"]
            self.assertLessEqual(interval["lower"], offset)
            self.assertGreaterEqual(interval["upper"], offset)
            self.assertEqual(value["round_trip_ns"], 10_000_000)
            self.assertNotEqual(value["interval_midpoint_ns"], offset)
            self.assertEqual(value["clock_step_policy_allowance_ns"], 1000)
            self.assertEqual(value["uncertainty_radius_ns"], 5_001_002)

    def test_drift_bounds_do_not_assume_constant_offset(self):
        assessment = clock.Assessment(5_000_000)
        assessment.push(sample(0))
        assessment.push(sample(1, drift=200_000))
        assessment.push(sample(2, drift=400_000))
        report = assessment.finish()
        bounds = report["first_to_last_offset_change_bounds_ns"]
        self.assertLess(bounds["lower"], 400_000)
        self.assertGreater(bounds["upper"], 400_000)
        self.assertEqual(report["accepted_samples"], 3)

    def test_clock_steps_nonmonotonic_identity_and_nonce_fail(self):
        for change in (
            "local_step",
            "remote_step",
            "remote_monotonic",
            "nonce",
            "identity",
        ):
            with self.subTest(change=change):
                assessment = clock.Assessment(1_000_000)
                assessment.push(sample(0))
                value = sample(1)
                if change == "local_step":
                    value["local_receive"]["utc_before_ns"] += 10_000_000
                    value["local_receive"]["utc_after_ns"] += 10_000_000
                elif change == "remote_step":
                    value["remote"]["stamp"]["utc_before_ns"] += 10_000_000
                    value["remote"]["stamp"]["utc_after_ns"] += 10_000_000
                elif change == "remote_monotonic":
                    value["remote"]["stamp"]["monotonic_ns"] = sample(0)["remote"][
                        "stamp"
                    ]["monotonic_ns"]
                elif change == "nonce":
                    value["remote"]["nonce"] = "c" * 32
                else:
                    value["remote"]["identity"]["boot_id"] = "different-boot"
                with self.assertRaises(clock.ProbeError):
                    assessment.push(value)

    def test_anchor_detects_accumulated_subthreshold_clock_deviation(self):
        assessment = clock.Assessment(1_000_000)
        assessment.push(sample(0))
        assessment.push(sample(1, drift=600_000))
        with self.assertRaisesRegex(clock.ProbeError, "clock_step"):
            assessment.push(sample(2, drift=1_200_000))

    def test_json_and_timestamps_are_bounded_and_finite(self):
        for raw in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":1e309}',
            b'{"a":-1e309}',
            b"{",
            b"x" * 4097,
        ):
            with self.subTest(raw=raw[:20]), self.assertRaises(clock.ProbeError):
                clock.strict_json(raw)
        for value in (True, -1, 2**64, float("nan")):
            remote = sample()["remote"]
            remote["stamp"]["monotonic_ns"] = value
            with self.assertRaises(clock.ProbeError):
                clock.validate_remote(remote)
        value = sample()
        value["local_send"]["utc_after_ns"] += 2_000_000
        with self.assertRaisesRegex(clock.ProbeError, "bracket"):
            clock.Assessment(1_000_000).push(value)

    def test_readiness_requires_exact_schema_domain_and_identity(self):
        self.assertEqual(clock.validate_ready(ready()), ready())
        for change in (
            {"schema": clock.SCHEMA},
            {"nonce": NONCE},
            {"stamp": stamp(BASE, BASE)},
            {"monotonic_domain": "worker_start"},
            {"identity": {"host_id": "a" * 64, "boot_id": False}},
        ):
            with self.subTest(change=change), self.assertRaises(clock.ProbeError):
                clock.validate_ready(ready() | change)
        for key in ready():
            value = ready()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(clock.ProbeError):
                clock.validate_ready(value)


class TransportTests(unittest.TestCase):
    def test_fixed_multiline_remote_program_via_local_shell_no_network(self):
        command = clock.ssh_arguments("worker-host")[-1]
        self.assertEqual(
            shlex.split(command), ["python3", "-u", "-c", clock.REMOTE_PROGRAM]
        )
        compile(clock.REMOTE_PROGRAM, "fixed-responder", "exec")
        with tempfile.TemporaryDirectory() as temporary:
            # Only supply a synthetic Linux boot file when executing on macOS.
            # The actual fixed responder and shell quoting remain unchanged.
            Path(temporary, "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                "original=Path.read_text\n"
                "def read(self,*args,**kwargs):\n"
                " if str(self)=='/proc/sys/kernel/random/boot_id': return 'synthetic-local-shell-only'\n"
                " return original(self,*args,**kwargs)\n"
                "Path.read_text=read\n"
            )
            with patch.dict(os.environ, {"PYTHONPATH": temporary}):
                probe = clock.SSHProbe(["/bin/sh", "-c", command])
            try:
                evidence = {}
                readiness = clock.validate_ready(
                    clock.strict_json(probe.readiness(time.monotonic() + 3, evidence))
                )
                self.assertEqual(
                    readiness["identity"]["boot_id"], "synthetic-local-shell-only"
                )
                self.assertIn("local_wait_started", evidence)
                self.assertIn("local_receive", evidence)
                self.assertNotIn("local_send", evidence)
                for nonce in ("a" * 32, "b" * 32):
                    response = clock.validate_remote(
                        clock.strict_json(
                            probe.exchange(nonce, time.monotonic() + 3, {})
                        )
                    )
                    self.assertEqual(response["nonce"], nonce)
                    self.assertEqual(response["identity"], readiness["identity"])
            finally:
                probe.close()

    def test_startup_timeout_and_partial_readiness_retain_safe_evidence(self):
        program = (
            "import sys,time;time.sleep(0.25);"
            "sys.stdout.write('{');sys.stdout.flush();time.sleep(30)"
        )
        probe = clock.SSHProbe([sys.executable, "-u", "-c", program])
        evidence = {}
        try:
            # Wait for the real partial byte without consuming it. Child startup
            # is independent of the transport deadline, even on a loaded host.
            readable, _, _ = select.select([probe.process.stdout], [], [], 10)
            self.assertEqual(readable, [probe.process.stdout])
            # Expire after the real pipe read, without relying on wall time or
            # adding a newline that would turn this into successful readiness.
            with (
                patch.object(clock.time, "monotonic", side_effect=(100, 102)),
                self.assertRaisesRegex(clock.ProbeError, "startup_deadline_exceeded"),
            ):
                probe.readiness(101, evidence)
            self.assertEqual(evidence["response_bytes"], 1)
            self.assertEqual(
                evidence["response_sha256"], clock.hashlib.sha256(b"{").hexdigest()
            )
            self.assertIn("local_wait_started", evidence)
            self.assertIn("local_failed_at", evidence)
            self.assertNotIn("local_send", evidence)
            self.assertNotIn("local_receive", evidence)
        finally:
            probe.close()
        self.assertIsNotNone(probe.process.poll())
        self.assertTrue(probe.process.stdin.closed)
        self.assertTrue(probe.process.stdout.closed)

    def test_expired_startup_deadline_retains_empty_evidence(self):
        probe = clock.SSHProbe(
            [sys.executable, "-u", "-c", "import time;time.sleep(30)"]
        )
        evidence = {}
        try:
            with (
                patch.object(clock.time, "monotonic", return_value=102),
                self.assertRaisesRegex(clock.ProbeError, "startup_deadline_exceeded"),
            ):
                probe.readiness(101, evidence)
            self.assertEqual(evidence["response_bytes"], 0)
            self.assertEqual(
                evidence["response_sha256"], clock.hashlib.sha256(b"").hexdigest()
            )
            self.assertIn("local_wait_started", evidence)
            self.assertIn("local_failed_at", evidence)
            self.assertNotIn("local_send", evidence)
            self.assertNotIn("local_receive", evidence)
        finally:
            probe.close()
        self.assertIsNotNone(probe.process.poll())
        self.assertTrue(probe.process.stdin.closed)
        self.assertTrue(probe.process.stdout.closed)

    def test_target_and_override_are_arguments_not_shell_source(self):
        args = clock.ssh_arguments("worker-host", "192.168.77.207", True)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("ServerAliveInterval=5", args)
        self.assertIn("ServerAliveCountMax=2", args)
        self.assertIn("Hostname=192.168.77.207", args)
        self.assertIn("ProxyJump=none", args)
        self.assertEqual(args[-2], "worker-host")
        self.assertEqual(args[-1], clock.ssh_arguments("another-host")[-1])
        for target in (
            "-oProxyCommand=bad",
            "user@worker-host",
            "worker-host;bad",
            "worker-host\n",
            "$(bad)",
        ):
            with self.subTest(target=target), self.assertRaises(clock.ProbeError):
                clock.ssh_arguments(target)
        with self.assertRaises(clock.ProbeError):
            clock.ssh_arguments("worker-host", "x -o StrictHostKeyChecking=no")

    def test_persistent_local_pipe_and_cleanup_no_network(self):
        program = "import sys,json\nfor line in sys.stdin:\n print(json.dumps(json.loads(line)),flush=True)"
        probe = clock.SSHProbe([sys.executable, "-u", "-c", program])
        pid = probe.process.pid
        try:
            for nonce in ("a" * 32, "b" * 32):
                evidence = {}
                value = clock.strict_json(
                    probe.exchange(nonce, time.monotonic() + 3, evidence)
                )
                self.assertEqual(value["nonce"], nonce)
                self.assertEqual(probe.process.pid, pid)
                self.assertIn("local_receive", evidence)
        finally:
            probe.close()
        self.assertIsNotNone(probe.process.poll())
        self.assertTrue(probe.process.stdin.closed)
        self.assertTrue(probe.process.stdout.closed)
        probe.close()

    def test_explicit_config_is_a_literal_argument_and_keeps_strict_policy(self):
        config = "/private/clock route/ssh config"
        args = clock.ssh_arguments("clock-worker-host", ssh_config=config)
        self.assertEqual(args[args.index("-F") + 1], config)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertEqual(args[-2], "clock-worker-host")
        self.assertEqual(args[-1], clock.ssh_arguments("worker-host")[-1])
        self.assertNotIn("-F", clock.ssh_arguments("worker-host"))
        for invalid in (
            "relative/config",
            "-Fother",
            "",
            "/tmp/a\nHost *",
            "/tmp/a\x00",
            True,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(clock.ProbeError):
                clock.ssh_arguments("clock-worker-host", ssh_config=invalid)

    def test_timeout_oversize_eof_and_failure_evidence_are_bounded(self):
        programs = (
            ("import time;time.sleep(30)", "deadline"),
            ("print('x'*5000,flush=True)", "too_large"),
            ("pass", "closed"),
        )
        for program, reason in programs:
            with self.subTest(reason=reason):
                probe = clock.SSHProbe([sys.executable, "-u", "-c", program])
                evidence = {}
                try:
                    timeout = 0.05 if reason == "deadline" else 3
                    with self.assertRaisesRegex(clock.ProbeError, reason):
                        probe.exchange(NONCE, time.monotonic() + timeout, evidence)
                finally:
                    probe.close()
                self.assertLessEqual(evidence["response_bytes"], clock.MAX_LINE + 1)
                self.assertIn("response_sha256", evidence)
                self.assertIn("local_failed_at", evidence)
                self.assertIsNotNone(probe.process.poll())

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process groups")
    def test_cleanup_kills_term_ignoring_descendant_after_leader_exit(self):
        for leader_exits_first in (True, False):
            with self.subTest(leader_exits_first=leader_exits_first):
                program = """
import os,signal,sys,time,json
sys.stdin.readline()
reader,writer=os.pipe()
child=os.fork()
if child == 0:
    os.close(reader)
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    os.write(writer,b"1")
    os.close(writer)
    time.sleep(30)
    os._exit(0)
os.close(writer)
os.read(reader,1)
os.close(reader)
print(json.dumps({"child_pid":child}),flush=True)
"""
                program += "sys.exit(0)" if leader_exits_first else "time.sleep(30)"
                probe = clock.SSHProbe([sys.executable, "-u", "-c", program])
                child = None
                try:
                    response = clock.strict_json(
                        probe.exchange(NONCE, time.monotonic() + 3, {})
                    )
                    child = response["child_pid"]
                    if leader_exits_first:
                        probe.process.wait(timeout=1)
                    original = os.killpg
                    with patch.object(clock.os, "killpg", wraps=original) as signals:
                        started = time.monotonic()
                        probe.close()
                        self.assertLess(time.monotonic() - started, 2.2)
                        self.assertTrue(
                            any(
                                call.args[1] == signal.SIGKILL
                                for call in signals.call_args_list
                            )
                        )
                    self.assertIsNotNone(probe.process.poll())
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(probe.process.pid, 0)
                finally:
                    if child is not None:
                        try:
                            os.kill(child, signal.SIGKILL)
                        except ProcessLookupError:
                            # The process-group assertion may already have reaped it.
                            pass
                    probe.close()


def arguments(**changes):
    values = dict(
        host="worker-host",
        hostname=None,
        no_proxyjump=False,
        ssh_config=None,
        samples=2,
        interval_ms=0,
        sample_timeout_ms=3000,
        startup_timeout_ms=30000,
        deadline_seconds=30,
        max_clock_step_ms=5,
    )
    return argparse.Namespace(**(values | changes))


class FakeTransport:
    def __init__(self, _args, fail=False):
        self.index, self.closed, self.fail = 0, False, fail

    def readiness(self, _deadline, evidence):
        evidence.update(local_wait_started=clock.stamp(), local_receive=clock.stamp())
        return json.dumps(ready()).encode() + b"\n"

    def exchange(self, nonce, _deadline, evidence):
        value = sample(self.index)
        self.index += 1
        value["nonce"] = value["remote"]["nonce"] = nonce
        evidence.update(
            local_send=value["local_send"], local_receive=value["local_receive"]
        )
        if self.fail:
            raise RuntimeError("synthetic-secret-must-not-be-reported")
        return json.dumps(value["remote"]).encode() + b"\n"

    def close(self):
        self.closed = True


class RunnerTests(unittest.TestCase):
    def test_selected_config_reaches_transport_and_is_recorded(self):
        config = "/private/clock route/config"
        seen = []

        def factory(args):
            seen.extend(args)
            return FakeTransport(args)

        report = cli.run(
            arguments(ssh_config=config),
            factory=factory,
            identity_fn=lambda: dict(IDENTITY),
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["settings"]["ssh_config"], config)
        self.assertEqual(seen[seen.index("-F") + 1], config)

    def test_runner_retains_successful_and_failed_evidence_and_cleans_up(self):
        for fail in (False, True):
            transport = FakeTransport([], fail=fail)
            report = cli.run(
                arguments(),
                factory=lambda _args, transport=transport: transport,
                identity_fn=lambda: dict(IDENTITY),
            )
            self.assertEqual(report["passed"], not fail)
            self.assertTrue(report["ssh_process_cleaned_up"])
            self.assertTrue(transport.closed)
            self.assertTrue(report["samples"])
            self.assertFalse(report["calibration_applied"])
            self.assertFalse(report["clocks_between_probes_verified"])
            self.assertNotIn("synthetic-secret", json.dumps(report))

    def test_bad_arguments_never_start_a_transport(self):
        for change in (
            {"samples": 65},
            {"deadline_seconds": 91},
            {"host": "worker-host;bad"},
            {"sample_timeout_ms": 0},
            {"startup_timeout_ms": 49},
            {"startup_timeout_ms": 30001},
            {"ssh_config": "relative/config"},
        ):
            with self.subTest(change=change):
                with patch.object(cli, "SSHProbe") as factory:
                    report = cli.run(arguments(**change), factory=factory)
                self.assertFalse(report["passed"])
                factory.assert_not_called()

    def test_startup_is_separate_and_limited_by_overall_deadline(self):
        now = [100.0]
        startup_deadlines, sample_deadlines = [], []
        transport = FakeTransport([])
        original_ready, original_exchange = transport.readiness, transport.exchange

        def readiness(deadline, evidence):
            startup_deadlines.append(deadline)
            self.assertEqual(transport.index, 0)
            now[0] = 129.0
            return original_ready(deadline, evidence)

        def exchange(nonce, deadline, evidence):
            sample_deadlines.append(deadline)
            now[0] += 0.1
            return original_exchange(nonce, deadline, evidence)

        transport.readiness, transport.exchange = readiness, exchange
        report = cli.run(
            arguments(deadline_seconds=45, sample_timeout_ms=10000),
            factory=lambda _args: transport,
            identity_fn=lambda: dict(IDENTITY),
            monotonic=lambda: now[0],
            sleep=lambda _seconds: None,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(startup_deadlines, [130.0])
        self.assertEqual(sample_deadlines, [139.0, 139.1])
        self.assertTrue(report["readiness"]["passed"])
        self.assertFalse(report["readiness"]["is_offset_sample"])
        self.assertEqual(report["samples"][0]["round_trip_ns"], 10_000_000)

        # Startup's 30-second setting cannot extend the 5-second overall budget.
        now[0] = 100.0
        transport = FakeTransport([])
        transport.readiness = readiness
        report = cli.run(
            arguments(deadline_seconds=5),
            factory=lambda _args: transport,
            identity_fn=lambda: dict(IDENTITY),
            monotonic=lambda: now[0],
        )
        self.assertEqual(startup_deadlines[-1], 105.0)
        self.assertEqual(report["failed_gate"], "startup_deadline_exceeded")
        self.assertFalse(report["readiness"]["passed"])
        self.assertEqual(report["accepted_samples"], 0)
        self.assertEqual(report["samples"], [])
        self.assertTrue(report["ssh_process_cleaned_up"])

    def test_failed_or_malformed_readiness_never_sends_nonce(self):
        for kind in ("failure", "overflow", "extra_field", "wrong_schema"):
            transport = FakeTransport([])

            def readiness(_deadline, evidence, kind=kind):
                evidence["local_wait_started"] = clock.stamp()
                if kind == "failure":
                    raise RuntimeError("synthetic-secret-must-not-be-reported")
                if kind == "overflow":
                    return b'{"x":1e309}'
                value = ready() | (
                    {"nonce": NONCE}
                    if kind == "extra_field"
                    else {"schema": clock.SCHEMA}
                )
                return json.dumps(value).encode()

            transport.readiness = readiness
            report = cli.run(
                arguments(),
                factory=lambda _args, transport=transport: transport,
                identity_fn=lambda: dict(IDENTITY),
            )
            self.assertFalse(report["passed"])
            self.assertFalse(report["readiness"]["passed"])
            self.assertIn("local_failed_at", report["readiness"])
            self.assertIn("response_sha256", report["readiness"])
            self.assertEqual(report["samples"], [])
            self.assertEqual(transport.index, 0)
            self.assertTrue(report["ssh_process_cleaned_up"])
            self.assertNotIn("synthetic-secret", json.dumps(report, allow_nan=False))

    def test_first_nonce_identity_must_match_readiness(self):
        transport = FakeTransport([])
        value = ready()
        value["identity"]["boot_id"] = "different-ready-boot"
        transport.readiness = lambda _deadline, _evidence: json.dumps(value).encode()
        report = cli.run(
            arguments(),
            factory=lambda _args: transport,
            identity_fn=lambda: dict(IDENTITY),
        )
        self.assertFalse(report["passed"])
        self.assertTrue(report["readiness"]["passed"])
        self.assertEqual(report["failed_gate"], "readiness_identity_mismatch")
        self.assertEqual(report["accepted_samples"], 0)
        self.assertFalse(report["samples"][0]["passed"])
        self.assertTrue(report["ssh_process_cleaned_up"])

    def test_wrong_nonce_and_overflow_retained_safely_as_failures(self):
        for kind in ("nonce", "overflow"):
            transport = FakeTransport([])
            original = transport.exchange

            def exchange(nonce, deadline, evidence, original=original, kind=kind):
                raw = original(nonce, deadline, evidence)
                if kind == "overflow":
                    return b'{"x":1e309}'
                value = json.loads(raw)
                value["nonce"] = "c" * 32
                return json.dumps(value).encode()

            transport.exchange = exchange
            report = cli.run(
                arguments(),
                factory=lambda _args, transport=transport: transport,
                identity_fn=lambda: dict(IDENTITY),
            )
            self.assertFalse(report["passed"])
            self.assertEqual(
                report["failed_gate"],
                "nonce_mismatch" if kind == "nonce" else "nonfinite_json_number",
            )
            self.assertIn("response_sha256", report["samples"][0])
            json.dumps(report, allow_nan=False)

    def test_cleanup_failure_cannot_report_success(self):
        transport = FakeTransport([])
        with patch.object(
            transport, "close", side_effect=RuntimeError("private detail")
        ):
            report = cli.run(
                arguments(),
                factory=lambda _args: transport,
                identity_fn=lambda: dict(IDENTITY),
            )
        self.assertFalse(report["passed"])
        self.assertFalse(report["ssh_process_cleaned_up"])
        self.assertEqual(report["failed_gate"], "ssh_cleanup_failed")
        self.assertEqual(len(report["samples"]), 2)
        self.assertNotIn("private detail", json.dumps(report))

    def test_output_is_private_exclusive_and_failed_report_is_saved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            argv = ["measure", "--host", "worker-host", "--output", str(output)]
            failed = {
                "schema": "synthetic-only",
                "passed": False,
                "samples": [],
                "failed_gate": "synthetic_failure",
            }
            with (
                patch.object(sys, "argv", argv),
                patch.object(cli, "run", return_value=copy.deepcopy(failed)) as run,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cli.main(), 1)
                self.assertEqual(json.loads(output.read_text()), failed)
                self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
                self.assertEqual(cli.main(), 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(json.loads(output.read_text()), failed)


if __name__ == "__main__":
    unittest.main()
