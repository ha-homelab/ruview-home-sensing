"""Read-only reference-clock probes; no clock adjustment or calibration."""

import hashlib
import json
import math
import os
import re
import select
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

MAX_LINE = 4096
MAX_SAMPLES = 64
SCHEMA = "ruview.reference_clock.exchange.v1"
READY_SCHEMA = "ruview.reference_clock.ready.v1"
REMOTE_MONOTONIC_DOMAIN = "python_time_monotonic_linux_host_not_worker_start"
U64 = 2**64 - 1

# Fixed source only: no host, pathname, nonce or operator input is interpolated.
# The remote host is Linux; its monotonic clock is not a worker's process-relative clock.
REMOTE_PROGRAM = r"""
import hashlib,json,signal,socket,sys,time
from pathlib import Path
signal.alarm(120)
identity={"host_id":hashlib.sha256(socket.gethostname().encode()).hexdigest(),
          "boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
ready={"schema":"ruview.reference_clock.ready.v1","identity":identity,
       "monotonic_domain":"python_time_monotonic_linux_host_not_worker_start"}
print(json.dumps(ready,separators=(",",":")),flush=True)
for _ in range(64):
    line=sys.stdin.buffer.readline(4097)
    if not line: break
    if len(line)>4096 or not line.endswith(b"\n"): sys.exit(2)
    request=json.loads(line)
    if set(request)!={"schema","nonce"} or request["schema"]!="ruview.reference_clock.exchange.v1": sys.exit(2)
    nonce=request["nonce"]
    if not isinstance(nonce,str) or len(nonce)!=32 or any(c not in "0123456789abcdef" for c in nonce): sys.exit(2)
    before=time.time_ns()
    mono=time.monotonic_ns()
    after=time.time_ns()
    response={"schema":request["schema"],"nonce":nonce,"identity":identity,
              "monotonic_domain":"python_time_monotonic_linux_host_not_worker_start",
              "stamp":{"utc_before_ns":before,"monotonic_ns":mono,"utc_after_ns":after}}
    print(json.dumps(response,separators=(",",":")),flush=True)
"""


class ProbeError(ValueError):
    """Fixed reason codes only; remote data and credentials never enter errors."""


def require(condition, code):
    if not condition:
        raise ProbeError(code)


def integer(value, low=0, high=U64):
    return type(value) is int and low <= value <= high


def strict_json(raw):
    require(len(raw) <= MAX_LINE, "response_too_large")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise ProbeError("nonfinite_json_number")

    def finite_float(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite_json_number")
        return value

    try:
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=finite_float,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProbeError("malformed_response_json") from error


def validate_identity(value):
    require(
        isinstance(value, dict) and set(value) == {"host_id", "boot_id"},
        "invalid_clock_identity",
    )
    require(
        isinstance(value["host_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["host_id"]),
        "invalid_host_identity",
    )
    require(
        isinstance(value["boot_id"], str)
        and re.fullmatch(r"[A-Za-z0-9-]{1,64}", value["boot_id"]),
        "invalid_boot_identity",
    )
    return value


def local_identity():
    # Same hashed hostname and OS boot identity conventions as coverage_producer.
    if sys.platform == "darwin":
        boot = (
            subprocess.check_output(
                ["sysctl", "-n", "kern.bootsessionuuid"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            .decode()
            .strip()
        )
    elif sys.platform.startswith("linux"):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    else:
        raise ProbeError("unsupported_local_clock_platform")
    return validate_identity(
        {
            "host_id": hashlib.sha256(socket.gethostname().encode()).hexdigest(),
            "boot_id": boot,
        }
    )


def stamp():
    before = time.time_ns()
    mono = time.monotonic_ns()
    after = time.time_ns()
    return {"utc_before_ns": before, "monotonic_ns": mono, "utc_after_ns": after}


def validate_stamp(value, tolerance_ns):
    require(
        isinstance(value, dict)
        and set(value) == {"utc_before_ns", "monotonic_ns", "utc_after_ns"},
        "invalid_clock_stamp",
    )
    require(all(integer(v) for v in value.values()), "invalid_timestamp_integer")
    require(
        value["utc_before_ns"] > 0 and value["utc_after_ns"] >= value["utc_before_ns"],
        "utc_clock_moved_backwards",
    )
    require(
        value["utc_after_ns"] - value["utc_before_ns"] <= tolerance_ns,
        "timestamp_bracket_too_wide",
    )


def clock_delta(old, new, tolerance_ns):
    delta = new["monotonic_ns"] - old["monotonic_ns"]
    require(
        delta > 0 and new["utc_before_ns"] > old["utc_after_ns"], "nonmonotonic_clock"
    )
    lower = new["utc_before_ns"] - old["utc_after_ns"] - delta
    upper = new["utc_after_ns"] - old["utc_before_ns"] - delta
    require(
        lower <= tolerance_ns and upper >= -tolerance_ns, "utc_monotonic_clock_step"
    )
    return {"lower": lower, "upper": upper}


def validate_ready(value):
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "identity", "monotonic_domain"}
        and value["schema"] == READY_SCHEMA,
        "invalid_readiness_schema",
    )
    require(
        value["monotonic_domain"] == REMOTE_MONOTONIC_DOMAIN,
        "unknown_remote_monotonic_domain",
    )
    validate_identity(value["identity"])
    return value


def validate_remote(value):
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "nonce", "identity", "stamp", "monotonic_domain"},
        "invalid_response_schema",
    )
    require(value["schema"] == SCHEMA, "invalid_response_schema")
    require(
        isinstance(value["nonce"], str)
        and re.fullmatch(r"[0-9a-f]{32}", value["nonce"]),
        "invalid_response_nonce",
    )
    require(
        value["monotonic_domain"] == REMOTE_MONOTONIC_DOMAIN,
        "unknown_remote_monotonic_domain",
    )
    validate_identity(value["identity"])
    # Type validation before retaining any remote fields in a report.
    validate_stamp(value["stamp"], U64)
    return value


class Assessment:
    def __init__(self, tolerance_ns):
        require(integer(tolerance_ns, 1, 1_000_000_000), "invalid_clock_step_policy")
        self.tolerance_ns = tolerance_ns
        self.first = self.last = None
        self.accepted = []

    def push(self, sample):
        before, after = sample["local_send"], sample["local_receive"]
        remote = sample["remote"]
        validate_remote(remote)
        require(remote["nonce"] == sample["nonce"], "nonce_mismatch")
        for value in (before, after, remote["stamp"]):
            validate_stamp(value, self.tolerance_ns)
        sample["local_exchange_clock_residual_ns"] = clock_delta(
            before, after, self.tolerance_ns
        )
        if self.first is not None:
            require(
                remote["identity"] == self.first["remote"]["identity"],
                "remote_host_or_boot_changed",
            )
            sample["local_since_previous_clock_residual_ns"] = clock_delta(
                self.last["local_receive"], before, self.tolerance_ns
            )
            sample["remote_since_previous_clock_residual_ns"] = clock_delta(
                self.last["remote"]["stamp"], remote["stamp"], self.tolerance_ns
            )
            sample["local_since_first_clock_residual_ns"] = clock_delta(
                self.first["local_send"], after, self.tolerance_ns
            )
            sample["remote_since_first_clock_residual_ns"] = clock_delta(
                self.first["remote"]["stamp"], remote["stamp"], self.tolerance_ns
            )
        lower = (
            remote["stamp"]["utc_before_ns"] - after["utc_after_ns"] - self.tolerance_ns
        )
        upper = (
            remote["stamp"]["utc_after_ns"]
            - before["utc_before_ns"]
            + self.tolerance_ns
        )
        require(lower <= upper, "inverted_offset_interval")
        midpoint = (lower + upper) // 2
        sample.update(
            passed=True,
            round_trip_ns=after["monotonic_ns"] - before["monotonic_ns"],
            remote_minus_local_offset_ns={"lower": lower, "upper": upper},
            interval_midpoint_ns=midpoint,
            uncertainty_radius_ns=max(midpoint - lower, upper - midpoint),
            clock_step_policy_allowance_ns=self.tolerance_ns,
        )
        self.first = self.first or sample
        self.last = sample
        self.accepted.append(sample)

    def finish(self):
        require(len(self.accepted) >= 2, "insufficient_clock_samples")
        intervals = [s["remote_minus_local_offset_ns"] for s in self.accepted]
        return {
            "remote_identity": self.first["remote"]["identity"],
            "accepted_samples": len(self.accepted),
            "observed_offset_envelope_ns": {
                "lower": min(v["lower"] for v in intervals),
                "upper": max(v["upper"] for v in intervals),
            },
            "first_to_last_offset_change_bounds_ns": {
                "lower": intervals[-1]["lower"] - intervals[0]["upper"],
                "upper": intervals[-1]["upper"] - intervals[0]["lower"],
            },
            "tightest_sample_index": min(
                range(len(self.accepted)),
                key=lambda i: self.accepted[i]["uncertainty_radius_ns"],
            ),
        }


def ssh_arguments(host, hostname=None, no_proxyjump=False, ssh_config=None):
    # Restrict to saved SSH aliases/hostnames or IPv4 literals. Username/key/port
    # policy stays in reviewed SSH config; neither input can become an option.
    pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}"
    require(isinstance(host, str) and re.fullmatch(pattern, host), "invalid_ssh_host")
    if hostname is not None:
        require(
            isinstance(hostname, str) and re.fullmatch(pattern, hostname),
            "invalid_ssh_hostname",
        )
    require(type(no_proxyjump) is bool, "invalid_proxyjump_option")
    if ssh_config is not None:
        require(
            isinstance(ssh_config, str)
            and len(ssh_config) <= 4096
            and os.path.isabs(ssh_config)
            and not any(char in ssh_config for char in ("\x00", "\n", "\r")),
            "invalid_ssh_config_path",
        )
    args = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "RequestTTY=no",
    ]
    if ssh_config is not None:
        # This is an explicitly reviewed OpenSSH configuration, not shell source.
        # Its jump-host policy must also require strict host-key verification.
        args.extend(["-F", ssh_config])
    if hostname is not None:
        args.extend(["-o", "Hostname=" + hostname])
    if no_proxyjump:
        args.extend(["-o", "ProxyJump=none"])
    args.extend(["--", host, "python3 -u -c " + shlex.quote(REMOTE_PROGRAM)])
    return args


class SSHProbe:
    """One process, bounded nonblocking pipe I/O, no retries or stderr retention."""

    def __init__(self, arguments):
        self.process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            start_new_session=True,
        )
        self.closed = False
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
        except BaseException:
            self.close()
            raise

    def _read_line(self, deadline, evidence, deadline_code):
        raw = bytearray()
        try:
            while b"\n" not in raw:
                remaining = deadline - time.monotonic()
                require(remaining > 0, deadline_code)
                ready, _, _ = select.select([self.process.stdout], [], [], remaining)
                require(bool(ready), deadline_code)
                chunk = os.read(self.process.stdout.fileno(), MAX_LINE + 1 - len(raw))
                require(bool(chunk), "remote_stdout_closed")
                raw.extend(chunk)
                require(len(raw) <= MAX_LINE, "response_too_large")
            evidence["local_receive"] = stamp()
            require(time.monotonic() <= deadline, deadline_code)
            require(
                raw.count(b"\n") == 1 and raw.endswith(b"\n"),
                "unsolicited_or_extra_response",
            )
            return bytes(raw)
        finally:
            evidence["response_bytes"] = len(raw)
            evidence["response_sha256"] = hashlib.sha256(raw).hexdigest()
            if "local_receive" not in evidence:
                evidence["local_failed_at"] = stamp()

    def readiness(self, deadline, evidence):
        # No request or clock sample is sent until this independent phase passes.
        evidence["local_wait_started"] = stamp()
        return self._read_line(deadline, evidence, "startup_deadline_exceeded")

    def exchange(self, nonce, deadline, sample):
        payload = (
            json.dumps(
                {"schema": SCHEMA, "nonce": nonce}, separators=(",", ":")
            ).encode()
            + b"\n"
        )
        require(len(payload) <= MAX_LINE, "request_too_large")
        sent = 0
        sample["local_send"] = stamp()
        sample["response_bytes"] = 0
        sample["response_sha256"] = hashlib.sha256(b"").hexdigest()
        try:
            while sent < len(payload):
                remaining = deadline - time.monotonic()
                require(remaining > 0, "sample_deadline_exceeded")
                _, ready, _ = select.select([], [self.process.stdin], [], remaining)
                require(bool(ready), "sample_deadline_exceeded")
                sent += os.write(self.process.stdin.fileno(), payload[sent:])
            return self._read_line(deadline, sample, "sample_deadline_exceeded")
        finally:
            if "local_receive" not in sample:
                sample["local_failed_at"] = stamp()

    def close(self):
        if self.closed:
            return
        self.closed = True

        def signal_group(value):
            try:
                os.killpg(self.process.pid, value)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                # macOS can report EPERM while a group is exiting. Treat it as
                # still present, never as successful cleanup; genuine denial
                # also fails closed unless the group disappears by the deadline.
                return True

        def group_exists():
            self.process.poll()  # Reap our leader; descendants may still exist.
            return signal_group(0)

        def wait_group(deadline):
            while group_exists():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                time.sleep(min(0.01, remaining))
            return True

        deadline = time.monotonic() + 2
        try:
            # A leader can exit while an owned proxy child retains the pipes.
            # Its entire process group must still receive TERM/KILL.
            signal_group(signal.SIGTERM)
            if not wait_group(min(deadline, time.monotonic() + 1)):
                signal_group(signal.SIGKILL)
                require(wait_group(deadline), "ssh_process_group_cleanup_timeout")
            self.process.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None:
                    stream.close()
