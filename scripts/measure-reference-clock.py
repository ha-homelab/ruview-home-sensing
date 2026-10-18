#!/usr/bin/env python3
"""Read-only, explicitly targeted clock probes. No automatic clock correction."""

import argparse
import hashlib
import json
import os
import sys
import time
import uuid

from reference_clock import (
    MAX_SAMPLES,
    Assessment,
    ProbeError,
    SSHProbe,
    integer,
    local_identity,
    require,
    ssh_arguments,
    stamp,
    strict_json,
    validate_ready,
    validate_remote,
)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeError("invalid_clock_probe_arguments")


def run(
    args,
    factory=SSHProbe,
    identity_fn=local_identity,
    monotonic=time.monotonic,
    sleep=time.sleep,
):
    report = {
        "schema": "ruview.reference_clock.measurement.v1",
        "probe_run_id": str(uuid.uuid4()),
        "started_at_ns": time.time_ns(),
        "passed": False,
        "read_only": True,
        "calibration_applied": False,
        "recognition_validated": False,
        "camera_or_recording_started": False,
        "midpoint_assumes_symmetric_network": False,
        "clocks_between_probes_verified": False,
        "local_monotonic_domain": "python_time_monotonic_local_host",
        "remote_monotonic_domain": "python_time_monotonic_linux_host_not_worker_start",
        "samples": [],
        "accepted_samples": 0,
    }
    probe = None
    sample = None
    try:
        require(integer(args.samples, 2, MAX_SAMPLES), "sample_count_out_of_bounds")
        require(integer(args.interval_ms, 0, 1000), "sample_interval_out_of_bounds")
        require(
            integer(args.sample_timeout_ms, 50, 10000), "sample_timeout_out_of_bounds"
        )
        require(
            integer(args.startup_timeout_ms, 50, 30000), "startup_timeout_out_of_bounds"
        )
        require(integer(args.deadline_seconds, 5, 90), "overall_deadline_out_of_bounds")
        require(
            integer(args.max_clock_step_ms, 1, 1000), "clock_step_policy_out_of_bounds"
        )
        arguments = ssh_arguments(
            args.host, args.hostname, args.no_proxyjump, args.ssh_config
        )
        deadline = monotonic() + args.deadline_seconds
        report["local_identity"] = identity_fn()
        report["settings"] = {
            key: getattr(args, key)
            for key in (
                "host",
                "hostname",
                "no_proxyjump",
                "ssh_config",
                "samples",
                "interval_ms",
                "sample_timeout_ms",
                "startup_timeout_ms",
                "deadline_seconds",
                "max_clock_step_ms",
            )
        }
        require(monotonic() < deadline, "overall_deadline_exceeded")
        assessment = Assessment(args.max_clock_step_ms * 1_000_000)
        readiness = {
            "passed": False,
            "local_process_started": stamp(),
            "response_bytes": 0,
            "response_sha256": hashlib.sha256(b"").hexdigest(),
            "is_offset_sample": False,
        }
        report["readiness"] = readiness
        startup_deadline = min(deadline, monotonic() + args.startup_timeout_ms / 1000)
        probe = factory(arguments)
        raw = probe.readiness(startup_deadline, readiness)
        readiness["response_bytes"] = len(raw)
        readiness["response_sha256"] = hashlib.sha256(raw).hexdigest()
        readiness["remote"] = validate_ready(strict_json(raw))
        require(monotonic() <= startup_deadline, "startup_deadline_exceeded")
        readiness["passed"] = True
        for index in range(args.samples):
            sample = {"index": index, "nonce": uuid.uuid4().hex, "passed": False}
            report["samples"].append(sample)
            sample_deadline = min(deadline, monotonic() + args.sample_timeout_ms / 1000)
            raw = probe.exchange(sample["nonce"], sample_deadline, sample)
            sample["response_bytes"] = len(raw)
            sample["response_sha256"] = hashlib.sha256(raw).hexdigest()
            sample["remote"] = validate_remote(strict_json(raw))
            require(
                sample["remote"]["identity"] == readiness["remote"]["identity"],
                "readiness_identity_mismatch",
            )
            assessment.push(sample)
            report["accepted_samples"] = len(assessment.accepted)
            if index + 1 < args.samples:
                wait = args.interval_ms / 1000
                require(monotonic() + wait < deadline, "overall_deadline_exceeded")
                sleep(wait)
        require(monotonic() <= deadline, "overall_deadline_exceeded")
        report.update(assessment.finish(), passed=True)
    except (Exception, KeyboardInterrupt) as error:
        report["error_type"] = type(error).__name__
        report["failed_gate"] = (
            str(error) if isinstance(error, ProbeError) else "clock_probe_failed"
        )
        if sample is not None:
            sample["passed"] = False
            sample["failed_gate"] = report["failed_gate"]
        elif "readiness" in report:
            report["readiness"].update(
                passed=False,
                failed_gate=report["failed_gate"],
                local_failed_at=stamp(),
            )
    finally:
        if probe is not None:
            try:
                probe.close()
                report["ssh_process_cleaned_up"] = True
            except Exception:
                report.update(
                    passed=False,
                    ssh_process_cleaned_up=False,
                    failed_gate="ssh_cleanup_failed",
                )
        report["finished_at_ns"] = time.time_ns()
    return report


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument(
            "--host", required=True, help="explicit reviewed SSH alias/hostname"
        )
        parser.add_argument("--hostname", help="explicit SSH Hostname override")
        parser.add_argument("--no-proxyjump", action="store_true")
        parser.add_argument(
            "--ssh-config",
            help="absolute path to an explicitly reviewed OpenSSH config for all hops",
        )
        parser.add_argument("--samples", type=int, default=8)
        parser.add_argument("--interval-ms", type=int, default=250)
        parser.add_argument("--sample-timeout-ms", type=int, default=3000)
        parser.add_argument("--startup-timeout-ms", type=int, default=30000)
        parser.add_argument("--deadline-seconds", type=int, default=30)
        parser.add_argument("--max-clock-step-ms", type=int, default=5)
        parser.add_argument(
            "--output", required=True, help="new private report path; never overwritten"
        )
        args = parser.parse_args()
        # Reserve the private output before starting a subprocess or network call.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            report = run(args)
            encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
            require(len(encoded.encode()) <= 1_048_576, "report_bound_exceeded")
            output.write(encoded)
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "accepted_samples": report.get("accepted_samples", 0),
                    "failed_gate": report.get("failed_gate"),
                }
            )
        )
        return 0 if report["passed"] else 1
    except (Exception, KeyboardInterrupt) as error:
        # Do not echo paths, SSH stderr, arguments or arbitrary exception strings.
        print(
            json.dumps(
                {
                    "passed": False,
                    "error_type": type(error).__name__,
                    "failed_gate": str(error)
                    if isinstance(error, ProbeError)
                    else "report_setup_or_write_failed",
                }
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
