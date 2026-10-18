#!/usr/bin/env python3
"""Bounded synthetic loopback proof of fleet warmup, withdrawal and recovery."""

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from service_smoke import check, port, save_json

MAX_HTTP = 1_048_576
MAX_TRACE = 32 * MAX_HTTP
DEADLINE_SECONDS = 45
NODES = (1, 2, 3)


def packet(node, sequence):
    return struct.pack(
        "<IBBHIIbbBB", 0xC5110001, node, 1, 64, 2462, sequence, -50, -90, 0, 0x10
    ) + bytes([15 + sequence % 3, 253] * 64)


def complete(value, sequences):
    nodes = {node["node_id"]: node for node in value["nodes"]}
    total = sum(sequences.values())
    return (
        value["counters"]["received"] == total
        and value["counters"]["record_written"] == total
        and len(value["nodes"]) == len(sequences)
        and set(nodes) == set(sequences)
        and all(
            nodes[node]["sequence"] == count - 1 and nodes[node]["frames"] == count
            for node, count in sequences.items()
        )
    )


def await_tail(snapshot, sequences, deadline):
    end = min(deadline, time.monotonic() + 1.5)
    while True:
        remaining = end - time.monotonic()
        check(remaining > 0, "fleet publication did not reach exact sent tail")
        value = snapshot(min(1, remaining))  # caller persists before any check
        check(time.monotonic() <= end, "fleet publication deadline exceeded")
        if complete(value, sequences):
            return value
        time.sleep(min(0.05, max(0, end - time.monotonic())))


def close_process_group(process):
    """Reap the owned leader and terminate surviving descendants within two seconds."""
    deadline = time.monotonic() + 2

    def send(sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def exists():
        process.poll()
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    send(signal.SIGTERM)
    grace = time.monotonic() + 0.5
    killed = False
    while exists():
        if not killed and time.monotonic() >= grace:
            send(signal.SIGKILL)
            killed = True
        check(time.monotonic() < deadline, "worker process group cleanup deadline")
        time.sleep(0.01)
    process.wait(timeout=max(0.001, deadline - time.monotonic()))
    return {
        "group_gone": True,
        "sigkill_required": killed,
        "exit_code": process.returncode,
    }


def save_completion(output, raw, sequences, summary, cleanup, failure):
    """Retain and check the raw artifact before permitting a successful report."""
    recording = {"retained": False, "validated": False}
    try:
        save_json(output / "expected.json", {"sent_frames_by_node": sequences})
        destination = output / "raw.synthetic.jsonl"
        # Missing/read/copy errors are evidence failures, including after an
        # otherwise successful executable run. Preserve any partial copy.
        with raw.open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target, 65536)
        recording["retained"] = True
        data = destination.read_bytes()
        check(len(data) <= 5_000_000, "raw artifact exceeded recording bound")
        rows = [json.loads(line) for line in data.splitlines()]
        recording.update(bytes=len(data), rows=len(rows))
        check(len(rows) == sum(sequences.values()), "raw recording coverage")
        counts = {node: 0 for node in sequences}
        for row in rows:
            node = row["node_id"]
            check(type(node) is int and node in counts, "raw node identity")
            check(
                type(row["sequence"]) is int and row["sequence"] == counts[node],
                "raw sequence continuity",
            )
            check(
                type(row["received_at_ns"]) is int
                and type(row["received_monotonic_ns"]) is int,
                "raw integer timestamps",
            )
            check(
                row["antennas"] == 1
                and row["subcarriers"] == 64
                and row["frequency_mhz"] == 2462
                and row["ppdu_type"] == 0
                and row["flags"] == 16,
                "raw grid metadata",
            )
            check(
                row["iq"] == [15 + counts[node] % 3, -3] * 64, "raw signed sample pairs"
            )
            if "worker_run_id" in summary:
                check(
                    row["session_id"] == summary["worker_run_id"], "raw worker identity"
                )
            counts[node] += 1
        check(counts == sequences, "raw per-node coverage")
        recording["validated"] = True
    except BaseException as error:
        recording["failure"] = f"{type(error).__name__}: {error}"
        failure = failure or recording["failure"]
    summary.update(
        passed=failure is None,
        failure=failure,
        cleanup=cleanup,
        raw_recording=recording,
    )
    save_json(output / "summary.json", summary)
    return failure


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def verify_lossless(value):
    check(value["catalog_count"] == 64, "catalog count changed")
    check(value["selected_algorithm_count"] == 21, "per-node selection changed")
    check(value["selected_fleet_algorithm_count"] == 1, "fleet selection missing")
    for name in (
        "rejected",
        "source_rejected",
        "queue_dropped",
        "processing_stale",
        "record_dropped",
        "record_error",
        "record_limit_reached",
    ):
        check(value["counters"][name] == 0, f"loss/error counter: {name}")
    for node in value["nodes"]:
        check(len(node["algorithms"]) == 64, "node catalog changed")
        check(
            node["duplicates"] == 0
            and node["missing_sequences"] == 0
            and node["sequence_discontinuities"] == 0,
            "sequence loss or duplication",
        )
        check(
            node["grid"]
            == {
                "antennas": 1,
                "subcarriers": 64,
                "frequency_mhz": 2462,
                "ppdu_type": 0,
                "flags": 16,
            },
            "raw grid changed",
        )
        check(
            not any(a["availability"] == "faulted" for a in node["algorithms"]),
            "node algorithm fault",
        )
    check(
        not any(e["algorithm"] == "aut_self_healing_mesh" for e in value["events"]),
        "fleet attributed to single node",
    )


def verify_running(value):
    verify_lossless(value)
    fleet = value["fleet"]
    check(
        fleet["availability"] == "running" and fleet["fresh"], "fleet not fresh/running"
    )
    check(fleet["configured_node_ids"] == list(NODES), "actual cohort IDs changed")
    for key in ("worker_run_id", "clock_id", "configuration_sha256"):
        check(fleet[key] == value[key], f"fleet identity differs: {key}")
    nodes = {node["node_id"]: node for node in value["nodes"]}
    check(all(node["fresh"] for node in nodes.values()), "member not fresh")
    inputs = fleet["member_inputs"]
    check(len(inputs) == 3, "incomplete input cohort")
    for index, item in enumerate(inputs):
        node = nodes[NODES[index]]
        check(
            item["index"] == index and item["node_id"] == node["node_id"],
            "native/actual index mapping",
        )
        check(item["node_epoch"] == node["node_epoch"], "member epoch differs")
        check(item["source_sequence"] == node["sequence"], "member sequence differs")
        check(
            item["observed_monotonic_ns"] == node["last_received_monotonic_ns"],
            "member timestamp differs",
        )
        check(item["algorithm"] == "coherence", "fabricated quality source")
        check(0 <= item["quality"] <= 1, "invalid coherence")
    oldest = min(int(item["observed_monotonic_ns"]) for item in inputs)
    newest = max(int(item["observed_monotonic_ns"]) for item in inputs)
    check(newest - oldest <= 500_000_000, "cohort observation spread")
    check(int(fleet["observed_monotonic_ns"]) == oldest, "oldest input not used")
    check(0 <= fleet["age_ms"] <= 2000, "fleet age")
    means = [event for event in fleet["events"] if event["event_id"] == "887"]
    check(len(means) == 1 and means[0]["fresh"], "native mean-quality event missing")
    check(means[0]["member_inputs"] == inputs, "mean event lost input lineage")
    for event in fleet["events"]:
        check(event["event_id"] in {"885", "886", "887", "888"}, "native ID changed")
        check(
            all(
                key not in event for key in ("node_id", "node_epoch", "source_sequence")
            ),
            "invented node attribution",
        )
        check(
            event["scope"] == "fleet" and event["member_node_ids"] == list(NODES),
            "event cohort",
        )
        check(
            event["advisory_only"] is True and event["recognition_validated"] is False,
            "semantic promotion",
        )
        check(event["fleet_epoch"] == fleet["fleet_epoch"], "event crossed epoch")
        if event["event_id"] == "885":
            check(
                event["subject_node_id"] == NODES[int(event["value"])],
                "subject mapping",
            )
        else:
            check(event["subject_node_id"] is None, "invented subject")


def main(binary, output):
    output.mkdir(parents=True, exist_ok=False)
    udp_port, http_port = port(socket.SOCK_DGRAM), port(socket.SOCK_STREAM)
    deadline = time.monotonic() + DEADLINE_SECONDS
    sequences = {node: 0 for node in NODES}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    failure = None
    cleanup = None
    process = None
    summary = {
        "synthetic_only": True,
        "passed": False,
        "hard_deadline_seconds": DEADLINE_SECONDS,
    }
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise TimeoutError("fleet socket smoke hard deadline")

    with (
        tempfile.TemporaryDirectory() as temporary,
        (output / "service.log").open("xb") as log,
        (output / "observations.jsonl").open("x") as trace,
    ):
        raw = Path(temporary) / "raw.jsonl"
        command = [
            str(binary),
            "--listen-udp",
            f"127.0.0.1:{udp_port}",
            "--listen-http",
            f"127.0.0.1:{http_port}",
            "--allow-source",
            "127.0.0.1",
            "--nodes",
            "1,2,3",
            "--record-jsonl",
            str(raw),
            "--record-seconds",
            "45",
            "--record-max-bytes",
            "5000000",
        ]
        trace_bytes = 0
        phase = "startup"

        def get(path, timeout):
            check(process.poll() is None, "worker exited before smoke completed")
            remaining = deadline - time.monotonic()
            check(remaining > 0, "fleet socket smoke deadline")
            with opener.open(
                f"http://127.0.0.1:{http_port}{path}", timeout=min(timeout, remaining)
            ) as response:
                check(response.status == 200, "worker HTTP status")
                data = response.read(MAX_HTTP + 1)
            check(len(data) <= MAX_HTTP, "HTTP response exceeded1MiB")
            return json.loads(data)

        def snapshot(timeout=1):
            nonlocal trace_bytes
            value = get("/v1/latest", timeout)
            encoded = (
                json.dumps(
                    {"phase": phase, "snapshot": value},
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            )
            trace_bytes += len(encoded.encode())
            check(trace_bytes <= MAX_TRACE, "snapshot trace limit")
            trace.write(encoded)
            trace.flush()
            return value

        def settled(name):
            value = await_tail(snapshot, sequences, deadline)
            save_json(output / f"{name}.json", value)
            verify_lossless(value)
            return value

        def send_rounds(sock, members, count):
            for _ in range(count):
                check(time.monotonic() < deadline, "packet phase deadline")
                for node in members:
                    data = packet(node, sequences[node])
                    check(
                        sock.sendto(data, ("127.0.0.1", udp_port)) == len(data),
                        "partial UDP send",
                    )
                    sequences[node] += 1
                time.sleep(0.032)

        try:
            signal.signal(signal.SIGALRM, expired)
            signal.setitimer(
                signal.ITIMER_REAL, max(0.001, deadline - time.monotonic())
            )
            process = subprocess.Popen(
                command, stdout=log, stderr=log, start_new_session=True
            )
            startup = min(deadline, time.monotonic() + 5)
            while True:
                check(time.monotonic() < startup, "worker startup deadline")
                try:
                    get("/health", max(0.001, min(0.2, startup - time.monotonic())))
                    break
                except OSError:
                    time.sleep(0.05)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                phase = "warmup"
                send_rounds(sock, NODES, 96)
                first = settled("running")
                verify_running(first)
                original_epoch = first["fleet"]["fleet_epoch"]
                phase = "one_member_quiet"
                send_rounds(sock, (1, 2), 100)
                quiet = settled("quiet")
                check(
                    quiet["worker_run_id"] == first["worker_run_id"], "worker restarted"
                )
                check(
                    all(n["fresh"] for n in quiet["nodes"][:2]),
                    "active control nodes expired",
                )
                check(not quiet["nodes"][2]["fresh"], "quiet node falsely fresh")
                check(
                    quiet["nodes"][2]["last_received_monotonic_ns"]
                    == first["nodes"][2]["last_received_monotonic_ns"],
                    "quiet node timestamp refreshed",
                )
                check(
                    quiet["fleet"]["availability"] in {"stale", "ineligible"},
                    "fleet failed to withdraw",
                )
                check(
                    not quiet["fleet"]["fresh"] and not quiet["fleet"]["events"],
                    "withdrawn graph retained fresh events",
                )
                check(
                    quiet["fleet"]["fleet_epoch"] > original_epoch,
                    "fleet invalidation did not reset epoch",
                )
                phase = "first_resumed_packet"
                send_rounds(sock, (3,), 1)
                resumed = settled("resumed_warmup")
                check(
                    resumed["nodes"][2]["node_epoch"] > first["nodes"][2]["node_epoch"],
                    "quiet node epoch not reset",
                )
                check(
                    resumed["nodes"][2]["epoch_reason"] == "receipt_gap",
                    "unexpected node reset cause",
                )
                check(
                    resumed["nodes"][2]["epoch_frames"] == 1, "resume bypassed warmup"
                )
                check(
                    resumed["fleet"]["availability"] == "warming_up"
                    and not resumed["fleet"]["events"],
                    "old graph survived resume",
                )
                phase = "recovery"
                send_rounds(sock, NODES, 96)
                recovered = settled("recovered")
                verify_running(recovered)
                check(
                    recovered["worker_run_id"] == first["worker_run_id"],
                    "worker restarted",
                )
                check(
                    recovered["fleet"]["fleet_epoch"] > original_epoch,
                    "old fleet epoch reused",
                )
                check(
                    all(
                        int(e["occurrence_seq"])
                        > max(
                            int(old["occurrence_seq"])
                            for old in first["fleet"]["events"]
                        )
                        for e in recovered["fleet"]["events"]
                    ),
                    "fleet occurrence reused",
                )
            phase = "idle_expiry"
            time.sleep(2.1)
            final = snapshot()
            save_json(output / "expired.json", final)
            check(
                final["fleet"]["availability"] == "stale"
                and not final["fleet"]["fresh"],
                "idle graph did not expire",
            )

            def immutable(value):
                return [
                    (e["occurrence_seq"], e["observed_at_ns"], e["member_inputs"])
                    for e in value["fleet"]["events"]
                ]

            check(
                immutable(final) == immutable(recovered), "idle polling rearmed fleet"
            )
            check(
                all(not e["fresh"] for e in final["fleet"]["events"]),
                "idle event falsely fresh",
            )
            summary.update(
                worker_run_id=first["worker_run_id"],
                original_fleet_epoch=original_epoch,
                recovered_fleet_epoch=recovered["fleet"]["fleet_epoch"],
                frames=sum(sequences.values()),
                observed_mean_quality_events=len(
                    [e for e in recovered["fleet"]["events"] if e["event_id"] == "887"]
                ),
            )
        except BaseException as error:
            failure = f"{type(error).__name__}: {error}"
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            if process is not None:
                try:
                    cleanup = close_process_group(process)
                except BaseException as error:
                    cleanup = {
                        "group_gone": False,
                        "error": f"{type(error).__name__}: {error}",
                    }
                    failure = failure or cleanup["error"]
            failure = save_completion(output, raw, sequences, summary, cleanup, failure)
    if failure:
        raise ValueError(failure)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    main(arguments.binary.resolve(), arguments.output.resolve())
