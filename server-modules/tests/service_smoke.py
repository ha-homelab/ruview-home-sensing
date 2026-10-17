#!/usr/bin/env python3
"""Offline executable integration: synthetic loopback traffic, no device calls."""

import argparse
import copy
import gzip
import hashlib
import io
import json
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

MAX_HTTP = 1_048_576


def port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def check(condition, message):
    if not condition:
        raise ValueError(message)


def save_json(path, value):
    with path.open("x") as destination:
        json.dump(value, destination, indent=2)


def synthetic_packet(node, sequence):
    return struct.pack(
        "<IBBHIIbbBB", 0xC5110001, node, 1, 64, 2462, sequence, -50, -90, 0, 0x10
    ) + bytes([15 + sequence % 3, 253] * 64)


def read_json_response(response, *, expected_encoding=None):
    wire = response.read(MAX_HTTP + 1)
    check(len(wire) <= MAX_HTTP, "wire response limit")
    check(int(response.headers["Content-Length"]) == len(wire), "exact content length")
    check(response.headers.get("Vary") == "Accept-Encoding", "encoding varies")
    encoding = response.headers.get("Content-Encoding")
    if expected_encoding is not None:
        check(encoding == expected_encoding, "negotiated content encoding")
    check(encoding in (None, "gzip"), "supported content encoding")
    if encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(wire)) as stream:
            decoded = stream.read(MAX_HTTP + 1)
    else:
        decoded = wire
    check(len(decoded) <= MAX_HTTP, "decoded response limit")
    return json.loads(decoded), {
        "encoding": encoding,
        "wire_bytes": len(wire),
        "decoded_bytes": len(decoded),
    }


def without_response_ages(value):
    """Keep original source times, identities, counters and every semantic field."""
    if isinstance(value, dict):
        return {
            key: without_response_ages(item)
            for key, item in value.items()
            if key not in ("generated_at_ns", "age_ms")
        }
    if isinstance(value, list):
        return [without_response_ages(item) for item in value]
    return value


def publication_complete(value, sequences):
    """Require both processing and asynchronous recording to reach the sent tail."""
    nodes = {node["node_id"]: node for node in value["nodes"]}
    total = sum(sequences.values())
    return (
        value["counters"]["received"] == total + 1
        and value["counters"]["rejected"] == 1
        and value["counters"]["record_written"] == total
        and all(
            node in nodes
            and nodes[node]["sequence"] == count - 1
            and nodes[node]["frames"] == count
            for node, count in sequences.items()
        )
    )


def await_publication(snapshot, sequences, observed, timeout=1.5):
    """Bounded wait for the cached publication; never manufacture fresh input."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        check(remaining > 0, "publication/recording did not reach the sent tail")
        value = snapshot(timeout=min(1, remaining))
        observed(value)
        check(time.monotonic() <= deadline, "publication readiness deadline exceeded")
        if publication_complete(value, sequences):
            return value
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def check_duplicate_preserved(before, after):
    expected = copy.deepcopy(before["nodes"])
    expected[0]["duplicates"] += 1
    check(
        without_response_ages(after["nodes"]) == without_response_ages(expected),
        "late duplicate changed node evidence or source times",
    )
    for key in ("events", "fleet"):
        check(
            without_response_ages(after[key]) == without_response_ages(before[key]),
            f"late duplicate changed {key}",
        )


def duplicate_publication_complete(value, total, frames, duplicates, discontinuities):
    node = value["nodes"][0]
    return (
        value["counters"]["received"] == value["counters"]["record_written"] == total
        and node["frames"] == frames
        and node["duplicates"] == duplicates
        and node["sequence_discontinuities"] == discontinuities
    )


def duplicate_smoke(binary, output):
    """Exercise replay admission through real UDP, HTTP and raw recording."""
    output.mkdir(parents=True, exist_ok=False)
    udp_port, http_port = port(socket.SOCK_DGRAM), port(socket.SOCK_STREAM)
    url = f"http://127.0.0.1:{http_port}/v1/latest"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with (
        tempfile.TemporaryDirectory() as temporary,
        (output / "service.log").open("xb") as log,
        (output / "observations.jsonl").open("x") as trace,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
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
            "--record-jsonl",
            str(raw),
            "--record-seconds",
            "20",
            "--record-max-bytes",
            "1000000",
        ]
        process = subprocess.Popen(command, stdout=log, stderr=log)
        sent = []

        def send(data):
            sock.sendto(data, ("127.0.0.1", udp_port))
            sent.append(data)

        def settled(total, frames, duplicates, discontinuities):
            deadline = time.monotonic() + 1.5
            while True:
                remaining = deadline - time.monotonic()
                check(remaining > 0, "duplicate smoke publication deadline")
                check(process.poll() is None, "duplicate worker exited")
                try:
                    request = urllib.request.Request(
                        url, headers={"Accept-Encoding": "gzip"}
                    )
                    with opener.open(request, timeout=min(1, remaining)) as response:
                        value, _ = read_json_response(response)
                except (OSError, urllib.error.URLError):
                    time.sleep(min(0.02, max(0, deadline - time.monotonic())))
                    continue
                trace.write(json.dumps(value, separators=(",", ":")) + "\n")
                trace.flush()
                check(time.monotonic() <= deadline, "duplicate smoke late response")
                if duplicate_publication_complete(
                    value, total, frames, duplicates, discontinuities
                ):
                    return value
                time.sleep(min(0.02, max(0, deadline - time.monotonic())))

        try:
            settled(0, 0, 0, 0)
            for sequence in range(80):
                send(synthetic_packet(1, sequence))
                time.sleep(0.032)
            before = settled(80, 80, 0, 0)
            check(before["nodes"][0]["node_epoch"] == 1, "contiguous warmup")
            check(before["nodes"][0]["frames"] == 80, "complete warmup")
            check(bool(before["events"]), "warmed event evidence exists")
            send(sent[77])
            replay = settled(81, 80, 1, 0)
            check_duplicate_preserved(before, replay)
            send(synthetic_packet(1, 80))
            continued = settled(82, 81, 1, 0)
            node = continued["nodes"][0]
            check(
                node["node_epoch"] == 1
                and node["sequence"] == 80
                and node["frames"] == 81
                and node["duplicates"] == 1
                and node["missing_sequences"] == node["sequence_discontinuities"] == 0,
                "continuation after replay preserves baseline",
            )
            conflicting = bytearray(sent[-1])
            conflicting[-1] ^= 1
            send(bytes(conflicting))
            conflict = settled(83, 82, 1, 1)
            node = conflict["nodes"][0]
            check(
                node["node_epoch"] == 2
                and node["frames"] == 82
                and node["epoch_frames"] == 1
                and node["duplicates"] == 1
                and node["sequence_discontinuities"] == 1
                and node["epoch_reason"] == "sequence_conflict_boot_unknown",
                "changed same-sequence packet resets unknown history",
            )
            check(not conflict["events"], "conflict clears old event evidence")
            check(
                all(
                    conflict["counters"][key] == 0
                    for key in (
                        "rejected",
                        "source_rejected",
                        "queue_dropped",
                        "processing_stale",
                        "record_dropped",
                        "record_error",
                        "record_limit_reached",
                    )
                ),
                "replay smoke had ingress or recording losses",
            )
            rows = [json.loads(line) for line in raw.read_text().splitlines()]
            check(len(rows) == len(sent) == 83, "raw retains all admitted datagrams")
            check(
                [row["raw_datagram_sha256"] for row in rows]
                == [hashlib.sha256(data).hexdigest() for data in sent],
                "raw recording preserves replay and conflict bytes in order",
            )
            save_json(
                output / "summary.json",
                {
                    "passed": True,
                    "synthetic_only": True,
                    "raw_datagrams": 83,
                    "processed_frames": 82,
                    "exact_late_duplicates": 1,
                    "unknown_sequence_conflicts": 1,
                },
            )
        except BaseException as error:
            save_json(output / "failure.json", {"passed": False, "failure": str(error)})
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            if raw.exists():
                with (output / "raw.synthetic.jsonl").open("xb") as destination:
                    destination.write(raw.read_bytes())


def main(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    udp_port, http_port = port(socket.SOCK_DGRAM), port(socket.SOCK_STREAM)
    url = f"http://127.0.0.1:{http_port}"
    with tempfile.TemporaryDirectory() as temporary:
        raw = Path(temporary) / "raw.jsonl"
        command = [
            str(binary),
            "--listen-udp",
            f"127.0.0.1:{udp_port}",
            "--listen-http",
            f"127.0.0.1:{http_port}",
            "--allow-source",
            "127.0.0.1",
            "--record-jsonl",
            str(raw),
            "--record-seconds",
            "10",
            "--record-max-bytes",
            "1000000",
        ]
        log = (output / "service.log").open("xb")
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            for _ in range(40):
                try:
                    with urllib.request.urlopen(
                        url + "/health", timeout=0.2
                    ) as response:
                        check(response.status == 200, "health")
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise ValueError("worker failed to start")
            sequences = {1: 0, 2: 0}
            rates = {1: 20, 2: 31.25}
            start = time.monotonic()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                while time.monotonic() - start < 6:
                    elapsed = time.monotonic() - start
                    for node, rate in rates.items():
                        if sequences[node] / rate <= elapsed:
                            seq = sequences[node]
                            packet = synthetic_packet(node, seq)
                            sock.sendto(packet, ("127.0.0.1", udp_port))
                            sequences[node] += 1
                    time.sleep(0.001)
                sock.sendto(b"malformed", ("127.0.0.1", udp_port))
            save_json(output / "expected.json", {"sent_frames_by_node": sequences})

            encoding_observations = []

            def snapshot(timeout=1, accept_encoding="gzip", endpoint="/v1/latest"):
                request = urllib.request.Request(
                    url + endpoint, headers={"Accept-Encoding": accept_encoding}
                )
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    value, observation = read_json_response(response)
                    encoding_observations.append(observation)
                    return value

            with (output / "readiness.jsonl").open("x") as trace:

                def observed(value):
                    trace.write(json.dumps(value, separators=(",", ":")) + "\n")
                    trace.flush()

                first = await_publication(snapshot, sequences, observed)
            save_json(output / "latest.synthetic.json", first)
            check(first["freshness_limit_ms"] == 2000, "freshness contract")
            check(len(first["nodes"]) == 3, "node catalog")
            check(
                all(len(node["algorithms"]) == 64 for node in first["nodes"]),
                "algorithm catalog",
            )
            check(first["nodes"][2]["sequence"] is None, "unseen node")
            check(
                all(node["grid"]["flags"] == 0x10 for node in first["nodes"][:2]),
                "sync-valid metadata preserved",
            )
            check(first["counters"]["rejected"] == 1, "malformed packet rejected")
            check(first["counters"]["queue_dropped"] == 0, "receiver drops")
            check(
                all(
                    first["counters"][key] == 0
                    for key in (
                        "source_rejected",
                        "processing_stale",
                        "record_dropped",
                        "record_error",
                        "record_limit_reached",
                    )
                ),
                "processing/recording loss",
            )
            check(
                all(
                    node["fresh"]
                    and node["node_epoch"] == 1
                    and node["epoch_frames"] == sequences[node["node_id"]]
                    for node in first["nodes"][:2]
                ),
                "fresh complete contiguous synthetic input",
            )
            check(
                not any(
                    a["availability"] == "faulted"
                    for n in first["nodes"]
                    for a in n["algorithms"]
                ),
                "native algorithm fault",
            )
            check(
                any(e["event_id"] == "850" and e["fresh"] for e in first["events"]),
                "full event ID not truncated",
            )
            original = {
                (e["node_id"], e["occurrence_seq"]): e["observed_at_ns"]
                for e in first["events"]
            }
            time.sleep(2.1)
            second = snapshot()
            save_json(output / "expired.synthetic.json", second)
            check(
                all(not node["fresh"] for node in second["nodes"]),
                "dynamic node expiry",
            )
            check(
                all(not event["fresh"] for event in second["events"]),
                "dynamic event expiry",
            )
            check(
                original
                == {
                    (e["node_id"], e["occurrence_seq"]): e["observed_at_ns"]
                    for e in second["events"]
                },
                "poll did not rearm",
            )
            check(
                all(row["encoding"] == "gzip" for row in encoding_observations),
                "fresh and stale observations used gzip",
            )
            reference = without_response_ages(second)
            for accept, expected in (
                ("gzip;q=0, *;q=1", None),
                ("identity", None),
                ("gzip;q=0.5, identity;q=1", None),
                ("GZIP", "gzip"),
                ("gzip, identity;q=0", "gzip"),
            ):
                value = snapshot(accept_encoding=accept)
                check(
                    encoding_observations[-1]["encoding"] == expected,
                    "q-value negotiation",
                )
                check(
                    without_response_ages(value) == reference,
                    "encoding preserved source times, identities, counters and stale state",
                )
            event_value = snapshot(endpoint="/v1/events")
            check(
                encoding_observations[-1]["encoding"] == "gzip", "events endpoint gzip"
            )
            check(
                without_response_ages(event_value) == reference,
                "events encoding equivalence",
            )
            check(
                all(
                    row["wire_bytes"] <= row["decoded_bytes"] - 128
                    for row in encoding_observations
                    if row["encoding"] == "gzip"
                ),
                "compression saves bytes",
            )
            save_json(output / "http-encoding.json", encoding_observations)
            rows = [json.loads(line) for line in raw.read_text().splitlines()]
            check(len(rows) == sum(sequences.values()), "raw recording coverage")
            check(
                all(
                    type(row["received_at_ns"]) is int
                    and len(row["iq"]) == 128
                    and row["iq"][1] == -3
                    and row["flags"] == 0x10
                    for row in rows
                ),
                "exact signed IQ and timestamps",
            )
            with (output / "summary.json").open("x") as destination:
                json.dump(
                    {
                        "passed": True,
                        "synthetic_only": True,
                        "frames": len(rows),
                        "events": len(first["events"]),
                        "queue_dropped": 0,
                    },
                    destination,
                    indent=2,
                )
        except BaseException as error:
            save_json(
                output / "failure.json",
                {"passed": False, "synthetic_only": True, "failure": str(error)},
            )
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            log.close()
            if raw.exists():
                with (output / "raw.synthetic.jsonl").open("xb") as destination:
                    destination.write(raw.read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    main(arguments.binary.resolve(), arguments.output.resolve())
    duplicate_smoke(
        arguments.binary.resolve(), arguments.output.resolve() / "duplicates"
    )
