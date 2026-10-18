#!/usr/bin/env python3
"""Read-only bounded recovery observation, run through stdin in the HA bridge.

This complements, and does not replace, verify-server-modules.py. Nothing is
published. A permitted gap can recover without becoming continuous evidence.
"""

import argparse
import collections
import http.client
import json
import math
import os
import sys
import time
import urllib.parse

import module_observations as modules
from bridge import node_placements, observations
from ruview_http import decode_http_body

COUNTERS = (
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
NODE_COUNTERS = (
    "frames",
    "duplicates",
    "missing_sequences",
    "sequence_discontinuities",
)
ALLOWED_RECOVERY = {"sequence_gap", "receipt_gap"}


class GateError(ValueError):
    """Only fixed, non-secret gate descriptions reach the report."""


def require(condition, message):
    if not condition:
        raise GateError(message)


def exact_ids(values):
    require(
        isinstance(values, list)
        and 1 <= len(values) <= 10
        and all(type(n) is int and 1 <= n <= 255 for n in values)
        and len(set(values)) == len(values),
        "Invalid or duplicate fleet node IDs",
    )
    return set(values)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise GateError("Nonfinite JSON constant")

    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "Nonfinite JSON number")
        return number

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float
    )


class Assessment:
    """Assess already decoded samples; observations never mutate a worker."""

    def __init__(self, node_ids, expected_selected_count=20):
        self.expected = exact_ids(node_ids)
        require(
            type(expected_selected_count) is int
            and expected_selected_count in (20, 21),
            "Unreviewed expected selection",
        )
        self.expected_selected_count = expected_selected_count
        self.identity = None
        self.previous = {}
        self.counters = None
        self.continuity = True
        self.samples = 0

    def push(self, snapshot, current):
        require(snapshot.get("recognition_validated") is False, "Recognition claim")
        require(modules.integer(snapshot["catalog_count"]) == 64, "Wrong catalog size")
        require(
            modules.integer(snapshot["selected_algorithm_count"])
            == self.expected_selected_count,
            "Wrong adapters",
        )
        require(snapshot["monotonic_origin"] == "worker_start", "Unknown clock origin")
        identity = tuple(
            snapshot[k] for k in ("worker_run_id", "clock_id", "configuration_sha256")
        )
        if self.identity is not None:
            require(identity == self.identity, "Worker restarted or changed")
        raw_nodes = snapshot["nodes"]
        require(
            exact_ids([n["node_id"] for n in raw_nodes]) == self.expected,
            "Worker fleet differs from expected nodes",
        )
        require(set(current) == self.expected, "Missing or stale fresh node diagnostic")
        counters = {k: modules.integer(snapshot["counters"][k]) for k in COUNTERS}
        if self.counters is not None:
            require(
                all(counters[k] >= self.counters[k] for k in COUNTERS),
                "Worker counters moved backwards",
            )
            if any(
                counters[k] > self.counters[k]
                for k in ("queue_dropped", "processing_stale", "record_dropped")
            ):
                self.continuity = False
        rows = {}
        next_previous = {}
        for raw in raw_nodes:
            node_id = raw["node_id"]
            node = current[node_id]
            require(
                node["worker_fresh"] is True
                and max(
                    modules.number(node[k])
                    for k in (
                        "worker_csi_age_ms",
                        "csi_age_ms",
                        "inference_age_ms",
                        "snapshot_age_ms",
                    )
                )
                <= modules.PRODUCER_MAX_AGE_MS,
                "Expired two-second freshness lease",
            )
            grid = raw["grid"]
            for key in (
                "antennas",
                "subcarriers",
                "frequency_mhz",
                "ppdu_type",
                "flags",
            ):
                modules.integer(grid[key])
            require(
                grid["antennas"] == 1
                and grid["subcarriers"] == 64
                and grid["ppdu_type"] == 0
                and grid["flags"] in (0, 0x10)
                and grid["frequency_mhz"] in range(2412, 2473, 5),
                "Unsupported native physical grid",
            )
            physical_grid = tuple(
                grid[k]
                for k in ("antennas", "subcarriers", "frequency_mhz", "ppdu_type")
            )
            epoch = modules.integer(raw["node_epoch"])
            require(epoch > 0 and epoch == node["node_epoch"], "Invalid node epoch")
            reason = modules.text(raw["epoch_reason"])
            sequence = modules.integer(raw["sequence"], 2**32 - 1)
            require(sequence == node["sequence"], "Decoded sequence mismatch")
            mono = int(modules.decimal(raw["last_received_monotonic_ns"]))
            utc = int(modules.decimal(raw["last_received_at_ns"]))
            node_counters = {k: modules.integer(raw[k]) for k in NODE_COUNTERS}
            algorithms = node["algorithms"]
            require(len(algorithms) == 64, "Missing catalog entries")
            catalog = sorted(
                (a["algorithm"], a["algorithm_version"], a["source_sha256"])
                for a in algorithms
            )
            counts = dict(collections.Counter(a["availability"] for a in algorithms))
            require(not counts.get("faulted"), "Faulted algorithm")
            running = counts.get("running", 0)
            require(running == node["running_algorithms"], "Running count mismatch")
            old = self.previous.get(node_id)
            delta, transition = None, None
            running_samples = 1 if running else 0
            recoveries = 0 if old is None else old["recoveries"]
            if old is not None:
                require(physical_grid == old["grid"], "Physical grid changed")
                require(catalog == old["catalog"], "Algorithm catalog changed")
                require(
                    all(node_counters[k] >= old["counters"][k] for k in NODE_COUNTERS),
                    "Node counters moved backwards",
                )
                require(
                    node_counters["sequence_discontinuities"]
                    == old["counters"]["sequence_discontinuities"],
                    "Backward sequence or unknown device reboot",
                )
                delta = (sequence - old["sequence"]) % 2**32
                require(delta < 2**31, "Node sequence moved backwards")
                require(
                    mono >= old["mono"] and utc >= old["utc"],
                    "Receipt clock moved backwards",
                )
                require(
                    abs((utc - old["utc"]) - (mono - old["mono"])) <= 250_000_000,
                    "Receipt clock discontinuity",
                )
                require(
                    (delta == 0 and mono == old["mono"] and utc == old["utc"])
                    or (delta > 0 and mono > old["mono"] and utc > old["utc"]),
                    "Sequence and original receipt timestamps disagree",
                )
                require(
                    (
                        delta == 0
                        and node_counters["frames"] == old["counters"]["frames"]
                    )
                    or (
                        delta > 0
                        and node_counters["frames"] > old["counters"]["frames"]
                    ),
                    "Sequence and processed frame count disagree",
                )
                require(
                    delta
                    == node_counters["frames"]
                    - old["counters"]["frames"]
                    + node_counters["missing_sequences"]
                    - old["counters"]["missing_sequences"],
                    "Sequence delta differs from processed frames and missing sequences",
                )
                if epoch != old["epoch"]:
                    require(
                        epoch == old["epoch"] + 1, "Unobserved or backward node epochs"
                    )
                    require(
                        reason in ALLOWED_RECOVERY and delta > 0,
                        "Unqualified epoch reset reason",
                    )
                    require(
                        (
                            reason == "sequence_gap"
                            and delta > 1
                            and node_counters["missing_sequences"]
                            > old["counters"]["missing_sequences"]
                        )
                        or (
                            reason == "receipt_gap"
                            and mono - old["mono"] > 2_000_000_000
                            and node_counters["missing_sequences"]
                            == old["counters"]["missing_sequences"]
                        ),
                        "Gap reset lacks matching sequence or receipt evidence",
                    )
                    self.continuity = False
                    recoveries += 1
                    transition = reason
                else:
                    require(
                        reason == old["reason"], "Epoch reason changed without reset"
                    )
                    require(
                        node_counters["missing_sequences"]
                        == old["counters"]["missing_sequences"],
                        "Sequence gap without epoch reset",
                    )
                    if running:
                        running_samples = old["running_samples"] + int(delta > 0)
                if node_counters["duplicates"] > old["counters"]["duplicates"]:
                    self.continuity = False
            next_previous[node_id] = {
                "epoch": epoch,
                "reason": reason,
                "sequence": sequence,
                "mono": mono,
                "utc": utc,
                "grid": physical_grid,
                "catalog": catalog,
                "counters": node_counters,
                "running_samples": running_samples,
                "recoveries": recoveries,
                "running": running,
            }
            rows[str(node_id)] = {
                "sequence": sequence,
                "sequence_delta": delta,
                "node_epoch": epoch,
                "epoch_reason": reason,
                "observed_recovery_transition": transition,
                "grid": grid,
                "counters": node_counters,
                "availability": counts,
                "running_advancing_samples_in_current_epoch": running_samples,
                **{
                    k: node[k]
                    for k in (
                        "worker_csi_age_ms",
                        "csi_age_ms",
                        "inference_age_ms",
                        "snapshot_age_ms",
                        "fresh_event_count",
                    )
                },
            }
        self.identity, self.counters, self.previous = identity, counters, next_previous
        self.samples += 1
        return {"worker_counters": counters, "nodes": rows}

    def finish(self):
        require(self.samples >= 2, "Insufficient observation samples")
        require(
            all(
                n["running"] > 0 and n["running_samples"] >= 2
                for n in self.previous.values()
            ),
            "Every node needs two advancing running samples and closing running",
        )
        return {
            "operational_readiness_observed": True,
            "operational_recovery_observed": any(
                n["recoveries"] for n in self.previous.values()
            ),
            "continuity_passed": self.continuity,
            "observed_gap_recoveries": {
                str(k): n["recoveries"] for k, n in self.previous.items()
            },
            "scope": "fresh runtime and permitted gap recovery at sampled observations only",
            "unobserved_transitions_verified": False,
            "recognition_validated": False,
        }


def get(base, path, token, deadline, stamps, *, accept_gzip=False):
    """GET only, no proxies/redirects/retries, bounded response and socket deadline."""
    target = urllib.parse.urlsplit(base)
    require(
        target.scheme in ("http", "https")
        and target.hostname
        and not target.username
        and not target.password
        and not target.query
        and not target.fragment,
        "Invalid read-only service URL",
    )
    end = min(deadline, time.monotonic() + 3)

    def remaining():
        value = end - time.monotonic()
        require(value > 0, "HTTP or observation deadline exceeded")
        return value

    conn_type = (
        http.client.HTTPSConnection
        if target.scheme == "https"
        else http.client.HTTPConnection
    )
    conn = conn_type(target.hostname, target.port, timeout=remaining())
    stamp = {
        "endpoint": path,
        "request_started_at_ns": str(time.time_ns()),
        "request_started_monotonic_ns": str(time.monotonic_ns()),
    }
    stamps.append(stamp)
    try:
        conn.connect()
        sock = conn.sock
        sock.settimeout(remaining())
        headers = {"Authorization": "Bearer " + token} if token else {}
        if accept_gzip:
            headers["Accept-Encoding"] = "gzip"
        conn.request(
            "GET",
            target.path.rstrip("/") + path,
            headers=headers,
        )
        sock.settimeout(remaining())
        response = conn.getresponse()
        stamp["http_status"] = response.status
        require(response.status == 200, "HTTP status is not 200")
        expected_bytes = response.length
        encoding = response.getheader("Content-Encoding")
        stamp.update(
            declared_response_bytes=expected_bytes,
            response_bytes=0,
            content_encoding=(encoding or "identity").strip().lower()
            if (encoding or "identity").strip().lower() in ("identity", "gzip")
            else "unsupported",
        )
        require(
            expected_bytes is None or 0 <= expected_bytes <= modules.MAX_RESPONSE_BYTES,
            "HTTP declared response bound exceeded",
        )
        raw = bytearray()
        while True:
            sock.settimeout(remaining())
            part = response.read1(min(65536, modules.MAX_RESPONSE_BYTES + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            stamp["response_bytes"] = len(raw)
            require(
                len(raw) <= modules.MAX_RESPONSE_BYTES, "HTTP response bound exceeded"
            )
            if response.isclosed():
                break
        remaining()
        require(
            expected_bytes is None or len(raw) == expected_bytes,
            "HTTP response body is truncated",
        )
        try:
            decoded = decode_http_body(bytes(raw), encoding, modules.MAX_RESPONSE_BYTES)
        except ValueError:
            raise GateError(
                "Invalid HTTP content encoding or compressed body"
            ) from None
        stamp["decoded_response_bytes"] = len(decoded)
        remaining()
        body = strict_json(decoded)
        remaining()
        stamp.update(
            received_at_ns=str(time.time_ns()),
            received_monotonic_ns=str(time.monotonic_ns()),
            response_bytes=len(raw),
        )
        return body
    finally:
        conn.close()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise GateError("Invalid observation arguments")


def main():
    report = {
        "schema": "ruview.fleet-module-recovery-observation.v1",
        "started_at_ns": str(time.time_ns()),
        "passed": False,
        "operational_recovery_observed": False,
        "operational_readiness_observed": False,
        "continuity_passed": False,
        "recognition_validated": False,
        "publishes_observations": False,
        "samples": [],
    }
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--samples", type=int, default=60)
        parser.add_argument("--nodes", type=int, nargs="+", default=[1, 2, 3])
        parser.add_argument("--deadline-seconds", type=int, default=600)
        parser.add_argument(
            "--accept-gzip",
            action="store_true",
            help="Request bounded gzip transfer from worker endpoints only",
        )
        parser.add_argument(
            "--expected-selected-count",
            type=int,
            choices=(20, 21),
            default=20,
            help="20 for frozen r4/r5; explicitly choose 21 only for the later source revision",
        )
        args = parser.parse_args()
        require(
            2 <= args.samples <= 600 and 5 <= args.deadline_seconds <= 1800,
            "Sample count or deadline out of bounds",
        )
        expected = exact_ids(args.nodes)
        configured = exact_ids(
            [int(x) for x in os.environ["RUVIEW_NODE_IDS"].split(",")]
        )
        require(expected == configured, "Configured fleet differs from explicit nodes")
        placement_json = os.environ["RUVIEW_NODE_PLACEMENTS"]
        strict_json(placement_json)
        placements = node_placements(placement_json)
        require(expected <= set(placements), "Missing node placement metadata")
        token = os.environ["RUVIEW_API_TOKEN"]
        require(bool(token), "Missing collector authentication")
        collector = os.getenv("RUVIEW_URL", "http://127.0.0.1:3000")
        worker = "http://ruview-server-modules.ruview.svc.cluster.local:5016"
        deadline = time.monotonic() + args.deadline_seconds
        assessor = Assessment(args.nodes, args.expected_selected_count)
        report.update(
            expected_node_ids=sorted(expected),
            requested_samples=args.samples,
            deadline_seconds=args.deadline_seconds,
            expected_catalog_count=64,
            expected_selected_algorithm_count=args.expected_selected_count,
            worker_accept_gzip=args.accept_gzip,
        )
        for _ in range(args.samples):
            sample = {"requests": []}
            report["samples"].append(sample)
            stamps = sample["requests"]
            health = get(collector, "/health", None, deadline, stamps)
            worker_health = get(
                worker, "/health", None, deadline, stamps, accept_gzip=args.accept_gzip
            )
            require(
                worker_health.get("status") == "ok"
                and worker_health.get("recognition_validated") is False,
                "Worker unhealthy",
            )
            fleet_started = time.monotonic()
            fleet = get(collector, "/api/v1/nodes", token, deadline, stamps)
            latest_started = time.monotonic()
            latest = get(collector, "/api/v1/sensing/latest", token, deadline, stamps)
            received = time.monotonic()
            # Reject duplicate/missing collector IDs before bridge dictionaries merge them.
            for body in (fleet, latest):
                require(
                    exact_ids([n["node_id"] for n in body["nodes"]]) == expected,
                    "Collector fleet differs from expected nodes",
                )
            core = observations(
                health,
                latest,
                fleet,
                time.time(),
                (received - fleet_started) * 1000,
                (received - latest_started) * 1000,
            )
            snapshot = get(
                worker,
                "/v1/latest",
                None,
                deadline,
                stamps,
                accept_gzip=args.accept_gzip,
            )
            report["worker_fixture"] = snapshot
            worker_received = time.monotonic()
            decoded = modules.decode(snapshot, time.time_ns())
            for node in core.values():
                node["csi_age_ms"] += (time.monotonic() - received) * 1000
                node["inference_age_ms"] += (time.monotonic() - received) * 1000
            current = modules.current(
                decoded, (time.monotonic() - worker_received) * 1000, core
            )
            candidate_created_ns = str(time.time_ns())
            report["ha_candidate_created_at_ns"] = candidate_created_ns
            report["ha_candidate_fixture"] = [
                {
                    "entity_id": f"sensor.ruview_node{n}_server_modules",
                    "state": node["state"],
                    "attributes": {
                        **{k: v for k, v in node.items() if k != "state"},
                        **placements[n],
                        "published_at_ns": candidate_created_ns,
                    },
                }
                for n, node in current.items()
                if n in expected
            ]
            sample.update(at_ns=str(time.time_ns()), **assessor.push(snapshot, current))
            if len(report["samples"]) < args.samples:
                require(
                    deadline - time.monotonic() >= 1, "Observation deadline exceeded"
                )
                time.sleep(1)
        report.update(assessor.finish(), passed=True)
    except Exception as error:
        report["error_type"] = type(error).__name__
        if isinstance(error, GateError):
            report["failed_gate"] = str(error)
    report["finished_at_ns"] = str(time.time_ns())
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
