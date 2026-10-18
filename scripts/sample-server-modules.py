#!/usr/bin/env python3
"""Fixed-length, read-only sampled diagnostic execution; never continuity proof.

Run through stdin in the bridge image. The caller retains stdout in a NEW private
file. No MQTT, device calls, retry, extension, or state mutation is performed.
"""

import argparse
import collections
import hashlib
import http.client
import json
import math
import os
import signal
import sys
import time
import urllib.parse

import module_observations as modules
from bridge import node_placements, observations

SCHEMA = "ruview.sampled-diagnostic-runtime.v1"
SAMPLES = 90
NODE_IDS = {1, 2, 3}
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
DISRUPTIONS = tuple(k for k in COUNTERS if k not in ("received", "record_written"))
NODE_COUNTERS = (
    "frames",
    "duplicates",
    "missing_sequences",
    "sequence_discontinuities",
)
GAP_REASONS = {"sequence_gap", "receipt_gap"}


class GateError(ValueError):
    """Fixed safe messages only; exceptions must not disclose request secrets."""


class CaptureDeadline(TimeoutError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def exact_ids(nodes):
    ids = [modules.integer(n["node_id"], 255) for n in nodes]
    require(len(ids) == 3 and set(ids) == NODE_IDS, "Unexpected or duplicate node IDs")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def invalid(_value):
        raise GateError("Nonfinite JSON value")

    def finite(value):
        number = float(value)
        require(math.isfinite(number), "Nonfinite JSON value")
        return number

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite
    )


def get(base, path, token, deadline, stamps):
    """Same bounded GET contract as the recovery observer, with raw byte hash."""
    url = urllib.parse.urlsplit(base)
    require(
        url.scheme in ("http", "https")
        and url.hostname
        and not url.username
        and not url.password
        and not url.query
        and not url.fragment,
        "Invalid service URL",
    )
    end = min(deadline, time.monotonic() + 3)

    def remaining():
        value = end - time.monotonic()
        require(value > 0, "Request deadline exceeded")
        return value

    conn_type = (
        http.client.HTTPSConnection
        if url.scheme == "https"
        else http.client.HTTPConnection
    )
    conn = conn_type(url.hostname, url.port, timeout=remaining())
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
        conn.request(
            "GET",
            url.path.rstrip("/") + path,
            headers={"Authorization": "Bearer " + token} if token else {},
        )
        sock.settimeout(remaining())
        response = conn.getresponse()
        require(response.status == 200, "HTTP status is not 200")
        declared = response.length
        require(
            declared is None or 0 <= declared <= modules.MAX_RESPONSE_BYTES,
            "Response size exceeds bound",
        )
        raw = bytearray()
        while True:
            sock.settimeout(remaining())
            part = response.read1(min(65536, modules.MAX_RESPONSE_BYTES + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            require(
                len(raw) <= modules.MAX_RESPONSE_BYTES, "Response size exceeds bound"
            )
            if response.isclosed():
                break
        remaining()
        require(declared is None or len(raw) == declared, "Truncated response")
        stamp.update(
            received_at_ns=str(time.time_ns()),
            received_monotonic_ns=str(time.monotonic_ns()),
            response_bytes=len(raw),
            response_sha256=hashlib.sha256(raw).hexdigest(),
        )
        return strict_json(raw)
    finally:
        conn.close()


class Assessment:
    """A failed sample stays failed; later samples cannot repair its contract."""

    def __init__(self, run_id, clock_id, configuration, catalog_sha256):
        self.identity = (
            modules.text(run_id),
            modules.text(clock_id),
            modules.digest(configuration),
        )
        self.previous = {}
        self.expected_catalog_sha256 = modules.digest(catalog_sha256)
        self.catalog = None
        self.baseline = self.counters = None
        self.baseline_index = self.counter_index = None
        self.contract_errors = []
        self.observed_faults = []
        self.counter_increases = set()
        self.unknown_transitions = collections.Counter()
        self.epoch_changes = collections.Counter()
        self.gap_samples = collections.Counter()
        self.node_baseline, self.node_counters = {}, {}
        self.states = {n: collections.Counter() for n in NODE_IDS}
        self.streaks = dict.fromkeys(NODE_IDS, 0)
        self.best_streaks = dict.fromkeys(NODE_IDS, 0)
        self.closing = {}
        self.valid_samples = 0
        self.last_index = None

    def failed(self, index, error):
        entry = {"sample_index": index, "error_type": type(error).__name__}
        if isinstance(error, GateError):
            entry["failed_gate"] = str(error)
        self.contract_errors.append(entry)
        self.streaks = dict.fromkeys(NODE_IDS, 0)
        self.closing = {}
        for n in NODE_IDS:
            self.states[n]["unassessed"] += 1
        return entry

    def push(self, snapshot, decoded, current, index):
        require(snapshot.get("recognition_validated") is False, "Recognition claim")
        require(
            tuple(
                snapshot[k]
                for k in ("worker_run_id", "clock_id", "configuration_sha256")
            )
            == self.identity,
            "Worker identity differs from explicit expectation",
        )
        require(
            snapshot.get("monotonic_origin") == "worker_start", "Unknown worker clock"
        )
        require(
            type(snapshot.get("catalog_count")) is int
            and snapshot["catalog_count"] == 64
            and type(snapshot.get("selected_algorithm_count")) is int
            and snapshot["selected_algorithm_count"] == 21,
            "Wrong catalog or selection",
        )
        exact_ids(snapshot["nodes"])
        require(
            set(current) <= NODE_IDS and set(decoded) <= NODE_IDS,
            "Unexpected decoded node",
        )
        counters = {k: modules.integer(snapshot["counters"][k]) for k in COUNTERS}
        if self.counters is not None:
            require(
                all(counters[k] >= self.counters[k] for k in COUNTERS),
                "Worker counters regressed",
            )
        next_previous, rows, catalogs = {}, {}, []
        faults = []
        for raw in snapshot["nodes"]:
            n = raw["node_id"]
            algorithms = raw["algorithms"]
            require(
                isinstance(algorithms, list) and len(algorithms) == 64,
                "Missing algorithm catalog",
            )
            identities = []
            availability = collections.Counter()
            for a in algorithms:
                identities.append(
                    (
                        modules.text(a["algorithm"]),
                        modules.text(a["algorithm_version"]),
                        modules.digest(a["source_sha256"]),
                    )
                )
                require(a["availability"] in modules.STATES, "Invalid availability")
                availability[a["availability"]] += 1
                modules.integer(a["processed_frames"])
                modules.integer(a["emitted_events"])
                maximum = modules.number(a["max_execution_us"])
                if a["availability"] == "faulted" or maximum > 50_000:
                    faults.append(
                        {
                            "sample_index": index,
                            "node_id": n,
                            "algorithm": a["algorithm"],
                            "reason": modules.text(a["reason"], 512),
                            "max_execution_us": maximum,
                        }
                    )
            identities.sort()
            require(
                len({a[0] for a in identities}) == 64
                and availability["unavailable"] == 43,
                "Duplicate algorithm or inconsistent selected catalog",
            )
            require(
                hashlib.sha256(
                    json.dumps(
                        identities, separators=(",", ":"), ensure_ascii=True
                    ).encode()
                ).hexdigest()
                == self.expected_catalog_sha256,
                "Catalog differs from reviewed source pin",
            )
            catalogs.append(identities)
            require(
                self.catalog is None or identities == self.catalog,
                "Algorithm catalog changed",
            )
            epoch = modules.integer(raw["node_epoch"])
            counts = {k: modules.integer(raw[k]) for k in NODE_COUNTERS}
            epoch_frames = modules.integer(raw["epoch_frames"])
            require(epoch_frames <= counts["frames"], "Epoch frames exceed total")
            reason = modules.text(raw["epoch_reason"])
            if n not in decoded:
                require(
                    epoch == 0
                    and counts["frames"] == 0
                    and epoch_frames == 0
                    and raw["grid"] is None
                    and raw["sequence"] is None
                    and raw["last_received_monotonic_ns"] is None
                    and raw["fresh"] is False,
                    "Unobserved node has contradictory evidence",
                )
                require(n not in self.previous, "Observed node became unobserved")
                rows[str(n)] = {
                    "state": "unobserved",
                    "fresh_running": False,
                    "running_advancing_streak": 0,
                    "node_epoch": epoch,
                    "counters": counts,
                    "availability": dict(availability),
                }
                continue
            require(epoch > 0, "Observed node has no epoch")
            grid = raw["grid"]
            for k in ("antennas", "subcarriers", "frequency_mhz", "ppdu_type", "flags"):
                modules.integer(grid[k])
            require(
                grid["antennas"] == 1
                and grid["subcarriers"] == 64
                and grid["ppdu_type"] == 0
                and grid["frequency_mhz"] in range(2412, 2473, 5)
                and grid["flags"] in (0, 16),
                "Unsupported physical grid",
            )
            physical = tuple(
                grid[k]
                for k in ("antennas", "subcarriers", "frequency_mhz", "ppdu_type")
            )
            sequence = modules.integer(raw["sequence"], 2**32 - 1)
            mono, utc = (
                int(modules.decimal(raw[k]))
                for k in ("last_received_monotonic_ns", "last_received_at_ns")
            )
            old = self.previous.get(n)
            delta, epoch_delta, unknown = None, 0, 0
            if old is not None:
                require(physical == old["grid"], "Physical grid changed")
                require(
                    all(counts[k] >= old["counts"][k] for k in NODE_COUNTERS),
                    "Node counters regressed",
                )
                require(
                    counts["sequence_discontinuities"]
                    == old["counts"]["sequence_discontinuities"],
                    "New backward sequence or unknown reboot",
                )
                delta = (sequence - old["sequence"]) % 2**32
                require(delta < 2**31, "Source sequence moved backwards")
                require(
                    (delta == 0 and (mono, utc) == (old["mono"], old["utc"]))
                    or (delta > 0 and mono > old["mono"]),
                    "Receipt and sequence disagree",
                )
                require(
                    abs((utc - old["utc"]) - (mono - old["mono"])) <= 250_000_000,
                    "Receipt clock discontinuity",
                )
                frame_delta = counts["frames"] - old["counts"]["frames"]
                missing_delta = (
                    counts["missing_sequences"] - old["counts"]["missing_sequences"]
                )
                require(
                    delta == frame_delta + missing_delta
                    and (delta == 0 or frame_delta > 0),
                    "Sequence/frame/missing accounting mismatch",
                )
                epoch_delta = epoch - old["epoch"]
                require(epoch_delta >= 0, "Node epoch moved backwards")
                if epoch_delta:
                    require(
                        delta > 0 and reason in GAP_REASONS,
                        "Unqualified latest epoch reason",
                    )
                    require(
                        (reason == "sequence_gap" and missing_delta > 0)
                        or (
                            reason == "receipt_gap"
                            and mono - old["mono"] > 2_000_000_000
                            and (epoch_delta > 1 or missing_delta == 0)
                        ),
                        "Latest gap has no matching evidence",
                    )
                    require(
                        0 < epoch_frames <= frame_delta,
                        "Reset epoch frame accounting mismatch",
                    )
                    # Multiple transitions hide their reasons. Never infer all were gaps.
                    unknown = max(0, epoch_delta - 1)
                else:
                    require(
                        reason == old["reason"] and missing_delta == 0,
                        "Unannounced node reset or gap",
                    )
                    require(
                        epoch_frames - old["epoch_frames"] == frame_delta,
                        "Contiguous epoch frame accounting mismatch",
                    )
            candidate = current.get(n)
            fresh = candidate is not None
            running = availability["running"]
            if candidate is not None:
                require(
                    candidate["node_epoch"] == epoch
                    and candidate["sequence"] == sequence
                    and candidate["running_algorithms"] == running,
                    "Candidate does not belong to this snapshot",
                )
                require(
                    max(
                        candidate[k]
                        for k in (
                            "worker_csi_age_ms",
                            "csi_age_ms",
                            "inference_age_ms",
                            "snapshot_age_ms",
                        )
                    )
                    <= modules.PRODUCER_MAX_AGE_MS,
                    "Candidate exceeded freshness lease",
                )
            if epoch_frames < 64:
                require(
                    running == 0
                    and not decoded[n]["events"]
                    and all(a["processed_frames"] == 0 for a in algorithms),
                    "Warmup retained native output",
                )
            if candidate is not None and not running:
                require(
                    candidate["state"] == "waiting_for_eligible_input"
                    and candidate["fresh_event_count"] == 0,
                    "Ineligible input retained fresh candidate output",
                )
            state = (
                "stale_or_core_unavailable"
                if not fresh
                else "running"
                if running
                else "warming_up"
                if availability["warming_up"]
                else "ineligible_or_faulted"
            )
            consecutive = (
                old is not None
                and self.last_index == index - 1
                and old["fresh_running"]
            )
            streak = (
                (
                    self.streaks[n] + 1
                    if consecutive and epoch_delta == 0 and delta and delta > 0
                    else 1
                )
                if fresh and running
                else 0
            )
            rows[str(n)] = {
                "state": state,
                "fresh_running": bool(fresh and running),
                "running_advancing_streak": streak,
                "node_epoch": epoch,
                "epoch_reason": reason,
                "epoch_delta": epoch_delta,
                "unobserved_epoch_transitions": unknown,
                "transition_reasons_qualified": None
                if epoch_delta == 0
                else epoch_delta == 1,
                "sequence": sequence,
                "sequence_delta": delta,
                "epoch_frames": epoch_frames,
                "counters": counts,
                "availability": dict(availability),
                "withdrawal_observed": not fresh or running == 0,
                "candidate_present": fresh,
            }
            next_previous[n] = {
                "grid": physical,
                "counts": counts,
                "epoch": epoch,
                "reason": reason,
                "sequence": sequence,
                "mono": mono,
                "utc": utc,
                "epoch_frames": epoch_frames,
                "fresh_running": bool(fresh and running),
            }
        require(all(c == catalogs[0] for c in catalogs), "Node catalogs disagree")
        # Commit assessment only after the complete sample validates.
        self.catalog = catalogs[0]
        if self.baseline is None:
            self.baseline, self.baseline_index = counters, index
        self.counter_index = index
        self.counters = counters
        self.counter_increases.update(
            k for k in DISRUPTIONS if counters[k] > self.baseline[k]
        )
        self.observed_faults.extend(faults)
        for n in NODE_IDS:
            row = rows[str(n)]
            self.states[n][row["state"]] += 1
            self.node_baseline.setdefault(n, row["counters"])
            self.node_counters[n] = row["counters"]
            self.gap_samples[n] += int(row.get("epoch_delta", 0) > 0)
            self.streaks[n] = row["running_advancing_streak"]
            self.best_streaks[n] = max(self.best_streaks[n], self.streaks[n])
            self.unknown_transitions[n] += row.get("unobserved_epoch_transitions", 0)
            self.epoch_changes[n] += row.get("epoch_delta", 0)
        self.previous, self.closing = next_previous, rows
        self.last_index, self.valid_samples = index, self.valid_samples + 1
        return {
            "contract_pass": True,
            "nodes": rows,
            "observed_faults": faults,
            "worker_counters": counters,
        }

    def finish(self, attempted, complete):
        closing_running = bool(self.closing) and all(
            self.closing[str(n)]["fresh_running"] for n in NODE_IDS
        )
        closing_pairs = closing_running and all(self.streaks[n] >= 2 for n in NODE_IDS)
        contract = (
            self.valid_samples == attempted
            and attempted > 0
            and not self.contract_errors
        )
        execution = (
            complete
            and contract
            and closing_pairs
            and not self.observed_faults
            and not self.counter_increases
        )
        return {
            "capture_complete": complete,
            "contract_pass": contract,
            "sampled_diagnostic_execution": bool(execution),
            "closing_all_nodes_fresh_running": closing_running,
            "closing_all_nodes_have_advancing_pair": bool(closing_pairs),
            "continuity_proven": False,
            "strict_qualification_pass": False,
            "unobserved_transitions_qualified": False,
            "recognition_validated": False,
            "mqtt_delivery_verified": False,
            "all_selected_algorithms_running_claim": False,
            "any_observed_faults": bool(self.observed_faults),
            "observed_faults": self.observed_faults,
            "contract_errors": self.contract_errors,
            "worker_counters": {
                "baseline": self.baseline,
                "current": self.counters,
                "baseline_sample_index": self.baseline_index,
                "current_sample_index": self.counter_index,
                "delta": None
                if self.baseline is None
                else {k: self.counters[k] - self.baseline[k] for k in COUNTERS},
                "disruption_counters_increased": sorted(self.counter_increases),
            },
            "per_node": {
                str(n): {
                    "closing_epoch": self.closing.get(str(n), {}).get("node_epoch"),
                    "closing_running_advancing_streak": self.streaks[n],
                    "maximum_running_advancing_streak": self.best_streaks[n],
                    "observed_epoch_increments": self.epoch_changes[n],
                    "gap_transition_samples": self.gap_samples[n],
                    "gap_transition_sample_fraction": self.gap_samples[n] / attempted
                    if attempted
                    else None,
                    "counters": {
                        "baseline": self.node_baseline.get(n),
                        "current": self.node_counters.get(n),
                        "delta": {
                            k: self.node_counters[n][k] - self.node_baseline[n][k]
                            for k in NODE_COUNTERS
                        }
                        if n in self.node_baseline
                        else None,
                    },
                    "unobserved_epoch_transitions": self.unknown_transitions[n],
                    "state_sample_counts": dict(self.states[n]),
                    "state_sample_fractions": {
                        k: v / attempted for k, v in self.states[n].items()
                    }
                    if attempted
                    else {},
                }
                for n in sorted(NODE_IDS)
            },
            "limitations": [
                "Sampling does not prove continuous operation or hidden transition reasons.",
                "Missing sequence values do not identify wire loss or its cause.",
                "Fault counters reset with native epochs; no unseen-fault absence is proved.",
                "Fractions count samples, not elapsed time; no recognition or MQTT proof.",
            ],
        }


def collect_sample(index, context, deadline):
    row = {"sample_index": index, "requests": [], "contract_pass": False}
    stamps = row["requests"]
    try:
        snapshot = get(context["worker"], "/v1/latest", None, deadline, stamps)
        row["worker_fixture"] = snapshot
        worker_received, worker_wall = time.monotonic(), time.time_ns()
        decoded = modules.decode(snapshot, worker_wall)
        worker_health = get(context["worker"], "/health", None, deadline, stamps)
        require(
            worker_health.get("status") == "ok"
            and worker_health.get("recognition_validated") is False,
            "Worker health failed",
        )
        health = get(context["collector"], "/health", None, deadline, stamps)
        fleet_started = time.monotonic()
        fleet = get(
            context["collector"], "/api/v1/nodes", context["token"], deadline, stamps
        )
        latest_started = time.monotonic()
        latest = get(
            context["collector"],
            "/api/v1/sensing/latest",
            context["token"],
            deadline,
            stamps,
        )
        received = time.monotonic()
        exact_ids(fleet["nodes"])
        exact_ids(latest["nodes"])
        require(
            health.get("source") == "esp32" and latest.get("source") == "esp32",
            "Collector source is not real ESP32 CSI",
        )
        core = observations(
            health,
            latest,
            fleet,
            time.time(),
            (received - fleet_started) * 1000,
            (received - latest_started) * 1000,
        )
        for node in core.values():
            node["csi_age_ms"] += (time.monotonic() - received) * 1000
            node["inference_age_ms"] += (time.monotonic() - received) * 1000
        current = modules.current(
            decoded, (time.monotonic() - worker_received) * 1000, core
        )
        created = str(time.time_ns())
        row["ha_candidate_created_at_ns"] = created
        row["ha_candidate_fixture"] = [
            {
                "entity_id": f"sensor.ruview_node{n}_server_modules",
                "state": node["state"],
                "attributes": {
                    **{k: v for k, v in node.items() if k != "state"},
                    **context["placements"][n],
                    "published_at_ns": created,
                },
            }
            for n, node in sorted(current.items())
        ]
        row["core_freshness"] = {
            str(n): {k: node[k] for k in ("csi_age_ms", "inference_age_ms")}
            for n, node in core.items()
        }
        require(
            abs(
                (time.time_ns() - context["start_wall_ns"])
                - (time.monotonic_ns() - context["start_mono_ns"])
            )
            <= 250_000_000,
            "Sampler wall clock discontinuity",
        )
        row.update(context["assessment"].push(snapshot, decoded, current, index))
    except CaptureDeadline:
        row["failure"] = context["assessment"].failed(index, CaptureDeadline())
        row["deadline_reached"] = True
    except Exception as error:
        row["failure"] = context["assessment"].failed(index, error)
    row.update(
        observed_at_ns=str(time.time_ns()),
        observed_monotonic_ns=str(time.monotonic_ns()),
    )
    return row


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise GateError("Invalid sampling arguments")


def main():
    header = {
        "schema": SCHEMA,
        "started_at_ns": str(time.time_ns()),
        "requested_samples": SAMPLES,
        "expected_node_ids": sorted(NODE_IDS),
        "expected_catalog_count": 64,
        "expected_selected_algorithm_count": 21,
        "publishes_observations": False,
    }
    summary = {
        "capture_complete": False,
        "contract_pass": False,
        "sampled_diagnostic_execution": False,
        "continuity_proven": False,
        "strict_qualification_pass": False,
        "recognition_validated": False,
        "passed": False,
    }
    assessment = None
    armed = streaming = False
    attempted, start_mono = 0, None
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--expected-worker-run-id", required=True)
        parser.add_argument("--expected-clock-id", required=True)
        parser.add_argument("--expected-config-sha256", required=True)
        parser.add_argument("--expected-catalog-sha256", required=True)
        parser.add_argument("--deadline-seconds", type=int, default=180)
        args = parser.parse_args()
        require(90 <= args.deadline_seconds <= 300, "Deadline must be 90..300 seconds")
        assessment = Assessment(
            args.expected_worker_run_id,
            args.expected_clock_id,
            args.expected_config_sha256,
            args.expected_catalog_sha256,
        )
        configured = [int(n) for n in os.environ["RUVIEW_NODE_IDS"].split(",")]
        require(
            len(configured) == 3 and set(configured) == NODE_IDS,
            "Configured fleet must be exactly 1,2,3",
        )
        placements = node_placements(os.environ["RUVIEW_NODE_PLACEMENTS"])
        require(NODE_IDS <= set(placements), "Missing placements")
        token = os.environ["RUVIEW_API_TOKEN"]
        require(bool(token), "Missing collector authentication")
        context = {
            "assessment": assessment,
            "placements": placements,
            "token": token,
            "collector": os.getenv("RUVIEW_URL", "http://127.0.0.1:3000"),
            "worker": "http://ruview-server-modules.ruview.svc.cluster.local:5016",
        }
        header.update(
            expected_identity={
                "worker_run_id": assessment.identity[0],
                "clock_id": assessment.identity[1],
                "configuration_sha256": assessment.identity[2],
            },
            deadline_seconds=args.deadline_seconds,
            expected_catalog_sha256=assessment.expected_catalog_sha256,
        )
        # Stream a single ordinary JSON document. The64MiB bridge must not retain
        # ninety full worker/candidate objects. A severed pipe remains incomplete.
        sys.stdout.write(json.dumps(header, allow_nan=False)[:-1] + ',"samples":[')
        sys.stdout.flush()
        streaming = True

        def expired(_signum, _frame):
            raise CaptureDeadline()

        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, args.deadline_seconds)
        armed = True
        start_mono, start_wall = time.monotonic_ns(), time.time_ns()
        context.update(start_mono_ns=start_mono, start_wall_ns=start_wall)
        deadline = time.monotonic() + args.deadline_seconds
        last_interrupted = False
        for index in range(SAMPLES):
            if time.monotonic() >= deadline:
                break
            row = collect_sample(index, context, deadline)
            last_interrupted = row.get("deadline_reached", False)
            if attempted:
                sys.stdout.write(",")
            json.dump(row, sys.stdout, allow_nan=False, separators=(",", ":"))
            sys.stdout.flush()
            attempted += 1
            del row
            if last_interrupted:
                break
            if index + 1 < SAMPLES:
                if deadline - time.monotonic() < 1:
                    break
                time.sleep(1)
        summary.update(
            assessment.finish(attempted, attempted == SAMPLES and not last_interrupted)
        )
        summary["passed"] = summary["sampled_diagnostic_execution"]
    except Exception as error:
        summary["error_type"] = type(error).__name__
        if isinstance(error, GateError):
            summary["failed_gate"] = str(error)
        if assessment is not None:
            summary.update(assessment.finish(attempted, False))
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if start_mono is not None:
            summary["sampled_duration_s"] = (time.monotonic_ns() - start_mono) / 1e9
    summary["attempted_samples"] = attempted
    summary["finished_at_ns"] = str(time.time_ns())
    if streaming:
        sys.stdout.write("],")
        # No duplicate keys between immutable header and final assessment.
        sys.stdout.write(json.dumps(summary, allow_nan=False)[1:] + "\n")
        sys.stdout.flush()
    else:
        print(json.dumps({**header, "samples": [], **summary}, allow_nan=False))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
