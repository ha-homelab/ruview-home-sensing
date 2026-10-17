"""Score held-out fall events without converting heuristic flags into ground truth.

Inputs are independent reviewed reference events, detector alerts, and explicit
reference/detector coverage on the same clock. This module never sends an alarm.
"""

import argparse
import hashlib
import json
import math
import re
from bisect import bisect_left, bisect_right
from pathlib import Path

SCHEMA = "ruview.fall-evaluation-input.v1"
MAX_BYTES = 8 * 1024 * 1024


def require(value, reason):
    if not value:
        raise ValueError(reason)


def integer(value, name, minimum=0):
    require(type(value) is int and minimum <= value <= 2**63 - 1, name)
    return value


def number(value, name, minimum=0):
    require(
        type(value) in (int, float) and math.isfinite(value) and value >= minimum,
        name,
    )
    return value


def identity(value):
    require(isinstance(value, str) and 0 < len(value) <= 128, "invalid_identity")
    return value


def sha(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
        "invalid_sha256",
    )
    return value


def canonical_sha(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def intervals(value, bounds):
    require(isinstance(value, list) and len(value) <= 10000, "invalid_coverage")
    output = []
    for pair in value:
        require(isinstance(pair, list) and len(pair) == 2, "invalid_interval")
        start, end = [integer(v, "invalid_interval_time") for v in pair]
        require(bounds[0] <= start < end <= bounds[1], "interval_out_of_bounds")
        require(not output or output[-1][1] <= start, "unordered_coverage")
        if output and output[-1][1] == start:
            output[-1][1] = end
        else:
            output.append([start, end])
    return output


def contains(spans, start, end=None):
    if end is None:
        return any(a <= start < b for a, b in spans)
    return any(a <= start <= end < b for a, b in spans)


def intersection_ns(left, right):
    i = j = total = 0
    while i < len(left) and j < len(right):
        a, b = left[i], right[j]
        total += max(0, min(a[1], b[1]) - max(a[0], b[0]))
        if a[1] <= b[1]:
            i += 1
        else:
            j += 1
    return total


def in_event_horizon(at, windows, starts):
    index = bisect_right(starts, at) - 1
    return index >= 0 and at <= windows[index][1]


def evaluate(data):
    """Return event-level metrics; passing numerical gates is not a deployment permit."""
    require(data.get("schema") == SCHEMA, "invalid_schema")
    classification = data.get("classification")
    require(classification in ("synthetic", "household_recording"), "classification")
    candidate_sha = sha(data["candidate_sha256"])
    training = data["training_session_ids"]
    require(isinstance(training, list) and len(training) <= 10000, "training_sessions")
    require(len(set(map(identity, training))) == len(training), "duplicate_training")
    policy = data["policy"]
    require(
        set(policy)
        == {
            "early_tolerance_ns",
            "max_latency_ns",
            "min_reference_hours",
            "min_negative_reference_hours",
            "min_fall_events",
            "min_detector_coverage_fraction",
            "min_recall",
            "max_false_alerts_per_reference_hour",
            "max_false_alerts_per_negative_hour",
            "max_p95_latency_seconds",
        },
        "invalid_policy",
    )
    early = integer(policy["early_tolerance_ns"], "early_tolerance_ns")
    late = integer(policy["max_latency_ns"], "max_latency_ns", 1)
    integer(policy["min_fall_events"], "min_fall_events", 1)
    require(
        number(policy["min_reference_hours"], "min_reference_hours") > 0,
        "positive_reference_hours_required",
    )
    require(
        number(policy["min_negative_reference_hours"], "min_negative_reference_hours")
        > 0,
        "positive_negative_hours_required",
    )
    for key in ("min_detector_coverage_fraction", "min_recall"):
        require(0 < number(policy[key], key) <= 1, "invalid_fraction")
    for key in (
        "max_false_alerts_per_reference_hour",
        "max_false_alerts_per_negative_hour",
        "max_p95_latency_seconds",
    ):
        number(policy[key], key)
    declared_sha = sha(data["predeclared_policy_sha256"])
    require(declared_sha == canonical_sha(policy), "policy_digest_mismatch")
    sha(data["reference_review_sha256"])
    sessions = data["sessions"]
    require(isinstance(sessions, list) and 0 < len(sessions) <= 1000, "sessions")
    seen, reference_hashes, recording_hashes, clock_spans = set(), set(), set(), {}
    totals = {
        key: 0
        for key in (
            "tp",
            "fn",
            "fp",
            "unscored_alerts",
            "reference_ns",
            "detector_reference_ns",
            "events_during_detector_gaps",
            "negative_reference_ns",
            "negative_false_alerts",
        )
    }
    latencies, details = [], []
    for session in sessions:
        sid = identity(session["session_id"])
        require(sid not in seen and sid not in training, "session_leakage_or_duplicate")
        seen.add(sid)
        clock_id = identity(session["clock_id"])
        require(
            session["reference_independent"] is True, "independent_reference_required"
        )
        require(session["reference_reviewed"] is True, "reviewed_reference_required")
        reference_hash = sha(session["reference_sha256"])
        recording_hash = sha(session["detector_recording_sha256"])
        require(
            reference_hash not in reference_hashes
            and recording_hash not in recording_hashes,
            "repeated_recording",
        )
        reference_hashes.add(reference_hash)
        recording_hashes.add(recording_hash)
        start = integer(session["start_ns"], "session_start")
        end = integer(session["end_ns"], "session_end", 1)
        require(start < end, "session_bounds")
        require(
            all(end <= a or start >= b for a, b in clock_spans.get(clock_id, [])),
            "overlapping_sessions",
        )
        clock_spans.setdefault(clock_id, []).append((start, end))
        reference = intervals(session["reference_coverage"], (start, end))
        detector = intervals(session["detector_coverage"], (start, end))
        events = session["reference_events"]
        alerts = session["alerts"]
        require(isinstance(events, list) and len(events) <= 10000, "event_count")
        require(isinstance(alerts, list) and len(alerts) <= 10000, "alert_count")
        event_ids, alert_ids, windows, predictions = set(), set(), [], []
        for event in events:
            eid = identity(event["event_id"])
            require(eid not in event_ids, "duplicate_event")
            event_ids.add(eid)
            onset = integer(event["onset_ns"], "event_onset")
            uncertainty = integer(event["uncertainty_ns"], "event_uncertainty")
            low, high = onset - uncertainty - early, onset + uncertainty + late
            # A truncated matching horizon cannot be counted as a fair evaluation.
            require(contains(reference, low, high), "event_horizon_not_observed")
            windows.append((low, high, onset, uncertainty, eid))
        windows.sort()
        require(
            all(a[1] < b[0] for a, b in zip(windows, windows[1:], strict=False)),
            "ambiguous_overlapping_event_horizons",
        )
        for alert in alerts:
            aid = identity(alert["alert_id"])
            require(aid not in alert_ids, "duplicate_alert")
            alert_ids.add(aid)
            at = integer(alert["at_ns"], "alert_time")
            require(start <= at < end, "alert_out_of_session")
            require(contains(detector, at), "alert_outside_detector_coverage")
            predictions.append((at, aid))
        predictions.sort()
        prediction_times = [at for at, _aid in predictions]
        window_starts = [window[0] for window in windows]

        matched, matches, missed = set(), [], []
        for low, high, onset, uncertainty, eid in windows:
            if not contains(detector, onset - uncertainty, onset + uncertainty):
                totals["events_during_detector_gaps"] += 1
            index = bisect_left(prediction_times, low)
            if index == len(predictions) or predictions[index][0] > high:
                missed.append(eid)
                continue
            at, aid = predictions[index]
            matched.add(aid)
            # Upper uncertainty bound is conservative for a latency acceptance gate.
            latency = (at - onset + uncertainty) / 1e9
            latencies.append(latency)
            matches.append(
                {
                    "event_id": eid,
                    "alert_id": aid,
                    "latency_lower_seconds": (at - onset - uncertainty) / 1e9,
                    "latency_upper_seconds": latency,
                }
            )
        false_alerts = [
            aid
            for at, aid in predictions
            if aid not in matched and contains(reference, at)
        ]
        negative_false_alerts = [
            aid
            for at, aid in predictions
            if contains(reference, at)
            and not in_event_horizon(at, windows, window_starts)
        ]
        unscored = [aid for at, aid in predictions if not contains(reference, at)]
        totals["tp"] += len(matches)
        totals["fn"] += len(
            missed
        )  # Includes events missed while detector was offline.
        totals["fp"] += len(false_alerts)
        totals["unscored_alerts"] += len(unscored)
        totals["reference_ns"] += sum(b - a for a, b in reference)
        totals["negative_reference_ns"] += sum(b - a for a, b in reference) - sum(
            high - low for low, high, *_ in windows
        )
        totals["negative_false_alerts"] += len(negative_false_alerts)
        totals["detector_reference_ns"] += intersection_ns(reference, detector)
        details.append(
            {
                "session_id": sid,
                "matches": matches,
                "missed_event_ids": missed,
                "false_alert_ids": false_alerts,
                "unscored_alert_ids": unscored,
            }
        )
    hours = totals["reference_ns"] / 3.6e12
    negative_hours = totals["negative_reference_ns"] / 3.6e12
    count = totals["tp"] + totals["fn"]
    recall = totals["tp"] / count if count else None
    precision_denominator = totals["tp"] + totals["fp"]
    precision = totals["tp"] / precision_denominator if precision_denominator else None
    rate = totals["fp"] / hours if hours else None
    negative_rate = (
        totals["negative_false_alerts"] / negative_hours if negative_hours else None
    )
    coverage = totals["detector_reference_ns"] / totals["reference_ns"] if hours else 0
    p95 = sorted(latencies)[math.ceil(0.95 * len(latencies)) - 1] if latencies else None
    gates = {
        "reference_duration": hours >= policy["min_reference_hours"],
        "negative_reference_duration": negative_hours
        >= policy["min_negative_reference_hours"],
        "fall_event_count": count >= policy["min_fall_events"],
        "detector_coverage": coverage >= policy["min_detector_coverage_fraction"],
        "recall": recall is not None and recall >= policy["min_recall"],
        "false_alert_rate": rate is not None
        and rate <= policy["max_false_alerts_per_reference_hour"],
        "negative_false_alert_rate": negative_rate is not None
        and negative_rate <= policy["max_false_alerts_per_negative_hour"],
        "latency": p95 is not None and p95 <= policy["max_p95_latency_seconds"],
    }
    return {
        "schema": "ruview.fall-evaluation-report.v1",
        "classification": classification,
        "input_sha256": canonical_sha(data),
        "candidate_sha256": candidate_sha,
        "policy_sha256": declared_sha,
        "reference_review_sha256": data["reference_review_sha256"],
        "counts": totals,
        "reference_hours": hours,
        "negative_reference_hours": negative_hours,
        "detector_coverage_fraction": coverage,
        "recall": recall,
        "precision": precision,
        "false_alerts_per_reference_hour": rate,
        "false_alerts_per_negative_hour": negative_rate,
        "p95_latency_upper_seconds": p95,
        "gates": gates,
        "numerical_gates_passed": all(gates.values()),
        "sessions": details,
        "recognition_validated": False,
        "publish_to_ha": False,
        "policy_predeclaration_verified": False,
        "reference_review_verified": False,
        "qualification": "dataset_evaluation_only_requires_independent_evidence_review",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with Path(args.input).open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input_too_large")
    from .__main__ import private_output
    from .capture import strict_json

    report = evaluate(strict_json(raw))
    report["input_original_sha256"] = hashlib.sha256(raw).hexdigest()
    with private_output(args.output) as out:
        json.dump(report, out, indent=2, allow_nan=False)
        out.write("\n")
    print(
        json.dumps(
            {
                "numerical_gates_passed": report["numerical_gates_passed"],
                "recognition_validated": False,
            }
        )
    )


if __name__ == "__main__":
    main()
