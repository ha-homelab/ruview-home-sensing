#!/usr/bin/env python3
"""Passively record accepted CSI freshness; never send measurements to RuView."""

import argparse
import json
import math
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from collector_profile import add_profile_arguments, load_profile
    from transport_security import http_opener
except ModuleNotFoundError as exc:
    if exc.name != "collector_profile":
        raise
    from scripts.collector_profile import add_profile_arguments, load_profile
    from scripts.transport_security import http_opener


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def assess_coverage(sample_times, elapsed_s):
    """Require observations across the measured interval, including its endpoints."""
    coverage = {
        "samples": len(sample_times),
        "max_allowed_uncovered_s": 5,
        "start_uncovered_s": None,
        "end_uncovered_s": None,
        "sample_span_s": None,
        "max_uncovered_s": None,
        "timestamps_valid": False,
        "passed": False,
    }
    if not finite_number(elapsed_s) or elapsed_s <= 0:
        return coverage
    if not all(finite_number(t) and 0 <= t <= elapsed_s for t in sample_times) or any(
        b <= a for a, b in zip(sample_times, sample_times[1:], strict=False)
    ):
        return coverage
    coverage["timestamps_valid"] = True
    if not sample_times:
        coverage["max_uncovered_s"] = elapsed_s
        return coverage
    start_gap = sample_times[0]
    end_gap = elapsed_s - sample_times[-1]
    gaps = [start_gap, end_gap]
    gaps.extend(b - a for a, b in zip(sample_times, sample_times[1:], strict=False))
    # The observer records milliseconds. Compare at that same resolution to
    # avoid rejecting an exact five-second decimal interval due to float noise.
    coverage.update(
        start_uncovered_s=round(start_gap, 3),
        end_uncovered_s=round(end_gap, 3),
        sample_span_s=round(sample_times[-1] - sample_times[0], 3),
        max_uncovered_s=round(max(gaps), 3),
    )
    coverage["passed"] = len(sample_times) >= 2 and coverage["max_uncovered_s"] <= 5
    return coverage


def is_fresh_csi(node, max_age_ms):
    age = node.get("csi_last_seen_ms")
    return (
        node.get("csi_status") == "active"
        and finite_number(age)
        and 0 <= age <= max_age_ms
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_profile_arguments(parser)
    parser.add_argument("--duration", type=int, default=315)
    parser.add_argument("--nodes", type=int, nargs="+", default=[1, 3])
    parser.add_argument("--max-age-ms", type=int, default=3000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    collector = load_profile(args.collector_profile, args.collector_profile_sha256)

    def revalidate():
        if (
            load_profile(args.collector_profile, args.collector_profile_sha256)
            != collector
        ):
            raise ValueError("collector_profile_changed")

    if args.duration < 5 or args.max_age_ms < 1:
        parser.error("Use a duration of at least five seconds and a positive age limit")
    token = os.environ.get("RUVIEW_API_TOKEN", "")
    if not token:
        parser.error("Set RUVIEW_API_TOKEN from the private credential source")
    opener = http_opener(NoRedirect())

    def get(path):
        revalidate()
        request = urllib.request.Request(
            collector.http_origin + path,
            headers={"Authorization": "Bearer " + token},
        )
        with opener.open(request, timeout=5) as reply:
            return json.load(reply)

    os.umask(0o077)
    started = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    samples, errors = [], []
    while time.monotonic() - start < args.duration:
        elapsed = round(time.monotonic() - start, 3)
        try:
            fleet = get("/api/v1/nodes")
            # Stamp the accepted-CSI response, not the beginning of a possibly
            # slow request. Sensing publication metadata is not the active grid:
            # vitals/privacy paths can omit amplitudes and publish count zero.
            received_s = round(time.monotonic() - start, 3)
            sensing = get("/api/v1/sensing/latest")
            published_counts = {
                node["node_id"]: node.get("subcarrier_count")
                for node in sensing.get("nodes", [])
            }
            samples.append(
                {
                    "elapsed_s": received_s,
                    "source": sensing.get("source"),
                    "nodes": [
                        {
                            **{
                                key: node.get(key)
                                for key in (
                                    "node_id",
                                    "csi_status",
                                    "csi_last_seen_ms",
                                    "csi_sequence",
                                )
                            },
                            "published_subcarrier_count": published_counts.get(
                                node["node_id"]
                            ),
                        }
                        for node in fleet.get("nodes", [])
                    ],
                }
            )
        except Exception as exc:
            errors.append({"elapsed_s": elapsed, "error": type(exc).__name__})
        time.sleep(min(1, max(0, args.duration - (time.monotonic() - start))))

    elapsed_s = round(time.monotonic() - start, 3)
    coverage = assess_coverage([sample["elapsed_s"] for sample in samples], elapsed_s)
    summary = {}
    for node_id in args.nodes:
        rows = [
            node
            for sample in samples
            for node in sample["nodes"]
            if node["node_id"] == node_id
        ]
        ages = [
            row["csi_last_seen_ms"]
            for row in rows
            if finite_number(row["csi_last_seen_ms"])
        ]
        sequences = {
            row["csi_sequence"] for row in rows if row["csi_sequence"] is not None
        }
        summary[node_id] = {
            "samples": len(rows),
            "missing_samples": len(samples) - len(rows),
            "max_accepted_age_ms": max(ages, default=None),
            "fresh_samples": sum(is_fresh_csi(row, args.max_age_ms) for row in rows),
            "distinct_sequences": len(sequences),
            "published_subcarrier_counts": sorted(
                {
                    row["published_subcarrier_count"]
                    for row in rows
                    if row["published_subcarrier_count"] is not None
                }
            ),
        }
    try:
        revalidate()
    except (ValueError, OSError):
        errors.append({"elapsed_s": elapsed_s, "error": "collector_profile_changed"})
    passed = (
        coverage["passed"]
        and not errors
        and all(sample["source"] == "esp32" for sample in samples)
        and all(
            row["fresh_samples"] == len(samples)
            and row["missing_samples"] == 0
            and row["distinct_sequences"] > 1
            for row in summary.values()
        )
    )
    report = {
        "started_utc": started,
        "collector_profile_sha256": args.collector_profile_sha256,
        "elapsed_s": elapsed_s,
        "poll_interval_s": 1,
        "coverage": coverage,
        "max_age_ms": args.max_age_ms,
        "passed": passed,
        "summary": summary,
        "errors": errors,
        "samples": samples,
    }
    with args.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "samples"}, indent=2
        )
    )
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
