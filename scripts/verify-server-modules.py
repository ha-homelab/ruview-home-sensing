#!/usr/bin/env python3
"""Read-only live verification; run through stdin inside the HA bridge container.

Writes one JSON report, including real worker and candidate HA fixtures, to stdout.
It never publishes MQTT, records raw CSI, or sends device commands.
"""

import argparse
import collections
import json
import os
import sys
import time
import urllib.request

import module_observations
from bridge import node_placements, observations


class VerificationError(ValueError):
    """A fixed, non-secret gate description safe for the saved report."""


class VerificationParser(argparse.ArgumentParser):
    def error(self, message):
        raise VerificationError("Invalid verification arguments")


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def validate_catalog(snapshot, expected_selected_count):
    require(
        type(expected_selected_count) is int and expected_selected_count in (20, 21),
        "Unreviewed expected selection",
    )
    require(
        module_observations.integer(snapshot["catalog_count"]) == 64,
        "Wrong catalog size",
    )
    require(
        module_observations.integer(snapshot["selected_algorithm_count"])
        == expected_selected_count,
        "Wrong adapters",
    )


def main():
    report = {
        "schema": "ruview.fleet-module-verification.v1",
        "started_at_ns": str(time.time_ns()),
        "recognition_validated": False,
        "publishes_observations": False,
        "samples": [],
        "passed": False,
    }
    try:
        parser = VerificationParser(description=__doc__)
        parser.add_argument("--samples", type=int, default=30)
        parser.add_argument("--nodes", type=int, nargs="+", default=[1, 2, 3])
        parser.add_argument(
            "--expected-selected-count",
            type=int,
            choices=(20, 21),
            default=20,
            help="20 for frozen r4/r5; explicitly choose 21 only for the later source revision",
        )
        args = parser.parse_args()
        require(2 <= args.samples <= 600, "Samples must be in 2..600")
        node_ids = [int(value) for value in os.environ["RUVIEW_NODE_IDS"].split(",")]
        expected = set(node_ids)
        require(
            1 <= len(expected) <= 10
            and len(expected) == len(node_ids)
            and all(1 <= node_id <= 255 for node_id in expected),
            "Invalid expected node set",
        )
        require(
            set(args.nodes) == expected and len(args.nodes) == len(expected),
            "Configured nodes differ from the explicit verification fleet",
        )
        report["expected_node_ids"] = sorted(expected)
        report["expected_catalog_count"] = 64
        report["expected_selected_algorithm_count"] = args.expected_selected_count
        placements = node_placements(os.environ["RUVIEW_NODE_PLACEMENTS"])
        token = os.environ["RUVIEW_API_TOKEN"]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        worker = "http://ruview-server-modules.ruview.svc.cluster.local:5016"
        collector = os.getenv("RUVIEW_URL", "http://127.0.0.1:3000")

        def get(base, path, authenticated=False):
            headers = {"Authorization": "Bearer " + token} if authenticated else {}
            request = urllib.request.Request(base + path, headers=headers)
            with opener.open(request, timeout=3) as response:
                raw = response.read(module_observations.MAX_RESPONSE_BYTES + 1)
            require(
                len(raw) <= module_observations.MAX_RESPONSE_BYTES, "Response bound"
            )
            return json.loads(raw)

        previous = None
        identity = None
        for index in range(args.samples):
            health = get(collector, "/health")
            get(worker, "/health")
            fleet_started = time.monotonic()
            fleet = get(collector, "/api/v1/nodes", True)
            latest_started = time.monotonic()
            latest = get(collector, "/api/v1/sensing/latest", True)
            received = time.monotonic()
            core = observations(
                health,
                latest,
                fleet,
                time.time(),
                (received - fleet_started) * 1000,
                (received - latest_started) * 1000,
            )
            snapshot = get(worker, "/v1/latest")
            report["worker_fixture"] = snapshot
            validate_catalog(snapshot, args.expected_selected_count)
            worker_received = time.monotonic()
            decoded = module_observations.decode(snapshot, time.time_ns())
            core_elapsed = (time.monotonic() - received) * 1000
            for node in core.values():
                node["csi_age_ms"] += core_elapsed
                node["inference_age_ms"] += core_elapsed
            current = module_observations.current(
                decoded, (time.monotonic() - worker_received) * 1000, core
            )
            require(set(current) == expected, "Missing fresh node diagnostic")
            current_identity = (
                snapshot["worker_run_id"],
                snapshot["clock_id"],
                snapshot["configuration_sha256"],
            )
            if identity is not None:
                require(current_identity == identity, "Worker restarted/changed")
            identity = current_identity
            counts = {}
            for node_id, node in current.items():
                require(len(node["algorithms"]) == 64, "Missing catalog entries")
                counts[node_id] = dict(
                    collections.Counter(
                        item["availability"] for item in node["algorithms"]
                    )
                )
                require(not counts[node_id].get("faulted"), "Faulted algorithm")
                require(node["running_algorithms"] > 0, "No running algorithms")
                if previous is not None:
                    old_sequence, old_epoch = previous[node_id]
                    require(node["node_epoch"] == old_epoch, "Node epoch changed")
                    delta = (node["sequence"] - old_sequence) % (2**32)
                    require(0 < delta < 2**31, "Node sequence did not advance")
            previous = {
                node_id: (node["sequence"], node["node_epoch"])
                for node_id, node in current.items()
            }
            report["samples"].append(
                {
                    "at_ns": str(time.time_ns()),
                    "worker_counters": snapshot["counters"],
                    "nodes": {
                        str(node_id): {
                            "sequence": node["sequence"],
                            "node_epoch": node["node_epoch"],
                            "worker_csi_age_ms": node["worker_csi_age_ms"],
                            "csi_age_ms": node["csi_age_ms"],
                            "inference_age_ms": node["inference_age_ms"],
                            "fresh_event_count": node["fresh_event_count"],
                            "availability": counts[node_id],
                        }
                        for node_id, node in current.items()
                    },
                }
            )
            report["worker_fixture"] = snapshot
            report["ha_candidate_fixture"] = [
                {
                    "entity_id": f"sensor.ruview_node{node_id}_server_modules",
                    "state": node["state"],
                    "attributes": {
                        **{key: value for key, value in node.items() if key != "state"},
                        "published_at_ns": str(time.time_ns()),
                        **placements[node_id],
                    },
                }
                for node_id, node in current.items()
            ]
            if index + 1 < args.samples:
                time.sleep(1)
        report["passed"] = True
    except Exception as error:
        # Exception details can contain request information; retain the type only.
        report["error_type"] = type(error).__name__
        if isinstance(error, VerificationError):
            report["failed_gate"] = str(error)
    report["finished_at_ns"] = str(time.time_ns())
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
