"""Extract RSSI-only proxy examples from a retained reference capture.

The old projection dropped node_features. Never reconstruct those features or
turn camera/RF states into occupancy labels. This adapter uses the explicitly
configured independent binary channels and the measured node RSSI values only.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path


def stamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone_required")
    return parsed.timestamp()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def extract(root, config):
    """Return immutable example rows plus consumed-prefix provenance."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe_evidence_root")
    start, end = stamp(config["start_utc"]), stamp(config["end_utc"])
    if not start < end < stamp(config["final_holdout_start_utc"]):
        raise ValueError("development_bounds_required")
    refs = config["references"]
    if (
        not isinstance(refs, list)
        or not 1 <= len(refs) <= 64
        or any(
            not isinstance(x, dict)
            or not isinstance(x.get("entity_id"), str)
            or not x["entity_id"]
            or not isinstance(x.get("source_group"), str)
            or not x["source_group"]
            for x in refs
        )
        or len({x["entity_id"] for x in refs}) != len(refs)
    ):
        raise ValueError("distinct_explicit_references_required")
    if len({x["source_group"] for x in refs}) != len(refs):
        raise ValueError("physical_source_aliases_must_be_deduplicated")
    if any(x.get("derived_from_ruview") is not False for x in refs):
        raise ValueError("independent_reference_declaration_required")
    nodes = config["node_ids"]
    if (
        not isinstance(nodes, list)
        or not 1 <= len(nodes) <= 16
        or any(type(n) is not int or not 1 <= n <= 65535 for n in nodes)
        or len(set(nodes)) != len(nodes)
    ):
        raise ValueError("distinct_explicit_nodes_required")
    contract = config["feature_contract"]
    if contract["features"] != [f"node_{n}_rssi_dbm" for n in nodes]:
        raise ValueError("explicit_rssi_only_contract_required")
    for key, default, maximum in [
        ("max_transport_bracket_seconds", 10, 60),
        ("max_csi_age_ms", 1500, 60000),
    ]:
        value = config.get(key, default)
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or not 0 < value <= maximum
        ):
            raise ValueError("invalid_" + key)
    exclusions = [
        (stamp(x["start_utc"]), stamp(x["end_utc"])) for x in config["exclusions"]
    ]
    if any(a >= b for a, b in exclusions):
        raise ValueError("invalid_exclusion_interval")
    examples, provenance, discarded = [], [], {}

    def reject(reason, count=1):
        discarded[reason] = discarded.get(reason, 0) + count

    for folder in sorted(root.glob("segment-*")):
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("unsafe_segment")
        meta_path = folder / "metadata.json"
        if (
            meta_path.is_symlink()
            or not meta_path.is_file()
            or meta_path.stat().st_size > 1024 * 1024
        ):
            raise ValueError("unsafe_capture_metadata")
        meta_raw = meta_path.read_bytes()
        meta = json.loads(meta_raw)
        states, pending = {}, []
        connected, generation, last_ha_ns, last_ns = False, None, None, -1
        for path in sorted(folder.glob("events-*.jsonl")):
            if path.is_symlink() or not path.is_file():
                raise ValueError("unsafe_evidence_file")
            digest, length = hashlib.sha256(), 0
            with path.open("rb") as stream:
                while True:
                    raw = stream.readline(1024 * 1024 + 1)
                    if not raw:
                        break
                    if len(raw) > 1024 * 1024:
                        raise ValueError("oversized_row")
                    if not raw.endswith(b"\n"):
                        reject("unfinished_tail")
                        break
                    row = json.loads(raw)
                    t = stamp(row["received_at_utc"])
                    if t >= end:
                        break
                    digest.update(raw)
                    length += len(raw)
                    ns = row["received_monotonic_ns"]
                    if (
                        row["run_id"] != meta["run_id"]
                        or type(ns) is not int
                        or ns < last_ns
                    ):
                        raise ValueError("capture_identity_or_clock_changed")
                    last_ns = ns
                    kind = row["kind"]
                    if kind in ("ha_gap", "ha_baseline", "clock_step"):
                        reject("unconfirmed_transport", len(pending))
                        pending.clear()
                        connected = False
                        states.clear()
                        last_ha_ns = ns
                        if kind == "ha_baseline":
                            generation = row["generation"]
                            connected = True
                            states = {s["entity_id"]: s for s in row["states"]}
                        elif kind == "clock_step":
                            # Time-aligned proxy rows after a clock discontinuity
                            # need a separately reviewed clock mapping.
                            raise ValueError("clock_step_requires_review")
                    elif kind == "ha_state_changed":
                        healthy = connected and row["generation"] == generation
                        for candidate, previous_ns in pending:
                            if (
                                healthy
                                and previous_ns is not None
                                and 0
                                <= (ns - previous_ns) / 1e9
                                <= config.get("max_transport_bracket_seconds", 10)
                            ):
                                candidate["provenance"][
                                    "transport_confirmed_at_utc"
                                ] = row["received_at_utc"]
                                examples.append(candidate)
                            else:
                                reject("unconfirmed_transport")
                        pending.clear()
                        if not healthy:
                            connected = False
                            states.clear()
                        elif not row.get("historical_or_duplicate"):
                            states[row["entity_id"]] = row["new"]
                        last_ha_ns = ns
                    elif (
                        kind == "ruview_sample"
                        and row.get("endpoint") == "nodes"
                        and t >= start
                    ):
                        if not connected or last_ha_ns is None:
                            reject("no_reference_baseline")
                            continue
                        if any(a <= t < b for a, b in exclusions):
                            reject("maintenance")
                            continue
                        node_rows = row["data"].get("nodes", [])
                        if (
                            not isinstance(node_rows, list)
                            or any(
                                not isinstance(n, dict)
                                or type(n.get("node_id")) is not int
                                for n in node_rows
                            )
                            or len({n["node_id"] for n in node_rows}) != len(node_rows)
                        ):
                            raise ValueError("invalid_or_duplicate_node_rows")
                        values = {n["node_id"]: n for n in node_rows}
                        features = {}
                        for n in nodes:
                            value = values.get(n, {})
                            rssi = value.get("rssi_dbm")
                            age = value.get("csi_last_seen_ms")
                            if (
                                value.get("csi_status") != "active"
                                or type(rssi) not in (int, float)
                                or not math.isfinite(rssi)
                                or not -127 <= rssi <= 0
                                or type(age) not in (int, float)
                                or not math.isfinite(age)
                                or not 0 <= age <= config.get("max_csi_age_ms", 1500)
                            ):
                                break
                            features[f"node_{n}_rssi_dbm"] = rssi
                        if len(features) != len(nodes):
                            reject("missing_or_stale_csi")
                            continue
                        references = []
                        for ref in refs:
                            value = states.get(ref["entity_id"], {})
                            if value.get("available") is not True or value.get(
                                "state"
                            ) not in ("on", "off"):
                                break
                            references.append(
                                {
                                    "source_group": ref["source_group"],
                                    "kind": "motion",
                                    "independent": True,
                                    "derived_from_ruview": False,
                                    "available": True,
                                    "state": value["state"],
                                    "observed_at_utc": row["received_at_utc"],
                                }
                            )
                        if len(references) != len(refs):
                            reject("unknown_reference")
                            continue
                        instant = row["received_at_utc"]
                        candidate = {
                            "schema": "ruview.shadow-motion-example.v1",
                            "example_id": f"{meta['run_id']}:{ns}",
                            "observed_at_utc": instant,
                            "interval_start_utc": instant,
                            "interval_end_utc": dt.datetime.fromtimestamp(
                                t + 0.000001, dt.timezone.utc
                            ).isoformat(),
                            "feature_contract": copy.deepcopy(contract),
                            "features": features,
                            "quality": {"eligible": True, "reasons": []},
                            "references": references,
                            "maintenance_excluded": False,
                            "provenance": {
                                "capture_run_id": meta["run_id"],
                                "receipt_monotonic_ns": ns,
                                "reference_generation": generation,
                                "reference_semantics": "Observed binary channel state; OFF is not empty-room evidence",
                                "original_reference_updated_at": {
                                    r["source_group"]: states[r["entity_id"]].get(
                                        "last_updated"
                                    )
                                    for r in refs
                                },
                                "features_semantics": "Instantaneous retained RSSI projection; no CSI spectral features reconstructed",
                                "native_profile_qualified": False,
                                "capture_metadata_sha256": hashlib.sha256(
                                    meta_raw
                                ).hexdigest(),
                            },
                        }
                        pending.append((candidate, last_ha_ns))
                        if len(pending) > 32:
                            reject("unconfirmed_transport", len(pending))
                            pending.clear()
            provenance.append(
                {
                    "segment": folder.name,
                    "part": path.name,
                    "prefix_bytes": length,
                    "prefix_sha256": digest.hexdigest(),
                    "is_full_final_file": False,
                }
            )
        reject("unconfirmed_transport", len(pending))
    return examples, {
        "schema": "ruview.shadow-legacy-export.v1",
        "rows": len(examples),
        "config_sha256": hashlib.sha256(encoded(config)).hexdigest(),
        "prefixes": provenance,
        "discarded": discarded,
        "recognition_validated": False,
        "publish_to_ha": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.output.resolve().is_relative_to(args.input.resolve()):
        raise ValueError("output_must_be_separate")
    examples, receipt = extract(args.input, json.loads(args.config.read_text()))
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    payload = b"".join(encoded(x) for x in examples)
    with (args.output / "examples.jsonl").open("xb") as stream:
        stream.write(payload)
    receipt["examples_sha256"] = hashlib.sha256(payload).hexdigest()
    (args.output / "receipt.json").write_bytes(encoded(receipt))
    print(
        json.dumps(
            {
                "rows": len(examples),
                "sha256": receipt["examples_sha256"],
                "discarded": receipt["discarded"],
            }
        )
    )


if __name__ == "__main__":
    main()
