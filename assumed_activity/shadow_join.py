"""Join verified weak-reference examples to earlier full-feature observations.

Only a proven shared host boot permits monotonic alignment. Source recordings
remain immutable; active journal prefixes are explicitly provisional.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
import uuid
from pathlib import Path

from .shadow_model import canonical, timestamp, validate_contract

MAX_BYTES = 1024 * 1024 * 1024
MAX_ROWS = 250_000
MAX_LINE = 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def regular(path, limit=MAX_BYTES):
    path = Path(path)
    require(not path.is_symlink(), "symlink_input")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "invalid_input_file")
    return path


def document(path):
    return json.loads(regular(path, MAX_LINE).read_bytes())


def hash_prefix(path, length):
    path = regular(path)
    require(
        type(length) is int and 0 <= length <= min(MAX_BYTES, path.stat().st_size),
        "invalid_prefix_length",
    )
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as stream:
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            require(bool(block), "short_source_prefix")
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def boot_id(value):
    try:
        parsed = uuid.UUID(value)
        return value if parsed.int and str(parsed) == value else None
    except (ValueError, TypeError, AttributeError):
        return None


def profile_identity(node):
    """Frozen radio/run identity, excluding normal bounded-history renewals."""
    worker = node.get("worker", {})
    diagnostics = node.get("collector_diagnostics", {})
    return {
        "worker": {
            key: worker.get(key)
            for key in (
                "worker_run_id",
                "configuration_sha256",
                "clock_id",
                "schema_valid",
                "grid",
            )
        },
        "collector": {
            key: diagnostics.get(key)
            for key in ("subcarrier_count", "frequency_mhz", "channel")
        },
    }


def reference_export(folder, source_root):
    folder, source_root = Path(folder), Path(source_root)
    require(not folder.is_symlink() and not source_root.is_symlink(), "symlink_root")
    receipt = document(folder / "receipt.json")
    require(
        receipt.get("schema") == "ruview.shadow-legacy-export.v1",
        "unexpected_reference_export",
    )
    path = regular(folder / "examples.jsonl")
    require(
        hash_prefix(path, path.stat().st_size) == receipt.get("examples_sha256"),
        "reference_examples_hash_mismatch",
    )
    require(
        isinstance(receipt.get("prefixes"), list) and len(receipt["prefixes"]) <= 4096,
        "invalid_reference_prefixes",
    )
    metadata = {}
    for prefix in receipt["prefixes"]:
        segment, part = prefix["segment"], prefix["part"]
        require(
            re.fullmatch(r"segment-[A-Za-z0-9-]+", segment) is not None,
            "unsafe_segment_name",
        )
        require(
            re.fullmatch(r"events-[0-9]+\.jsonl", part) is not None,
            "unsafe_reference_part",
        )
        segment_root = source_root / segment
        require(not segment_root.is_symlink(), "symlink_segment")
        actual = hash_prefix(segment_root / part, prefix["prefix_bytes"])
        require(actual == prefix["prefix_sha256"], "reference_source_prefix_mismatch")
        raw = regular(segment_root / "metadata.json", MAX_LINE).read_bytes()
        meta = json.loads(raw)
        require(
            meta.get("schema") == "ruview.ha-reference-capture.v1",
            "unexpected_reference_metadata",
        )
        metadata[hashlib.sha256(raw).hexdigest()] = meta
    examples = []
    with path.open("rb") as stream:
        while raw := stream.readline(MAX_LINE + 1):
            require(
                len(raw) <= MAX_LINE and raw.endswith(b"\n"), "invalid_reference_line"
            )
            examples.append(json.loads(raw))
            require(len(examples) <= MAX_ROWS, "too_many_reference_rows")
    require(len(examples) == receipt.get("rows"), "reference_row_count_mismatch")
    for row in examples:
        provenance = row.get("provenance", {})
        meta = metadata.get(provenance.get("capture_metadata_sha256"))
        require(
            meta is not None and provenance.get("capture_run_id") == meta.get("run_id"),
            "reference_metadata_binding_mismatch",
        )
        require(
            type(provenance.get("receipt_monotonic_ns")) is int,
            "reference_monotonic_missing",
        )
        require(
            timestamp(provenance["transport_confirmed_at_utc"])
            >= timestamp(row["observed_at_utc"]),
            "reference_transport_unconfirmed",
        )
    return examples, metadata, receipt


def journal_export(root, expected_metadata_sha256):
    root = Path(root)
    require(not root.is_symlink() and root.is_dir(), "invalid_journal_root")
    raw_meta = regular(root / "metadata.json", MAX_LINE).read_bytes()
    require(
        hashlib.sha256(raw_meta).hexdigest() == expected_metadata_sha256,
        "journal_metadata_hash_mismatch",
    )
    meta = json.loads(raw_meta)
    require(
        meta.get("schema") == "ruview.shadow-journal.v1", "unexpected_journal_schema"
    )
    require(
        meta.get("configuration_sha256") == sha(meta["configuration"]),
        "journal_configuration_hash_mismatch",
    )
    require(
        meta.get("monotonic_clock") == "CLOCK_MONOTONIC",
        "journal_monotonic_clock_unknown",
    )
    paths = sorted(root.glob("observations-*.jsonl"))
    require(0 < len(paths) <= 256, "invalid_journal_parts")
    terminal = (
        document(root / "terminal.json") if (root / "terminal.json").exists() else None
    )
    status = terminal or document(root / "status.json")
    closed = {x["name"]: x for x in status.get("parts", status.get("closed_parts", []))}
    prefixes = []
    receipt = {
        "prefixes": prefixes,
        "provisional": terminal is None
        or bool(set(p.name for p in paths) - set(closed)),
        "verification_complete": False,
    }

    def records():
        total = row_count = 0
        previous_index, previous_mono = -1, -1
        for path in paths:
            require(
                re.fullmatch(r"observations-[0-9]+\.jsonl", path.name) is not None,
                "unsafe_journal_part",
            )
            path = regular(path)
            initial = path.stat()
            total += initial.st_size
            require(total <= MAX_BYTES, "journal_byte_limit")
            if path.name in closed:
                part = closed[path.name]
                require(
                    initial.st_size == part["bytes"]
                    and hash_prefix(path, initial.st_size) == part["sha256"],
                    "closed_journal_hash_mismatch",
                )
            digest, consumed = hashlib.sha256(), 0
            with path.open("rb") as stream:
                while consumed < initial.st_size:
                    raw = stream.readline(min(MAX_LINE + 1, initial.st_size - consumed))
                    require(len(raw) <= MAX_LINE, "oversized_journal_line")
                    if not raw.endswith(b"\n"):
                        require(
                            path.name not in closed and terminal is None,
                            "unfinished_closed_journal_line",
                        )
                        break
                    digest.update(raw)
                    consumed += len(raw)
                    row = json.loads(raw)
                    require(
                        row.get("schema") == "ruview.shadow-features.v1"
                        and row.get("kind") == "observation",
                        "unexpected_observation_schema",
                    )
                    require(
                        row.get("run_id") == meta["run_id"]
                        and row.get("configuration_sha256")
                        == meta["configuration_sha256"],
                        "observation_identity_mismatch",
                    )
                    index, mono = row.get("index"), row.get("monotonic_ns")
                    require(
                        type(index) is int
                        and type(mono) is int
                        and index > previous_index
                        and mono >= previous_mono,
                        "journal_order_violation",
                    )
                    require(
                        type(row.get("utc_ns")) is int
                        and type(row.get("clock_epoch")) is int
                        and row["clock_epoch"] >= 0,
                        "invalid_observation_clock",
                    )
                    require(
                        abs(
                            int(timestamp(row["captured_at_utc"]) * 1e9) - row["utc_ns"]
                        )
                        <= 1000,
                        "observation_wall_timestamp_disagrees",
                    )
                    row = {
                        **row,
                        "_source": {
                            "part": path.name,
                            "end_offset": consumed,
                            "row_sha256": hashlib.sha256(raw).hexdigest(),
                        },
                        "_index_gap": previous_index >= 0
                        and index != previous_index + 1,
                    }
                    row_count += 1
                    previous_index, previous_mono = index, mono
                    require(row_count <= MAX_ROWS, "journal_row_limit")
                    yield row
            final = path.stat()
            require(
                (initial.st_dev, initial.st_ino) == (final.st_dev, final.st_ino)
                and final.st_size >= consumed,
                "journal_changed_while_reading",
            )
            if path.name in closed:
                require(
                    consumed == closed[path.name]["bytes"]
                    and digest.hexdigest() == closed[path.name]["sha256"],
                    "closed_journal_changed_while_reading",
                )
            prefixes.append(
                {
                    "part": path.name,
                    "prefix_bytes": consumed,
                    "prefix_sha256": digest.hexdigest(),
                    "closed_hash_verified": path.name in closed,
                }
            )
        require(
            not (set(closed) - {p.name for p in paths}), "closed_journal_part_missing"
        )
        receipt["verification_complete"] = True

    return records(), meta, receipt


def configuration(config):
    require(
        config.get("schema") == "ruview.shadow-join-config.v1", "unexpected_join_config"
    )
    require(
        boot_id(config.get("expected_boot_id")) is not None,
        "shared_boot_binding_required",
    )
    require(
        type(config.get("expected_clock_epoch")) is int
        and config["expected_clock_epoch"] >= 0,
        "clock_epoch_binding_required",
    )
    nodes, keys = config["node_ids"], config["feature_keys"]
    require(
        isinstance(nodes, list)
        and 1 <= len(nodes) <= 16
        and len(set(nodes)) == len(nodes)
        and all(type(n) is int and 1 <= n <= 65535 for n in nodes),
        "invalid_join_nodes",
    )
    require(
        isinstance(keys, list)
        and 1 <= len(keys) <= 64
        and len(set(keys)) == len(keys)
        and all(
            isinstance(k, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", k)
            for k in keys
        )
        and len(nodes) * len(keys) <= 64,
        "invalid_join_features",
    )
    require(
        set(config["expected_profiles"]) == {str(n) for n in nodes},
        "explicit_profiles_required",
    )
    require(0 < config.get("max_lag_seconds", 1.5) <= 1.5, "invalid_join_lag")
    require(
        0 <= config.get("max_clock_disagreement_ms", 100) <= 500,
        "invalid_clock_tolerance",
    )
    anchor = config.get("minimum_observation_index", 0)
    require(type(anchor) is int and 0 <= anchor <= 2**31 - 1, "invalid_binding_anchor")
    samples = config.get("epoch_stability_samples", 2)
    seconds = config.get("epoch_stability_seconds", 1.0)
    require(
        type(samples) is int and 2 <= samples <= 60, "invalid_epoch_stability_samples"
    )
    require(
        type(seconds) in (int, float) and math.isfinite(seconds) and 1 <= seconds <= 60,
        "invalid_epoch_stability_seconds",
    )
    identity = {
        key: copy.deepcopy(config[key])
        for key in (
            "reference_feature_contract_sha256",
            "journal_metadata_sha256",
            "expected_boot_id",
            "expected_clock_epoch",
            "expected_profiles",
        )
    }
    identity["alignment"] = {
        "direction": "backward_only",
        "max_lag_seconds": config.get("max_lag_seconds", 1.5),
        "max_clock_disagreement_ms": config.get("max_clock_disagreement_ms", 100),
        "minimum_observation_index": anchor,
        "epoch_stability_samples": samples,
        "epoch_stability_seconds": seconds,
        "recoverable_epoch_reasons": ["sequence_gap", "receipt_gap"],
    }
    contract = {
        "name": "full_node_features_same_boot_shadow_join",
        "version": 1,
        "features": [f"node_{node}_{key}" for node in nodes for key in keys],
        "identity": identity,
    }
    validate_contract(contract)
    return contract


class InputStability:
    """Exclude a gap, then observe new primary inputs; never infer continuity."""

    def __init__(self, config, max_age_ms=2500):
        self.samples = config.get("epoch_stability_samples", 2)
        self.delay_ns = int(config.get("epoch_stability_seconds", 1.0) * 1e9)
        self.keys = config["feature_keys"]
        self.max_age_ms = max_age_ms
        self.nodes = {}
        self.summary = {"gap_boundaries": 0, "recoveries": 0, "hard_invalidations": 0}

    def interrupt(self, node, row):
        state = self.nodes.get(node)
        if state and state["gap"]:
            state["gap"].update(stable_samples=0, stable_after_ns=row["monotonic_ns"])

    def observe(self, node, entry, row, uninterrupted):
        worker = entry.get("worker", {})
        epoch, count = worker.get("node_epoch"), worker.get("sequence_discontinuities")
        state = self.nodes.get(node)
        if state is None:
            self.nodes[node] = {
                "epoch": epoch,
                "count": count,
                "gap": None,
                "blocked": None,
                "last_recovery": None,
            }
            return None
        gap_reason = None
        if epoch != state["epoch"]:
            reason = worker.get("epoch_reason")
            if reason in ("sequence_gap", "receipt_gap"):
                gap_reason = reason
            elif reason != "bounded_history_renewal":
                state["blocked"] = "node_epoch_requires_new_binding"
                self.summary["hard_invalidations"] += 1
        if (
            type(count) is int
            and type(state["count"]) is int
            and count != state["count"]
        ):
            if count < state["count"]:
                state["blocked"] = "discontinuity_counter_reset_requires_new_binding"
                self.summary["hard_invalidations"] += 1
            else:
                gap_reason = gap_reason or "sequence_discontinuity"
        state.update(epoch=epoch, count=count)
        if state["blocked"]:
            return state["blocked"]
        if gap_reason:
            state["gap"] = {
                "reason": gap_reason,
                "boundary_index": row["index"],
                "boundary_monotonic_ns": row["monotonic_ns"],
                "stable_after_ns": row["monotonic_ns"],
                "stable_samples": 0,
                "last_source_time_ns": entry.get("source_time_ns"),
            }
            self.summary["gap_boundaries"] += 1
            return "observed_input_stability_pending"
        gap = state["gap"]
        if gap is None:
            return None
        source = entry.get("source_time_ns")
        age = entry.get("source_age_ms")
        rate = entry.get("features", {}).get("frame_rate_hz")
        valid_metrics = all(
            type(entry.get("features", {}).get(key)) in (int, float)
            and math.isfinite(entry["features"][key])
            for key in self.keys
        )
        fresh = (
            uninterrupted
            and entry.get("available") is True
            and valid_metrics
            and type(source) is int
            and source <= row["utc_ns"]
            and type(gap["last_source_time_ns"]) is int
            and source > gap["last_source_time_ns"]
            and type(age) in (int, float)
            and math.isfinite(age)
            and 0 <= age <= self.max_age_ms
            and type(rate) in (int, float)
            and math.isfinite(rate)
            and rate > 0
        )
        if fresh:
            gap["stable_samples"] += 1
            gap["last_source_time_ns"] = source
        else:
            gap.update(
                stable_samples=0,
                stable_after_ns=row["monotonic_ns"],
                last_source_time_ns=source,
            )
        if (
            gap["stable_samples"] >= self.samples
            and row["monotonic_ns"] - gap["stable_after_ns"] >= self.delay_ns
        ):
            state["last_recovery"] = {
                **gap,
                "recovery_index": row["index"],
                "recovery_monotonic_ns": row["monotonic_ns"],
                "meaning": "new_observed_inputs_not_reconstructed_continuity",
            }
            state["gap"] = None
            self.summary["recoveries"] += 1
            return None
        return "observed_input_stability_pending"

    def evidence(self):
        return {
            str(node): copy.deepcopy(state["last_recovery"])
            for node, state in self.nodes.items()
            if state["last_recovery"] is not None
        }


def join(examples, observations, reference_metadata, journal_metadata, config):
    contract = configuration(config)
    expected_boot = config["expected_boot_id"]
    require(journal_metadata.get("boot_id") == expected_boot, "journal_boot_mismatch")
    require(
        journal_metadata.get("monotonic_clock") == "CLOCK_MONOTONIC",
        "journal_clock_unproven",
    )
    max_lag_ns = int(config.get("max_lag_seconds", 1.5) * 1e9)
    tolerance_ns = int(config.get("max_clock_disagreement_ms", 100) * 1e6)
    max_age_ms = journal_metadata.get("configuration", {}).get(
        "max_source_age_ms", 2500
    )
    require(
        type(max_age_ms) in (int, float)
        and math.isfinite(max_age_ms)
        and 0 < max_age_ms <= 60000,
        "invalid_journal_source_age_limit",
    )
    stability = InputStability(config, max_age_ms)

    def guarded(row):
        if row["index"] < config.get("minimum_observation_index", 0):
            return row, "before_binding_anchor", {}
        reason = None
        nodes = {n["node_id"]: n for n in row["nodes"]}
        require(len(nodes) == len(row["nodes"]), "duplicate_journal_node")
        if row.get("clock_epoch") != config["expected_clock_epoch"]:
            reason = "journal_clock_epoch_changed"
        if row.get("late_interval") is True or row.get("_index_gap") is True:
            reason = reason or "journal_gap"
        uninterrupted = reason is None
        for node in config["node_ids"]:
            entry = nodes.get(node)
            if entry is None or entry.get("available") is not True:
                reason = reason or "feature_node_unavailable"
                stability.interrupt(node, row)
                continue
            if profile_identity(entry) != config["expected_profiles"][str(node)]:
                reason = reason or "profile_binding_changed"
                stability.interrupt(node, row)
                continue
            stability_reason = stability.observe(node, entry, row, uninterrupted)
            reason = reason or stability_reason
        return row, reason, stability.evidence()

    iterator = iter(observations)
    previous_mono = -1

    def advance():
        nonlocal previous_mono
        row = next(iterator, None)
        if row is None:
            return None
        require(row["monotonic_ns"] >= previous_mono, "unordered_journal")
        previous_mono = row["monotonic_ns"]
        return guarded(row)

    pending, last = advance(), None
    output, discarded = [], {}

    def reject(reason):
        discarded[reason] = discarded.get(reason, 0) + 1

    for reference in sorted(
        examples, key=lambda row: row["provenance"]["receipt_monotonic_ns"]
    ):
        provenance = reference["provenance"]
        meta = reference_metadata.get(provenance.get("capture_metadata_sha256"))
        require(
            meta is not None and meta.get("boot_id") == expected_boot,
            "reference_boot_mismatch",
        )
        require(
            sha(reference["feature_contract"])
            == config["reference_feature_contract_sha256"],
            "reference_contract_mismatch",
        )
        require(
            reference.get("quality", {}).get("eligible") is True
            and reference.get("maintenance_excluded") is False,
            "reference_not_verified_eligible",
        )
        target_ns = provenance["receipt_monotonic_ns"]
        while pending is not None and pending[0]["monotonic_ns"] <= target_ns:
            last, pending = pending, advance()
        if last is None:
            reject("no_earlier_feature_observation")
            continue
        row, guard_reason, continuity_evidence = last
        lag = target_ns - row["monotonic_ns"]
        if lag > max_lag_ns:
            reject("feature_observation_too_old")
            continue
        if guard_reason:
            reject(guard_reason)
            continue
        reference_utc_ns = int(timestamp(reference["observed_at_utc"]) * 1e9)
        wall_lag = reference_utc_ns - row["utc_ns"]
        if wall_lag < 0 or abs(wall_lag - lag) > tolerance_ns:
            reject("wall_monotonic_alignment_disagrees")
            continue
        values, node_evidence = {}, {}
        for node in row["nodes"]:
            if node["node_id"] not in config["node_ids"]:
                continue
            for key in config["feature_keys"]:
                value = node.get("features", {}).get(key)
                if type(value) in (int, float) and math.isfinite(value):
                    values[f"node_{node['node_id']}_{key}"] = value
            node_evidence[str(node["node_id"])] = {
                key: copy.deepcopy(node.get(key))
                for key in (
                    "worker",
                    "native_profile_compatible",
                    "receiver_proof",
                    "source_age_ms",
                    "source_time_ns",
                )
            }
        if set(values) != set(contract["features"]):
            reject("required_feature_missing")
            continue
        example = copy.deepcopy(reference)
        example.update(
            example_id=reference["example_id"]
            + f":full:{row['run_id']}:{row['index']}",
            feature_contract=copy.deepcopy(contract),
            features=values,
            interval_start_utc=row["captured_at_utc"],
        )
        example["provenance"].update(
            original_reference_example_id=reference["example_id"],
            original_reference_example_sha256=sha(reference),
            original_reference_interval_start_utc=reference["interval_start_utc"],
            features_semantics="Earlier full-feature observation from a separate shadow journal; binary reference copied unchanged",
            journal_run_id=row["run_id"],
            journal_observation_index=row["index"],
            journal_metadata_sha256=config["journal_metadata_sha256"],
            journal_source=row.get("_source"),
            feature_lag_ns=lag,
            shared_boot_id=expected_boot,
            node_evidence=node_evidence,
            observed_input_recovery=continuity_evidence,
            native_profile_qualified=False,
        )
        output.append(example)
    # Complete every consumed-prefix hash verification before returning output.
    while pending is not None:
        pending = advance()
    return output, {
        "schema": "ruview.shadow-join-export.v1",
        "rows": len(output),
        "discarded": discarded,
        "feature_contract": contract,
        "configuration_sha256": sha(config),
        "observed_input_stability": stability.summary,
        "reference_is_ground_truth": False,
        "recognition_validated": False,
        "publish_to_ha": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--references", required=True, type=Path)
    parser.add_argument("--reference-root", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    for source in (args.references, args.reference_root, args.journal):
        require(
            not args.output.resolve().is_relative_to(source.resolve()),
            "output_must_be_separate",
        )
    config = document(args.config)
    references, metadata, reference_receipt = reference_export(
        args.references, args.reference_root
    )
    observations, journal_meta, prefixes = journal_export(
        args.journal, config["journal_metadata_sha256"]
    )
    examples, receipt = join(references, observations, metadata, journal_meta, config)
    require(prefixes["verification_complete"], "journal_prefix_verification_incomplete")
    receipt.update(
        journal_prefixes=prefixes,
        reference_export_sha256=sha(reference_receipt),
        reference_examples_sha256=reference_receipt["examples_sha256"],
    )
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    payload = b"".join(canonical(row) + b"\n" for row in examples)
    (args.output / "examples.jsonl").write_bytes(payload)
    receipt["examples_sha256"] = hashlib.sha256(payload).hexdigest()
    (args.output / "receipt.json").write_bytes(canonical(receipt) + b"\n")
    print(
        json.dumps(
            {
                "rows": len(examples),
                "discarded": receipt["discarded"],
                "provisional": prefixes["provisional"],
            }
        )
    )


if __name__ == "__main__":
    main()
