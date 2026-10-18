"""Bind independent annotation UTC to a capture using actual bracket probes.

Two probes cannot prove clock behavior between them. The explicit reviewed
between-probe allowance remains an assumption, never measured calibration.
"""

import copy
import hashlib

from scripts.reference_clock import (
    Assessment,
    clock_delta,
    validate_identity,
    validate_ready,
)

from .capture import strict_json
from .capture_session import IDENTITY, require
from .pipeline import digest, integer, nonempty, sha, validate_label

SCHEMA = "ruview.reference_alignment.v1"


def probe(raw):
    require(len(raw) <= 1_048_576, "clock report exceeds bound")
    report = strict_json(raw)
    require(
        report.get("schema") == "ruview.reference_clock.measurement.v1"
        and report.get("passed") is True
        and report.get("read_only") is True
        and report.get("calibration_applied") is False
        and report.get("clocks_between_probes_verified") is False
        and report.get("ssh_process_cleaned_up") is True,
        "successful original read-only clock report required",
    )
    validate_identity(report["local_identity"])
    validate_identity(report["remote_identity"])
    require(
        report.get("local_monotonic_domain") == "python_time_monotonic_local_host"
        and report.get("remote_monotonic_domain")
        == "python_time_monotonic_linux_host_not_worker_start",
        "clock domains changed",
    )
    samples = report["samples"]
    require(
        isinstance(samples, list) and 2 <= len(samples) <= 64,
        "invalid probe sample count",
    )
    integer(report["accepted_samples"], "accepted probe samples", 2, 64)
    integer(report["settings"]["samples"], "requested probe samples", 2, 64)
    require(
        len(samples) == report["accepted_samples"] == report["settings"]["samples"],
        "partial clock probe cannot establish brackets",
    )
    assessment = Assessment(
        integer(report["settings"]["max_clock_step_ms"], "probe clock policy", 1, 1000)
        * 1_000_000
    )
    for index, sample in enumerate(samples):
        require(
            type(sample.get("index")) is int
            and sample["index"] == index
            and sample.get("passed") is True,
            "probe sample order/result changed",
        )
        checked = copy.deepcopy(sample)
        assessment.push(checked)
        require(
            digest(checked) == digest(sample),
            "saved clock sample differs from original exchange recomputation",
        )
    summary = assessment.finish()
    require(
        all(digest(report[key]) == digest(value) for key, value in summary.items()),
        "saved probe summary differs from samples",
    )
    ready = report["readiness"]
    validate_ready(ready["remote"])
    require(
        ready.get("passed") is True
        and ready["remote"]["identity"] == report["remote_identity"],
        "probe readiness identity mismatch",
    )
    return report


def make_alignment(
    before_raw, after_raw, evidence, *, between_probe_allowance_ns, assumption_reference
):
    from .evidence import validate_evidence

    validate_evidence(evidence)
    require(
        evidence["status"] == "verified_closed_capture",
        "alignment requires a closed v2 capture",
    )
    allowance = integer(
        between_probe_allowance_ns, "explicit between-probe allowance", 1, 1_000_000_000
    )
    nonempty(assumption_reference, "reviewed between-probe assumption reference")
    before, after = probe(before_raw), probe(after_raw)
    require(
        before["local_identity"] == after["local_identity"]
        and before["remote_identity"] == after["remote_identity"],
        "host or boot changed across reference probes",
    )
    require(
        evidence["clock_id"]
        == before["remote_identity"]["boot_id"] + "/" + evidence["worker_run_id"],
        "probe did not observe capture worker host boot",
    )
    left, right = before["samples"][-1], after["samples"][0]
    start = evidence["start_boundary"]["clock"]["utc_ns"]
    end = evidence["end_boundary"]["clock"]["utc_ns"]
    require(
        left["remote"]["stamp"]["utc_after_ns"]
        <= start
        < end
        <= right["remote"]["stamp"]["utc_before_ns"],
        "clock probes must bracket the complete original capture",
    )
    # These are same-host monotonic comparisons. Worker-relative mono never
    # appears in these subtractions.
    clock_delta(left["local_receive"], right["local_send"], allowance)
    clock_delta(left["remote"]["stamp"], right["remote"]["stamp"], allowance)
    lower = (
        min(
            before["observed_offset_envelope_ns"]["lower"],
            after["observed_offset_envelope_ns"]["lower"],
        )
        - allowance
    )
    upper = (
        max(
            before["observed_offset_envelope_ns"]["upper"],
            after["observed_offset_envelope_ns"]["upper"],
        )
        + allowance
    )
    midpoint = (lower + upper) // 2
    result = {
        "schema": SCHEMA,
        **{key: evidence[key] for key in IDENTITY},
        "opening_sha256": evidence["opening_sha256"],
        "terminal_sha256": evidence["terminal_sha256"],
        "before_report_sha256": hashlib.sha256(before_raw).hexdigest(),
        "after_report_sha256": hashlib.sha256(after_raw).hexdigest(),
        "label_clock": before["local_identity"],
        "receiver_host_clock": before["remote_identity"],
        "label_interval_ns": {
            "start": left["local_receive"]["utc_after_ns"],
            "end": right["local_send"]["utc_before_ns"],
        },
        "receiver_interval_ns": {"start": start, "end": end},
        "offset_bounds_ns": {"lower": lower, "upper": upper},
        "label_to_csi_clock_offset_ns": midpoint,
        "clock_uncertainty_ns": max(midpoint - lower, upper - midpoint),
        "between_probe_allowance_ns": allowance,
        "assumption_reference": assumption_reference,
        "clocks_between_probes_verified": False,
        "calibration_applied": False,
        "method": "measured_brackets_with_declared_between_probe_allowance",
    }
    result["alignment_sha256"] = digest(result)
    validate_alignment(result, evidence)
    return result


def validate_alignment(value, evidence):
    require(
        value.get("schema") == SCHEMA
        and value.get("method")
        == "measured_brackets_with_declared_between_probe_allowance"
        and value.get("clocks_between_probes_verified") is False
        and value.get("calibration_applied") is False,
        "unsupported reference alignment claim",
    )
    require(
        value.get("alignment_sha256")
        == digest({k: v for k, v in value.items() if k != "alignment_sha256"}),
        "changed reference alignment",
    )
    for key in IDENTITY + ("opening_sha256", "terminal_sha256"):
        require(
            value.get(key) == evidence.get(key), "alignment/capture identity mismatch"
        )
    for key in ("before_report_sha256", "after_report_sha256"):
        sha(value.get(key), key)
    validate_identity(value["label_clock"])
    validate_identity(value["receiver_host_clock"])
    require(
        value["clock_id"]
        == value["receiver_host_clock"]["boot_id"] + "/" + value["worker_run_id"],
        "alignment clock domain mismatch",
    )
    for key in ("label_interval_ns", "receiver_interval_ns"):
        interval = value[key]
        require(set(interval) == {"start", "end"}, "invalid alignment interval")
        integer(interval["start"], "interval start", 1)
        integer(interval["end"], "interval end", interval["start"] + 1)
    require(
        value["receiver_interval_ns"]
        == {
            "start": evidence["start_boundary"]["clock"]["utc_ns"],
            "end": evidence["end_boundary"]["clock"]["utc_ns"],
        },
        "alignment receiver scope changed",
    )
    bounds = value["offset_bounds_ns"]
    require(
        set(bounds) == {"lower", "upper"}
        and type(bounds["lower"]) is int
        and type(bounds["upper"]) is int
        and bounds["lower"] <= bounds["upper"],
        "invalid signed offset interval",
    )
    midpoint = (bounds["lower"] + bounds["upper"]) // 2
    require(
        type(value["label_to_csi_clock_offset_ns"]) is int
        and value["label_to_csi_clock_offset_ns"] == midpoint,
        "changed alignment midpoint",
    )
    radius = integer(value["clock_uncertainty_ns"], "alignment uncertainty", 1)
    require(
        radius == max(midpoint - bounds["lower"], bounds["upper"] - midpoint),
        "changed clock uncertainty",
    )
    allowance = integer(
        value["between_probe_allowance_ns"], "between-probe allowance", 1, 1_000_000_000
    )
    require(radius >= allowance, "uncertainty omits explicit between-probe allowance")
    nonempty(value["assumption_reference"], "between-probe assumption reference")
    return value


def align_label(original, alignment, evidence, *, expected_coordinate_frame=None):
    validate_alignment(alignment, evidence)
    validate_label(original, expected_coordinate_frame=expected_coordinate_frame)
    require(
        original["schema"] == "ruview.ground_truth.v2"
        and all(original.get(key) == evidence[key] for key in IDENTITY),
        "annotation/capture identity mismatch",
    )
    lineage = original["reference_lineage"]
    require(
        lineage.get("clock_offset_applied") is False
        and lineage.get("label_clock") == alignment["label_clock"]
        and lineage.get("opening_sha256") == evidence["opening_sha256"],
        "annotation source clock/opening changed",
    )
    for key in ("metadata_sha256", "review_sha256"):
        sha(lineage.get(key), "reference " + key)
    interval = alignment["label_interval_ns"]
    require(
        interval["start"]
        <= original["start_ns"]
        < original["end_ns"]
        <= interval["end"],
        "annotation lies outside measured clock brackets",
    )
    adjusted = copy.deepcopy(original)
    adjusted["time_uncertainty_ns"] += alignment["clock_uncertainty_ns"]
    return adjusted


def validate_paired_alignment(record, *, expected_coordinate_frame=None):
    """Recheck retained timing arithmetic; hashes do not authenticate edited files."""
    evidence = record["capture_evidence"]
    alignment = record["time_alignment"]
    adjusted = align_label(
        record["original_label"],
        alignment,
        evidence,
        expected_coordinate_frame=expected_coordinate_frame,
    )
    require(
        digest(adjusted) == digest(record["label"]),
        "paired annotation dropped original or clock uncertainty",
    )
    require(
        record["alignment"]["label_to_csi_clock_offset_ns"]
        == alignment["label_to_csi_clock_offset_ns"],
        "paired label offset differs from measured bracket",
    )
    return record
