"""Offline verification of a bounded raw recording and original worker snapshots.

This verifies recorded evidence, not RF completeness, labels or model accuracy.
It never contacts a worker, seals a live file or manufactures missing snapshots.
"""

import hashlib
import json
import math
import os
import stat
import struct
from collections import Counter

from .pipeline import integer, nonempty, sha, validate_frame

SCHEMA = "ruview.csi.capture_manifest.v1"
MAX_BYTES = 1_000_000_000
MAX_LINE = 16_384
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
IDENTITY = ("worker_run_id", "clock_id", "configuration_sha256")


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite JSON constant: " + value)

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite JSON numeric overflow")
        return result

    return json.loads(
        data,
        object_pairs_hook=pairs,
        parse_constant=constant,
        parse_float=finite_float,
    )


def regular_reader(path):
    """Reject links and writerless FIFOs before reading evidence."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("evidence must be a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def file_bytes(path, maximum):
    with regular_reader(path) as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("evidence file exceeds bound")
    return data


def checked_file(data, expected):
    sha(expected.get("sha256"), "original-file hash")
    integer(expected.get("bytes"), "original-file bytes", 1, MAX_BYTES)
    if (
        len(data) != expected["bytes"]
        or hashlib.sha256(data).hexdigest() != expected["sha256"]
    ):
        raise ValueError("original evidence bytes/hash mismatch")


def validate_manifest(manifest):
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unknown capture manifest schema")
    for key in ("session_id", "worker_run_id", "clock_id", "provenance_reference"):
        nonempty(manifest.get(key), key)
    if manifest["session_id"] != manifest["worker_run_id"]:
        raise ValueError("worker v1 session must equal original run UUID")
    sha(manifest.get("configuration_sha256"), "worker configuration")
    if type(manifest.get("synthetic_only")) is not bool:
        raise ValueError("explicit synthetic classification required")
    nodes = manifest.get("expected_node_ids")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 10:
        raise ValueError("declare 1..10 expected physical node IDs")
    for node in nodes:
        integer(node, "expected node", 1, 16)
    if len(set(nodes)) != len(nodes):
        raise ValueError("duplicate expected node")
    limits = manifest["recording_limits"]
    integer(limits["record_seconds"], "record_seconds", 1, 3600)
    integer(limits["record_max_bytes"], "record_max_bytes", 1024, MAX_BYTES)
    interval = manifest["planned_interval"]
    start = integer(interval["start_utc_ns"], "planned start", 1)
    end = integer(interval["end_utc_ns"], "planned end", start + 1)
    if end - start > limits["record_seconds"] * 1_000_000_000:
        raise ValueError("planned interval exceeds recording duration limit")
    for key in (
        "max_receipt_gap_ns",
        "max_boundary_gap_ns",
        "max_clock_step_ns",
        "max_snapshot_counter_skew_ns",
    ):
        integer(manifest["policy"][key], key, 0, end - start)
    if manifest["policy"]["max_receipt_gap_ns"] == 0:
        raise ValueError("receipt gap policy must be positive")
    for name in ("raw", "opening_snapshot", "closing_snapshot"):
        entry = manifest["files"][name]
        sha(entry["sha256"], "original-file hash")
        integer(entry["bytes"], "original-file bytes", 1, MAX_BYTES)
    if manifest["files"]["raw"]["bytes"] > limits["record_max_bytes"]:
        raise ValueError("raw size exceeds declared recording limit")
    return manifest


def snapshot(path, expected, manifest):
    data = file_bytes(path, 1_048_576)
    checked_file(data, expected)
    value = strict_json(data)
    if (
        value.get("schema") != "ruview.server-modules.v1"
        or value.get("recognition_validated") is not False
        or value.get("monotonic_origin") != "worker_start"
        or any(value.get(key) != manifest[key] for key in IDENTITY)
    ):
        raise ValueError("worker snapshot identity/schema mismatch")
    stamp = value.get("generated_at_ns")
    if not isinstance(stamp, str) or not stamp.isascii() or not stamp.isdecimal():
        raise ValueError("snapshot timestamp must be decimal nanoseconds")
    integer(int(stamp), "snapshot timestamp", 1, 2**64 - 1)
    for key in COUNTERS:
        integer(value["counters"][key], "worker counter", 0, 2**64 - 1)
    return value


def datagram(frame):
    """Reconstruct the original ADR018 bytes, without interpreting pair phase."""
    for key in ("rssi_dbm", "noise_floor_dbm"):
        integer(frame.get(key), key, -128, 127)
    return struct.pack(
        "<IBBHIIbbBB",
        0xC5110001,
        frame["node_id"],
        frame["antennas"],
        frame["subcarriers"],
        frame["frequency_mhz"],
        frame["sequence"],
        frame["rssi_dbm"],
        frame["noise_floor_dbm"],
        frame["ppdu_type"],
        frame["flags"],
    ) + bytes(value & 255 for value in frame["iq"])


def verify_capture(manifest, raw_path, opening_path, closing_path):
    validate_manifest(manifest)
    opening = snapshot(opening_path, manifest["files"]["opening_snapshot"], manifest)
    closing = snapshot(closing_path, manifest["files"]["closing_snapshot"], manifest)
    interval, policy = manifest["planned_interval"], manifest["policy"]
    start, end = interval["start_utc_ns"], interval["end_utc_ns"]
    if (
        not int(opening["generated_at_ns"])
        <= start
        < end
        <= int(closing["generated_at_ns"])
    ):
        raise ValueError("original snapshots must bracket the planned interval")
    before, after = opening["counters"], closing["counters"]
    if any(after[key] < before[key] for key in COUNTERS):
        raise ValueError("worker counters moved backwards")
    findings = Counter()
    nodes = {}
    digest = hashlib.sha256()
    total = count = 0
    opening_receipts = 0
    opening_counter_deadline = (
        int(opening["generated_at_ns"]) + policy["max_snapshot_counter_skew_ns"]
    )
    previous_global = None
    with regular_reader(raw_path) as stream:
        initial = os.fstat(stream.fileno())
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("raw evidence must be a regular file")
        while line := stream.readline(MAX_LINE + 1):
            total += len(line)
            if len(line) > MAX_LINE or total > manifest["files"]["raw"]["bytes"]:
                raise ValueError("raw line/file exceeds declared bound")
            digest.update(line)
            if not line.endswith(b"\n") or not line.strip():
                raise ValueError("blank or unterminated JSONL evidence")
            frame = validate_frame(strict_json(line))
            if frame["schema"] != "ruview.csi.frame.v1":
                raise ValueError(
                    "legacy recording verifier only accepts original v1 frames"
                )
            if (
                frame["session_id"] != manifest["session_id"]
                or frame["clock_id"] != manifest["clock_id"]
                or frame["configuration_sha256"] != manifest["configuration_sha256"]
                or frame["node_id"] not in manifest["expected_node_ids"]
                or frame.get("monotonic_origin") != "worker_start"
                or frame.get("iq_order") != "wire_byte_order"
                or frame.get("source_pair_order") != "esp_idf_imaginary_real"
                or frame.get("worker_phase_convention")
                != "ruview_legacy_atan2_byte1_byte0"
                or frame.get("device_boot_id") is not None
                or frame.get("device_timestamp") is not None
            ):
                raise ValueError("raw frame differs from original worker contract")
            if (
                frame["ppdu_type"] != 0
                or frame["flags"] not in (0, 0x10)
                or frame["frequency_mhz"] not in range(2412, 2473, 5)
                or hashlib.sha256(datagram(frame)).hexdigest()
                != frame.get("raw_datagram_sha256")
            ):
                raise ValueError("raw packet grid or original datagram hash mismatch")
            utc, mono = frame["received_at_ns"], frame["received_monotonic_ns"]
            if utc <= opening_counter_deadline:
                opening_receipts += 1
            if utc > int(closing["generated_at_ns"]):
                findings["frame_after_closing_snapshot"] += 1
            if mono > manifest["recording_limits"]["record_seconds"] * 1_000_000_000:
                findings["recording_duration_limit_exceeded"] += 1
            if previous_global:
                old_utc, old_mono = previous_global
                if mono <= old_mono or utc <= old_utc:
                    findings["nonmonotonic_receipt"] += 1
                if (
                    abs((utc - old_utc) - (mono - old_mono))
                    > policy["max_clock_step_ns"]
                ):
                    findings["receipt_clock_discontinuity"] += 1
            previous_global = utc, mono
            node = nodes.setdefault(
                frame["node_id"],
                {
                    "frames": 0,
                    "first_utc_ns": utc,
                    "last_utc_ns": utc,
                    "first_monotonic_ns": mono,
                    "last_monotonic_ns": mono,
                    "first_sequence": frame["sequence"],
                    "last_sequence": frame["sequence"],
                    "frequency_mhz": frame["frequency_mhz"],
                    "max_receipt_gap_ns": 0,
                },
            )
            if node["frames"]:
                if (frame["sequence"] - node["last_sequence"]) % 2**32 != 1:
                    findings["sequence_gap_duplicate_or_reset"] += 1
                gap = mono - node["last_monotonic_ns"]
                node["max_receipt_gap_ns"] = max(node["max_receipt_gap_ns"], gap)
                if gap > policy["max_receipt_gap_ns"]:
                    findings["receipt_gap"] += 1
                if frame["frequency_mhz"] != node["frequency_mhz"]:
                    findings["radio_grid_changed"] += 1
            node.update(
                last_utc_ns=utc, last_monotonic_ns=mono, last_sequence=frame["sequence"]
            )
            node["frames"] += 1
            count += 1
        final = os.fstat(stream.fileno())
    if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    ):
        raise ValueError("raw evidence changed while being read")
    if (
        total != manifest["files"]["raw"]["bytes"]
        or digest.hexdigest() != manifest["files"]["raw"]["sha256"]
    ):
        raise ValueError("original raw bytes/hash mismatch")
    if not count:
        findings["no_frames"] += 1
    # HTTP stamps the response before reading independent atomic counters.
    # Writes may lag receipts; they cannot precede them beyond declared skew.
    if before["record_written"] > opening_receipts:
        findings["opening_written_exceeds_receipt_prefix"] += 1
    # Rejected packets have no raw row. Use all final rejections as a loose
    # upper bound rather than pretending their individual receipt times exist.
    if before["received"] > (
        opening_receipts + after["rejected"] + after["source_rejected"]
    ):
        findings["opening_received_exceeds_receipt_upper_bound"] += 1
    for node_id in manifest["expected_node_ids"]:
        node = nodes.get(node_id)
        if not node:
            findings["expected_node_missing"] += 1
        elif (
            node["first_utc_ns"] > start + policy["max_boundary_gap_ns"]
            or node["last_utc_ns"] < end - policy["max_boundary_gap_ns"]
        ):
            findings["planned_interval_not_covered"] += 1
    if after["record_written"] != count:
        findings["record_written_count_mismatch"] += 1
    admitted = after["received"] - after["rejected"] - after["source_rejected"]
    if admitted != count:
        findings["admitted_packet_count_mismatch"] += 1
    for key in (
        "queue_dropped",
        "record_dropped",
        "record_error",
        "record_limit_reached",
    ):
        if after[key]:
            findings[key] = after[key]
    return {
        "schema": "ruview.csi.capture_verification.v1",
        "synthetic_only": manifest["synthetic_only"],
        "synthetic_classification_basis": "operator_manifest_declaration",
        "original_file_integrity": "verified",
        "recording_complete": not findings,
        "scope": "recorded admitted packets and declared interval, not lossless RF capture",
        "findings": dict(findings),
        "frames": count,
        "nodes": [{"node_id": key, **value} for key, value in sorted(nodes.items())],
        "session_id": manifest["session_id"],
        **{key: manifest[key] for key in IDENTITY},
        "original_files": manifest["files"],
        "recording_limits": manifest["recording_limits"],
        "recording_limits_basis": "operator_declaration_not_reported_by_worker",
        "planned_interval": interval,
        "policy": policy,
        "opening_counters": before,
        "closing_counters": after,
        "opening_receipt_prefix_frames": opening_receipts,
        "snapshot_counter_timing_basis": "upper_bounds_with_declared_skew_not_atomic_snapshots",
        "worker_file_closed_verified": False,
        "cross_host_alignment_verified": False,
        "recognition_validated": False,
        "publish_to_ha": False,
    }
