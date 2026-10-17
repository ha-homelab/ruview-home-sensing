"""Bind offline pairing to original capture evidence, without qualifying a model."""

import hashlib
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .capture import (
    checked_file,
    file_bytes,
    regular_reader,
    strict_json,
    validate_manifest,
    verify_capture,
)
from .pipeline import digest, integer, nonempty, sha

SCHEMA = "ruview.csi.pair_capture_evidence.v1"
UNVERIFIED = {"schema": SCHEMA, "status": "unverified_research"}
HASH_FIELDS = (
    "manifest_sha256",
    "verification_report_sha256",
    "raw_sha256",
    "opening_snapshot_sha256",
    "closing_snapshot_sha256",
    "configuration_sha256",
)
SCHEMA_V2 = "ruview.csi.pair_capture_evidence.v2"
VERIFIED_MODES = {"verified_recording", "verified_closed_capture"}


def validate_session_evidence(value, window=None):
    from .capture_session import IDENTITY, boundary, require
    from .pipeline import validate_capture_identity

    fields = {
        "schema",
        "status",
        "synthetic_only",
        "expected_node_ids",
        "manifest_sha256",
        "verification_report_sha256",
        "raw_sha256",
        "opening_sha256",
        "terminal_sha256",
        "start_boundary",
        "end_boundary",
    } | set(IDENTITY)
    require(
        set(value) == fields and value.get("status") == "verified_closed_capture",
        "invalid v2 capture evidence",
    )
    validate_capture_identity(value)
    for key in fields:
        if key.endswith("sha256"):
            sha(value[key], key)
    require(
        type(value["synthetic_only"]) is bool,
        "explicit synthetic classification required",
    )
    nodes = value["expected_node_ids"]
    require(isinstance(nodes, list) and 1 <= len(nodes) <= 10, "invalid v2 node scope")
    for node in nodes:
        integer(node, "verified capture node", 1, 16)
    require(nodes == sorted(set(nodes)), "verified nodes must be sorted and unique")
    start, end = boundary(value["start_boundary"]), boundary(value["end_boundary"])
    require(
        start["clock"]["monotonic_ns"] <= end["clock"]["monotonic_ns"]
        and start["clock"]["utc_ns"] < end["clock"]["utc_ns"]
        and start["ingress_sequence"] <= end["ingress_sequence"],
        "invalid verified capture boundaries",
    )
    if window is not None:
        require(
            window.get("schema") == "ruview.csi.window.v2"
            and all(window.get(k) == value[k] for k in IDENTITY)
            and window["node_id"] in nodes,
            "window differs from closed capture identity",
        )
        for key, axis in (
            ("timestamps_ns", "utc_ns"),
            ("monotonic_ns", "monotonic_ns"),
        ):
            require(
                start["clock"][axis]
                <= window[key][0]
                <= window[key][-1]
                <= end["clock"][axis],
                "window outside verified capture bounds",
            )
        require(
            start["ingress_sequence"]
            < window["ingress_sequences"][0]
            <= window["ingress_sequences"][-1]
            <= end["ingress_sequence"],
            "window outside capture ingress bounds",
        )
    return value


def validate_evidence(value, window=None):
    """Validate retained lineage; this cannot authenticate caller-edited records."""
    if value is None:
        value = dict(UNVERIFIED)  # Legacy research records never gain verification.
    if value.get("schema") == SCHEMA_V2:
        return validate_session_evidence(value, window)
    if value.get("schema") != SCHEMA:
        raise ValueError("unknown paired capture evidence schema")
    if value.get("status") == "unverified_research":
        if value != UNVERIFIED:
            raise ValueError("unverified evidence cannot carry verification claims")
        return value
    if value.get("status") != "verified_recording":
        raise ValueError("unknown capture verification mode")
    if window is not None and window.get("schema") == "ruview.csi.window.v2":
        raise ValueError("v1 recording evidence cannot verify a v2 capture")
    if set(value) != set(HASH_FIELDS) | {
        "schema",
        "status",
        "session_id",
        "clock_id",
        "synthetic_only",
        "expected_node_ids",
        "planned_interval",
    }:
        raise ValueError("unexpected verified capture evidence fields")
    for key in HASH_FIELDS:
        sha(value.get(key), key)
    for key in ("session_id", "clock_id"):
        nonempty(value.get(key), key)
    if type(value.get("synthetic_only")) is not bool:
        raise ValueError("capture synthetic classification must remain explicit")
    nodes = value.get("expected_node_ids")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 10:
        raise ValueError("invalid verified node scope")
    for node in nodes:
        integer(node, "verified node", 1, 16)
    if nodes != sorted(set(nodes)):
        raise ValueError("verified nodes must be unique and sorted")
    interval = value["planned_interval"]
    if set(interval) != {"start_utc_ns", "end_utc_ns"}:
        raise ValueError("unexpected capture interval fields")
    start = integer(interval["start_utc_ns"], "capture interval start", 1)
    end = integer(interval["end_utc_ns"], "capture interval end", start + 1)
    if window is not None and (
        any(
            value[key] != window[key]
            for key in ("session_id", "clock_id", "configuration_sha256")
        )
        or window["node_id"] not in nodes
        or not start <= window["timestamps_ns"][0] <= window["timestamps_ns"][-1] <= end
    ):
        raise ValueError("window differs from verified capture scope")
    return value


def capture_lineage(records):
    modes = set()
    classifications = set()
    recordings = {}
    for record in records:
        evidence = validate_evidence(record.get("capture_evidence"), record["window"])
        modes.add(evidence["status"])
        if evidence["status"] in VERIFIED_MODES:
            classifications.add(evidence["synthetic_only"])
            session = evidence["session_id"]
            if session in recordings and digest(recordings[session]) != digest(
                evidence
            ):
                raise ValueError("one session has conflicting capture evidence")
            recordings[session] = evidence
    if len(modes) != 1:
        raise ValueError("cannot mix verified and unverified capture modes")
    if len(classifications) > 1:
        raise ValueError("cannot mix synthetic and household capture classifications")
    mode = modes.pop()
    return {
        "schema": "ruview.csi.capture_lineage.v2"
        if mode == "verified_closed_capture"
        else "ruview.csi.capture_lineage.v1",
        "status": mode,
        "recordings": [recordings[key] for key in sorted(recordings)],
    }


def validate_lineage(value, sessions, identity):
    if value is None:
        value = {
            "schema": "ruview.csi.capture_lineage.v1",
            "status": "unverified_research",
            "recordings": [],
        }
    expected_schema = (
        "ruview.csi.capture_lineage.v2"
        if value.get("status") == "verified_closed_capture"
        else "ruview.csi.capture_lineage.v1"
    )
    if value.get("schema") != expected_schema:
        raise ValueError("unknown checkpoint capture lineage")
    if set(value) != {"schema", "status", "recordings"}:
        raise ValueError("unexpected checkpoint capture lineage fields")
    recordings = value.get("recordings")
    if not isinstance(recordings, list):
        raise ValueError("invalid checkpoint capture recordings")
    if value.get("status") == "unverified_research":
        if recordings:
            raise ValueError("unverified checkpoint has verified recordings")
    elif value.get("status") in VERIFIED_MODES:
        if (value["status"] == "verified_closed_capture") != (
            identity.get("source_frame_schema") == "ruview.csi.frame.v2"
        ):
            raise ValueError(
                "checkpoint source frame schema differs from verified capture mode"
            )
        seen = set()
        classifications = set()
        for evidence in recordings:
            validate_evidence(evidence)
            if (
                evidence["status"] != value["status"]
                or evidence["session_id"] in seen
                or identity["node_id"] not in evidence["expected_node_ids"]
                or identity["configuration_sha256"] != evidence["configuration_sha256"]
            ):
                raise ValueError("checkpoint capture lineage differs from input")
            seen.add(evidence["session_id"])
            classifications.add(evidence["synthetic_only"])
        if seen != sessions:
            raise ValueError("checkpoint capture sessions differ from train/evaluation")
        if len(classifications) != 1:
            raise ValueError("checkpoint mixes capture classifications")
    else:
        raise ValueError("unknown checkpoint capture mode")
    return value


def _copy_raw(source, destination, expected):
    """Private bounded byte copy prevents verification/use path replacement."""
    size = 0
    checksum = hashlib.sha256()
    with (
        regular_reader(source) as src,
        os.fdopen(
            os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as out,
    ):
        if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
            raise ValueError("raw evidence must be a regular file")
        while chunk := src.read(min(65536, expected["bytes"] - size + 1)):
            size += len(chunk)
            if size > expected["bytes"]:
                raise ValueError("raw copy exceeds manifest bound")
            checksum.update(chunk)
            out.write(chunk)
    if size != expected["bytes"] or checksum.hexdigest() != expected["sha256"]:
        raise ValueError("original raw copy hash/size mismatch")


@contextmanager
def verified_recording(frames, manifest_path, report_path, opening, closing, node_ids):
    """Recheck exact original evidence, then yield a private stable raw copy."""
    manifest_bytes = file_bytes(manifest_path, 1_048_576)
    manifest = validate_manifest(strict_json(manifest_bytes))
    report_bytes = file_bytes(report_path, 1_048_576)
    report = strict_json(report_bytes)
    if sorted(node_ids) != sorted(manifest["expected_node_ids"]):
        raise ValueError("commissioning profiles differ from verified node coverage")
    with tempfile.TemporaryDirectory(prefix="ruview-verified-pair-") as directory:
        root = Path(directory)
        raw_copy = root / "raw.jsonl"
        _copy_raw(frames, raw_copy, manifest["files"]["raw"])
        for name, source in (
            ("opening_snapshot", opening),
            ("closing_snapshot", closing),
        ):
            data = file_bytes(source, 1_048_576)
            checked_file(data, manifest["files"][name])
            with os.fdopen(
                os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as out:
                out.write(data)
        checked = verify_capture(
            manifest, raw_copy, root / "opening_snapshot", root / "closing_snapshot"
        )
        checked["manifest_original_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        if checked["recording_complete"] is not True:
            raise ValueError("capture evidence does not establish recording completion")
        if digest(report) != digest(checked):
            raise ValueError("capture report differs from recomputed original evidence")
        evidence = {
            "schema": SCHEMA,
            "status": "verified_recording",
            "manifest_sha256": checked["manifest_original_sha256"],
            "verification_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            **{
                key + "_sha256": manifest["files"][key]["sha256"]
                for key in ("raw", "opening_snapshot", "closing_snapshot")
            },
            **{
                key: manifest[key]
                for key in (
                    "session_id",
                    "clock_id",
                    "configuration_sha256",
                    "planned_interval",
                    "synthetic_only",
                )
            },
            "expected_node_ids": sorted(manifest["expected_node_ids"]),
        }
        validate_evidence(evidence)
        yield raw_copy, evidence
