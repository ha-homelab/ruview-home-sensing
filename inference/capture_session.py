"""Verify original closed v2 captures. Closure is not lossless RF or ground truth."""

import hashlib
import os
import stat
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from .capture import (
    MAX_LINE,
    checked_file,
    datagram,
    file_bytes,
    regular_reader,
    strict_json,
)
from .pipeline import (
    digest,
    integer,
    nonempty,
    sha,
    validate_capture_identity,
    validate_frame,
)

MANIFEST = "ruview.csi.capture_manifest.v2"
EVIDENCE = "ruview.csi.pair_capture_evidence.v2"
REPORT = "ruview.csi.capture_verification.v2"
IDENTITY = (
    "session_id",
    "capture_id",
    "worker_run_id",
    "clock_id",
    "configuration_sha256",
)
COUNTERS = (
    "admitted",
    "enqueued",
    "written",
    "queue_dropped",
    "writer_disconnected",
    "write_errors",
    "byte_limit_rejected",
)
U64 = 2**64 - 1
MAX_SESSION_BYTES = 100 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def clock(value):
    require(
        isinstance(value, dict) and set(value) == {"utc_ns", "monotonic_ns"},
        "invalid capture clock",
    )
    integer(value["utc_ns"], "capture UTC", 1, U64)
    integer(value["monotonic_ns"], "capture monotonic", 0, U64)
    return value


def boundary(value):
    require(
        isinstance(value, dict) and set(value) == {"clock", "ingress_sequence"},
        "invalid capture boundary",
    )
    clock(value["clock"])
    integer(value["ingress_sequence"], "boundary ingress sequence", 0, U64)
    return value


def validate_opening(value):
    require(
        value.get("schema") == "ruview.capture.opening.v2",
        "expected original capture opening v2",
    )
    validate_capture_identity(value)
    sha(value.get("configuration_sha256"), "capture configuration")
    require(
        value["clock_id"].endswith("/" + value["worker_run_id"]),
        "clock/run identity mismatch",
    )
    require(
        value.get("frame_schema") == "ruview.csi.frame.v2"
        and value.get("source") == "esp32"
        and value.get("execution") == "server"
        and value.get("recognition_validated") is False,
        "unsupported capture source",
    )
    nodes = value.get("node_ids")
    require(
        isinstance(nodes, list) and 1 <= len(nodes) <= 10, "invalid capture node scope"
    )
    for node in nodes:
        integer(node, "capture node", 1, 16)
    require(nodes == sorted(set(nodes)), "capture nodes must be sorted and unique")
    limits = value["limits"]
    require(set(limits) == {"duration_ms", "max_bytes"}, "invalid capture limits")
    integer(limits["duration_ms"], "capture duration", 1, 3_600_000)
    integer(limits["max_bytes"], "capture byte limit", 1024, MAX_SESSION_BYTES)
    boundary(value["start_boundary"])
    start = value["start_boundary"]["clock"]["monotonic_ns"]
    origin = clock(value["worker_start_clock"])
    require(
        origin["monotonic_ns"] <= start,
        "worker initial clock must precede capture start",
    )
    integer(value["deadline_monotonic_ns"], "capture deadline", 1, U64)
    require(
        value["deadline_monotonic_ns"] == start + limits["duration_ms"] * 1_000_000,
        "capture deadline differs from original limits",
    )
    require(value["raw_file"] == "raw.jsonl", "unsupported raw basename")
    return value


def validate_manifest(value):
    require(value.get("schema") == MANIFEST, "unknown v2 manifest schema")
    validate_capture_identity(value)
    sha(value.get("configuration_sha256"), "manifest configuration")
    nonempty(value.get("provenance_reference"), "manifest provenance")
    require(
        type(value.get("synthetic_only")) is bool,
        "explicit synthetic classification required",
    )
    policy = value["policy"]
    require(
        set(policy) == {"max_clock_step_ns", "max_receipt_gap_ns"},
        "unknown v2 observation policy",
    )
    integer(policy["max_clock_step_ns"], "clock-step policy", 0, 1_000_000_000)
    integer(
        policy["max_receipt_gap_ns"], "gap observation policy", 1, 3_600_000_000_000
    )
    require(
        set(value["files"]) == {"raw", "opening", "terminal"},
        "original capture file set required",
    )
    for name, item in value["files"].items():
        require(set(item) == {"bytes", "sha256"}, "unexpected original-file fields")
        integer(
            item["bytes"],
            "original-file size",
            0 if name == "raw" else 1,
            MAX_SESSION_BYTES if name == "raw" else 1_048_576,
        )
        sha(item["sha256"], "original-file hash")
    return value


def _document(path, expected):
    raw = file_bytes(path, 1_048_576)
    checked_file(raw, expected)
    return strict_json(raw), raw


def verify_session(manifest, frames, opening_path, terminal_path):
    """Recompute bounded byte/counter/barrier evidence; report radio discontinuities."""
    validate_manifest(manifest)
    opening, opening_raw = _document(opening_path, manifest["files"]["opening"])
    terminal, _ = _document(terminal_path, manifest["files"]["terminal"])
    validate_opening(opening)
    require(
        terminal.get("schema") == "ruview.capture.terminal.v2",
        "original terminal receipt required",
    )
    # Validate types before comparing: Python True == 1 is not evidence equality.
    validate_opening({**opening, **terminal, "schema": "ruview.capture.opening.v2"})
    for key in IDENTITY:
        require(
            opening.get(key) == terminal.get(key) == manifest.get(key),
            "capture identity mismatch",
        )
    for key in (
        "worker_start_clock",
        "frame_schema",
        "node_ids",
        "limits",
        "start_boundary",
        "deadline_monotonic_ns",
    ):
        require(
            opening.get(key) == terminal.get(key), "opening/terminal contract mismatch"
        )
    require(
        hashlib.sha256(opening_raw).hexdigest() == terminal["opening_sha256"],
        "terminal does not bind original opening",
    )
    start, end = opening["start_boundary"], boundary(terminal["end_boundary"])
    begin, finish = start["clock"], end["clock"]
    written_clock = clock(terminal["writer_finished_clock"])
    require(
        begin["monotonic_ns"] <= finish["monotonic_ns"]
        and begin["monotonic_ns"] <= written_clock["monotonic_ns"],
        "invalid monotonic closure boundaries",
    )
    require(
        start["ingress_sequence"] <= end["ingress_sequence"],
        "ingress boundary moved backwards",
    )
    counters = terminal["counters"]
    require(set(counters) == set(COUNTERS), "unexpected capture counters")
    for key in COUNTERS:
        integer(counters[key], key, 0, U64)
    require(
        counters["admitted"]
        == counters["enqueued"]
        + counters["queue_dropped"]
        + counters["writer_disconnected"],
        "capture admission accounting mismatch",
    )
    require(
        counters["written"] <= counters["enqueued"] <= counters["admitted"],
        "capture writer accounting mismatch",
    )
    raw = terminal["raw"]
    require(raw.get("file") == "raw.jsonl", "invalid terminal raw file")
    integer(raw.get("bytes"), "terminal raw bytes", 0, MAX_SESSION_BYTES)
    sha(raw.get("sha256"), "terminal raw hash")
    for key in ("bytes", "sha256"):
        require(
            raw.get(key) == manifest["files"]["raw"][key],
            "terminal/manifest raw mismatch",
        )
    require(
        raw["bytes"] <= opening["limits"]["max_bytes"],
        "capture exceeds requested byte bound",
    )
    integer(raw.get("frames"), "raw frames", 0, U64)
    require(raw["frames"] == counters["written"], "raw/writer count mismatch")
    require(
        type(terminal.get("complete")) is bool
        and isinstance(terminal.get("failures"), list),
        "invalid terminal result",
    )
    findings = Counter()
    observations = Counter()
    if terminal["complete"] is not True:
        findings["worker_reported_incomplete"] += 1
    if written_clock["monotonic_ns"] < finish["monotonic_ns"]:
        findings["writer_closed_before_stop_barrier"] += 1
    if terminal.get("end_reason") not in ("manual_stop", "duration_elapsed"):
        findings["unclean_end_reason"] += 1
    if raw.get("fsynced") is not True or raw.get("closed") is not True:
        findings["raw_not_durably_closed"] += 1
    if (
        terminal["failures"]
        or any(counters[k] for k in COUNTERS[3:])
        or counters["admitted"] != counters["written"]
    ):
        findings["capture_writer_loss_or_error"] += 1
    if (
        terminal.get("end_reason") == "duration_elapsed"
        and finish["monotonic_ns"] < opening["deadline_monotonic_ns"]
    ):
        findings["duration_closed_early"] += 1
    nodes = {
        node: {
            "node_id": node,
            "frames": 0,
            "sequence_discontinuities": 0,
            "receipt_gaps": 0,
            "max_receipt_gap_ns": 0,
        }
        for node in opening["node_ids"]
    }
    previous_nodes = {}
    previous = begin
    previous_ingress = start["ingress_sequence"]
    previous_capture = 0
    total = count = 0
    checksum = hashlib.sha256()
    with regular_reader(frames) as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode), "raw must be a regular file")
        while line := stream.readline(MAX_LINE + 1):
            total += len(line)
            require(
                len(line) <= MAX_LINE and total <= raw["bytes"],
                "raw exceeds declared bound",
            )
            require(
                line.endswith(b"\n") and line.strip(),
                "blank or unterminated raw evidence",
            )
            checksum.update(line)
            frame = validate_frame(strict_json(line))
            require(
                frame["schema"] == "ruview.csi.frame.v2"
                and all(frame.get(k) == opening[k] for k in IDENTITY),
                "frame/capture identity mismatch",
            )
            node = frame["node_id"]
            require(node in nodes, "frame outside selected nodes")
            require(
                frame.get("monotonic_origin") == "worker_start"
                and frame.get("iq_order") == "wire_byte_order"
                and frame.get("source_pair_order") == "esp_idf_imaginary_real"
                and frame.get("worker_phase_convention")
                == "ruview_legacy_atan2_byte1_byte0"
                and frame.get("device_boot_id") is None
                and frame.get("device_timestamp") is None,
                "raw frame changed native clock/pair contract",
            )
            packet = datagram(frame)
            require(
                frame["ppdu_type"] == 0
                and frame["flags"] in (0, 0x10)
                and frame["frequency_mhz"] in range(2412, 2473, 5),
                "unsupported native grid",
            )
            require(
                frame.get("raw_datagram_hex") == packet.hex()
                and frame.get("raw_datagram_sha256")
                == hashlib.sha256(packet).hexdigest(),
                "raw datagram reconstruction mismatch",
            )
            current = {
                "utc_ns": frame["received_at_ns"],
                "monotonic_ns": frame["received_monotonic_ns"],
            }
            clock(current)
            require(
                current["monotonic_ns"] <= written_clock["monotonic_ns"],
                "written frame received after writer closed",
            )
            require(
                previous_ingress < frame["ingress_sequence"] <= end["ingress_sequence"],
                "raw ingress outside barrier/order",
            )
            require(
                previous_capture < frame["capture_sequence"] <= counters["admitted"],
                "raw capture admission ordinal invalid",
            )
            if frame["capture_sequence"] != previous_capture + 1:
                findings["missing_capture_admission"] += 1
            require(
                begin["monotonic_ns"]
                <= current["monotonic_ns"]
                <= finish["monotonic_ns"]
                and current["monotonic_ns"] < opening["deadline_monotonic_ns"],
                "raw outside capture time boundaries",
            )
            require(
                current["monotonic_ns"] >= previous["monotonic_ns"],
                "raw monotonic order changed",
            )
            if (
                abs(
                    (current["utc_ns"] - previous["utc_ns"])
                    - (current["monotonic_ns"] - previous["monotonic_ns"])
                )
                > manifest["policy"]["max_clock_step_ns"]
            ):
                observations["worker_clock_discontinuities"] += 1
            stats = nodes[node]
            if node in previous_nodes:
                old = previous_nodes[node]
                gap = current["monotonic_ns"] - old["received_monotonic_ns"]
                stats["max_receipt_gap_ns"] = max(stats["max_receipt_gap_ns"], gap)
                stats["receipt_gaps"] += int(
                    gap > manifest["policy"]["max_receipt_gap_ns"]
                )
                stats["sequence_discontinuities"] += int(
                    (frame["sequence"] - old["sequence"]) % 2**32 != 1
                )
            else:
                stats["first_received_at_ns"] = current["utc_ns"]
            stats["last_received_at_ns"] = current["utc_ns"]
            stats["frames"] += 1
            previous_nodes[node] = frame
            previous, previous_ingress, previous_capture = (
                current,
                frame["ingress_sequence"],
                frame["capture_sequence"],
            )
            count += 1
        final = os.fstat(stream.fileno())
        require(
            (initial.st_size, initial.st_mtime_ns, initial.st_ino)
            == (final.st_size, final.st_mtime_ns, final.st_ino),
            "raw changed during verification",
        )
    require(
        total == raw["bytes"]
        and checksum.hexdigest() == raw["sha256"]
        and count == raw["frames"],
        "original raw bytes/hash/rows mismatch",
    )
    if previous_capture != counters["admitted"]:
        findings["missing_final_admission"] += 1
    for left, right in ((previous, finish), (begin, finish), (finish, written_clock)):
        if (
            abs(
                (right["utc_ns"] - left["utc_ns"])
                - (right["monotonic_ns"] - left["monotonic_ns"])
            )
            > manifest["policy"]["max_clock_step_ns"]
        ):
            observations["worker_clock_discontinuities"] += 1
    return {
        "schema": REPORT,
        **{k: opening[k] for k in IDENTITY},
        "capture_closed_verified": not findings,
        "scope": "selected admitted native packets and durable session closure; not RF completeness",
        "synthetic_only": manifest["synthetic_only"],
        "frames": count,
        "nodes": list(nodes.values()),
        "findings": dict(findings),
        "observations": dict(observations),
        "start_boundary": start,
        "end_boundary": end,
        "raw_sha256": raw["sha256"],
        "opening_sha256": manifest["files"]["opening"]["sha256"],
        "terminal_sha256": manifest["files"]["terminal"]["sha256"],
        "cross_host_alignment_verified": False,
        "recognition_validated": False,
        "publish_to_ha": False,
    }


@contextmanager
def verified_session(frames, manifest_path, report_path, opening, terminal, node_ids):
    from .evidence import _copy_raw, validate_evidence

    manifest_raw = file_bytes(manifest_path, 1_048_576)
    manifest = validate_manifest(strict_json(manifest_raw))
    report_raw = file_bytes(report_path, 1_048_576)
    report = strict_json(report_raw)
    with tempfile.TemporaryDirectory(prefix="ruview-verified-session-") as directory:
        root = Path(directory)
        _copy_raw(frames, root / "raw.jsonl", manifest["files"]["raw"])
        for name, source in (("opening", opening), ("terminal", terminal)):
            value = file_bytes(source, 1_048_576)
            checked_file(value, manifest["files"][name])
            with os.fdopen(
                os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as out:
                out.write(value)
        checked = verify_session(
            manifest, root / "raw.jsonl", root / "opening", root / "terminal"
        )
        checked["manifest_original_sha256"] = hashlib.sha256(manifest_raw).hexdigest()
        require(
            checked["capture_closed_verified"] is True
            and digest(checked) == digest(report),
            "capture is not verified closed or saved report differs",
        )
        require(
            sorted(node_ids) == [n["node_id"] for n in checked["nodes"]],
            "profiles differ from capture node scope",
        )
        require(
            all(n["frames"] > 0 for n in checked["nodes"]),
            "selected node has no recorded frames",
        )
        require(
            not checked["observations"].get("worker_clock_discontinuities"),
            "worker clock discontinuity prevents label pairing",
        )
        evidence = {
            "schema": EVIDENCE,
            "status": "verified_closed_capture",
            **{k: manifest[k] for k in IDENTITY},
            "synthetic_only": manifest["synthetic_only"],
            "expected_node_ids": sorted(node_ids),
            "manifest_sha256": checked["manifest_original_sha256"],
            "verification_report_sha256": hashlib.sha256(report_raw).hexdigest(),
            **{
                k + "_sha256": manifest["files"][k]["sha256"]
                for k in ("raw", "opening", "terminal")
            },
            "start_boundary": checked["start_boundary"],
            "end_boundary": checked["end_boundary"],
        }
        validate_evidence(evidence)
        yield root / "raw.jsonl", evidence
