"""Stream and verify a private capture without opening a network socket."""

import hashlib
import ipaddress
import os
import re
import stat

from scripts.site_context import _directory, _json, _read, write_private_output

from .capture import FRESHNESS_NS, MAX_UDP_BYTES, SCHEMA, decision, json_bytes
from .config import MAX_CONFIG_BYTES, Config, validate
from .quality import QualityObserver

MAX_ROW_BYTES = MAX_UDP_BYTES * 2 + 2048
MANIFEST_FIELDS = {
    "schema",
    "diagnostic_only",
    "config_sha256",
    "requested_seconds",
    "started_monotonic_ns",
    "ended_monotonic_ns",
    "started_wall_ns",
    "ended_wall_ns",
    "freshness_ns",
    "completion",
    "complete",
    "records",
    "received_datagrams",
    "bytes",
    "datagrams_sha256",
    "accepted",
    "rejected",
    "rejection_reasons",
    "truncated_datagrams",
    "unrecorded_datagrams",
    "subscriptions_sent",
    "errors",
    "network_loss",
    "identity_check",
}
ROW_FIELDS = {
    "schema",
    "record",
    "received_monotonic_ns",
    "received_wall_ns",
    "origin_ip",
    "origin_port",
    "raw_hex",
    "truncated",
    "rejection",
}


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def replay(input_directory, output):
    """Check capture consistency, not authenticity, and recompute its final quality."""
    directory = _directory(input_directory)
    fd = None
    try:
        manifest = _json(_read(directory, "manifest.json", 65536))
        raw = _read(directory, "config.json", MAX_CONFIG_BYTES)
        if (
            not isinstance(manifest, dict)
            or set(manifest) != MANIFEST_FIELDS
            or manifest.get("schema") != SCHEMA
        ):
            raise ValueError("Unsupported capture manifest")
        if hashlib.sha256(raw).hexdigest() != manifest.get("config_sha256"):
            raise ValueError("Recorded configuration digest mismatch")
        config = Config(raw, manifest["config_sha256"], validate(_json(raw)))
        start, end = (
            manifest.get("started_monotonic_ns"),
            manifest.get("ended_monotonic_ns"),
        )
        if not _integer(start) or not _integer(end) or end < start:
            raise ValueError("Invalid capture time interval")
        for name in (
            "records",
            "received_datagrams",
            "bytes",
            "accepted",
            "rejected",
            "truncated_datagrams",
            "unrecorded_datagrams",
            "subscriptions_sent",
            "started_wall_ns",
            "ended_wall_ns",
        ):
            if not _integer(manifest.get(name)):
                raise ValueError(f"Invalid manifest integer: {name}")
        if not isinstance(manifest.get("errors"), list) or not all(
            isinstance(e, str) for e in manifest["errors"]
        ):
            raise ValueError("Invalid manifest errors")
        if (
            type(manifest.get("diagnostic_only")) is not bool
            or not manifest["diagnostic_only"]
        ):
            raise ValueError("Capture must be diagnostic only")
        if (
            type(manifest.get("freshness_ns")) is not int
            or manifest["freshness_ns"] != FRESHNESS_NS
        ):
            raise ValueError("Unsupported freshness threshold")
        if (
            not _integer(manifest.get("requested_seconds"), 1)
            or manifest["requested_seconds"] > 2400
        ):
            raise ValueError("Invalid requested duration")
        if not isinstance(manifest.get("completion"), str) or manifest[
            "completion"
        ] not in {
            "duration_elapsed",
            "record_limit",
            "byte_limit",
            "interrupted",
            "io_or_processing_error",
            "write_error",
        }:
            raise ValueError("Unknown completion status")
        if (
            manifest["completion"] == "duration_elapsed"
            and end < start + manifest["requested_seconds"] * 1_000_000_000
        ):
            raise ValueError("Completed capture ended before its deadline")
        if (
            not isinstance(manifest["datagrams_sha256"], str)
            or re.fullmatch(r"[a-f0-9]{64}", manifest["datagrams_sha256"]) is None
        ):
            raise ValueError("Invalid datagram digest")
        if not isinstance(manifest["rejection_reasons"], dict) or not all(
            isinstance(key, str) and _integer(value, 1)
            for key, value in manifest["rejection_reasons"].items()
        ):
            raise ValueError("Invalid rejection counts")
        if (
            manifest["network_loss"]
            != "unknown; UDP and OS drops are not observable here"
            or manifest["identity_check"]
            != "IP, port and decoded MAC allowlist; not authentication"
        ):
            raise ValueError("Unsupported capture evidence contract")
        if (
            manifest["received_datagrams"]
            != manifest["records"] + manifest["unrecorded_datagrams"]
        ):
            raise ValueError("Received/recorded datagram counts disagree")
        observer = QualityObserver(
            list(config.receivers.values()), freshness_ns=FRESHNESS_NS
        )
        fd = os.open(
            "datagrams.jsonl",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > config.document["max_bytes"]
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise ValueError("Capture must be a private bounded regular file")
        digest = hashlib.sha256()
        records = total = accepted = rejected = truncated_count = 0
        reasons = {}
        previous = start
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while line := stream.readline(MAX_ROW_BYTES + 1):
                if len(line) > MAX_ROW_BYTES or not line.endswith(b"\n"):
                    raise ValueError("Oversize or incomplete capture row")
                records += 1
                total += len(line)
                if total > config.document["max_bytes"]:
                    raise ValueError("Capture byte limit exceeded during replay")
                if records > config.document["max_records"]:
                    raise ValueError("Capture record limit exceeded")
                digest.update(line)
                row = _json(line)
                if (
                    not isinstance(row, dict)
                    or set(row) != ROW_FIELDS
                    or row["schema"] != SCHEMA
                    or type(row["record"]) is not int
                    or row["record"] != records
                ):
                    raise ValueError("Invalid capture envelope")
                received = row["received_monotonic_ns"]
                if (
                    not _integer(received)
                    or not previous <= received <= end
                    or not _integer(row["received_wall_ns"])
                ):
                    raise ValueError("Invalid or regressing capture timestamp")
                previous = received
                if (
                    type(row["truncated"]) is not bool
                    or not isinstance(row["origin_ip"], str)
                    or not _integer(row["origin_port"])
                    or row["origin_port"] > 65535
                ):
                    raise ValueError("Invalid captured source")
                ipaddress.IPv4Address(row["origin_ip"])
                encoded = row["raw_hex"]
                if (
                    not isinstance(encoded, str)
                    or len(encoded) > MAX_UDP_BYTES * 2
                    or len(encoded) % 2
                    or re.fullmatch(r"[0-9a-f]*", encoded) is None
                ):
                    raise ValueError("Invalid raw datagram encoding")
                data = bytes.fromhex(encoded)
                rejection, packet = decision(
                    config,
                    data,
                    (row["origin_ip"], row["origin_port"]),
                    row["truncated"],
                )
                if rejection != row["rejection"]:
                    raise ValueError("Recorded rejection differs from replay")
                truncated_count += int(row["truncated"])
                if rejection is None:
                    accepted += 1
                    observer.ingest(packet, received)
                else:
                    rejected += 1
                    reasons[rejection] = reasons.get(rejection, 0) + 1
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("Capture changed during replay")
        for field, expected in {
            "records": records,
            "bytes": total,
            "accepted": accepted,
            "rejected": rejected,
            "truncated_datagrams": truncated_count,
            "rejection_reasons": reasons,
            "datagrams_sha256": digest.hexdigest(),
        }.items():
            if manifest.get(field) != expected:
                raise ValueError(f"Capture manifest mismatch: {field}")
        if (
            not _integer(manifest.get("unrecorded_datagrams"))
            or type(manifest.get("complete")) is not bool
        ):
            raise ValueError("Invalid capture completeness fields")
        expected_complete = (
            manifest["completion"] == "duration_elapsed"
            and not truncated_count
            and not manifest["unrecorded_datagrams"]
            and not manifest.get("errors")
        )
        if manifest["complete"] != expected_complete:
            raise ValueError("Inconsistent capture completeness")
        result = {
            "schema": SCHEMA,
            "diagnostic_only": True,
            "manifest": manifest,
            "quality": observer.snapshot(end),
        }
        original = _json(_read(directory, "summary.json", 2 * 1024**2))
        if result != original:
            raise ValueError("Recomputed quality differs from recorded summary")
        report = {
            "schema": "wisp.pilot-replay.v1",
            "diagnostic_only": True,
            "verification": "internal consistency only; capture is not authenticated",
            "result": result,
        }
        write_private_output(output, json_bytes(report))
        return report
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
