"""Bounded read-only observations at an independent shadow evaluation boundary.

This stream does not reproduce an earlier production evaluation or supply
labels for rooms, people, postures, coordinates or falls.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from scripts.transport_security import http_opener

from .polling import ReceiverReads, SourceReads
from .proofs import ReceiverProofs

SCHEMA = "ruview.shadow-features.v1"
MAX_RESPONSE = 2 * 1024 * 1024
MAX_ROW = 256 * 1024
RESERVED_BYTES = 256 * 1024
FEATURE_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
IDENTITY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_HTTP_LOCAL = threading.local()


def thread_http_opener():
    """Reuse TLS initialization per worker without sharing request credentials.

    urllib constructs a verified TLS context even for plain HTTP through our
    common transport policy. Rebuilding its certificate store every second can
    consume most of a short polling deadline on a busy host. Handlers stay
    thread-local; Authorization remains solely on each new Request object.
    """
    signature = (
        http_opener,
        os.environ.get("RUVIEW_STRICT_TLS"),
        os.environ.get("SSL_CERT_FILE"),
        os.environ.get("SSL_CERT_DIR"),
    )
    if getattr(_HTTP_LOCAL, "signature", None) != signature:
        opener = http_opener()
        _HTTP_LOCAL.opener = opener
        _HTTP_LOCAL.signature = signature
    return _HTTP_LOCAL.opener


def encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def utc(ns):
    return dt.datetime.fromtimestamp(ns / 1e9, dt.timezone.utc).isoformat()


def host_boot_id(path=Path("/proc/sys/kernel/random/boot_id")):
    """A same-kernel monotonic clock binding; unsupported hosts stay unknown."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(128)
        value = raw.decode("ascii").strip()
        parsed = uuid.UUID(value)
        if parsed.int == 0 or str(parsed) != value:
            return None
        return value
    except (OSError, ValueError, UnicodeError):
        return None


def finite(value, minimum=None, maximum=None):
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    if (
        minimum is not None
        and value < minimum
        or maximum is not None
        and value > maximum
    ):
        return None
    return value


def integer(value, minimum=0, maximum=2**63 - 1):
    return value if type(value) is int and minimum <= value <= maximum else None


def stamp(value):
    if (
        isinstance(value, str)
        and value.isascii()
        and value.isdecimal()
        and len(value) <= 20
    ):
        value = int(value)
    return integer(value)


def identity(value):
    return value if isinstance(value, str) and IDENTITY.fullmatch(value) else None


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("deadline_requires_timezone")
    return int(parsed.timestamp() * 1e9)


def endpoint(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        raise ValueError("invalid_read_only_endpoint")
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def decode(raw):
    def reject(_value):
        raise ValueError("nonfinite_json")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    if not isinstance(value, dict):
        raise ValueError("object_required")
    return value


def read_json(url, timeout, token=None):
    """No ambient proxy, redirect, URL credentials, or unbounded response body."""
    endpoint(url)
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    before = time.monotonic()
    with thread_http_opener().open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError("http_status")
        if response.getheader("Content-Encoding", "identity") not in ("", "identity"):
            raise ValueError("unsupported_content_encoding")
        chunks, count = [], 0
        while True:
            if time.monotonic() - before > timeout:
                raise TimeoutError()
            chunk = response.read1(min(65536, MAX_RESPONSE + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > MAX_RESPONSE:
                raise ValueError("document_too_large")
        return decode(b"".join(chunks))


def timed_read(url, timeout, submitted, token=None, receiver=False):
    started, wall_started = time.monotonic(), time.time_ns()
    detail = {"outcome": "ok", "started_at_ns": wall_started}
    try:
        value = read_json(url, timeout, token)
        if receiver:
            value = {
                "document": value,
                "started": started,
                "finished": time.monotonic(),
                "started_at_ns": wall_started,
                "finished_at_ns": time.time_ns(),
            }
    except Exception as error:
        value = {}
        reason = "read_failed"
        if isinstance(error, (TimeoutError, socket.timeout)):
            reason = "timeout"
        elif isinstance(error, urllib.error.HTTPError):
            reason = "http_status"
            detail["http_status"] = error.code
        elif isinstance(error, (OSError, urllib.error.URLError)):
            reason = "network_error"
        elif isinstance(error, (ValueError, UnicodeError)):
            reason = "invalid_document"
        detail.update(outcome="error", reason=reason)
    detail.update(
        finished_at_ns=time.time_ns(),
        request_ms=(time.monotonic() - started) * 1000,
        queue_ms=max(0, (started - submitted) * 1000),
    )
    return value, detail


def indexed(value, field="nodes"):
    rows = value.get(field, []) if isinstance(value, dict) else []
    if not isinstance(rows, list) or len(rows) > 64:
        return {}
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            return {}
        node = integer(row.get("node_id"), 1, 65535)
        if node is None or node in result:
            return {}
        result[node] = row
    return result


def worker_projection(worker, row):
    grid = row.get("grid") if isinstance(row.get("grid"), dict) else {}
    return {
        "schema_valid": (
            worker.get("schema") == "ruview.server-modules.v1"
            and worker.get("recognition_validated") is False
        ),
        **{
            key: identity(worker.get(key))
            for key in ("worker_run_id", "configuration_sha256", "clock_id")
        },
        "generated_at_ns": stamp(worker.get("generated_at_ns")),
        "fresh": row.get("fresh") if type(row.get("fresh")) is bool else None,
        "age_ms": finite(row.get("age_ms"), 0),
        **{
            key: stamp(row.get(key))
            for key in ("last_received_at_ns", "last_received_monotonic_ns")
        },
        "sequence": integer(row.get("sequence"), 0, 2**32 - 1),
        "node_epoch": integer(row.get("node_epoch")),
        "sequence_discontinuities": integer(row.get("sequence_discontinuities")),
        "epoch_reason": identity(row.get("epoch_reason")),
        "legacy_raw64_profile": row.get("admission") is None,
        "admission_profile": identity(row["admission"].get("profile"))
        if isinstance(row.get("admission"), dict)
        else None,
        "admission_manifest_sha256": identity(row["admission"].get("manifest_sha256"))
        if isinstance(row.get("admission"), dict)
        else None,
        "grid": {
            key: integer(grid.get(key))
            for key in (
                "antennas",
                "subcarriers",
                "ppdu_type",
                "flags",
                "frequency_mhz",
            )
        },
    }


def project(sensing, worker, nodes, now_ns, max_age_ms, proofs=None):
    """The collector's full features live in node_features, not nodes."""
    by_node, diagnostics = indexed(sensing, "node_features"), indexed(sensing)
    worker_nodes = indexed(worker)
    source_seconds = finite(sensing.get("timestamp"), 1, 1e11)
    source_ns = int(source_seconds * 1e9) if source_seconds is not None else None
    result = []
    for node in nodes:
        raw = by_node.get(node, {})
        raw_features = raw.get("features", {})
        features, invalid_features = {}, []
        if isinstance(raw_features, dict) and len(raw_features) <= 64:
            for key, value in raw_features.items():
                if not isinstance(key, str) or not FEATURE_KEY.fullmatch(key):
                    continue
                measured = finite(value)
                if measured is not None:
                    features[key] = measured
                else:
                    invalid_features.append(key)
        for key in ("rssi", "frame_rate_hz"):
            measured = finite(raw.get(key))
            if measured is not None:
                features[key] = measured
        age = finite(raw.get("last_seen_ms"), 0)
        observed_age = (
            max(age, (now_ns - source_ns) / 1e6 + age)
            if age is not None and source_ns
            else None
        )
        reason = "available"
        if sensing.get("source") != "esp32" or sensing.get("type") != "sensing_update":
            reason = "invalid_source_schema"
        elif not raw:
            reason = "source_node_missing"
        elif source_ns is None or source_ns > now_ns + 500_000_000:
            reason = "invalid_source_time"
        elif (
            raw.get("stale") is not False
            or observed_age is None
            or observed_age > max_age_ms
        ):
            reason = "stale_or_unknown_source"
        elif any(
            finite(features.get(key), 0) is None
            for key in ("motion_band_power", "variance")
        ):
            reason = "required_feature_missing_or_invalid"
        projected_worker = worker_projection(worker, worker_nodes.get(node, {}))
        grid = projected_worker["grid"]
        profile = None
        if projected_worker["schema_valid"] and all(
            grid[key] is not None
            for key in ("antennas", "subcarriers", "ppdu_type", "flags")
        ):
            profile = (
                grid["antennas"] == 1
                and grid["subcarriers"] == 64
                and grid["ppdu_type"] == 0
                and grid["flags"] in (0, 16)
                and projected_worker["legacy_raw64_profile"]
            )
        result.append(
            {
                "node_id": node,
                "available": reason == "available",
                "reason": reason,
                "features": features,
                "invalid_feature_keys": sorted(invalid_features),
                "source_time_ns": source_ns,
                "source_age_ms": observed_age,
                "collector_diagnostics": {
                    k: finite(diagnostics.get(node, {}).get(k))
                    for k in (
                        "rssi_dbm",
                        "subcarrier_count",
                        "frequency_mhz",
                        "channel",
                    )
                },
                "worker": projected_worker,
                "native_profile_compatible": profile,
                "receiver_proof": (proofs or {}).get(node),
                "feature_contract_sha256": digest(sorted(features)),
            }
        )
    return result


def atomic(path, value):
    temporary = path.with_name("." + path.name + ".tmp")
    with temporary.open("xb") as target:
        target.write(encoded(value) + b"\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, path)


class Journal:
    """A single-owner append-only run. Each closed part has a durable hash."""

    def __init__(self, root, metadata, max_bytes, part_bytes):
        if (
            max_bytes < RESERVED_BYTES * 2
            or not 1024 <= part_bytes <= max_bytes - RESERVED_BYTES
            or math.ceil(max_bytes / part_bytes) > 256
        ):
            raise ValueError("invalid_journal_limits")
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.root.chmod(0o700)
        self.max_bytes, self.part_bytes = max_bytes, part_bytes
        self.total = self.rows = self.part_size = 0
        self.parts, self.stream, self.part_hash = [], None, None
        atomic(self.root / "metadata.json", metadata)
        self.total += (self.root / "metadata.json").stat().st_size

    def close_part(self):
        if self.stream is None:
            return
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        self.parts.append(
            {
                "name": self.part_name,
                "bytes": self.part_size,
                "sha256": self.part_hash.hexdigest(),
            }
        )
        self.stream = None

    def append(self, value):
        raw = encoded(value) + b"\n"
        if len(raw) > MAX_ROW:
            raise ValueError("observation_too_large")
        if self.total + len(raw) > self.max_bytes - RESERVED_BYTES:
            return False
        if self.stream is not None and self.part_size + len(raw) > self.part_bytes:
            self.close_part()
        if self.stream is None:
            self.part_name = f"observations-{len(self.parts):04d}.jsonl"
            self.stream = (self.root / self.part_name).open("xb")
            self.part_size, self.part_hash = 0, hashlib.sha256()
        self.stream.write(raw)
        self.stream.flush()
        self.part_hash.update(raw)
        self.part_size += len(raw)
        self.total += len(raw)
        self.rows += 1
        return True

    def status(self, reason="recording", **fields):
        atomic(
            self.root / "status.json",
            {
                "schema": "ruview.shadow-journal-status.v1",
                "state": reason,
                "updated_at_utc": utc(time.time_ns()),
                "rows": self.rows,
                "stored_bytes": self.total,
                "closed_parts": self.parts,
                **fields,
            },
        )

    def finish(self, reason, **fields):
        self.close_part()
        terminal = {
            "schema": "ruview.shadow-journal-terminal.v1",
            "reason": reason,
            "finished_at_utc": utc(time.time_ns()),
            "rows": self.rows,
            "stored_bytes": self.total,
            "parts": self.parts,
            **fields,
        }
        atomic(self.root / "terminal.json", terminal)
        self.status(reason, **fields)
        return terminal


def token_value(args):
    if args.token_file:
        raw = Path(args.token_file).read_bytes()
        if len(raw) > 8192:
            raise ValueError("invalid_token_file")
        token = raw.decode().strip()
    elif args.token_env:
        token = os.environ.get(args.token_env, "")
    else:
        token = ""
    if "\r" in token or "\n" in token:
        raise ValueError("invalid_token")
    return token or None


def collect(args):
    os.umask(0o077)
    deadline = timestamp(args.deadline)
    started_ns, started_mono = time.time_ns(), time.monotonic_ns()
    if not started_ns < deadline <= started_ns + 48 * 3600 * 10**9:
        raise ValueError("deadline_must_be_future_within_48_hours")
    if not 0.25 <= args.interval <= 60 or not 0.05 <= args.timeout <= min(
        args.interval, 2
    ):
        raise ValueError("invalid_poll_timing")
    nodes = sorted(set(args.node))
    if not 1 <= len(nodes) <= 16 or any(not 1 <= n <= 65535 for n in nodes):
        raise ValueError("invalid_nodes")
    urls = {0: endpoint(args.sensing_url)}
    if args.worker_url:
        urls[1] = endpoint(args.worker_url)
    token = token_value(args)
    proof_manager = None
    if bool(args.receiver_config) != bool(args.receiver_sha256):
        raise ValueError("receiver_config_requires_pinned_sha256")
    if args.receiver_config:
        receiver_config = decode(Path(args.receiver_config).read_bytes())
        proof_manager = ReceiverProofs(
            receiver_config,
            nodes,
            timeout=args.timeout,
            expected_sha256=args.receiver_sha256,
        )
    config = {
        "schema": "ruview.shadow-journal-config.v1",
        "nodes": nodes,
        "deadline_utc": utc(deadline),
        "interval_seconds": args.interval,
        "timeout_seconds": args.timeout,
        "max_source_age_ms": args.max_age_ms,
        "max_bytes": args.max_bytes,
        "part_bytes": args.part_bytes,
        "min_free_bytes": args.min_free_bytes,
        "endpoint_sha256": {
            str(k): hashlib.sha256(v.encode()).hexdigest() for k, v in urls.items()
        },
        "receiver_configuration_sha256": args.receiver_sha256,
    }
    run_id = str(uuid.uuid4())
    metadata = {
        "schema": "ruview.shadow-journal.v1",
        "run_id": run_id,
        "started_at_utc": utc(started_ns),
        "started_monotonic_ns": started_mono,
        "boot_id": host_boot_id(),
        "monotonic_clock": "CLOCK_MONOTONIC",
        "configuration": config,
        "configuration_sha256": digest(config),
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "independent_shadow_observation": True,
        "production_replay": False,
        "reference_is_ground_truth": False,
        "publishes_to_ha": False,
    }
    root = Path(args.output)
    if shutil.disk_usage(root.parent).free < args.min_free_bytes:
        raise ValueError("insufficient_initial_free_space")
    journal = Journal(root, metadata, args.max_bytes, args.part_bytes)
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    previous_handlers = {
        s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)
    }
    sources = SourceReads(
        urls,
        lambda url, timeout, submitted: timed_read(
            url, timeout, submitted, token if url == urls[0] else None
        ),
    )
    receivers = (
        ReceiverReads(
            nodes,
            lambda url, timeout, submitted: timed_read(
                url, timeout, submitted, receiver=True
            ),
        )
        if proof_manager
        else None
    )
    reason, index, clock_epoch = "deadline", 0, 0
    previous_wall, previous_mono = started_ns, started_mono
    next_poll = time.monotonic()
    deadline_mono = started_mono + deadline - started_ns
    try:
        journal.status(run_id=run_id, deadline_utc=utc(deadline))
        while (
            not stopped
            and time.time_ns() < deadline
            and time.monotonic_ns() < deadline_mono
        ):
            if (root / "STOP").exists():
                reason = "operator_stop"
                break
            if shutil.disk_usage(root).free < args.min_free_bytes:
                reason = "free_space_limit"
                break
            readings, details = sources.collect(urls, args.timeout, args.timeout)
            sensing, worker = readings.get(0, {}), readings.get(1, {})
            proofs = None
            if proof_manager:
                requests = proof_manager.requests(worker, time.monotonic())
                values, receiver_details = receivers.collect(
                    requests, args.timeout, args.timeout
                )
                proofs = proof_manager.resolve(worker, values, time.monotonic())
            else:
                receiver_details = {}
            wall, mono = time.time_ns(), time.monotonic_ns()
            if wall >= deadline or mono >= deadline_mono or stopped:
                break
            drift = (wall - previous_wall) - (mono - previous_mono)
            if abs(drift) > 500_000_000:
                clock_epoch += 1
            row = {
                "schema": SCHEMA,
                "kind": "observation",
                "run_id": run_id,
                "configuration_sha256": digest(config),
                "index": index,
                "captured_at_utc": utc(wall),
                "utc_ns": wall,
                "monotonic_ns": mono,
                "clock_epoch": clock_epoch,
                "clock_step_ns": drift if abs(drift) > 500_000_000 else None,
                "interval_ns": mono - previous_mono,
                "late_interval": mono - previous_mono > args.interval * 1.5e9,
                "reads": details,
                "receiver_reads": receiver_details,
                "nodes": project(sensing, worker, nodes, wall, args.max_age_ms, proofs),
                "reference_is_ground_truth": False,
                "production_replay": False,
            }
            if not journal.append(row):
                reason = "byte_limit"
                break
            previous_wall, previous_mono = wall, mono
            index += 1
            if index % 10 == 0:
                journal.status(
                    run_id=run_id, deadline_utc=utc(deadline), clock_epoch=clock_epoch
                )
            next_poll += args.interval
            if next_poll < time.monotonic():
                next_poll = time.monotonic()
            time.sleep(
                max(
                    0,
                    min(
                        next_poll - time.monotonic(),
                        (deadline_mono - time.monotonic_ns()) / 1e9,
                    ),
                )
            )
        if stopped:
            reason = "signal_stop"
    except Exception as error:
        reason = "collector_error"
        journal.finish(
            reason,
            error_type=type(error).__name__,
            run_id=run_id,
            clock_epoch=clock_epoch,
        )
        raise
    finally:
        sources.close()
        if receivers:
            receivers.close()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    terminal = journal.finish(reason, run_id=run_id, clock_epoch=clock_epoch)
    print(
        encoded(
            {
                "run_id": run_id,
                "reason": reason,
                "rows": terminal["rows"],
                "stored_bytes": terminal["stored_bytes"],
            }
        ).decode()
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensing-url", required=True)
    parser.add_argument("--worker-url")
    parser.add_argument("--node", required=True, type=int, action="append")
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--deadline", required=True, help="Fixed timezone-aware ISO UTC deadline"
    )
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=0.8)
    parser.add_argument("--max-age-ms", type=float, default=2500)
    parser.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--part-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--min-free-bytes", type=int, default=1024 * 1024 * 1024)
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--token-file")
    credentials.add_argument("--token-env")
    parser.add_argument("--receiver-config")
    parser.add_argument("--receiver-sha256")
    args = parser.parse_args(argv)
    if finite(args.max_age_ms, 1, 60000) is None or args.min_free_bytes < 0:
        parser.error("invalid source-age/free-space limit")
    collect(args)


if __name__ == "__main__":
    main()
