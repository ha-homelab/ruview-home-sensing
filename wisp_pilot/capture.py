"""Bounded diagnostic UDP capture. No discovery, firmware control or HA writes."""

import hashlib
import json
import os
import socket
import time
from pathlib import Path

from scripts.site_context import _directory

from .protocol import MAX_DATAGRAM_BYTES, ProtocolError, parse_packet, subscribe_packet
from .quality import QualityObserver

SCHEMA = "wisp.pilot-capture.v1"
FRESHNESS_NS = 3_000_000_000
REFRESH_SECONDS = 4
MAX_UDP_BYTES = 65535


def json_bytes(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def decision(config, data, origin, truncated=False):
    """Return a reproducible rejection and packet. This is not authentication."""
    if truncated:
        return "datagram_truncated", None
    if len(data) > MAX_DATAGRAM_BYTES:
        return "oversize_datagram", None
    if origin[0] not in config.receivers:
        return "unlisted_source_ip", None
    if origin[1] != config.document["source_port"]:
        return "unexpected_source_port", None
    try:
        packet = parse_packet(data)
    except ProtocolError:
        return "invalid_protocol", None
    if packet["receiver_mac"] != config.receivers[origin[0]]:
        return "receiver_mac_mismatch", None
    return None, packet


def _new_directory(path):
    path = Path(os.path.abspath(path))
    parent = _directory(path.parent)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        return os.open(
            path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
    finally:
        os.close(parent)


def _file(directory, name):
    return os.fdopen(
        os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        ),
        "wb",
    )


def _save(directory, name, raw):
    with _file(directory, name) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def capture(
    config,
    output,
    seconds,
    *,
    socket_factory=socket.socket,
    monotonic_ns=time.monotonic_ns,
    wall_ns=time.time_ns,
):
    """Record every received datagram within limits; report any discarded boundary row."""
    if type(seconds) is not int or not 1 <= seconds <= 2400:
        raise ValueError("Capture seconds must be an integer in 1..2400")
    directory = _new_directory(output)
    sock = None
    record_file = None
    started, wall_started = monotonic_ns(), wall_ns()
    ended = started
    deadline = started + seconds * 1_000_000_000
    observer = QualityObserver(
        list(config.receivers.values()), freshness_ns=FRESHNESS_NS
    )
    records = total_bytes = accepted = rejected = received_count = 0
    digest = hashlib.sha256()
    reasons = {}
    errors = []
    completion = "duration_elapsed"
    truncated_count = subscription_count = 0
    try:
        _save(directory, "config.json", config.raw)
        record_file = _file(directory, "datagrams.jsonl")
        sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.25)
        sock.bind((config.document["bind_ip"], 0))
        next_subscribe = started
        while monotonic_ns() < deadline:
            now = monotonic_ns()
            if now >= deadline:
                break
            if now >= next_subscribe:
                for ip in config.receivers:
                    remaining = (deadline - monotonic_ns()) / 1e9
                    if remaining <= 0:
                        break
                    sock.settimeout(min(0.25, remaining))
                    sock.sendto(
                        subscribe_packet(streams=3),
                        (ip, config.document["source_port"]),
                    )
                    subscription_count += 1
                next_subscribe = now + REFRESH_SECONDS * 1_000_000_000
            if monotonic_ns() >= deadline:
                break
            sock.settimeout(max(0.001, min(0.25, (deadline - monotonic_ns()) / 1e9)))
            try:
                data, _ancillary, flags, origin = sock.recvmsg(MAX_UDP_BYTES)
            except socket.timeout:
                continue
            received_count += 1
            received = monotonic_ns()
            received_wall = wall_ns()
            truncated = bool(flags & socket.MSG_TRUNC)
            rejection, packet = decision(config, data, origin, truncated)
            row = {
                "schema": SCHEMA,
                "record": records + 1,
                "received_monotonic_ns": received,
                "received_wall_ns": received_wall,
                "origin_ip": origin[0],
                "origin_port": origin[1],
                "raw_hex": data.hex(),
                "truncated": truncated,
                "rejection": rejection,
            }
            encoded = json_bytes(row)
            if (
                records >= config.document["max_records"]
                or total_bytes + len(encoded) > config.document["max_bytes"]
            ):
                completion = (
                    "record_limit"
                    if records >= config.document["max_records"]
                    else "byte_limit"
                )
                break
            record_file.write(encoded)
            digest.update(encoded)
            records += 1
            total_bytes += len(encoded)
            truncated_count += int(truncated)
            if rejection is None:
                accepted += 1
                observer.ingest(packet, received)
            else:
                rejected += 1
                reasons[rejection] = reasons.get(rejection, 0) + 1
        ended = monotonic_ns()
    except KeyboardInterrupt:
        completion = "interrupted"
        ended = monotonic_ns()
    except (OSError, ValueError) as error:
        completion = "io_or_processing_error"
        errors.append(type(error).__name__)
        ended = monotonic_ns()
    except BaseException as error:
        # Persist incomplete evidence without replacing the original failure.
        completion = "io_or_processing_error"
        errors.append(type(error).__name__)
        ended = monotonic_ns()
        raise
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError as error:
                completion = "io_or_processing_error"
                errors.append(type(error).__name__)
        if record_file is not None:
            try:
                record_file.flush()
                os.fsync(record_file.fileno())
            except OSError as error:
                completion = "write_error"
                errors.append(type(error).__name__)
            finally:
                try:
                    record_file.close()
                except OSError as error:
                    completion = "write_error"
                    errors.append(type(error).__name__)
        manifest = {
            "schema": SCHEMA,
            "diagnostic_only": True,
            "config_sha256": config.sha256,
            "requested_seconds": seconds,
            "started_monotonic_ns": started,
            "ended_monotonic_ns": ended,
            "started_wall_ns": wall_started,
            "ended_wall_ns": wall_ns(),
            "freshness_ns": FRESHNESS_NS,
            "completion": completion,
            "complete": completion == "duration_elapsed" and not truncated_count,
            "records": records,
            "received_datagrams": received_count,
            "bytes": total_bytes,
            "datagrams_sha256": digest.hexdigest(),
            "accepted": accepted,
            "rejected": rejected,
            "rejection_reasons": reasons,
            "truncated_datagrams": truncated_count,
            "unrecorded_datagrams": received_count - records,
            "subscriptions_sent": subscription_count,
            "errors": errors,
            "network_loss": "unknown; UDP and OS drops are not observable here",
            "identity_check": "IP, port and decoded MAC allowlist; not authentication",
        }
        summary = {
            "schema": SCHEMA,
            "diagnostic_only": True,
            "manifest": manifest,
            "quality": observer.snapshot(ended),
        }
        try:
            _save(directory, "manifest.json", json_bytes(manifest))
            _save(directory, "summary.json", json_bytes(summary))
        finally:
            os.close(directory)
    return summary
