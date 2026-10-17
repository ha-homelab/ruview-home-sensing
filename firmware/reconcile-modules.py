#!/usr/bin/env python3
"""Restore a qualified module once per manually armed generation.

The persistent attempt marker is reserved before the POST and never removed.
A lost reply, process crash or receiver reboot cannot rearm restoration. An
operator must review the evidence and explicitly choose a new generation.
This bounds automatic attempts; it does not guarantee successful restoration.
The explicit .10/.11/.12 boot_bound_v1 mode uses separate immutable MAC/nonce markers;
it never removes or rearms any legacy generation marker.
"""

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import struct
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

BOOT_MODE = "boot_bound_v1"
BOOT_VERSIONS = ("0.8.8.10", "0.8.8.11", "0.8.8.12")
LEGACY_VERSIONS = ("0.8.8.4", "0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8")
BOOT_SCHEMA = "ruview.boot-nonce.v1"
BOOT_HEADER = "X-RuView-Expected-Boot-Nonce"
BOOT_MARKER_SCHEMA = "ruview.boot-restore-attempt.v1"
BOOT_WINDOW_NS = 3600 * 1_000_000_000
BOOT_WINDOW_LIMIT = 3
BOOT_MARKER_LIMIT = 256
BOOT_DIRECTORY_LIMIT = 4096

# Only locally defined guard messages may become public diagnostics. Arbitrary
# exception text can contain receiver replies, request URLs or filesystem data.
REVIEW_REASON_BY_MESSAGE = {
    "Callback diagnostics are missing or inconsistent": "callback_diagnostics_invalid",
    "Callback overrun history needs operator review": "callback_overrun_history",
    "Callback maximum exceeds signed budget": "callback_budget_exceeded",
    "Boot firmware changed or not qualified": "firmware_not_qualified",
    "Exact boot target qualification is required": "target_not_qualified",
    "Exact reviewed boot package required": "package_not_qualified",
    "Boot identity or station MAC mismatch": "receiver_identity_mismatch",
    "Receiver rebooted during preflight": "receiver_rebooted",
    "Receiver rebooted between observations": "receiver_rebooted",
    "Receiver minimum uptime is 60 seconds": "minimum_uptime_not_met",
    "Boot runtime memory margin failed": "memory_margin_failed",
    "Inconsistent boot runtime memory diagnostics": "memory_diagnostics_invalid",
    "Boot preflight deadline exceeded": "preflight_deadline_exceeded",
    "Boot preflight stability/deadline failed": "preflight_stability_failed",
    "Receiver uptime did not advance consistently": "uptime_progress_invalid",
    "Existing module fault, stop or identity mismatch needs review": "module_state_invalid",
    "Module state changed during preflight": "module_state_changed",
    "Unrelated modules need operator review": "unexpected_modules",
    "Invalid retained boot reservation": "retained_reservation_invalid",
    "Invalid boot marker file": "retained_marker_invalid",
    "Invalid boot reservation lock": "reservation_lock_invalid",
    "Reservation wall clock moved backwards": "reservation_clock_rollback",
    "Boot restore hourly attempt limit reached": "hourly_attempt_limit",
    "Boot marker retention limit reached": "marker_retention_limit",
    "Boot upload result unknown or mismatched; no retry": "upload_outcome_unknown",
}


def review_reason(error):
    """Return a fixed diagnostic token without printing untrusted error text."""
    if type(error) is ValueError and len(error.args) == 1:
        message = error.args[0]
        if isinstance(message, str) and message in REVIEW_REASON_BY_MESSAGE:
            return REVIEW_REASON_BY_MESSAGE[message]
    if isinstance(error, TimeoutError):
        return "request_timeout"
    if isinstance(error, OSError):
        return "io_failure"
    return "invalid_response_or_configuration"


def boot_require(value, message):
    if not value:
        raise ValueError(message)


def valid_nonce(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{32}", value) is not None
        and value != "0" * 32
    )


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            boot_require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def number(_):
        raise ValueError("Boot restore evidence requires integer numbers")

    return json.loads(
        raw, object_pairs_hook=pairs, parse_float=number, parse_constant=number
    )


def boot_binding(target, packages):
    """New qualification is additive; legacy manifest fields are not reinterpreted."""
    boot_require(
        target.get("enabled") is True, "Explicit boot restore enablement required"
    )
    node, mac, ip = target.get("node_id"), target.get("mac"), target.get("ip")
    boot_require(type(node) is int and 1 <= node <= 10, "Invalid boot node ID")
    boot_require(
        isinstance(mac, str)
        and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
        and mac != "00:00:00:00:00:00"
        and int(mac[:2], 16) & 1 == 0,
        "Canonical unicast station MAC required",
    )
    boot_require(
        isinstance(ip, str) and str(ipaddress.IPv4Address(ip)) == ip,
        "Canonical IPv4 required",
    )
    boot_require(
        target.get("firmware_version") in BOOT_VERSIONS,
        "Boot mode requires qualified .10, .11 or .12 firmware",
    )
    boot_require(
        isinstance(packages, list) and 1 <= len(packages) <= 3,
        "Boot restoration requires a bounded package catalog",
    )
    seen_hashes, seen_names, selected = set(), set(), []
    for item in packages:
        boot_require(
            isinstance(item, (tuple, list))
            and len(item) == 2
            and isinstance(item[0], dict),
            "Invalid boot catalog entry",
        )
        candidate, _ = item
        digest, name = candidate.get("sha256"), candidate.get("name")
        boot_require(
            isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest)
            and isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,30}", name)
            and digest not in seen_hashes
            and name not in seen_names,
            "Duplicate or invalid boot catalog identity",
        )
        seen_hashes.add(digest)
        seen_names.add(name)
        if digest == target.get("package_sha256"):
            selected.append(item)
    boot_require(len(selected) == 1, "Exactly one target package must match")
    package, data = selected[0]
    boot_require(
        package.get("deployment") == "qualified_for_auto_restore"
        and isinstance(data, bytes)
        and 0 < len(data) <= 256 * 1024
        and package.get("sha256") == hashlib.sha256(data).hexdigest()
        and target.get("package_sha256") == package["sha256"],
        "Exact reviewed boot package required",
    )
    binding = {
        k: target[k]
        for k in ("node_id", "mac", "ip", "firmware_version", "restore_mode")
    }
    approved = package.get("qualified_boot_restore_targets")
    boot_require(
        isinstance(approved, list)
        and 1 <= len(approved) <= 10
        and sum(
            type(item) is dict
            and set(item) == set(binding)
            and all(
                type(item[key]) is type(value) and item[key] == value
                for key, value in binding.items()
            )
            for item in approved
        )
        == 1,
        "Exact boot target qualification is required",
    )
    capabilities(package["capabilities"])
    boot_require(
        isinstance(package.get("name"), str)
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,30}", package["name"])
        and type(package.get("wasm_bytes")) is int
        and 0 < package["wasm_bytes"] <= 256 * 1024
        and type(package.get("max_frame_us")) is int
        and 1 <= package["max_frame_us"] <= 10000,
        "Invalid boot package metadata",
    )
    return package, data


def reserve_boot_attempt(directory, target, package, nonce, now_ns):
    """One persistent MAC+boot reservation, plus three new boots per hour.

    Package, firmware and generation changes never rearm the same boot. Files
    are never deleted. Clock rollback, partial evidence or full inventory fails
    closed; these operational limits are not recognition qualification.
    """
    boot_require(valid_nonce(nonce), "Invalid boot nonce")
    boot_require(
        type(now_ns) is int and BOOT_WINDOW_NS < now_ns < 2**63,
        "Invalid reservation clock",
    )
    boot_require(directory is not None, "Persistent boot state directory required")
    directory = Path(directory)
    boot_require(
        directory.is_absolute() and directory.resolve(strict=True) == directory,
        "Canonical persistent boot directory required",
    )
    mac = target["mac"]
    prefix = "boot-" + mac.replace(":", "")
    filename = prefix + "--" + nonce + ".attempt.json"
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        lock_flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            lock = os.open(
                prefix + ".lock",
                lock_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent,
            )
        except FileExistsError:
            lock = os.open(prefix + ".lock", lock_flags, dir_fd=parent)
        # Kubelet fsGroup ownership may add group rw on a later volume mount.
        # Only the running identity and its configured primary group are trusted.
        info = os.fstat(lock)
        boot_require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.geteuid()
            and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) in (0o600, 0o660),
            "Invalid boot reservation lock",
        )
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        markers = []
        found = False
        with os.scandir(parent) as entries:
            for index, entry in enumerate(entries):
                boot_require(
                    index < BOOT_DIRECTORY_LIMIT,
                    "Restore directory inventory limit reached",
                )
                if not entry.name.startswith(prefix + "--"):
                    continue
                match = re.fullmatch(
                    re.escape(prefix) + r"--([0-9a-f]{32})\.attempt\.json", entry.name
                )
                boot_require(match is not None, "Unexpected boot marker name")
                fd = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    boot_require(
                        stat.S_ISREG(info.st_mode)
                        and info.st_nlink == 1
                        and info.st_uid == os.geteuid()
                        and info.st_gid == os.getegid()
                        and stat.S_IMODE(info.st_mode) in (0o600, 0o660),
                        "Invalid boot marker file",
                    )
                    raw = stream.read(4097)
                boot_require(len(raw) <= 4096, "Boot marker exceeds bound")
                item = strict_json(raw)
                boot_require(
                    isinstance(item, dict)
                    and set(item)
                    == {
                        "schema",
                        "station_mac",
                        "boot_nonce",
                        "node_id",
                        "ip",
                        "firmware_version",
                        "package_sha256",
                        "reserved_unix_ns",
                        "reserved_utc",
                        "status",
                    }
                    and item.get("schema") == BOOT_MARKER_SCHEMA
                    and item.get("station_mac") == mac
                    and item.get("boot_nonce") == match.group(1)
                    and valid_nonce(item.get("boot_nonce"))
                    and type(item.get("reserved_unix_ns")) is int
                    and BOOT_WINDOW_NS < item["reserved_unix_ns"] < 2**63
                    and type(item.get("node_id")) is int
                    and 1 <= item["node_id"] <= 10
                    and isinstance(item.get("ip"), str)
                    and str(ipaddress.IPv4Address(item["ip"])) == item["ip"]
                    and isinstance(item.get("firmware_version"), str)
                    and re.fullmatch(r"[0-9.]{1,32}", item["firmware_version"])
                    and isinstance(item.get("package_sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", item["package_sha256"])
                    and item.get("reserved_utc")
                    == datetime.fromtimestamp(
                        item["reserved_unix_ns"] // 1_000_000_000, timezone.utc
                    ).isoformat()
                    and item.get("status") == "attempt_reserved_outcome_may_be_unknown",
                    "Invalid retained boot reservation",
                )
                markers.append(item)
                found |= entry.name == filename
                boot_require(
                    len(markers) <= BOOT_MARKER_LIMIT,
                    "Boot marker retention limit reached",
                )
        if found:
            return False
        boot_require(
            len(markers) < BOOT_MARKER_LIMIT, "Boot marker retention limit reached"
        )
        boot_require(
            all(item["reserved_unix_ns"] <= now_ns for item in markers),
            "Reservation wall clock moved backwards",
        )
        boot_require(
            sum(item["reserved_unix_ns"] >= now_ns - BOOT_WINDOW_NS for item in markers)
            < BOOT_WINDOW_LIMIT,
            "Boot restore hourly attempt limit reached",
        )
        payload = {
            "schema": BOOT_MARKER_SCHEMA,
            "station_mac": mac,
            "boot_nonce": nonce,
            "node_id": target["node_id"],
            "ip": target["ip"],
            "firmware_version": target["firmware_version"],
            "package_sha256": package["sha256"],
            "reserved_unix_ns": now_ns,
            "reserved_utc": datetime.fromtimestamp(
                now_ns // 1_000_000_000, timezone.utc
            ).isoformat(),
            "status": "attempt_reserved_outcome_may_be_unknown",
        }
        raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
        fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            remaining = memoryview(raw)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Boot marker write did not advance")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
        return True
    finally:
        if lock is not None:
            os.close(lock)
        os.close(parent)


def capabilities(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("Invalid module capabilities")
    result = int(value, 16)
    if not 1 <= result <= 0x7F:
        raise ValueError("Invalid module capabilities")
    return result


def package_bytes(package, directory):
    filename = package["file"]
    if (
        not isinstance(filename, str)
        or not filename
        or filename in (".", "..")
        or any(character in filename for character in ("/", "\\", "\0"))
    ):
        raise ValueError("Package file must be a plain basename")
    directory = Path(directory).resolve(strict=True)
    # ConfigMaps project file -> ..data/file -> ..timestamp/file. Resolve once
    # and read that regular file, allowing descendants but never escapes.
    path = (directory / filename).resolve(strict=True)
    if not path.is_relative_to(directory) or not path.is_file():
        raise ValueError(
            "Package must be a regular file within the configured directory"
        )
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != package["sha256"]:
        raise ValueError("Signed package hash mismatch")
    if len(data) < 200 or data[:4] != b"RVF\x01":
        raise ValueError("Invalid RVF package")
    name = data[32:64].split(b"\0", 1)[0].decode("ascii")
    if (
        name != package["name"]
        or struct.unpack_from("<I", data, 12)[0] != package["wasm_bytes"]
    ):
        raise ValueError("Package manifest mismatch")
    return data


def reserve_restore_attempt(directory, target, package, data):
    """Consume the generation durably before any upload; never unlink a marker."""
    node_id, generation = target.get("node_id"), target.get("restore_generation")
    if type(node_id) is not int or not 1 <= node_id <= 255:
        raise ValueError("Invalid restore node identity")
    if not isinstance(generation, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", generation
    ):
        raise ValueError("Explicit valid restore generation is required")
    if directory is None:
        raise ValueError("Persistent restore state directory is required")
    directory = Path(directory)
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise ValueError("Restore state directory must be absolute and canonical")
    package_sha = hashlib.sha256(data).hexdigest()
    if package.get("sha256") != package_sha:
        raise ValueError("Signed package hash mismatch")
    firmware = target.get("firmware_version")
    if not isinstance(firmware, str) or not firmware:
        raise ValueError("Qualified firmware identity is required")
    # The canonical key deliberately excludes IP, firmware, package and its
    # hash: config changes cannot silently grant another automatic attempt.
    filename = f"node-{node_id}--{generation}.attempt.json"
    payload = (
        json.dumps(
            {
                "node_id": node_id,
                "restore_generation": generation,
                "firmware_version": firmware,
                "package_sha256": package_sha,
                "reserved_utc": datetime.now(timezone.utc).isoformat(),
                "status": "attempt_reserved_outcome_may_be_unknown",
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        marker_fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            remaining = memoryview(payload)
            while remaining:
                written = os.write(marker_fd, remaining)
                if written <= 0:
                    raise OSError("Restore marker write did not advance")
                remaining = remaining[written:]
            os.fsync(marker_fd)
        finally:
            os.close(marker_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def require_callback_diagnostics(slot, budget):
    """Firmware .7 must expose complete persistent callback-overrun evidence."""
    keys = ("max_frame_us", "max_timer_us", "frame_overruns", "timer_overruns")
    if not all(
        type(slot.get(key)) is int and 0 <= slot[key] <= 0xFFFFFFFF for key in keys
    ) or slot.get("max_us") != max(slot["max_frame_us"], slot["max_timer_us"]):
        raise ValueError("Callback diagnostics are missing or inconsistent")
    if slot["frame_overruns"] != 0 or slot["timer_overruns"] != 0:
        raise ValueError("Callback overrun history needs operator review")
    if slot["max_frame_us"] > budget or slot["max_timer_us"] > budget:
        raise ValueError("Callback maximum exceeds signed budget")


def require_empty_receiver(listing, version):
    """The qualified workload has one module and requires a fully empty device."""
    slots = listing.get("modules")
    if (
        type(listing.get("max")) is not int
        or listing["max"] != 4
        or type(listing.get("loaded")) is not int
        or listing["loaded"] != 0
        or not isinstance(slots, list)
        or len(slots) != 4
        or not all(type(slot.get("id")) is int for slot in slots)
        or {slot["id"] for slot in slots} != {0, 1, 2, 3}
    ):
        raise ValueError("Four unique empty slots are required for restoration")
    zero_fields = (
        "binary_size",
        "frame_count",
        "event_count",
        "error_count",
        "mean_us",
        "max_us",
        "budget_us",
        "budget_faults",
    )
    diagnostic_fields = (
        "max_frame_us",
        "max_timer_us",
        "frame_overruns",
        "timer_overruns",
    )
    for slot in slots:
        if (
            slot.get("state") != "empty"
            or slot.get("name") != ""
            or slot.get("caps") != "0x0000"
            or not all(
                type(slot.get(key)) is int and slot[key] == 0 for key in zero_fields
            )
            or not all(
                type(slot[key]) is int and slot[key] == 0
                for key in diagnostic_fields
                if key in slot
            )
        ):
            raise ValueError("Nonempty or inconsistent slots need operator review")
        if version in ("0.8.8.7", "0.8.8.8", *BOOT_VERSIONS):
            require_callback_diagnostics(slot, 0)


def boot_observation(target, request, *, monotonic=time.monotonic):
    status = request(target, "GET", "/ota/status", None)
    boot_require(isinstance(status, dict), "Boot status must be an object")
    boot_require(
        status.get("version") == target["firmware_version"],
        "Boot firmware changed or not qualified",
    )
    # Receiver uptime is sampled inside its HTTP handler, not when the caller
    # finishes reading the response. Retain the complete possible sample window.
    sample_started = monotonic()
    listing = request(target, "GET", "/wasm/list", None)
    sample_finished = monotonic()
    boot_require(
        0 <= sample_started <= sample_finished,
        "Invalid local runtime observation clock",
    )
    boot_require(isinstance(listing, dict), "Module listing must be an object")
    runtime = listing.get("runtime")
    boot_require(
        isinstance(runtime, dict), "Complete boot runtime diagnostics required"
    )
    for value in (status, runtime):
        boot_require(
            value.get("boot_nonce_schema") == BOOT_SCHEMA
            and valid_nonce(value.get("boot_nonce"))
            and value.get("station_mac") == target["mac"],
            "Boot identity or station MAC mismatch",
        )
    boot_require(
        status["boot_nonce"] == runtime["boot_nonce"],
        "Receiver rebooted during preflight",
    )
    boot_require(
        type(runtime.get("uptime_ms")) is int
        and 60_000 <= runtime["uptime_ms"] < 2**63,
        "Receiver minimum uptime is 60 seconds",
    )
    for key, minimum in (
        ("internal_free_bytes", 16384),
        ("internal_min_free_bytes", 16384),
        ("internal_largest_free_block", 8192),
        ("worker_stack_min_free_bytes", 4096),
    ):
        boot_require(
            type(runtime.get(key)) is int and minimum <= runtime[key] <= 0xFFFFFFFF,
            "Boot runtime memory margin failed",
        )
    boot_require(
        runtime.get("worker_stack_bytes") == 32768
        and type(runtime["worker_stack_bytes"]) is int
        and runtime["worker_stack_min_free_bytes"] <= runtime["worker_stack_bytes"]
        and runtime["internal_min_free_bytes"] <= runtime["internal_free_bytes"]
        and runtime["internal_largest_free_block"] <= runtime["internal_free_bytes"],
        "Inconsistent boot runtime memory diagnostics",
    )
    return status["boot_nonce"], listing, (sample_started, sample_finished)


def boot_runtime_state(listing, package, *, firmware_version="0.8.8.10"):
    slots = listing.get("modules")
    boot_require(
        type(listing.get("max")) is int
        and listing["max"] == 4
        and isinstance(slots, list)
        and len(slots) == 4
        and all(
            isinstance(slot, dict) and type(slot.get("id")) is int for slot in slots
        )
        and {slot["id"] for slot in slots} == {0, 1, 2, 3},
        "Four complete unique module slots required",
    )
    if listing.get("loaded") == 0:
        require_empty_receiver(listing, firmware_version)
        return "empty"
    selected = [slot for slot in slots if slot.get("name") == package["name"]]
    boot_require(
        type(listing.get("loaded")) is int
        and listing["loaded"] == 1
        and len(selected) == 1,
        "Unrelated modules need operator review",
    )
    slot = selected[0]
    boot_require(
        slot.get("state") == "running"
        and type(slot.get("binary_size")) is int
        and slot["binary_size"] == package["wasm_bytes"]
        and capabilities(slot.get("caps")) == capabilities(package["capabilities"])
        and type(slot.get("budget_us")) is int
        and slot["budget_us"] == package["max_frame_us"]
        and all(
            type(slot.get(key)) is int and slot[key] == 0
            for key in ("error_count", "budget_faults")
        ),
        "Existing module fault, stop or identity mismatch needs review",
    )
    boot_require(type(slot.get("max_us")) is int, "Integer callback maximum required")
    require_callback_diagnostics(slot, package["max_frame_us"])
    for other in slots:
        if other is slot:
            continue
        empty = {
            **listing,
            "loaded": 0,
            "modules": [dict(other, id=i) for i in range(4)],
        }
        require_empty_receiver(empty, firmware_version)
    # The API exposes name/size/capabilities, not the loaded binary hash. A
    # healthy existing instance is preserved, never claimed hash-attested.
    return "present_no_mutation"


def reconcile_boot(
    target, packages, request, *, state_directory, monotonic, sleep, wall_time_ns
):
    package, data = boot_binding(target, packages)
    started = monotonic()
    nonce, first, first_window = boot_observation(target, request, monotonic=monotonic)
    first_at = monotonic()
    first_state = boot_runtime_state(
        first, package, firmware_version=target["firmware_version"]
    )
    boot_require(0 <= first_at - started <= 25, "Boot preflight deadline exceeded")
    sleep(2)
    second_nonce, second, second_window = boot_observation(
        target, request, monotonic=monotonic
    )
    last_at = monotonic()
    boot_require(
        2 <= last_at - first_at <= 25 and last_at - started <= 50,
        "Boot preflight stability/deadline failed",
    )
    boot_require(nonce == second_nonce, "Receiver rebooted between observations")
    uptime_delta = second["runtime"]["uptime_ms"] - first["runtime"]["uptime_ms"]
    earliest_delta = (second_window[0] - first_window[1]) * 1000
    latest_delta = (second_window[1] - first_window[0]) * 1000
    boot_require(
        max(2000, earliest_delta - 500) <= uptime_delta <= latest_delta + 500,
        "Receiver uptime did not advance consistently",
    )
    state = boot_runtime_state(
        second, package, firmware_version=target["firmware_version"]
    )
    boot_require(state == first_state, "Module state changed during preflight")
    if state != "empty":
        return [package["name"] + ":" + state]
    if not reserve_boot_attempt(
        state_directory, target, package, nonce, wall_time_ns()
    ):
        return [package["name"] + ":boot_attempt_already_reserved"]
    reply = request(target, "POST", "/wasm/upload", data, headers={BOOT_HEADER: nonce})
    boot_require(
        isinstance(reply, dict)
        and reply.get("boot_nonce_schema") == BOOT_SCHEMA
        and reply.get("boot_nonce") == nonce
        and reply.get("name") == package["name"]
        and reply.get("started") is True,
        "Boot upload result unknown or mismatched; no retry",
    )
    return [package["name"] + ":restored"]


def reconcile(
    target,
    packages,
    request,
    *,
    state_directory=None,
    monotonic=time.monotonic,
    sleep=time.sleep,
    wall_time_ns=time.time_ns,
):
    if target.get("enabled", False):
        boot_require(
            target.get("firmware_version") in (*LEGACY_VERSIONS, *BOOT_VERSIONS),
            "Unsupported firmware version",
        )
    if target.get("enabled", False) and target.get("firmware_version") in BOOT_VERSIONS:
        boot_require(
            target.get("restore_mode") == BOOT_MODE,
            "Explicit .10/.11/.12 boot restore mode required",
        )
    if target.get("enabled", False) and target.get("restore_mode") is not None:
        boot_require(target["restore_mode"] == BOOT_MODE, "Unknown restore mode")
        return reconcile_boot(
            target,
            packages,
            request,
            state_directory=state_directory,
            monotonic=monotonic,
            sleep=sleep,
            wall_time_ns=wall_time_ns,
        )
    return reconcile_legacy(target, packages, request, state_directory=state_directory)


def reconcile_legacy(target, packages, request, *, state_directory=None):
    """Only one armed attempt into an empty device; stopped/fault states are kept."""
    if not target.get("enabled", False):
        return ["disabled"]
    # Check the complete manifest before even reading the receiver: an enabled
    # inventory flag alone cannot authorize a failed or unqualified package.
    for package, _ in packages:
        if package.get("deployment") != "qualified_for_auto_restore":
            raise ValueError("Package is not qualified for automatic restoration")
        capabilities(package["capabilities"])
        budget = package["max_frame_us"]
        if type(budget) is not int or not 1 <= budget <= 10000:
            raise ValueError("Invalid package execution budget")
    status = request(target, "GET", "/ota/status", None)
    if status.get("version") != target["firmware_version"]:
        return ["awaiting_qualified_firmware"]
    results = []
    for package, data in packages:
        listing = request(target, "GET", "/wasm/list", None)
        slots = listing.get("modules")
        if not isinstance(slots, list):
            raise ValueError("Receiver did not return module slots")
        existing = [slot for slot in slots if slot.get("name") == package["name"]]
        if existing:
            if len(existing) != 1:
                raise ValueError("Duplicate module names need operator review")
            slot = existing[0]
            if (
                slot.get("state") != "running"
                or type(slot.get("error_count")) is not int
                or slot["error_count"] != 0
                or type(slot.get("budget_faults")) is not int
                or slot["budget_faults"] != 0
            ):
                raise ValueError("Existing module fault or stop needs operator review")
            if (
                type(slot.get("binary_size")) is not int
                or slot["binary_size"] != package["wasm_bytes"]
                or capabilities(slot.get("caps"))
                != capabilities(package["capabilities"])
                or type(slot.get("budget_us")) is not int
                or slot["budget_us"] != package["max_frame_us"]
            ):
                raise ValueError("Module identity mismatch needs operator review")
            if (
                type(slot.get("max_us")) is not int
                or not 0 <= slot["max_us"] <= slot["budget_us"]
            ):
                raise ValueError("Module execution budget needs operator review")
            if target["firmware_version"] in ("0.8.8.7", "0.8.8.8"):
                require_callback_diagnostics(slot, slot["budget_us"])
            results.append(package["name"] + ":running")
            continue
        if len(packages) != 1:
            raise ValueError("Restoration requires exactly one selected package")
        require_empty_receiver(listing, target["firmware_version"])
        reserve_restore_attempt(state_directory, target, package, data)
        reply = request(target, "POST", "/wasm/upload", data)
        if reply.get("name") != package["name"] or reply.get("started") is not True:
            raise ValueError("Module failed to start; operator review required")
        results.append(package["name"] + ":restored")
    return results


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@contextmanager
def boot_http_deadline():
    """The opt-in CronJob uses its main thread; never override an existing alarm."""
    previous = signal.getsignal(signal.SIGALRM)
    boot_require(
        signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        and previous in (signal.SIG_DFL, signal.SIG_IGN),
        "Boot HTTP requires an unused process deadline timer",
    )

    def expired(_signum, _frame):
        raise TimeoutError("Boot HTTP absolute deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, 10)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def make_request():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(target, method, path, data, *, headers=None):
        boot = target.get("restore_mode") == BOOT_MODE
        outgoing = {"Content-Type": "application/octet-stream"}
        if boot:
            boot_require(
                (method, path)
                in (
                    ("GET", "/ota/status"),
                    ("GET", "/wasm/list"),
                    ("POST", "/wasm/upload"),
                ),
                "Unexpected boot request",
            )
            if method == "POST":
                boot_require(
                    isinstance(headers, dict)
                    and set(headers) == {BOOT_HEADER}
                    and valid_nonce(headers[BOOT_HEADER]),
                    "Expected boot header required",
                )
                outgoing.update(headers)
            else:
                boot_require(
                    headers is None and data is None,
                    "Boot GET cannot carry upload data",
                )
        else:
            boot_require(headers is None, "Legacy transport has no boot headers")
        req = urllib.request.Request(
            "http://" + target["ip"] + ":8032" + path,
            method=method,
            data=data,
            headers=outgoing,
        )
        if boot:
            with boot_http_deadline(), opener.open(req, timeout=10) as response:
                raw = response.read(65537)
                boot_require(len(raw) <= 65536, "Boot response exceeds bound")
                value = strict_json(raw)
                boot_require(isinstance(value, dict), "Boot response must be an object")
                return value
        with opener.open(req, timeout=15) as response:
            return json.load(response)

    return request


def load_approved_manifest(path, expected_sha256):
    """Read one bounded projection and authenticate exactly the bytes we parse.

    Kubernetes projects ConfigMaps through symlinks. Opening the selected file
    once supports those projections without trusting a later path re-read.
    """
    if not isinstance(expected_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_sha256
    ):
        raise ValueError("Independent module manifest SHA256 required")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Module manifest must be a regular file")
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Module manifest differs from independent approval")
    manifest = strict_json(raw)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("packages"), list):
        raise ValueError("Invalid module manifest")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument(
        "--state-directory",
        type=Path,
        help="Existing persistent canonical directory; missing path disables uploads",
    )
    args = parser.parse_args()
    manifest = load_approved_manifest(
        args.directory / "manifest.json", args.manifest_sha256
    )
    targets = json.loads((args.directory / "targets.json").read_text())
    packages = [(p, package_bytes(p, args.directory)) for p in manifest["packages"]]
    request = make_request()
    failed = False
    for target in targets:
        try:
            results = reconcile(
                target, packages, request, state_directory=args.state_directory
            )
            print(f"node{target['node_id']}: {','.join(results)}", flush=True)
        except (OSError, ValueError, KeyError, TypeError) as error:
            # Do not log raw responses or headers.
            print(
                f"node{target['node_id']}: review_required "
                f"({type(error).__name__}; reason={review_reason(error)})",
                flush=True,
            )
            failed = True
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
