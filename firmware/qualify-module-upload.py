#!/usr/bin/env python3
"""Controlled single-receiver signed upload; never retry an uncertain mutation automatically.

Scope: explicitly selected receiver, supported firmware and approved package.
Station bindings and supported versions require an independently approved context.
Run only after the independent empty-firmware baseline and passive CSI capture
pass. This helper does not qualify sustained execution or sensing accuracy.
"""

import argparse
import hashlib
import json
import math
import os
import struct
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:  # Direct script execution.
    from qualification_packages import HOME_SIGNAL, add_package_arguments, load_package
except ModuleNotFoundError as exc:  # Import by repository tests/tools.
    if exc.name != "qualification_packages":
        raise
    from firmware.qualification_packages import (
        HOME_SIGNAL,
        add_package_arguments,
        load_package,
    )

try:
    from qualification_receivers import (
        add_context_arguments,
        load_receiver,
        supports_version,
    )
except ModuleNotFoundError as exc:
    if exc.name != "qualification_receivers":
        raise
    from firmware.qualification_receivers import (
        add_context_arguments,
        load_receiver,
        supports_version,
    )

# Inert compatibility aliases never select an installed package.
PACKAGE = HOME_SIGNAL.path
PACKAGE_SHA = HOME_SIGNAL.package_sha256
WASM_SHA = HOME_SIGNAL.wasm_sha256
EXPECTED_VERSIONS = (
    "0.8.8.5",
    "0.8.8.6",
    "0.8.8.7",
    "0.8.8.8",
    "0.8.8.10",
    "0.8.8.11",
    "0.8.8.12",
)
RECOVERY_VERSION = "0.8.8.10"  # Historical default for direct callers.
RECOVERY_VERSIONS = (RECOVERY_VERSION, "0.8.8.11", "0.8.8.12")
BOOT_SCHEMA = "ruview.boot-nonce.v1"
BOOT_KEYS = ("boot_nonce_schema", "boot_nonce", "station_mac")
MAX_DEVICE_REPLY_BYTES = 65536
PING_STABLE_COUNTERS = (
    "attempts",
    "starts",
    "create_failures",
    "start_failures",
    "stop_failures",
    "delete_failures",
    "stalls",
    "ends",
    "network_epoch",
)
PING_CALLBACK_COUNTERS = ("successes", "timeouts")
PING_MAX_AGE_MS = 3000
CALLBACK_KEYS = ("max_frame_us", "max_timer_us", "frame_overruns", "timer_overruns")
SLOT_KEYS = (
    "id",
    "state",
    "name",
    "binary_size",
    "caps",
    "frame_count",
    "event_count",
    "error_count",
    "mean_us",
    "max_us",
    "budget_us",
    "budget_faults",
)
RUNTIME_KEYS = (
    "uptime_ms",
    "worker_stack_bytes",
    "worker_stack_min_free_bytes",
    "internal_free_bytes",
    "internal_min_free_bytes",
    "internal_largest_free_block",
)
REPLY_KEYS = (
    "status",
    "format",
    "module_id",
    "name",
    "wasm_size",
    "caps",
    "budget_us",
    "started",
)


class GateError(ValueError):
    """Only fixed, nonsecret error codes are stored in the report."""


def require(condition, code):
    if not condition:
        raise GateError(code)


def integer(value, low=0, high=0xFFFFFFFF):
    return type(value) is int and low <= value <= high


def recovery_identity(value, *, receiver):
    nonce = value.get("boot_nonce")
    if not (
        value.get("boot_nonce_schema") == BOOT_SCHEMA
        and value.get("station_mac") == receiver.station_mac
        and isinstance(nonce, str)
        and len(nonce) == 32
        and all(c in "0123456789abcdef" for c in nonce)
        and nonce != "0" * 32
    ):
        raise GateError("boot_identity_invalid")
    return nonce


def recovery_status(
    status,
    partition,
    expected_nonce=None,
    *,
    receiver,
    expected_version=RECOVERY_VERSION,
):
    if (
        expected_version not in RECOVERY_VERSIONS
        or status.get("version") != expected_version
        or status.get("running_partition") != partition
    ):
        raise GateError("firmware_or_partition_mismatch")
    nonce = recovery_identity(status, receiver=receiver)
    if expected_nonce is not None and nonce != expected_nonce:
        raise GateError("boot_nonce_changed")
    return nonce


def validate_self_ping(ping):
    if not isinstance(ping, dict) or not (
        ping.get("state") == "running"
        and ping.get("supervisor_started") is True
        and ping.get("last_progress_age_basis") == "session_start_or_ping_callback"
        and integer(ping.get("last_progress_age_ms"), 0, PING_MAX_AGE_MS)
        and all(
            integer(ping.get(k), 0, 0xFFFFFFFF)
            for k in (*PING_STABLE_COUNTERS, *PING_CALLBACK_COUNTERS)
        )
        and ping["starts"] >= 1
        and ping["attempts"] >= ping["starts"]
        and type(ping.get("last_error")) is int
        and ping["last_error"] == 0
    ):
        raise GateError("self_ping_not_healthy")


def self_ping_continuity(before, after):
    validate_self_ping(before)
    validate_self_ping(after)
    if any(after[k] != before[k] for k in PING_STABLE_COUNTERS) or any(
        after[k] < before[k] for k in PING_CALLBACK_COUNTERS
    ):
        raise GateError("self_ping_lifecycle_changed")


def validate_package(data, package=HOME_SIGNAL):
    require(package.enabled, "package_profile_unavailable")
    require(
        hashlib.sha256(data).hexdigest() == package.package_sha256,
        "package_sha_mismatch",
    )
    require(len(data) == package.package_bytes, "package_size_mismatch")
    require(
        struct.unpack_from("<IHHIIIIII", data)
        == (0x01465652, 1, 1, 96, package.wasm_bytes, 64, 0, package.package_bytes, 0),
        "package_header_mismatch",
    )
    require(
        data[32:64].split(b"\0", 1)[0] == package.name.encode("ascii"),
        "package_name_mismatch",
    )
    require(
        struct.unpack_from("<HII", data, 64) == (1, 0x6B, 10000),
        "package_manifest_mismatch",
    )
    require(
        hashlib.sha256(data[128:-64]).hexdigest() == package.wasm_sha256,
        "wasm_sha_mismatch",
    )
    require(data[80:112].hex() == package.wasm_sha256, "embedded_wasm_sha_mismatch")


def validate_snapshot(
    snapshot,
    partition,
    module_id=None,
    package=HOME_SIGNAL,
    *,
    receiver,
    expected_version="0.8.8.5",
):
    require(expected_version in EXPECTED_VERSIONS, "invalid_expected_version")
    require(
        supports_version(receiver, expected_version), "receiver_version_not_supported"
    )
    status, listing = snapshot["status"], snapshot["listing"]
    require(
        status["version"] == expected_version
        and status["running_partition"] == partition,
        "firmware_or_partition_mismatch",
    )
    if expected_version in RECOVERY_VERSIONS:
        nonce = recovery_status(
            status, partition, expected_version=expected_version, receiver=receiver
        )
        require(
            recovery_identity(listing["runtime"], receiver=receiver) == nonce,
            "boot_nonce_status_list_mismatch",
        )
        validate_self_ping(listing["runtime"].get("self_ping"))
    slots = listing["modules"]
    require(
        integer(listing["max"], 4, 4) and isinstance(slots, list) and len(slots) == 4,
        "four_slots_required",
    )
    require(
        all(integer(s["id"], 0, 3) for s in slots)
        and {s["id"] for s in slots} == {0, 1, 2, 3},
        "slot_ids_invalid",
    )
    if expected_version in ("0.8.8.7", "0.8.8.8", *RECOVERY_VERSIONS):
        for slot in slots:
            require(
                all(integer(slot.get(key)) for key in (*CALLBACK_KEYS, "max_us")),
                "callback_metrics_invalid",
            )
            require(
                slot["max_us"] == max(slot["max_frame_us"], slot["max_timer_us"]),
                "callback_maximum_mismatch",
            )
            require(
                slot["frame_overruns"] == 0 and slot["timer_overruns"] == 0,
                "callback_overrun_recorded",
            )
            if slot["state"] == "empty":
                require(
                    all(slot[key] == 0 for key in (*CALLBACK_KEYS, "max_us")),
                    "empty_callback_metrics_nonzero",
                )
            else:
                require(
                    slot["max_frame_us"] <= 10000 and slot["max_timer_us"] <= 10000,
                    "callback_budget_exceeded",
                )
    runtime = listing["runtime"]
    require(integer(runtime["uptime_ms"], 1, (1 << 64) - 1), "uptime_unavailable")
    require(integer(runtime["worker_stack_bytes"], 32768, 32768), "worker_stack_size")
    require(
        integer(runtime["worker_stack_min_free_bytes"], 4096, 32768),
        "worker_stack_margin",
    )
    free, low, block = (
        runtime[k]
        for k in (
            "internal_free_bytes",
            "internal_min_free_bytes",
            "internal_largest_free_block",
        )
    )
    require(
        integer(free)
        and integer(low, 16384)
        and low <= free
        and integer(block, 8192)
        and block <= free,
        "internal_heap_margin",
    )
    if module_id is None:
        require(
            integer(listing["loaded"], 0, 0)
            and all(s["state"] == "empty" for s in slots),
            "slots_not_empty",
        )
        return
    require(
        integer(module_id, 0, 3) and integer(listing["loaded"], 1, 1),
        "loaded_module_count",
    )
    module = next(s for s in slots if s["id"] == module_id)
    require(
        all(s["state"] == "empty" for s in slots if s["id"] != module_id),
        "unexpected_other_module",
    )
    require(
        module["state"] == "running"
        and module["name"] == package.name
        and integer(module["binary_size"], package.wasm_bytes, package.wasm_bytes)
        and module["caps"] == "0x006b"
        and integer(module["budget_us"], 10000, 10000),
        "running_module_metadata",
    )
    require(
        integer(module["error_count"], 0, 0) and integer(module["budget_faults"], 0, 0),
        "immediate_module_fault",
    )
    require(
        integer(module["frame_count"])
        and integer(module["event_count"])
        and integer(module["max_us"], 0, 10000)
        and integer(module["mean_us"], 0, module["max_us"]),
        "immediate_module_telemetry",
    )


def validate_continuity(before, after, *, receiver, expected_version="0.8.8.5"):
    old, new = before["listing"]["runtime"], after["listing"]["runtime"]
    require(new["uptime_ms"] > old["uptime_ms"], "uptime_reset_or_stall")
    if expected_version in RECOVERY_VERSIONS:
        require(
            recovery_identity(old, receiver=receiver)
            == recovery_identity(new, receiver=receiver),
            "boot_nonce_changed",
        )
        self_ping_continuity(old["self_ping"], new["self_ping"])
    # Each read happened somewhere within its local request interval. The same
    # boot epoch must fit both intervals, allowing 0.5 s total clock tolerance.
    lower = max(
        s["request_start_s"] - s["listing"]["runtime"]["uptime_ms"] / 1000
        for s in (before, after)
    )
    upper = min(
        s["received_s"] - s["listing"]["runtime"]["uptime_ms"] / 1000
        for s in (before, after)
    )
    require(lower <= upper + 0.5, "uptime_disagrees_with_elapsed")
    require(
        new["worker_stack_min_free_bytes"] <= old["worker_stack_min_free_bytes"]
        and new["internal_min_free_bytes"] <= old["internal_min_free_bytes"],
        "low_watermarks_reset",
    )


def validate_reply(reply, package=HOME_SIGNAL, *, expected_nonce=None):
    require(isinstance(reply, dict), "upload_reply_not_object")
    require(
        reply["status"] == "ok"
        and reply["format"] == "rvf"
        and reply["name"] == package.name
        and reply["started"] is True,
        "upload_did_not_start_expected_module",
    )
    require(
        integer(reply["module_id"], 0, 3)
        and integer(reply["wasm_size"], package.wasm_bytes, package.wasm_bytes)
        and reply["caps"] == "0x006b"
        and integer(reply["budget_us"], 10000, 10000),
        "upload_reply_metadata",
    )
    if expected_nonce is not None:
        require(
            reply.get("boot_nonce_schema") == BOOT_SCHEMA
            and reply.get("boot_nonce") == expected_nonce,
            "upload_reply_boot_nonce_mismatch",
        )
    return reply["module_id"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def reject_constant(value):
    raise ValueError("Invalid numeric JSON")


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Invalid numeric JSON")
    return result


def make_request(*, receiver, revalidate):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(method, path, data=None, *, expected_boot_nonce=None):
        require(
            (method, path)
            in (
                ("GET", "/ota/status"),
                ("GET", "/wasm/list"),
                ("POST", "/wasm/upload"),
            ),
            "unexpected_request",
        )
        headers = {"Content-Type": "application/octet-stream"}
        if expected_boot_nonce is not None:
            require(
                method == "POST"
                and isinstance(expected_boot_nonce, str)
                and len(expected_boot_nonce) == 32
                and all(c in "0123456789abcdef" for c in expected_boot_nonce)
                and expected_boot_nonce != "0" * 32,
                "invalid_expected_boot_nonce_header",
            )
            headers["X-RuView-Expected-Boot-Nonce"] = expected_boot_nonce
        revalidate()
        req = urllib.request.Request(
            receiver.base_url + path,
            data=data,
            method=method,
            headers=headers,
        )
        with opener.open(req, timeout=45 if method == "POST" else 5) as reply:
            require(reply.status == 200, "unexpected_http_success_status")
            body = reply.read(MAX_DEVICE_REPLY_BYTES + 1)
            require(len(body) <= MAX_DEVICE_REPLY_BYTES, "device_reply_too_large")
            return json.loads(
                body, parse_constant=reject_constant, parse_float=finite_float
            )

    return request


def run_upload(
    data,
    partition,
    request,
    checkpoint,
    clock=time.monotonic,
    *,
    receiver,
    package=HOME_SIGNAL,
    expected_version="0.8.8.5",
    revalidate,
):
    """Injectable state machine; exactly one valid POST at most, even on failure."""
    report = {
        "receiver": receiver.metadata(),
        "package_profile": package.profile,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "expected_partition": partition,
        "expected_version": expected_version,
        "passed": False,
        "phase": "input_validation",
        "control_post_attempted": False,
        "valid_post_attempted": False,
        "outcome": "not_attempted",
        "snapshots": [],
        "errors": [],
        "package_sha256": hashlib.sha256(data).hexdigest(),
        "package_bytes": len(data),
        "sustained_runtime_qualified": False,
        "recognition_accuracy_qualified": False,
        "limitations": [
            "A successful independent empty-firmware baseline and 64-bin passive CSI capture are prerequisites.",
            "A missing or invalid upload response can mean the device accepted the module. Never automatically retry; inspect the saved state first.",
            "A corrupt-signature HTTP 403 plus valid signed upload is a control test. The device does not expose a live module digest.",
            "Only immediate lifecycle state is checked here; the separate >=305 s module observation must pass before deployment qualification.",
        ],
    }
    start = clock()

    def save(phase=None):
        if phase:
            report["phase"] = phase
        checkpoint(report)

    def failure(exc, stage):
        detail = {"stage": stage, "type": type(exc).__name__}
        if isinstance(exc, GateError):
            detail["code"] = str(exc)  # GateError messages are fixed codes only.
        if isinstance(exc, urllib.error.HTTPError):
            detail["http_status"] = exc.code
            exc.close()
        report["errors"].append(detail)

    def snapshot(label):
        requested = clock() - start
        raw_status = request("GET", "/ota/status")
        require(
            raw_status.get("version") == expected_version
            and raw_status.get("running_partition") == partition,
            "firmware_or_partition_mismatch",
        )
        if expected_version in RECOVERY_VERSIONS:
            nonce = recovery_status(
                raw_status,
                partition,
                report.get("boot_nonce"),
                expected_version=expected_version,
                receiver=receiver,
            )
            report["boot_nonce"] = nonce
        raw_list = request("GET", "/wasm/list")
        slot_keys = SLOT_KEYS + (
            CALLBACK_KEYS
            if expected_version in ("0.8.8.7", "0.8.8.8", *RECOVERY_VERSIONS)
            else ()
        )
        result = {
            "label": label,
            "request_start_s": requested,
            "received_s": clock() - start,
            "status": {
                k: raw_status.get(k)
                for k in ("version", "running_partition")
                + (BOOT_KEYS if expected_version in RECOVERY_VERSIONS else ())
            },
            "listing": {
                "loaded": raw_list.get("loaded"),
                "max": raw_list.get("max"),
                "modules": [
                    {k: s.get(k) for k in slot_keys} for s in raw_list["modules"]
                ],
                "runtime": {
                    k: raw_list["runtime"].get(k)
                    for k in RUNTIME_KEYS
                    + (
                        BOOT_KEYS + ("self_ping",)
                        if expected_version in RECOVERY_VERSIONS
                        else ()
                    )
                },
            },
        }
        report["snapshots"].append(result)
        save()
        return result

    def post(data):
        if expected_version in RECOVERY_VERSIONS:
            return request(
                "POST", "/wasm/upload", data, expected_boot_nonce=report["boot_nonce"]
            )
        return request("POST", "/wasm/upload", data)

    try:
        save()
        require(expected_version in EXPECTED_VERSIONS, "invalid_expected_version")
        require(
            supports_version(receiver, expected_version),
            "receiver_version_not_supported",
        )
        require(partition in ("ota_0", "ota_1"), "invalid_expected_partition")
        validate_package(data, package)
        save("preflight")
        before = snapshot("before_control")
        validate_snapshot(
            before,
            partition,
            package=package,
            expected_version=expected_version,
            receiver=receiver,
        )
        bad = bytearray(data)
        bad[-1] ^= 1  # The final byte belongs to the Ed25519 signature.
        revalidate()
        report["control_post_attempted"] = True
        report["outcome"] = "control_outcome_uncertain"
        save("corrupt_signature_post")  # Durable before the mutation begins.
        try:
            reply = post(bytes(bad))
        except urllib.error.HTTPError as exc:
            report["invalid_signature_http"] = exc.code
            code = exc.code
            exc.close()
            require(code == 403, "corrupt_signature_expected_http403")
        else:
            report["unexpected_control_reply"] = (
                {
                    k: reply.get(k)
                    for k in REPLY_KEYS
                    + (
                        ("boot_nonce_schema", "boot_nonce")
                        if expected_version in RECOVERY_VERSIONS
                        else ()
                    )
                }
                if isinstance(reply, dict)
                else {"type": type(reply).__name__}
            )
            raise GateError("corrupt_signature_was_not_rejected")
        report["outcome"] = "control_rejected_pending_empty_recheck"
        save("empty_recheck")
        after_control = snapshot("after_control")
        validate_snapshot(
            after_control,
            partition,
            package=package,
            expected_version=expected_version,
            receiver=receiver,
        )
        validate_continuity(
            before, after_control, expected_version=expected_version, receiver=receiver
        )
        revalidate()
        report["valid_post_attempted"] = True
        report["outcome"] = "valid_upload_outcome_uncertain"
        save("valid_signed_post")  # Never repeat this POST after any outcome.
        try:
            reply = post(data)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve an uncertain mutation, never expose exception text
            failure(exc, "valid_signed_post")
            # One bounded read-only inspection, not a repeat POST. This cannot
            # turn a lost/malformed response into a successful qualification.
            try:
                snapshot("readback_after_uncertain_post")
            except (Exception, KeyboardInterrupt) as read_exc:  # noqa: BLE001
                failure(read_exc, "uncertain_readback")
            save("operator_review_required")
            return report
        report["valid_upload_reply"] = (
            {
                k: reply.get(k)
                for k in REPLY_KEYS
                + (
                    ("boot_nonce_schema", "boot_nonce")
                    if expected_version in RECOVERY_VERSIONS
                    else ()
                )
            }
            if isinstance(reply, dict)
            else {"type": type(reply).__name__}
        )
        save("valid_reply_validation")
        module_id = validate_reply(
            reply,
            package,
            expected_nonce=report.get("boot_nonce")
            if expected_version in RECOVERY_VERSIONS
            else None,
        )
        report["module_id"] = module_id
        report["outcome"] = "upload_acknowledged_pending_state"
        save("running_state_check")
        after_upload = snapshot("after_valid_upload")
        validate_snapshot(
            after_upload,
            partition,
            module_id,
            package,
            expected_version=expected_version,
            receiver=receiver,
        )
        validate_continuity(
            before, after_upload, expected_version=expected_version, receiver=receiver
        )
        validate_continuity(
            after_control,
            after_upload,
            expected_version=expected_version,
            receiver=receiver,
        )
        revalidate()
        report["passed"] = True
        report["outcome"] = "immediate_running_state_confirmed_trial_required"
        save("complete")
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - fail closed and preserve attempted flags
        failure(exc, report["phase"])
        if not report["control_post_attempted"]:
            report["outcome"] = "preflight_rejected_no_upload"
        elif not report["valid_post_attempted"]:
            report["outcome"] = "control_or_recheck_failed_no_valid_upload"
        save("operator_review_required")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--expect-partition", choices=("ota_0", "ota_1"), required=True)
    parser.add_argument("--expected-version", choices=EXPECTED_VERSIONS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    add_package_arguments(parser)
    add_context_arguments(parser)
    args = parser.parse_args()
    receiver = load_receiver(args)
    approval = {
        "site_context_sha256": args.site_context_sha256,
        "installation_identity_sha256": args.installation_identity_sha256,
        "package_catalog_sha256": args.package_catalog_sha256,
    }

    def revalidate():
        if load_package(args) != package:
            raise ValueError("qualification_package_changed")
        if load_receiver(args) != receiver:
            raise ValueError("qualification_receiver_changed")

    try:
        package = load_package(args)
    except ValueError as exc:
        parser.error(str(exc))
    os.umask(0o077)
    # Existing reports are never opened for writing. Checkpoints only update
    # this new report; flush/fsync saves the attempted flag before either POST.
    revalidate()
    with args.output.open("x") as output:

        def checkpoint(report):
            report["installation_approval"] = approval
            contents = json.dumps(report, indent=2, allow_nan=False) + "\n"
            output.seek(0)
            output.write(contents)
            output.truncate()
            output.flush()
            os.fsync(output.fileno())

        try:
            data = package.path.read_bytes()
        except OSError as exc:
            checkpoint(
                {
                    "passed": False,
                    "package_profile": package.profile,
                    "expected_version": args.expected_version,
                    "outcome": "package_read_failed_no_upload",
                    "error_type": type(exc).__name__,
                }
            )
            return 1
        report = run_upload(
            data,
            args.expect_partition,
            make_request(receiver=receiver, revalidate=revalidate),
            checkpoint,
            package=package,
            expected_version=args.expected_version,
            receiver=receiver,
            revalidate=revalidate,
        )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "passed",
                    "outcome",
                    "phase",
                    "valid_post_attempted",
                    "errors",
                )
            },
            indent=2,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
