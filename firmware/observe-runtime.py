#!/usr/bin/env python3
"""Read-only single-receiver runtime trial; passing never qualifies recognition accuracy.

Scope: explicitly selected receiver, supported firmware and approved package.
Station bindings and supported versions require an independently approved context.
Requires websockets 15 and RUVIEW_API_TOKEN in the environment. Never uploads,
reboots, reads credential files, or retries a mutation. A module trial assumes
the operator already performed the controlled signed upload of the pinned RVF.
"""

import argparse
import asyncio
import hashlib
import json
import math
import os
import time
import urllib.request
from datetime import datetime, timezone
from itertools import pairwise
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

from scripts.collector_profile import add_profile_arguments, load_profile  # noqa: E402

# Inert compatibility aliases never select an installed package.
PACKAGE_SHA = HOME_SIGNAL.package_sha256
PACKAGE = HOME_SIGNAL.path
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
LIMITS = {
    "minimum_duration_s": 305,
    "max_uncovered_s": 5,
    "max_csi_age_ms": 3000,
    "uptime_clock_tolerance_s": 0.5,
    "worker_stack_bytes": 32768,
    "minimum_worker_free_bytes": 4096,
    "minimum_internal_free_bytes": 16384,
    "minimum_largest_internal_block_bytes": 8192,
    "max_module_us": 10000,
    "max_ws_message_age_s": 10,
    "max_future_clock_skew_s": 0.25,
}


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def integer(value, minimum=0, maximum=None):
    return (
        type(value) is int
        and value >= minimum
        and (maximum is None or value <= maximum)
    )


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
        raise ValueError("boot_identity_invalid")
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
        raise ValueError("firmware_or_partition_mismatch")
    nonce = recovery_identity(status, receiver=receiver)
    if expected_nonce is not None and nonce != expected_nonce:
        raise ValueError("boot_nonce_changed")
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
        raise ValueError("self_ping_not_healthy")


def self_ping_continuity(before, after):
    validate_self_ping(before)
    validate_self_ping(after)
    if any(after[k] != before[k] for k in PING_STABLE_COUNTERS) or any(
        after[k] < before[k] for k in PING_CALLBACK_COUNTERS
    ):
        raise ValueError("self_ping_lifecycle_changed")


def coverage(times, elapsed):
    valid = (
        number(elapsed)
        and elapsed > 0
        and len(times) >= 2
        and all(number(t) and 0 <= t <= elapsed for t in times)
        and all(b > a for a, b in pairwise(times))
    )
    if not valid:
        return {"passed": False, "samples": len(times), "max_uncovered_s": None}
    gaps = [times[0], elapsed - times[-1], *[b - a for a, b in pairwise(times)]]
    return {
        "passed": max(gaps) <= LIMITS["max_uncovered_s"],
        "samples": len(times),
        "start_uncovered_s": times[0],
        "end_uncovered_s": elapsed - times[-1],
        "sample_span_s": times[-1] - times[0],
        "max_uncovered_s": max(gaps),
    }


def evaluate(report, package=HOME_SIGNAL, *, receiver, expected_version="0.8.8.5"):
    """Pure evaluator: malformed/missing evidence fails closed, including -O."""
    failures = []
    metrics = {}

    def require(condition, reason):
        if not condition and reason not in failures:
            failures.append(reason)

    try:
        require(expected_version in EXPECTED_VERSIONS, "invalid_expected_version")
        require(
            supports_version(receiver, expected_version),
            "receiver_version_not_supported",
        )
        require(
            report.get("receiver") == receiver.metadata(),
            "receiver_binding_mismatch",
        )
        # Reports written before explicit version selection describe only .5.
        require(
            report.get("expected_version", "0.8.8.5") == expected_version,
            "expected_version_mismatch",
        )
        require(package.enabled, "package_profile_unavailable")
        require(
            report.get("package_profile", "home-signal") == package.profile,
            "package_profile_mismatch",
        )
        elapsed = report["elapsed_s"]
        mode = report["mode"]
        module_id = report["module_id"]
        partition = report["expected_partition"]
        require(mode in ("baseline", "module"), "invalid_mode")
        require(partition in ("ota_0", "ota_1"), "invalid_expected_partition")
        require(integer(module_id, 0, 3), "invalid_module_id")
        require(
            number(elapsed) and elapsed >= LIMITS["minimum_duration_s"],
            "short_duration",
        )
        require(report["errors"] == [], "transport_or_capture_error")
        require(
            report["local_package_sha256"] == package.package_sha256,
            "local_package_mismatch",
        )
        samples = report["samples"]
        updates = report["ws_updates"]
        events = report["wasm_packets"]
        for name, times in (
            ("http_coverage", [s["received_s"] for s in samples]),
            ("accepted_csi_coverage", [s["csi_received_s"] for s in samples]),
            ("ws_coverage", [s["received_s"] for s in updates]),
        ):
            metrics[name] = coverage(times, elapsed)
            require(metrics[name]["passed"], name)
        require(
            number(report["ws_opened_s"]) and 0 <= report["ws_opened_s"] <= 5,
            "ws_missing_start",
        )
        require(
            number(report["ws_closed_s"]) and 0 <= elapsed - report["ws_closed_s"] <= 5,
            "ws_missing_end",
        )
        previous = None
        boot_nonce = None
        ping_advances = []
        previous_ping = None
        ping_ages = []
        boot_lowers, boot_uppers = [], []
        stack_margins, heap_margins, heap_blocks, ages, modules = [], [], [], [], []
        for sample in samples:
            started, received = sample["request_start_s"], sample["received_s"]
            require(
                number(started) and 0 <= started <= received <= elapsed,
                "request_time_invalid",
            )
            require(
                received <= sample["csi_received_s"] <= elapsed,
                "csi_receipt_order_invalid",
            )
            status, listing, csi = sample["status"], sample["listing"], sample["csi"]
            require(
                status["version"] == expected_version
                and status["running_partition"] == partition,
                "firmware_or_slot_changed",
            )
            slots = listing["modules"]
            require(
                listing["max"] == 4
                and len(slots) == 4
                and all(integer(s["id"], 0, 3) for s in slots)
                and {s["id"] for s in slots} == {0, 1, 2, 3},
                "slot_inventory_invalid",
            )
            if expected_version in ("0.8.8.7", "0.8.8.8", *RECOVERY_VERSIONS):
                for slot in slots:
                    valid_metrics = all(
                        integer(slot.get(key), 0, 0xFFFFFFFF)
                        for key in (*CALLBACK_KEYS, "max_us")
                    )
                    require(valid_metrics, "callback_metrics_invalid")
                    if valid_metrics:
                        require(
                            slot["max_us"]
                            == max(slot["max_frame_us"], slot["max_timer_us"]),
                            "callback_maximum_mismatch",
                        )
                        require(
                            slot["frame_overruns"] == 0 and slot["timer_overruns"] == 0,
                            "callback_overrun_recorded",
                        )
                        if slot["state"] == "empty":
                            require(
                                all(
                                    slot[key] == 0 for key in (*CALLBACK_KEYS, "max_us")
                                ),
                                "empty_callback_metrics_nonzero",
                            )
                        else:
                            require(
                                slot["max_frame_us"] <= 10000
                                and slot["max_timer_us"] <= 10000,
                                "callback_budget_exceeded",
                            )
            runtime = listing["runtime"]
            if expected_version in RECOVERY_VERSIONS:
                nonce = recovery_status(
                    status,
                    partition,
                    boot_nonce,
                    expected_version=expected_version,
                    receiver=receiver,
                )
                require(
                    recovery_identity(runtime, receiver=receiver) == nonce,
                    "boot_nonce_status_list_mismatch",
                )
                boot_nonce = nonce
                ping = runtime.get("self_ping")
                validate_self_ping(ping)
                ping_ages.append(ping["last_progress_age_ms"])
                if previous_ping is not None:
                    self_ping_continuity(previous_ping, ping)
                if previous_ping is None or sum(
                    ping[k] for k in PING_CALLBACK_COUNTERS
                ) > sum(previous_ping[k] for k in PING_CALLBACK_COUNTERS):
                    ping_advances.append(received)
                previous_ping = ping
            uptime = runtime["uptime_ms"]
            free = runtime["internal_free_bytes"]
            low = runtime["internal_min_free_bytes"]
            block = runtime["internal_largest_free_block"]
            stack = runtime["worker_stack_min_free_bytes"]
            require(integer(uptime, 1), "uptime_invalid")
            require(
                runtime["worker_stack_bytes"] == LIMITS["worker_stack_bytes"],
                "worker_stack_size",
            )
            require(
                integer(stack, LIMITS["minimum_worker_free_bytes"], 32768),
                "worker_stack_margin",
            )
            require(
                integer(low, LIMITS["minimum_internal_free_bytes"]),
                "internal_heap_margin",
            )
            require(
                integer(free)
                and integer(block, LIMITS["minimum_largest_internal_block_bytes"])
                and low <= free
                and block <= free,
                "internal_heap_shape_or_block",
            )
            boot_lowers.append(started - uptime / 1000)
            boot_uppers.append(received - uptime / 1000)
            stack_margins.append(stack)
            heap_margins.append(low)
            heap_blocks.append(block)
            require(
                integer(csi["node_id"]) and csi["node_id"] == receiver.node_id,
                "csi_node_mismatch",
            )
            age, sequence = csi["csi_last_seen_ms"], csi["csi_sequence"]
            require(
                csi["csi_status"] == "active"
                and number(age)
                and 0 <= age <= LIMITS["max_csi_age_ms"],
                "csi_not_fresh",
            )
            require(integer(sequence, 0, 0xFFFFFFFF), "csi_sequence_invalid")
            ages.append(age)
            module = None
            if mode == "baseline":
                require(
                    listing["loaded"] == 0
                    and all(s["state"] == "empty" for s in slots),
                    "baseline_not_empty",
                )
            else:
                require(listing["loaded"] == 1, "module_count")
                module = next(s for s in slots if s["id"] == module_id)
                require(
                    all(s["state"] == "empty" for s in slots if s["id"] != module_id),
                    "unexpected_other_module",
                )
                require(
                    module["name"] == package.name
                    and module["state"] == "running"
                    and module["binary_size"] == package.wasm_bytes
                    and module["caps"] == "0x006b"
                    and module["budget_us"] == 10000,
                    "module_metadata_or_state",
                )
                require(
                    integer(module["error_count"])
                    and module["error_count"] == 0
                    and integer(module["budget_faults"])
                    and module["budget_faults"] == 0,
                    "module_fault",
                )
                require(
                    integer(module["frame_count"], 1, 0xFFFFFFFF)
                    and integer(module["event_count"], 0, 0xFFFFFFFF),
                    "module_counters_invalid",
                )
                # budget_faults clears only after a frame below 5 ms; frames
                # between 5 and 10 ms do not clear it. Persistent max_us also
                # catches a transient overrun between HTTP observations.
                require(
                    integer(module["max_us"], 1, 10000)
                    and integer(module["mean_us"], 0, module["max_us"]),
                    "module_budget_exceeded",
                )
                modules.append(module)
            if previous:
                old_runtime, old_csi, old_module = previous
                require(uptime > old_runtime["uptime_ms"], "uptime_reset_or_stall")
                require(
                    stack <= old_runtime["worker_stack_min_free_bytes"]
                    and low <= old_runtime["internal_min_free_bytes"],
                    "low_watermark_reset",
                )
                require(
                    0
                    < ((sequence - old_csi["csi_sequence"]) & 0xFFFFFFFF)
                    < 0x80000000,
                    "csi_sequence_reset_or_stall",
                )
                if module:
                    require(
                        module["frame_count"] > old_module["frame_count"],
                        "module_frames_reset_or_stall",
                    )
                    require(
                        module["event_count"] >= old_module["event_count"]
                        and module["max_us"] >= old_module["max_us"],
                        "module_telemetry_reset",
                    )
                    if expected_version in ("0.8.8.7", "0.8.8.8", *RECOVERY_VERSIONS):
                        require(
                            all(
                                integer(module.get(key), 0, 0xFFFFFFFF)
                                and integer(old_module.get(key), 0, 0xFFFFFFFF)
                                and module[key] >= old_module[key]
                                for key in CALLBACK_KEYS
                            ),
                            "callback_telemetry_reset",
                        )
            previous = runtime, csi, module
        if expected_version in RECOVERY_VERSIONS:
            metrics["self_ping_callback_coverage"] = coverage(ping_advances, elapsed)
            require(
                metrics["self_ping_callback_coverage"]["passed"],
                "self_ping_callbacks_not_advancing",
            )
            metrics["boot_nonce"] = boot_nonce
            metrics["max_self_ping_watchdog_age_ms"] = (
                max(ping_ages) if ping_ages else None
            )
            metrics["self_ping_progress_is_not_csi_evidence"] = True
        require(bool(boot_lowers), "no_runtime_samples")
        if boot_lowers:
            drift = max(boot_lowers) - min(boot_uppers)
            metrics["uptime_boot_interval_excess_s"] = max(0, drift)
            require(
                drift <= LIMITS["uptime_clock_tolerance_s"],
                "uptime_disagrees_with_elapsed",
            )
            metrics.update(
                min_worker_free_bytes=min(stack_margins),
                min_internal_free_bytes=min(heap_margins),
                min_internal_largest_block_bytes=min(heap_blocks),
                max_csi_age_ms=max(ages),
            )
        ticks = []
        for update in updates:
            tick, age = update["tick"], update["wall_clock_age_s"]
            require(update["source"] == "esp32", "ws_source")
            require(integer(tick), "ws_tick_invalid")
            require(number(age) and -0.25 <= age <= 10, "ws_timestamp_not_fresh")
            ticks.append(tick)
        require(all(b > a for a, b in pairwise(ticks)), "ws_ticks_reset_or_stall")
        event_times = []
        for packet in events:
            received = packet["received_s"]
            require(
                number(received) and 0 <= received <= elapsed,
                "wasm_receipt_time_invalid",
            )
            require(
                integer(packet["node_id"])
                and packet["node_id"] == receiver.node_id
                and integer(packet["module_id"])
                and packet["module_id"] == module_id,
                "wasm_packet_identity",
            )
            require(
                isinstance(packet["events"], list) and 1 <= len(packet["events"]) <= 16,
                "wasm_events_invalid",
            )
            for event in packet["events"]:
                require(
                    integer(event["event_type"])
                    and event["event_type"] in (1, 2, 3, 10)
                    and number(event["value"]),
                    "wasm_event_contract",
                )
            event_times.append(received)
        require(
            all(b >= a for a, b in pairwise(event_times)),
            "wasm_receipts_nonmonotonic",
        )
        if mode == "module":
            require(
                any(t < elapsed / 2 for t in event_times)
                and any(t >= elapsed / 2 for t in event_times),
                "wasm_packets_not_observed_in_both_halves",
            )
            if modules:
                require(
                    modules[-1]["event_count"] > modules[0]["event_count"],
                    "module_events_not_advancing",
                )
                metrics.update(
                    frame_delta=modules[-1]["frame_count"] - modules[0]["frame_count"],
                    event_delta=modules[-1]["event_count"] - modules[0]["event_count"],
                    max_execution_us=max(m["max_us"] for m in modules),
                )
        else:
            require(not events, "unexpected_wasm_packets_during_baseline")
        metrics["wasm_packets"] = len(events)
    except (
        KeyError,
        TypeError,
        ValueError,
        StopIteration,
        OverflowError,
        AttributeError,
        IndexError,
    ) as exc:
        if type(exc) is ValueError and str(exc) in {
            "boot_identity_invalid",
            "firmware_or_partition_mismatch",
            "boot_nonce_changed",
            "self_ping_not_healthy",
            "self_ping_lifecycle_changed",
        }:
            require(False, str(exc))
        else:
            require(False, "malformed_evidence_" + type(exc).__name__)
    return {"passed": not failures, "failures": failures, "metrics": metrics}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def reject_json_constant(value):
    raise ValueError("Non-finite JSON constant")


def finite_json_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite JSON number")
    return result


def read_sample(
    get,
    now,
    partition,
    *,
    receiver,
    collector,
    expected_version="0.8.8.5",
    expected_nonce=None,
):
    if expected_version not in EXPECTED_VERSIONS or partition not in ("ota_0", "ota_1"):
        raise ValueError("invalid_expected_identity")
    if not supports_version(receiver, expected_version):
        raise ValueError("receiver_version_not_supported")
    requested = now()
    status = get(receiver.base_url + "/ota/status")
    if (
        status.get("version") != expected_version
        or status.get("running_partition") != partition
    ):
        raise ValueError("firmware_or_partition_mismatch")
    if expected_version in RECOVERY_VERSIONS:
        nonce = recovery_status(
            status,
            partition,
            expected_nonce,
            expected_version=expected_version,
            receiver=receiver,
        )
    listing = get(receiver.base_url + "/wasm/list")
    if (
        expected_version in RECOVERY_VERSIONS
        and recovery_identity(listing["runtime"], receiver=receiver) != nonce
    ):
        raise ValueError("boot_nonce_status_list_mismatch")
    received = now()
    fleet = get(collector.http_origin + "/api/v1/nodes", True)
    csi_received = now()
    nodes = [n for n in fleet["nodes"] if n.get("node_id") == receiver.node_id]
    if len(nodes) != 1:
        raise ValueError("Expected exactly one selected receiver entry")
    node = nodes[0]
    return {
        "request_start_s": requested,
        "received_s": received,
        "csi_received_s": csi_received,
        "status": {
            k: status[k]
            for k in ("version", "running_partition")
            + (BOOT_KEYS if expected_version in RECOVERY_VERSIONS else ())
        },
        "listing": listing,
        "csi": {
            k: node[k]
            for k in ("node_id", "csi_status", "csi_last_seen_ms", "csi_sequence")
        },
    }


async def observe(
    duration,
    mode,
    module_id,
    partition,
    token,
    package=HOME_SIGNAL,
    *,
    receiver,
    collector,
    expected_version="0.8.8.5",
    revalidate,
):
    if expected_version not in EXPECTED_VERSIONS:
        raise ValueError("invalid_expected_version")
    if not supports_version(receiver, expected_version):
        raise ValueError("receiver_version_not_supported")
    if not package.enabled:
        raise ValueError("package_profile_unavailable")
    from websockets.asyncio.client import connect
    from websockets.exceptions import WebSocketException

    class NoRedirectConnect(connect):
        def process_redirect(self, exc):
            return exc

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    report = {
        "receiver": receiver.metadata(),
        "package_profile": package.profile,
        "mode": mode,
        "module_id": module_id,
        "expected_partition": partition,
        "expected_version": expected_version,
        "samples": [],
        "ws_updates": [],
        "wasm_packets": [],
        "errors": [],
        "ws_opened_s": None,
        "ws_closed_s": None,
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    start = time.monotonic()

    def now():
        return time.monotonic() - start

    def error(stage, exc):
        report["errors"].append(
            {"received_s": now(), "stage": stage, "type": type(exc).__name__}
        )
        # Exception text, response bodies, and headers can contain credentials.
        print(f"Observation error: {stage} ({type(exc).__name__})", flush=True)

    def get(url, auth=False):
        revalidate()
        headers = {"Authorization": "Bearer " + token} if auth else {}
        request = urllib.request.Request(url, headers=headers)
        with opener.open(request, timeout=3) as response:
            if expected_version in RECOVERY_VERSIONS and not auth:
                body = response.read(MAX_DEVICE_REPLY_BYTES + 1)
                if len(body) > MAX_DEVICE_REPLY_BYTES:
                    raise ValueError("device_reply_too_large")
                return json.loads(
                    body,
                    parse_constant=reject_json_constant,
                    parse_float=finite_json_float,
                )
            return json.load(
                response,
                parse_constant=reject_json_constant,
                parse_float=finite_json_float,
            )

    pinned_nonce = None

    def sample():
        nonlocal pinned_nonce
        result = read_sample(
            get,
            now,
            partition,
            expected_version=expected_version,
            expected_nonce=pinned_nonce,
            receiver=receiver,
            collector=collector,
        )
        if expected_version in RECOVERY_VERSIONS:
            pinned_nonce = result["status"]["boot_nonce"]
        return result

    async def poll():
        while now() < duration:
            try:
                report["samples"].append(await asyncio.to_thread(sample))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                error("http", exc)
            await asyncio.sleep(min(1, max(0, duration - now())))

    async def stream(ws):
        last_tick = None
        while now() < duration:
            remaining = duration - now()
            try:
                message = json.loads(
                    await asyncio.wait_for(ws.recv(), min(5, remaining)),
                    parse_constant=reject_json_constant,
                    parse_float=finite_json_float,
                )
            except TimeoutError as exc:
                if now() < duration:
                    error("websocket_silence", exc)
                break
            received = now()
            if message.get("type") == "sensing_update":
                tick, stamp = message.get("tick"), message.get("timestamp")
                # Duplicate publication ticks do not add freshness evidence.
                if tick != last_tick:
                    report["ws_updates"].append(
                        {
                            "received_s": received,
                            "source": message.get("source"),
                            "tick": tick,
                            "wall_clock_age_s": time.time() - stamp
                            if number(stamp)
                            else None,
                        }
                    )
                    last_tick = tick
            elif (
                message.get("type") == "wasm_event"
                and message.get("node_id") == receiver.node_id
            ):
                report["wasm_packets"].append(
                    {
                        "received_s": received,
                        **{
                            k: message.get(k)
                            for k in ("node_id", "module_id", "events")
                        },
                    }
                )

    try:
        revalidate()
        async with NoRedirectConnect(
            collector.websocket_url,
            additional_headers={"Authorization": "Bearer " + token},
            proxy=None,
            open_timeout=5,
            close_timeout=3,
            max_size=1 << 20,
        ) as ws:
            report["ws_opened_s"] = now()
            # HTTP collection is awaited even if WS fails; never leave an
            # untracked background request after the report is closed.
            results = await asyncio.gather(poll(), stream(ws), return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    error("websocket_or_poll", result)
            report["ws_closed_s"] = now()
    except (OSError, ValueError, TypeError, WebSocketException) as exc:
        error("websocket_connect_or_close", exc)
    report["elapsed_s"] = now()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--mode", choices=("baseline", "module"), required=True)
    parser.add_argument("--expect-partition", choices=("ota_0", "ota_1"), required=True)
    parser.add_argument("--expected-version", choices=EXPECTED_VERSIONS, required=True)
    parser.add_argument("--module-id", type=int, choices=range(4), default=0)
    parser.add_argument("--duration", type=int, default=315)
    parser.add_argument("--output", type=Path, required=True)
    add_package_arguments(parser)
    add_context_arguments(parser)
    add_profile_arguments(parser)
    args = parser.parse_args()
    receiver = load_receiver(args)
    collector = load_profile(args.collector_profile, args.collector_profile_sha256)
    approval = {
        "site_context_sha256": args.site_context_sha256,
        "installation_identity_sha256": args.installation_identity_sha256,
        "package_catalog_sha256": args.package_catalog_sha256,
        "collector_profile_sha256": args.collector_profile_sha256,
    }

    def revalidate():
        if load_package(args) != package:
            raise ValueError("qualification_package_changed")
        if (
            load_receiver(args) != receiver
            or load_profile(args.collector_profile, args.collector_profile_sha256)
            != collector
        ):
            raise ValueError("qualification_receiver_changed")

    try:
        package = load_package(args)
    except ValueError as exc:
        parser.error(str(exc))
    if args.duration < LIMITS["minimum_duration_s"]:
        parser.error("Duration must be at least 305 seconds")
    token = os.environ.get("RUVIEW_API_TOKEN", "")
    if not token:
        parser.error("Set RUVIEW_API_TOKEN in the environment")
    package_sha = hashlib.sha256(package.path.read_bytes()).hexdigest()
    if package_sha != package.package_sha256:
        parser.error("Local pinned signed package hash mismatch")
    os.umask(0o077)
    # Exclusive creation happens before the first live request. Reusing a path
    # can never overwrite the original report, including an interrupted run.
    revalidate()
    with args.output.open("x") as output:
        report = asyncio.run(
            observe(
                args.duration,
                args.mode,
                args.module_id,
                args.expect_partition,
                token,
                package,
                expected_version=args.expected_version,
                revalidate=revalidate,
                receiver=receiver,
                collector=collector,
            )
        )
        report["local_package_sha256"] = package_sha
        report["limits"] = LIMITS
        report["installation_approval"] = approval
        try:
            revalidate()
        except (ValueError, OSError):
            report["assessment"] = {
                "passed": False,
                "failures": ["installation_context_changed"],
                "metrics": {},
            }
        else:
            report["assessment"] = evaluate(
                report,
                package,
                expected_version=args.expected_version,
                receiver=receiver,
            )
        report["limitations"] = [
            "These conservative operational margins do not establish an upper bound for every future workload.",
            "WS receipts are collector broadcasts of UDP packets. Packets lack timestamps, sequence numbers, boot IDs, signatures and package hashes; source freshness and origin cannot be attested from their payload.",
            "Live module name/size/caps identify the expected upload operationally, not cryptographically. A controlled signed upload of the pinned package is a prerequisite.",
            "Events can be suppressed by deadband. Frames and fresh accepted CSI, not event cadence, establish observed continued execution.",
            "No raw CSI grid width is inferred from publication metadata. A synchronized passive packet capture must independently establish the 64-bin LLTF input.",
            "Passing is a bounded runtime/transport result. Fall, pose, occupancy and medical accuracy remain unqualified.",
        ]
        output.write(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["assessment"], indent=2, allow_nan=False))
    return 0 if report["assessment"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
