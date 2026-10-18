"""Private, read-only producer evidence. No labels, calibration or promotion."""

import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from .module_manifest import load_module_manifest
    from .site_context import FILES, load_site_context
else:
    from module_manifest import load_module_manifest
    from site_context import FILES, load_site_context

NODE_IDS = (1, 2, 3)
# Only this installed firmware's read-only runtime endpoint has been reviewed.
# Legacy and future firmware require source/reset diagnostics before probing;
# observing a version does not authorize /wasm/list or imply its safety.
RUNTIME_PROBE_VERSIONS = frozenset({"0.8.8.8"})
MAX_BODY = 1024 * 1024
MAX_GAP_SECONDS = 5
CLASSIFICATIONS = ("absent", "present_still", "present_moving", "unknown")
SLOT_FIELDS = (
    "id",
    "state",
    "name",
    "binary_size",
    "caps",
    "budget_us",
    "frame_count",
    "event_count",
    "error_count",
    "budget_faults",
    "mean_us",
    "max_us",
    "max_frame_us",
    "max_timer_us",
    "frame_overruns",
    "timer_overruns",
)
RUNTIME_FIELDS = (
    "uptime_ms",
    "worker_stack_bytes",
    "worker_stack_min_free_bytes",
    "internal_free_bytes",
    "internal_min_free_bytes",
    "internal_largest_free_block",
)


class EvidenceError(ValueError):
    """Messages are fixed reason codes, never remote payloads or credentials."""


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def integer(value, low=0, high=0xFFFFFFFFFFFFFFFF):
    return type(value) is int and low <= value <= high


def parse_time(text):
    require(isinstance(text, str), "invalid_utc")
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("invalid_utc") from error
    require(value.tzinfo is not None, "utc_offset_required")
    return value


def digest(data):
    if not isinstance(data, bytes):
        data = json.dumps(
            data, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    return hashlib.sha256(data).hexdigest()


def json_load(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise EvidenceError("nonfinite_json_number")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def clock_identity():
    # Exactly the consumer's host/boot scheme. No cross-host monotonic join.
    if sys.platform == "darwin":
        boot = subprocess.check_output(
            ["sysctl", "-n", "kern.bootsessionuuid"], text=True, timeout=5
        ).strip()
    elif sys.platform.startswith("linux"):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    else:
        raise EvidenceError("unsupported_clock_identity_platform")
    return {
        "host_id": hashlib.sha256(socket.gethostname().encode()).hexdigest(),
        "boot_id": boot,
    }


class Clock:
    def stamp(self):
        return {
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
        }

    def sleep(self, seconds):
        time.sleep(seconds)


def check_stamp(stamp, anchor):
    require(integer(stamp.get("monotonic_ns")), "invalid_monotonic_ns")
    elapsed = (stamp["monotonic_ns"] - anchor["monotonic_ns"]) / 1e9
    elapsed_utc = (
        parse_time(stamp.get("observed_utc")) - parse_time(anchor["observed_utc"])
    ).total_seconds()
    require(
        elapsed >= 0
        and abs(elapsed_utc - elapsed) <= anchor["clock_tolerance_seconds"],
        "clock_discontinuity",
    )


def consumer_anchor(path, identity, now):
    raw = Path(path).read_bytes()
    require(len(raw) <= MAX_BODY, "consumer_metadata_too_large")
    metadata = json_load(raw)
    require(
        type(metadata.get("schema_version")) is int and metadata["schema_version"] == 1,
        "consumer_schema_mismatch",
    )
    require(
        isinstance(metadata.get("session_id"), str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", metadata["session_id"]),
        "invalid_session_id",
    )
    require(
        all(
            metadata.get(key) == identity.get(key) and identity.get(key)
            for key in ("host_id", "boot_id")
        ),
        "consumer_host_or_boot_mismatch",
    )
    require(integer(metadata.get("monotonic_ns")), "invalid_consumer_monotonic_ns")
    tolerance = metadata.get("clock_tolerance_seconds")
    require(
        number(tolerance) and 0 < tolerance <= 2, "invalid_consumer_clock_tolerance"
    )
    check_stamp(now, metadata)
    return {
        key: metadata[key]
        for key in (
            "schema_version",
            "session_id",
            "host_id",
            "boot_id",
            "observed_utc",
            "monotonic_ns",
            "clock_tolerance_seconds",
        )
    }, digest(raw)


def origin_url(value):
    url = urlsplit(value)
    require(
        url.scheme in ("http", "https")
        and url.hostname
        and not url.username
        and not url.password
        and url.path in ("", "/")
        and not url.query
        and not url.fragment,
        "invalid_collector_origin",
    )
    try:
        _ = url.port
    except ValueError as error:
        raise EvidenceError("invalid_collector_port") from error
    return value.rstrip("/")


def inventory_nodes(context):
    nodes = context.documents["nodes.json"]["nodes"]
    result, macs = {}, set()
    for node in nodes:
        if node.get("identity_verified") is not True:
            continue
        node_id = node.get("firmware_node_id")
        require(
            integer(node_id, 1, 255) and node_id not in result,
            "invalid_inventory_node_ids",
        )
        ipaddress.IPv4Address(node["ip"])
        require(
            isinstance(node.get("mac"), str)
            and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", node["mac"]),
            "invalid_inventory_mac",
        )
        require(node["mac"] not in macs, "duplicate_inventory_mac")
        macs.add(node["mac"])
        result[node_id] = node
    require(1 <= len(result) <= 10, "inventory_requires_1_to_10_verified_nodes")
    return result


def node_scope(node_ids, inventory):
    require(
        isinstance(node_ids, (list, tuple))
        and 1 <= len(node_ids) <= 10
        and all(integer(n, 1, 255) for n in node_ids)
        and len(set(node_ids)) == len(node_ids),
        "invalid_or_duplicate_selected_node_ids",
    )
    require(set(node_ids) <= set(inventory), "selected_nodes_not_verified")
    return tuple(sorted(node_ids))


def repository_fingerprint(
    root, expected_image, context, module_manifest, *, package_directory
):
    require(
        re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", expected_image),
        "immutable_expected_image_required",
    )
    paths = [
        *sorted(p for p in (root / "config").glob("*.json") if p.name not in FILES),
        *sorted((root / "infrastructure/k3s").glob("*.tf")),
    ]
    paths += [
        root / item
        for item in (
            "bridge.py",
            "collector/source-lock.json",
            "collector/Dockerfile",
            "firmware/upstream-files.json",
            "firmware/reconcile-modules.py",
            "scripts/module_manifest.py",
            "scripts/site_context.py",
            "scripts/coverage_producer.py",
            "scripts/record-coverage-producer.py",
        )
    ]
    files = {str(path.relative_to(root)): digest(path.read_bytes()) for path in paths}
    manifest = module_manifest.document
    for package in manifest["packages"]:
        name = package["file"]
        require(
            isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]+\.rvf", name),
            "invalid_package_basename",
        )
        path = Path(package_directory) / name
        require(
            digest(path.read_bytes()) == package["sha256"],
            "repository_package_hash_mismatch",
        )
        files["firmware/modules/" + name] = digest(path.read_bytes())
    # Preserve the original logical paths and exact private byte digests even
    # when installation data lives outside this checkout.
    files.update({"config/" + name: digest(raw) for name, raw in context.raw.items()})
    files["firmware/modules/manifest.json"] = digest(module_manifest.raw)
    release_manifest = root / "RELEASE-MANIFEST.json"
    if release_manifest.is_file():
        released = json_load(release_manifest.read_bytes())
        require(
            released.get("schema") == "ruview.source-release.v1",
            "invalid_source_release",
        )
        revision = released.get("revision")
        require(
            isinstance(revision, str) and re.fullmatch("[a-f0-9]{40}", revision),
            "invalid_source_revision",
        )
        changed = False
        for path in paths:
            name = str(path.relative_to(root))
            require(
                released.get("files", {}).get(name, {}).get("sha256") == files[name],
                "released_source_changed",
            )
    else:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=5
        ).strip()
        changed = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=normal", "--", *files],
            cwd=root,
            text=True,
            timeout=5,
        )
    return {
        "source_revision": revision,
        "site_context_manifest_sha256": context.manifest_sha256,
        "module_manifest_sha256": module_manifest.sha256,
        "fingerprinted_worktree_dirty": bool(changed),
        "repository_files_sha256": files,
        "collector_expected_image": expected_image,
        "collector_observed_image": None,
        "actual_firmware_image_hashes": None,
        "actual_loaded_module_hashes": None,
        "actual_model_hash": None,
        "actual_calibration_receipt": None,
        "actual_radio_configuration": None,
        "raw_csi_grid": None,
        "fingerprint_complete": False,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ReadOnlyHTTP:
    """One GET per call, no redirects/proxy/retries, five-second total deadline."""

    def __init__(self, origin, token, nodes):
        self.origin = origin_url(origin)
        self.token = token
        self.nodes = nodes
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )

    def get(self, endpoint, timeout):
        require(0 < timeout <= 5, "invalid_http_timeout")
        if endpoint in ("collector_nodes", "collector_sensing"):
            url = (
                self.origin
                + {
                    "collector_nodes": "/api/v1/nodes",
                    "collector_sensing": "/api/v1/sensing/latest",
                }[endpoint]
            )
            headers = {"Authorization": "Bearer " + self.token}
        else:
            matched = re.fullmatch(r"node([1-9][0-9]{0,2})_(status|runtime)", endpoint)
            require(matched is not None, "unapproved_read_endpoint")
            node_id = int(matched[1])
            require(node_id in self.nodes, "unselected_device_endpoint")
            path = "/ota/status" if matched[2] == "status" else "/wasm/list"
            url, headers = f"http://{self.nodes[node_id]['ip']}:8032{path}", {}

        def timed_out(signum, frame):
            raise TimeoutError("http_deadline")

        # SIGALRM also bounds slow bodies and DNS, unlike per-socket timeouts.
        require(
            signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "existing_process_timer"
        )
        previous = signal.signal(signal.SIGALRM, timed_out)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            request = urllib.request.Request(url, method="GET", headers=headers)
            with self.opener.open(request, timeout=timeout) as reply:
                require(reply.status == 200, "http_status_not_200")
                data = reply.read(MAX_BODY + 1)
                require(len(data) <= MAX_BODY, "http_body_too_large")
                return json_load(data)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


def indexed_nodes(value, node_ids=NODE_IDS, allowed_node_ids=None):
    require(
        isinstance(value, dict) and isinstance(value.get("nodes"), list),
        "invalid_collector_nodes",
    )
    result = {}
    for node in value["nodes"]:
        require(isinstance(node, dict), "malformed_node")
        node_id = node.get("node_id")
        require(
            integer(node_id, 1, 255) and node_id not in result,
            "malformed_or_duplicate_node_id",
        )
        result[node_id] = node
    allowed = set(node_ids if allowed_node_ids is None else allowed_node_ids)
    require(set(node_ids) <= set(result) <= allowed, "missing_or_unexpected_node_id")
    return result


def select_sample(
    fleet,
    sensing,
    received_utc,
    fleet_delay_ms=0,
    *,
    node_ids=NODE_IDS,
    allowed_node_ids=None,
):
    require(
        isinstance(sensing, dict) and sensing.get("source") == "esp32",
        "source_mismatch",
    )
    require(sensing.get("type") == "sensing_update", "sensing_type_mismatch")
    require(
        integer(sensing.get("tick")) and number(sensing.get("timestamp")),
        "invalid_collector_timestamp_or_tick",
    )
    server_age = parse_time(received_utc).timestamp() - sensing["timestamp"]
    issues = []
    if not -0.25 <= server_age <= 10:
        issues.append("stale_or_future_collector_timestamp")
    statuses = indexed_nodes(fleet, node_ids, allowed_node_ids)
    inferred = indexed_nodes(sensing, node_ids, allowed_node_ids)
    nodes = []
    for node_id in node_ids:
        status, node = statuses[node_id], inferred[node_id]
        age, sequence = status.get("csi_last_seen_ms"), status.get("csi_sequence")
        require(
            number(age) and age >= 0 and integer(sequence, 0, 0xFFFFFFFF),
            "invalid_csi_diagnostics",
        )
        state = status.get("csi_status")
        require(
            state in ("active", "stale", "inactive", "unknown"), "invalid_csi_status"
        )
        effective_age = age + fleet_delay_ms
        if state != "active" or effective_age > 3000:
            issues.append(f"node{node_id}_stale_accepted_csi")
        inference = node.get("node_inference")
        require(isinstance(inference, dict), "missing_node_inference")
        cls_raw, confidence, infer_age = (
            inference.get(key) for key in ("classification", "confidence", "age_ms")
        )
        # Match the bridge's explicit higher-motion alias; preserve the source label.
        cls = "present_moving" if cls_raw == "active" else cls_raw
        require(
            isinstance(cls_raw, str)
            and cls in CLASSIFICATIONS
            and number(confidence)
            and 0 <= confidence <= 1
            and number(infer_age)
            and infer_age >= 0,
            "malformed_node_inference",
        )
        effective_infer_age = infer_age + max(0, server_age * 1000)
        if cls == "unknown" or effective_infer_age > 10000:
            issues.append(f"node{node_id}_unknown_or_stale_inference")
        count, rssi = node.get("subcarrier_count"), node.get("rssi_dbm")
        require(
            integer(count, 0, 4096) and number(rssi) and -127 <= rssi <= 0,
            "invalid_publication_diagnostics",
        )
        nodes.append(
            {
                "node_id": node_id,
                "accepted_csi": {
                    "status": state,
                    "age_ms": age,
                    "age_at_observation_ms": effective_age,
                    "sequence": sequence,
                },
                "inference": {
                    "classification": cls,
                    "classification_raw": cls_raw,
                    "confidence": confidence,
                    "age_ms": infer_age,
                    "age_at_observation_ms": effective_infer_age,
                    "validation": "unverified",
                },
                "rssi_dbm": rssi,
                "published_subcarrier_count": count,
                "raw_csi_grid": None,
                "vitals": None,
                "vitals_availability": "not_exposed_by_selected_rest_contract",
            }
        )
    return {
        "source": "esp32",
        "unselected_verified_node_ids_seen": sorted(
            (set(statuses) | set(inferred)) - set(node_ids)
        ),
        "tick": sensing["tick"],
        "source_timestamp": sensing["timestamp"],
        "source_wall_clock_age_s": server_age,
        "nodes": nodes,
        "issues": issues,
    }


def select_firmware(status):
    require(isinstance(status, dict), "invalid_firmware_response")
    version, partition = status.get("version"), status.get("running_partition")
    require(
        isinstance(version, str)
        and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version)
        and partition in ("ota_0", "ota_1", "factory"),
        "invalid_firmware_identity",
    )
    result = {"version": version, "running_partition": partition}
    for key, alias in (("build_date", "date"), ("build_time", "time")):
        value = status.get(key, status.get(alias))
        require(
            value is None
            or isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9 :.-]{1,32}", value),
            "invalid_firmware_build",
        )
        result[key] = value
    return result


def select_boundary(status, listing):
    firmware = select_firmware(status)
    require(isinstance(listing, dict), "invalid_runtime_response")
    raw_slots = listing.get("modules")
    require(
        isinstance(raw_slots, list)
        and integer(listing.get("max"), 1, 4)
        and integer(listing.get("loaded"), 0, 4),
        "invalid_module_listing",
    )
    slots, ids, issues = [], set(), []
    for slot in raw_slots:
        require(
            isinstance(slot, dict) and integer(slot.get("id"), 0, 3),
            "invalid_module_id",
        )
        if slot["id"] in ids:
            issues.append("duplicate_module_id")
        ids.add(slot["id"])
        require(
            slot.get("state") in ("empty", "loaded", "running", "stopped", "error"),
            "invalid_module_state",
        )
        selected = {}
        for key in SLOT_FIELDS:
            value = slot.get(key)
            if key in ("state", "name", "caps"):
                require(
                    value is None
                    or isinstance(value, str)
                    and re.fullmatch(r"[A-Za-z0-9_.-]{0,64}", value),
                    "invalid_module_metadata",
                )
            else:
                require(value is None or integer(value), "invalid_module_counter")
            selected[key] = value
        slots.append(selected)
    runtime = listing.get("runtime")
    require(runtime is None or isinstance(runtime, dict), "invalid_runtime_metrics")
    metrics = {key: (runtime or {}).get(key) for key in RUNTIME_FIELDS}
    require(
        all(value is None or integer(value) for value in metrics.values()),
        "invalid_runtime_metrics",
    )
    wifi = listing.get("wifi")
    require(wifi is None or isinstance(wifi, dict), "invalid_wifi_diagnostics")
    radio = {
        key: (wifi or {}).get(key)
        for key in ("associated", "bssid", "channel", "rssi_dbm", "ap_info_error")
    }
    require(
        radio["associated"] is None or type(radio["associated"]) is bool,
        "invalid_wifi_association",
    )
    require(
        radio["bssid"] is None
        or isinstance(radio["bssid"], str)
        and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", radio["bssid"]),
        "invalid_bssid",
    )
    require(
        radio["channel"] is None or integer(radio["channel"], 1, 196),
        "invalid_wifi_channel",
    )
    require(
        radio["rssi_dbm"] is None
        or number(radio["rssi_dbm"])
        and -127 <= radio["rssi_dbm"] <= 0,
        "invalid_wifi_rssi",
    )
    require(
        radio["ap_info_error"] is None or type(radio["ap_info_error"]) is int,
        "invalid_wifi_error",
    )
    if len(slots) != listing["max"] or listing["loaded"] != sum(
        slot["state"] != "empty" for slot in slots
    ):
        issues.append("incomplete_or_inconsistent_module_listing")
    if runtime is None or any(value is None for value in metrics.values()):
        issues.append("runtime_resource_diagnostics_unavailable")
    if wifi is None:
        issues.append("wifi_diagnostics_unavailable")
    elif (
        radio["associated"] is not True
        or radio["ap_info_error"] != 0
        or radio["bssid"] is None
        or radio["channel"] is None
    ):
        issues.append("wifi_association_unverifiable")
    for slot in slots:
        required = set(SLOT_FIELDS) - {
            "max_frame_us",
            "max_timer_us",
            "frame_overruns",
            "timer_overruns",
        }
        if firmware["version"] in ("0.8.8.7", "0.8.8.8"):
            required = set(SLOT_FIELDS)
        if any(slot[key] is None for key in required):
            issues.append("module_diagnostics_unavailable")
        if slot["state"] == "error":
            issues.append("runtime_module_error_state")
        if any(
            slot.get(key) not in (None, 0)
            for key in (
                "error_count",
                "budget_faults",
                "frame_overruns",
                "timer_overruns",
            )
        ):
            issues.append("runtime_fault_recorded")
        if slot.get("budget_us") and any(
            slot.get(key) is not None and slot[key] > slot["budget_us"]
            for key in ("max_us", "max_frame_us", "max_timer_us")
        ):
            issues.append("runtime_budget_exceeded")
    return {
        "firmware": firmware,
        "modules": sorted(slots, key=lambda slot: slot["id"]),
        "loaded": listing["loaded"],
        "max": listing["max"],
        "runtime": metrics,
        "wifi": radio,
        "issues": sorted(set(issues)),
        "runtime_identity_valid": not issues,
        "observed_firmware_image_sha256": None,
        "observed_module_payload_sha256": None,
    }


def runtime_identity(boundary):
    # Dynamic counters, RSSI, uptime and low watermarks are diagnostics only.
    return {
        "firmware": boundary["firmware"],
        "max": boundary["max"],
        "loaded": boundary["loaded"],
        "modules": [
            {
                key: slot[key]
                for key in ("id", "state", "name", "binary_size", "caps", "budget_us")
            }
            for slot in boundary["modules"]
        ],
        "wifi": {
            key: boundary["wifi"][key] for key in ("associated", "bssid", "channel")
        },
    }


def boundary_issues(opening, closing, opening_timing, closing_timing):
    issues = []
    if runtime_identity(opening) != runtime_identity(closing):
        issues.append("runtime_identity_changed")
    before, after = opening["runtime"]["uptime_ms"], closing["runtime"]["uptime_ms"]
    if before is not None and after is not None:
        intervals = [
            (
                timing["request_started"]["monotonic_ns"] / 1e9 - uptime / 1000 - 0.005,
                timing["received"]["monotonic_ns"] / 1e9 - uptime / 1000 + 0.005,
            )
            for timing, uptime in ((opening_timing, before), (closing_timing, after))
        ]
        if after <= before or max(low for low, _ in intervals) > min(
            high for _, high in intervals
        ):
            issues.append("runtime_reboot_or_clock_mismatch")
    old = {slot["id"]: slot for slot in opening["modules"]}
    for slot in closing["modules"]:
        if any(
            slot.get(key) not in (None, 0)
            for key in (
                "error_count",
                "budget_faults",
                "frame_overruns",
                "timer_overruns",
            )
        ):
            issues.append("runtime_fault_recorded")
        if slot["id"] in old and any(
            slot.get(key) is not None
            and old[slot["id"]].get(key) is not None
            and slot[key] < old[slot["id"]][key]
            for key in (
                "frame_count",
                "event_count",
                "max_us",
                "max_frame_us",
                "max_timer_us",
            )
        ):
            issues.append("module_counter_reset")
    return sorted(set(issues))


def exclusive_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")


def save_json(path, value):
    with exclusive_file(path) as output:
        output.write(json.dumps(value, indent=2, allow_nan=False) + "\n")
        output.flush()
        os.fsync(output.fileno())


def inspect_capture(path):
    """A missing terminal row/newline is incomplete, even if samples parse."""
    count, last = 0, None
    try:
        with Path(path).open() as stream:
            for line in stream:
                require(line.endswith("\n"), "truncated_jsonl")
                last = json_load(line)
                count += last.get("kind") == "sample"
        require(
            last is not None and last.get("kind") == "terminal",
            "missing_terminal_record",
        )
        require(last.get("samples") == count, "sample_count_mismatch")
        return {"stream_complete": True, "samples": count}
    except (ValueError, OSError):
        return {"stream_complete": False, "samples": count}


def record(
    root,
    consumer_path,
    output,
    duration,
    expected_image,
    http,
    *,
    site_context,
    site_context_sha256,
    module_manifest,
    module_manifest_sha256,
    package_directory,
    clock=None,
    identity=None,
    node_ids=NODE_IDS,
):
    """Dependencies are injected in offline tests; all persistence is exclusive."""
    require(integer(duration, 5, 3600), "duration_must_be_5_to_3600_seconds")
    context = load_site_context(site_context, site_context_sha256)
    approved_modules = load_module_manifest(module_manifest, module_manifest_sha256)
    clock = clock or Clock()
    identity = identity or clock_identity()
    start = clock.stamp()
    anchor, consumer_sha = consumer_anchor(consumer_path, identity, start)
    configured = repository_fingerprint(
        root,
        expected_image,
        context,
        approved_modules,
        package_directory=package_directory,
    )
    nodes = inventory_nodes(context)
    node_ids = node_scope(node_ids, nodes)
    boundary_budget = max(30, 10 * len(node_ids))
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output, 0o700)
    errors, sample_times, previous = [], [], None

    def row(kind, **values):
        return {
            "schema_version": 1,
            "session_id": anchor["session_id"],
            **identity,
            **clock.stamp(),
            "stream": "ruview_producer",
            "kind": kind,
            **values,
        }

    metadata = row(
        "metadata",
        consumer_metadata_sha256=consumer_sha,
        consumer_anchor=anchor,
        requested_duration_s=duration,
        interval_s=1,
        http_total_timeout_s=5,
        boundary_budget_s=boundary_budget,
        selected_node_ids=list(node_ids),
        configured_verified_node_ids=sorted(nodes),
        runtime_probe_firmware_allowlist=sorted(RUNTIME_PROBE_VERSIONS),
        local_monotonic_alignment=True,
        collector_clock_offset_uncertainty_ms=None,
        purpose="characterization",
        completion_requires_summary_and_terminal_record=True,
        fingerprint=configured,
        node_bindings={
            str(i): {
                key: nodes[i].get(key)
                for key in (
                    "mac",
                    "ip",
                    "room",
                    "floorplan_marker_id",
                    "antenna",
                    "current_placement",
                )
            }
            for i in node_ids
        },
        limitations=[
            "REST snapshots can miss short events",
            "No raw CSI or WebSocket capture",
            "Boundary-only firmware/module/AP reads cannot detect an intervening change and revert",
            "Published subcarrier count is not accepted/raw CSI grid",
            "Actual firmware/module image hashes, model and calibration are unknown",
            "No human labels, calibration or validation promotion",
        ],
    )
    save_json(output / "metadata.json", metadata)
    overall_deadline = (
        start["monotonic_ns"] + (duration + 2 * boundary_budget + 5) * 1_000_000_000
    )
    opening, closing = {}, {}
    sampled_duration = 0.0
    sampling_started_ns = sampling_finished_ns = None
    recording_complete = False
    with exclusive_file(output / "capture.jsonl") as stream:

        def emit(value):
            stream.write(json.dumps(value, allow_nan=False) + "\n")
            stream.flush()

        def issue(code, **details):
            errors.append({"code": code, **details})

        def request(endpoint, deadline):
            started = clock.stamp()
            check_stamp(started, anchor)
            remaining = (
                min(deadline, overall_deadline) - started["monotonic_ns"]
            ) / 1e9
            require(remaining > 0, "capture_deadline_exceeded")
            try:
                payload = http.get(endpoint, min(5, remaining))
                received = clock.stamp()
                check_stamp(received, anchor)
                require(
                    received["monotonic_ns"] >= started["monotonic_ns"],
                    "request_clock_reversed",
                )
                require(
                    received["monotonic_ns"] <= min(deadline, overall_deadline),
                    "request_crossed_deadline",
                )
                return payload, {
                    "endpoint": endpoint,
                    "request_started": started,
                    "received": received,
                }
            except Exception as error:
                emit(
                    row(
                        "request_error",
                        endpoint=endpoint,
                        request_started=started,
                        error=type(error).__name__,
                    )
                )
                raise

        def boundary(phase):
            result = {}
            deadline = min(
                overall_deadline,
                clock.stamp()["monotonic_ns"] + boundary_budget * 1_000_000_000,
            )
            for node_id in node_ids:
                try:
                    status, status_timing = request(f"node{node_id}_status", deadline)
                    firmware = select_firmware(status)
                    emit(
                        row(
                            "firmware_boundary",
                            phase=phase,
                            node_id=node_id,
                            firmware=firmware,
                            requests=[status_timing],
                        )
                    )
                    if firmware["version"] not in RUNTIME_PROBE_VERSIONS:
                        issue(
                            "runtime_probe_not_qualified",
                            phase=phase,
                            node_id=node_id,
                            firmware_version=firmware["version"],
                        )
                        emit(
                            row(
                                "runtime_probe_skipped",
                                phase=phase,
                                node_id=node_id,
                                reason="runtime_probe_not_qualified",
                                firmware_version=firmware["version"],
                            )
                        )
                        continue
                    listing, runtime_timing = request(
                        f"node{node_id}_runtime", deadline
                    )
                    data = select_boundary(status, listing)
                    for code in data["issues"]:
                        issue(code, phase=phase, node_id=node_id)
                    value = row(
                        "runtime_boundary",
                        phase=phase,
                        node_id=node_id,
                        diagnostics=data,
                        requests=[status_timing, runtime_timing],
                    )
                    check_stamp(value, anchor)
                    emit(value)
                    result[node_id] = value
                except Exception as error:
                    code = (
                        str(error)
                        if isinstance(error, EvidenceError)
                        else type(error).__name__
                    )
                    issue(code, phase=phase, node_id=node_id)
                    emit(
                        row("boundary_error", phase=phase, node_id=node_id, reason=code)
                    )
            return result

        try:
            opening = boundary("opening")
            begin = clock.stamp()["monotonic_ns"]
            sampling_started_ns = begin
            deadline = min(
                overall_deadline - 30_000_000_000, begin + duration * 1_000_000_000
            )
            while clock.stamp()["monotonic_ns"] < deadline:
                cycle_start = clock.stamp()["monotonic_ns"]
                remaining = (deadline - cycle_start) / 1e9
                if previous is not None and remaining < 1:
                    # Do not start an intentional fractional final poll. The
                    # unobserved tail still participates in the <=5s gap gate.
                    clock.sleep(remaining)
                    break
                fleet, fleet_timing = request("collector_nodes", deadline)
                sensing, sensing_timing = request("collector_sensing", deadline)
                # /nodes has no response-generation timestamp: conservatively
                # include its entire request, then the second GET's latency.
                fleet_delay_ms = (
                    sensing_timing["received"]["monotonic_ns"]
                    - fleet_timing["request_started"]["monotonic_ns"]
                ) / 1e6
                selected = select_sample(
                    fleet,
                    sensing,
                    sensing_timing["received"]["observed_utc"],
                    fleet_delay_ms,
                    node_ids=node_ids,
                    allowed_node_ids=nodes,
                )
                now = sensing_timing["received"]["monotonic_ns"]
                if previous is not None:
                    if selected["tick"] <= previous["tick"]:
                        selected["issues"].append("collector_tick_reset_or_stall")
                    for current, old in zip(
                        selected["nodes"], previous["nodes"], strict=True
                    ):
                        delta = (
                            current["accepted_csi"]["sequence"]
                            - old["accepted_csi"]["sequence"]
                        ) & 0xFFFFFFFF
                        if not 0 < delta < 0x80000000:
                            selected["issues"].append(
                                f"node{current['node_id']}_csi_sequence_reset_or_stall"
                            )
                for code in selected["issues"]:
                    issue(code, sample=len(sample_times))
                emit(
                    {
                        **row(
                            "sample",
                            **selected,
                            requests=[fleet_timing, sensing_timing],
                            observation_valid=not selected["issues"],
                        ),
                        **sensing_timing["received"],
                    }
                )
                sample_times.append(now)
                previous = selected
                clock.sleep(
                    max(
                        0,
                        (
                            min(deadline, cycle_start + 1_000_000_000)
                            - clock.stamp()["monotonic_ns"]
                        )
                        / 1e9,
                    )
                )
            sampling_finished_ns = clock.stamp()["monotonic_ns"]
            sampled_duration = (sampling_finished_ns - begin) / 1e9
            closing = boundary("closing")
            recording_complete = sampled_duration >= duration
            for node_id in node_ids:
                if node_id not in opening or node_id not in closing:
                    issue("runtime_boundary_missing", node_id=node_id)
                    continue
                if (
                    not opening[node_id]["diagnostics"]["runtime_identity_valid"]
                    or not closing[node_id]["diagnostics"]["runtime_identity_valid"]
                ):
                    issue("runtime_identity_unverifiable", node_id=node_id)
                    continue
                for code in boundary_issues(
                    opening[node_id]["diagnostics"],
                    closing[node_id]["diagnostics"],
                    opening[node_id]["requests"][-1],
                    closing[node_id]["requests"][-1],
                ):
                    issue(code, node_id=node_id)
            gaps = (
                [duration]
                if not sample_times
                else [
                    (sample_times[0] - begin) / 1e9,
                    (deadline - sample_times[-1]) / 1e9,
                    *[
                        (b - a) / 1e9
                        for a, b in zip(sample_times, sample_times[1:], strict=False)
                    ],
                ]
            )
            if (
                len(sample_times) < 2
                or max(gaps) > MAX_GAP_SECONDS
                or sampled_duration < duration
            ):
                issue("sample_interval_incomplete_or_gapped")
            require(
                repository_fingerprint(
                    root,
                    expected_image,
                    load_site_context(site_context, site_context_sha256),
                    load_module_manifest(module_manifest, module_manifest_sha256),
                    package_directory=package_directory,
                )
                == configured,
                "repository_configuration_changed",
            )
            require(
                digest(Path(consumer_path).read_bytes()) == consumer_sha,
                "consumer_metadata_changed",
            )
            check_stamp(clock.stamp(), anchor)
        except BaseException as error:
            if sampling_started_ns is not None and sampling_finished_ns is None:
                sampled_duration = max(
                    0, (clock.stamp()["monotonic_ns"] - sampling_started_ns) / 1e9
                )
            code = (
                str(error) if isinstance(error, EvidenceError) else type(error).__name__
            )
            issue(code)
            issue("capture_interrupted")
        emit(
            row(
                "terminal",
                samples=len(sample_times),
                recording_complete=recording_complete,
                capture_status="invalid" if errors else "complete",
                validation_decision="not_evaluated",
                reasons=errors,
            )
        )
        stream.flush()
        os.fsync(stream.fileno())
    observed = {
        str(node_id): runtime_identity(item["diagnostics"])
        for node_id, item in opening.items()
    }
    fingerprint = {
        "selected_node_ids": list(node_ids),
        "configured": configured,
        "observed_opening": observed,
        "observed_closing": {
            str(node_id): runtime_identity(item["diagnostics"])
            for node_id, item in closing.items()
        },
        "fingerprint_complete": False,
    }
    summary = row(
        "summary",
        capture_status="invalid" if errors else "complete",
        recording_complete=recording_complete,
        evidence_integrity="invalid" if errors else "valid",
        validation_decision="not_evaluated",
        coverage_validated=False,
        sample_count=len(sample_times),
        sampled_duration_s=sampled_duration,
        selected_node_ids=list(node_ids),
        reasons=errors,
        fingerprint=fingerprint,
        partial_fingerprint_sha256=digest(
            {
                "configured": configured,
                "observed": observed,
                "selected_node_ids": list(node_ids),
            }
        ),
        capture_sha256=digest((output / "capture.jsonl").read_bytes()),
        **inspect_capture(output / "capture.jsonl"),
    )
    save_json(output / "summary.json", summary)
    return summary
