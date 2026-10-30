"""Bounded unsupervised signal baseline; geometry weights are not localization."""

import copy
import hashlib
import json
import math
import re
import statistics
from collections import deque

from .persistence import Persistence

DEFAULTS = {
    "poll_seconds": 1,
    "http_timeout_seconds": 2,
    "ttl_seconds": 5,
    "max_source_age_ms": 2500,
    "reset_gap_seconds": 10,
    "baseline_seconds": 300,
    "min_baseline_samples": 30,
    "min_baseline_seconds": 30,
    "log_scale_floor": 0.05,
    "activity_threshold": 3,
    "max_score": 12,
    "kernel_radius_m": 4,
}
METRICS = ("motion_band_power", "variance")
PERSISTENCE_KEYS = {
    "activity_min_samples",
    "activity_min_seconds",
    "activity_max_gap_seconds",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def number(value, name, lower=0, upper=1e12):
    require(
        type(value) in (int, float)
        and math.isfinite(value)
        and lower <= value <= upper,
        name,
    )
    return value


def integer(value, name, lower=0, upper=2**64 - 1):
    require(type(value) is int and lower <= value <= upper, name)
    return value


def encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def identifier(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value),
        "invalid_identifier",
    )


def point(value):
    require(isinstance(value, list) and len(value) == 2, "invalid_point")
    return [number(n, "invalid_coordinate", -10000, 10000) for n in value]


def centroid(polygon):
    require(isinstance(polygon, list) and 3 <= len(polygon) <= 64, "invalid_polygon")
    points = [point(p) for p in polygon]
    area = x = z = 0
    for a, b in zip(points, points[1:] + points[:1], strict=True):
        cross = a[0] * b[1] - b[0] * a[1]
        area += cross
        x += (a[0] + b[0]) * cross
        z += (a[1] + b[1]) * cross
    require(abs(area) > 1e-8, "degenerate_polygon")
    return [x / (3 * area), z / (3 * area)]


def configuration(value, *, expected_coordinate_frame):
    require(
        isinstance(expected_coordinate_frame, str)
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}_xz_metres", expected_coordinate_frame
        ),
        "coordinate_frame_approval_required",
    )
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "coordinate_frame",
            "geometry_assumed",
            "floorplan_sha256",
            "assumption_reference",
            "receivers",
            "zones",
            "policy",
        },
        "invalid_config_fields",
    )
    require(
        value["schema"] == "ruview.assumed-activity.config.v1"
        and value["coordinate_frame"] == expected_coordinate_frame
        and value["geometry_assumed"] is True,
        "explicit_assumed_geometry_required",
    )
    require(
        isinstance(value["floorplan_sha256"], str)
        and re.fullmatch("[0-9a-f]{64}", value["floorplan_sha256"]),
        "invalid_floorplan_hash",
    )
    require(
        isinstance(value["assumption_reference"], str)
        and 0 < len(value["assumption_reference"].strip()) <= 4096,
        "assumption_reference_required",
    )
    require(
        isinstance(value["policy"], dict)
        and set(value["policy"]) <= set(DEFAULTS) | PERSISTENCE_KEYS,
        "unknown_policy",
    )
    policy = DEFAULTS | value["policy"]
    if PERSISTENCE_KEYS & set(policy):
        require(PERSISTENCE_KEYS <= set(policy), "incomplete_activity_persistence")
        integer(policy["activity_min_samples"], "invalid_activity_min_samples", 2, 10)
        number(policy["activity_min_seconds"], "invalid_activity_min_seconds", 0.1, 10)
        number(
            policy["activity_max_gap_seconds"],
            "invalid_activity_max_gap_seconds",
            0.2,
            5,
        )
    for key, limits in {
        "poll_seconds": (0.2, 10),
        "http_timeout_seconds": (0.1, 5),
        "ttl_seconds": (1, 30),
        "max_source_age_ms": (100, 10000),
        "reset_gap_seconds": (1, 60),
        "baseline_seconds": (2, 1800),
        "min_baseline_seconds": (1, 600),
        "log_scale_floor": (0.001, 10),
        "activity_threshold": (0.1, 100),
        "max_score": (1, 100),
        "kernel_radius_m": (0.1, 100),
    }.items():
        number(policy[key], "invalid_policy_" + key, *limits)
    integer(policy["min_baseline_samples"], "invalid_sample_minimum", 3, 3600)
    require(
        policy["min_baseline_seconds"] <= policy["baseline_seconds"]
        and policy["activity_threshold"] <= policy["max_score"],
        "inconsistent_policy",
    )
    receivers, zones = value["receivers"], value["zones"]
    require(
        isinstance(receivers, list) and 1 <= len(receivers) <= 16, "invalid_receivers"
    )
    require(isinstance(zones, list) and 1 <= len(zones) <= 32, "invalid_zones")
    ids = set()
    for receiver in receivers:
        require(
            set(receiver) == {"node_id", "position_xz_m"}, "invalid_receiver_fields"
        )
        node = integer(receiver["node_id"], "invalid_node", 1, 16)
        require(node not in ids, "duplicate_node")
        ids.add(node)
        point(receiver["position_xz_m"])
    names, weights = set(), {}
    for zone in zones:
        require(
            set(zone) == {"zone_id", "room_id", "polygon_xz_m"}, "invalid_zone_fields"
        )
        identifier(zone["zone_id"])
        identifier(zone["room_id"])
        require(zone["zone_id"] not in names, "duplicate_zone")
        names.add(zone["zone_id"])
        centre = centroid(zone["polygon_xz_m"])
        raw = {
            str(r["node_id"]): 1
            / (
                policy["kernel_radius_m"] ** 2
                + sum(
                    (a - b) ** 2
                    for a, b in zip(centre, r["position_xz_m"], strict=True)
                )
            )
            for r in receivers
        }
        weights[zone["zone_id"]] = {
            node: weight / sum(raw.values()) for node, weight in raw.items()
        }
    return policy, weights


def indexed(rows):
    require(isinstance(rows, list) and len(rows) <= 256, "invalid_node_list")
    result = {}
    for row in rows:
        require(isinstance(row, dict), "invalid_node_record")
        node = integer(row.get("node_id"), "invalid_node_id", 1, 255)
        require(node not in result, "duplicate_source_node")
        result[node] = row
    return result


def timestamp(value):
    require(
        isinstance(value, str)
        and value.isascii()
        and value.isdecimal()
        and len(value) <= 20,
        "invalid_source_timestamp",
    )
    return int(value)


class Producer:
    def __init__(
        self, config, receiver_identity_sha=None, *, expected_coordinate_frame
    ):
        self.config = copy.deepcopy(config)
        self.policy, self.weights = configuration(
            config, expected_coordinate_frame=expected_coordinate_frame
        )
        self.config_sha = digest(config)
        self.geometry_sha = digest(
            {key: config[key] for key in ("coordinate_frame", "receivers", "zones")}
        )
        self.history = {}
        self.history_generation = 0
        self.persistence = (
            Persistence(self.policy) if PERSISTENCE_KEYS <= set(self.policy) else None
        )
        self.last = None
        self.last_mono = None
        self.receiver_identity_sha = receiver_identity_sha
        self.last_rejection = None

    def envelope(self, now_ns):
        result = {
            "schema": "ruview.assumed-zone-activity.v1",
            "state": "unknown",
            "reason": "no_input",
            "generated_at_ns": str(now_ns),
            "oldest_source_at_ns": None,
            "expires_at_ns": str(now_ns + int(self.policy["ttl_seconds"] * 1e9)),
            "ttl_ms": int(self.policy["ttl_seconds"] * 1000),
            "geometry_assumed": True,
            "physical_geometry_verified": False,
            "recognition_validated": False,
            "supervised_training": False,
            "floorplan_sha256": self.config["floorplan_sha256"],
            "geometry_sha256": self.geometry_sha,
            "configuration_sha256": self.config_sha,
            "score_semantics": "positive_robust_deviation_from_recent_ambient_baseline",
            "effective_policy": self.policy,
            "source": None,
            "nodes": [],
            "zones": [],
        }
        if self.receiver_identity_sha is not None:
            result["receiver_identity_configuration_sha256"] = (
                self.receiver_identity_sha
            )
        if self.persistence is not None:
            result["activity_gate"] = {
                "schema": "ruview.activity-persistence.v1",
                "status": "unavailable",
                "raw_active": None,
                "confirmed_nodes": [],
                "nodes": [],
            }
        return result

    def zone_rows(self, nodes):
        ready = bool(nodes) and all(n["status"] == "ready" for n in nodes)
        scores = {str(n["node_id"]): n["score"] for n in nodes}
        status = (
            "ready"
            if ready
            else "warming_up"
            if nodes and all(n["status"] != "unknown" for n in nodes)
            else "unknown"
        )
        return [
            {
                "zone_id": z["zone_id"],
                "room_id": z["room_id"],
                "status": status,
                "signal_score": sum(
                    w * scores[node] for node, w in self.weights[z["zone_id"]].items()
                )
                if ready
                else None,
                "receiver_weights": self.weights[z["zone_id"]],
                "spatial_resolution": "assumed_geometry_weighting_not_localization",
            }
            for z in self.config["zones"]
        ]

    def unknown(self, reason, now_ns, mono):
        result = self.envelope(now_ns)
        if self.persistence is not None:
            result["activity_gate"] = self.persistence.unavailable()
        result.update(reason=reason, zones=self.zone_rows([]))
        self.last, self.last_mono = result, mono
        return copy.deepcopy(result)

    def sample(
        self, node, worker, sensing, now_ns, mono, identity, collector_ns, proof=None
    ):
        row = {
            "node_id": node,
            "status": "unknown",
            "reason": "invalid_source",
            "score": None,
            "metrics": None,
            "baseline_samples": 0,
            "baseline_span_seconds": 0,
            "source_age_ms": None,
            "source_at_ns": None,
        }
        try:
            require(worker.get("admission") is None, "ineligible_native_profile")
            grid = worker["grid"]
            require(
                type(grid["antennas"]) is int
                and grid["antennas"] == 1
                and type(grid["subcarriers"]) is int
                and grid["subcarriers"] == 64
                and type(grid["ppdu_type"]) is int
                and grid["ppdu_type"] == 0
                and type(grid["flags"]) is int
                and grid["flags"] in (0, 16),
                "ineligible_raw_grid",
            )
            frequency = integer(grid["frequency_mhz"], "invalid_frequency", 2000, 8000)
            require(worker["fresh"] is True and sensing["stale"] is False, "stale_node")
            age = max(
                number(worker["age_ms"], "invalid_worker_age"),
                number(sensing["last_seen_ms"], "invalid_collector_age"),
                (now_ns - timestamp(worker["last_received_at_ns"])) / 1e6,
                (now_ns - collector_ns) / 1e6 + sensing["last_seen_ms"],
            )
            require(age <= self.policy["max_source_age_ms"], "stale_node")
            require(
                timestamp(worker["last_received_at_ns"]) <= now_ns + 500_000_000,
                "future_node",
            )
            number(sensing["frame_rate_hz"], "invalid_frame_rate", 0.01, 1000)
            values = [
                number(sensing["features"][key], "invalid_signal_metric")
                for key in METRICS
            ]
            row.update(
                metrics=dict(zip(METRICS, values, strict=True)),
                source_age_ms=max(0, age),
                source_at_ns=str(now_ns - int(max(0, age) * 1e6)),
            )
            token = timestamp(worker["last_received_monotonic_ns"])
            sequence = integer(worker["sequence"], "invalid_sequence", 0, 2**32 - 1)
            epoch = integer(worker["node_epoch"], "invalid_node_epoch")
            discontinuities = integer(
                worker["sequence_discontinuities"], "invalid_discontinuities"
            )
            reason = worker["epoch_reason"]
            require(
                isinstance(reason, str) and re.fullmatch("[a-z_]{1,64}", reason),
                "invalid_epoch_reason",
            )
            row.update(
                node_epoch=epoch,
                epoch_reason=reason,
                sequence_discontinuities=discontinuities,
            )
            key = (*identity, frequency, grid["flags"])
            reordering = False
            if self.receiver_identity_sha is not None:
                proof = proof or {}
                row["boot_proof"] = proof.get("diagnostic", {"status": "unavailable"})
                require(
                    proof.get("accept") is True,
                    proof.get("reason", "receiver_proof_required"),
                )
                radio_channel = proof["identity"][3]
                require(
                    frequency
                    == (2484 if radio_channel == 14 else 2407 + 5 * radio_channel),
                    "receiver_radio_grid_mismatch",
                )
                if proof.get("bracket_after_ns") is not None:
                    require(
                        proof["bracket_after_ns"] <= int(row["source_at_ns"])
                        and max(timestamp(worker["last_received_at_ns"]), collector_ns)
                        <= proof["bracket_before_ns"],
                        "scalar_outside_receiver_proofs",
                    )
                key += tuple(proof["identity"])
                reordering = proof.get("allow_reordering") is True
            previous = self.history.get(node)
            if previous is not None and (
                previous["identity"] != key
                or discontinuities < previous["discontinuities"]
                or (previous["discontinuities"] != discontinuities and not reordering)
                or epoch < previous["epoch"]
                or (
                    epoch != previous["epoch"]
                    and reason not in ("sequence_gap", "bounded_history_renewal")
                    and not (reordering and reason == "sequence_backwards_boot_unknown")
                )
                or mono - previous["mono"] > self.policy["reset_gap_seconds"]
                or mono < previous["mono"]
                or token < previous["token"]
                or collector_ns < previous["collector_ns"]
                or (
                    (sequence - previous["sequence"]) % 2**32 >= 2**31
                    and not reordering
                )
            ):
                previous = None
            if previous is None:
                self.history_generation += 1
                previous = {
                    "generation": self.history_generation,
                    "identity": key,
                    "samples": deque(maxlen=3600),
                    "mono": mono,
                    "token": -1,
                    "collector_ns": -1,
                    "sequence": sequence,
                    "epoch": epoch,
                    "discontinuities": discontinuities,
                }
                self.history[node] = previous
            require(
                token > previous["token"] and collector_ns > previous["collector_ns"],
                "no_new_sample",
            )
            history = previous["samples"]
            while history and mono - history[0][0] > self.policy["baseline_seconds"]:
                history.popleft()
            span = history[-1][0] - history[0][0] if len(history) > 1 else 0
            row.update(baseline_samples=len(history), baseline_span_seconds=span)
            logs = [math.log1p(value) for value in values]
            if (
                len(history) >= self.policy["min_baseline_samples"]
                and span >= self.policy["min_baseline_seconds"]
            ):
                scores = []
                for i, current in enumerate(logs):
                    samples = [sample[1][i] for sample in history]
                    median = statistics.median(samples)
                    scale = max(
                        self.policy["log_scale_floor"],
                        1.4826 * statistics.median(abs(v - median) for v in samples),
                    )
                    scores.append(
                        min(
                            self.policy["max_score"], max(0, (current - median) / scale)
                        )
                    )
                row.update(
                    status="ready",
                    reason="recent_ambient_comparison",
                    score=sum(scores) / len(scores),
                )
            else:
                row.update(
                    status="warming_up", reason="collecting_recent_ambient_baseline"
                )
            history.append((mono, logs))
            previous.update(
                mono=mono,
                token=token,
                collector_ns=collector_ns,
                sequence=sequence,
                epoch=epoch,
                discontinuities=discontinuities,
            )
        except (KeyError, TypeError, ValueError) as error:
            row["reason"] = (
                str(error) if isinstance(error, ValueError) else "invalid_source"
            )
        return row

    def update(self, health, worker, sensing, now_ns, mono, proofs=None):
        self.last_rejection = None
        try:
            require(health.get("status") == "ok", "worker_unhealthy")
            require(
                worker["schema"] == "ruview.server-modules.v1"
                and worker["recognition_validated"] is False,
                "invalid_worker_schema",
            )
            require(
                sensing["source"] == "esp32" and sensing["type"] == "sensing_update",
                "invalid_collector_schema",
            )
            worker_ns = timestamp(worker["generated_at_ns"])
            collector_ns = int(
                number(sensing["timestamp"], "invalid_collector_time", 1, 1e11) * 1e9
            )
            for at in (worker_ns, collector_ns):
                require(
                    -500_000_000
                    <= now_ns - at
                    <= self.policy["max_source_age_ms"] * 1e6,
                    "stale_or_future_snapshot",
                )
            identity = (
                worker["worker_run_id"],
                worker["configuration_sha256"],
                worker["clock_id"],
            )
            require(
                all(isinstance(v, str) and 0 < len(v) <= 256 for v in identity),
                "invalid_worker_identity",
            )
            wn, sn = indexed(worker["nodes"]), indexed(sensing["node_features"])
            nodes = [
                self.sample(
                    r["node_id"],
                    wn.get(r["node_id"], {}),
                    sn.get(r["node_id"], {}),
                    now_ns,
                    mono,
                    identity,
                    collector_ns,
                    (proofs or {}).get(r["node_id"]),
                )
                for r in self.config["receivers"]
            ]
            result = self.envelope(now_ns)
            oldest = min(
                [now_ns, worker_ns, collector_ns]
                + [
                    int(n["source_at_ns"])
                    for n in nodes
                    if n["source_at_ns"] is not None
                ]
            )
            result.update(
                oldest_source_at_ns=str(oldest),
                expires_at_ns=str(oldest + int(self.policy["ttl_seconds"] * 1e9)),
                nodes=nodes,
                zones=self.zone_rows(nodes),
                source={
                    "worker_run_id": identity[0],
                    "worker_configuration_sha256": identity[1],
                    "worker_generated_at_ns": str(worker_ns),
                    "collector_timestamp_ns": str(collector_ns),
                },
            )
            if any(n["status"] == "unknown" for n in nodes):
                result.update(state="unknown", reason="required_node_unavailable")
            elif any(n["status"] == "warming_up" for n in nodes):
                result.update(
                    state="warming_up", reason="collecting_recent_ambient_baseline"
                )
            else:
                active = any(
                    n["score"] >= self.policy["activity_threshold"] for n in nodes
                )
                if self.persistence is not None:
                    gate = self.persistence.update(
                        nodes,
                        mono,
                        {
                            n["node_id"]: (
                                self.history[n["node_id"]]["generation"],
                                self.history[n["node_id"]]["epoch"],
                                self.history[n["node_id"]]["discontinuities"],
                            )
                            for n in nodes
                        },
                        {
                            n["node_id"]: (
                                self.history[n["node_id"]]["token"],
                                self.history[n["node_id"]]["collector_ns"],
                            )
                            for n in nodes
                        },
                    )
                    if gate["status"] == "unavailable":
                        return self.unknown(
                            "activity_confirmation_unavailable", now_ns, mono
                        )
                    result["activity_gate"] = gate
                    active = bool(gate["confirmed_nodes"])
                result.update(
                    state="active" if active else "quiet",
                    reason="elevated_signal_anomaly"
                    if active
                    else "no_elevated_signal_anomaly_not_empty",
                )
                if self.persistence is not None:
                    result["reason"] = (
                        "persistent_signal_anomaly"
                        if active
                        else "awaiting_persistent_signal_anomaly"
                        if result["activity_gate"]["raw_active"]
                        else "no_elevated_signal_anomaly_not_empty"
                    )
            if self.persistence is not None and result["state"] in (
                "unknown",
                "warming_up",
            ):
                result["activity_gate"] = self.persistence.unavailable()
            self.last, self.last_mono = result, mono
            return copy.deepcopy(result)
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            # Internal diagnostics only: never retain input values or exception text.
            allowed = {
                "worker_unhealthy",
                "invalid_worker_schema",
                "invalid_collector_schema",
                "invalid_source_timestamp",
                "invalid_collector_time",
                "stale_or_future_snapshot",
                "invalid_worker_identity",
                "invalid_node_list",
                "invalid_node_record",
                "invalid_node_id",
                "duplicate_source_node",
            }
            code = error.args[0] if len(error.args) == 1 else None
            self.last_rejection = (
                code
                if type(error) is ValueError and type(code) is str and code in allowed
                else "missing_input_field"
                if isinstance(error, KeyError)
                else "invalid_input_type"
                if isinstance(error, (TypeError, AttributeError))
                else "invalid_input_value"
            )
            return self.unknown("invalid_or_unavailable_inputs", now_ns, mono)

    def snapshot(self, now_ns, mono):
        if self.last is None:
            result = self.envelope(now_ns)
            result["zones"] = self.zone_rows([])
            return result
        result = copy.deepcopy(self.last)
        if (
            mono - self.last_mono >= self.policy["ttl_seconds"]
            or mono < self.last_mono
            or now_ns >= int(result["expires_at_ns"])
            or now_ns < int(result["generated_at_ns"])
        ):
            result.update(
                state="unknown",
                reason="producer_snapshot_expired",
                zones=self.zone_rows([]),
            )
            for node in result["nodes"]:
                node.update(
                    status="unknown", reason="producer_snapshot_expired", score=None
                )
            if self.persistence is not None:
                result["activity_gate"] = self.envelope(now_ns)["activity_gate"]
        return result
