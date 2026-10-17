"""Offline temporal fall candidates from declared metric body observations.

No sensor transport, calibration, person association, reference labels or alarms
are supplied here. A candidate is never a confirmed or validated fall.
"""

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path

CONFIG_SCHEMA = "ruview.metric-fall-candidate-config.v1"
OBSERVATION_SCHEMA = "ruview.metric-body-observation.v1"
REPLAY_SCHEMA = "ruview.metric-fall-candidate-replay.v1"
MAX_BYTES = 8 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_TIME = 2**63 - 1
PROVENANCE_FIELDS = {
    "session_id",
    "source_id",
    "clock_id",
    "track_id",
    "body_model_sha256",
    "transform_sha256",
    "floor_reference_sha256",
    "frame",
    "landmark",
}
POLICY_FIELDS = {
    "max_source_age_ms",
    "max_gap_ms",
    "min_confidence",
    "max_height_uncertainty_m",
    "upright_min_height_m",
    "lying_max_height_m",
    "min_drop_m",
    "min_upright_ms",
    "min_upright_samples",
    "max_descent_ms",
    "min_lying_ms",
    "min_lying_samples",
    "cooldown_ms",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def keys(value, fields):
    require(type(value) is dict and set(value) == set(fields), "invalid_fields")


def integer(value, low=0, high=MAX_TIME):
    require(type(value) is int and low <= value <= high, "invalid_integer")
    return value


def number(value, low, high):
    require(
        type(value) in (int, float) and math.isfinite(value) and low <= value <= high,
        "invalid_number",
    )
    return value


def identity(value):
    require(
        type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value),
        "invalid_identity",
    )


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def configuration(value):
    keys(value, {"schema", "classification", "provenance", "policy"})
    require(value["schema"] == CONFIG_SCHEMA, "invalid_config_schema")
    require(
        value["classification"] in ("synthetic", "recorded_metric_body"),
        "invalid_classification",
    )
    provenance = value["provenance"]
    keys(provenance, PROVENANCE_FIELDS)
    for name in ("session_id", "source_id", "clock_id", "track_id"):
        identity(provenance[name])
    for name in ("body_model_sha256", "transform_sha256", "floor_reference_sha256"):
        require(
            type(provenance[name]) is str
            and re.fullmatch(r"[0-9a-f]{64}", provenance[name]),
            "invalid_provenance_sha256",
        )
    require(provenance["frame"] == "floor_local_xyz_m", "metric_floor_frame_required")
    require(
        provenance["landmark"] in ("pelvis_center", "sternum"), "unsupported_landmark"
    )
    p = value["policy"]
    keys(p, POLICY_FIELDS)
    for name in ("max_source_age_ms", "max_gap_ms"):
        integer(p[name], 1, 10_000)
    for name in ("min_upright_ms", "max_descent_ms", "min_lying_ms"):
        integer(p[name], 1, 60_000)
    for name in ("min_upright_samples", "min_lying_samples"):
        integer(p[name], 2, 4096)
    integer(p["cooldown_ms"], 0, 3_600_000)
    number(p["min_confidence"], 0, 1)
    number(p["max_height_uncertainty_m"], 0, 1)
    for name in ("upright_min_height_m", "lying_max_height_m", "min_drop_m"):
        number(p[name], 0.001, 10)
    require(
        p["upright_min_height_m"] > p["lying_max_height_m"], "height_threshold_order"
    )
    return copy.deepcopy(value)


class FallCandidateDetector:
    """One explicitly configured track, bounded constant-memory state.

    Callers supply times on the declared clock. Tick with ``advance`` when input
    is absent; neither this clock declaration nor provenance hashes authenticate
    a body model, its association, a floor survey or measurement accuracy.
    """

    def __init__(self, config):
        self.config = configuration(config)
        self.policy = self.config["policy"]
        self.config_sha = digest(self.config)
        self.implementation_sha = hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest()
        self.candidate_sha = digest(
            {
                "configuration": self.config_sha,
                "implementation": self.implementation_sha,
            }
        )
        self.last_now = self.last_source = self.last_received = None
        self.last_sequence = self.epoch = None
        self.cooldown_until = 0
        self.occurrences = 0
        self.clear()

    def clear(self):
        self.upright = self.descent = self.lying = None

    def result(self, now, state, reason, event=None):
        return {
            "schema": "ruview.metric-fall-candidate-state.v1",
            "at_ns": now,
            "state": state,
            "reason": reason,
            "event": event,
            "classification": self.config["classification"],
            "candidate_sha256": self.candidate_sha,
            "provenance_verified": False,
            "confirmed": False,
            "recognition_validated": False,
            "publish_to_ha": False,
        }

    def unavailable(self, now, reason):
        self.clear()
        return self.result(now, "unavailable", reason)

    def clock(self, now):
        try:
            integer(now)
        except ValueError:
            # A caller may recover from malformed input. It must not recover the
            # preceding transition as well; retain only time/cooldown high-water.
            self.clear()
            raise
        if self.last_now is not None and now < self.last_now:
            return False
        self.last_now = now
        return True

    def advance(self, now_ns):
        """Withdraw accumulated evidence after an input gap; never emits an event."""
        if not self.clock(now_ns):
            return self.unavailable(now_ns, "receipt_clock_reversed")
        if (
            self.last_source is None
            or now_ns - self.last_source
            > min(self.policy["max_source_age_ms"], self.policy["max_gap_ms"])
            * 1_000_000
        ):
            return self.unavailable(now_ns, "no_fresh_body_observation")
        return self.result(now_ns, "waiting", "no_new_body_observation")

    def update(self, observation, *, now_ns):
        if not self.clock(now_ns):
            return self.unavailable(now_ns, "receipt_clock_reversed")
        try:
            keys(
                observation,
                {
                    "schema",
                    "classification",
                    "provenance",
                    "epoch",
                    "sequence",
                    "source_at_ns",
                    "received_at_ns",
                    "person_count",
                    "association_unambiguous",
                    "point_xyz_m",
                    "height_uncertainty_m",
                    "body_confidence",
                    "posture",
                    "posture_confidence",
                },
            )
            require(
                observation["schema"] == OBSERVATION_SCHEMA,
                "invalid_observation_schema",
            )
            require(
                observation["classification"] == self.config["classification"]
                and observation["provenance"] == self.config["provenance"],
                "source_provenance_changed",
            )
            identity(observation["epoch"])
            seq = integer(observation["sequence"])
            at = integer(observation["source_at_ns"])
            received = integer(observation["received_at_ns"])
            require(
                at <= received <= now_ns
                and now_ns - at <= self.policy["max_source_age_ms"] * 1_000_000,
                "stale_or_future_observation",
            )
            require(
                self.last_source is None or at > self.last_source,
                "source_time_not_increasing",
            )
            require(
                self.last_received is None or received >= self.last_received,
                "receipt_time_not_increasing",
            )
            if observation["epoch"] == self.epoch:
                require(seq > self.last_sequence, "sequence_not_increasing")
            sequence_gap = (
                observation["epoch"] == self.epoch and seq != self.last_sequence + 1
            )
            changed = self.epoch is not None and self.epoch != observation["epoch"]
            gap = (
                self.last_source is not None
                and at - self.last_source > self.policy["max_gap_ms"] * 1_000_000
            )
            self.epoch, self.last_sequence = observation["epoch"], seq
            self.last_source, self.last_received = at, received
            if changed or gap or sequence_gap:
                self.clear()
            require(
                type(observation["person_count"]) is int
                and observation["person_count"] == 1
                and observation["association_unambiguous"] is True,
                "ambiguous_body_association",
            )
            point = observation["point_xyz_m"]
            require(
                type(point) is list and len(point) == 3, "metric_body_point_required"
            )
            number(point[0], -100_000, 100_000)
            number(point[1], -100_000, 100_000)
            height = number(point[2], 0, 10)
            uncertainty = number(observation["height_uncertainty_m"], 0, 10)
            body_confidence = number(observation["body_confidence"], 0, 1)
            posture_confidence = number(observation["posture_confidence"], 0, 1)
            posture = observation["posture"]
            require(posture in ("standing", "seated", "lying"), "unknown_posture")
            require(
                uncertainty <= self.policy["max_height_uncertainty_m"]
                and min(body_confidence, posture_confidence)
                >= self.policy["min_confidence"],
                "insufficient_body_quality",
            )
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            reason = str(error) if type(error) is ValueError else "invalid_observation"
            return self.unavailable(now_ns, reason)
        if now_ns < self.cooldown_until:
            self.clear()
            return self.result(now_ns, "cooldown", "candidate_cooldown")
        lower, upper = height - uncertainty, height + uncertainty
        upright = posture == "standing" and lower >= self.policy["upright_min_height_m"]
        if upright:
            if self.descent is not None:
                self.clear()
            if self.upright is None:
                self.upright = {"start": at, "last": at, "count": 0, "lower": lower}
            self.upright.update(
                last=at,
                count=min(4096, self.upright["count"] + 1),
                lower=min(lower, self.upright["lower"]),
            )
            armed = self.armed()
            return self.result(
                now_ns,
                "armed" if armed else "arming",
                "stable_upright" if armed else "collecting_upright_history",
            )
        if not self.armed():
            self.clear()
            return self.result(now_ns, "tracking", "no_prior_stable_upright")
        if self.descent is None:
            self.descent = {"start": at, "anchor": self.upright["last"]}
        drop = self.upright["lower"] - upper
        low_lying = (
            posture == "lying"
            and upper <= self.policy["lying_max_height_m"]
            and drop >= self.policy["min_drop_m"]
        )
        if self.lying is None:
            if at - self.descent["anchor"] > self.policy["max_descent_ms"] * 1_000_000:
                self.clear()
                return self.result(now_ns, "tracking", "descent_too_slow")
            if not low_lying:
                return self.result(now_ns, "descent", "awaiting_low_lying_evidence")
            self.lying = {"start": at, "count": 0, "upper": upper}
        if not low_lying:
            self.clear()
            return self.result(now_ns, "tracking", "lying_evidence_interrupted")
        self.lying.update(
            count=min(4096, self.lying["count"] + 1),
            upper=max(upper, self.lying["upper"]),
        )
        if (
            at - self.lying["start"] < self.policy["min_lying_ms"] * 1_000_000
            or self.lying["count"] < self.policy["min_lying_samples"]
        ):
            return self.result(now_ns, "lying_pending", "awaiting_sustained_lying")
        self.occurrences += 1
        evidence = {
            "upright_start_ns": self.upright["start"],
            "last_upright_ns": self.upright["last"],
            "descent_start_ns": self.descent["start"],
            "lying_start_ns": self.lying["start"],
            "last_source_at_ns": at,
            "upright_samples": self.upright["count"],
            "lying_samples": self.lying["count"],
            "upright_height_lower_m": self.upright["lower"],
            "lying_height_upper_m": self.lying["upper"],
            "drop_lower_bound_m": self.upright["lower"] - self.lying["upper"],
            "descent_duration_ms": (self.lying["start"] - self.descent["anchor"])
            / 1_000_000,
            "lying_duration_ms": (at - self.lying["start"]) / 1_000_000,
        }
        event = {
            "alert_id": "candidate-"
            + digest(
                {
                    "candidate": self.candidate_sha,
                    "epoch": self.epoch,
                    "occurrence": self.occurrences,
                    "at": now_ns,
                }
            )[:24],
            "at_ns": now_ns,
            "source_onset_ns": self.descent["start"],
            "kind": "fall_candidate",
            "candidate_sha256": self.candidate_sha,
            "configuration_sha256": self.config_sha,
            "implementation_sha256": self.implementation_sha,
            "classification": self.config["classification"],
            "provenance": copy.deepcopy(self.config["provenance"]),
            "source_epoch": self.epoch,
            "evidence": evidence,
            "confirmed": False,
            "recognition_validated": False,
            "provenance_verified": False,
            "publish_to_ha": False,
        }
        self.cooldown_until = now_ns + self.policy["cooldown_ms"] * 1_000_000
        self.clear()
        return self.result(
            now_ns, "candidate", "rapid_drop_then_sustained_low_lying", event
        )

    def armed(self):
        return (
            self.upright is not None
            and self.upright["last"] - self.upright["start"]
            >= self.policy["min_upright_ms"] * 1_000_000
            and self.upright["count"] >= self.policy["min_upright_samples"]
        )


def replay(data):
    keys(data, {"schema", "configuration", "records"})
    require(data["schema"] == REPLAY_SCHEMA, "invalid_replay_schema")
    require(
        type(data["records"]) is list and 0 < len(data["records"]) <= MAX_RECORDS,
        "invalid_record_count",
    )
    detector = FallCandidateDetector(data["configuration"])
    states, events = [], []
    for record in data["records"]:
        keys(record, {"now_ns", "observation"})
        result = (
            detector.advance(record["now_ns"])
            if record["observation"] is None
            else detector.update(record["observation"], now_ns=record["now_ns"])
        )
        states.append({k: v for k, v in result.items() if k != "event"})
        if result["event"] is not None:
            events.append(result["event"])
    return {
        "schema": "ruview.metric-fall-candidate-replay-result.v1",
        "classification": detector.config["classification"],
        "candidate_sha256": detector.candidate_sha,
        "configuration_sha256": detector.config_sha,
        "implementation_sha256": detector.implementation_sha,
        "input_canonical_sha256": digest(data),
        "states": states,
        "events": events,
        "alerts": [{"alert_id": e["alert_id"], "at_ns": e["at_ns"]} for e in events],
        "confirmed": False,
        "recognition_validated": False,
        "provenance_verified": False,
        "publish_to_ha": False,
    }


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    fd = os.open(args.input, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(
            stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular_input_required"
        )
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input_too_large")
    data = json.loads(
        raw,
        object_pairs_hook=strict_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")),
    )
    result = replay(data)
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    encoded = (json.dumps(result, indent=2, allow_nan=False) + "\n").encode()
    require(len(encoded) <= MAX_OUTPUT, "output_too_large")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
