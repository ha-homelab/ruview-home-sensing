"""Preserve native CSI identity/time and pair it with independent reviewed labels."""

import hashlib
import json
import math
import re
import uuid
from collections import Counter

from .feature_contracts import (
    FEATURE_CONTRACT,
    PREFIX_FEATURE_CONTRACT,
    prefix_selection,
    selected_contract,
    validate_contract,
    validate_prefix_scope,
)

FRAME_SCHEMA = "ruview.csi.frame.v1"
FRAME_SCHEMA_V2 = "ruview.csi.frame.v2"
WINDOW_SCHEMA_V2 = "ruview.csi.window.v2"
LABEL_SCHEMA_V2 = "ruview.ground_truth.v2"
PAIR_SCHEMA = "ruview.csi.paired.v1"
PAIR_SCHEMA_V2 = "ruview.csi.paired.v2"
POSTURES = ("standing", "seated", "lying")
HASH = re.compile(r"^[0-9a-f]{64}$")
WIRE_METADATA = (
    "iq_order",
    "source_pair_order",
    "worker_phase_convention",
    "monotonic_origin",
)
AMPLITUDE_CONTRACT = "native-wire-pair-hypot-phase-unused-v1"


def integer(value, name, minimum=0, maximum=None):
    if (
        type(value) is not int
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise ValueError(f"invalid {name}")
    return value


def nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing {name}")
    return value


def approved_coordinate_frame(value):
    """Validate an independently selected frame, never infer it from input data."""
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value
    ):
        raise ValueError("independently approved coordinate frame required")
    return value


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def sha(value, name):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def validate_capture_identity(value):
    """A capture is distinct from the source worker run; neither is a clock."""
    for key in ("session_id", "capture_id", "worker_run_id"):
        item = value.get(key)
        if not isinstance(item, str):
            raise ValueError(f"invalid canonical UUID {key}")
        try:
            canonical = str(uuid.UUID(item))
        except ValueError as error:
            raise ValueError(f"invalid canonical UUID {key}") from error
        if item != canonical:
            raise ValueError(f"invalid canonical UUID {key}")
    if (
        value["session_id"] != value["capture_id"]
        or value["capture_id"] == value["worker_run_id"]
    ):
        raise ValueError("capture/session identity must differ from worker run")
    nonempty(value.get("clock_id"), "source worker clock_id")
    return value


def validate_window_identity(window):
    if window.get("schema") == WINDOW_SCHEMA_V2:
        validate_capture_identity(window)
        if window.get("source_frame_schema") != FRAME_SCHEMA_V2:
            raise ValueError("window v2 requires explicit source frame v2")
    elif window.get("schema") != "ruview.csi.window.v1":
        raise ValueError("unknown window schema")
    return window


def validate_frame(frame):
    if frame.get("schema") == FRAME_SCHEMA_V2:
        validate_capture_identity(frame)
        for key in ("ingress_sequence", "capture_sequence"):
            integer(frame.get(key), key, 1, 2**64 - 1)
    elif frame.get("schema") != FRAME_SCHEMA:
        raise ValueError("unsupported CSI frame schema")
    for key in ("session_id", "clock_id"):
        nonempty(frame.get(key), key)
    sha(frame.get("configuration_sha256"), "configuration_sha256")
    integer(frame.get("node_id"), "node_id", 1, 255)
    integer(frame.get("received_at_ns"), "received_at_ns", 1)
    integer(frame.get("received_monotonic_ns"), "received_monotonic_ns", 0)
    integer(frame.get("sequence"), "sequence", 0, 2**32 - 1)
    integer(frame.get("frequency_mhz"), "frequency_mhz", 2000, 8000)
    integer(frame.get("ppdu_type"), "ppdu_type", 0, 255)
    integer(frame.get("flags"), "flags", 0, 255)
    if (
        type(frame.get("antennas")) is not int
        or type(frame.get("subcarriers")) is not int
        or frame["antennas"] != 1
        or frame["subcarriers"] != 64
    ):
        raise ValueError("requires native one-antenna 64-pair CSI; no remapping")
    iq = frame.get("iq")
    if not isinstance(iq, list) or len(iq) != 128:
        raise ValueError("CSI needs exactly 128 signed I/Q bytes")
    for item in iq:
        integer(item, "I/Q value", -128, 127)
    for key in WIRE_METADATA:
        if key in frame:
            nonempty(frame[key], key)
    if frame.get("iq_order", "wire_byte_order") != "wire_byte_order":
        raise ValueError("requires original wire-byte order")
    return frame


def stream_identity(frame):
    identity = tuple(
        frame.get(key)
        for key in (
            "session_id",
            "node_id",
            "clock_id",
            "configuration_sha256",
            "antennas",
            "subcarriers",
            "frequency_mhz",
            "ppdu_type",
            "flags",
            "device_boot_id",
        )
        + WIRE_METADATA
    )
    if frame.get("schema") == FRAME_SCHEMA_V2:
        return (FRAME_SCHEMA_V2, frame["capture_id"], frame["worker_run_id"]) + identity
    return identity


def validate_profile(profile):
    if profile.get("schema") != "ruview.commissioning.profile.v1":
        raise ValueError("unknown commissioning profile")
    integer(profile.get("node_id"), "profile node_id", 1, 255)
    for key in (
        "placement_revision",
        "room_id",
        "orientation_reference",
        "antenna_path",
        "ap_bssid",
        "firmware_version",
        "inference_revision",
        "evidence_reference",
    ):
        nonempty(profile.get(key), key)
    for key in ("firmware_sha256", "floorplan_sha256"):
        sha(profile.get(key), key)
    finite_vector(profile.get("receiver_position_ha_m"), 3, "receiver_position_ha_m")
    integer(profile.get("frequency_mhz"), "profile frequency_mhz", 2000, 8000)
    if not isinstance(profile.get("module_sha256s"), list):
        raise ValueError("module hashes must be explicit, including an empty list")
    for value in profile["module_sha256s"]:
        sha(value, "module hash")
    if profile.get("placement_confirmed") is not True:
        raise ValueError("commissioning requires confirmed current placement")
    return profile


class WindowBuilder:
    """Non-overlapping native-rate windows; reset instead of fill/interpolate."""

    def __init__(
        self,
        duration_ms=1000,
        max_gap_ms=250,
        min_frames=8,
        max_clock_step_ms=25,
        profiles=None,
        feature_contract=FEATURE_CONTRACT,
    ):
        self.feature_contract = validate_contract(feature_contract)
        if not profiles:
            raise ValueError("explicit per-node commissioning profiles required")
        self.profiles = {}
        for profile in profiles:
            validate_profile(profile)
            node = profile["node_id"]
            if node in self.profiles:
                raise ValueError("duplicate commissioning node")
            self.profiles[node] = profile
        self.duration_ns = integer(duration_ms, "duration_ms", 1) * 1_000_000
        self.max_gap_ns = integer(max_gap_ms, "max_gap_ms", 1) * 1_000_000
        self.min_frames = integer(min_frames, "min_frames", 2)
        self.max_clock_step_ns = (
            integer(max_clock_step_ms, "max_clock_step_ms", 0) * 1_000_000
        )
        self.pending = {}
        self.last = {}
        self.stats = Counter()

    def push(self, frame):
        validate_frame(frame)
        if self.feature_contract == PREFIX_FEATURE_CONTRACT:
            validate_prefix_scope(frame)
        node = frame["node_id"]
        if node not in self.profiles:
            self.stats["unconfigured_node"] += 1
            return None
        if frame["frequency_mhz"] != self.profiles[node]["frequency_mhz"]:
            self.pending.pop(node, None)
            self.last.pop(node, None)
            self.stats["profile_frequency_mismatch"] += 1
            return None
        self.stats["frames"] += 1
        previous = self.last.get(node)
        if previous is not None:
            utc_delta = frame["received_at_ns"] - previous["received_at_ns"]
            delta = frame["received_monotonic_ns"] - previous["received_monotonic_ns"]
            seq_delta = (frame["sequence"] - previous["sequence"]) % 2**32
            reason = None
            if stream_identity(frame) != stream_identity(previous):
                reason = "identity_change"
            elif frame["schema"] == FRAME_SCHEMA_V2 and any(
                frame[key] <= previous[key]
                for key in ("ingress_sequence", "capture_sequence")
            ):
                reason = "nonmonotonic_admission"
            elif delta <= 0 or utc_delta <= 0:
                reason = "nonmonotonic_time"
            elif abs(utc_delta - delta) > self.max_clock_step_ns:
                reason = "clock_step"
            elif delta > self.max_gap_ns:
                reason = "gap"
            elif seq_delta != 1:
                reason = "sequence_discontinuity"
            if reason:
                self.pending.pop(node, None)
                self.stats[reason] += 1
                # A duplicate/backwards record must not seed a fresh window.
                if reason in ("nonmonotonic_time", "nonmonotonic_admission") or (
                    reason == "sequence_discontinuity" and seq_delta == 0
                ):
                    return None
        self.last[node] = frame
        frames = self.pending.setdefault(node, [])
        frames.append(frame)
        if len(frames) > 4096:
            self.pending[node] = []
            self.stats["frame_limit"] += 1
            return None
        if (
            frame["received_monotonic_ns"] - frames[0]["received_monotonic_ns"]
            < self.duration_ns
        ):
            return None
        self.pending[node] = []
        if len(frames) < self.min_frames:
            self.stats["insufficient_frames"] += 1
            return None
        first = frames[0]
        window = {
            key: first.get(key)
            for key in (
                "session_id",
                "node_id",
                "clock_id",
                "configuration_sha256",
                "antennas",
                "subcarriers",
                "frequency_mhz",
                "ppdu_type",
                "flags",
                "device_boot_id",
            )
            + WIRE_METADATA
        }
        window.update(
            {
                "schema": "ruview.csi.window.v1",
                "amplitude_contract": AMPLITUDE_CONTRACT,
                "timestamps_ns": [f["received_at_ns"] for f in frames],
                "monotonic_ns": [f["received_monotonic_ns"] for f in frames],
                "sequences": [f["sequence"] for f in frames],
                "amplitudes": [
                    [math.hypot(*f["iq"][i : i + 2]) for i in range(0, 128, 2)]
                    for f in frames
                ],
                "policy": {
                    "duration_ns": self.duration_ns,
                    "max_gap_ns": self.max_gap_ns,
                    "min_frames": self.min_frames,
                    "max_clock_step_ns": self.max_clock_step_ns,
                },
                "time_basis": "receiver_host_arrival_not_device_capture",
                "commissioning_profile": self.profiles[node],
                "commissioning_sha256": digest(self.profiles[node]),
            }
        )
        if first["schema"] == FRAME_SCHEMA_V2:
            window.update(
                schema=WINDOW_SCHEMA_V2,
                source_frame_schema=FRAME_SCHEMA_V2,
                capture_id=first["capture_id"],
                worker_run_id=first["worker_run_id"],
                ingress_sequences=[f["ingress_sequence"] for f in frames],
                capture_sequences=[f["capture_sequence"] for f in frames],
            )
        if self.feature_contract == PREFIX_FEATURE_CONTRACT:
            window["feature_selection"] = prefix_selection()
        window["window_id"] = digest(window)
        self.stats["windows"] += 1
        return window


def finite_vector(value, size, name, lower=None, upper=None):
    if not isinstance(value, list) or len(value) != size:
        raise ValueError(f"{name} needs {size} values")
    if any(
        type(v) not in (int, float)
        or not math.isfinite(v)
        or (lower is not None and v < lower)
        or (upper is not None and v > upper)
        for v in value
    ):
        raise ValueError(f"invalid {name}")
    return value


def validate_label(label, *, expected_coordinate_frame=None):
    if (
        label.get("schema") not in ("ruview.ground_truth.v1", LABEL_SCHEMA_V2)
        or label.get("reviewed") is not True
    ):
        raise ValueError("requires reviewed independent ground truth")
    if label["schema"] == LABEL_SCHEMA_V2:
        validate_capture_identity(label)
    for key in ("label_id", "session_id", "trial_id", "provenance", "room_id"):
        nonempty(label.get(key), key)
    if label.get("source") not in (
        "manual_observation",
        "camera_annotation",
        "calibrated_camera",
    ):
        raise ValueError("ground truth must not come from CSI/model predictions")
    start = integer(label.get("start_ns"), "label start", 1)
    if integer(label.get("end_ns"), "label end", 1) <= start:
        raise ValueError("invalid label interval")
    integer(label.get("time_uncertainty_ns"), "time uncertainty", 0)
    integer(label.get("person_count"), "person count", 0)
    integer(label.get("node_id"), "label node_id", 1, 255)
    sha(label.get("configuration_sha256"), "label configuration_sha256")
    sha(label.get("commissioning_sha256"), "label commissioning_sha256")
    if label.get("posture") is not None and label["posture"] not in POSTURES:
        raise ValueError("unknown posture label")
    if label.get("house_xy_m") is not None:
        finite_vector(label["house_xy_m"], 2, "house_xy_m")
        if label.get("coordinate_frame") != approved_coordinate_frame(
            expected_coordinate_frame
        ):
            raise ValueError(
                "house coordinates require the explicit HA X/Z floor frame"
            )
        sha(label.get("coordinate_calibration_sha256"), "coordinate calibration")
        nonempty(
            label.get("coordinate_reference"),
            "independently measured coordinate reference",
        )
    if label.get("image_pose_2d") is not None:
        finite_vector(label["image_pose_2d"], 34, "COCO17 normalized image pose", 0, 1)
        nonempty(label.get("camera_id"), "camera_id")
        sha(label.get("image_geometry_sha256"), "image geometry")
        if label.get("source") not in ("camera_annotation", "calibrated_camera"):
            raise ValueError("image joints require camera reference")
    return label


def pair_window(
    window,
    labels,
    clock_offset_ns,
    max_uncertainty_ns=100_000_000,
    *,
    expected_coordinate_frame=None,
):
    """Offset is added to label times to place them on the CSI arrival clock."""
    validate_window_identity(window)
    is_v2 = window["schema"] == WINDOW_SCHEMA_V2
    if selected_contract(window) == PREFIX_FEATURE_CONTRACT:
        validate_prefix_scope(window)
    if type(clock_offset_ns) is not int:
        raise ValueError("clock offset must be explicit integer nanoseconds")
    integer(max_uncertainty_ns, "max uncertainty", 0)
    candidates = []
    for label in labels:
        validate_label(label, expected_coordinate_frame=expected_coordinate_frame)
        uncertainty = label["time_uncertainty_ns"]
        if (
            (label["schema"] == LABEL_SCHEMA_V2) != is_v2
            or (
                is_v2
                and any(
                    label[key] != window[key]
                    for key in ("capture_id", "worker_run_id", "clock_id")
                )
            )
            or label["session_id"] != window["session_id"]
            or label["node_id"] != window["node_id"]
            or label["configuration_sha256"] != window["configuration_sha256"]
            or label["commissioning_sha256"] != window["commissioning_sha256"]
            or uncertainty > max_uncertainty_ns
        ):
            continue
        lo = label["start_ns"] + clock_offset_ns + uncertainty
        hi = label["end_ns"] + clock_offset_ns - uncertainty
        if lo <= window["timestamps_ns"][0] and window["timestamps_ns"][-1] <= hi:
            candidates.append(label)
    if len(candidates) != 1:
        return None  # Missing/overlapping labels cannot become training truth.
    return {
        "schema": PAIR_SCHEMA_V2 if is_v2 else PAIR_SCHEMA,
        "window": window,
        "label": candidates[0],
        "alignment": {
            "label_to_csi_clock_offset_ns": clock_offset_ns,
            "max_uncertainty_ns": max_uncertainty_ns,
        },
        "validation": "paired_reference_not_model_accuracy",
    }
