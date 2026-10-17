"""Read-only LD2450 V1.03 report decoding and surveyed HA X/Z projection.

No device, file, network, serial-command, or publication side effects. The caller
owns a directly connected, commissioned UART and one monotonic clock domain.
Report slots are transient local slots, never person IDs or skeleton joints.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from .config import AXES, require_complete_profile

HEADER = bytes.fromhex("aa ff 03 00")
FOOTER = bytes.fromhex("55 cc")
FRAME_BYTES = 30
MAX_CHUNK_BYTES = 4096
SCHEMA = "ruview.ld2450.observation.v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def stamp(value: Any) -> int:
    require(
        type(value) is int and value > 0, "positive integer nanosecond clock required"
    )
    return value


def finite(value: Any) -> float:
    require(
        type(value) in (int, float) and math.isfinite(value), "finite number required"
    )
    return float(value)


def identifier(value: Any) -> str:
    require(
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value),
        "nonempty bounded identifier required",
    )
    return value


def digest(value: Any) -> str:
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
        "lowercase SHA-256 required",
    )
    return value


def signed_magnitude(raw: bytes) -> int:
    """The wire sign is positive when bit 15 is SET; this is not int16."""
    require(len(raw) == 2, "two bytes required")
    value = int.from_bytes(raw, "little")
    magnitude = value & 0x7FFF
    return magnitude if value & 0x8000 else -magnitude


@dataclass(frozen=True)
class Target:
    slot: int
    x_mm: int
    y_mm: int
    speed_cm_s: int
    distance_resolution_mm: int


def decode_report(raw: bytes) -> tuple[Target, ...]:
    """Decode exactly one report, preserving units and all nonzero records."""
    require(isinstance(raw, bytes), "report must be bytes")
    require(len(raw) == FRAME_BYTES, "report length must be 30 bytes")
    require(raw.startswith(HEADER) and raw.endswith(FOOTER), "report framing invalid")
    targets = []
    for slot in range(1, 4):
        record = raw[4 + (slot - 1) * 8 : 4 + slot * 8]
        if record == bytes(8):
            continue
        targets.append(
            Target(
                slot,
                signed_magnitude(record[0:2]),
                signed_magnitude(record[2:4]),
                signed_magnitude(record[4:6]),
                int.from_bytes(record[6:8], "little"),
            )
        )
    return tuple(targets)


@dataclass(frozen=True)
class Report:
    raw: bytes
    targets: tuple[Target, ...]
    first_byte_monotonic_ns: int
    first_byte_utc_ns: int
    last_byte_monotonic_ns: int


class StreamDecoder:
    """Bounded report framing. Unframed data never refreshes an observation.

    The protocol has no report checksum, device timestamp, sequence, or ID.
    Framing alone cannot authenticate or prove an uncorrupted measurement.
    """

    def __init__(self) -> None:
        self.buffer: list[tuple[int, int, int]] = []
        self.discarded_bytes = 0
        self.invalid_frames = 0
        self.last_complete_event_valid: bool | None = None

    def feed(self, data: bytes, monotonic_ns: int, utc_ns: int) -> list[Report]:
        require(isinstance(data, bytes), "UART chunk must be bytes")
        require(len(data) <= MAX_CHUNK_BYTES, "UART chunk exceeds 4096 bytes")
        stamp(monotonic_ns)
        stamp(utc_ns)
        self.buffer.extend((byte, monotonic_ns, utc_ns) for byte in data)
        reports = []
        while len(self.buffer) >= len(HEADER):
            raw = bytes(item[0] for item in self.buffer)
            if not raw.startswith(HEADER):
                self.discarded_bytes += 1
                del self.buffer[0]
                continue
            if len(raw) < FRAME_BYTES:
                break
            candidate = raw[:FRAME_BYTES]
            if not candidate.endswith(FOOTER):
                self.invalid_frames += 1
                self.last_complete_event_valid = False
                self.discarded_bytes += 1
                del self.buffer[0]
                continue
            reports.append(
                Report(
                    candidate,
                    decode_report(candidate),
                    self.buffer[0][1],
                    self.buffer[0][2],
                    self.buffer[FRAME_BYTES - 1][1],
                )
            )
            self.last_complete_event_valid = True
            del self.buffer[:FRAME_BYTES]
        return reports


@dataclass(frozen=True)
class Configuration:
    sensor_id: str
    hardware_identity: str
    firmware_version: str
    tracking_mode: str
    serial_endpoint_id: str
    origin_xz_m: tuple[float, float]
    yaw_deg: float
    mounting_height_m: float
    floorplan_sha256: str
    survey_evidence_sha256: str
    declared_transform_uncertainty_m: float
    ttl_ns: int
    sha256: str
    coordinate_frame: str

    @classmethod
    def load(cls, config: dict, *, expected_coordinate_frame=None) -> Configuration:
        require_complete_profile(
            config, expected_coordinate_frame=expected_coordinate_frame
        )
        require(isinstance(config, dict), "configuration must be an object")
        require(
            config.get("schema") == "ruview.ld2450.configuration.v1",
            "configuration schema",
        )
        require(config.get("model") == "HLK-LD2450", "only LD2450 is supported")
        require(
            config.get("hardware_confirmed") is True,
            "hardware commissioning not confirmed",
        )
        require(
            config.get("coordinate_frame") == expected_coordinate_frame,
            "wrong coordinate frame",
        )
        survey = config.get("survey")
        require(isinstance(survey, dict), "survey required")
        require(survey.get("status") == "measured", "measured survey required")
        require(
            survey.get("mounting") == "upright_level",
            "tilted/inverted mounting unsupported",
        )
        require(
            survey.get("axis_convention") == AXES,
            "explicit verified axis convention required",
        )
        require(
            survey.get("axes_verified") is True, "walk-point axis verification required"
        )
        origin = survey.get("origin_xz_m")
        require(
            isinstance(origin, list) and len(origin) == 2,
            "two origin coordinates required",
        )
        origin = tuple(finite(value) for value in origin)
        yaw = finite(survey.get("yaw_deg"))
        require(-180 <= yaw <= 180, "yaw outside [-180,180]")
        height = finite(survey.get("mounting_height_m"))
        require(height > 0, "positive measured mounting height required")
        uncertainty = finite(survey.get("transform_uncertainty_m"))
        require(uncertainty > 0, "positive declared transform uncertainty required")
        ttl_ms = config.get("ttl_ms")
        require(
            type(ttl_ms) is int and 100 <= ttl_ms <= 5000, "ttl_ms outside [100,5000]"
        )
        mode = config.get("tracking_mode")
        require(mode in ("single", "multi"), "verified tracking mode required")
        return cls(
            identifier(config.get("sensor_id")),
            identifier(config.get("hardware_identity")),
            identifier(config.get("firmware_version")),
            mode,
            identifier(config.get("serial_endpoint_id")),
            origin,
            yaw,
            height,
            digest(config.get("floorplan_sha256")),
            digest(survey.get("evidence_sha256")),
            uncertainty,
            ttl_ms * 1_000_000,
            hashlib.sha256(
                json.dumps(
                    config, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest(),
            expected_coordinate_frame,
        )

    def project(self, target: Target) -> list[float]:
        x, y = target.x_mm / 1000, target.y_mm / 1000
        theta = math.radians(self.yaw_deg)
        return [
            self.origin_xz_m[0] + math.cos(theta) * x - math.sin(theta) * y,
            self.origin_xz_m[1] + math.sin(theta) * x + math.cos(theta) * y,
        ]


class ObservationAdapter:
    """One UART connection at a time; reconnects explicitly clear old data.

    UTC and monotonic stamps must come from the same host immediately on UART
    receipt, not MQTT delivery, file replay, or a polling response. Buffering
    before that receipt is not measurable by this protocol. A transport wrapper
    must flush old UART input on connect and call disconnect on read failure.
    """

    def __init__(
        self, config: dict | None = None, *, expected_coordinate_frame=None
    ) -> None:
        self.config = (
            Configuration.load(
                config, expected_coordinate_frame=expected_coordinate_frame
            )
            if config is not None
            else None
        )
        self.decoder = StreamDecoder()
        self.epoch: str | None = None
        self.report: Report | None = None
        self.reason = "hardware_unavailable" if self.config else "configuration_missing"
        self.last_clock: tuple[int, int] | None = None
        self.report_count = 0
        self.connected = False

    def connect(self, source_epoch: str) -> None:
        require(self.config is not None, "configuration missing")
        source_epoch = identifier(source_epoch)
        require(source_epoch != self.epoch, "reconnect requires a new source epoch")
        self.epoch = source_epoch
        self.decoder = StreamDecoder()
        self.report = None
        self.reason = "waiting_for_uart_report"
        self.last_clock = None
        self.report_count = 0
        self.connected = True

    def disconnect(self) -> None:
        self.report = None
        self.decoder = StreamDecoder()
        self.reason = "hardware_unavailable"
        self.last_clock = None
        self.connected = False
        # Keep the previous epoch so reconnect cannot silently reuse it.

    def _clock(self, monotonic_ns: int, utc_ns: int) -> None:
        stamp(monotonic_ns)
        stamp(utc_ns)
        if self.last_clock is not None:
            old_mono, old_utc = self.last_clock
            require(monotonic_ns >= old_mono, "monotonic clock regressed")
            require(
                abs((utc_ns - old_utc) - (monotonic_ns - old_mono)) <= 100_000_000,
                "UTC/monotonic clock discontinuity",
            )
        self.last_clock = monotonic_ns, utc_ns

    def feed(self, data: bytes, *, monotonic_ns: int, utc_ns: int) -> int:
        require(self.config is not None, "configuration missing")
        require(self.connected, "UART disconnected")
        try:
            self._clock(monotonic_ns, utc_ns)
            before = self.decoder.invalid_frames
            reports = self.decoder.feed(data, monotonic_ns, utc_ns)
            for report in reports:
                require(
                    self.config.tracking_mode != "single" or len(report.targets) <= 1,
                    "report contradicts commissioned single-target mode",
                )
                self.report = report
                self.report_count += 1
                self.reason = "fresh_uart_report"
            if (
                self.decoder.invalid_frames != before
                and not self.decoder.last_complete_event_valid
            ):
                self.report = None
                self.reason = "invalid_uart_frame"
            return len(reports)
        except ValueError:
            self.disconnect()
            self.reason = "invalid_input_requires_reconnect"
            raise

    def snapshot(self, *, monotonic_ns: int, utc_ns: int) -> dict:
        result = {
            "schema": SCHEMA,
            "status": "unavailable",
            "reason": self.reason,
            "targets": [],
            "source_epoch": self.epoch,
            "coordinate_frame": self.config.coordinate_frame if self.config else None,
            "person_identity_available": False,
            "body_pose_available": False,
            "body_height_available": False,
            "fall_detection_available": False,
            "recognition_validated": False,
        }
        try:
            self._clock(monotonic_ns, utc_ns)
        except ValueError:
            self.disconnect()
            self.reason = "clock_discontinuity_requires_reconnect"
            result["reason"] = self.reason
            return result
        if self.config is None:
            return result
        c = self.config
        result.update(
            sensor_id=c.sensor_id,
            hardware_identity=c.hardware_identity,
            firmware_version=c.firmware_version,
            tracking_mode=c.tracking_mode,
            serial_endpoint_id=c.serial_endpoint_id,
            configuration_sha256=c.sha256,
            floorplan_sha256=c.floorplan_sha256,
            survey_evidence_sha256=c.survey_evidence_sha256,
            declared_transform_uncertainty_m=c.declared_transform_uncertainty_m,
            position_semantics="radar_target_centroid_transformed_under_declared_survey",
            timestamp_basis="host_first_byte_receipt_not_sensor_acquisition",
            sensor_acquisition_timestamp_available=False,
            wire_checksum_available=False,
            diagnostics={
                "received_reports": self.report_count,
                "discarded_bytes": self.decoder.discarded_bytes,
                "invalid_frames": self.decoder.invalid_frames,
            },
        )
        report = self.report
        if report is None:
            return result
        age = monotonic_ns - report.first_byte_monotonic_ns
        if age < 0 or age >= c.ttl_ns or utc_ns >= report.first_byte_utc_ns + c.ttl_ns:
            result["reason"] = "stale_uart_report"
            return result
        result.update(
            status="available",
            reason="targets_reported"
            if report.targets
            else "no_targets_reported_not_empty_room",
            observed_at_ns=str(report.first_byte_utc_ns),
            expires_at_ns=str(report.first_byte_utc_ns + c.ttl_ns),
            source_age_ms=age / 1_000_000,
            uart_frame_receive_span_ms=(
                report.last_byte_monotonic_ns - report.first_byte_monotonic_ns
            )
            / 1_000_000,
            raw_report_hex=report.raw.hex(),
            raw_report_sha256=hashlib.sha256(report.raw).hexdigest(),
            reported_target_count=len(report.targets),
            targets=[
                {
                    "slot": t.slot,
                    "sensor_xy_mm": [t.x_mm, t.y_mm],
                    "speed_cm_s": t.speed_cm_s,
                    "speed_m_s": t.speed_cm_s / 100,
                    "distance_resolution_mm": t.distance_resolution_mm,
                    "house_xz_m": c.project(t),
                }
                for t in report.targets
            ],
        )
        return result
