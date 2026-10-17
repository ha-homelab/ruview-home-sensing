"""Pure LD2450 configuration inspection; completeness is not hardware validation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

from inference.pipeline import approved_coordinate_frame

PROFILE_SCHEMA = "ruview.ld2450.configuration.v1"
FLEET_SCHEMA = "ruview.ld2450.fleet.v1"
AXES = "x_right_y_forward__yaw_from_plan_x_toward_z"
PROFILE_FIELDS = {
    "schema",
    "model",
    "sensor_id",
    "hardware_confirmed",
    "hardware_identity",
    "serial_endpoint_id",
    "firmware_version",
    "tracking_mode",
    "coordinate_frame",
    "floorplan_sha256",
    "ttl_ms",
    "survey",
}
SURVEY_FIELDS = {
    "status",
    "mounting",
    "axis_convention",
    "axes_verified",
    "origin_xz_m",
    "yaw_deg",
    "mounting_height_m",
    "transform_uncertainty_m",
    "evidence_sha256",
}


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _number(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def inspect_profile(
    value: Any, path: str = "$", *, expected_coordinate_frame=None
) -> dict:
    errors, pending = [], []

    def issue(target, field, code, message):
        target.append(
            {
                "path": f"{path}.{field}" if field else path,
                "code": code,
                "message": message,
            }
        )

    def field(obj, name, prefix, check, message):
        item = obj.get(name)
        label = prefix + name
        if item is None:
            issue(pending, label, "missing_declaration", message)
        elif not check(item):
            issue(errors, label, "invalid_value", message)

    def ident(item):
        return isinstance(item, str) and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", item
        )

    def sha(item):
        return isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)

    if not isinstance(value, dict):
        issue(errors, "", "invalid_profile", "Each radar profile must be an object.")
        value = {}
    elif set(value) - PROFILE_FIELDS:
        issue(errors, "", "unknown_fields", "Remove fields outside the profile schema.")
    for name, expected in [
        ("schema", PROFILE_SCHEMA),
        ("model", "HLK-LD2450"),
    ]:
        if value.get(name) != expected:
            issue(errors, name, "unsupported_value", f"Must be {expected}.")
    if value.get("coordinate_frame") != approved_coordinate_frame(
        expected_coordinate_frame
    ):
        issue(
            errors,
            "coordinate_frame",
            "unsupported_value",
            "Coordinate frame differs from independent approval.",
        )
    for name in [
        "sensor_id",
        "hardware_identity",
        "serial_endpoint_id",
        "firmware_version",
    ]:
        field(
            value,
            name,
            "",
            ident,
            "Declare a bounded identifier from commissioning evidence.",
        )
    field(
        value,
        "tracking_mode",
        "",
        lambda v: v in ("single", "multi"),
        "Declare the verified single or multi tracking mode.",
    )
    field(
        value,
        "floorplan_sha256",
        "",
        sha,
        "Bind the exact floorplan bytes by lowercase SHA-256.",
    )
    field(
        value,
        "ttl_ms",
        "",
        lambda v: type(v) is int and 100 <= v <= 5000,
        "Use an integer lease from 100 to 5000 ms.",
    )
    if value.get("hardware_confirmed") is not True:
        target = (
            pending
            if value.get("hardware_confirmed") is False
            or value.get("hardware_confirmed") is None
            else errors
        )
        issue(
            target,
            "hardware_confirmed",
            "commissioning_not_declared",
            "Physical identity and UART commissioning have not been declared confirmed.",
        )
    survey = value.get("survey")
    if survey is None:
        survey = {}
    elif not isinstance(survey, dict):
        issue(errors, "survey", "invalid_survey", "Survey must be an object.")
        survey = {}
    elif set(survey) - SURVEY_FIELDS:
        issue(
            errors,
            "survey",
            "unknown_fields",
            "Remove fields outside the survey schema.",
        )
    if survey.get("status") != "measured":
        target = pending if survey.get("status") in (None, "proposed") else errors
        issue(
            target,
            "survey.status",
            "survey_not_declared_measured",
            "Keep proposed until the physical survey has been performed.",
        )
    field(
        survey,
        "mounting",
        "survey.",
        lambda v: v == "upright_level",
        "Only upright, level mounting is supported.",
    )
    field(
        survey,
        "axis_convention",
        "survey.",
        lambda v: v == AXES,
        "Use the documented sensor-to-plan axis convention.",
    )
    if survey.get("axes_verified") is not True:
        target = (
            pending
            if survey.get("axes_verified") is False
            or survey.get("axes_verified") is None
            else errors
        )
        issue(
            target,
            "survey.axes_verified",
            "axes_not_declared_verified",
            "Verify axis directions against physical walking points.",
        )
    field(
        survey,
        "origin_xz_m",
        "survey.",
        lambda v: isinstance(v, list) and len(v) == 2 and all(_number(n) for n in v),
        "Declare two finite measured plan coordinates in metres.",
    )
    field(
        survey,
        "yaw_deg",
        "survey.",
        lambda v: _number(v) and -180 <= v <= 180,
        "Declare measured yaw from -180 to 180 degrees.",
    )
    for name in ["mounting_height_m", "transform_uncertainty_m"]:
        field(
            survey,
            name,
            "survey.",
            lambda v: _number(v) and v > 0,
            "Declare a positive finite value in metres from the survey.",
        )
    field(
        survey,
        "evidence_sha256",
        "survey.",
        sha,
        "Bind the physical survey evidence bytes by lowercase SHA-256.",
    )
    return {
        "sensor_id": value.get("sensor_id") if ident(value.get("sensor_id")) else None,
        "status": "invalid" if errors else "draft" if pending else "config_complete",
        "errors": errors,
        "pending": pending,
    }


def require_complete_profile(value: Any, *, expected_coordinate_frame=None) -> None:
    result = inspect_profile(value, expected_coordinate_frame=expected_coordinate_frame)
    issues = result["errors"] + result["pending"]
    if issues:
        first = issues[0]
        raise ValueError(f"{first['path']}: {first['message']}")


def inspect_document(value: Any, *, expected_coordinate_frame=None) -> dict:
    """Inspect one profile or 1–5 profiles; never validate hardware or labels."""
    errors = []
    profiles = []
    raw_profiles = []
    if isinstance(value, dict) and value.get("schema") == PROFILE_SCHEMA:
        raw_profiles = [value]
        profiles = [
            inspect_profile(value, expected_coordinate_frame=expected_coordinate_frame)
        ]
    elif isinstance(value, dict) and value.get("schema") == FLEET_SCHEMA:
        if set(value) != {"schema", "radars"}:
            errors.append(
                {
                    "path": "$",
                    "code": "invalid_fleet_fields",
                    "message": "Fleet fields must be exactly schema and radars.",
                }
            )
        radars = value.get("radars")
        if not isinstance(radars, list) or not 1 <= len(radars) <= 5:
            errors.append(
                {
                    "path": "$.radars",
                    "code": "invalid_fleet_size",
                    "message": "Configure between one and five radar profiles.",
                }
            )
        else:
            raw_profiles = radars
            profiles = [
                inspect_profile(
                    p,
                    f"$.radars[{i}]",
                    expected_coordinate_frame=expected_coordinate_frame,
                )
                for i, p in enumerate(radars)
            ]
            for field in ["sensor_id", "hardware_identity", "serial_endpoint_id"]:
                seen = set()
                for i, profile in enumerate(radars):
                    item = profile.get(field) if isinstance(profile, dict) else None
                    if not isinstance(item, str) or not item:
                        continue
                    # These are fleet-wide logical identifiers, not case-sensitive OS paths.
                    identity = item.casefold()
                    if identity in seen:
                        errors.append(
                            {
                                "path": f"$.radars[{i}].{field}",
                                "code": "duplicate_binding",
                                "message": f"Each {field} must be unique across this fleet.",
                            }
                        )
                    seen.add(identity)
            hashes = {
                p.get("floorplan_sha256")
                for p in radars
                if isinstance(p, dict) and isinstance(p.get("floorplan_sha256"), str)
            }
            if len(hashes) > 1:
                errors.append(
                    {
                        "path": "$.radars",
                        "code": "mixed_floorplans",
                        "message": "All declared floorplan hashes must match; do not combine coordinate frames.",
                    }
                )
    else:
        errors.append(
            {
                "path": "$.schema",
                "code": "unsupported_schema",
                "message": "Expected an LD2450 single-profile or fleet schema.",
            }
        )
    valid = not errors and all(p["status"] != "invalid" for p in profiles)
    complete = (
        valid
        and bool(profiles)
        and all(p["status"] == "config_complete" for p in profiles)
    )
    result = {
        "schema": "ruview.ld2450.config-inspection.v1",
        "status": "config_complete" if complete else "draft" if valid else "invalid",
        "structurally_valid": valid,
        "declared_config_complete": complete,
        "scope": "configuration_declarations_only_not_measurement_validation",
        "hardware_observed": False,
        "survey_evidence_verified": False,
        "transport_started": False,
        "recognition_validated": False,
        "profiles": profiles,
        "errors": errors,
        "counts": {
            name: sum(p["status"] == name for p in profiles)
            for name in ["config_complete", "draft", "invalid"]
        },
    }
    if valid:
        result["configuration_sha256"] = canonical_sha256(value)
        for profile, raw in zip(profiles, raw_profiles, strict=True):
            profile["configuration_sha256"] = canonical_sha256(raw)
    return result
