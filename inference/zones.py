"""Offline two-zone readiness and score admission; no recorder or fitted model."""

import argparse
import math
import re
from collections import Counter

from .capture import file_bytes, strict_json
from .evidence import validate_session_evidence
from .feature_contracts import selected_contract, validate_contract
from .model import features, model_identity
from .pipeline import (
    PAIR_SCHEMA_V2,
    WINDOW_SCHEMA_V2,
    digest,
    integer,
    nonempty,
    pair_window,
    sha,
)
from .reference_alignment import validate_paired_alignment
from .session_commands import private_json

UNKNOWN = "unknown"
NEGATIVES = ("empty", "stationary", "outside_zones", "transition", "simultaneous_zones")
MAX_DOCUMENT = 32 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def keys(value, wanted):
    require(
        isinstance(value, dict) and set(value) == set(wanted), "unexpected zone fields"
    )


def sealed(value, name):
    sha(value.get(name), name)
    require(
        value[name] == digest({k: v for k, v in value.items() if k != name}),
        "changed " + name,
    )


def number(value, name, minimum=None):
    require(type(value) in (int, float) and math.isfinite(value), "invalid " + name)
    require(minimum is None or value >= minimum, "invalid " + name)
    return value


def definition(value):
    keys(
        value,
        (
            "schema",
            "zone_ids",
            "room_id",
            "floorplan_sha256",
            "zone_geometry_sha256",
            "definition_sha256",
        ),
    )
    require(value["schema"] == "ruview.zone_definition.v1", "zone definition schema")
    zones = value["zone_ids"]
    require(
        isinstance(zones, list) and len(zones) == 2 and len(set(zones)) == 2,
        "exactly two distinct zones required",
    )
    for zone in zones:
        require(
            isinstance(zone, str)
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", zone)
            and zone != UNKNOWN,
            "invalid zone ID",
        )
    nonempty(value["room_id"], "zone room")
    for key in ("floorplan_sha256", "zone_geometry_sha256"):
        sha(value[key], key)
    sealed(value, "definition_sha256")
    return zones + [UNKNOWN]


def plan(value):
    keys(
        value,
        (
            "schema",
            "definition",
            "node_id",
            "feature_contract",
            "training_capture_ids",
            "evaluation_capture_ids",
            "min_windows_per_class",
            "min_trials_per_class",
            "max_label_uncertainty_ns",
            "data_classification",
        ),
    )
    require(value["schema"] == "ruview.zone_readiness_plan.v1", "zone plan schema")
    definition(value["definition"])
    integer(value["node_id"], "selected node", 1, 16)
    validate_contract(value["feature_contract"])
    require(
        value["data_classification"] in ("synthetic", "recorded"),
        "explicit data classification required",
    )
    for name in (
        "min_windows_per_class",
        "min_trials_per_class",
        "max_label_uncertainty_ns",
    ):
        integer(value[name], name, 1)
    for key in ("training_capture_ids", "evaluation_capture_ids"):
        ids = value[key]
        require(
            isinstance(ids, list)
            and ids
            and all(isinstance(v, str) for v in ids)
            and len(ids) == len(set(ids)),
            "explicit unique capture split required",
        )
        for capture in ids:
            require(
                re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    capture,
                ),
                "canonical capture UUID required",
            )
    require(
        not set(value["training_capture_ids"]) & set(value["evaluation_capture_ids"]),
        "same capture cannot train and evaluate",
    )
    return value


def reference(value, paired, scope):
    keys(
        value,
        (
            "schema",
            "reference_id",
            "original_label_sha256",
            "definition_sha256",
            "zone_id",
            "condition",
            "source",
            "reviewed",
            "provenance",
        ),
    )
    require(value["schema"] == "ruview.zone_reference.v1", "zone reference schema")
    require(
        value["reviewed"] is True
        and value["source"] in ("manual_observation", "camera_annotation"),
        "independent reviewed zone reference required",
    )
    nonempty(value["reference_id"], "zone reference ID")
    nonempty(value["provenance"], "zone reference provenance")
    require(
        value["original_label_sha256"] == digest(paired["original_label"]),
        "zone reference original label mismatch",
    )
    require(
        value["definition_sha256"] == scope["definition_sha256"],
        "zone reference geometry mismatch",
    )
    label = paired["label"]
    if value["zone_id"] in scope["zone_ids"]:
        require(
            value["condition"] == "single_zone_movement"
            and label["person_count"] == 1
            and label["room_id"] == scope["room_id"],
            "positive zone needs independent single-zone movement reference",
        )
    else:
        require(
            value["zone_id"] == UNKNOWN and value["condition"] in NEGATIVES,
            "unknown needs an explicit negative condition",
        )
        if value["condition"] == "empty":
            require(label["person_count"] == 0, "empty reference count mismatch")
        if value["condition"] == "simultaneous_zones":
            require(
                label["person_count"] >= 2, "simultaneous-zone reference count mismatch"
            )
    return value


def readiness(settings, records, *, expected_coordinate_frame=None):
    """Validate paired v2 inputs; readiness is not training or model qualification."""
    plan(settings)
    require(
        isinstance(records, list) and len(records) <= 10000,
        "bounded zone records required",
    )
    classes = definition(settings["definition"])
    partitions = {
        capture: part
        for part, key in (
            ("train", "training_capture_ids"),
            ("eval", "evaluation_capture_ids"),
        )
        for capture in settings[key]
    }
    totals = {part: Counter() for part in ("train", "eval")}
    negatives = {part: Counter() for part in totals}
    trials = {part: {name: set() for name in classes} for part in totals}
    sources, windows, refs, identity = {}, set(), {}, None
    reference_intervals = {}
    for row in records:
        keys(row, ("paired", "zone_reference"))
        paired = row["paired"]
        require(
            paired.get("schema") == PAIR_SCHEMA_V2, "zones require original v2 captures"
        )
        window = paired["window"]
        require(window["node_id"] == settings["node_id"], "mixed or unselected node")
        require(
            window.get("ppdu_type") == 0 and window.get("flags") in (0, 16),
            "unqualified zone input header",
        )
        require(
            selected_contract(window) == settings["feature_contract"],
            "zone feature contract mismatch",
        )
        features(window, settings["feature_contract"])
        require(
            window["commissioning_profile"]["floorplan_sha256"]
            == settings["definition"]["floorplan_sha256"],
            "zone floorplan/profile mismatch",
        )
        evidence = validate_session_evidence(paired["capture_evidence"], window)
        require(
            evidence["synthetic_only"]
            == (settings["data_classification"] == "synthetic"),
            "synthetic/recorded classification mismatch",
        )
        validate_paired_alignment(
            paired, expected_coordinate_frame=expected_coordinate_frame
        )
        require(
            paired["label"]["time_uncertainty_ns"]
            <= settings["max_label_uncertainty_ns"],
            "zone label uncertainty exceeds policy",
        )
        require(
            pair_window(
                window,
                [paired["label"]],
                paired["alignment"]["label_to_csi_clock_offset_ns"],
                settings["max_label_uncertainty_ns"],
                expected_coordinate_frame=expected_coordinate_frame,
            )
            is not None,
            "zone reference must cover complete window",
        )
        ref = reference(row["zone_reference"], paired, settings["definition"])
        current_identity = model_identity(window)
        if identity is None:
            identity = current_identity
        require(
            identity == current_identity,
            "mixed node/profile/configuration/window policy",
        )
        require(window["window_id"] not in windows, "duplicate window")
        windows.add(window["window_id"])
        capture = window["capture_id"]
        require(capture in partitions, "capture missing from explicit split")
        source = {
            key: evidence[key]
            for key in (
                "raw_sha256",
                "opening_sha256",
                "terminal_sha256",
                "start_boundary",
                "end_boundary",
                "worker_run_id",
                "clock_id",
            )
        }
        require(
            capture not in sources or sources[capture] == source,
            "capture evidence changed within dataset",
        )
        sources[capture] = source
        ref_key = (capture, ref["reference_id"])
        require(
            ref_key not in refs or refs[ref_key] == ref,
            "zone reference ID reused with different truth",
        )
        refs[ref_key] = ref
        original = paired["original_label"]
        interval = (
            original["start_ns"],
            original["end_ns"],
            ref["zone_id"],
            ref["condition"],
        )
        prior = reference_intervals.setdefault(capture, {})
        for old_key, old in prior.items():
            require(
                old_key == ref_key
                or interval[1] <= old[0]
                or old[1] <= interval[0]
                or interval[2:] == old[2:],
                "overlapping contradictory zone references",
            )
        prior[ref_key] = interval
        part = partitions[capture]
        totals[part][ref["zone_id"]] += 1
        trials[part][ref["zone_id"]].add((capture, paired["label"]["trial_id"]))
        if ref["zone_id"] == UNKNOWN:
            negatives[part][ref["condition"]] += 1
    # Whole raw capture ranges, not just selected labeled windows, must be disjoint.
    for a, left in sources.items():
        for b, right in sources.items():
            if partitions[a] == partitions[b]:
                continue
            require(
                left["raw_sha256"] != right["raw_sha256"],
                "renamed raw recording cannot be held out",
            )
            require(
                left["end_boundary"]["clock"]["utc_ns"]
                < right["start_boundary"]["clock"]["utc_ns"]
                or right["end_boundary"]["clock"]["utc_ns"]
                < left["start_boundary"]["clock"]["utc_ns"],
                "training/evaluation capture intervals overlap",
            )
    missing = [
        "missing_capture:" + capture
        for capture in sorted(set(partitions) - set(sources))
    ]
    for part in totals:
        for name in classes:
            if totals[part][name] < settings["min_windows_per_class"]:
                missing.append(part + ":insufficient_windows:" + name)
            if len(trials[part][name]) < settings["min_trials_per_class"]:
                missing.append(part + ":insufficient_trials:" + name)
        for condition in NEGATIVES:
            if not negatives[part][condition]:
                missing.append(part + ":missing_unknown_condition:" + condition)
    result = {
        "schema": "ruview.zone_readiness.v1",
        "plan_sha256": digest(settings),
        "dataset_sha256": digest(records),
        "definition_sha256": settings["definition"]["definition_sha256"],
        "data_classification": settings["data_classification"],
        "contract_ready": not missing,
        "recorded_data_ready": not missing
        and settings["data_classification"] == "recorded",
        "missing": missing,
        "windows": {
            part: {name: totals[part][name] for name in classes} for part in totals
        },
        "trials": {
            part: {name: len(trials[part][name]) for name in classes} for part in trials
        },
        "unknown_conditions": {part: dict(negatives[part]) for part in negatives},
        "captures": sources,
        "input_identity": identity,
        "model_fitted": False,
        "recognition_validated": False,
        "publish_to_ha": False,
        "limits": "Checks paired metadata and clock lineage, not original-file authenticity, annotation truth, physical separability, or accuracy. Reverify originals with existing capture/reference tools. Minimum counts are caller policy, not qualification thresholds.",
    }
    result["readiness_sha256"] = digest(result)
    return result


def decision(settings, observation, review=None, artifact_sha256=None):
    """Admit externally computed scores only; never invent scores or fit weights.

    Review/score documents are caller evidence, not authenticated attestations.
    Even an admitted result remains a private candidate with no HA authorization.
    """
    keys(
        settings,
        (
            "schema",
            "definition",
            "feature_contract",
            "max_age_ns",
            "min_score",
            "min_margin",
            "max_domain_distance",
            "policy_sha256",
        ),
    )
    require(
        settings["schema"] == "ruview.zone_decision_policy.v1",
        "zone decision policy schema",
    )
    classes = definition(settings["definition"])
    validate_contract(settings["feature_contract"])
    integer(settings["max_age_ns"], "maximum input age", 1, 2_000_000_000)
    number(settings["min_score"], "minimum score")
    number(settings["min_margin"], "minimum margin", 0)
    number(settings["max_domain_distance"], "maximum domain distance", 0)
    sealed(settings, "policy_sha256")

    def result(reason, zone=UNKNOWN):
        return {
            "schema": "ruview.zone_decision.v1",
            "zone": zone,
            "reason": reason,
            "status": "abstained" if zone == UNKNOWN else "candidate_only",
            "confidence": None,
            "recognition_validated": False,
            "publish_to_ha": False,
            "policy_sha256": settings["policy_sha256"],
            "model_sha256": artifact_sha256,
        }

    if review is None or artifact_sha256 is None:
        return result("no_reviewed_trained_artifact")
    keys(
        review,
        (
            "schema",
            "status",
            "model_sha256",
            "training_report_sha256",
            "evaluation_report_sha256",
            "independent_review_sha256",
            "training_capture_ids",
            "evaluation_capture_ids",
            "input_identity_sha256",
            "policy_sha256",
            "definition_sha256",
            "feature_contract",
            "class_order",
            "review_sha256",
        ),
    )
    require(
        review["schema"] == "ruview.zone_model_review.v1", "zone model review schema"
    )
    sealed(review, "review_sha256")
    if review["status"] != "independently_reviewed_trained_candidate":
        return result("model_not_reviewed_trained")
    for key in (
        "model_sha256",
        "training_report_sha256",
        "evaluation_report_sha256",
        "independent_review_sha256",
        "input_identity_sha256",
    ):
        sha(review[key], key)
    if review["model_sha256"] != artifact_sha256:
        return result("model_artifact_mismatch")
    if (
        any(
            review[key] != settings[key]
            for key in ("feature_contract", "policy_sha256")
        )
        or review["definition_sha256"] != settings["definition"]["definition_sha256"]
        or review["class_order"] != classes
    ):
        return result("model_contract_mismatch")
    for key in ("training_capture_ids", "evaluation_capture_ids"):
        require(
            isinstance(review[key], list)
            and review[key]
            and all(isinstance(x, str) for x in review[key]),
            "model requires capture split",
        )
    if set(review["training_capture_ids"]) & set(review["evaluation_capture_ids"]):
        return result("model_capture_leakage")
    if observation is None:
        return result("no_input")
    keys(
        observation,
        (
            "schema",
            "window",
            "model_sha256",
            "scores",
            "domain_distance",
            "signal_sufficient",
            "scope",
            "scope_evidence_reference",
            "now_monotonic_ns",
            "clock_id",
        ),
    )
    require(
        observation["schema"] == "ruview.zone_score_evidence.v1", "zone score schema"
    )
    window = observation["window"]
    if (
        window.get("schema") != WINDOW_SCHEMA_V2
        or window.get("ppdu_type") != 0
        or window.get("flags") not in (0, 16)
    ):
        return result("invalid_or_incompatible_input")
    try:
        features(window, settings["feature_contract"])
    except (KeyError, TypeError, ValueError):
        return result("invalid_or_incompatible_input")
    if (
        observation["model_sha256"] != artifact_sha256
        or digest(model_identity(window)) != review["input_identity_sha256"]
    ):
        return result("input_model_identity_mismatch")
    if (
        window["commissioning_profile"]["floorplan_sha256"]
        != settings["definition"]["floorplan_sha256"]
    ):
        return result("input_geometry_mismatch")
    if observation["clock_id"] != window["clock_id"]:
        return result("clock_domain_mismatch")
    now = integer(observation["now_monotonic_ns"], "current monotonic timestamp", 0)
    age = now - window["monotonic_ns"][-1]
    if age < 0 or age > settings["max_age_ns"]:
        return result("future_or_stale_input")
    require(
        type(observation["signal_sufficient"]) is bool,
        "explicit signal assessment required",
    )
    if not observation["signal_sufficient"]:
        return result("insufficient_signal")
    require(
        observation["scope"] in ("single_zone", "simultaneous_zones", "unknown"),
        "explicit scope assessment required",
    )
    if observation["scope"] != "single_zone":
        return result("simultaneous_or_unknown_scope")
    nonempty(observation["scope_evidence_reference"], "independent scope assessment")
    if (
        number(observation["domain_distance"], "domain distance", 0)
        > settings["max_domain_distance"]
    ):
        return result("out_of_domain")
    scores = observation["scores"]
    keys(scores, classes)
    for value in scores.values():
        number(value, "classifier score")
    ranked = sorted(scores, key=lambda name: scores[name], reverse=True)
    winner, second = ranked[:2]
    if winner == UNKNOWN:
        return result("unknown_class")
    if scores[winner] < settings["min_score"]:
        return result("insufficient_score")
    if scores[winner] - scores[second] <= settings["min_margin"]:
        return result("ambiguous_scores")
    return result("reviewed_candidate_score_admitted", winner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("readiness")
    check.add_argument("--plan", required=True)
    check.add_argument(
        "--records",
        required=True,
        help="JSON array of paired records and independent zone references",
    )
    admit = sub.add_parser("decision")
    admit.add_argument("--policy", required=True)
    admit.add_argument("--observation")
    admit.add_argument("--model-review")
    admit.add_argument("--model-artifact")
    for command in (check, admit):
        command.add_argument("--output", required=True)
    check.add_argument("--expected-coordinate-frame")
    args = parser.parse_args()

    def load(path):
        return strict_json(file_bytes(path, MAX_DOCUMENT)) if path else None

    if args.command == "readiness":
        output = readiness(
            load(args.plan),
            load(args.records),
            expected_coordinate_frame=args.expected_coordinate_frame,
        )
    else:
        import hashlib

        require(
            bool(args.model_review) == bool(args.model_artifact),
            "model review and artifact must be supplied together",
        )
        artifact = (
            hashlib.sha256(file_bytes(args.model_artifact, MAX_DOCUMENT)).hexdigest()
            if args.model_artifact
            else None
        )
        output = decision(
            load(args.policy), load(args.observation), load(args.model_review), artifact
        )
    private_json(args.output, output)
    print(output.get("reason", "contract_ready=" + str(output.get("contract_ready"))))


if __name__ == "__main__":
    main()
