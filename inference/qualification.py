"""Reproducible held-out evaluation and offline review; never a deployment permit."""

import argparse
import json
import math
import re

from .capture import file_bytes, strict_json
from .evidence import VERIFIED_MODES, validate_evidence
from .model import evaluate_candidate_values, target_identity, validate_model
from .pipeline import digest, integer, pair_window, sha, validate_label
from .reference_alignment import validate_paired_alignment
from .session_commands import private_json

PROTOCOL = "ruview.model-evaluation-protocol.v1"
REPORT = "ruview.model-evaluation-report.v1"
REVIEW = "ruview.offline-evaluation-review.v1"
MAX_RECORDS = 5000
MAX_SESSIONS = 100
MAX_TRIALS = 1000
COMMON_LIMITS = {
    "min_sessions",
    "min_trials_per_session",
    "min_windows_per_trial",
    "max_time_uncertainty_ns",
}
REVIEW_CHECKS = {
    "capture_originals_reverified",
    "reference_truth_reviewed",
    "clock_alignment_reviewed",
    "policy_predeclared",
    "independent_of_training_and_tuning",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), "unexpected_fields")


def identity(value):
    require(
        type(value) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value),
        "unsafe_identity",
    )
    return value


def number(value, name, upper=None):
    require(
        type(value) in (int, float)
        and math.isfinite(value)
        and value >= 0
        and (upper is None or value <= upper),
        name,
    )
    return value


def percentile95(values):
    """Conservative nearest-rank percentile; no interpolation or dropped tails."""
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def capture_bounds(evidence):
    if evidence["status"] == "verified_closed_capture":
        return tuple(
            evidence[k]["clock"]["utc_ns"] for k in ("start_boundary", "end_boundary")
        )
    return tuple(
        evidence["planned_interval"][k] for k in ("start_utc_ns", "end_utc_ns")
    )


def household_evidence(value, window=None):
    value = validate_evidence(value, window)
    require(value["status"] in VERIFIED_MODES, "unverified_capture")
    require(value["synthetic_only"] is False, "synthetic_capture")
    identity(value["session_id"])
    return value


def policy_for(task, policy):
    extra = (
        {"min_trials_per_class", "min_trial_accuracy", "min_class_trial_accuracy"}
        if task == "posture"
        else {"max_trial_mean_error", "max_trial_p95_error"}
    )
    if task == "image_pose_2d":
        extra.add("max_joint_p95_error")
    keys(policy, COMMON_LIMITS | extra)
    for name, maximum in (
        ("min_sessions", MAX_SESSIONS),
        ("min_trials_per_session", MAX_TRIALS),
        ("min_windows_per_trial", MAX_RECORDS),
    ):
        integer(policy[name], name, 1, maximum)
    integer(policy["max_time_uncertainty_ns"], "time_uncertainty", 0, 10**12)
    if task == "posture":
        integer(policy["min_trials_per_class"], "class_trials", 1, MAX_TRIALS)
        for name in ("min_trial_accuracy", "min_class_trial_accuracy"):
            number(policy[name], name, 1)
    else:
        for name in extra:
            number(policy[name], name)


def evaluate(model, records, protocol, *, expected_coordinate_frame=None):
    """Recompute exact candidate predictions, not the checkpoint's stored metrics.

    Capture/reference declarations are checked for consistency, not authenticated.
    Original evidence and human truth still need a separate independent review.
    """
    require(type(model) is dict, "candidate_document")
    validate_model(model, expected_coordinate_frame=expected_coordinate_frame)
    keys(
        protocol,
        {
            "schema",
            "classification",
            "candidate_sha256",
            "task",
            "author_id",
            "policy",
            "predeclared_policy_sha256",
            "predeclaration_reference_sha256",
            "sessions",
        },
    )
    require(protocol["schema"] == PROTOCOL, "protocol_schema")
    require(protocol["classification"] == "household_recording", "synthetic_protocol")
    require(protocol["candidate_sha256"] == model["model_sha256"], "candidate_binding")
    require(protocol["task"] == model["task"], "task_binding")
    identity(protocol["author_id"])
    sha(protocol["predeclaration_reference_sha256"], "predeclaration_reference")
    task, policy = model["task"], protocol["policy"]
    policy_for(task, policy)
    require(protocol["predeclared_policy_sha256"] == digest(policy), "policy_binding")
    require(type(records) is list and 0 < len(records) <= MAX_RECORDS, "record_bound")
    history = model["capture_lineage"]["recordings"]
    require(0 < len(history) <= MAX_SESSIONS, "verified_model_history_required")
    history = [household_evidence(e) for e in history]
    require(
        len({e["raw_sha256"] for e in history}) == len(history), "aliased_model_history"
    )
    by_session = {e["session_id"]: capture_bounds(e) for e in history}
    for training in model["training_sessions"]:
        start, end = by_session[training]
        require(
            all(
                end <= by_session[s][0] or start >= by_session[s][1]
                for s in model["evaluation_sessions"]
            ),
            "training_development_time_overlap",
        )
    excluded = set(model["training_sessions"] + model["evaluation_sessions"])
    for sid in excluded:
        identity(sid)
    raw_hashes = {e["raw_sha256"] for e in history}
    occupied = [capture_bounds(e) for e in history]
    sessions = protocol["sessions"]
    require(
        type(sessions) is list and 0 < len(sessions) <= MAX_SESSIONS, "session_bound"
    )
    session_map, trial_map, declared_windows = {}, {}, set()
    reference_hashes = set()
    retained_bindings = (
        {"reference_metadata_sha256", "time_alignment_sha256"}
        if model["capture_lineage"]["status"] == "verified_closed_capture"
        else set()
    )
    for session in sessions:
        keys(
            session,
            {
                "session_id",
                "capture_evidence",
                "reference_sha256",
                "reference_review_sha256",
                "clock_review_sha256",
                "reference_independent",
                "reference_reviewed",
                "trials",
            }
            | retained_bindings,
        )
        sid = identity(session["session_id"])
        require(
            sid not in excluded and sid not in session_map,
            "training_development_or_duplicate_session",
        )
        require(
            session["reference_independent"] is True
            and session["reference_reviewed"] is True,
            "independent_reviewed_reference_required",
        )
        for field in (
            "reference_sha256",
            "reference_review_sha256",
            "clock_review_sha256",
        ) + tuple(sorted(retained_bindings)):
            sha(session[field], field)
        require(
            session["reference_sha256"] not in reference_hashes, "renamed_reference"
        )
        reference_hashes.add(session["reference_sha256"])
        evidence = household_evidence(session["capture_evidence"])
        require(evidence["session_id"] == sid, "capture_session_binding")
        require(
            evidence["status"] == model["capture_lineage"]["status"],
            "capture_mode_binding",
        )
        require(evidence["raw_sha256"] not in raw_hashes, "renamed_capture")
        raw_hashes.add(evidence["raw_sha256"])
        start, end = capture_bounds(evidence)
        require(
            all(end <= a or start >= b for a, b in occupied), "capture_time_overlap"
        )
        occupied.append((start, end))
        session_map[sid] = session
        require(
            type(session["trials"]) is list and session["trials"], "trials_required"
        )
        spans = []
        for trial in session["trials"]:
            keys(trial, {"trial_id", "start_utc_ns", "end_utc_ns", "window_ids"})
            tid = identity(trial["trial_id"])
            require(
                (sid, tid) not in trial_map and len(trial_map) < MAX_TRIALS,
                "trial_identity_or_bound",
            )
            lo = integer(trial["start_utc_ns"], "trial_start", start, end)
            hi = integer(trial["end_utc_ns"], "trial_end", lo + 1, end)
            require(all(hi < a or lo > b for a, b in spans), "trial_overlap")
            spans.append((lo, hi))
            ids = trial["window_ids"]
            require(type(ids) is list and 0 < len(ids) <= MAX_RECORDS, "trial_windows")
            for wid in ids:
                sha(wid, "window_id")
                require(wid not in declared_windows, "duplicate_declared_window")
                declared_windows.add(wid)
            require(len(declared_windows) <= MAX_RECORDS, "window_bound")
            trial_map[sid, tid] = {"definition": trial, "rows": []}
    seen, label_bindings, window_spans = set(), {}, {}
    for record in records:
        window, label = (
            record["window"],
            validate_label(
                record["label"], expected_coordinate_frame=expected_coordinate_frame
            ),
        )
        sid, tid, wid = (
            identity(window["session_id"]),
            identity(label["trial_id"]),
            window["window_id"],
        )
        lid = identity(label["label_id"])
        require(
            (sid, lid) not in label_bindings
            or label_bindings[sid, lid] == digest(label),
            "contradictory_label_identity",
        )
        label_bindings[sid, lid] = digest(label)
        require(
            sid in session_map and (sid, tid) in trial_map,
            "undeclared_session_or_trial",
        )
        require(
            wid not in seen and wid in trial_map[sid, tid]["definition"]["window_ids"],
            "duplicate_or_undeclared_window",
        )
        seen.add(wid)
        evidence = household_evidence(record.get("capture_evidence"), window)
        require(
            evidence == session_map[sid]["capture_evidence"], "capture_evidence_changed"
        )
        if evidence["status"] == "verified_closed_capture":
            validate_paired_alignment(
                record, expected_coordinate_frame=expected_coordinate_frame
            )
            require(
                label["reference_lineage"]["review_sha256"]
                == session_map[sid]["reference_review_sha256"],
                "reference_review_binding",
            )
            require(
                label["reference_lineage"]["metadata_sha256"]
                == session_map[sid]["reference_metadata_sha256"],
                "reference_metadata_binding",
            )
            require(
                record["time_alignment"]["alignment_sha256"]
                == session_map[sid]["time_alignment_sha256"],
                "time_alignment_binding",
            )
        require(
            label["person_count"] == 1 and label.get(task) is not None,
            "single_person_task_reference_required",
        )
        require(
            target_identity(label, task) == model["target_identity"],
            "target_geometry_binding",
        )
        require(
            label["time_uncertainty_ns"] <= policy["max_time_uncertainty_ns"],
            "reference_time_uncertainty",
        )
        paired = pair_window(
            window,
            [label],
            record["alignment"]["label_to_csi_clock_offset_ns"],
            record["alignment"]["max_uncertainty_ns"],
            expected_coordinate_frame=expected_coordinate_frame,
        )
        require(
            paired is not None and paired["schema"] == record["schema"],
            "incomplete_label_interval",
        )
        bounds = trial_map[sid, tid]["definition"]
        require(
            bounds["start_utc_ns"]
            <= window["timestamps_ns"][0]
            < window["timestamps_ns"][-1]
            <= bounds["end_utc_ns"],
            "partial_or_outside_trial",
        )
        window_spans.setdefault(sid, []).append(
            (window["timestamps_ns"][0], window["timestamps_ns"][-1])
        )
        prediction = evaluate_candidate_values(
            model,
            window,
            model["feature_contract"],
            expected_coordinate_frame=expected_coordinate_frame,
        )
        if task == "posture":
            require(label[task] in model["classes"], "untrained_posture")
            value = (label[task], prediction)
        else:
            actual = label[task]
            value = [
                math.hypot(prediction[i] - actual[i], prediction[i + 1] - actual[i + 1])
                for i in range(0, len(actual), 2)
            ]
            require(all(math.isfinite(v) for v in value), "nonfinite_error")
        trial_map[sid, tid]["rows"].append(value)
    require(seen == declared_windows, "partial_evaluation_windows")
    for spans in window_spans.values():
        ordered = sorted(spans)
        require(
            all(a[1] < b[0] for a, b in zip(ordered[:-1], ordered[1:], strict=True)),
            "overlapping_evaluation_windows",
        )
    failures, results, class_trials = [], [], {c: [] for c in model["classes"]}
    if len(sessions) < policy["min_sessions"]:
        failures.append("insufficient_sessions")
    for sid, session in session_map.items():
        if len(session["trials"]) < policy["min_trials_per_session"]:
            failures.append("insufficient_trials:" + sid)
    for (sid, tid), trial in sorted(trial_map.items()):
        rows = trial["rows"]
        passed = len(rows) >= policy["min_windows_per_trial"]
        metrics = {"windows": len(rows)}
        if task == "posture":
            metrics["accuracy"] = sum(a == b for a, b in rows) / len(rows)
            metrics["confusion"] = [
                [sum(a == c and b == p for a, b in rows) for p in model["classes"]]
                for c in model["classes"]
            ]
            for c in model["classes"]:
                subset = [(a, b) for a, b in rows if a == c]
                if subset:
                    class_trials[c].append(sum(a == b for a, b in subset) / len(subset))
            passed &= metrics["accuracy"] >= policy["min_trial_accuracy"]
        else:
            errors = [sum(v) / len(v) for v in rows]
            metrics.update(
                mean_error=sum(errors) / len(errors), p95_error=percentile95(errors)
            )
            passed &= (
                metrics["mean_error"] <= policy["max_trial_mean_error"]
                and metrics["p95_error"] <= policy["max_trial_p95_error"]
            )
            if task == "image_pose_2d":
                metrics["joint_p95_errors"] = [
                    percentile95([row[i] for row in rows]) for i in range(17)
                ]
                passed &= (
                    max(metrics["joint_p95_errors"]) <= policy["max_joint_p95_error"]
                )
        if not passed:
            failures.append("trial_policy_failed:" + sid + ":" + tid)
        results.append(
            {
                "session_id": sid,
                "trial_id": tid,
                "passed": bool(passed),
                "metrics": metrics,
            }
        )
    class_metrics = {}
    for c, values in class_trials.items():
        mean = sum(values) / len(values) if values else None
        class_metrics[c] = {"trials": len(values), "trial_mean_accuracy": mean}
        if (
            len(values) < policy["min_trials_per_class"]
            or mean is None
            or mean < policy["min_class_trial_accuracy"]
        ):
            failures.append("class_policy_failed:" + c)
    return {
        "schema": REPORT,
        "candidate_sha256": model["model_sha256"],
        "protocol_sha256": digest(protocol),
        "policy_sha256": digest(policy),
        "paired_sha256": digest(records),
        "task": task,
        "classes": list(model["classes"]),
        "policy": dict(policy),
        "input_identity": model["input_identity"],
        "target_identity": model["target_identity"],
        "units": {
            "posture": "categorical",
            "house_xy_m": "metres",
            "image_pose_2d": "normalized_image_distance",
        }[task],
        "evaluation_sessions": sorted(session_map),
        "session_evidence": {
            sid: {
                "capture_evidence_sha256": digest(session_map[sid]["capture_evidence"]),
                **{
                    key: session_map[sid][key]
                    for key in (
                        "reference_sha256",
                        "reference_review_sha256",
                        "clock_review_sha256",
                    )
                    + tuple(sorted(retained_bindings))
                },
            }
            for sid in sorted(session_map)
        },
        "excluded_development_sessions": sorted(excluded),
        "window_count": len(records),
        "trial_results": results,
        "class_metrics": class_metrics,
        "passed_numerical_policy": not failures,
        "failures": failures,
        "percentile_method": "nearest_rank",
        "external_review_required": True,
        "evidence_authenticated": False,
        "model_qualified": False,
        "runtime_qualified": False,
        "publish_to_ha": False,
        "scope": "held_out_single_person_task_only; no applicability, abstention, tracking or fall validation",
    }


def review(
    model, records, protocol, report, attestation, *, expected_coordinate_frame=None
):
    """Accept a declared independent offline review, without authenticating its author."""
    require(
        digest(report)
        == digest(
            evaluate(
                model,
                records,
                protocol,
                expected_coordinate_frame=expected_coordinate_frame,
            )
        ),
        "evaluation_report_replay_mismatch",
    )
    require(report["passed_numerical_policy"] is True, "numerical_policy_failed")
    keys(
        attestation,
        {
            "schema",
            "status",
            "reviewer_id",
            "reviewed_at_ns",
            "candidate_sha256",
            "protocol_sha256",
            "evaluation_report_sha256",
            "paired_sha256",
            "checks",
        },
    )
    require(
        attestation["schema"] == REVIEW and attestation["status"] == "approved",
        "review_not_approved",
    )
    require(
        identity(attestation["reviewer_id"]) != protocol["author_id"],
        "independent_reviewer_required",
    )
    integer(attestation["reviewed_at_ns"], "review_timestamp", 1)
    for key in ("candidate_sha256", "protocol_sha256", "paired_sha256"):
        require(attestation[key] == report[key], "review_binding")
    require(
        attestation["evaluation_report_sha256"] == digest(report),
        "review_report_binding",
    )
    keys(attestation["checks"], REVIEW_CHECKS)
    require(
        all(v is True for v in attestation["checks"].values()),
        "incomplete_external_review",
    )
    return {
        "schema": "ruview.offline-evaluation-review-result.v1",
        "status": "independently_reviewed_offline_evaluation",
        "candidate_sha256": report["candidate_sha256"],
        "evaluation_report_sha256": digest(report),
        "review_sha256": digest(attestation),
        "task": report["task"],
        "input_identity": report["input_identity"],
        "target_identity": report["target_identity"],
        "passed_numerical_policy": True,
        "external_review_attested": True,
        "reviewer_authenticated": False,
        "evidence_authenticated": False,
        "model_qualified": False,
        "runtime_qualified": False,
        "publish_to_ha": False,
        "remaining_requirements": [
            "applicability_and_abstention",
            "live_provenance_and_expiry",
            "separate_runtime_and_publication_review",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("evaluate", "review"))
    for name in ("model", "paired", "protocol", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--report")
    parser.add_argument("--review", dest="attestation")
    parser.add_argument("--expected-coordinate-frame")
    args = parser.parse_args(argv)
    try:
        require(
            (args.report is not None and args.attestation is not None)
            if args.command == "review"
            else args.report is None and args.attestation is None,
            "review_arguments",
        )
        model = strict_json(file_bytes(args.model, 4 * 1024 * 1024))
        protocol = strict_json(file_bytes(args.protocol, 4 * 1024 * 1024))
        raw = file_bytes(args.paired, 64 * 1024 * 1024)
        require(raw.endswith(b"\n"), "partial_jsonl_tail")
        lines = raw.splitlines()
        require(
            0 < len(lines) <= MAX_RECORDS
            and all(0 < len(line) <= 2 * 1024 * 1024 for line in lines),
            "jsonl_bound",
        )
        records = [strict_json(line) for line in lines]
        result = (
            evaluate(
                model,
                records,
                protocol,
                expected_coordinate_frame=args.expected_coordinate_frame,
            )
            if args.command == "evaluate"
            else review(
                model,
                records,
                protocol,
                strict_json(file_bytes(args.report, 4 * 1024 * 1024)),
                strict_json(file_bytes(args.attestation, 1024 * 1024)),
                expected_coordinate_frame=args.expected_coordinate_frame,
            )
        )
        private_json(args.output, result)
        print(
            json.dumps(
                {
                    "completed": True,
                    "passed_numerical_policy": result["passed_numerical_policy"],
                    "publish_to_ha": False,
                }
            )
        )
        return 0 if result["passed_numerical_policy"] else 2
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
        OverflowError,
    ) as error:
        print(
            json.dumps(
                {
                    "completed": False,
                    "error_type": type(error).__name__,
                    "publish_to_ha": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
