"""Actual offline ridge zone baseline; fitted artifacts remain private candidates."""

import argparse
from collections import Counter

from .capture import file_bytes, strict_json
from .feature_contracts import feature_count, validate_contract
from .model import features, model_identity
from .pipeline import WINDOW_SCHEMA_V2, digest, finite_vector, integer, sha
from .session_commands import private_json
from .zones import (
    MAX_DOCUMENT,
    NEGATIVES,
    UNKNOWN,
    decision,
    definition,
    keys,
    number,
    readiness,
    require,
    sealed,
)

SCHEMA = "ruview.zone_ridge_candidate.v1"
DOMAIN = "minimum_rms_distance_to_train_standardized_class_centroid_v1"


def _policy(policy, settings=None):
    # Reuse the complete policy validator, without presenting a model or scores.
    decision(policy, None)
    if settings is not None:
        require(
            policy["definition"] == settings["definition"]
            and policy["feature_contract"] == settings["feature_contract"],
            "model policy differs from readiness plan",
        )


def _rows(settings, records, *, expected_coordinate_frame=None):
    report = readiness(
        settings, records, expected_coordinate_frame=expected_coordinate_frame
    )
    require(
        report["contract_ready"],
        "zone dataset is not contract-ready: " + ",".join(report["missing"]),
    )
    train_ids = set(settings["training_capture_ids"])
    fitted = sorted(
        (r for r in records if r["paired"]["window"]["capture_id"] in train_ids),
        key=lambda r: r["paired"]["window"]["window_id"],
    )
    held = sorted(
        (r for r in records if r["paired"]["window"]["capture_id"] not in train_ids),
        key=lambda r: r["paired"]["window"]["window_id"],
    )
    return report, fitted, held


def _matrix(rows, contract):
    import numpy as np

    return np.asarray(
        [features(r["paired"]["window"], contract) for r in rows], dtype=np.float64
    )


def _distances(standardized, centroids):
    import numpy as np

    return np.asarray(
        [
            min(float(np.sqrt(np.mean((row - center) ** 2))) for center in centroids)
            for row in standardized
        ]
    )


def train(
    settings, records, policy, regularization=1.0, *, expected_coordinate_frame=None
):
    """Fit only the declared training captures; report untouched held-out scores."""
    import numpy as np

    _policy(policy, settings)
    number(regularization, "ridge penalty", 0)
    require(regularization > 0, "ridge penalty must be positive")
    report, fitted, _ = _rows(
        settings, records, expected_coordinate_frame=expected_coordinate_frame
    )
    classes = definition(settings["definition"])
    x = _matrix(fitted, settings["feature_contract"])
    labels = np.asarray([classes.index(r["zone_reference"]["zone_id"]) for r in fitted])
    mean, scale = x.mean(axis=0), x.std(axis=0)
    scale[scale < 1e-8] = 1.0
    z = (x - mean) / scale
    targets = np.eye(3)[labels]
    bias = targets.mean(axis=0)
    centered = targets - bias
    if len(z) < z.shape[1]:
        weights = z.T @ np.linalg.solve(
            z @ z.T + regularization * np.eye(len(z)), centered
        )
    else:
        weights = np.linalg.solve(
            z.T @ z + regularization * np.eye(z.shape[1]), z.T @ centered
        )
    centroids = np.asarray([z[labels == label].mean(axis=0) for label in range(3)])
    distances = _distances(z, centroids)
    model = {
        "schema": SCHEMA,
        "status": "candidate_unqualified",
        "task": "movement_zone",
        "publish_to_ha": False,
        "recognition_validated": False,
        "data_classification": settings["data_classification"],
        "definition": settings["definition"],
        "classes": classes,
        "feature_contract": settings["feature_contract"],
        "input_identity": report["input_identity"],
        "policy": policy,
        "regularization": regularization,
        "mean": mean.tolist(),
        "scale": scale.tolist(),
        "weights": weights.tolist(),
        "bias": bias.tolist(),
        "domain_centroids": centroids.tolist(),
        "domain_metric": DOMAIN,
        "training_distance_summary": {
            "median": float(np.median(distances)),
            "p95": float(np.quantile(distances, 0.95)),
            "max": float(distances.max()),
        },
        "training_capture_ids": sorted(settings["training_capture_ids"]),
        "training_raw_sha256": sorted(
            {r["paired"]["capture_evidence"]["raw_sha256"] for r in fitted}
        ),
        "training_data_sha256": digest(fitted),
        "training_windows": len(fitted),
        "training_class_counts": {
            name: int(np.sum(labels == i)) for i, name in enumerate(classes)
        },
        "threshold_selection": "explicit_policy_before_held_out_evaluation_no_automatic_tuning",
    }
    model["model_sha256"] = digest(model)
    validate_model(model)
    return model, evaluate(
        model, settings, records, expected_coordinate_frame=expected_coordinate_frame
    )


def validate_model(model):
    keys(
        model,
        (
            "schema",
            "status",
            "task",
            "publish_to_ha",
            "recognition_validated",
            "data_classification",
            "definition",
            "classes",
            "feature_contract",
            "input_identity",
            "policy",
            "regularization",
            "mean",
            "scale",
            "weights",
            "bias",
            "domain_centroids",
            "domain_metric",
            "training_distance_summary",
            "training_capture_ids",
            "training_raw_sha256",
            "training_data_sha256",
            "training_windows",
            "training_class_counts",
            "threshold_selection",
            "model_sha256",
        ),
    )
    require(
        model["schema"] == SCHEMA
        and model["status"] == "candidate_unqualified"
        and model["task"] == "movement_zone",
        "unsupported zone model",
    )
    require(
        model["publish_to_ha"] is False and model["recognition_validated"] is False,
        "zone baseline cannot claim qualification",
    )
    require(
        model["data_classification"] in ("recorded", "synthetic"),
        "model data classification required",
    )
    require(
        model["classes"] == definition(model["definition"]),
        "model class order mismatch",
    )
    sealed(model, "model_sha256")
    validate_contract(model["feature_contract"])
    _policy(model["policy"], model)
    require(model["domain_metric"] == DOMAIN, "unsupported domain distance")
    require(
        model["threshold_selection"]
        == "explicit_policy_before_held_out_evaluation_no_automatic_tuning",
        "unsupported threshold selection",
    )
    count = feature_count(model["feature_contract"])
    finite_vector(model["mean"], count, "training mean")
    finite_vector(model["scale"], count, "training scale")
    require(all(v > 0 for v in model["scale"]), "training scales must be positive")
    require(
        isinstance(model["weights"], list) and len(model["weights"]) == count,
        "model coefficient shape",
    )
    for row in model["weights"]:
        finite_vector(row, 3, "class coefficients")
    finite_vector(model["bias"], 3, "class intercepts")
    require(
        isinstance(model["domain_centroids"], list)
        and len(model["domain_centroids"]) == 3,
        "domain centroid shape",
    )
    for center in model["domain_centroids"]:
        finite_vector(center, count, "training centroid")
    number(model["regularization"], "ridge penalty", 0)
    require(model["regularization"] > 0, "ridge penalty must be positive")
    require(
        isinstance(model["input_identity"], dict)
        and model["input_identity"].get("source_frame_schema") == "ruview.csi.frame.v2",
        "model requires native v2 identity",
    )
    integer(model["training_windows"], "training window count", 3)
    keys(model["training_class_counts"], model["classes"])
    for count in model["training_class_counts"].values():
        integer(count, "training class count", 1)
    require(
        sum(model["training_class_counts"].values()) == model["training_windows"],
        "training counts do not reconcile",
    )
    keys(model["training_distance_summary"], ("median", "p95", "max"))
    for value in model["training_distance_summary"].values():
        number(value, "training distance", 0)
    for key in ("training_capture_ids", "training_raw_sha256"):
        require(
            isinstance(model[key], list)
            and model[key]
            and all(isinstance(v, str) for v in model[key])
            and len(model[key]) == len(set(model[key])),
            "model training provenance missing or duplicated",
        )
    for value in model["training_raw_sha256"]:
        sha(value, "training raw hash")
    sha(model["training_data_sha256"], "training data hash")
    return model


def _score(model, vector):
    import numpy as np

    z = (np.asarray(vector) - np.asarray(model["mean"])) / np.asarray(model["scale"])
    scores = z @ np.asarray(model["weights"]) + np.asarray(model["bias"])
    distance = float(_distances([z], np.asarray(model["domain_centroids"]))[0])
    require(
        np.isfinite(scores).all() and np.isfinite(distance), "nonfinite model result"
    )
    return dict(zip(model["classes"], scores.tolist(), strict=True)), distance


def _classify(model, scores, distance):
    policy = model["policy"]
    if distance > policy["max_domain_distance"]:
        return UNKNOWN, "out_of_domain"
    ranked = sorted(scores, key=lambda name: scores[name], reverse=True)
    first, second = ranked[:2]
    if first == UNKNOWN:
        return UNKNOWN, "unknown_class"
    if scores[first] < policy["min_score"]:
        return UNKNOWN, "insufficient_score"
    if scores[first] - scores[second] <= policy["min_margin"]:
        return UNKNOWN, "ambiguous_scores"
    return first, "candidate_score_admitted"


def score(model, window):
    """Produce actual fitted-model scores and a training-derived distance."""
    validate_model(model)
    require(
        window.get("schema") == WINDOW_SCHEMA_V2
        and window.get("ppdu_type") == 0
        and window.get("flags") in (0, 16),
        "unqualified model input header",
    )
    vector = features(window, model["feature_contract"])
    require(
        model_identity(window) == model["input_identity"],
        "window/model identity mismatch",
    )
    require(
        window["commissioning_profile"]["floorplan_sha256"]
        == model["definition"]["floorplan_sha256"],
        "model floorplan mismatch",
    )
    scores, distance = _score(model, vector)
    return scores, distance


def predict(model, window, context=None):
    """Score an offline window; require explicit input context for a zone decision."""
    scores, distance = score(model, window)
    zone, reason = UNKNOWN, "input_context_unverified"
    if context is not None:
        keys(
            context,
            (
                "clock_id",
                "now_monotonic_ns",
                "signal_sufficient",
                "scope",
                "scope_evidence_reference",
            ),
        )
        require(
            type(context["signal_sufficient"]) is bool,
            "explicit signal assessment required",
        )
        require(
            context["scope"] in ("single_zone", "simultaneous_zones", "unknown"),
            "explicit scope assessment required",
        )
        now = integer(context["now_monotonic_ns"], "current monotonic timestamp", 0)
        age = now - window["monotonic_ns"][-1]
        if context["clock_id"] != window["clock_id"]:
            reason = "clock_domain_mismatch"
        elif age < 0 or age > model["policy"]["max_age_ns"]:
            reason = "future_or_stale_input"
        elif not context["signal_sufficient"]:
            reason = "insufficient_signal"
        elif context["scope"] != "single_zone":
            reason = "simultaneous_or_unknown_scope"
        else:
            from .pipeline import nonempty

            nonempty(context["scope_evidence_reference"], "scope evidence")
            zone, reason = _classify(model, scores, distance)
    return {
        "schema": "ruview.zone_ridge_prediction.v1",
        "model_sha256": model["model_sha256"],
        "window_id": window["window_id"],
        "data_classification": model["data_classification"],
        "zone": zone,
        "reason": reason,
        "scores": scores,
        "domain_distance": distance,
        "domain_metric": DOMAIN,
        "confidence": None,
        "status": "candidate_unqualified",
        "recognition_validated": False,
        "publish_to_ha": False,
    }


def evaluate(model, settings, records, *, expected_coordinate_frame=None):
    """Use held-out features only for scoring; never fit or select thresholds here."""
    validate_model(model)
    report, fitted, held = _rows(
        settings, records, expected_coordinate_frame=expected_coordinate_frame
    )
    require(
        settings["definition"] == model["definition"]
        and settings["feature_contract"] == model["feature_contract"]
        and settings["data_classification"] == model["data_classification"],
        "evaluation/model scope mismatch",
    )
    require(
        report["input_identity"] == model["input_identity"]
        and digest(fitted) == model["training_data_sha256"],
        "evaluation changed original fitted dataset",
    )
    require(
        sorted(settings["training_capture_ids"]) == model["training_capture_ids"],
        "evaluation changed fitted capture IDs",
    )
    classes = model["classes"]
    confusion = [[0] * 3 for _ in range(3)]
    reasons, negatives = (
        Counter(),
        {name: {"windows": 0, "false_zone_acceptances": 0} for name in NEGATIVES},
    )
    majority = max(classes, key=lambda name: model["training_class_counts"][name])
    majority_correct, accepted_correct = 0, 0
    for row in held:
        scores, distance = score(model, row["paired"]["window"])
        predicted, reason = _classify(model, scores, distance)
        truth = row["zone_reference"]["zone_id"]
        confusion[classes.index(truth)][classes.index(predicted)] += 1
        reasons[reason] += 1
        majority_correct += truth == majority
        accepted_correct += predicted != UNKNOWN and truth == predicted
        if truth == UNKNOWN:
            condition = row["zone_reference"]["condition"]
            negatives[condition]["windows"] += 1
            negatives[condition]["false_zone_acceptances"] += predicted != UNKNOWN
    per_class = {}
    for i, name in enumerate(classes):
        truth_count, predicted_count = (
            sum(confusion[i]),
            sum(row[i] for row in confusion),
        )
        correct = confusion[i][i]
        per_class[name] = {
            "truth_windows": truth_count,
            "predicted_windows": predicted_count,
            "correct": correct,
            "precision": correct / predicted_count if predicted_count else None,
            "recall": correct / truth_count if truth_count else None,
        }
    for values in negatives.values():
        values["false_acceptance_rate"] = (
            values["false_zone_acceptances"] / values["windows"]
            if values["windows"]
            else None
        )
    count = len(held)
    unknown = per_class[UNKNOWN]["predicted_windows"]
    accepted = count - unknown
    return {
        "schema": "ruview.zone_ridge_evaluation.v1",
        "model_sha256": model["model_sha256"],
        "data_classification": model["data_classification"],
        "evaluation_data_sha256": digest(held),
        "evaluation_capture_ids": sorted(settings["evaluation_capture_ids"]),
        "evaluation_raw_sha256": sorted(
            {r["paired"]["capture_evidence"]["raw_sha256"] for r in held}
        ),
        "policy_sha256": model["policy"]["policy_sha256"],
        "class_order": classes,
        "confusion_rows_truth_columns_prediction": confusion,
        "per_class": per_class,
        "total_windows": count,
        "accepted_zone_predictions": accepted,
        "unknown_predictions": unknown,
        "unknown_class_predictions": reasons["unknown_class"],
        "gate_abstentions": unknown - reasons["unknown_class"],
        "unknown_output_rate": unknown / count,
        "gate_abstention_rate": (unknown - reasons["unknown_class"]) / count,
        "accepted_zone_accuracy": accepted_correct / accepted if accepted else None,
        "three_class_accuracy": sum(confusion[i][i] for i in range(3)) / count,
        "training_majority_class": majority,
        "majority_baseline_accuracy": majority_correct / count,
        "decision_reasons": dict(reasons),
        "negative_conditions": negatives,
        "ground_truth_used_to_gate_predictions": False,
        "thresholds_tuned_on_evaluation": False,
        "recognition_validated": False,
        "publish_to_ha": False,
        "limit": "Offline held-out candidate result, not independent model qualification. Negative truth never forces unknown: false acceptance remains measurable. Collection/selection history and scope remain independently reviewable.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fit = sub.add_parser("train")
    fit.add_argument("--policy", required=True)
    fit.add_argument("--regularization", type=float, default=1.0)
    fit.add_argument("--model-output", required=True)
    fit.add_argument("--report-output", required=True)
    assess = sub.add_parser("evaluate")
    assess.add_argument("--model", required=True)
    assess.add_argument("--output", required=True)
    for command in (fit, assess):
        command.add_argument("--plan", required=True)
        command.add_argument("--records", required=True)
    infer = sub.add_parser("predict")
    infer.add_argument("--model", required=True)
    infer.add_argument("--window", required=True)
    infer.add_argument("--context")
    infer.add_argument("--output", required=True)
    parser.add_argument("--expected-coordinate-frame")
    args = parser.parse_args()

    def load(path):
        return strict_json(file_bytes(path, MAX_DOCUMENT)) if path else None

    if args.command == "train":
        model, report = train(
            load(args.plan),
            load(args.records),
            load(args.policy),
            args.regularization,
            expected_coordinate_frame=args.expected_coordinate_frame,
        )
        private_json(args.model_output, model)
        private_json(args.report_output, report)
        print("candidate fitted; held-out report written; no publication authorization")
    elif args.command == "evaluate":
        private_json(
            args.output,
            evaluate(
                load(args.model),
                load(args.plan),
                load(args.records),
                expected_coordinate_frame=args.expected_coordinate_frame,
            ),
        )
    else:
        private_json(
            args.output,
            predict(load(args.model), load(args.window), load(args.context)),
        )


if __name__ == "__main__":
    main()
