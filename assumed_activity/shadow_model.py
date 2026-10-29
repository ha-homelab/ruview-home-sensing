"""Train/load shadow models of independent sensor outputs, never occupancy."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import stat
import statistics
import tempfile
from pathlib import Path

SCHEMA = "ruview.shadow-motion-example.v1"
POLICY_SCHEMA = "ruview.shadow-motion-policy.v1"
MODEL_SCHEMA = "ruview.shadow-motion-model.v1"
TASK = "independent_sensor_activity_proxy"
MAX_EXAMPLES = 250_000
MAX_FILE_BYTES = 256 * 1024 * 1024


class ShadowModelError(ValueError):
    """Input cannot support the declared model or evaluation."""


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def timestamp(value):
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or not math.isfinite(result.timestamp()):
            raise ValueError()
        return result.timestamp()
    except (ValueError, TypeError, AttributeError) as exc:
        raise ShadowModelError("A timezone-aware timestamp is required") from exc


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def require(condition, reason):
    if not condition:
        raise ShadowModelError(reason)


def validate_contract(contract):
    require(isinstance(contract, dict), "Missing feature contract")
    require(
        isinstance(contract.get("name"), str) and contract["name"],
        "Unnamed feature contract",
    )
    require(
        type(contract.get("version")) is int and contract["version"] > 0,
        "Invalid contract version",
    )
    features = contract.get("features")
    require(
        isinstance(features, list) and 0 < len(features) <= 64, "Invalid feature count"
    )
    require(
        all(isinstance(x, str) and 0 < len(x) <= 160 for x in features),
        "Invalid feature name",
    )
    require(len(set(features)) == len(features), "Duplicate feature names")
    require(
        isinstance(contract.get("identity"), dict) and contract["identity"],
        "Missing input identity",
    )
    require(len(canonical(contract)) <= 32_768, "Oversized feature contract")


def validate_policy(policy):
    require(policy.get("schema") == POLICY_SCHEMA, "Unexpected policy schema")
    validate_contract(policy.get("feature_contract"))
    groups = policy.get("reference_groups")
    require(
        isinstance(groups, list) and 0 < len(groups) <= 64,
        "Missing selected reference groups",
    )
    require(
        all(isinstance(x, str) and x and len(x) <= 200 for x in groups),
        "Invalid reference group",
    )
    require(len(set(groups)) == len(groups), "Duplicate reference groups")
    require(
        all("ruview" not in x.lower() for x in groups),
        "Derived RuView reference is prohibited",
    )
    require(
        timestamp(policy["validation_start_utc"])
        < timestamp(policy["final_holdout_start_utc"]),
        "Invalid chronological split",
    )
    for key, default, low, high in [
        ("split_gap_seconds", 30, 0, 3600),
        ("reference_max_age_seconds", 10, 0, 300),
        ("learning_rate", 0.1, 0.001, 1),
        ("l2", 0.01, 0, 10),
        ("threshold", 0.5, 0.01, 0.99),
        ("minimum_logloss_improvement", 0.0, 0, 1),
    ]:
        require(
            finite(policy.get(key, default))
            and low <= policy.get(key, default) <= high,
            "Invalid policy value: " + key,
        )
    for key, default, low, high in [
        ("epochs", 400, 1, 3000),
        ("min_train_per_class", 10, 2, 10000),
        ("min_validation_per_class", 5, 2, 10000),
    ]:
        value = policy.get(key, default)
        require(
            type(value) is int and low <= value <= high, "Invalid policy value: " + key
        )


def bounds(row):
    require(isinstance(row, dict), "Example must be an object")
    require(row.get("schema") == SCHEMA, "Unexpected example schema")
    require(
        isinstance(row.get("example_id"), str) and row["example_id"],
        "Missing example identity",
    )
    start, at, end = (
        timestamp(row.get(k))
        for k in ("interval_start_utc", "observed_at_utc", "interval_end_utc")
    )
    require(start <= at <= end and end - start <= 300, "Invalid feature interval")
    return start, at, end


def feature_vector(row, contract):
    if row.get("feature_contract") != contract:
        return None, "feature_contract_mismatch"
    if row.get("quality", {}).get("eligible") is not True:
        return None, "input_quality_unavailable"
    if row.get("maintenance_excluded") is not False:
        return None, "maintenance_or_exclusion_unknown"
    values = row.get("features")
    if not isinstance(values, dict):
        return None, "missing_features"
    names = contract["features"]
    if any(not finite(values.get(key)) for key in names):
        return None, "missing_or_nonfinite_features"
    if any(abs(values[key]) > 1e15 for key in names):
        return None, "feature_out_of_bounds"
    return [float(values[key]) for key in names], None


def reference_target(row, policy, at):
    """Deduplicate aliases; OFF means the named proxy is inactive, not empty."""
    refs = row.get("references")
    if not isinstance(refs, list) or len(refs) > 256:
        return None, "missing_references"
    selected, groups = set(policy["reference_groups"]), {}
    for ref in refs:
        group = ref.get("source_group")
        if group not in selected:
            continue
        if ref.get("independent") is not True or ref.get("kind") not in {
            "motion",
            "person",
            "presence",
        }:
            return None, "reference_not_independent"
        if ref.get("derived_from_ruview") is not False:
            return None, "reference_lineage_unverified"
        if ref.get("available") is not True or ref.get("state") not in ("on", "off"):
            return None, "reference_unavailable"
        try:
            age = at - timestamp(ref.get("observed_at_utc"))
        except ShadowModelError:
            return None, "reference_timestamp_missing"
        if not 0 <= age <= policy.get("reference_max_age_seconds", 10):
            return None, "reference_time_not_current"
        state = ref["state"] == "on"
        if group in groups and groups[group] != state:
            return None, "conflicting_reference_aliases"
        groups[group] = state
    if set(groups) != selected:
        return None, "incomplete_reference_groups"
    return int(any(groups.values())), None


def prepare(examples, policy):
    validate_policy(policy)
    require(len(examples) <= MAX_EXAMPLES, "Too many examples")
    validation_start = timestamp(policy["validation_start_utc"])
    holdout, gap = (
        timestamp(policy["final_holdout_start_utc"]),
        policy.get("split_gap_seconds", 30),
    )
    partition, skipped, identities, ordered = (
        {"train": [], "validation": []},
        {},
        set(),
        [],
    )
    for row in examples:
        start, at, end = bounds(row)
        require(row["example_id"] not in identities, "Duplicate example identity")
        identities.add(row["example_id"])
        ordered.append((start, end, at, row))
    ordered.sort(key=lambda item: (item[0], item[1], item[3]["example_id"]))
    previous = None
    for start, end, at, row in ordered:
        if previous is not None:
            require(
                start >= previous[1] and at != previous[2],
                "Overlapping or duplicate feature intervals",
            )
        previous = (start, end, at)
        if end >= holdout:
            reason = "reserved_final_holdout"
        elif end < validation_start - gap:
            reason, group = None, "train"
        elif start >= validation_start:
            reason, group = None, "validation"
        else:
            reason = "split_gap"
        if reason is None:
            vector, reason = feature_vector(row, policy["feature_contract"])
        if reason is None:
            label, reason = reference_target(row, policy, at)
        if reason is None:
            partition[group].append((vector, label, row))
        else:
            skipped[reason] = skipped.get(reason, 0) + 1
    counts = [sum(y == label for _, y, _ in partition["train"]) for label in (0, 1)]
    require(
        min(counts) >= policy.get("min_train_per_class", 10),
        f"Insufficient train examples per class: {counts}",
    )
    return partition, skipped


def sigmoid(value):
    return 1 / (1 + math.exp(-max(-40, min(40, value))))


def transform(vector, mean, scale):
    return [
        max(-10, min(10, (x - m) / s))
        for x, m, s in zip(vector, mean, scale, strict=True)
    ]


def probability(parameters, vector):
    values = transform(vector, parameters["mean"], parameters["scale"])
    return sigmoid(
        parameters["bias"]
        + sum(w * x for w, x in zip(parameters["weights"], values, strict=True))
    )


def metrics(labels, probabilities, threshold=0.5):
    require(bool(labels) and len(labels) == len(probabilities), "Invalid metric inputs")
    tp = tn = fp = fn = 0
    loss = brier = 0.0
    for label, p in zip(labels, probabilities, strict=True):
        p = max(1e-12, min(1 - 1e-12, p))
        loss -= label * math.log(p) + (1 - label) * math.log(1 - p)
        brier += (p - label) ** 2
        prediction = p >= threshold
        tp += int(label == 1 and prediction)
        tn += int(label == 0 and not prediction)
        fp += int(label == 0 and prediction)
        fn += int(label == 1 and not prediction)
    pos, neg = tp + fn, tn + fp
    return {
        "examples": len(labels),
        "positive_examples": pos,
        "negative_examples": neg,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "logloss": loss / len(labels),
        "brier": brier / len(labels),
        "balanced_accuracy": (tp / pos + tn / neg) / 2 if pos and neg else None,
        "positive_recall": tp / pos if pos else None,
        "negative_recall": tn / neg if neg else None,
        "threshold": threshold,
    }


def episode_support(partition):
    """Describe correlated support; repeated held states are not independent trials."""
    transitions = positive_runs = negative_runs = 0
    previous = None
    for _, label, row in partition:
        at = timestamp(row["observed_at_utc"])
        # A gap creates a new observed run, never a manufactured transition.
        contiguous = previous is not None and at - previous[1] <= 30
        if not contiguous or previous[0] != label:
            positive_runs += int(label == 1)
            negative_runs += int(label == 0)
            transitions += int(contiguous)
        previous = (label, at)
    return {
        "observed_positive_runs": positive_runs,
        "observed_negative_runs": negative_runs,
        "observed_state_transitions": transitions,
        "independent_trials_claimed": False,
        "run_gap_seconds": 30,
    }


def train(examples, policy):
    partitions, skipped = prepare(examples, policy)
    training, validation = partitions["train"], partitions["validation"]
    columns = list(zip(*(x for x, _, _ in training), strict=True))
    mean = [statistics.fmean(column) for column in columns]
    scale = [statistics.pstdev(column) or 1.0 for column in columns]
    transformed = [transform(x, mean, scale) for x, _, _ in training]
    labels = [y for _, y, _ in training]
    prior = statistics.fmean(labels)
    weights = [0.0] * len(mean)
    bias = math.log(prior / (1 - prior))
    rate, regularization = policy.get("learning_rate", 0.1), policy.get("l2", 0.01)
    for _ in range(policy.get("epochs", 400)):
        gradient = [0.0] * len(weights)
        bias_gradient = 0.0
        for values, label in zip(transformed, labels, strict=True):
            error = (
                sigmoid(bias + sum(w * x for w, x in zip(weights, values, strict=True)))
                - label
            )
            bias_gradient += error
            for index, value in enumerate(values):
                gradient[index] += error * value
        for index in range(len(weights)):
            weights[index] -= rate * (
                gradient[index] / len(labels) + regularization * weights[index]
            )
        bias -= rate * bias_gradient / len(labels)
    parameters = {"mean": mean, "scale": scale, "weights": weights, "bias": bias}
    threshold = policy.get("threshold", 0.5)
    val_labels = [y for _, y, _ in validation]
    candidate = (
        metrics(
            val_labels,
            [probability(parameters, x) for x, _, _ in validation],
            threshold,
        )
        if validation
        else None
    )
    baseline = (
        metrics(val_labels, [prior] * len(validation), threshold)
        if validation
        else None
    )
    validation_sufficient = min(val_labels.count(0), val_labels.count(1)) >= policy.get(
        "min_validation_per_class", 5
    )
    improves = (
        validation_sufficient
        and candidate["logloss"] + policy.get("minimum_logloss_improvement", 0)
        < baseline["logloss"]
        and candidate["balanced_accuracy"] >= baseline["balanced_accuracy"]
    )
    report = {
        "schema": "ruview.shadow-motion-evaluation.v1",
        "task": TASK,
        "evaluation_partition": "chronological_development_validation",
        "train_examples": len(training),
        "validation_examples": len(validation),
        "validation_sufficient": validation_sufficient,
        "evaluation_status": "compared"
        if validation_sufficient
        else "pending_validation",
        "train_support": episode_support(training),
        "validation_support": episode_support(validation),
        "skipped_examples": skipped,
        "candidate": candidate,
        "train_prior_baseline": baseline,
        "passes_shadow_baseline": improves,
        "recognition_validated": False,
        "publish_to_ha": False,
        "production_promotion_allowed": False,
        "limitations": [
            "Binary targets describe selected sensors, not absence or occupancy.",
            "Chronological within-capture validation is exploratory, not independent household qualification.",
            "Accuracy depends on reference coverage, correlation and input profile stability.",
        ],
    }
    payload = {
        "schema": MODEL_SCHEMA,
        "task": TASK,
        "algorithm": "standardized_logistic_v1",
        "mode": "shadow",
        "publish_to_ha": False,
        "recognition_validated": False,
        "policy": policy,
        "parameters": parameters,
        "train_positive_prior": prior,
        "training_examples_sha256": sha([row for _, _, row in training]),
        "validation_examples_sha256": sha([row for _, _, row in validation]),
        "train_time_bounds": [
            training[0][2]["interval_start_utc"],
            training[-1][2]["interval_end_utc"],
        ],
        "validation_time_bounds": [
            validation[0][2]["interval_start_utc"],
            validation[-1][2]["interval_end_utc"],
        ]
        if validation
        else None,
        "evaluation": report,
    }
    return {"payload": payload, "payload_sha256": sha(payload)}, report


def validate_artifact(artifact):
    require(
        isinstance(artifact, dict) and set(artifact) == {"payload", "payload_sha256"},
        "Invalid artifact envelope",
    )
    payload = artifact["payload"]
    require(sha(payload) == artifact["payload_sha256"], "Artifact integrity mismatch")
    require(
        payload.get("schema") == MODEL_SCHEMA and payload.get("task") == TASK,
        "Unknown model/task contract",
    )
    require(
        payload.get("algorithm") == "standardized_logistic_v1",
        "Unknown model algorithm",
    )
    require(
        payload.get("mode") == "shadow"
        and payload.get("publish_to_ha") is False
        and payload.get("recognition_validated") is False,
        "Model must remain shadow-only",
    )
    validate_policy(payload["policy"])
    dimensions = len(payload["policy"]["feature_contract"]["features"])
    p = payload["parameters"]
    for key in ("mean", "scale", "weights"):
        require(
            isinstance(p.get(key), list)
            and len(p[key]) == dimensions
            and all(finite(x) for x in p[key]),
            "Invalid parameter dimensions/values",
        )
    require(
        all(x > 0 for x in p["scale"]) and finite(p.get("bias")),
        "Invalid parameter scale/bias",
    )
    return payload


def predict(artifact, examples):
    payload = validate_artifact(artifact)
    contract = payload["policy"]["feature_contract"]
    predictions = []
    for row in examples:
        require(isinstance(row, dict), "Example must be an object")
        try:
            bounds(row)
            vector, reason = feature_vector(row, contract)
        except ShadowModelError as exc:
            vector, reason = None, str(exc)
        item = {
            "schema": "ruview.shadow-motion-prediction.v1",
            "example_id": row.get("example_id"),
            "observed_at_utc": row.get("observed_at_utc"),
            "task": TASK,
            "model_sha256": artifact["payload_sha256"],
            "mode": "shadow",
            "publish_to_ha": False,
            "available": reason is None,
            "abstention_reason": reason,
            "probability_reference_active": None,
            "predicted_reference_active": None,
        }
        if reason is None:
            p = probability(payload["parameters"], vector)
            item["probability_reference_active"] = p
            item["predicted_reference_active"] = p >= payload["policy"].get(
                "threshold", 0.5
            )
        predictions.append(item)
    return predictions


def evaluate(artifact, examples, start_utc, end_utc):
    """Score a frozen model inside explicitly supplied evaluation bounds."""
    payload = validate_artifact(artifact)
    start, end = timestamp(start_utc), timestamp(end_utc)
    require(start < end, "Invalid evaluation bounds")
    train_end = timestamp(payload["train_time_bounds"][1])
    require(
        start >= train_end + payload["policy"].get("split_gap_seconds", 30)
        and start > train_end,
        "Evaluation overlaps fitting data or purge gap",
    )
    require(len(examples) <= MAX_EXAMPLES, "Too many examples")
    seen, previous = set(), None
    for row in sorted(examples, key=lambda row: bounds(row)[0]):
        a, at, b = bounds(row)
        require(row["example_id"] not in seen, "Duplicate evaluation identity")
        seen.add(row["example_id"])
        if previous is not None:
            require(
                a >= previous[1] and at != previous[2],
                "Overlapping evaluation intervals",
            )
        previous = a, b, at
    predictions = predict(artifact, examples)
    labels, probs, skipped = [], [], {}
    for row, prediction in zip(examples, predictions, strict=True):
        a, at, b = bounds(row)
        if not start <= a <= b < end:
            reason = "outside_explicit_evaluation_bounds"
        else:
            reason = prediction["abstention_reason"]
        if reason is None:
            label, reason = reference_target(row, payload["policy"], at)
        if reason is None:
            labels.append(label)
            probs.append(prediction["probability_reference_active"])
        else:
            skipped[reason] = skipped.get(reason, 0) + 1
    require(labels, "No eligible evaluation examples")
    threshold = payload["policy"].get("threshold", 0.5)
    sufficient = min(labels.count(0), labels.count(1)) >= payload["policy"].get(
        "min_validation_per_class", 5
    )
    return {
        "task": TASK,
        "model_sha256": artifact["payload_sha256"],
        "candidate": metrics(labels, probs, threshold),
        "train_prior_baseline": metrics(
            labels, [payload["train_positive_prior"]] * len(labels), threshold
        ),
        "skipped_examples": skipped,
        "validation_sufficient": sufficient,
        "evaluation_status": "compared" if sufficient else "pending_validation",
        "publish_to_ha": False,
        "recognition_validated": False,
    }


def read_bounded(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
            "Unsafe or oversized input file",
        )
        raw = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
    require(
        len(raw) <= MAX_FILE_BYTES
        and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        "Input changed during read",
    )
    return raw


def load_json(path):
    return json.loads(read_bounded(path))


def load_model(path, expected_sha256):
    raw = read_bounded(path)
    require(
        hashlib.sha256(raw).hexdigest() == expected_sha256,
        "Externally pinned model file hash mismatch",
    )
    artifact = json.loads(raw)
    validate_artifact(artifact)
    return artifact


def load_examples(path):
    path = Path(path)
    require(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size <= MAX_FILE_BYTES,
        "Unsafe or oversized examples file",
    )
    result = []
    with path.open() as source:
        for line in source:
            require(len(line) <= 1024 * 1024, "Oversized example")
            if line.strip():
                result.append(json.loads(line))
            require(len(result) <= MAX_EXAMPLES, "Too many examples")
    return result


def write_new(path, value):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), "Output already exists")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    training = commands.add_parser("train")
    training.add_argument("--examples", required=True)
    training.add_argument("--policy", required=True)
    training.add_argument("--output", required=True)
    training.add_argument("--report", required=True)
    for name in ("predict", "evaluate"):
        command = commands.add_parser(name)
        command.add_argument("--model", required=True)
        command.add_argument(
            "--expected-sha256", required=True, help="SHA-256 of the model file"
        )
        command.add_argument("--examples", required=True)
        command.add_argument("--output", required=True)
        if name == "evaluate":
            command.add_argument("--start-utc", required=True)
            command.add_argument("--end-utc", required=True)
    args = parser.parse_args(argv)
    examples = load_examples(args.examples)
    if args.command == "train":
        artifact, report = train(examples, load_json(args.policy))
        write_new(args.output, artifact)
        write_new(args.report, report)
        print(
            json.dumps(
                {
                    "model_payload_sha256": artifact["payload_sha256"],
                    "model_file_sha256": hashlib.sha256(
                        Path(args.output).read_bytes()
                    ).hexdigest(),
                    "passes_shadow_baseline": report["passes_shadow_baseline"],
                    "publish_to_ha": False,
                }
            )
        )
    else:
        artifact = load_model(args.model, args.expected_sha256)
        result = (
            predict(artifact, examples)
            if args.command == "predict"
            else evaluate(artifact, examples, args.start_utc, args.end_utc)
        )
        write_new(args.output, result)
        print(json.dumps({"output": args.output, "publish_to_ha": False}))


if __name__ == "__main__":
    main()
