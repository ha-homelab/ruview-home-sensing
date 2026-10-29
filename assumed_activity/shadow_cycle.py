"""One immutable, time-anchored shadow training cycle; never promotes a model."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import math
from pathlib import Path

from . import shadow_model as model

SCHEMA = "ruview.shadow-cycle-policy.v1"


def iso(value):
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat()


def cycle(examples, policy, as_of_utc, previous_model=None):
    """Build a deterministic cycle from timestamps, without using label outcomes."""
    model.require(policy.get("schema") == SCHEMA, "Unexpected cycle policy schema")
    start = model.timestamp(policy["capture_start_utc"])
    holdout = model.timestamp(policy["final_holdout_start_utc"])
    as_of = model.timestamp(as_of_utc)
    model.require(start < holdout, "Invalid capture/holdout bounds")
    seconds = policy.get("cycle_seconds", 900)
    validation_seconds = policy.get("validation_seconds", 1800)
    for name, value in [
        ("cycle_seconds", seconds),
        ("validation_seconds", validation_seconds),
    ]:
        model.require(type(value) is int and 60 <= value <= 86400, "Invalid " + name)
    cutoff = start + math.floor((min(as_of, holdout) - start) / seconds) * seconds
    validation_start = cutoff - validation_seconds
    fit_policy = copy.deepcopy(policy["fit_policy"])
    fit_policy.update(
        schema=model.POLICY_SCHEMA,
        validation_start_utc=iso(validation_start),
        final_holdout_start_utc=iso(holdout),
    )
    model.validate_policy(fit_policy)
    result = {
        "schema": "ruview.shadow-cycle.v1",
        "task": model.TASK,
        "cycle_policy_sha256": model.sha(policy),
        "cycle_policy": copy.deepcopy(policy),
        "as_of_utc": as_of_utc,
        "capture_start_utc": iso(start),
        "completed_cutoff_utc": iso(cutoff),
        "validation_start_utc": iso(validation_start),
        "final_holdout_start_utc": iso(holdout),
        "fit_policy": fit_policy,
        "status": "fit_pending",
        "candidate": None,
        "evaluation": None,
        "previous_evaluation": None,
        "model_update_allowed": False,
        "publish_to_ha": False,
        "previous_model_preserved": True,
        "prior_validation_can_enter_later_training": True,
        "qualification": "Exploratory rolling development; only final holdout remains untouched.",
    }
    if cutoff <= start or validation_start <= start:
        result["reason"] = (
            "Not enough completed history for the declared validation duration"
        )
        return result
    model.require(len(examples) <= model.MAX_EXAMPLES, "Too many examples")
    selected = []
    outside = 0
    for row in examples:
        a, _, b = model.bounds(row)
        if start <= a <= b < cutoff:
            selected.append(row)
        else:
            outside += 1
    result["selected_examples"] = len(selected)
    result["outside_completed_development_examples"] = outside
    result["selected_examples_sha256"] = model.sha(selected)
    try:
        artifact, report = model.train(selected, fit_policy)
    except model.ShadowModelError as exc:
        if not str(exc).startswith("Insufficient train examples per class:"):
            raise
        result["reason"] = str(exc)
        return result
    result["candidate"] = artifact
    result["evaluation"] = report
    if not report["validation_sufficient"]:
        result["status"] = "eval_pending"
        result["reason"] = (
            "Insufficient validation examples under the unchanged class minima"
        )
    else:
        result["status"] = (
            "passes" if report["passes_shadow_baseline"] else "no_improvement"
        )
        result["reason"] = (
            "Compared against the training-prior baseline on the fixed later partition"
        )
    if previous_model is not None:
        previous = model.validate_artifact(previous_model)
        result["previous_model_sha256"] = previous_model["payload_sha256"]
        if previous["policy"]["feature_contract"] != fit_policy["feature_contract"]:
            result["previous_comparison_status"] = "feature_contract_incompatible"
        elif previous["policy"]["reference_groups"] != fit_policy["reference_groups"]:
            result["previous_comparison_status"] = "target_groups_incompatible"
        elif previous["policy"].get("reference_max_age_seconds", 10) != fit_policy.get(
            "reference_max_age_seconds", 10
        ):
            result["previous_comparison_status"] = (
                "target_freshness_policy_incompatible"
            )
        else:
            try:
                before = model.evaluate(
                    previous_model, selected, iso(validation_start), iso(cutoff)
                )
            except model.ShadowModelError as exc:
                result["previous_comparison_status"] = "inapplicable"
                result["previous_comparison_reason"] = str(exc)
            else:
                result["previous_evaluation"] = before
                sufficient = (
                    before["validation_sufficient"] and report["validation_sufficient"]
                )
                result["previous_comparison_status"] = (
                    "compared" if sufficient else "eval_pending"
                )
                if sufficient:
                    current, old = report["candidate"], before["candidate"]
                    better = (
                        current["logloss"]
                        + fit_policy.get("minimum_logloss_improvement", 0)
                        < old["logloss"]
                        and current["balanced_accuracy"] >= old["balanced_accuracy"]
                    )
                    result["improves_previous"] = better
                    if not better and result["status"] == "passes":
                        result["status"] = "no_improvement"
                        result["reason"] = (
                            "Candidate did not improve the preserved previous model"
                        )
        if (
            result.get("previous_comparison_status") != "compared"
            and result["status"] == "passes"
        ):
            result["status"] = "eval_pending"
            result["reason"] = (
                "The prior-model comparison is incomplete or inapplicable"
            )
    return result


def write_cycle(directory, result, previous_model=None):
    """Keep candidate, policy, comparison and optional prior artifact immutable."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = {}
    for name, value in [
        ("cycle-policy.json", result["cycle_policy"]),
        ("policy.json", result["fit_policy"]),
        ("candidate.json", result["candidate"]),
        ("evaluation.json", result["evaluation"]),
        ("previous-model.json", previous_model),
    ]:
        if value is not None:
            model.write_new(directory / name, value)
            files[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    manifest = {
        key: value
        for key, value in result.items()
        if key not in ("candidate", "evaluation", "fit_policy", "cycle_policy")
    }
    manifest["files_sha256"] = files
    manifest["candidate_payload_sha256"] = (
        result["candidate"]["payload_sha256"] if result["candidate"] else None
    )
    model.write_new(directory / "manifest.json", manifest)
    return manifest


def main(argv=None):
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--examples", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--as-of-utc", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--previous-model")
    parser.add_argument("--previous-sha256")
    args = parser.parse_args(argv)
    model.require(
        bool(args.previous_model) == bool(args.previous_sha256),
        "Previous model path and file SHA-256 must be supplied together",
    )
    previous = (
        model.load_model(args.previous_model, args.previous_sha256)
        if args.previous_model
        else None
    )
    result = cycle(
        model.load_examples(args.examples),
        model.load_json(args.policy),
        args.as_of_utc,
        previous,
    )
    manifest = write_cycle(args.output_directory, result, previous)
    print(
        json.dumps(
            {
                key: manifest[key]
                for key in [
                    "status",
                    "reason",
                    "candidate_payload_sha256",
                    "publish_to_ha",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()
