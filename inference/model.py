"""A local supervised ridge baseline, trained only from paired household data.

The checkpoint is plain JSON. It is always a research candidate, never an HA
publication permit. NumPy is imported only by training/prediction commands.
"""

import math
from bisect import bisect_right

from .feature_contracts import (
    FEATURE_CONTRACT,
    MODEL_SCHEMAS,
    PREFIX_FEATURE_CONTRACT,
    feature_count,
    pair_indices,
    selected_contract,
    validate_contract,
    validate_prefix_scope,
)
from .pipeline import (
    AMPLITUDE_CONTRACT,
    FRAME_SCHEMA_V2,
    LABEL_SCHEMA_V2,
    PAIR_SCHEMA,
    PAIR_SCHEMA_V2,
    POSTURES,
    WINDOW_SCHEMA_V2,
    WIRE_METADATA,
    approved_coordinate_frame,
    digest,
    finite_vector,
    integer,
    nonempty,
    sha,
    validate_frame,
    validate_label,
    validate_profile,
    validate_window_identity,
)

TASKS = ("posture", "image_pose_2d", "house_xy_m")


def features(window, feature_contract=FEATURE_CONTRACT):
    """Three stats per explicitly selected wire pair, with unchanged source arrays."""
    validate_contract(feature_contract)
    if selected_contract(window) != feature_contract:
        raise ValueError("requested feature contract differs from window")
    if feature_contract == PREFIX_FEATURE_CONTRACT:
        validate_prefix_scope(window)
    validate_window_identity(window)
    if window.get("amplitude_contract") != AMPLITUDE_CONTRACT:
        raise ValueError("unknown amplitude transformation")
    if window.get("antennas") != 1 or window.get("subcarriers") != 64:
        raise ValueError("feature contract requires one antenna and 64 native bins")
    original = {k: v for k, v in window.items() if k != "window_id"}
    if window.get("window_id") != digest(original):
        raise ValueError("window integrity mismatch")
    validate_profile(window["commissioning_profile"])
    if window["commissioning_sha256"] != digest(window["commissioning_profile"]):
        raise ValueError("commissioning profile mismatch")
    if (
        window["commissioning_profile"]["node_id"] != window["node_id"]
        or window["commissioning_profile"]["frequency_mhz"] != window["frequency_mhz"]
    ):
        raise ValueError("window differs from commissioning profile")
    rows = window.get("amplitudes", [])
    timestamps = window.get("monotonic_ns", [])
    utc = window.get("timestamps_ns", [])
    seq = window.get("sequences", [])
    if len(rows) < 2 or not len(rows) == len(timestamps) == len(utc) == len(seq):
        raise ValueError("window dimensions mismatch")
    if window["schema"] == WINDOW_SCHEMA_V2:
        for key in ("ingress_sequences", "capture_sequences"):
            ordinals = window.get(key)
            if not isinstance(ordinals, list) or len(ordinals) != len(rows):
                raise ValueError("window admission ordinal dimensions mismatch")
            for ordinal in ordinals:
                integer(ordinal, key, 1, 2**64 - 1)
            # Other nodes share these counters; per-node differences may exceed1.
            if any(b <= a for a, b in zip(ordinals[:-1], ordinals[1:], strict=True)):
                raise ValueError("nonmonotonic window admission ordinals")
    for row in rows:
        finite_vector(row, 64, "amplitudes", 0)
    gaps = [(b - a) / 1e9 for a, b in zip(timestamps[:-1], timestamps[1:], strict=True)]
    if any(g <= 0 or not math.isfinite(g) for g in gaps):
        raise ValueError("nonmonotonic window")
    if any((b - a) % 2**32 != 1 for a, b in zip(seq[:-1], seq[1:], strict=True)):
        raise ValueError("noncontiguous window")
    policy = window["policy"]
    if (
        len(rows) < policy["min_frames"]
        or max(gaps) * 1e9 > policy["max_gap_ns"] + 1
        or timestamps[-1] - timestamps[0] < policy["duration_ns"]
    ):
        raise ValueError("window violates cadence policy")
    if any(b <= a for a, b in zip(utc[:-1], utc[1:], strict=True)):
        raise ValueError("nonmonotonic UTC")
    if any(
        abs((ub - ua) - (mb - ma)) > policy["max_clock_step_ns"]
        for ua, ub, ma, mb in zip(
            utc[:-1], utc[1:], timestamps[:-1], timestamps[1:], strict=True
        )
    ):
        raise ValueError("UTC clock step in window")
    indices = pair_indices(feature_contract)
    means = [sum(row[i] for row in rows) / len(rows) for i in indices]
    stds = [
        math.sqrt(sum((row[i] - means[j]) ** 2 for row in rows) / len(rows))
        for j, i in enumerate(indices)
    ]
    slopes = [
        sum(
            abs(b[i] - a[i]) / dt
            for a, b, dt in zip(rows[:-1], rows[1:], gaps, strict=True)
        )
        / len(gaps)
        for i in indices
    ]
    return means + stds + slopes


def model_identity(window):
    # The offline runner also supplies a validated frame plus window policy.
    # Keep that v1 pre-window check unchanged; v2 must retain its explicit source.
    if window.get("schema") == WINDOW_SCHEMA_V2:
        validate_window_identity(window)
    elif window.get("schema") == FRAME_SCHEMA_V2:
        validate_frame(window)
    identity = {
        key: window.get(key)
        for key in (
            "node_id",
            "configuration_sha256",
            "antennas",
            "subcarriers",
            "frequency_mhz",
            "ppdu_type",
            "flags",
            "policy",
            "time_basis",
            "commissioning_sha256",
            "amplitude_contract",
        )
        + WIRE_METADATA
    }
    if selected_contract(window) == PREFIX_FEATURE_CONTRACT:
        identity["feature_selection"] = window["feature_selection"]
    if window.get("schema") in (WINDOW_SCHEMA_V2, FRAME_SCHEMA_V2):
        identity["source_frame_schema"] = FRAME_SCHEMA_V2
    return identity


def target_identity(label, task):
    if task == "image_pose_2d":
        return {
            "frame": "normalized_camera_image",
            "camera_id": label["camera_id"],
            "image_geometry_sha256": label["image_geometry_sha256"],
        }
    if task == "house_xy_m":
        return {
            "frame": label["coordinate_frame"],
            "coordinate_calibration_sha256": label["coordinate_calibration_sha256"],
            "coordinate_reference": label["coordinate_reference"],
        }
    return {"frame": "categorical_body_posture"}


def train(
    records,
    task,
    eval_sessions,
    regularization=1.0,
    min_train=20,
    min_eval=5,
    feature_contract=FEATURE_CONTRACT,
    *,
    expected_coordinate_frame=None,
):
    from .evidence import capture_lineage

    if task not in TASKS or not eval_sessions:
        raise ValueError("known task and explicit held-out sessions required")
    if not math.isfinite(regularization) or regularization <= 0:
        raise ValueError("regularization must be positive")
    capture_lineage(records)  # Reject mixed modes even in out-of-task records.
    validate_contract(feature_contract)
    usable = []
    seen = set()
    source_versions = set()
    for record in records:
        if record.get("schema") not in (PAIR_SCHEMA, PAIR_SCHEMA_V2):
            raise ValueError("unpaired data cannot train a model")
        label = validate_label(
            record["label"], expected_coordinate_frame=expected_coordinate_frame
        )
        window = validate_window_identity(record["window"])
        is_v2 = window["schema"] == WINDOW_SCHEMA_V2
        if (
            (record["schema"] == PAIR_SCHEMA_V2) != is_v2
            or (label["schema"] == LABEL_SCHEMA_V2) != is_v2
            or (
                is_v2
                and any(
                    label[key] != window[key]
                    for key in ("capture_id", "worker_run_id", "clock_id")
                )
            )
        ):
            raise ValueError("paired source schema/capture identity mismatch")
        source_versions.add(window["schema"])
        if (
            record.get("capture_evidence", {}).get("status")
            == "verified_closed_capture"
        ):
            from .reference_alignment import validate_paired_alignment

            validate_paired_alignment(
                record, expected_coordinate_frame=expected_coordinate_frame
            )
        if len(source_versions) != 1:
            raise ValueError("cannot mix source frame versions")
        if selected_contract(window) != feature_contract:
            raise ValueError("mixed or unrequested feature contracts")
        if (
            label["node_id"] != window["node_id"]
            or label["session_id"] != window["session_id"]
            or label["configuration_sha256"] != window["configuration_sha256"]
        ):
            raise ValueError("label/window identity mismatch")
        if label["person_count"] != 1 or label.get(task) is None:
            continue
        from .pipeline import pair_window

        paired = pair_window(
            window,
            [label],
            record["alignment"]["label_to_csi_clock_offset_ns"],
            record["alignment"]["max_uncertainty_ns"],
            expected_coordinate_frame=expected_coordinate_frame,
        )
        if paired is None:
            raise ValueError("label does not cover the complete window")
        if window["window_id"] in seen:
            raise ValueError("duplicate window")
        seen.add(window["window_id"])
        usable.append((record, features(window, feature_contract)))
    if not usable:
        raise ValueError("no single-person reviewed labels for this task")
    identity = model_identity(usable[0][0]["window"])
    target = target_identity(usable[0][0]["label"], task)
    for record, _ in usable:
        if model_identity(record["window"]) != identity:
            raise ValueError(
                "train a separate model for each node/configuration/cadence"
            )
        if target_identity(record["label"], task) != target:
            raise ValueError("mixed target coordinate/camera calibration")
    train_rows = [
        r for r in usable if r[0]["window"]["session_id"] not in eval_sessions
    ]
    eval_rows = [r for r in usable if r[0]["window"]["session_id"] in eval_sessions]
    if len(train_rows) < min_train or len(eval_rows) < min_eval:
        raise ValueError("insufficient training or held-out windows")
    used_eval = {r[0]["window"]["session_id"] for r in eval_rows}
    if set(eval_sessions) != used_eval:
        raise ValueError("a requested held-out session has no usable labels")
    # Renaming an overlapping recording must not turn it into held-out evidence.
    intervals = []
    for fitted, _ in train_rows:
        w = fitted["window"]
        intervals.append((w["timestamps_ns"][0], w["timestamps_ns"][-1]))
    # All windows describe one physical node/profile. Concurrent worker runs
    # observing the same UTC interval are not independent held-out trials.
    merged = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    starts = [interval[0] for interval in merged]
    for held, _ in eval_rows:
        ew = held["window"]
        index = bisect_right(starts, ew["timestamps_ns"][-1]) - 1
        if index >= 0 and merged[index][1] >= ew["timestamps_ns"][0]:
            raise ValueError("training and evaluation recordings overlap in time")
    import numpy as np

    x = np.asarray([r[1] for r in train_rows], dtype=np.float64)
    xe = np.asarray([r[1] for r in eval_rows], dtype=np.float64)
    mean, scale = x.mean(axis=0), x.std(axis=0)
    scale[scale < 1e-8] = 1.0
    x, xe = (x - mean) / scale, (xe - mean) / scale
    classes = (
        sorted({r[0]["label"][task] for r in train_rows}) if task == "posture" else []
    )
    if task == "posture":
        if len(classes) < 2 or {r[0]["label"][task] for r in eval_rows} != set(classes):
            raise ValueError("train/evaluation must both represent every posture class")
        y = np.eye(len(classes))[
            [classes.index(r[0]["label"][task]) for r in train_rows]
        ]
        ye = np.asarray([classes.index(r[0]["label"][task]) for r in eval_rows])
    else:
        y = np.asarray([r[0]["label"][task] for r in train_rows], dtype=np.float64)
        ye = np.asarray([r[0]["label"][task] for r in eval_rows], dtype=np.float64)
        if not np.any(y.std(axis=0) > 1e-8):
            raise ValueError("constant training targets do not establish a predictor")
    # Center targets so the intercept is not penalized. Solve the smaller ridge system.
    bias = y.mean(axis=0)
    centered = y - bias
    if len(x) < x.shape[1]:
        weights = x.T @ np.linalg.solve(
            x @ x.T + regularization * np.eye(len(x)), centered
        )
    else:
        weights = np.linalg.solve(
            x.T @ x + regularization * np.eye(x.shape[1]), x.T @ centered
        )
    predictions = xe @ weights + bias
    if task == "posture":
        predicted = predictions.argmax(axis=1)
        confusion = [
            [int(np.sum((ye == i) & (predicted == j))) for j in range(len(classes))]
            for i in range(len(classes))
        ]
        metrics = {
            "accuracy": float(np.mean(predicted == ye)),
            "confusion": confusion,
            "class_order": classes,
            "majority_baseline_accuracy": float(np.mean(ye == bias.argmax())),
        }
    else:
        distances = np.linalg.norm(predictions - ye, axis=1)
        if task == "image_pose_2d":
            distances = np.linalg.norm(
                (predictions - ye).reshape(-1, 17, 2), axis=2
            ).mean(axis=1)
        metrics = {
            "mean_error": float(distances.mean()),
            "median_error": float(np.median(distances)),
            "p95_error": float(np.quantile(distances, 0.95)),
            "units": "metres" if task == "house_xy_m" else "normalized_image_distance",
            "prediction_std": predictions.std(axis=0).tolist(),
            "mean_target_baseline_rmse": float(np.sqrt(np.mean((ye - bias) ** 2))),
            "rmse": float(np.sqrt(np.mean((predictions - ye) ** 2))),
        }
    model = {
        "schema": MODEL_SCHEMAS[feature_contract],
        "task": task,
        "status": "candidate_unqualified",
        "publish_to_ha": False,
        "feature_contract": feature_contract,
        "input_identity": identity,
        "target_identity": target,
        "classes": classes,
        "mean": mean.tolist(),
        "scale": scale.tolist(),
        "weights": weights.tolist(),
        "bias": bias.tolist(),
        "regularization": regularization,
        "training_sessions": sorted({r[0]["window"]["session_id"] for r in train_rows}),
        "evaluation_sessions": sorted(used_eval),
        "training_windows": len(train_rows),
        "evaluation_windows": len(eval_rows),
        "metrics": metrics,
        "dataset_sha256": digest(records),
        "capture_lineage": capture_lineage([record for record, _ in usable]),
        "qualification": "offline_baseline_only_no_accuracy_acceptance_threshold",
    }
    model["model_sha256"] = digest(model)
    return model


def validate_model(model, *, expected_coordinate_frame=None):
    """A matching checksum is not a substitute for the checkpoint contract."""
    contract = validate_contract(model.get("feature_contract"))
    if (
        model.get("schema") != MODEL_SCHEMAS[contract]
        or model.get("status") != "candidate_unqualified"
        or model.get("publish_to_ha") is not False
        or model.get("model_sha256")
        != digest({k: v for k, v in model.items() if k != "model_sha256"})
    ):
        raise ValueError("unknown, changed or non-candidate model")
    if selected_contract(model["input_identity"]) != contract:
        raise ValueError("checkpoint feature selection differs from contract")
    if (
        "source_frame_schema" in model["input_identity"]
        and model["input_identity"]["source_frame_schema"] != FRAME_SCHEMA_V2
    ):
        raise ValueError("unknown checkpoint source frame schema")
    if contract == PREFIX_FEATURE_CONTRACT:
        validate_prefix_scope(model["input_identity"])
    task = model.get("task")
    if task not in TASKS:
        raise ValueError("unknown checkpoint task")
    classes = model.get("classes")
    if not isinstance(classes, list):
        raise ValueError("invalid checkpoint classes")
    if task == "posture":
        if (
            not 2 <= len(classes) <= len(POSTURES)
            or any(c not in POSTURES for c in classes)
            or classes != sorted(set(classes))
        ):
            raise ValueError("invalid checkpoint posture classes")
        dimensions = len(classes)
    else:
        if classes:
            raise ValueError("regression checkpoint cannot have classes")
        dimensions = 2 if task == "house_xy_m" else 34
    inputs = feature_count(contract)
    finite_vector(model.get("mean"), inputs, "checkpoint mean")
    finite_vector(model.get("scale"), inputs, "checkpoint scale")
    if any(v <= 0 for v in model["scale"]):
        raise ValueError("checkpoint scales must be positive")
    weights = model.get("weights")
    if not isinstance(weights, list) or len(weights) != inputs:
        raise ValueError(f"checkpoint needs {inputs} weight rows")
    for row in weights:
        finite_vector(row, dimensions, "checkpoint weight row")
    finite_vector(model.get("bias"), dimensions, "checkpoint bias")
    target = model.get("target_identity")
    if not isinstance(target, dict):
        raise ValueError("invalid checkpoint target identity")
    if task == "posture":
        expected = {"frame": "categorical_body_posture"}
    elif task == "house_xy_m":
        expected = {
            "frame": approved_coordinate_frame(expected_coordinate_frame),
            "coordinate_calibration_sha256": sha(
                target.get("coordinate_calibration_sha256"), "coordinate calibration"
            ),
            "coordinate_reference": nonempty(
                target.get("coordinate_reference"), "coordinate reference"
            ),
        }
    else:
        expected = {
            "frame": "normalized_camera_image",
            "camera_id": nonempty(target.get("camera_id"), "camera identity"),
            "image_geometry_sha256": sha(
                target.get("image_geometry_sha256"), "image geometry"
            ),
        }
    if target != expected:
        raise ValueError("checkpoint target frame does not match task")
    sessions = []
    for key in ("training_sessions", "evaluation_sessions"):
        values = model.get(key)
        if not isinstance(values, list) or not values:
            raise ValueError("checkpoint must declare training/held-out sessions")
        for value in values:
            nonempty(value, key)
        if len(values) != len(set(values)):
            raise ValueError("duplicate checkpoint session")
        sessions.append(set(values))
    if sessions[0] & sessions[1]:
        raise ValueError("checkpoint training/held-out sessions overlap")
    integer(model.get("training_windows"), "training windows", 1)
    integer(model.get("evaluation_windows"), "evaluation windows", 1)
    finite_vector([model.get("regularization")], 1, "regularization")
    if model["regularization"] <= 0:
        raise ValueError("checkpoint regularization must be positive")
    sha(model.get("dataset_sha256"), "dataset checksum")
    from .evidence import validate_lineage

    validate_lineage(
        model.get("capture_lineage"), sessions[0] | sessions[1], model["input_identity"]
    )


def predict(
    model,
    window,
    capture_evidence=None,
    feature_contract=FEATURE_CONTRACT,
    *,
    expected_coordinate_frame=None,
):
    from .evidence import validate_evidence, validate_lineage

    validate_model(model, expected_coordinate_frame=expected_coordinate_frame)
    validate_contract(feature_contract)
    if model["feature_contract"] != feature_contract:
        raise ValueError("requested feature contract differs from checkpoint")
    lineage = validate_lineage(
        model.get("capture_lineage"),
        set(model["training_sessions"]) | set(model["evaluation_sessions"]),
        model["input_identity"],
    )
    capture_evidence = validate_evidence(capture_evidence, window)
    if capture_evidence["status"] != lineage["status"]:
        raise ValueError("prediction cannot mix verified and unverified capture modes")
    if (
        capture_evidence["status"] in ("verified_recording", "verified_closed_capture")
        and capture_evidence["synthetic_only"]
        != lineage["recordings"][0]["synthetic_only"]
    ):
        raise ValueError("prediction capture classification differs from model")
    prediction = evaluate_candidate_values(
        model,
        window,
        feature_contract,
        expected_coordinate_frame=expected_coordinate_frame,
    )
    task = model["task"]
    result = {
        "schema": "ruview.research_prediction.v1",
        "task": task,
        "prediction": prediction,
        "target_identity": model["target_identity"],
        "model_sha256": model["model_sha256"],
        "window_id": window["window_id"],
        "capture_evidence": capture_evidence,
        "model_capture_lineage": lineage,
        "node_id": window["node_id"],
        "observed_at_ns": window["timestamps_ns"][-1],
        "validation": "unverified",
        "publish_to_ha": False,
        "confidence": None,
    }
    if feature_contract == PREFIX_FEATURE_CONTRACT:
        result["feature_contract"] = feature_contract
        result["feature_selection"] = window["feature_selection"]
    return result


def evaluate_candidate_values(
    model, window, feature_contract=FEATURE_CONTRACT, *, expected_coordinate_frame=None
):
    """Exact candidate arithmetic only; supplies no input provenance or permit.

    Offline predict() still enforces its original capture-lineage contract.
    The offline stream diagnostic supplies a separate, explicitly unverified
    replay-input contract instead of reusing a historical recording proof.
    """
    import numpy as np

    validate_model(model, expected_coordinate_frame=expected_coordinate_frame)
    validate_contract(feature_contract)
    if model["feature_contract"] != feature_contract:
        raise ValueError("requested feature contract differs from checkpoint")
    if model_identity(window) != model["input_identity"]:
        raise ValueError("model/configuration/cadence fingerprint mismatch")
    value = (np.asarray(features(window, feature_contract)) - model["mean"]) / model[
        "scale"
    ] @ np.asarray(model["weights"]) + model["bias"]
    if not np.isfinite(value).all():
        raise ValueError("nonfinite prediction")
    return (
        model["classes"][int(value.argmax())]
        if model["task"] == "posture"
        else value.tolist()
    )
