"""Private human observations and explicit review; no capture, model or HA calls."""

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from scripts.reference_clock import local_identity, validate_identity

from .capture_session import validate_opening
from .pipeline import (
    approved_coordinate_frame,
    digest,
    finite_vector,
    integer,
    sha,
    validate_label,
    validate_profile,
)

MAX_FILE = 1_048_576
MAX_EVENT_BYTES = 16_384
MAX_EVENTS = 4096
MAX_EXPORT_BYTES = 16 * MAX_FILE
MAX_SESSION_NS = 3_600_000_000_000
SESSION_SCHEMA = "ruview.reference_session.v1"
EVENT_SCHEMA = "ruview.reference_event.v1"
REVIEW_SCHEMA = "ruview.reference_review.v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text(value, name, limit=1024):
    require(isinstance(value, str) and 0 < len(value.strip()) <= limit, name)
    return value


def identifier(value, name):
    text(value, name, 100)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value), name)
    return value


def raw_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(raw) <= MAX_FILE, "document exceeds bound")
    return raw


def strict(raw):
    require(len(raw) <= MAX_FILE, "document exceeds bound")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def floating(value):
        result = float(value)
        require(math.isfinite(result), "nonfinite JSON number")
        return result

    def constant(_):
        raise ValueError("nonfinite JSON number")

    return json.loads(
        raw, object_pairs_hook=pairs, parse_float=floating, parse_constant=constant
    )


def read_bytes(path, limit=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            "regular bounded file required",
        )
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "file exceeds bound")
    return raw


def read(path, limit=MAX_FILE):
    raw = read_bytes(path, limit)
    return strict(raw), raw


def write_bytes(path, raw, limit=MAX_FILE):
    """Publish a complete new inode atomically without replacing an existing name."""
    require(len(raw) <= limit, "document exceeds bound")
    temporary = path.parent / (".pending-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink()
    return raw_hash(raw)


def write(path, value):
    return write_bytes(path, encoded(value))


def create_private_directory(directory):
    """Normalize inherited setgid only on an exclusively created directory."""
    directory.mkdir(mode=0o700)
    created = directory.lstat()
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        require(
            identity == (created.st_dev, created.st_ino)
            and stat.S_ISDIR(opened.st_mode)
            and opened.st_uid == os.geteuid()
            and stat.S_IMODE(opened.st_mode) & ~(0o700 | stat.S_ISGID) == 0,
            "new private directory changed before initialization",
        )
        os.fchmod(fd, 0o700)
        current = directory.lstat()
        require(
            identity == (current.st_dev, current.st_ino)
            and stat.S_ISDIR(current.st_mode)
            and stat.S_IMODE(current.st_mode) == 0o700,
            "new private directory changed during initialization",
        )
    finally:
        os.close(fd)


@contextmanager
def locked(directory):
    require(
        not directory.is_symlink() and directory.is_dir(),
        "private session directory required",
    )
    require(
        stat.S_IMODE(directory.stat().st_mode) == 0o700,
        "session directory must be 0700",
    )
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "invalid lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def now():
    identity = local_identity()
    before = time.time_ns()
    mono = time.monotonic_ns()
    after = time.time_ns()
    return {
        **identity,
        "utc_before_ns": before,
        "utc_after_ns": after,
        "monotonic_ns": mono,
    }


def validate_stamp(stamp):
    validate_identity({k: stamp.get(k) for k in ("host_id", "boot_id")})
    for key in ("utc_before_ns", "utc_after_ns", "monotonic_ns"):
        integer(stamp.get(key), key, 1, 2**63 - 1)
    require(stamp["utc_after_ns"] >= stamp["utc_before_ns"], "backwards stamp bracket")


def clock_error(stamp, initial, previous, policy):
    validate_stamp(stamp)
    if any(stamp[k] != initial[k] for k in ("host_id", "boot_id")):
        return "label host/boot changed"
    if stamp["utc_after_ns"] - stamp["utc_before_ns"] > policy["max_stamp_bracket_ns"]:
        return "stamp bracket exceeds policy"
    for earlier in (initial, previous):
        elapsed = stamp["monotonic_ns"] - earlier["monotonic_ns"]
        if elapsed <= 0:
            return "nonmonotonic event clock"
        utc_elapsed = stamp["utc_before_ns"] - earlier["utc_before_ns"]
        if abs(utc_elapsed - elapsed) > policy["max_clock_step_ns"]:
            return "UTC/monotonic disagreement"
    if stamp["monotonic_ns"] - initial["monotonic_ns"] > MAX_SESSION_NS:
        return "session duration exceeded"
    return None


def validate_points(calibration, *, expected_coordinate_frame=None):
    if calibration is None:
        return {}
    require(
        calibration.get("schema") == "ruview.reference_points.v1",
        "unknown point manifest",
    )
    require(
        calibration.get("coordinate_frame")
        == approved_coordinate_frame(expected_coordinate_frame),
        "wrong coordinate frame",
    )
    sha(calibration.get("floorplan_sha256"), "floorplan hash")
    text(calibration.get("coordinate_reference"), "body reference")
    text(calibration.get("measurement_method"), "measurement method")
    points = calibration.get("points")
    require(isinstance(points, list) and 0 < len(points) <= 100, "point count")
    result = {}
    for point in points:
        point_id = identifier(point.get("point_id"), "point ID")
        require(point_id not in result, "duplicate point")
        text(point.get("room_id"), "point room", 32)
        finite_vector(point.get("house_xy_m"), 2, "HA X/Z point")
        require(point.get("status") in ("proposed", "measured"), "point status")
        uncertainty = point.get("spatial_uncertainty_m")
        require(
            type(uncertainty) in (int, float)
            and math.isfinite(uncertainty)
            and 0 < uncertainty <= 10,
            "positive spatial uncertainty required",
        )
        if point["status"] == "measured":
            text(point.get("measurement_evidence"), "physical measurement evidence")
        result[point_id] = point
    return result


def validate_binding(binding):
    # Share exact wire-opening admission; this is not successful capture completion.
    return validate_opening(binding)


def validate_policy(policy):
    require(
        isinstance(policy, dict)
        and set(policy)
        == {"transition_margin_ns", "max_clock_step_ns", "max_stamp_bracket_ns"},
        "explicit timing policy required",
    )
    for key in policy:
        integer(policy[key], key, 1, 60_000_000_000)


def initialize(
    directory,
    binding,
    profiles,
    calibration,
    policy,
    operator,
    stamp=None,
    opening_raw=None,
    *,
    expected_coordinate_frame=None,
):
    validate_binding(binding)
    opening_raw = encoded(binding) if opening_raw is None else opening_raw
    require(strict(opening_raw) == binding, "original opening bytes differ")
    text(operator, "operator identity")
    require(
        isinstance(profiles, list) and 0 < len(profiles) <= 16,
        "explicit node profiles required",
    )
    nodes = {}
    for profile in profiles:
        validate_profile(profile)
        key = str(profile["node_id"])
        require(key not in nodes, "duplicate node profile")
        nodes[key] = profile
    require(
        {int(k) for k in nodes} == set(binding["node_ids"]),
        "profiles must bind exact capture node scope",
    )
    validate_points(calibration, expected_coordinate_frame=expected_coordinate_frame)
    if calibration is not None:
        require(
            all(
                p["floorplan_sha256"] == calibration["floorplan_sha256"]
                for p in profiles
            ),
            "point/profile floorplan mismatch",
        )
    validate_policy(policy)
    stamp = now() if stamp is None else stamp
    validate_stamp(stamp)
    require(
        stamp["utc_after_ns"] - stamp["utc_before_ns"]
        <= policy["max_stamp_bracket_ns"],
        "initial stamp bracket exceeds policy",
    )
    metadata = {
        "schema": SESSION_SCHEMA,
        "capture": binding,
        "capture_opening_sha256": raw_hash(opening_raw),
        "profiles": nodes,
        "profile_sha256": {k: digest(p) for k, p in nodes.items()},
        "calibration": calibration,
        "calibration_sha256": digest(calibration) if calibration else None,
        "policy": policy,
        "operator": operator,
        "created": stamp,
        "capture_verified": False,
        "model_qualified": False,
        "clock_alignment_applied": False,
    }
    create_private_directory(directory)
    create_private_directory(directory / "events")
    write_bytes(directory / "capture-opening.json", opening_raw)
    write(directory / "metadata.json", metadata)
    return metadata


def state(directory, *, expected_coordinate_frame=None):
    metadata, raw = read(directory / "metadata.json")
    require(metadata.get("schema") == SESSION_SCHEMA, "session schema")
    validate_binding(metadata["capture"])
    validate_policy(metadata["policy"])
    validate_stamp(metadata["created"])
    text(metadata["operator"], "operator identity")
    require(
        all(
            metadata.get(k) is False
            for k in ("capture_verified", "model_qualified", "clock_alignment_applied")
        ),
        "reference declaration scope changed",
    )
    require(
        set(metadata["profiles"]) == {str(n) for n in metadata["capture"]["node_ids"]},
        "profile/capture node scope changed",
    )
    require(
        all(str(p["node_id"]) == k for k, p in metadata["profiles"].items()),
        "profile node binding changed",
    )
    opening, opening_raw = read(directory / "capture-opening.json")
    require(
        opening == metadata["capture"]
        and raw_hash(opening_raw) == metadata["capture_opening_sha256"],
        "original capture opening changed",
    )
    validate_points(
        metadata["calibration"], expected_coordinate_frame=expected_coordinate_frame
    )
    require(
        metadata["profile_sha256"]
        == {k: digest(validate_profile(p)) for k, p in metadata["profiles"].items()},
        "profile hashes changed",
    )
    require(
        metadata["calibration_sha256"]
        == (digest(metadata["calibration"]) if metadata["calibration"] else None),
        "calibration hash changed",
    )
    if metadata["calibration"] is not None:
        require(
            all(
                p["floorplan_sha256"] == metadata["calibration"]["floorplan_sha256"]
                for p in metadata["profiles"].values()
            ),
            "point/profile floorplan mismatch",
        )
    meta_hash = raw_hash(raw)
    events_dir = directory / "events"
    require(
        not events_dir.is_symlink() and events_dir.is_dir(), "event directory identity"
    )
    names = []
    for path in events_dir.iterdir():
        names.append(path)
        require(len(names) <= MAX_EVENTS, "event count exceeded")
    names.sort()
    events, hashes = [], []
    previous = meta_hash
    for i, path in enumerate(names):
        require(path.name == f"{i:06d}.json", "event sequence/incomplete write")
        event, original = read(path, MAX_EVENT_BYTES)
        integer(event.get("index"), "event index", 0, MAX_EVENTS - 1)
        require(
            event["schema"] == EVENT_SCHEMA and event["index"] == i, "event identity"
        )
        require(
            event["previous_sha256"] == previous
            and event["metadata_sha256"] == meta_hash,
            "event hash chain mismatch",
        )
        validate_stamp(event["observed"])
        require(
            event["event"] in ("begin", "end", "interrupt", "exclude"), "event kind"
        )
        identifier(event["trial_id"], "trial ID")
        expected_error = clock_error(
            event["observed"],
            metadata["created"],
            events[-1]["observed"] if events else metadata["created"],
            metadata["policy"],
        )
        require(event["clock_error"] == expected_error, "event clock finding changed")
        if event["event"] in ("begin", "end"):
            validate_observation(
                event["observation"],
                metadata,
                expected_coordinate_frame=expected_coordinate_frame,
            )
            require(event["reason"] is None, "unexpected observation reason")
        else:
            require(event["observation"] is None, "interruption supplied body target")
            text(event["reason"], "interruption reason")
        previous = raw_hash(original)
        events.append(event)
        hashes.append(previous)
    return metadata, meta_hash, events, hashes


def validate_observation(observation, metadata, *, expected_coordinate_frame=None):
    require(isinstance(observation, dict), "explicit observation required")
    require(
        set(observation)
        == {
            "person_count",
            "posture",
            "point_id",
            "room_id",
            "source",
            "provenance",
            "time_uncertainty_ns",
            "truth_uncertainty",
            "frame_evidence_reference",
        },
        "explicit observation fields required",
    )
    count = integer(observation["person_count"], "observed person count", 0, 100)
    text(observation["room_id"], "observed room", 32)
    integer(
        observation["time_uncertainty_ns"],
        "explicit timing uncertainty",
        1,
        60_000_000_000,
    )
    require(
        isinstance(observation["truth_uncertainty"], str)
        and len(observation["truth_uncertainty"]) <= 1024,
        "truth uncertainty",
    )
    require(
        observation["source"] in ("manual_observation", "camera_annotation"),
        "independent reference source required",
    )
    text(observation["provenance"], "observation provenance")
    if observation["source"] == "camera_annotation":
        text(
            observation["frame_evidence_reference"],
            "explicit camera frame evidence required",
        )
    else:
        require(
            observation["frame_evidence_reference"] is None,
            "manual observation has no camera frame",
        )
    if count != 1:
        require(
            observation["posture"] is None and observation["point_id"] is None,
            "negative/multiple-person evidence cannot supply a single body target",
        )
    else:
        require(
            observation["posture"] in (None, "standing", "seated", "lying"),
            "unknown posture",
        )
    if observation["point_id"] is not None:
        point = validate_points(
            metadata["calibration"], expected_coordinate_frame=expected_coordinate_frame
        ).get(observation["point_id"])
        require(point is not None, "unknown point")
        require(
            point["room_id"] == observation["room_id"], "observed point room mismatch"
        )
    return observation


def mark(
    directory,
    trial_id,
    event,
    observation=None,
    reason=None,
    stamp=None,
    *,
    expected_coordinate_frame=None,
):
    stamp = now() if stamp is None else stamp
    identifier(trial_id, "trial ID")
    require(event in ("begin", "end", "interrupt", "exclude"), "event kind")
    state(directory, expected_coordinate_frame=expected_coordinate_frame)
    with locked(directory):
        require(not (directory / "review.json").exists(), "reviewed session is closed")
        metadata, mh, events, hashes = state(
            directory, expected_coordinate_frame=expected_coordinate_frame
        )
        require(len(events) < MAX_EVENTS, "event count exceeded")
        if event in ("begin", "end"):
            validate_observation(
                observation,
                metadata,
                expected_coordinate_frame=expected_coordinate_frame,
            )
            require(reason is None, "observation event has no exclusion reason")
        else:
            text(reason, "interruption/exclusion reason")
            require(observation is None, "interruption cannot create target truth")
        error = clock_error(
            stamp,
            metadata["created"],
            events[-1]["observed"] if events else metadata["created"],
            metadata["policy"],
        )
        row = {
            "schema": EVENT_SCHEMA,
            "index": len(events),
            "previous_sha256": hashes[-1] if hashes else mh,
            "metadata_sha256": mh,
            "trial_id": trial_id,
            "event": event,
            "observed": stamp,
            "observation": observation,
            "reason": reason,
            "clock_error": error,
        }
        require(len(encoded(row)) <= MAX_EVENT_BYTES, "event exceeds bound")
        write(directory / "events" / f"{len(events):06d}.json", row)
        return row


def intervals(metadata, events, *, expected_coordinate_frame=None):
    """Return truthful exclusions; never infer missing endpoints or scheduled acts."""
    included, excluded = [], []
    points = validate_points(
        metadata["calibration"], expected_coordinate_frame=expected_coordinate_frame
    )
    interrupted = {
        e["trial_id"] for e in events if e["event"] in ("interrupt", "exclude")
    }
    active, overlapping = set(), set()
    for row in events:
        if row["event"] == "begin":
            if active:
                overlapping.update(active | {row["trial_id"]})
            active.add(row["trial_id"])
        elif row["event"] in ("end", "interrupt", "exclude"):
            active.discard(row["trial_id"])
    seen_trials = set()
    clock_broken = False
    for i, event in enumerate(events):
        if event["clock_error"]:
            clock_broken = True
        if event["event"] != "begin":
            continue
        trial = event["trial_id"]
        reason = None
        end = events[i + 1] if i + 1 < len(events) else None
        if clock_broken or (end and end["clock_error"]):
            reason = "clock discontinuity; new session required"
        elif (
            trial in seen_trials
            or sum(e["event"] == "begin" and e["trial_id"] == trial for e in events)
            != 1
        ):
            reason = "reused trial ID"
        elif trial in interrupted:
            reason = "explicit interruption or exclusion"
        elif trial in overlapping:
            reason = "overlapping human trials"
        elif end is None or end["event"] != "end" or end["trial_id"] != trial:
            reason = "missing immediate matching end"
        else:
            left, right = event["observation"], end["observation"]
            validate_observation(
                left, metadata, expected_coordinate_frame=expected_coordinate_frame
            )
            validate_observation(
                right, metadata, expected_coordinate_frame=expected_coordinate_frame
            )
            compared = ("person_count", "posture", "point_id", "room_id", "source")
            if any(left[k] != right[k] for k in compared):
                reason = "endpoint observations differ"
            elif left["truth_uncertainty"] or right["truth_uncertainty"]:
                reason = "truth uncertain"
            elif (
                left["point_id"] is not None
                and points[left["point_id"]]["status"] != "measured"
            ):
                reason = "point is proposed, not physically measured"
            else:
                start = (
                    event["observed"]["utc_after_ns"]
                    + metadata["policy"]["transition_margin_ns"]
                )
                finish = (
                    end["observed"]["utc_before_ns"]
                    - metadata["policy"]["transition_margin_ns"]
                )
                uncertainty = max(
                    left["time_uncertainty_ns"], right["time_uncertainty_ns"]
                )
                if finish - start <= 2 * uncertainty:
                    reason = "no stable interval after margins and uncertainty"
                else:
                    included.append(
                        {
                            "trial_id": trial,
                            "start_ns": start,
                            "end_ns": finish,
                            "time_uncertainty_ns": uncertainty,
                            "observation": left,
                            "end_observation": right,
                            "event_indices": [i, i + 1],
                        }
                    )
        seen_trials.add(trial)
        if reason:
            excluded.append({"trial_id": trial, "begin_index": i, "reason": reason})
    return included, excluded


def review(
    directory,
    reviewer,
    evidence,
    accept_reference_truth=False,
    stamp=None,
    *,
    expected_coordinate_frame=None,
):
    require(accept_reference_truth is True, "explicit reference-truth review required")
    text(reviewer, "reviewer")
    text(evidence, "review evidence reference")
    state(directory, expected_coordinate_frame=expected_coordinate_frame)
    with locked(directory):
        metadata, mh, events, hashes = state(
            directory, expected_coordinate_frame=expected_coordinate_frame
        )
        require(events, "no human observations")
        selected, excluded = intervals(
            metadata, events, expected_coordinate_frame=expected_coordinate_frame
        )
        stamp = now() if stamp is None else stamp
        validate_stamp(stamp)
        result = {
            "schema": REVIEW_SCHEMA,
            "metadata_sha256": mh,
            "event_sha256": hashes,
            "reviewer": reviewer,
            "review_evidence": evidence,
            "reviewed_at": stamp,
            "reference_truth_reviewed": True,
            "model_qualified": False,
            "included": selected,
            "excluded": excluded,
        }
        write(directory / "review.json", result)
        return result


def build_export(directory, node_ids, *, expected_coordinate_frame=None):
    require(
        isinstance(node_ids, list) and 0 < len(node_ids) <= 16,
        "explicit node expansion required",
    )
    require(len(set(node_ids)) == len(node_ids), "duplicate export node")
    metadata, mh, events, hashes = state(
        directory, expected_coordinate_frame=expected_coordinate_frame
    )
    reviewed, review_raw = read(directory / "review.json")
    require(
        reviewed.get("schema") == REVIEW_SCHEMA
        and reviewed.get("reference_truth_reviewed") is True,
        "explicit reviewed reference required",
    )
    require(
        reviewed["metadata_sha256"] == mh and reviewed["event_sha256"] == hashes,
        "review no longer binds exact source events",
    )
    text(reviewed.get("reviewer"), "reviewer")
    text(reviewed.get("review_evidence"), "review evidence reference")
    validate_stamp(reviewed["reviewed_at"])
    require(
        reviewed.get("model_qualified") is False,
        "reference review is not model qualification",
    )
    included, excluded = intervals(
        metadata, events, expected_coordinate_frame=expected_coordinate_frame
    )
    require(
        reviewed["included"] == included and reviewed["excluded"] == excluded,
        "review interval mismatch",
    )
    require(
        all(type(n) is int and str(n) in metadata["profiles"] for n in node_ids),
        "export node has no explicit profile",
    )
    require(included, "no reviewed stable intervals")
    points = validate_points(
        metadata["calibration"], expected_coordinate_frame=expected_coordinate_frame
    )
    labels, chunks = [], []
    total_bytes = 0
    for interval in included:
        observed = interval["observation"]
        for node in node_ids:
            label = {
                "schema": "ruview.ground_truth.v2",
                "label_id": interval["trial_id"] + f"-node{node}",
                "session_id": metadata["capture"]["session_id"],
                "capture_id": metadata["capture"]["capture_id"],
                "worker_run_id": metadata["capture"]["worker_run_id"],
                "clock_id": metadata["capture"]["clock_id"],
                "trial_id": interval["trial_id"],
                "node_id": node,
                "room_id": observed["room_id"],
                "start_ns": interval["start_ns"],
                "end_ns": interval["end_ns"],
                "time_uncertainty_ns": interval["time_uncertainty_ns"],
                "person_count": observed["person_count"],
                "source": observed["source"],
                "provenance": f"reference-review-sha256:{raw_hash(review_raw)}; trial:{interval['trial_id']}",
                "reviewed": True,
                "configuration_sha256": metadata["capture"]["configuration_sha256"],
                "commissioning_sha256": metadata["profile_sha256"][str(node)],
                "reference_lineage": {
                    "opening_sha256": metadata["capture_opening_sha256"],
                    "metadata_sha256": mh,
                    "review_sha256": raw_hash(review_raw),
                    "worker_run_id": metadata["capture"]["worker_run_id"],
                    "worker_clock_id": metadata["capture"]["clock_id"],
                    "label_clock": {
                        k: metadata["created"][k] for k in ("host_id", "boot_id")
                    },
                    "event_indices": interval["event_indices"],
                    "clock_offset_applied": False,
                },
            }
            if observed["posture"] is not None:
                label["posture"] = observed["posture"]
            if observed["point_id"] is not None:
                point = points[observed["point_id"]]
                label.update(
                    house_xy_m=point["house_xy_m"],
                    coordinate_frame=expected_coordinate_frame,
                    coordinate_calibration_sha256=metadata["calibration_sha256"],
                    coordinate_reference=metadata["calibration"][
                        "coordinate_reference"
                    ],
                    spatial_uncertainty_m=point["spatial_uncertainty_m"],
                    reference_point_id=point["point_id"],
                )
            validate_label(label, expected_coordinate_frame=expected_coordinate_frame)
            chunk = (json.dumps(label, sort_keys=True, allow_nan=False) + "\n").encode()
            total_bytes += len(chunk)
            require(total_bytes <= MAX_EXPORT_BYTES, "export size exceeds bound")
            chunks.append(chunk)
            labels.append(label)
    raw = b"".join(chunks)
    receipt = {
        "schema": "ruview.reference_export.v1",
        "completed": True,
        "label_count": len(labels),
        "labels_sha256": raw_hash(raw),
        "opening_sha256": metadata["capture_opening_sha256"],
        "metadata_sha256": mh,
        "review_sha256": raw_hash(review_raw),
        "node_ids": node_ids,
        "excluded": excluded,
        "source_clocks_unchanged": True,
        "capture_verified": False,
        "model_qualified": False,
        "clock_alignment_applied": False,
    }
    return labels, raw, receipt


def export(directory, output, node_ids, *, expected_coordinate_frame=None):
    state(directory, expected_coordinate_frame=expected_coordinate_frame)
    with locked(directory):
        _, raw, receipt = build_export(
            directory, node_ids, expected_coordinate_frame=expected_coordinate_frame
        )
        # A receipt exists only after complete, durable labels in a new private directory.
        create_private_directory(output)
        write_bytes(output / "labels.jsonl", raw, MAX_EXPORT_BYTES)
        write(output / "receipt.json", receipt)
        return receipt


def verify_export(directory, export_directory, *, expected_coordinate_frame=None):
    """Recompute original observations/review and compare exact export bytes; no writes."""
    # No lock creation here: readback is read-only; any concurrent change fails hashes.
    require(not directory.is_symlink() and directory.is_dir(), "session directory")
    require(
        not export_directory.is_symlink() and export_directory.is_dir(),
        "export directory",
    )
    receipt, receipt_raw = read(export_directory / "receipt.json")
    labels, expected_raw, expected_receipt = build_export(
        directory,
        receipt["node_ids"],
        expected_coordinate_frame=expected_coordinate_frame,
    )
    require(receipt_raw == encoded(expected_receipt), "export receipt changed")
    actual = read_bytes(export_directory / "labels.jsonl", MAX_EXPORT_BYTES)
    require(actual == expected_raw, "export labels differ from reviewed source")
    # Re-read all original inputs after comparing outputs to reject an intervening edit.
    _, final_raw, final_receipt = build_export(
        directory,
        receipt["node_ids"],
        expected_coordinate_frame=expected_coordinate_frame,
    )
    require(
        final_raw == expected_raw and final_receipt == expected_receipt,
        "reference changed during verification",
    )
    require(
        read_bytes(export_directory / "receipt.json") == receipt_raw,
        "receipt changed during verification",
    )
    return labels, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--capture-opening", type=Path, required=True)
    init.add_argument("--profiles", type=Path, required=True)
    init.add_argument("--points", type=Path)
    init.add_argument("--timing-policy", type=Path, required=True)
    init.add_argument("--operator", required=True)
    marking = commands.add_parser("mark")
    marking.add_argument("--trial-id", required=True)
    marking.add_argument(
        "--event", choices=("begin", "end", "interrupt", "exclude"), required=True
    )
    marking.add_argument("--observation", type=Path)
    marking.add_argument("--reason")
    reviewing = commands.add_parser("review")
    reviewing.add_argument("--reviewer", required=True)
    reviewing.add_argument("--evidence", required=True)
    reviewing.add_argument("--accept-reference-truth", action="store_true")
    exporting = commands.add_parser("export")
    exporting.add_argument("--output", type=Path, required=True)
    exporting.add_argument("--node-ids", type=int, nargs="+", required=True)
    for command in (init, marking, reviewing, exporting):
        command.add_argument(
            "--expected-coordinate-frame",
            help="Independently reviewed frame; required when the session contains points",
        )
    args = parser.parse_args()
    if args.command == "init":
        opening, opening_raw = read(args.capture_opening)
        result = initialize(
            args.directory,
            opening,
            read(args.profiles)[0],
            read(args.points)[0] if args.points else None,
            read(args.timing_policy)[0],
            args.operator,
            opening_raw=opening_raw,
            expected_coordinate_frame=args.expected_coordinate_frame,
        )
        print(
            json.dumps(
                {"session_id": result["capture"]["session_id"], "labels_created": 0}
            )
        )
    elif args.command == "mark":
        result = mark(
            args.directory,
            args.trial_id,
            args.event,
            read(args.observation)[0] if args.observation else None,
            args.reason,
            expected_coordinate_frame=args.expected_coordinate_frame,
        )
        print(
            json.dumps({"index": result["index"], "clock_error": result["clock_error"]})
        )
    elif args.command == "review":
        result = review(
            args.directory,
            args.reviewer,
            args.evidence,
            args.accept_reference_truth,
            expected_coordinate_frame=args.expected_coordinate_frame,
        )
        print(
            json.dumps(
                {
                    "included": len(result["included"]),
                    "excluded": len(result["excluded"]),
                    "model_qualified": False,
                }
            )
        )
    else:
        print(
            json.dumps(
                export(
                    args.directory,
                    args.output,
                    args.node_ids,
                    expected_coordinate_frame=args.expected_coordinate_frame,
                )
            )
        )


if __name__ == "__main__":
    main()
