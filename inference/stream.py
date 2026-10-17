"""Bounded offline replay diagnostics. No network, HA publication or promotion."""

import argparse
import copy
import hashlib
import json
import os
import selectors
import stat
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .capture import datagram, strict_json
from .capture_session import IDENTITY, verified_session
from .evidence import VERIFIED_MODES, validate_evidence, validate_lineage
from .feature_contracts import (
    PREFIX_FEATURE_CONTRACT,
    prefix_selection,
    validate_contract,
)
from .model import evaluate_candidate_values, features, model_identity, validate_model
from .pipeline import (
    AMPLITUDE_CONTRACT,
    WindowBuilder,
    digest,
    integer,
    sha,
    stream_identity,
    validate_frame,
    validate_profile,
)

CONFIG_SCHEMA = "ruview.offline_stream_config.v1"
CONFIG_SCHEMA_V2 = "ruview.offline_stream_config.v2"
EVENT_SCHEMA = "ruview.offline_replay_event.v1"
OUTPUT_SCHEMA = "ruview.offline_stream_diagnostic.v1"
MAX_CONFIG = 4 * 1024 * 1024
MAX_LINE = 16_384
MAX_INPUT = 64 * 1024 * 1024
MAX_LINES = 100_000
MAX_OUTPUT = 64 * 1024 * 1024
U64 = 2**64 - 1
WIRE = {
    "iq_order": "wire_byte_order",
    "source_pair_order": "esp_idf_imaginary_real",
    "worker_phase_convention": "ruview_legacy_atan2_byte1_byte0",
    "monotonic_origin": "worker_start",
    "device_boot_id": None,
    "device_timestamp": None,
}
DEFAULT_POLICY = {
    "duration_ms": 1000,
    "max_gap_ms": 250,
    "min_frames": 8,
    "max_clock_step_ms": 25,
    "max_source_age_ms": 2000,
    "no_input_timeout_ms": 2000,
}


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unexpected contract fields")


def text(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("invalid bounded identity")
    return value


def open_regular(path):
    """Reject writerless FIFOs before any blocking read, including configuration."""
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("named input must be a regular file")
        return fd
    except BaseException:
        os.close(fd)
        raise


class ReplayRunner:
    """Two clocks: declared worker-origin replay time and local silence time.

    Neither is a cross-host clock alignment or a current household observation.
    The only observation status is unavailable; optional numeric candidates are
    a separate research field, never a qualified observation.
    """

    def __init__(
        self,
        config,
        *,
        emit_candidates=False,
        clock=time.monotonic_ns,
        _capture_evidence=None,
        expected_coordinate_frame=None,
    ):
        self.expected_coordinate_frame = expected_coordinate_frame
        # Copy once, so caller mutation cannot change declared identities mid-run.
        config = strict_json(json.dumps(config, allow_nan=False))
        if len(json.dumps(config).encode()) > MAX_CONFIG:
            raise ValueError("configuration bound")
        keys(
            config,
            (
                "schema",
                "source",
                "classification",
                "feature_contract",
                "profiles",
                "models",
                "policy",
            ),
        )
        if config["schema"] not in (CONFIG_SCHEMA, CONFIG_SCHEMA_V2):
            raise ValueError("unknown offline stream config")
        self.v2 = config["schema"] == CONFIG_SCHEMA_V2
        self.capture_evidence = None
        if self.v2:
            if _capture_evidence is None:
                raise ValueError(
                    "v2 requires open_replay with a verified closed session"
                )
            self.capture_evidence = copy.deepcopy(validate_evidence(_capture_evidence))
            if self.capture_evidence["schema"] != "ruview.csi.pair_capture_evidence.v2":
                raise ValueError("v2 capture evidence required")
        elif _capture_evidence is not None:
            raise ValueError("v1 does not accept v2 capture evidence")
        if config["classification"] not in ("synthetic", "household_recording"):
            raise ValueError("explicit recording classification required")
        if type(emit_candidates) is not bool:
            raise ValueError("explicit research candidate switch required")
        self.contract = validate_contract(config["feature_contract"])
        self.source = config["source"]
        keys(
            self.source,
            IDENTITY if self.v2 else ("session_id", "clock_id", "configuration_sha256"),
        )
        text(self.source["session_id"])
        text(self.source["clock_id"])
        sha(self.source["configuration_sha256"], "source configuration")
        if self.v2 and (
            any(self.source[k] != self.capture_evidence[k] for k in IDENTITY)
            or self.capture_evidence["synthetic_only"]
            != (config["classification"] == "synthetic")
        ):
            raise ValueError(
                "config differs from verified capture identity/classification"
            )
        self.policy = config["policy"]
        keys(self.policy, DEFAULT_POLICY)
        for name, low, high in (
            ("duration_ms", 1, 60_000),
            ("max_gap_ms", 1, 60_000),
            ("min_frames", 2, 4096),
            ("max_clock_step_ms", 0, 1000),
            ("max_source_age_ms", 1, 10_000),
            ("no_input_timeout_ms", 1, 10_000),
        ):
            integer(self.policy[name], name, low, high)
        profiles = config["profiles"]
        if not isinstance(profiles, list) or not 1 <= len(profiles) <= 10:
            raise ValueError("one to ten declared node profiles required")
        self.profiles = {}
        for profile in profiles:
            validate_profile(profile)
            node = profile["node_id"]
            if node in self.profiles:
                raise ValueError("duplicate node profile")
            self.profiles[node] = profile
        if (
            self.v2
            and sorted(self.profiles) != self.capture_evidence["expected_node_ids"]
        ):
            raise ValueError("profiles differ from verified capture node scope")
        models = config["models"]
        if not isinstance(models, dict) or set(models) - {
            str(n) for n in self.profiles
        }:
            raise ValueError("model outside declared node scope")
        self.models, self.lineage = {}, {}
        for key, model in models.items():
            node = int(key)
            validate_model(model, expected_coordinate_frame=expected_coordinate_frame)
            source_schema = model["input_identity"].get("source_frame_schema")
            if self.v2 and source_schema != "ruview.csi.frame.v2":
                raise ValueError("offline stream v2 requires original v2 model inputs")
            if not self.v2 and source_schema is not None:
                raise ValueError("offline stream v1 requires original v1 model inputs")
            identity = model["input_identity"]
            if (
                model["feature_contract"] != self.contract
                or identity["node_id"] != node
                or identity["configuration_sha256"]
                != self.source["configuration_sha256"]
                or identity["commissioning_sha256"] != digest(self.profiles[node])
                or identity["policy"] != self.window_policy()
            ):
                raise ValueError("model/profile/configuration/policy binding mismatch")
            lineage = validate_lineage(
                model.get("capture_lineage"),
                set(model["training_sessions"]) | set(model["evaluation_sessions"]),
                identity,
            )
            if lineage["status"] in VERIFIED_MODES and (
                lineage["recordings"][0]["synthetic_only"]
                != (config["classification"] == "synthetic")
            ):
                raise ValueError("model/replay recording classification mismatch")
            self.models[node], self.lineage[node] = model, lineage
        self.clock = clock
        self.started = self.last_local = integer(clock(), "local clock", 0, U64)
        self.replay_at = None
        self.run_id = str(uuid.uuid4())
        self.sequence = 0
        self.config_sha = digest(config)
        self.classification = config["classification"]
        self.emit_candidates = emit_candidates
        self.closed = False
        self.admission_highwater = None
        self.nodes = {
            n: {
                "epoch": 1,
                "builder": self.builder(n),
                "last": None,
                "local_at": self.started,
                "active": True,
                "blocked": False,
                "receipt_highwater": None,
                "candidate_window_id": None,
                "candidate_source_at": None,
                "candidate_local_at": None,
                "candidate_initial_age": None,
            }
            for n in self.profiles
        }

    def window_policy(self):
        return {
            "duration_ns": self.policy["duration_ms"] * 1_000_000,
            "max_gap_ns": self.policy["max_gap_ms"] * 1_000_000,
            "min_frames": self.policy["min_frames"],
            "max_clock_step_ns": self.policy["max_clock_step_ms"] * 1_000_000,
        }

    def builder(self, node):
        return WindowBuilder(
            **{
                k: self.policy[k]
                for k in (
                    "duration_ms",
                    "max_gap_ms",
                    "min_frames",
                    "max_clock_step_ms",
                )
            },
            profiles=[self.profiles[node]],
            feature_contract=self.contract,
        )

    def record(self, kind, **values):
        self.sequence += 1
        return copy.deepcopy(
            {
                "schema": OUTPUT_SCHEMA,
                "kind": kind,
                "runner_run_id": self.run_id,
                "sequence": self.sequence,
                "runner_config_sha256": self.config_sha,
                "runner_elapsed_ns": self.last_local - self.started,
                "replay_at_ns": self.replay_at,
                "mode": "offline_replay",
                "status": "unavailable",
                "qualification": "missing_qualification_permit",
                "qualified": False,
                "publish_to_ha": False,
                **values,
            }
        )

    def start_record(self):
        return self.record(
            "run_start",
            source_stream=self.source,
            input_classification=self.classification,
            replay_time_basis=(
                "recorded_worker_arrival_not_current_time"
                if self.v2
                else "declared_worker_start_monotonic_not_current_time"
            ),
            recording_verification="verified_closed_capture"
            if self.v2
            else "not_supplied",
            **self.capture_provenance(),
            feature_contract=self.contract,
            policy=self.policy,
            models={
                str(n): {
                    "model_sha256": m["model_sha256"],
                    "task": m["task"],
                    "target_identity": m["target_identity"],
                    "model_capture_lineage": self.lineage[n],
                }
                for n, m in self.models.items()
            },
            declared_profiles={
                str(n): {"sha256": digest(p), "profile": p}
                for n, p in self.profiles.items()
            },
            physical_configuration_monitoring=False,
        )

    def capture_provenance(self, window=None):
        if not self.v2:
            return {}
        result = {
            "capture_evidence": self.capture_evidence,
            "device_boot_id": None,
            "device_boot_identity_verified": False,
            "device_boot_identity_source": "not_transmitted_by_recorded_wire_contract",
        }
        if window is not None:
            result["original_window_timeline"] = {
                key: window[key]
                for key in (
                    "timestamps_ns",
                    "monotonic_ns",
                    "sequences",
                    "ingress_sequences",
                    "capture_sequences",
                )
            }
        return result

    def consume_input(self, value):
        """V2 replays original raw rows at their recorded arrival, without retiming."""
        if self.v2:
            value = {
                "schema": EVENT_SCHEMA,
                "kind": "frame",
                "at_ns": value["received_monotonic_ns"],
                "clock_id": self.source["clock_id"],
                "frame": value,
            }
        return self.consume(value)

    def finish_input(self, proof):
        if not self.v2:
            return []
        if proof["sha256"] != self.capture_evidence["raw_sha256"]:
            raise ValueError("verified replay spool bytes changed")
        # Preserve the actual terminal silence, not a fabricated extra interval.
        return self.consume(
            {
                "schema": EVENT_SCHEMA,
                "kind": "tick",
                "at_ns": self.capture_evidence["end_boundary"]["clock"]["monotonic_ns"],
                "clock_id": self.source["clock_id"],
            }
        )

    def invalidate(self, node, reason, *, block=False):
        state = self.nodes[node]
        withdrawn = state["candidate_window_id"]
        state.update(
            epoch=state["epoch"] + 1,
            builder=self.builder(node),
            last=None,
            local_at=self.last_local,
            active=False,
            blocked=block,
            candidate_window_id=None,
            candidate_source_at=None,
            candidate_local_at=None,
            candidate_initial_age=None,
        )
        return self.record(
            "node_status",
            node_id=node,
            node_epoch=state["epoch"],
            reason=reason,
            candidate_state="withdrawn",
            withdrawn_window_id=withdrawn,
        )

    def withdraw_candidate(self, node, reason):
        """Expire one result without discarding fresh partial window input."""
        state = self.nodes[node]
        withdrawn = state["candidate_window_id"]
        state.update(
            candidate_window_id=None,
            candidate_source_at=None,
            candidate_local_at=None,
            candidate_initial_age=None,
        )
        return self.record(
            "node_status",
            node_id=node,
            node_epoch=state["epoch"],
            reason=reason,
            candidate_state="withdrawn",
            withdrawn_window_id=withdrawn,
        )

    def poll(self):
        if self.closed:
            raise ValueError("runner is closed")
        now = integer(self.clock(), "local clock", 0, U64)
        if now < self.last_local:
            raise ValueError("local monotonic clock regressed")
        self.last_local = now
        result = []
        for node, state in self.nodes.items():
            if state["active"] and now - state["local_at"] >= (
                self.policy["no_input_timeout_ms"] * 1_000_000
            ):
                result.append(self.invalidate(node, "no_input_timeout"))
            elif state["candidate_window_id"] is not None and (
                state["candidate_initial_age"] + now - state["candidate_local_at"]
                > self.policy["max_source_age_ms"] * 1_000_000
            ):
                result.append(self.withdraw_candidate(node, "candidate_local_expired"))
        return result

    def consume(self, event):
        result = self.poll()
        if not isinstance(event, dict) or event.get("kind") not in ("frame", "tick"):
            raise ValueError("unknown replay event kind")
        keys(
            event,
            ("schema", "kind", "at_ns", "clock_id")
            + (("frame",) if event["kind"] == "frame" else ()),
        )
        if (
            event["schema"] != EVENT_SCHEMA
            or event["clock_id"] != self.source["clock_id"]
        ):
            raise ValueError("replay clock identity differs")
        at = integer(event["at_ns"], "replay time", 0, U64)
        if self.replay_at is not None and at < self.replay_at:
            raise ValueError("replay clock regressed")
        self.replay_at = at
        for node, state in self.nodes.items():
            if state["last"] is not None and (
                at - state["last"]["received_monotonic_ns"]
                > self.policy["max_source_age_ms"] * 1_000_000
            ):
                result.append(self.invalidate(node, "source_expired"))
            elif state["candidate_window_id"] is not None and (
                at - state["candidate_source_at"]
                > self.policy["max_source_age_ms"] * 1_000_000
            ):
                result.append(self.withdraw_candidate(node, "candidate_source_expired"))
        if event["kind"] == "tick":
            return result
        frame = event["frame"]
        validate_frame(frame)
        if not self.v2 and frame["schema"] != "ruview.csi.frame.v1":
            raise ValueError("offline stream v1 does not accept dynamic v2 captures")
        if self.v2 and frame["schema"] != "ruview.csi.frame.v2":
            raise ValueError("verified replay requires original v2 frames")
        node = frame["node_id"]
        if node not in self.nodes:
            raise ValueError("frame outside declared node scope")
        # Admission belongs to the whole capture, including blocked nodes.
        if self.v2:
            admission = (frame["ingress_sequence"], frame["capture_sequence"])
            if self.admission_highwater is not None and (
                admission[0] <= self.admission_highwater[0]
                or admission[1] != self.admission_highwater[1] + 1
            ):
                raise ValueError("changed v2 admission timeline")
            self.admission_highwater = admission
        state = self.nodes[node]
        if state["blocked"]:
            return result
        for key in ("received_at_ns", "received_monotonic_ns"):
            integer(frame[key], key, 0 if key.endswith("monotonic_ns") else 1, U64)
        text(frame["session_id"])
        text(frame["clock_id"])
        if any(frame[k] != v for k, v in self.source.items()):
            result.append(self.invalidate(node, "source_identity_mismatch", block=True))
            return result
        if (
            any(key not in frame or frame[key] != value for key, value in WIRE.items())
            or frame["ppdu_type"] != 0
            or frame["flags"] not in (0, 16)
            or frame["frequency_mhz"] not in (*range(2412, 2473, 5), 2484)
            or frame.get("first_word_invalid") is not None
            or frame.get("first_word_sanitized") is not None
            or hashlib.sha256(datagram(frame)).hexdigest()
            != frame.get("raw_datagram_sha256")
        ):
            result.append(self.invalidate(node, "raw_contract_mismatch", block=True))
            return result
        age = at - frame["received_monotonic_ns"]
        if age < 0 or age > self.policy["max_source_age_ms"] * 1_000_000:
            result.append(self.invalidate(node, "future_or_stale_frame"))
            return result
        profile = self.profiles[node]
        if frame["frequency_mhz"] != profile["frequency_mhz"]:
            result.append(
                self.invalidate(node, "profile_frequency_mismatch", block=True)
            )
            return result
        context = {
            **frame,
            "policy": self.window_policy(),
            "commissioning_sha256": digest(profile),
            "amplitude_contract": AMPLITUDE_CONTRACT,
            "time_basis": "receiver_host_arrival_not_device_capture",
        }
        if self.contract == PREFIX_FEATURE_CONTRACT:
            context["feature_selection"] = prefix_selection()
        model = self.models.get(node)
        if model is not None and model_identity(context) != model["input_identity"]:
            result.append(self.invalidate(node, "model_input_mismatch", block=True))
            return result
        stamp = (frame["received_monotonic_ns"], frame["received_at_ns"])
        highwater = state["receipt_highwater"]
        if highwater is not None and any(
            a <= b for a, b in zip(stamp, highwater, strict=True)
        ):
            result.append(self.invalidate(node, "replayed_or_regressed_receipt"))
            return result
        # Keep this across resets, including a discarded discontinuity boundary.
        state["receipt_highwater"] = stamp
        previous = state["last"]
        if previous is not None:
            dm = frame["received_monotonic_ns"] - previous["received_monotonic_ns"]
            du = frame["received_at_ns"] - previous["received_at_ns"]
            if (
                stream_identity(frame) != stream_identity(previous)
                or dm <= 0
                or du <= 0
                or abs(dm - du) > self.window_policy()["max_clock_step_ns"]
                or dm > self.window_policy()["max_gap_ns"]
                or (frame["sequence"] - previous["sequence"]) % 2**32 != 1
            ):
                result.append(self.invalidate(node, "input_discontinuity"))
                return result  # Discard the boundary frame, never fill a gap.
        state["last"] = copy.deepcopy(frame)
        state["local_at"], state["active"] = self.last_local, True
        # Retain only the accepted copy; caller mutation must not alter pending CSI.
        window = state["builder"].push(state["last"])
        if window is None:
            return result
        if self.v2:
            validate_evidence(self.capture_evidence, window)
        feature_values = features(window, self.contract)
        candidate = None
        if model is not None and self.emit_candidates:
            candidate = {
                "prediction": evaluate_candidate_values(
                    model,
                    window,
                    self.contract,
                    expected_coordinate_frame=self.expected_coordinate_frame,
                ),
                "task": model["task"],
                "target_identity": model["target_identity"],
                "model_sha256": model["model_sha256"],
                "confidence": None,
                "validation": "unverified",
                "publish_to_ha": False,
            }
        # Expensive local computation cannot extend a frame's silence lease.
        result.extend(self.poll())
        if not state["active"]:
            return result
        if candidate is not None:
            if age + self.last_local - state["local_at"] > (
                self.policy["max_source_age_ms"] * 1_000_000
            ):
                result.append(
                    self.withdraw_candidate(node, "candidate_expired_before_emission")
                )
                return result
            state.update(
                candidate_window_id=window["window_id"],
                candidate_source_at=frame["received_monotonic_ns"],
                candidate_local_at=state["local_at"],
                candidate_initial_age=age,
            )
        result.append(
            self.record(
                "window_diagnostic",
                node_id=node,
                node_epoch=state["epoch"],
                reason="missing_candidate_model"
                if model is None
                else "missing_qualification_permit",
                candidate_state="research_only" if candidate else "not_emitted",
                research_candidate=candidate,
                current_input_provenance={
                    "schema": "ruview.offline_replay_input.v2"
                    if self.v2
                    else "ruview.offline_replay_input.v1",
                    **self.source,
                    "recording_verification": "verified_closed_capture"
                    if self.v2
                    else "not_supplied",
                    **self.capture_provenance(window),
                    "classification": self.classification,
                    "window_id": window["window_id"],
                    "node_id": node,
                    "start_utc_ns": window["timestamps_ns"][0],
                    "end_utc_ns": window["timestamps_ns"][-1],
                    "start_monotonic_ns": window["monotonic_ns"][0],
                    "end_monotonic_ns": window["monotonic_ns"][-1],
                    "replay_at_ns": at,
                    "source_age_ns": age,
                    "last_original_datagram_sha256": frame["raw_datagram_sha256"],
                    "commissioning_sha256": window["commissioning_sha256"],
                    "first_word_invalid": None,
                    "validity_source": "not_transmitted_by_legacy_firmware",
                },
                feature_count=len(feature_values),
                feature_sha256=digest(feature_values),
            )
        )
        return result

    def close(self, reason):
        if self.closed:
            return []
        result = [self.invalidate(n, reason) for n in self.nodes]
        self.closed = True
        return result


def run_input(fd, runner, emit, *, max_seconds=30, clock=time.monotonic):
    """Read only a regular file or pipe, checking silence even without input."""
    integer(max_seconds, "max_seconds", 1, 3600)
    mode = os.fstat(fd).st_mode
    if not (stat.S_ISREG(mode) or stat.S_ISFIFO(mode)):
        raise ValueError("input must be a regular file or pipe")
    deadline = clock() + max_seconds
    pending = bytearray()
    checksum = hashlib.sha256()
    total = lines = 0
    selector = selectors.DefaultSelector()
    try:
        if stat.S_ISFIFO(mode):
            selector.register(fd, selectors.EVENT_READ)
        while True:
            for record in runner.poll():
                emit(record)
            if clock() >= deadline:
                raise ValueError("input deadline")
            if stat.S_ISFIFO(mode) and not selector.select(
                min(0.05, deadline - clock())
            ):
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                if pending:
                    raise ValueError("unterminated JSONL tail")
                proof = {"bytes": total, "lines": lines, "sha256": checksum.hexdigest()}
                for record in runner.finish_input(proof):
                    emit(record)
                return proof
            total += len(chunk)
            checksum.update(chunk)
            if total > MAX_INPUT:
                raise ValueError("input byte bound")
            pending.extend(chunk)
            while b"\n" in pending:
                line, _, remaining = pending.partition(b"\n")
                pending = bytearray(remaining)
                lines += 1
                if lines > MAX_LINES or not line or len(line) > MAX_LINE:
                    raise ValueError("input line/count bound")
                for record in runner.consume_input(strict_json(line)):
                    emit(record)
                if clock() >= deadline:
                    raise ValueError("input deadline")
            if len(pending) > MAX_LINE:
                raise ValueError("input line bound")
    finally:
        selector.close()


@contextmanager
def open_replay(
    config,
    input_path,
    *,
    manifest=None,
    capture_report=None,
    opening=None,
    terminal=None,
    **runner_options,
):
    """Verify and hold a private v2 spool for the entire replay, or open legacy v1.

    Full-session verification precedes output creation. The caller must consume
    the yielded path (not the mutable original) with run_input, which rechecks its
    byte hash at EOF. This does not authenticate the operator or physical profile.
    """
    paths = (manifest, capture_report, opening, terminal)
    if config.get("schema") != CONFIG_SCHEMA_V2:
        if any(p is not None for p in paths):
            raise ValueError("capture evidence options require v2 config")
        yield ReplayRunner(config, **runner_options), input_path
        return
    if input_path == "-" or not all(p is not None for p in paths):
        raise ValueError("v2 requires original files and all closed-session evidence")
    with verified_session(
        input_path,
        manifest,
        capture_report,
        opening,
        terminal,
        [p["node_id"] for p in config["profiles"]],
    ) as (spool, evidence):
        if spool.stat().st_size > MAX_INPUT:
            raise ValueError("input byte bound")
        yield ReplayRunner(config, _capture_evidence=evidence, **runner_options), spool


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--input", required=True, help="offline JSONL file, or - for stdin pipe"
    )
    parser.add_argument("--output", required=True, help="new private diagnostic JSONL")
    parser.add_argument("--manifest", help="v2 capture manifest")
    parser.add_argument("--capture-report", help="saved v2 session verification report")
    parser.add_argument("--opening", help="original v2 opening.json")
    parser.add_argument("--terminal", help="original v2 terminal.json")
    parser.add_argument("--emit-research-candidates", action="store_true")
    parser.add_argument("--max-seconds", type=int, default=30)
    parser.add_argument("--expected-coordinate-frame")
    args = parser.parse_args()
    runner = None
    try:
        with os.fdopen(open_regular(args.config), "rb") as source:
            data = source.read(MAX_CONFIG + 1)
        if len(data) > MAX_CONFIG:
            raise ValueError("configuration byte bound")
        config = strict_json(data)
        # A new file prevents stale output/evidence replacement, including symlinks.
        with (
            open_replay(
                config,
                args.input,
                manifest=args.manifest,
                capture_report=args.capture_report,
                opening=args.opening,
                terminal=args.terminal,
                emit_candidates=args.emit_research_candidates,
                expected_coordinate_frame=args.expected_coordinate_frame,
            ) as (runner, input_path),
            os.fdopen(
                os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as out,
        ):
            used = 0

            def emit(record, closing=False):
                nonlocal used
                data = (
                    json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n"
                ).encode()
                limit = MAX_OUTPUT if closing else MAX_OUTPUT - 65_536
                if used + len(data) > limit:
                    raise ValueError("output byte bound")
                out.write(data)
                out.flush()
                used += len(data)

            emit(runner.start_record())
            fd = None
            completed, proof = False, None
            try:
                fd = (
                    sys.stdin.fileno()
                    if input_path == "-"
                    else open_regular(input_path)
                )
                proof = run_input(fd, runner, emit, max_seconds=args.max_seconds)
                completed = True
            finally:
                if fd is not None and input_path != "-":
                    os.close(fd)
                for record in runner.close(
                    "input_ended" if completed else "input_failed"
                ):
                    emit(record, closing=True)
                emit(
                    runner.record("run_end", completed=completed, original_input=proof),
                    closing=True,
                )
        print(
            json.dumps({"completed": True, "qualified": False, "publish_to_ha": False})
        )
        return 0
    except Exception as error:
        # Do not echo private paths, raw frames, checkpoint targets or exception text.
        print(
            json.dumps(
                {
                    "completed": False,
                    "error_type": type(error).__name__,
                    "qualified": False,
                    "publish_to_ha": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
