"""Offline commands. Writes new private output files; never opens a device/camera."""

import argparse
import hashlib
import json
import os
from contextlib import nullcontext
from pathlib import Path

from .feature_contracts import FEATURE_CONTRACT, FEATURE_CONTRACTS
from .pipeline import WindowBuilder, integer, pair_window, validate_label


def read_jsonl(path):
    with Path(path).open() as stream:
        for line_number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON at line {line_number}") from exc


def private_output(path):
    # O_EXCL also rejects symlinks and accidental replacement of earlier evidence.
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")


def select_node(records, node_id):
    """Select an explicitly requested stream; never combine physical receivers."""
    if node_id is None:
        yield from records
        return
    integer(node_id, "selected node ID", 1, 255)
    found = False
    for record in records:
        identity = integer(record["window"]["node_id"], "window node ID", 1, 255)
        if identity == node_id:
            found = True
            yield record
    if not found:
        raise ValueError("selected node has no windows")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    from .session_commands import arguments as session_arguments

    session_arguments(sub)
    pair = sub.add_parser(
        "pair", help="native frame JSONL -> independently labeled windows"
    )
    pair.add_argument("--frames", required=True)
    pair.add_argument("--labels", required=True)
    pair.add_argument(
        "--profiles", required=True, help="JSON list of per-node commissioning profiles"
    )
    pair.add_argument("--output", required=True)
    pair.add_argument("--label-clock-offset-ms", type=int, required=True)
    pair.add_argument("--max-label-uncertainty-ms", type=int, default=100)
    pair.add_argument("--window-ms", type=int, default=1000)
    pair.add_argument("--max-gap-ms", type=int, default=250)
    pair.add_argument("--min-frames", type=int, default=8)
    for option in (
        "capture-manifest",
        "capture-report",
        "opening-snapshot",
        "closing-snapshot",
    ):
        pair.add_argument(
            "--" + option, help="all four evidence options are required together"
        )
    train_cmd = sub.add_parser(
        "train", help="fit a per-node candidate with session holdout"
    )
    train_cmd.add_argument("--paired", required=True)
    train_cmd.add_argument(
        "--task", choices=("posture", "image_pose_2d", "house_xy_m"), required=True
    )
    train_cmd.add_argument("--eval-session", action="append", required=True)
    train_cmd.add_argument("--output", required=True)
    train_cmd.add_argument("--ridge", type=float, default=1.0)
    train_cmd.add_argument(
        "--node-id", type=int, help="select one physical node from a shared recording"
    )
    predict_cmd = sub.add_parser(
        "predict-candidate", help="offline research outputs only"
    )
    predict_cmd.add_argument("--model", required=True)
    predict_cmd.add_argument(
        "--paired", required=True, help="paired JSONL supplies windows"
    )
    predict_cmd.add_argument("--output", required=True)
    predict_cmd.add_argument(
        "--node-id", type=int, help="select one physical node; must match checkpoint"
    )
    for command in (pair, train_cmd, predict_cmd):
        command.add_argument(
            "--feature-contract",
            choices=FEATURE_CONTRACTS,
            default=FEATURE_CONTRACT,
            help="explicit selection; must match stored windows and checkpoint",
        )
    capture_cmd = sub.add_parser(
        "verify-capture", help="verify original raw/snapshot bytes and capture coverage"
    )
    for option in (
        "manifest",
        "frames",
        "opening-snapshot",
        "closing-snapshot",
        "output",
    ):
        capture_cmd.add_argument("--" + option, required=True)
    for command in (pair, train_cmd, predict_cmd):
        command.add_argument(
            "--expected-coordinate-frame",
            help="Independently reviewed frame; required for house-coordinate data",
        )
    args = parser.parse_args()
    if args.command in ("index-session", "verify-session", "pair-session"):
        from .session_commands import run

        run(args)
    elif args.command == "verify-capture":
        from .capture import file_bytes, strict_json, verify_capture

        raw_manifest = file_bytes(args.manifest, 1_048_576)
        result = verify_capture(
            strict_json(raw_manifest),
            args.frames,
            args.opening_snapshot,
            args.closing_snapshot,
        )
        result["manifest_original_sha256"] = hashlib.sha256(raw_manifest).hexdigest()
        with private_output(args.output) as out:
            json.dump(result, out, indent=2, allow_nan=False)
            out.write("\n")
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in ("recording_complete", "frames", "findings")
                }
            )
        )
        if not result["recording_complete"]:
            raise SystemExit(1)
    elif args.command == "pair":
        from .evidence import UNVERIFIED, validate_evidence, verified_recording

        bundle = (
            args.capture_manifest,
            args.capture_report,
            args.opening_snapshot,
            args.closing_snapshot,
        )
        if any(bundle) and not all(bundle):
            parser.error("pair capture evidence requires all four evidence options")
        labels = list(read_jsonl(args.labels))
        for label in labels:
            validate_label(
                label, expected_coordinate_frame=args.expected_coordinate_frame
            )
        profiles = json.loads(Path(args.profiles).read_text())
        builder = WindowBuilder(
            args.window_ms,
            args.max_gap_ms,
            args.min_frames,
            profiles=profiles,
            feature_contract=args.feature_contract,
        )
        paired_count = 0
        source = (
            verified_recording(args.frames, *bundle, list(builder.profiles))
            if all(bundle)
            else nullcontext((args.frames, dict(UNVERIFIED)))
        )
        with source as (frames_path, evidence):
            if evidence["status"] == "verified_recording":
                for label in labels:
                    if (
                        label["session_id"] != evidence["session_id"]
                        or label["configuration_sha256"]
                        != evidence["configuration_sha256"]
                        or label["node_id"] not in evidence["expected_node_ids"]
                    ):
                        raise ValueError("label differs from verified capture identity")
            with private_output(args.output) as out:
                for frame in read_jsonl(frames_path):
                    if evidence["status"] == "verified_recording":
                        interval = evidence["planned_interval"]
                        if (
                            not interval["start_utc_ns"]
                            <= frame["received_at_ns"]
                            <= interval["end_utc_ns"]
                        ):
                            continue
                    window = builder.push(frame)
                    if window is None:
                        continue
                    paired = pair_window(
                        window,
                        labels,
                        args.label_clock_offset_ms * 1_000_000,
                        args.max_label_uncertainty_ms * 1_000_000,
                        expected_coordinate_frame=args.expected_coordinate_frame,
                    )
                    if paired is not None:
                        paired["capture_evidence"] = validate_evidence(evidence, window)
                        out.write(json.dumps(paired, allow_nan=False) + "\n")
                        paired_count += 1
        print(
            json.dumps(
                {
                    "windows_paired": paired_count,
                    "window_stats": builder.stats,
                    "output": args.output,
                    "accuracy_validated": False,
                    "capture_verification": evidence["status"],
                }
            )
        )
    elif args.command == "train":
        from .model import train

        model = train(
            list(select_node(read_jsonl(args.paired), args.node_id)),
            args.task,
            set(args.eval_session),
            args.ridge,
            feature_contract=args.feature_contract,
            expected_coordinate_frame=args.expected_coordinate_frame,
        )
        with private_output(args.output) as out:
            json.dump(model, out, indent=2, allow_nan=False)
            out.write("\n")
        print(
            json.dumps(
                {
                    key: model[key]
                    for key in (
                        "task",
                        "status",
                        "training_windows",
                        "evaluation_windows",
                        "metrics",
                        "model_sha256",
                    )
                }
            )
        )
    else:
        from .model import predict, validate_model

        model = json.loads(Path(args.model).read_text())
        validate_model(model, expected_coordinate_frame=args.expected_coordinate_frame)
        if (
            args.node_id is not None
            and args.node_id != model["input_identity"]["node_id"]
        ):
            raise ValueError("selected node differs from checkpoint")
        records = select_node(read_jsonl(args.paired), args.node_id)
        with private_output(args.output) as out:
            for record in records:
                out.write(
                    json.dumps(
                        predict(
                            model,
                            record["window"],
                            record.get("capture_evidence"),
                            feature_contract=args.feature_contract,
                            expected_coordinate_frame=args.expected_coordinate_frame,
                        ),
                        allow_nan=False,
                    )
                    + "\n"
                )


if __name__ == "__main__":
    main()
