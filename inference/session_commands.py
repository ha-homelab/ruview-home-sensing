"""Offline CLI for original closed captures and reviewed independent references."""

import hashlib
import json
import os
import stat
from collections import Counter
from pathlib import Path

from .capture import file_bytes, strict_json
from .capture_session import (
    IDENTITY,
    MANIFEST,
    MAX_SESSION_BYTES,
    require,
    validate_opening,
    verified_session,
    verify_session,
)
from .feature_contracts import FEATURE_CONTRACT, FEATURE_CONTRACTS
from .pipeline import WindowBuilder, integer, pair_window


def arguments(sub):
    index = sub.add_parser(
        "index-session",
        help="index and verify already closed original v2 files; never closes a live recording",
    )
    for option in (
        "frames",
        "opening",
        "terminal",
        "manifest-output",
        "report-output",
        "provenance-reference",
    ):
        index.add_argument("--" + option, required=True)
    index.add_argument(
        "--classification", choices=("synthetic", "household_recording"), required=True
    )
    index.add_argument("--max-clock-step-ns", type=int, required=True)
    index.add_argument("--max-receipt-gap-ns", type=int, required=True)
    verify = sub.add_parser(
        "verify-session", help="recompute original v2 capture closure evidence"
    )
    for option in ("frames", "opening", "terminal", "manifest", "report-output"):
        verify.add_argument("--" + option, required=True)
    pair = sub.add_parser(
        "pair-session",
        help="closed v2 CSI + reviewed reference export + actual bracketing clock probes",
    )
    for option in (
        "frames",
        "opening",
        "terminal",
        "manifest",
        "capture-report",
        "profiles",
        "reference-directory",
        "reference-export",
        "clock-before",
        "clock-after",
        "clock-assumption-reference",
        "output",
        "report-output",
    ):
        pair.add_argument("--" + option, required=True)
    pair.add_argument("--expected-coordinate-frame")
    pair.add_argument("--between-probe-allowance-ns", type=int, required=True)
    pair.add_argument("--max-label-uncertainty-ns", type=int, required=True)
    pair.add_argument("--window-ms", type=int, default=1000)
    pair.add_argument("--max-gap-ms", type=int, default=250)
    pair.add_argument("--min-frames", type=int, default=8)
    pair.add_argument(
        "--feature-contract", choices=FEATURE_CONTRACTS, default=FEATURE_CONTRACT
    )


def private_json(path, value):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as out:
        json.dump(value, out, indent=2, allow_nan=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())


def fingerprint(path, maximum):
    total, checksum = 0, hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(
            stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
            "original file must be regular",
        )
        while chunk := stream.read(min(65536, maximum - total + 1)):
            total += len(chunk)
            require(total <= maximum, "original file exceeds bound")
            checksum.update(chunk)
    return {"bytes": total, "sha256": checksum.hexdigest()}


def run(args):
    if args.command in ("index-session", "verify-session"):
        if args.command == "index-session":
            opening = validate_opening(strict_json(file_bytes(args.opening, 1_048_576)))
            manifest = {
                "schema": MANIFEST,
                **{key: opening[key] for key in IDENTITY},
                "synthetic_only": args.classification == "synthetic",
                "provenance_reference": args.provenance_reference,
                "policy": {
                    "max_clock_step_ns": args.max_clock_step_ns,
                    "max_receipt_gap_ns": args.max_receipt_gap_ns,
                },
                "files": {
                    key: fingerprint(path, bound)
                    for key, path, bound in (
                        ("raw", args.frames, MAX_SESSION_BYTES),
                        ("opening", args.opening, 1_048_576),
                        ("terminal", args.terminal, 1_048_576),
                    )
                },
            }
            # Indexing never changes original bytes or fabricates a terminal.
            report = verify_session(manifest, args.frames, args.opening, args.terminal)
            private_json(args.manifest_output, manifest)
            original = file_bytes(args.manifest_output, 1_048_576)
        else:
            original = file_bytes(args.manifest, 1_048_576)
            report = verify_session(
                strict_json(original), args.frames, args.opening, args.terminal
            )
        report["manifest_original_sha256"] = hashlib.sha256(original).hexdigest()
        private_json(args.report_output, report)
        print(
            json.dumps(
                {
                    key: report[key]
                    for key in (
                        "capture_closed_verified",
                        "frames",
                        "findings",
                        "observations",
                    )
                }
            )
        )
        if not report["capture_closed_verified"]:
            raise SystemExit(1)
        return

    from .evidence import validate_evidence
    from .reference_alignment import (
        align_label,
        make_alignment,
        validate_paired_alignment,
    )
    from .reference_session import verify_export

    integer(args.max_label_uncertainty_ns, "explicit total label uncertainty budget", 1)
    profiles = strict_json(file_bytes(args.profiles, 1_048_576))
    builder = WindowBuilder(
        args.window_ms,
        args.max_gap_ms,
        args.min_frames,
        profiles=profiles,
        feature_contract=args.feature_contract,
    )
    originals, reference_receipt = verify_export(
        Path(args.reference_directory),
        Path(args.reference_export),
        expected_coordinate_frame=args.expected_coordinate_frame,
    )
    require(
        sorted(reference_receipt["node_ids"]) == sorted(builder.profiles),
        "reference export/profile node scope mismatch",
    )
    totals = Counter()
    paired_hash = hashlib.sha256()
    with verified_session(
        args.frames,
        args.manifest,
        args.capture_report,
        args.opening,
        args.terminal,
        list(builder.profiles),
    ) as (raw_path, evidence):
        alignment = make_alignment(
            file_bytes(args.clock_before, 1_048_576),
            file_bytes(args.clock_after, 1_048_576),
            evidence,
            between_probe_allowance_ns=args.between_probe_allowance_ns,
            assumption_reference=args.clock_assumption_reference,
        )
        adjusted = [
            align_label(
                label,
                alignment,
                evidence,
                expected_coordinate_frame=args.expected_coordinate_frame,
            )
            for label in originals
        ]
        original_by_id = {label["label_id"]: label for label in originals}
        require(len(original_by_id) == len(originals), "duplicate reference label ID")
        with (
            os.fdopen(
                os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as out,
            open(raw_path, "rb") as frames,
        ):
            for line in frames:
                totals["source_frames"] += 1
                window = builder.push(strict_json(line))
                if window is None:
                    continue
                paired = pair_window(
                    window,
                    adjusted,
                    alignment["label_to_csi_clock_offset_ns"],
                    args.max_label_uncertainty_ns,
                    expected_coordinate_frame=args.expected_coordinate_frame,
                )
                if paired is None:
                    totals["windows_without_unique_usable_label"] += 1
                    continue
                paired["capture_evidence"] = validate_evidence(evidence, window)
                paired["original_label"] = original_by_id[paired["label"]["label_id"]]
                paired["time_alignment"] = alignment
                validate_paired_alignment(
                    paired, expected_coordinate_frame=args.expected_coordinate_frame
                )
                data = (json.dumps(paired, allow_nan=False) + "\n").encode()
                out.write(data)
                paired_hash.update(data)
                totals["paired_windows"] += 1
                totals[
                    "single_person_windows"
                    if paired["label"]["person_count"] == 1
                    else "negative_or_multiple_person_windows"
                ] += 1
            out.flush()
            os.fsync(out.fileno())
        report = {
            "schema": "ruview.csi.pair_session_report.v1",
            "completed": True,
            "capture_evidence": evidence,
            "reference_export": reference_receipt,
            "time_alignment": alignment,
            "counts": dict(totals),
            "window_stats": dict(builder.stats),
            "paired_sha256": paired_hash.hexdigest(),
            "recognition_validated": False,
            "publish_to_ha": False,
        }
        private_json(args.report_output, report)
    print(
        json.dumps(
            {
                "completed": True,
                "counts": dict(totals),
                "window_stats": dict(builder.stats),
                "recognition_validated": False,
            }
        )
    )
