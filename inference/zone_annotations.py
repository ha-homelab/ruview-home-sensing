"""Import independently reviewed whole-interval zone observations; no live calls."""

import argparse
import json
from collections import Counter
from pathlib import Path

from . import reference_session as reference
from . import zones
from .capture import file_bytes, strict_json
from .evidence import validate_session_evidence
from .feature_contracts import selected_contract
from .model import features, model_identity
from .pipeline import PAIR_SCHEMA_V2, digest, integer, pair_window
from .reference_alignment import validate_alignment, validate_paired_alignment

SCHEMA = "ruview.zone_annotations.v1"
MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 10000
PAIR_FIELDS = {
    "schema",
    "window",
    "label",
    "alignment",
    "validation",
    "capture_evidence",
    "original_label",
    "time_alignment",
}
INTERVAL_FIELDS = {
    "reference_id",
    "trial_id",
    "original_label_sha256",
    "start_ns",
    "end_ns",
    "room_id",
    "person_count",
    "source",
    "zone_id",
    "condition",
    "provenance",
    "observed_throughout_interval",
    "truth_uncertainty",
}


def load_inputs(
    reference_directory,
    reference_export,
    paired,
    pair_report,
    definition,
    geometry,
    *,
    expected_coordinate_frame=None,
):
    """Reverify reference originals and paired metadata, not original raw CSI bytes."""
    paths = {
        "paired": Path(paired),
        "pair_report": Path(pair_report),
        "definition": Path(definition),
        "geometry": Path(geometry),
    }
    raw = {
        key: file_bytes(path, reference.MAX_FILE if key == "geometry" else MAX_BYTES)
        for key, path in paths.items()
    }
    scope = strict_json(raw["definition"])
    zones.definition(scope)
    reference.identifier(scope["room_id"], "safe room ID required")
    directory, exported = Path(reference_directory), Path(reference_export)
    labels, receipt = reference.verify_export(
        directory, exported, expected_coordinate_frame=expected_coordinate_frame
    )
    zones.require(len(receipt["node_ids"]) == 1, "export exactly one receiver")
    node = integer(receipt["node_ids"][0], "selected receiver", 1, 16)
    shape = strict_json(raw["geometry"])
    zones.require(
        isinstance(shape, dict)
        and shape.get("schema") == "home_floorplan.zone_geometry.v1",
        "original zone geometry schema required",
    )
    zones.require(
        reference.raw_hash(raw["geometry"]) == scope["zone_geometry_sha256"],
        "original geometry bytes differ from definition",
    )
    regions = shape.get("zones")
    zones.require(
        isinstance(regions, list)
        and len(regions) == 2
        and all(isinstance(region, dict) for region in regions),
        "two original geometry regions required",
    )
    zones.require(
        type(shape.get("node_id")) is int
        and shape["node_id"] == node
        and shape.get("room_id") == scope["room_id"]
        and [region.get("zone_id") for region in regions] == scope["zone_ids"]
        and shape.get("floorplan_sha256") == scope["floorplan_sha256"],
        "geometry receiver/room/zones/floorplan identity mismatch",
    )
    originals = {}
    for label in labels:
        for key in ("trial_id", "label_id", "room_id"):
            reference.identifier(label[key], "safe reference " + key + " required")
        key = digest(label)
        zones.require(key not in originals, "duplicate original reference label")
        originals[key] = label
    report = strict_json(raw["pair_report"])
    zones.require(
        report.get("schema") == "ruview.csi.pair_session_report.v1"
        and report.get("completed") is True
        and report.get("recognition_validated") is False
        and report.get("publish_to_ha") is False,
        "completed research pair-session report required",
    )
    zones.require(report["reference_export"] == receipt, "reference export mismatch")
    zones.require(
        report["paired_sha256"] == reference.raw_hash(raw["paired"]),
        "paired bytes differ from pair-session report",
    )
    evidence = validate_session_evidence(report["capture_evidence"])
    zones.require(evidence["expected_node_ids"] == [node], "paired node scope mismatch")
    validate_alignment(report["time_alignment"], evidence)
    lines = raw["paired"].splitlines()
    zones.require(
        0 < len(lines) <= MAX_RECORDS, "bounded nonempty paired records required"
    )
    records = []
    windows, identities, counts = set(), set(), Counter()
    for line in lines:
        zones.require(len(line) <= reference.MAX_FILE, "paired line exceeds bound")
        row = strict_json(line)
        zones.keys(row, PAIR_FIELDS)
        zones.require(row["schema"] == PAIR_SCHEMA_V2, "original v2 pairing required")
        label_key = digest(row["original_label"])
        zones.require(
            label_key in originals, "paired original absent from verified export"
        )
        zones.require(
            row["capture_evidence"] == evidence
            and row["time_alignment"] == report["time_alignment"],
            "paired evidence or alignment differs from report",
        )
        window = row["window"]
        zones.require(
            type(window["node_id"]) is int
            and window["node_id"] == node
            and type(window["ppdu_type"]) is int
            and window["ppdu_type"] == 0
            and type(window["flags"]) is int
            and window["flags"] in (0, 16),
            "unselected receiver or ineligible raw header",
        )
        features(window, selected_contract(window))
        zones.require(
            window["commissioning_profile"]["floorplan_sha256"]
            == scope["floorplan_sha256"],
            "zone floorplan/profile mismatch",
        )
        validate_session_evidence(evidence, window)
        validate_paired_alignment(
            row, expected_coordinate_frame=expected_coordinate_frame
        )
        expected = pair_window(
            window,
            [row["label"]],
            row["alignment"]["label_to_csi_clock_offset_ns"],
            integer(
                row["alignment"]["max_uncertainty_ns"], "label uncertainty policy", 1
            ),
            expected_coordinate_frame=expected_coordinate_frame,
        )
        zones.require(
            expected is not None and expected == {key: row[key] for key in expected},
            "original pairing or complete-window coverage changed",
        )
        zones.require(window["window_id"] not in windows, "duplicate paired window")
        windows.add(window["window_id"])
        identities.add(digest(model_identity(window)))
        counts[label_key] += 1
        records.append(row)
    zones.require(len(identities) == 1, "mixed receiver/profile/window identity")
    expected_counts = {
        "paired_windows": len(records),
        "single_person_windows": sum(r["label"]["person_count"] == 1 for r in records),
        "negative_or_multiple_person_windows": sum(
            r["label"]["person_count"] != 1 for r in records
        ),
    }
    for key, value in expected_counts.items():
        zones.require(
            integer(report["counts"].get(key, 0), key) == value,
            "pair-session count mismatch",
        )
    paths.update(
        reference_receipt=exported / "receipt.json",
        reference_labels=exported / "labels.jsonl",
    )
    raw.update(
        {
            key: file_bytes(paths[key], MAX_BYTES)
            for key in ("reference_receipt", "reference_labels")
        }
    )
    zones.require(
        strict_json(raw["reference_receipt"]) == receipt, "export changed during read"
    )
    zones.require(
        reference.raw_hash(raw["reference_labels"]) == receipt["labels_sha256"],
        "export labels changed during read",
    )
    return {
        "expected_coordinate_frame": expected_coordinate_frame,
        "paths": paths,
        "raw": raw,
        "scope": scope,
        "node": node,
        "labels": originals,
        "records": records,
        "counts": counts,
        "reference_directory": directory,
        "reference_export": exported,
        "receipt": receipt,
        "evidence": evidence,
    }


def template(inputs):
    """Copy identity only; all observation and review decisions remain unfilled."""
    return {
        "schema": SCHEMA,
        "node_id": inputs["node"],
        "definition_sha256": inputs["scope"]["definition_sha256"],
        "input_sha256": {
            key: reference.raw_hash(raw) for key, raw in inputs["raw"].items()
        },
        "review": {
            "reviewed": False,
            "reviewer": None,
            "evidence": None,
            "observations_independent_of_csi": False,
        },
        "intervals": [
            {
                "reference_id": None,
                "trial_id": label["trial_id"],
                "original_label_sha256": key,
                "start_ns": label["start_ns"],
                "end_ns": label["end_ns"],
                "room_id": None,
                "person_count": None,
                "source": None,
                "zone_id": None,
                "condition": None,
                "provenance": None,
                "observed_throughout_interval": False,
                "truth_uncertainty": None,
            }
            for key, label in inputs["labels"].items()
        ],
    }


def convert(inputs, annotations, annotation_sha256):
    expected = template(inputs)
    zones.keys(annotations, expected)
    for key in ("schema", "node_id", "definition_sha256", "input_sha256"):
        zones.require(
            annotations[key] == expected[key], "annotation input binding mismatch"
        )
    integer(annotations["node_id"], "annotation receiver", 1, 16)
    review = annotations["review"]
    zones.keys(review, expected["review"])
    zones.require(
        review["reviewed"] is True
        and review["observations_independent_of_csi"] is True,
        "explicit independent zone review required",
    )
    for key in ("reviewer", "evidence"):
        reference.text(review[key], "zone review " + key)
    intervals = annotations["intervals"]
    zones.require(
        isinstance(intervals, list) and len(intervals) == len(inputs["labels"]),
        "annotate every complete exported interval exactly once",
    )
    refs, names, spans = {}, set(), []
    for interval in intervals:
        zones.keys(interval, INTERVAL_FIELDS)
        reference.identifier(
            interval["reference_id"], "safe zone reference ID required"
        )
        zones.require(
            interval["reference_id"] not in names, "duplicate zone reference ID"
        )
        names.add(interval["reference_id"])
        key = interval["original_label_sha256"]
        zones.require(
            isinstance(key, str) and key in inputs["labels"] and key not in refs,
            "unknown or duplicate original interval",
        )
        label = inputs["labels"][key]
        for field in (
            "trial_id",
            "start_ns",
            "end_ns",
            "room_id",
            "person_count",
            "source",
        ):
            zones.require(
                interval[field] == label[field],
                "zone observation differs from original " + field,
            )
        for field in ("start_ns", "end_ns", "person_count"):
            integer(interval[field], field)
        zones.require(
            interval["observed_throughout_interval"] is True
            and interval["truth_uncertainty"] == "",
            "whole-interval observation without uncertain truth required",
        )
        zones.require(
            label["room_id"] == inputs["scope"]["room_id"],
            "observation outside target room",
        )
        reference.text(interval["provenance"], "zone observation provenance")
        condition, count = interval["condition"], label["person_count"]
        if condition in ("stationary", "outside_zones", "transition"):
            zones.require(count == 1, "single-person negative condition count mismatch")
        result = {
            "schema": "ruview.zone_reference.v1",
            "reference_id": interval["reference_id"],
            "original_label_sha256": key,
            "definition_sha256": inputs["scope"]["definition_sha256"],
            "zone_id": interval["zone_id"],
            "condition": condition,
            "source": interval["source"],
            "reviewed": True,
            "provenance": interval["provenance"]
            + "; zone-annotations-sha256:"
            + annotation_sha256
            + "; reviewer:"
            + review["reviewer"]
            + "; review:"
            + review["evidence"],
        }
        zones.reference(
            result, {"original_label": label, "label": label}, inputs["scope"]
        )
        for old in spans:
            zones.require(
                interval["end_ns"] <= old["start_ns"]
                or old["end_ns"] <= interval["start_ns"],
                "overlapping zone observation intervals",
            )
        spans.append(interval)
        refs[key] = result
    rows = [
        {"paired": paired, "zone_reference": refs[digest(paired["original_label"])]}
        for paired in inputs["records"]
    ]
    return rows


def unchanged(inputs):
    _, receipt = reference.verify_export(
        inputs["reference_directory"],
        inputs["reference_export"],
        expected_coordinate_frame=inputs["expected_coordinate_frame"],
    )
    zones.require(receipt == inputs["receipt"], "reference changed during import")
    zones.require(
        all(
            file_bytes(inputs["paths"][key], MAX_BYTES) == raw
            for key, raw in inputs["raw"].items()
        ),
        "input changed during import",
    )


def import_annotations(inputs, annotations_path, output):
    raw = file_bytes(annotations_path, MAX_BYTES)
    annotation_sha = reference.raw_hash(raw)
    annotations = strict_json(raw)
    rows = convert(inputs, annotations, annotation_sha)
    records_raw = (json.dumps(rows, sort_keys=True, allow_nan=False) + "\n").encode()
    zones.require(len(records_raw) <= MAX_BYTES, "zone records exceed bound")
    receipt = {
        "schema": "ruview.zone_annotation_import.v1",
        "completed": True,
        "node_id": inputs["node"],
        "capture_id": inputs["evidence"]["capture_id"],
        "definition_sha256": inputs["scope"]["definition_sha256"],
        "input_sha256": annotations["input_sha256"],
        "annotations_sha256": annotation_sha,
        "review": annotations["review"],
        "records_sha256": reference.raw_hash(records_raw),
        "records": len(rows),
        "intervals": len(inputs["labels"]),
        "windows_per_original_label": {
            key: inputs["counts"][key] for key in inputs["labels"]
        },
        "reference_chain_reverified": True,
        "paired_metadata_reverified": True,
        "geometry_identity_verified": True,
        "physical_geometry_verified": False,
        "raw_capture_reverified": False,
        "observation_truth_authenticated": False,
        "recognition_validated": False,
        "publish_to_ha": False,
    }
    unchanged(inputs)
    zones.require(
        file_bytes(annotations_path, MAX_BYTES) == raw,
        "annotations changed during import",
    )
    output = Path(output)
    output.mkdir(mode=0o700)
    reference.write_bytes(output / "records.json", records_raw, MAX_BYTES)
    reference.write(output / "receipt.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("template", "import"))
    for flag in (
        "reference-directory",
        "reference-export",
        "paired",
        "pair-report",
        "definition",
        "geometry",
        "output",
    ):
        parser.add_argument("--" + flag, required=True, type=Path)
    parser.add_argument("--annotations", type=Path)
    parser.add_argument("--expected-coordinate-frame")
    args = parser.parse_args()
    if (args.command == "import") != (args.annotations is not None):
        parser.error("--annotations is required only for import")
    inputs = load_inputs(
        args.reference_directory,
        args.reference_export,
        args.paired,
        args.pair_report,
        args.definition,
        args.geometry,
        expected_coordinate_frame=args.expected_coordinate_frame,
    )
    if args.command == "template":
        unchanged(inputs)
        reference.write(args.output, template(inputs))
        print(json.dumps({"template_created": True, "reviewed": False}))
    else:
        receipt = import_annotations(inputs, args.annotations, args.output)
        print(
            json.dumps(
                {
                    key: receipt[key]
                    for key in (
                        "completed",
                        "records",
                        "intervals",
                        "recognition_validated",
                    )
                }
            )
        )


if __name__ == "__main__":
    main()
