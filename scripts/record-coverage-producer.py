#!/usr/bin/env python3
"""Record bounded private RuView snapshots under an existing local HA session."""

import argparse
import json
import os
from pathlib import Path

from coverage_producer import (
    EvidenceError,
    ReadOnlyHTTP,
    inventory_nodes,
    node_scope,
    record,
)
from module_manifest import add_module_manifest_arguments, load_module_manifest
from site_context import load_site_context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer-metadata", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--duration", required=True, type=int)
    parser.add_argument("--expected-image", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--site-context", required=True, type=Path)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument(
        "--nodes",
        nargs="+",
        type=int,
        default=[1, 2, 3],
        help="Explicit verified receiver scope; default: 1 2 3",
    )
    parser.add_argument("--package-directory", required=True, type=Path)
    add_module_manifest_arguments(parser)
    args = parser.parse_args()
    if not 5 <= args.duration <= 3600:
        parser.error("Duration must be 5..3600 seconds")
    root = Path(__file__).resolve().parents[1]
    try:
        context = load_site_context(args.site_context, args.site_context_sha256)
        load_module_manifest(args.module_manifest, args.module_manifest_sha256)
        inventory = inventory_nodes(context)
        selected = node_scope(args.nodes, inventory)
        token = os.environ.get("RUVIEW_API_TOKEN")
        if not token:
            parser.error("Set RUVIEW_API_TOKEN from the private credential source")
        http = ReadOnlyHTTP(args.url, token, {n: inventory[n] for n in selected})
        summary = record(
            root,
            args.consumer_metadata,
            args.output_directory,
            args.duration,
            args.expected_image,
            http,
            node_ids=selected,
            site_context=args.site_context,
            site_context_sha256=args.site_context_sha256,
            module_manifest=args.module_manifest,
            module_manifest_sha256=args.module_manifest_sha256,
            package_directory=args.package_directory,
        )
    except (ValueError, OSError) as error:
        # Never echo HTTP payloads, exception URLs or credentials.
        reason = (
            str(error) if isinstance(error, EvidenceError) else type(error).__name__
        )
        parser.exit(2, "Producer capture rejected: " + reason + "\n")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "session_id",
                    "capture_status",
                    "sample_count",
                    "validation_decision",
                    "coverage_validated",
                    "partial_fingerprint_sha256",
                )
            }
        )
    )
    raise SystemExit(0 if summary["capture_status"] == "complete" else 1)


if __name__ == "__main__":
    main()
