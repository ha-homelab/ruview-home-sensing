"""Offline configuration inspection. Never opens a configured UART endpoint."""

import argparse
import hashlib
import json
import os
import stat
import sys

from .config import inspect_document

MAX_CONFIG_BYTES = 65536


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("Non-finite JSON number")


def read_configuration(path):
    before = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_CONFIG_BYTES:
        raise ValueError("Configuration must be a regular file of at most 65536 bytes")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise ValueError("Configuration file changed during open")
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Configuration exceeds 65536 bytes")
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
    ), hashlib.sha256(raw).hexdigest()


def render_text(report):
    lines = [
        f"LD2450 configuration: {report['status']}",
        "Scope: declarations only; no hardware, survey evidence or accuracy was verified.",
    ]
    for error in report["errors"]:
        lines.append(f"ERROR {error['path']}: {error['message']}")
    for i, profile in enumerate(report["profiles"]):
        lines.append(
            f"Radar {i + 1} ({profile['sensor_id'] or 'unassigned'}): {profile['status']}"
        )
        for kind in ["errors", "pending"]:
            for issue in profile[kind]:
                lines.append(f"  {kind.upper()} {issue['path']}: {issue['message']}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate-config", help="Inspect a regular JSON file without hardware access"
    )
    validate.add_argument("path")
    validate.add_argument("--format", choices=("text", "json"), default="text")
    validate.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit 3 for incomplete declarations; completeness is not hardware readiness",
    )
    validate.add_argument("--expected-coordinate-frame", required=True)
    args = parser.parse_args(argv)
    try:
        value, raw_sha = read_configuration(args.path)
        report = inspect_document(
            value, expected_coordinate_frame=args.expected_coordinate_frame
        )
        report["source_sha256"] = raw_sha
    except (OSError, ValueError, RecursionError, OverflowError):
        # No raw file content or OS error context (which may contain sensitive paths).
        report = inspect_document(
            None, expected_coordinate_frame=args.expected_coordinate_frame
        )
        report["errors"] = [
            {
                "path": "$",
                "code": "unreadable_or_invalid_json",
                "message": "Use a readable regular UTF-8 JSON file <=65536 bytes, without duplicate keys or non-finite numbers.",
            }
        ]
    print(
        json.dumps(report, indent=2, allow_nan=False)
        if args.format == "json"
        else render_text(report)
    )
    if not report["structurally_valid"]:
        return 2
    if args.require_complete and not report["declared_config_complete"]:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
