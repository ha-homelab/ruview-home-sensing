"""An explicit, private, bounded Wisp transport pilot."""

import argparse
import json
import sys

from .capture import capture
from .config import load_config
from .replay import replay


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-config", "capture"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True)
        command.add_argument("--config-sha256", required=True)
        if name == "capture":
            command.add_argument("--output", required=True)
            command.add_argument("--seconds", required=True, type=int)
    command = commands.add_parser("replay")
    command.add_argument("--input", required=True)
    command.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "replay":
            report = replay(args.input, args.output)
            print(
                json.dumps(
                    {
                        "verified": True,
                        "records": report["result"]["manifest"]["records"],
                    }
                )
            )
            return 0
        config = load_config(args.config, args.config_sha256)
        if args.command == "validate-config":
            print(
                json.dumps(
                    {
                        "valid": True,
                        "receivers": len(config.receivers),
                        "network_io": False,
                    }
                )
            )
            return 0
        summary = capture(config, args.output, args.seconds)
        print(
            json.dumps(
                {
                    "completion": summary["manifest"]["completion"],
                    "records": summary["manifest"]["records"],
                    "complete": summary["manifest"]["complete"],
                }
            )
        )
        return 0 if summary["manifest"]["complete"] else 2
    except (ValueError, OSError, KeyError, RecursionError, OverflowError) as error:
        print(
            f"Pilot failed ({type(error).__name__}); verify private inputs and output permissions.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
