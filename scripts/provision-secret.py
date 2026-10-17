#!/usr/bin/env python3
"""Provision the runtime Secret without credentials entering Terraform state."""

import argparse
import base64
import json
import os
import secrets
import subprocess


def context_name(value):
    if (
        not value
        or len(value) > 256
        or value.startswith("-")
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise argparse.ArgumentTypeError(
            "context must be an explicit name without whitespace, controls or a leading dash"
        )
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=context_name)
    args = parser.parse_args(argv)
    names = ("RUVIEW_API_TOKEN", "MQTT_USERNAME", "MQTT_PASSWORD")
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise SystemExit("Missing environment variables: " + ", ".join(missing))
    prior = subprocess.run(
        [
            "kubectl",
            "--context",
            args.context,
            "-n",
            "ruview",
            "get",
            "secret",
            "ruview-secrets",
            "-o",
            "json",
            "--ignore-not-found",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    previous = (
        json.loads(prior.stdout or "{}").get("data", {}).get("WDP_RUFIELD_SIGNING_SEED")
    )
    seed = os.environ.get("WDP_RUFIELD_SIGNING_SEED") or (
        base64.b64decode(previous).decode() if previous else secrets.token_hex(32)
    )
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {"namespace": "ruview", "name": "ruview-secrets"},
        "stringData": {
            **{name: os.environ[name] for name in names},
            "WDP_RUFIELD_SIGNING_SEED": seed,
        },
    }
    subprocess.run(
        [
            "kubectl",
            "--context",
            args.context,
            "apply",
            "--server-side",
            "--field-manager=ruview-secrets",
            "-f",
            "-",
        ],
        input=json.dumps(secret),
        text=True,
        check=True,
    )


if __name__ == "__main__":
    main()
