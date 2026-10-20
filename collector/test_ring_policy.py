#!/usr/bin/env python3
"""Run the RSA policy regression against every actually compiled native ring."""

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deps", type=Path, help="Native Cargo target/debug/deps")
    parser.add_argument(
        "--original",
        action="store_true",
        help="Negative calibration against the unmodified upstream library only",
    )
    args = parser.parse_args()
    libraries = sorted(args.deps.resolve().glob("libring-*.rlib"))
    if not 1 <= len(libraries) <= 8:
        raise ValueError("Expected compiled ring libraries, not a skipped regression")
    env = dict(os.environ, RUVIEW_RING_FIXTURES=str(ROOT / "ring-policy/fixtures"))
    with tempfile.TemporaryDirectory() as temp:
        for index, library in enumerate(libraries):
            binary = Path(temp) / f"ring-policy-{index}"
            subprocess.run(
                [
                    "rustc",
                    "--edition=2021",
                    "--deny=warnings",
                    str(ROOT / "ring-policy/keyfloor.rs"),
                    "-L",
                    f"dependency={args.deps.resolve()}",
                    "--extern",
                    f"ring={library}",
                    "-o",
                    str(binary),
                ],
                env=env,
                check=True,
            )
            subprocess.run(
                [str(binary), *(["--original"] if args.original else [])], check=True
            )
    print(f"Actual ring policy checked: {len(libraries)} compiled libraries")


if __name__ == "__main__":
    main()
