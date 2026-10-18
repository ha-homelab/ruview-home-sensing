#!/usr/bin/env python3
"""Verify library imports and entrypoint metadata from a non-editable wheel."""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

PROBE = r"""
import importlib
import importlib.metadata
import pathlib
import sys
root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
for name in (
    "assumed_activity.service", "inference.reference_alignment",
    "inference.fall_detection", "radar.config", "wisp_pilot.protocol",
    "scripts.reference_clock",
):
    module = importlib.import_module(name)
    assert pathlib.Path(module.__file__).resolve().is_relative_to(root), name
dist = importlib.metadata.distribution("ruview-home-sensing")
assert pathlib.Path(dist.locate_file("inference/__init__.py")).resolve().is_relative_to(root)
assert {point.name for point in dist.entry_points} == {
    "ruview-inference", "ruview-radar", "ruview-wisp", "ruview-activity",
}
for point in dist.entry_points:
    assert callable(point.load()), point.name
print("Installed wheel libraries and four console entrypoints verified.")
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    if wheel.suffix != ".whl":
        raise ValueError("An explicit built wheel is required")
    with tempfile.TemporaryDirectory(prefix="ruview-wheel-") as temporary:
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--target",
                temporary,
                str(wheel),
            ],
            check=True,
        )
        subprocess.run(
            [sys.executable, "-I", "-c", PROBE, temporary], cwd=temporary, check=True
        )


if __name__ == "__main__":
    main()
