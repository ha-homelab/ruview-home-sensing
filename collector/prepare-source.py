#!/usr/bin/env python3
"""Fetch pinned public collector sources and apply the reviewed local fixes."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from ring_policy import prepare_ring

ROOT = Path(__file__).resolve().parent
MAIN = Path("v2/crates/wifi-densepose-sensing-server/src/main.rs")


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def verify_sha(path, expected):
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"Pinned source checksum mismatch: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source", type=Path, help="Dedicated public build source directory"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Verify/apply an already fetched checkout",
    )
    parser.add_argument(
        "--ring-archive",
        type=Path,
        help="Previously downloaded SHA-256-pinned ring crate; required with --offline",
    )
    args = parser.parse_args()
    if args.offline and args.ring_archive is None:
        parser.error("--offline also requires --ring-archive")
    source = args.source.resolve()
    lock = json.loads((ROOT / "source-lock.json").read_text())
    if not (source / ".git").is_dir():
        if args.offline or source.exists():
            raise ValueError("Expected a new directory or the exact Git checkout")
        source.mkdir(parents=True)
        git(source, "init")
        git(source, "remote", "add", "origin", lock["repository"])
        git(source, "fetch", "--depth=1", "origin", lock["revision"])
        git(source, "checkout", "--detach", "FETCH_HEAD")
    if git(source, "rev-parse", "HEAD") != lock["revision"]:
        raise ValueError(
            "Unexpected source revision; refusing to reset an existing checkout"
        )
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Source checkout is dirty or already patched")
    if not args.offline:
        git(
            source,
            "submodule",
            "update",
            "--init",
            "--recursive",
            "--depth=1",
            "--jobs=2",
            "--",
            *lock["required_submodules"],
        )
    for path, revision in lock["required_submodules"].items():
        if git(source / path, "rev-parse", "HEAD") != revision:
            raise ValueError(f"Unexpected submodule revision: {path}")
        if git(source / path, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError(f"Dirty submodule: {path}")
    verify_sha(source / MAIN, lock["main_sha256"])
    verify_sha(source / "v2/Cargo.lock", lock["cargo_lock_sha256"])
    for path, expected in lock["security_source_sha256"].items():
        verify_sha(source / path, expected)
    prepare_ring(source, args.ring_archive)
    for name in (
        "0001-expire-csi-grid.patch",
        "0002-raw-csi-mirror.patch",
        "0003-security-boundaries.patch",
    ):
        patch = ROOT / "patches" / name
        git(source, "apply", "--check", str(patch))
        git(source, "apply", str(patch))
    for name in ("grid_gate.rs", "raw_csi_mirror.rs", "security_boundaries.rs"):
        shutil.copyfile(ROOT / "src" / name, source / MAIN.parent / name)
    print(
        f"Pinned {lock['revision']}, verified lock/submodules, applied reviewed collector patches"
    )


if __name__ == "__main__":
    main()
