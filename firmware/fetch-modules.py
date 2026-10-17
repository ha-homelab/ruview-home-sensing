#!/usr/bin/env python3
"""Fetch pinned RuView WASM module sources and the locked home build inputs."""

import argparse
import hashlib
import json
import shutil
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "modules"
V2_PATCH = ROOT / "patches/0001-bounded-gesture-dtw.patch"
V2_PATCH_SHA = "4b117bbecfa360d77cbc71d0e612c0f9944fd37d0128ab001546031be055fd07"
V3_PATCH = ROOT / "patches/0002-incremental-gesture-dtw.patch"
V3_PATCH_SHA = "951b85e9dfcf68b604fa53c51df0e5a9baba7a41dc1fe3e7b4a62dfee7b98964"

V4_PATCH = ROOT / "patches/0003-two-row-gesture-dtw.patch"
V4_PATCH_SHA = "4ae3597972e2dc886c882ee41d14246debbe3e0609f413c974ae4c349f98b338"

V5_PATCH = ROOT / "patches/0004-one-row-gesture-dtw.patch"
V5_PATCH_SHA = "8a5ee290a77ee2205216f2325f947042b014fd61c7747e1b9b3eaf219bc934d0"


def apply_profile(output, lock, profile):
    """Opt-in source profiles preserve upstream and every earlier artifact."""
    if profile == "upstream":
        return
    if profile not in (
        "home-signal-v2",
        "home-signal-v3",
        "home-signal-v4",
        "home-signal-v5",
    ):
        raise ValueError("Unknown module source profile")
    patches = [(V2_PATCH, V2_PATCH_SHA)]
    if profile in ("home-signal-v3", "home-signal-v4", "home-signal-v5"):
        patches.append((V3_PATCH, V3_PATCH_SHA))
    if profile in ("home-signal-v4", "home-signal-v5"):
        patches.append((V4_PATCH, V4_PATCH_SHA))
    if profile == "home-signal-v5":
        patches.append((V5_PATCH, V5_PATCH_SHA))
    # Verify the complete pinned checkout before any local source patch runs.
    # Running the fetcher again restores upstream bytes first, then reapplies.
    for item in lock["files"]:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe source path")
        if (
            hashlib.sha256((output / relative).read_bytes()).hexdigest()
            != item["sha256"]
        ):
            raise ValueError(f"Unverified source before patch: {relative}")
    # Verify all patch inputs before mutating the checkout, including the v2
    # prerequisite when v3 is selected. Never silently repatch a v2 checkout.
    for patch, expected_sha in patches:
        if hashlib.sha256(patch.read_bytes()).hexdigest() != expected_sha:
            raise ValueError("Module source patch hash mismatch")
    for patch, _ in patches:
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=output, check=True)
        subprocess.run(["git", "apply", str(patch)], cwd=output, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", type=Path, help="Module source directory on the builder"
    )
    parser.add_argument(
        "--profile",
        choices=(
            "upstream",
            "home-signal-v2",
            "home-signal-v3",
            "home-signal-v4",
            "home-signal-v5",
        ),
        default="upstream",
        help="Opt in to v2 rolling DTW, v3 four-row, v4 two-row or v5 one-row incremental DTW",
    )
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="Fetch pristine upstream sources without locked home build overlays",
    )
    args = parser.parse_args()
    if args.source_only and args.profile != "upstream":
        parser.error("--source-only requires --profile upstream")
    lock = json.loads((ROOT / "upstream-files.json").read_text())
    base = f"https://raw.githubusercontent.com/ruvnet/RuView/{lock['commit']}/{lock['base']}"

    def fetch(item):
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe source path")
        dest = args.output / relative
        if (
            dest.exists()
            and hashlib.sha256(dest.read_bytes()).hexdigest() == item["sha256"]
        ):
            return
        url = (
            f"https://raw.githubusercontent.com/ruvnet/RuView/{lock['commit']}/"
            + item["repository_path"]
            if "repository_path" in item
            else base + item["path"]
        )
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"Hash mismatch: {relative}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(fetch, [*lock["files"], *lock["licenses"]]))
    apply_profile(args.output, lock, args.profile)
    if not args.source_only:
        shutil.copy(ROOT / "Cargo.lock", args.output / "Cargo.lock")
        shutil.copy(ROOT / "rust-toolchain.toml", args.output / "rust-toolchain.toml")
        shutil.copy(ROOT / "wasm-target.toml", args.output / ".cargo/config.toml")
    print(f"Verified {len(lock['files'])} WASM source files at {lock['commit']}")
    if args.profile != "upstream":
        hashes = [V2_PATCH_SHA]
        if args.profile in ("home-signal-v3", "home-signal-v4", "home-signal-v5"):
            hashes.append(V3_PATCH_SHA)
        if args.profile in ("home-signal-v4", "home-signal-v5"):
            hashes.append(V4_PATCH_SHA)
        if args.profile == "home-signal-v5":
            hashes.append(V5_PATCH_SHA)
        print(
            f"Applied {args.profile} source patches {', '.join(hashes)}; "
            "hardware budget unqualified"
        )


if __name__ == "__main__":
    main()
