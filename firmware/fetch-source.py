#!/usr/bin/env python3
"""Fetch the exact public RuView firmware sources, verifying pinned SHA-256s."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def verification_header(path=None, expected_sha256=None):
    """No baked-in trust by default; an explicit independently pinned key opts in."""
    if (path is None) != (expected_sha256 is None):
        raise ValueError(
            "Public key path and independently approved SHA256 required together"
        )
    if path is None:
        return b"#pragma once\n#define RUVIEW_WASM_PUBLIC_KEY_CONFIGURED 0\n"
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Invalid public key approval digest")
    path = Path(path)
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Public key symlink refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != 32:
            raise ValueError("Public key must be exactly 32 raw Ed25519 bytes")
        data = stream.read(33)
    if len(data) != 32 or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Public key approval mismatch")
    if data == bytes(32):
        raise ValueError("All-zero public key refused")
    values = ", ".join(f"0x{value:02x}" for value in data)
    return (
        "#pragma once\n#include <stdint.h>\n"
        "#define RUVIEW_WASM_PUBLIC_KEY_CONFIGURED 1\n"
        f"static const uint8_t HOME_WASM_PUBLIC_KEY[32] = {{{values}}};\n"
    ).encode()


def copy_build_inputs(
    output,
    fleet_plan=None,
    fleet_overlay=None,
    firmware_version=None,
    preferred_ap_overlay=None,
    preferred_ap_overlay_sha256=None,
    wasm_public_key=None,
    wasm_public_key_sha256=None,
):
    """Authenticate selected inputs first; never copy the legacy private overlay."""
    header = verification_header(wasm_public_key, wasm_public_key_sha256)
    supplied = (
        fleet_plan is not None,
        fleet_overlay is not None,
        firmware_version is not None,
    )
    if any(supplied) and not all(supplied):
        raise ValueError(
            "Fleet plan, overlay and explicit firmware version are required together"
        )
    preferred = (
        preferred_ap_overlay is not None,
        preferred_ap_overlay_sha256 is not None,
    )
    if any(preferred) and (not all(preferred) or any(supplied)):
        raise ValueError(
            "Select either a complete preferred-AP input/pin or fleet inputs"
        )
    profile_path = ROOT / "fleet/build_profile.py"
    profile = None
    spec = importlib.util.spec_from_file_location("fleet_build_profile", profile_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    if all(preferred):
        if preferred_ap_overlay.resolve().is_relative_to(output.resolve()):
            raise ValueError(
                "Keep the private preferred-AP input outside the build context"
            )
        helper.read_preferred_overlay(preferred_ap_overlay, preferred_ap_overlay_sha256)
    if (output / "sdkconfig.home-node2-preferred-ap").exists():
        raise ValueError("Use a fresh context without the historical private overlay")
    if all(supplied):
        overlay = fleet_overlay.read_bytes()
        profile = helper.prepare(fleet_plan.read_bytes(), overlay, firmware_version)
    output.mkdir(parents=True, exist_ok=True)
    public = output / "fleet-build"
    public.mkdir(exist_ok=True)
    shutil.copy(profile_path, public / "build_profile.py")
    if profile is not None:
        helper.export(public, profile, overlay)
    for name in [
        "Dockerfile",
        "sdkconfig.home-s3-n16r8",
    ]:
        shutil.copy(ROOT / name, output / name)
    key_header = output / "home_wasm_pubkey.h"
    if key_header.exists() and key_header.read_bytes() != header:
        raise ValueError("Refusing to replace a different verification key")
    key_header.write_bytes(header)
    for name in ["patches", "vendor"]:
        shutil.copytree(ROOT / name, output / name, dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", type=Path, help="Build context directory outside the repository"
    )
    parser.add_argument("--fleet-plan", type=Path)
    parser.add_argument("--fleet-overlay", type=Path)
    parser.add_argument("--firmware-version")
    parser.add_argument("--preferred-ap-overlay", type=Path)
    parser.add_argument("--preferred-ap-overlay-sha256")
    parser.add_argument("--wasm-public-key", type=Path)
    parser.add_argument("--wasm-public-key-sha256")
    args = parser.parse_args()
    copy_build_inputs(
        args.output,
        args.fleet_plan,
        args.fleet_overlay,
        args.firmware_version,
        args.preferred_ap_overlay,
        args.preferred_ap_overlay_sha256,
        args.wasm_public_key,
        args.wasm_public_key_sha256,
    )
    lock = json.loads((ROOT / "upstream-files.json").read_text())
    base = f"https://raw.githubusercontent.com/ruvnet/RuView/{lock['commit']}/firmware/esp32-csi-node/"
    args.output.mkdir(parents=True, exist_ok=True)

    def fetch(item):
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe source path")
        dest = args.output / "source" / relative
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
    print(f"Verified {len(lock['files'])} source files at {lock['commit']}")


if __name__ == "__main__":
    main()
