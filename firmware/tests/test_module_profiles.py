#!/usr/bin/env python3
"""Check immutable module source profiles offline against a pinned checkout.

This exercises real source/patch application and rejection before mutation.
The embedded Rust regressions and ESP32 timing trial remain separate checks.
"""

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned WASM sources")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location(
        "module_fetch", ROOT / "fetch-modules.py"
    )
    fetch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fetch)
    lock = json.loads((ROOT / "modules/upstream-files.json").read_text())
    expected = {entry["path"]: entry["sha256"] for entry in lock["files"]}
    for name, sha in expected.items():
        require(digest(args.source / name) == sha, f"Unpinned source: {name}")

    def hashes(output):
        return {name: digest(output / name) for name in expected}

    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)

        def checkout(name):
            output = work / name
            for relative in expected:
                destination = output / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(args.source / relative, destination)
            return output

        def reject_unchanged(output, profile, selected_lock=lock):
            before = hashes(output)
            try:
                fetch.apply_profile(output, selected_lock, profile)
            except ValueError:
                pass
            else:
                raise RuntimeError(f"Invalid input accepted for {profile}")
            require(hashes(output) == before, "Rejected input mutated source")

        upstream = checkout("upstream")
        fetch.apply_profile(upstream, lock, "upstream")
        require(hashes(upstream) == expected, "Upstream profile changed source")
        for source_only in (True, False):
            output = checkout(f"cli-upstream-{source_only}")
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "fetch-modules.py"),
                    str(output),
                    *(["--source-only"] if source_only else []),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            if source_only:
                require(hashes(output) == expected, "Source-only changed pinned bytes")
                require(
                    not (output / "rust-toolchain.toml").exists(),
                    "Source-only installed a build overlay",
                )
            else:
                for overlay, destination in (
                    ("Cargo.lock", "Cargo.lock"),
                    ("rust-toolchain.toml", "rust-toolchain.toml"),
                    ("wasm-target.toml", ".cargo/config.toml"),
                ):
                    require(
                        digest(output / destination)
                        == digest(ROOT / "modules" / overlay),
                        f"Default build overlay changed: {destination}",
                    )
        for profile in (
            "home-signal-v2",
            "home-signal-v3",
            "home-signal-v4",
            "home-signal-v5",
        ):
            output = work / f"rejected-source-only-{profile}"
            rejected = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "fetch-modules.py"),
                    str(output),
                    "--profile",
                    profile,
                    "--source-only",
                ],
                capture_output=True,
                text=True,
            )
            require(
                rejected.returncode == 2
                and "--source-only requires --profile upstream" in rejected.stderr,
                f"Source-only accepted {profile}",
            )
            require(not output.exists(), "Rejected source-only profile wrote output")
        profiles = {}
        for profile in (
            "home-signal-v2",
            "home-signal-v3",
            "home-signal-v4",
            "home-signal-v5",
        ):
            output = checkout(profile)
            fetch.apply_profile(output, lock, profile)
            profiles[profile] = hashes(output)
            changed = {
                name for name, sha in hashes(output).items() if sha != expected[name]
            }
            require(
                changed == {"src/gesture.rs", "src/lib.rs"}, "Unexpected patch scope"
            )
            reject_unchanged(output, profile)

        v2, v3 = profiles["home-signal-v2"], profiles["home-signal-v3"]
        require(
            v2["src/gesture.rs"]
            == "462cee47127e314964d229d9257c3932c5581342f7743dd32d22a82fb8dcc6dc",
            "Published v2 source changed",
        )
        require(
            v2["src/lib.rs"]
            == "7f11b93fc77c8cb28f5fb989fd403f101faf0c2b284a0b6f3f21adaeaa321ae5",
            "Published v2 pipeline changed",
        )
        require(
            {name for name in expected if v2[name] != v3[name]}
            == {"src/gesture.rs", "src/lib.rs"},
            "V3 changes more than gesture and its initialization/tests",
        )

        require(
            profiles["home-signal-v4"]["src/gesture.rs"]
            == "9f480647290264bc556479250185060d1210817d8f28bdb5bf7762c3a6958695",
            "V4 source differs from reviewed two-row candidate: src/gesture.rs",
        )
        require(
            profiles["home-signal-v4"]["src/lib.rs"]
            == "3bd93ac58bf8e1324c383abd8d5ab42f40ca5730a4c7cd224ff58ed4b3b108a5",
            "V4 source differs from reviewed two-row candidate: src/lib.rs",
        )

        require(
            profiles["home-signal-v5"]["src/gesture.rs"]
            == "ca8eea0744b223b6f36ad1efd4198cb5594202bd31a055238f9a7aaf8b26adf4",
            "V5 source differs from reviewed one-row candidate: src/gesture.rs",
        )
        require(
            profiles["home-signal-v5"]["src/lib.rs"]
            == "648ef206301c71917c2da0c31ee09abe1ec0e4dbedff3a7e8b2b0b13269e64ed",
            "V5 source differs from reviewed one-row candidate: src/lib.rs",
        )

        reject_unchanged(checkout("unknown"), "not-a-profile")
        bad_source = checkout("bad-source")
        with (bad_source / "src/gesture.rs").open("a") as stream:
            stream.write("\n// tampered\n")
        reject_unchanged(bad_source, "home-signal-v3")
        unsafe_lock = {"files": [{"path": "../outside", "sha256": "unused"}]}
        reject_unchanged(checkout("unsafe-path"), "home-signal-v3", unsafe_lock)

        for variable, profile in (
            ("V2_PATCH", "home-signal-v2"),
            ("V2_PATCH", "home-signal-v3"),
            ("V3_PATCH", "home-signal-v3"),
            ("V2_PATCH", "home-signal-v4"),
            ("V3_PATCH", "home-signal-v4"),
            ("V4_PATCH", "home-signal-v4"),
            ("V2_PATCH", "home-signal-v5"),
            ("V3_PATCH", "home-signal-v5"),
            ("V4_PATCH", "home-signal-v5"),
            ("V5_PATCH", "home-signal-v5"),
        ):
            original = getattr(fetch, variable)
            bad_patch = work / f"{variable}-{profile}.patch"
            bad_patch.write_bytes(original.read_bytes() + b"\n# tampered\n")
            setattr(fetch, variable, bad_patch)
            try:
                reject_unchanged(checkout(bad_patch.stem), profile)
            finally:
                setattr(fetch, variable, original)

    print(
        "PASS: upstream/v2/v3/v4/v5 scope, immutable v2 hashes, "
        "source-only/default CLI overlays, source-only profile rejection, "
        "reapplication, source/path/profile and all selected patch-tamper rejections"
    )


if __name__ == "__main__":
    main()
