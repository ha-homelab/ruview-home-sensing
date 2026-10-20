#!/usr/bin/env python3
"""Prepare a public, pinned native worker build outside this checkout."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Support direct source-checkout execution before runtime dependencies exist.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.transport_security import open_source  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORKER_PATCHES = {
    # This next source revision does not alter the frozen r4/r5 inputs.
    "0003-bounded-tailgating-peaks.patch": "800afad4da392318a231bcac067d878b2f24d33a9502b893f68b883b4d21fb98",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply_worker_patches(upstream):
    for name, expected in WORKER_PATCHES.items():
        path = HERE / "patches" / name
        if sha(path.read_bytes()) != expected:
            raise ValueError("Unreviewed worker module patch")
        subprocess.run(["git", "apply", "--check", str(path)], cwd=upstream, check=True)
        subprocess.run(["git", "apply", str(path)], cwd=upstream, check=True)
    return list(WORKER_PATCHES.items())


def worker_inputs():
    """Fingerprint source/test inputs, never generated deployment evidence."""
    source_inputs = [
        HERE / name
        for name in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "algorithms.json",
            "prepare.py",
            "package-runtime.py",
            "Dockerfile.runtime",
            "Dockerfile.builder",
            "build.sh",
        )
    ]
    source_inputs += sorted((HERE / "src").glob("*.rs"))
    source_inputs += sorted((HERE / "tests").glob("*.py"))
    source_inputs += [HERE / "tests/fixtures/capture-v2.synthetic.json"]
    source_inputs += [HERE / "patches" / name for name in WORKER_PATCHES]
    return {
        str(p.relative_to(HERE)): sha(p.read_bytes())
        for p in source_inputs
        if p.is_file()
    }


def prepare(destination, source=None, offline=False):
    destination = destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        raise ValueError("Prepare outside the application checkout")
    lock_path = ROOT / "firmware/modules/upstream-files.json"
    lock = json.loads(lock_path.read_text())
    if lock["commit"] != "e04f269f1a76eb6ed4e8cd33e2ccfeda6fd391a3":
        raise ValueError("Unreviewed upstream revision")
    upstream = destination / "upstream"
    pristine = destination / "pristine"
    worker = destination / "worker"
    upstream.mkdir(parents=True, exist_ok=True)
    worker.mkdir(parents=True, exist_ok=True)

    def fetch(item):
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe pinned source path")
        target = upstream / relative
        candidates = [pristine / relative, target]
        if source:
            candidates.append(source / relative)
        for candidate in candidates:
            if candidate.is_file():
                data = candidate.read_bytes()
                if sha(data) == item["sha256"]:
                    break
        else:
            if offline:
                raise ValueError(f"Missing pristine source: {relative}")
            remote = item.get("repository_path", lock["base"] + str(relative))
            url = f"https://raw.githubusercontent.com/ruvnet/RuView/{lock['commit']}/{remote}"
            with open_source(url, timeout=30) as response:
                data = response.read()
            if sha(data) != item["sha256"]:
                raise ValueError(f"Upstream hash mismatch: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        cached = pristine / relative
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch, lock["files"] + lock.get("licenses", [])))
    patches = [
        (
            "0001-bounded-gesture-dtw.patch",
            "4b117bbecfa360d77cbc71d0e612c0f9944fd37d0128ab001546031be055fd07",
        ),
        (
            "0002-incremental-gesture-dtw.patch",
            "951b85e9dfcf68b604fa53c51df0e5a9baba7a41dc1fe3e7b4a62dfee7b98964",
        ),
    ]
    for name, expected in patches:
        path = ROOT / "firmware/modules/patches" / name
        if sha(path.read_bytes()) != expected:
            raise ValueError("Unreviewed module patch")
        subprocess.run(["git", "apply", "--check", str(path)], cwd=upstream, check=True)
        subprocess.run(["git", "apply", str(path)], cwd=upstream, check=True)
    patches += apply_worker_patches(upstream)
    for name in ("src", "tests", "patches"):
        if (HERE / name).exists():
            shutil.copytree(
                HERE / name,
                worker / name,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "algorithms.json",
        "prepare.py",
        "package-runtime.py",
        "Dockerfile.runtime",
        "Dockerfile.builder",
    ):
        if (HERE / name).exists():
            shutil.copyfile(HERE / name, worker / name)
    # Runtime reports/live fixtures are outputs, never source inputs. Including
    # them would make a post-build release report change the next binary hash.
    for name in ("LICENSE", "NOTICE"):
        shutil.copyfile(ROOT / name, worker / name)
    inputs = worker_inputs()
    source_hashes = {
        item["path"]: sha((upstream / item["path"]).read_bytes())
        for item in lock["files"] + lock.get("licenses", [])
    }
    provenance = {
        "upstream_revision": lock["commit"],
        "upstream_manifest_sha256": sha(lock_path.read_bytes()),
        "upstream_files_sha256": source_hashes,
        "patches": dict(patches),
        "worker_inputs_sha256": inputs,
        "raw_grid": {"antennas": 1, "subcarriers": 64},
        "recognition_validated": False,
    }
    serialized = json.dumps(provenance, sort_keys=True, separators=(",", ":"))
    (worker / "provenance.json").write_text(serialized + "\n")
    print(
        json.dumps(
            {
                "worker": str(worker),
                "provenance_sha256": sha((worker / "provenance.json").read_bytes()),
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    prepare(args.destination, args.source, args.offline)
