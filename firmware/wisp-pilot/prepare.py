#!/usr/bin/env python3
"""Package pinned Wisp source and the local pilot recipe without network or flashing."""

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.site_context import write_private_output  # noqa: E402

COMMIT = "56813ac91a0fe696dae20e1fec468d33fc1e60ed"
ESPHOME = "2026.9.1"
MAX_ARCHIVE = 8 * 1024 * 1024


def git(source, *args):
    return subprocess.run(
        ["git", "-C", str(source), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    ).stdout


def require_source(source):
    if git(source, "rev-parse", "HEAD").decode().strip() != COMMIT:
        raise ValueError("Source HEAD must match the reviewed Wisp commit")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Wisp source must be clean, including untracked files")


def unpack_source(raw):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Wisp source archive exceeds the packaging bound")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name
            parts = name.split("/")
            if name.startswith("/") or any(p in {"", ".", ".."} for p in parts):
                raise ValueError("Unsafe Wisp archive path")
            if name != "LICENSE" and not (
                name in {"firmware", "firmware/components", "firmware/components/wisp"}
                or name.startswith("firmware/components/wisp/")
            ):
                raise ValueError("Unexpected Wisp source member")
            if member.isdir():
                continue
            if not member.isfile() or member.size > MAX_ARCHIVE:
                raise ValueError("Wisp source members must be bounded regular files")
            target = "source/" + name
            if target in files:
                raise ValueError("Duplicate Wisp source member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Unreadable Wisp source member")
            files[target] = stream.read()
    if "source/LICENSE" not in files or (
        "source/firmware/components/wisp/__init__.py" not in files
    ):
        raise ValueError("Wisp component or license missing")
    return files


def bundle(files, template):
    files = dict(files)
    files["node-esp32s3.yaml"] = template
    receipt = {
        "schema": "ruview.wisp-pilot-build-inputs.v1",
        "source_commit": COMMIT,
        "esphome_version": ESPHOME,
        "status": "prepared_only_not_compiled_or_hardware_qualified",
        "sha256": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())
        },
    }
    files["build-inputs.json"] = (
        json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    ).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o600
            member.mtime = 0
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def prepare(source, output):
    # Existing checkouts may hold private state; output belongs outside Git.
    inside_git = subprocess.run(
        ["git", "-C", str(output.parent), "rev-parse", "--show-toplevel"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if inside_git.returncode == 0:
        raise ValueError("Build inputs must be written outside Git checkouts")
    require_source(source)
    template_path = Path(__file__).with_name("node-esp32s3.yaml")
    template = template_path.read_bytes()
    raw = git(
        source, "archive", "--format=tar", COMMIT, "firmware/components/wisp", "LICENSE"
    )
    result = bundle(unpack_source(raw), template)
    require_source(source)
    if template_path.read_bytes() != template:
        raise ValueError("Pilot template changed during preparation")
    write_private_output(output, result)
    return {
        "schema": "ruview.wisp-pilot-preparation.v1",
        "source_commit": COMMIT,
        "archive_sha256": hashlib.sha256(result).hexdigest(),
        "bytes": len(result),
        "status": "prepared_only",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.source, args.output), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as exc:
        parser.exit(2, f"Preparation failed: {exc}\n")


if __name__ == "__main__":
    main()
