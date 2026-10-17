#!/usr/bin/env python3
"""Build a deterministic source/tool release from an exact committed Git tree.

The archive is the supported distribution for tools that need sibling source
files. It contains no working-tree files, Git history, timestamps or author data.
Run the publication/privacy gate before uploading the resulting artifact.
"""

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

REPOSITORY = "ha-homelab/ruview-home-sensing"
SCHEMA = "ruview.source-release.v1"
MANIFEST = "RELEASE-MANIFEST.json"
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def safe_path(name):
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and str(path) == name
        and all(part not in ("", ".", "..", ".git") for part in path.parts)
        and "\\" not in name
        and not any(ord(char) < 32 for char in name)
        and name != MANIFEST
    )


def build(root, revision):
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("An exact 40-character Git commit is required")
    resolved = git(root, "rev-parse", f"{revision}^{{commit}}").decode().strip()
    if resolved != revision:
        raise ValueError("Revision must identify the exact commit")
    files, total = {}, 0
    for record in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        name = raw_name.decode("utf-8")
        if kind != "blob" or mode not in ("100644", "100755") or not safe_path(name):
            raise ValueError("Release contains a link, submodule or unsafe path")
        if name in files:
            raise ValueError("Duplicate release path")
        size = int(git(root, "cat-file", "-s", oid))
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("Release size exceeds the reviewed bounds")
        raw = git(root, "cat-file", "blob", oid)
        if len(raw) != size:
            raise ValueError("Git object changed during packaging")
        files[name] = (raw, 0o755 if mode == "100755" else 0o644)
    manifest = {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "revision": revision,
        "files": {
            name: {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "mode": mode,
            }
            for name, (raw, mode) in sorted(files.items())
        },
    }
    files[MANIFEST] = (
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        0o644,
    )
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            for name, (raw, mode) in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(raw), mode
                archive.addfile(item, io.BytesIO(raw))
    return buffer.getvalue(), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw, manifest = build(args.source, args.revision)
    # Do not accidentally replace a reviewed artifact or follow a symlink.
    with args.output.open("xb") as output:
        output.write(raw)
    checksum = hashlib.sha256(raw).hexdigest()
    receipt = {
        "schema": "ruview.release-receipt.v1",
        "repository": REPOSITORY,
        "revision": args.revision,
        "archive": args.output.name,
        "sha256": checksum,
        "files": len(manifest["files"]),
    }
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
