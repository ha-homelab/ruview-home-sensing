#!/usr/bin/env python3
"""Reject private deployment material in a public source tree or source archive.

Diagnostics expose paths and rule names only, never matching values.
This is a publication gate, not a substitute for secret scanning and review.
"""

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 50 * 1024 * 1024
MAX_TOTAL = 250 * 1024 * 1024
FORBIDDEN_COMPONENTS = {"private", "build-records", "candidates", ".terraform", ".git"}
FORBIDDEN_FILES = {
    "config/nodes.json",
    "config/placements.json",
    "config/sensing-scope.json",
    "config/firmware-release.json",
    "config/assumed-activity.json",
    "config/assumed-activity-receivers.json",
    "config/assumed-activity-runtime.json",
    "firmware/home_wasm_pubkey.h",
    "firmware/modules/manifest.json",
    "collector/ui/home-floor/floor-config.js",
    "collector/ui/home-floor/home-floor.js",
}
RULES = {
    "location-label": re.compile(
        r"\b(?:bed[r]oom|kit[c]hen|living[ _-]r[o]om|dining[ _-]r[o]om|micro[w]ave|fri[d]ge|refri[g]erator|lou[n]ge|hall[w]ay)\b",
        re.I,
    ),
    "private-repository": re.compile(r"github\.com/[4]alvit/", re.I),
    "operator-home-path": re.compile(
        r"(?<![a-zA-Z0-9])/(?:Use[r]s|ho[m]e)/(?!runner(?:/|\b)|example(?:/|\b)|user(?:/|\b))[a-zA-Z][^/\s]+/"
    ),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "credential-url": re.compile(r"https?://(?!(?:user|example):)[^/\s:@]+:[^/\s@]+@"),
}
# Rule examples are deliberately assembled in tests to avoid publishing labels.


def inspect_file(name, data, approved):
    path = PurePosixPath(name)
    issues = []
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        issues.append("unsafe-path")
    if FORBIDDEN_COMPONENTS.intersection(path.parts) or name in FORBIDDEN_FILES:
        issues.append("private-path")
    if path.name.startswith(".env") and path.name != ".env.example":
        issues.append("environment-file")
    if path.suffix in {".pcap", ".pcapng", ".tfstate", ".tfvars", ".tfplan", ".heic"}:
        issues.append("private-artifact")
    if len(data) > MAX_FILE:
        return issues + ["oversized-file"]
    try:
        text = data.decode("utf-8")
        if "\x00" in text:
            raise UnicodeDecodeError("utf-8", data, 0, 1, "binary NUL")
    except UnicodeDecodeError:
        expected = approved.get(name)
        if not expected or hashlib.sha256(data).hexdigest() != expected:
            issues.append("unreviewed-binary")
        return issues
    for rule, expression in RULES.items():
        if expression.search(text):
            issues.append(rule)
    return issues


def tree_files(root):
    # git ls-files includes reviewed tracked files and staged additions only.
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and Path(result.stdout.strip()).resolve() == root:
        names = (
            subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
            .decode()
            .split("\0")
        )
        paths = [root / n for n in names if n]
    else:
        paths = [
            p
            for p in root.rglob("*")
            if p.is_file()
            and not set(p.relative_to(root).parts).intersection(
                {".git", "__pycache__", ".venv", ".ruff_cache"}
            )
        ]
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("source symlinks are not publishable")
        yield path.relative_to(root).as_posix(), path.read_bytes()


def archive_files(path, strip_components=0):
    seen = set()

    def normalize(name):
        original = PurePosixPath(name)
        if original.is_absolute() or ".." in original.parts or "\\" in name:
            raise ValueError("unsafe archive path")
        parts = original.parts
        if len(parts) <= strip_components:
            raise ValueError("invalid archive wrapper")
        result = str(PurePosixPath(*parts[strip_components:]))
        if result in seen:
            raise ValueError("duplicate archive member")
        seen.add(result)
        return result

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                if (
                    item.file_size > MAX_FILE
                    or (item.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise ValueError("unsafe ZIP member")
                yield normalize(item.filename), archive.read(item)
    else:
        with tarfile.open(path, "r:*") as archive:
            for item in archive:
                if item.isdir():
                    continue
                if not item.isfile() or item.size > MAX_FILE:
                    raise ValueError("unsafe tar member")
                yield normalize(item.name), archive.extractfile(item).read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--strip-components", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    approved = json.loads((ROOT / ".public-binary-assets.json").read_text())
    files = (
        archive_files(args.archive, args.strip_components)
        if args.archive
        else tree_files(ROOT)
    )
    failures, count, total = [], 0, 0
    for name, data in files:
        count += 1
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError("publication inventory is oversized")
        failures.extend((name, rule) for rule in inspect_file(name, data, approved))
    for name, rule in failures:
        print(f"{name}: {rule}")
    print(f"Checked {count} files; {len(failures)} publication boundary findings")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
