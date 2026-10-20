#!/usr/bin/env python3
"""Collect original notices for the selected collector Cargo build graph."""

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

PACKAGE = "wifi-densepose-sensing-server"
TARGET = "aarch64-unknown-linux-gnu"
NOTICE = re.compile(r"(licen[cs]e|copying|notice|copyright|authors)(?:$|[._-])", re.I)
SOURCE_SUFFIXES = {".rs", ".py", ".js", ".ts", ".c", ".h", ".cpp", ".hpp", ".go"}


class MissingNotices(ValueError):
    pass


def is_notice(path):
    return path.suffix.lower() not in SOURCE_SUFFIXES and (
        NOTICE.match(path.name)
        or any(p.lower() in {"licenses", "licences"} for p in path.parts[:-1])
    )


def command(*args, cwd):
    return subprocess.check_output(args, cwd=cwd, text=True)


def inherited_package(root, repository):
    for parent in (root, *root.parents):
        if not parent.is_relative_to(repository):
            break
        manifest = parent / "Cargo.toml"
        if manifest.is_file():
            workspace = tomllib.loads(manifest.read_text()).get("workspace")
            if workspace is not None:
                return parent, workspace["package"]
    raise ValueError("Inherited package license has no authenticated workspace")


def registry_source(locked, cargo_home, staging):
    """Use real Cargo cache archives, not cargo-vendor-only checksum files."""
    key = f"{locked['name']}-{locked['version']}"
    raw = None
    for candidate in (cargo_home / "registry/cache").glob(f"*/{key}.crate"):
        data = candidate.read_bytes()
        if hashlib.sha256(data).hexdigest() == locked["checksum"]:
            raw = data
            break
    if raw is None:
        raise ValueError(f"Authenticated Cargo archive is absent: {key}")
    root = staging / key
    root.mkdir()
    checksums = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        manifest = archive.extractfile(f"{key}/Cargo.toml").read()
        declared = tomllib.loads(manifest.decode())["package"].get("license-file")
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != key
            ):
                raise ValueError("Unexpected path in authenticated Cargo archive")
            relative = PurePosixPath(*path.parts[1:])
            wanted = relative.as_posix() in {"Cargo.toml", declared} or is_notice(
                relative
            )
            if not wanted or member.isdir():
                continue
            if not member.isfile() or member.size > 32 * 1024 * 1024:
                raise ValueError("Unexpected Cargo notice member")
            data = archive.extractfile(member).read()
            target = root.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
            checksums[relative.as_posix()] = hashlib.sha256(data).hexdigest()
    return root, checksums


def selected_packages(tree, workspace, cargo_home, registry_staging):
    """Do not mistake unrelated workspace or target packages for selected code."""
    selected = {}
    for line in tree.splitlines():
        match = re.fullmatch(r"([\w-]+) v(\S+)(.*)", line)
        if not match:
            raise ValueError(f"Unexpected Cargo tree row: {line!r}")
        name, version, suffix = match.groups()
        paths = [
            Path(p) for p in re.findall(r"\(([^()]*)\)", suffix) if p.startswith("/")
        ]
        selected[name, version] = paths[0] if paths else None
    if not selected or not any(name == PACKAGE for name, _ in selected):
        raise ValueError("The collector package is missing from the Cargo graph")
    lock = tomllib.loads((workspace / "Cargo.lock").read_text())
    packages = []
    for (name, version), path in sorted(selected.items()):
        matches = [
            p for p in lock["package"] if (p["name"], p["version"]) == (name, version)
        ]
        if len(matches) != 1:
            raise ValueError(f"Ambiguous or absent locked package: {name} {version}")
        locked = matches[0]
        checksums = None
        if locked.get("source", "").startswith("registry+"):
            path, checksums = registry_source(locked, cargo_home, registry_staging)
        elif path is None or locked.get("source"):
            raise ValueError(f"Unsupported package source: {name} {version}")
        manifest = path / "Cargo.toml"
        package = tomllib.loads(manifest.read_text())["package"]
        license_value = package.get("license")
        license_file = package.get("license-file")
        if isinstance(license_value, dict) or isinstance(license_file, dict):
            owner, inherited = inherited_package(path, workspace.parent)
            if isinstance(license_value, dict):
                license_value = inherited.get("license")
            if isinstance(license_file, dict):
                license_file = str(owner / inherited["license-file"])
        packages.append(
            {
                "name": name,
                "version": version,
                "source": locked.get("source"),
                "manifest_path": str(manifest),
                "license": license_value,
                "license_file": license_file,
                "checksum": locked.get("checksum"),
                "file_checksums": checksums,
            }
        )
    return packages


def notice_files(package, workspace):
    root = Path(package["manifest_path"]).resolve().parent
    repository = workspace.parent.resolve()
    local = package.get("source") is None and root.is_relative_to(repository)
    boundary = repository if local else root
    files = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "target", "node_modules"})
        for name in names:
            if is_notice((Path(directory) / name).relative_to(root)):
                files.add(Path(directory) / name)
    declared = package.get("license_file")
    if declared:
        path = Path(declared)
        files.add(path if path.is_absolute() else root / path)
    # Workspace crates may inherit their original repository license.
    if not files and local:
        parent = root.parent
        while parent.is_relative_to(repository):
            files.update(
                p for p in parent.iterdir() if is_notice(Path(p.name)) and p.is_file()
            )
            if files or parent == repository:
                break
            parent = parent.parent
    if not files:
        raise MissingNotices(
            f"No original license/notice text found for {package['name']}"
        )
    resolved = []
    for path in sorted(files):
        target = path.resolve(strict=True)
        if not target.is_relative_to(boundary) or not target.is_file():
            raise ValueError(f"License file escapes authenticated source: {path}")
        checksums = package.get("file_checksums")
        if checksums is not None:
            expected = checksums.get(target.relative_to(root).as_posix())
            if expected != hashlib.sha256(target.read_bytes()).hexdigest():
                raise ValueError(f"Cargo notice checksum mismatch: {path}")
        resolved.append((target.relative_to(boundary).as_posix(), target))
    return sorted(set(resolved))


def source_documents(package, workspace, overrides):
    try:
        return notice_files(package, workspace)
    except MissingNotices:
        sources = json.loads((overrides / "sources.json").read_text())
        matches = [
            p
            for p in sources["packages"]
            if (p["name"], p["version"], p["crate_sha256"])
            == (package["name"], package["version"], package.get("checksum"))
        ]
        if len(matches) != 1 or not matches[0]["documents"]:
            raise MissingNotices(
                f"No exact upstream notice recovery for {package['name']}"
            ) from None
        result = []
        for document in matches[0]["documents"]:
            path = (overrides / document["path"]).resolve(strict=True)
            if not path.is_relative_to(overrides.resolve()):
                raise ValueError(
                    "Recovered notice path escapes its source directory"
                ) from None
            if hashlib.sha256(path.read_bytes()).hexdigest() != document["sha256"]:
                raise ValueError(
                    "Recovered upstream notice checksum mismatch"
                ) from None
            result.append((document["url"], path))
        return result


def copy_notice(source, target, origin, bundle):
    data = source.read_bytes()
    if not data or len(data) > 32 * 1024 * 1024:
        raise ValueError(f"Invalid notice size: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {
        "origin": origin,
        "file": target.relative_to(bundle).as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def build_bundle(
    packages, workspace, output, project_notices, rust_copyright, overrides
):
    """Stage atomically; never publish a partial bundle after a missing notice."""
    if output.exists():
        raise ValueError("License output must be a new directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir()
        rows = []
        for package in packages:
            key = f"{package['name']}-{package['version']}"
            if not re.fullmatch(r"[\w.+-]+", key):
                raise ValueError("Invalid package identifier")
            documents = []
            for index, (origin, source) in enumerate(
                source_documents(package, workspace, overrides)
            ):
                filename = f"{index:03d}-{source.name}"
                documents.append(
                    copy_notice(
                        source, stage / "crates" / key / filename, origin, stage
                    )
                )
            rows.append(
                {
                    "name": package["name"],
                    "version": package["version"],
                    "declared_license": package.get("license"),
                    "source": package.get("source")
                    or "authenticated workspace/path dependency",
                    "locked_crate_checksum": package.get("checksum"),
                    "manifest_sha256": hashlib.sha256(
                        Path(package["manifest_path"]).read_bytes()
                    ).hexdigest(),
                    "documents": documents,
                }
            )
        extra = [
            copy_notice(path, stage / "project" / path.name, path.name, stage)
            for path in project_notices
        ]
        extra.append(
            copy_notice(
                rust_copyright,
                stage / "toolchain" / "COPYRIGHT.html",
                "selected Rust toolchain share/doc/rust/COPYRIGHT.html",
                stage,
            )
        )
        extra.append(
            copy_notice(
                overrides / "sources.json",
                stage / "recovered-notice-sources.json",
                "Pinned upstream notice recovery provenance",
                stage,
            )
        )
        index = {
            "package": PACKAGE,
            "target": TARGET,
            "features": ["mqtt"],
            "edges": ["normal", "build"],
            "scope": (
                "Original texts for every package in the selected build graph; build-only "
                "packages and full toolchain notices are intentionally included. This is "
                "not an assertion that all their code is linked into the executable."
            ),
            "package_count": len(rows),
            "packages": rows,
            "additional_documents": extra,
        }
        (stage / "index.json").write_text(json.dumps(index, indent=2) + "\n")
        (stage / "README.txt").write_text(
            "Collector binary license notices\n\n"
            "Distribute this complete directory alongside sensing-server. index.json identifies "
            "the selected Cargo packages and hashes their original notices. The files preserve "
            "upstream terms; the repository MIT license does not replace them.\n"
            "The runtime-libraries directory, added by the image build, retains Debian copyright "
            "notices for the required libc/libm and libgcc shared libraries. System libraries "
            "remain separate dynamically linked components of the pinned runtime image.\n"
        )
        stage.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-notices", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    common = (
        "--locked",
        "--offline",
        "-p",
        PACKAGE,
        "--features",
        "mqtt",
        "--target",
        TARGET,
    )
    tree = command(
        "cargo",
        "tree",
        *common,
        "--edges",
        "normal,build",
        "--prefix",
        "none",
        "--format",
        "{p}",
        cwd=workspace,
    )
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    sysroot = Path(command("rustc", "--print", "sysroot", cwd=workspace).strip())
    with tempfile.TemporaryDirectory(prefix="collector-notice-sources-") as temporary:
        packages = selected_packages(tree, workspace, cargo_home, Path(temporary))
        build_bundle(
            packages,
            workspace,
            args.output.resolve(),
            [args.project_notices / "LICENSE", args.project_notices / "NOTICE"],
            sysroot / "share/doc/rust/COPYRIGHT.html",
            Path(__file__).resolve().parent / "license-overrides",
        )
    print(f"Collected original notices for {len(packages)} selected Cargo packages")


if __name__ == "__main__":
    main()
