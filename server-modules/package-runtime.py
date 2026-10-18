#!/usr/bin/env python3
"""Package a trusted, natively compiled Linux worker and exact runtime closure."""

import argparse
import hashlib
import json
import platform
import re
import shutil
import struct
import subprocess
from pathlib import Path

ELF_ARCHITECTURES = {62: "amd64", 183: "arm64"}
HOST_ARCHITECTURES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}
LIBRARY_PREFIXES = ("/usr/lib/", "/lib/", "/lib64/")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_architecture(binary):
    with binary.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:4] != b"\x7fELF":
        raise ValueError("Expected an ELF worker")
    if header[4:7] != b"\x02\x01\x01":
        raise ValueError("Expected a little-endian ELF64 worker")
    architecture = ELF_ARCHITECTURES.get(struct.unpack_from("<H", header, 18)[0])
    if architecture is None:
        raise ValueError("Unsupported worker ELF architecture")
    host = HOST_ARCHITECTURES.get(platform.machine().lower())
    if platform.system() != "Linux" or host is None:
        raise ValueError("Expected a supported native Linux packaging host")
    if architecture != host:
        raise ValueError("Worker architecture does not match the native host")
    return architecture


def package(binary, destination):
    if destination.exists():
        raise ValueError("Runtime output must be new")
    architecture = native_architecture(binary)
    elf = subprocess.check_output(["readelf", "-h", str(binary)], text=True)
    dynamic = subprocess.check_output(["readelf", "-d", str(binary)], text=True)
    versions = subprocess.check_output(
        ["readelf", "--version-info", str(binary)], text=True
    )
    linkage = subprocess.check_output(["ldd", str(binary)], text=True)
    if "not found" in linkage:
        raise ValueError("Unresolved worker linkage")
    paths = set(re.findall(r"(/[^\s()]+)", linkage))
    if not paths or not any("ld-linux" in path for path in paths):
        raise ValueError("Missing dynamic loader evidence")
    dependencies = []
    for path in sorted(paths):
        source = Path(path)
        resolved = source.resolve()
        if not source.is_file() or not str(resolved).startswith(LIBRARY_PREFIXES):
            raise ValueError("Unexpected dynamic dependency")
        dependencies.append((path, resolved))
    version_names = set(re.findall(r"GLIBC_(\d+\.\d+)", versions))
    if not version_names:
        raise ValueError("Missing GLIBC version evidence")
    maximum_glibc = max(version_names, key=lambda v: tuple(map(int, v.split("."))))
    root = destination / "rootfs"
    (root / "app").mkdir(parents=True)
    shutil.copy2(binary, root / "app/ruview-server-modules")
    for path, resolved in dependencies:
        target = root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, target)
        target.chmod(0o755)
    shutil.copy2(
        Path(__file__).with_name("Dockerfile.runtime"), destination / "Dockerfile"
    )
    closure = {
        str(path.relative_to(root)): sha(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    metadata = {
        "architecture": architecture,
        "binary_sha256": sha(binary),
        "binary_bytes": binary.stat().st_size,
        "needed": re.findall(r"Shared library: \[([^]]+)\]", dynamic),
        "maximum_glibc": maximum_glibc,
        "runtime_file_sha256": closure,
        "recognition_validated": False,
        "registry_manifest": None,
        "deployment": "pending",
    }
    (destination / "runtime-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n"
    )
    (destination / "elf-header.txt").write_text(elf)
    (destination / "elf-dynamic.txt").write_text(dynamic)
    (destination / "elf-versions.txt").write_text(versions)
    (destination / "ldd.txt").write_text(linkage)
    print(json.dumps(metadata))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    package(args.binary.resolve(), args.destination.resolve())
