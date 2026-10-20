"""Prepare the exact ring source with an exact-bit RSA minimum policy."""

import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "ring-policy"
sys.path.insert(0, str(ROOT.parent))
from scripts.transport_security import open_source  # noqa: E402


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_bytes(archive=None):
    lock = json.loads((POLICY / "source.json").read_text())
    if archive is None:
        with open_source(lock["url"], timeout=60) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
    else:
        with Path(archive).open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
    if digest(raw) != lock["sha256"]:
        raise ValueError("Unpinned ring source archive")
    return raw


def extract_ring(raw, destination):
    """Only regular files/directories under the authenticated crate prefix."""
    lock = json.loads((POLICY / "source.json").read_text())
    if digest(raw) != lock["sha256"]:
        raise ValueError("Unpinned ring source archive")
    destination.mkdir()
    prefix = f"ring-{lock['version']}"
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if sum(m.size for m in members) > 32 * 1024 * 1024:
            raise ValueError("Unexpected ring source size")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != prefix
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("Unsafe ring archive member")
            target = destination.joinpath(*path.parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
    changed = destination / lock["changed_source"]
    if digest(changed.read_bytes()) != lock["original_source_sha256"]:
        raise ValueError("Unexpected ring modulus implementation")
    subprocess.run(
        ["git", "apply", "--check", str(POLICY / "exact-minimum.patch")],
        cwd=destination,
        check=True,
    )
    subprocess.run(
        ["git", "apply", str(POLICY / "exact-minimum.patch")],
        cwd=destination,
        check=True,
    )
    if digest(changed.read_bytes()) != lock["patched_source_sha256"]:
        raise ValueError("Unexpected patched ring modulus implementation")


def prepare_ring(source, archive=None):
    lock = json.loads((POLICY / "source.json").read_text())
    manifest = source / "v2/Cargo.toml"
    original_manifest = manifest.read_bytes()
    if digest(original_manifest) != lock["workspace_manifest_sha256"]:
        raise ValueError("Unexpected workspace manifest for ring override")
    cargo_lock = source / "v2/Cargo.lock"
    original_lock = cargo_lock.read_text()
    if digest(original_lock.encode()) != lock["workspace_lock_sha256"]:
        raise ValueError("Unexpected workspace lockfile for ring override")
    entry = (
        'name = "ring"\nversion = "0.17.14"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        f'checksum = "{lock["sha256"]}"\n'
    )
    if original_lock.count(entry) != 1:
        raise ValueError("Expected exactly one pinned registry ring package")
    output = source / "ruview-dependencies"
    if output.exists():
        raise ValueError("Use a fresh source tree for ring policy")
    raw = archive_bytes(archive)
    with tempfile.TemporaryDirectory(dir=source) as temporary:
        stage = Path(temporary) / "dependencies"
        stage.mkdir()
        extract_ring(raw, stage / "ring")
        notices = stage / "licenses/ring"
        notices.mkdir(parents=True)
        for name in lock["licenses"]:
            shutil.copyfile(stage / "ring" / name, notices / name.replace("/", "__"))
        shutil.copytree(POLICY, stage / "ring-policy")
        shutil.copyfile(ROOT / "test_ring_policy.py", stage / "test_ring_policy.py")
        receipt = {
            **lock,
            "patch_sha256": digest((POLICY / "exact-minimum.patch").read_bytes()),
            "policy": "Exact minimum RSA modulus bit length; algorithms unchanged",
        }
        (stage / "ring-policy-receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n"
        )
        stage.rename(output)
    manifest.write_bytes(
        original_manifest
        + b'\n[patch.crates-io]\nring = { path = "../ruview-dependencies/ring" }\n'
    )
    cargo_lock.write_text(
        original_lock.replace(entry, 'name = "ring"\nversion = "0.17.14"\n')
    )
