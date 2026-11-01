"""Apply the reviewed TLS/QUIC lockfile delta after the pinned ring policy."""

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def verify_digest(data, expected, description):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Unexpected {description}; use the exact reviewed source")


def prepare_dependency_security(source):
    """Keep source/manifests pinned and reject any unreviewed lockfile changes."""
    source = Path(source)
    policy_path = ROOT / "dependency-security.json"
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes)
    patch = ROOT / "patches" / "0005-upstream-dependency-security.patch"
    verify_digest(patch.read_bytes(), policy["patch_sha256"], "dependency patch")
    lock = source / "v2/Cargo.lock"
    verify_digest(lock.read_bytes(), policy["lock_before_sha256"], "post-ring lockfile")
    # A dry run fails before changing the source if the patch cannot apply.
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=source, check=True)
    verify_digest(lock.read_bytes(), policy["lock_after_sha256"], "secured lockfile")
    (source / "ruview-dependencies/dependency-security-receipt.json").write_bytes(
        policy_bytes
    )
