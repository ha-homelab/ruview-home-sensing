"""Fictional receiver selection and real pinned CLI input fixtures; no device I/O."""

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from collector_fixture import profile_arguments
from module_package_fixture import package_arguments
from site_context_fixture import FIXTURES, NAMES, document

from firmware.qualification_receivers import QualificationReceiver


def get_test_receiver(node_id):
    if type(node_id) is not int or node_id not in (1, 2, 3):
        raise ValueError("unknown_qualification_receiver")
    return QualificationReceiver(
        **document("installation-identity.json")["receivers"][node_id - 1],
        allowed_versions=tuple(
            document("installation-identity.json")["policy"]["receiver_versions"][
                str(node_id)
            ]
        ),
    )


RECEIVER = get_test_receiver(2)


def context_arguments(directory):
    root = Path(directory).resolve()
    context = root / "context"
    context.mkdir(mode=0o700)
    hashes = {}
    for name in NAMES:
        raw = (FIXTURES / name).read_bytes()
        path = context / name
        path.write_bytes(raw)
        path.chmod(0o600)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    manifest = json.dumps(
        {"schema": "ruview.private-site-context.v1", "files": hashes}, sort_keys=True
    ).encode()
    (context / "manifest.json").write_bytes(manifest)
    (context / "manifest.json").chmod(0o600)
    identity = root / "identity.json"
    identity.write_bytes((FIXTURES / "installation-identity.json").read_bytes())
    identity.chmod(0o600)
    return [
        "--site-context",
        str(context),
        "--site-context-sha256",
        hashlib.sha256(manifest).hexdigest(),
        "--installation-identity",
        str(identity),
        "--installation-identity-sha256",
        hashlib.sha256(identity.read_bytes()).hexdigest(),
    ]


def run_cli(module):
    """Existing CLI behavior tests use real, separately pinned synthetic inputs."""
    with tempfile.TemporaryDirectory() as directory:
        flags = context_arguments(directory) + package_arguments(directory)
        for key, value in (
            ("--node", "2"),
            ("--expected-version", "0.8.8.5"),
            ("--package-profile", "home-signal"),
        ):
            if key not in sys.argv:
                flags += [key, value]
        if hasattr(module, "observe"):
            flags += profile_arguments(directory)
        with patch("sys.argv", [*sys.argv, *flags]):
            return module.main()
