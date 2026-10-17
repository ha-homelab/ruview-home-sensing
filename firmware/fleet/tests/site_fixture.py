"""Explicit private snapshots for offline fleet tests; no command defaults."""

import hashlib
import json
from pathlib import Path

from scripts.installation_identity import load_installation_context
from scripts.site_context import FILES


def site_fixture(parent):
    directory = Path(parent).resolve() / "site-context"
    directory.mkdir(mode=0o700)
    root = Path(__file__).resolve().parents[3]
    for name in FILES:
        # Independent fictional fixture only; never an operator approval recipe.
        raw = (root / "tests/fixtures/site" / name).read_bytes()
        path = directory / name
        path.write_bytes(raw)
        path.chmod(0o600)
    manifest = {
        "schema": "ruview.private-site-context.v1",
        "files": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in FILES
        },
    }
    raw = json.dumps(manifest, sort_keys=True).encode()
    (directory / "manifest.json").write_bytes(raw)
    (directory / "manifest.json").chmod(0o600)
    pin = hashlib.sha256(raw).hexdigest()
    identity = json.loads(
        (root / "tests/fixtures/site/installation-identity.json").read_text()
    )
    raw = json.dumps(identity, sort_keys=True).encode()
    identity_path = directory / "identity.json"
    identity_path.write_bytes(raw)
    identity_path.chmod(0o600)
    identity_pin = hashlib.sha256(raw).hexdigest()
    args = {
        "site_context": directory,
        "site_context_sha256": pin,
        "installation_identity": identity_path,
        "installation_identity_sha256": identity_pin,
    }
    return args, load_installation_context(directory, pin, identity_path, identity_pin)
