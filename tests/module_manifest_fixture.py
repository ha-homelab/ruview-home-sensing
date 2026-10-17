"""Independent fictional module authorization, never a production default."""

import hashlib
import json
from pathlib import Path

from scripts.module_manifest import ModuleManifest

FIXTURE = Path(__file__).resolve().parent / "fixtures/module-manifest.json"


def catalog():
    return json.loads(FIXTURE.read_text())


def manifest_value(value=None):
    raw = FIXTURE.read_bytes() if value is None else json.dumps(value).encode()
    return ModuleManifest(raw, json.loads(raw), hashlib.sha256(raw).hexdigest())


def manifest_arguments(directory):
    path = Path(directory).resolve() / "approved-modules.json"
    path.write_bytes(FIXTURE.read_bytes())
    path.chmod(0o600)
    return [
        "--module-manifest",
        str(path),
        "--module-manifest-sha256",
        manifest_value().sha256,
    ]


def runtime_arguments(path):
    return ["--manifest-sha256", hashlib.sha256(Path(path).read_bytes()).hexdigest()]
