"""Explicit local test fixtures for the required private Terraform inputs."""

import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/site"
NAMES = (
    "nodes.json",
    "placements.json",
    "assumed-activity.json",
    "assumed-activity-receivers.json",
    "assumed-activity-runtime.json",
)


def document(name):
    """Return fresh, independent synthetic data; never load an installed context."""
    return json.loads((FIXTURES / name).read_text())


def write_site_inputs(module, fixture_root, source=ROOT):
    raw = {}
    for name in NAMES:
        fixture = fixture_root / "config" / name
        raw[name] = (fixture if fixture.exists() else FIXTURES / name).read_text()
    manifest = json.dumps(
        {
            "schema": "ruview.private-site-context.v1",
            "files": {
                n: hashlib.sha256(v.encode()).hexdigest() for n, v in raw.items()
            },
        },
        sort_keys=True,
    )
    values = {
        "site_context": {"manifest": manifest, "inputs": raw},
        "site_context_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
    }
    # Independent known-reference fixture; do not approve mutated test inputs.
    identity = document("installation-identity.json")
    identity_raw = json.dumps(identity, sort_keys=True)
    values["installation_identity_json"] = identity_raw
    values["installation_identity_sha256"] = hashlib.sha256(
        identity_raw.encode()
    ).hexdigest()
    if (source / "infrastructure/k3s/installation-identity.tf").exists():
        shutil.copyfile(
            source / "infrastructure/k3s/installation-identity.tf",
            module / "installation-identity.tf",
        )
    write_deployment_inputs(module, source)
    # This is only a synthetic test approval, not the operator export recipe.
    path = module / "site.auto.tfvars.json"
    path.write_text(json.dumps(values))
    path.chmod(0o600)
    shutil.copyfile(
        source / "infrastructure/k3s/site-context.tf", module / "site-context.tf"
    )
    return values


def write_deployment_inputs(module, source=ROOT):
    """Provide a separately fixed fictional routing approval to real HCL tests."""
    profile_tf = source / "infrastructure/k3s/deployment-profile.tf"
    if not profile_tf.exists():
        return
    raw = (FIXTURES / "deployment-profile.json").read_text()
    values = {
        "deployment_profile_json": raw,
        "deployment_profile_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "kube_context": "example-test-context",
    }
    shutil.copyfile(profile_tf, module / "deployment-profile.tf")
    path = module / "deployment.auto.tfvars.json"
    path.write_text(json.dumps(values))
    path.chmod(0o600)
