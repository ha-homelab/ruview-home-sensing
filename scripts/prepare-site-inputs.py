#!/usr/bin/env python3
"""Export verified private data for Terraform; the approval pin stays separate."""

import argparse
import json
from pathlib import Path

if __package__:
    from .installation_identity import load_installation_context
    from .module_manifest import add_module_manifest_arguments, load_module_manifest
    from .site_context import load_pinned_json, write_private_output
else:
    from installation_identity import load_installation_context
    from module_manifest import add_module_manifest_arguments, load_module_manifest
    from site_context import load_pinned_json, write_private_output


def terraform_inputs(context):
    return {
        "site_context": {
            "manifest": context.manifest_raw.decode("utf-8"),
            "inputs": {name: raw.decode("utf-8") for name, raw in context.raw.items()},
        }
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", type=Path, required=True)
    parser.add_argument("--installation-identity-sha256", required=True)
    parser.add_argument("--deployment-profile", type=Path, required=True)
    parser.add_argument("--deployment-profile-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    add_module_manifest_arguments(parser)
    args = parser.parse_args()
    context = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    manifest = load_module_manifest(args.module_manifest, args.module_manifest_sha256)
    deployment_raw, _ = load_pinned_json(
        args.deployment_profile, args.deployment_profile_sha256, 64 * 1024
    )
    # Exclusive creation refuses a pre-existing file or symlink. Never emit the
    # configuration on stdout or write an approval root into the generated data.
    data = terraform_inputs(context) | {
        "installation_identity_json": context.identity_raw.decode(),
        "module_manifest_json": manifest.raw.decode("utf-8"),
        "deployment_profile_json": deployment_raw.decode("utf-8"),
    }
    raw = (json.dumps(data, indent=2) + "\n").encode()
    load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    load_module_manifest(args.module_manifest, args.module_manifest_sha256)
    load_pinned_json(args.deployment_profile, args.deployment_profile_sha256, 64 * 1024)
    write_private_output(args.output, raw)


if __name__ == "__main__":
    main()
