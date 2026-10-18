#!/usr/bin/env python3
"""Create a private per-board candidate plan and NVS image; never flash it."""

import argparse
import json
import secrets
from pathlib import Path

from fleetlib import (
    binding,
    candidate_plan,
    create_directory,
    inspect_application,
    load_installation_context,
    nvs_tool,
    private_path,
    provision_values,
    public_key,
    require,
    save,
    sha,
    verify_backup,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--node", required=True, type=int)
    parser.add_argument("--firmware", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--preferred-bssid",
        help="Explicit per-board reviewed AP preference; omission uses associated all-channel auto selection",
    )
    parser.add_argument(
        "--existing-ota-key",
        type=Path,
        help="Optional private key only when preserving this board's already provisioned key",
    )
    parser.add_argument(
        "--network-settings",
        type=Path,
        help="Private JSON for blank NVS only: ssid,password,target_ip,target_port",
    )
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", required=True, type=Path)
    parser.add_argument("--installation-identity-sha256", required=True)
    args = parser.parse_args()
    context = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    report, raw = verify_backup(args.backup)
    require(
        report["node_id"] == args.node, "Backup's physical unit differs from target"
    )
    image = args.firmware.read_bytes()
    require(len(image) > 0 and sha(image) == args.sha256, "Firmware digest mismatch")
    inspect_application(image, args.version)
    inventory = context.documents["nodes.json"]
    node = binding(args.node, report["identity"]["mac"], inventory, context.identity)
    plan, overlay = candidate_plan(
        report, node, len(image), args.sha256, args.preferred_bssid
    )
    output = create_directory(args.output)
    plan.update(
        backup_sha256=report["flash_sha256"],
        firmware_version=args.version,
        note="The supplied image is checked for target/size only. Rebuilding with this overlay is a separate reviewed operation; this plan never asserts its options are already in the image.",
    )
    save(output / "sdkconfig.candidate", overlay.encode())
    if not plan["image_fits_both_ota_slots"]:
        load_installation_context(
            args.site_context,
            args.site_context_sha256,
            args.installation_identity,
            args.installation_identity_sha256,
        )
        save(output / "plan.json", plan)
        print(
            json.dumps(
                {
                    "status": plan["status"],
                    "node_id": args.node,
                    "device_written": False,
                }
            )
        )
        raise SystemExit(1)
    parts = [
        p
        for p in report["layout"]["partitions"]
        if p["type"] == 1 and p["subtype"] == 2
    ]
    require(len(parts) == 1, "Expected one verified unencrypted NVS partition")
    part = parts[0]
    nvs = raw[part["offset"] : part["offset"] + part["bytes"]]
    tool = nvs_tool()
    old = tool.logical_values(nvs)
    stored_key = old.get(("security", "ota_psk"))
    if args.existing_ota_key:
        key = private_path(args.existing_ota_key, existing=True).read_text().strip()
    elif stored_key is not None:
        require(stored_key[0] == "string", "Existing OTA key type needs review")
        key = stored_key[1]  # Preserve this board's key; do not copy another unit's.
    else:
        key = secrets.token_hex(32)
    network = None
    if args.network_settings:
        network = json.loads(
            private_path(args.network_settings, existing=True).read_text()
        )
    expected = provision_values(old, args.node, key, public_key(context), network)
    prepared = tool.generate(expected, len(nvs))
    require(
        len(prepared) == len(nvs) and tool.logical_values(prepared) == expected,
        "Prepared NVS round-trip mismatch",
    )
    save(output / "ota-key.private.txt", (key + "\n").encode())
    save(output / "nvs-prepared.bin", prepared)
    changes = [
        {
            "namespace": ns,
            "key": name,
            "action": "added" if (ns, name) not in old else "explicitly_updated",
        }
        for (ns, name), value in expected.items()
        if old.get((ns, name)) != value
    ]
    plan.update(
        nvs={
            "offset": part["offset"],
            "bytes": part["bytes"],
            "before_sha256": sha(nvs),
            "prepared_sha256": sha(prepared),
            "logical_values_before": len(old),
            "preserved_unchanged": sum(expected.get(k) == v for k, v in old.items()),
            "changed_keys_without_values": changes,
        },
        ota_key_preserved=stored_key is not None,
        signing_public_key_sha256=sha(public_key(context)),
        router_reservation_pending_verification=True,
        firmware_overlay_not_yet_built=True,
    )
    load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    save(output / "plan.json", plan)
    print(
        json.dumps(
            {
                "status": plan["status"],
                "node_id": args.node,
                "reserved_ip": node["reserved_ip"],
                "device_written": False,
                "prepared_nvs_bytes": len(prepared),
            }
        )
    )


if __name__ == "__main__":
    main()
