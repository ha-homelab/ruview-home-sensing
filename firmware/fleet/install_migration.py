#!/usr/bin/env python3
"""One reviewed five-range migration; no erase-all, retry or automatic reset.

The `check` action is offline. `install` opens only an explicit observed USB
port after all offline gates pass. Even a verified write leaves the board in
ROM/stub: first boot requires a separate explicit operator action.
"""

import argparse
import contextlib
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path

import boot_rule
import plan_migration as planner
from backup import snapshot, usb_ports
from fleetlib import (
    ESPT_VERSION,
    ROOT,
    binding,
    create_directory,
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

OFFSETS = {
    "bootloader.bin": 0,
    "partition-table.bin": 0x8000,
    "nvs-prepared.bin": 0x9000,
    "ota_data_initial.bin": 0xF000,
    "esp32-csi-node.bin": 0x20000,
}


def tool_hashes():
    names = [
        "firmware/fleet/" + name
        for name in (
            "install_migration.py",
            "boot_rule.py",
            "backup.py",
            "fleetlib.py",
            "plan_migration.py",
            "build_profile.py",
        )
    ] + [
        "firmware/provision-ota-key.py",
        "scripts/site_context.py",
        "scripts/installation_identity.py",
    ]
    return {name: sha((ROOT / name).read_bytes()) for name in names}


def private_read(path, limit):
    private_path(path, existing=True)
    return boot_rule.read_regular(path, limit)


def validate_candidate(
    candidate, report, raw, manifest, blobs, node, payloads, *, site_context
):
    require(
        type(candidate.get("schema_version")) is int
        and candidate["schema_version"] == 1
        and candidate.get("action") == "offline_layout_migration_candidate"
        and candidate.get("status") == "requires_boot_selection_and_install_review"
        and candidate.get("flash_write_authorized") is False
        and candidate.get("layout_changes_authorized") is False,
        "Original unauthorized offline candidate required",
    )
    require(
        candidate["binding"] == node
        and candidate["hardware_profile"] == "home-s3-n16r8"
        and candidate["backup_sha256"] == report["flash_sha256"]
        and candidate["source_partition_table_sha256"] == sha(raw[0x8000:0x9000])
        and candidate["build_artifacts"] == manifest,
        "Candidate unit/backup/bundle mismatch",
    )
    identity = report["identity"]
    require(
        identity["chip"] == "ESP32-S3"
        and type(identity["flash_bytes"]) is int
        and identity["flash_bytes"] == 0x1000000
        and type(identity.get("embedded_psram_bytes")) is int
        and identity["embedded_psram_bytes"] == 0x800000,
        "Only verified S3 N16R8 hardware is supported",
    )
    profile, layout = planner.validate_bundle(blobs, node)
    require(
        candidate["build_profile"] == profile and candidate["target_layout"] == layout,
        "Candidate target/profile changed",
    )
    parts = planner.source_layout(report, raw, candidate["source_layout_class"])
    require(
        candidate["intended_boot_selection"]
        == {
            "partition": "ota_0",
            "offset": 0x20000,
            "initial_otadata": "erased",
            "bootloader_selection_verified": False,
            "automatic_rollback_enabled": False,
            "inactive_slot_application_prepared": False,
        }
        and candidate["runtime_and_sensing_qualified"] is False
        and candidate["restore_qualified"] is False,
        "Candidate cannot promote boot/runtime/restore qualification",
    )
    require(set(payloads) == set(OFFSETS), "Exactly five migration payloads required")
    tool = nvs_tool()
    old = tool.logical_values(raw[0x9000:0xF000]) if parts else {}
    require(len(payloads["nvs-prepared.bin"]) == 0x6000, "Exact NVS size required")
    new = tool.logical_values(payloads["nvs-prepared.bin"])
    key = new[("security", "ota_psk")]
    require(key[0] == "string", "Prepared OTA key type differs")
    network_names = ("ssid", "password", "target_ip", "target_port")
    network = None
    if not any(("csi_cfg", key) in old for key in network_names):
        network = {name: new[("csi_cfg", name)][1] for name in network_names}
    expected = provision_values(
        old, node["node_id"], key[1], public_key(site_context), network
    )
    require(
        new == expected and all(new.get(k) == v for k, v in old.items()),
        "NVS preservation or identity differs",
    )
    # Reconstruct the only admitted write/complement map independently of the
    # candidate's declared offsets. Include erased sector tails in verification.
    ranges, blocks, unchanged, cursor = [], [], [], 0
    for name, offset in sorted(OFFSETS.items(), key=lambda pair: pair[1]):
        logical = payloads[name] if name == "nvs-prepared.bin" else blobs[name]
        data = logical.ljust((len(logical) + 4095) // 4096 * 4096, b"\xff")
        require(
            payloads[name] == data, "Payload differs from inspected bundle/NVS bytes"
        )
        end = offset + len(data)
        require(
            offset >= cursor and end <= len(raw) and data,
            "Overlapping/out-of-bounds migration range",
        )
        if offset > cursor:
            unchanged.append(
                {
                    "offset": cursor,
                    "bytes": offset - cursor,
                    "sha256": sha(raw[cursor:offset]),
                }
            )
        ranges.append(
            {
                "file": "payloads/" + name,
                "offset": offset,
                "bytes": len(data),
                "logical_bytes": len(logical),
                "sha256": sha(data),
                "before_sha256": sha(raw[offset:end]),
            }
        )
        blocks.append((offset, data))
        cursor = end
    if cursor < len(raw):
        unchanged.append(
            {"offset": cursor, "bytes": len(raw) - cursor, "sha256": sha(raw[cursor:])}
        )
    # Strict canonical JSON also distinguishes bools/floats from integer ranges.
    require(
        candidate["write_ranges"] == ranges
        and candidate["unchanged_ranges"] == unchanged
        and all(
            type(row[field]) is int
            for row in candidate["write_ranges"]
            for field in ("offset", "bytes", "logical_bytes")
        )
        and all(
            type(row[field]) is int
            for row in candidate["unchanged_ranges"]
            for field in ("offset", "bytes")
        ),
        "Complete disjoint sector coverage differs",
    )
    return blocks, unchanged, layout


def load_inputs(
    review_path,
    *,
    site_context,
    site_context_sha256,
    installation_identity,
    installation_identity_sha256,
):
    context = load_installation_context(
        site_context,
        site_context_sha256,
        installation_identity,
        installation_identity_sha256,
    )
    review_raw = private_read(review_path, 131072)
    review_path = private_path(review_path, existing=True)
    review = planner.strict_json(review_raw)
    require(
        set(review)
        == {
            "schema_version",
            "action",
            "coordinator_approved",
            "build_provenance_reviewed",
            "power_loss_recovery_reviewed",
            "node_id",
            "expected_mac",
            "candidate_file",
            "candidate_sha256",
            "backup_directory",
            "backup_sha256",
            "build_manifest",
            "bundle_sha256",
            "idf_source_directory",
            "boot_build_evidence",
            "boot_build_evidence_sha256",
            "tool_sha256",
        },
        "Unknown reviewed migration schema",
    )
    require(
        type(review["schema_version"]) is int
        and review["schema_version"] == 1
        and review["action"] == "layout_migration_usb"
        and all(
            review[k] is True
            for k in (
                "coordinator_approved",
                "build_provenance_reviewed",
                "power_loss_recovery_reviewed",
            )
        )
        and review["tool_sha256"] == tool_hashes(),
        "Reviewed migration/provenance/recovery/tool binding required",
    )
    report, raw = verify_backup(review["backup_directory"])
    require(
        report["node_id"] == review["node_id"]
        and report["identity"]["mac"] == review["expected_mac"]
        and report["flash_sha256"] == review["backup_sha256"],
        "Reviewed backup identity differs",
    )
    inventory = context.documents["nodes.json"]
    node = binding(
        review["node_id"], review["expected_mac"], inventory, context.identity
    )
    require(
        node["inventory_binding_verified"] is True,
        "Physical inventory identity must be reviewed first",
    )
    candidate_raw = private_read(review["candidate_file"], 1_048_576)
    candidate_file = private_path(review["candidate_file"], existing=True)
    private_path(candidate_file.parent, existing=True)
    require(
        sha(candidate_raw) == review["candidate_sha256"], "Candidate digest changed"
    )
    candidate = planner.strict_json(candidate_raw)
    manifest, blobs = planner.load_bundle(
        Path(review["build_manifest"]), review["bundle_sha256"]
    )
    payloads = {
        name: private_read(candidate_file.parent / "payloads" / name, 0x200000)
        for name in OFFSETS
    }
    blocks, unchanged, layout = validate_candidate(
        candidate, report, raw, manifest, blobs, node, payloads, site_context=context
    )
    boot = boot_rule.verify_boot_rule(
        blobs,
        layout,
        boot_rule.read_regular(review["boot_build_evidence"], 131072),
        review["boot_build_evidence_sha256"],
        review["idf_source_directory"],
    )
    load_installation_context(
        site_context,
        site_context_sha256,
        installation_identity,
        installation_identity_sha256,
    )
    return {
        "review_sha256": sha(review_raw),
        "candidate_sha256": sha(candidate_raw),
        "node": node,
        "backup": report,
        "raw": raw,
        "blocks": blocks,
        "unchanged": unchanged,
        "boot_rule": boot,
        # Anchor to the canonical original candidate, independent of review
        # wrapper location/format. Never duplicate candidates to rearm a write.
        "marker": candidate_file.parent
        / ("migration-attempt-" + sha(candidate_raw) + ".json"),
    }


def reserve_attempt(context):
    marker = context["marker"]
    save(
        marker,
        {
            "review_sha256": context["review_sha256"],
            "candidate_sha256": context["candidate_sha256"],
            "mac": context["node"]["mac"],
            "status": "attempt_reserved_outcome_may_be_unknown",
        },
    )
    fd = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_once(esp, context, writer, reserve):
    require(
        not esp.get_secure_boot_enabled() and not esp.get_flash_encryption_enabled(),
        "Live secure boot/encryption requires separate workflow",
    )
    live = snapshot(esp)
    expected = context["backup"]["identity"]
    require(
        all(
            live[k] == expected[k]
            for k in ("chip", "mac", "flash_id", "flash_bytes", "embedded_psram_bytes")
        ),
        "Live hardware identity differs",
    )
    raw = context["raw"]
    for chunk in context["backup"]["chunks"]:
        off, size = chunk["offset"], chunk["bytes"]
        require(
            esp.flash_md5sum(off, size).lower()
            == hashlib.md5(raw[off : off + size]).hexdigest(),
            "Live flash changed since backup",
        )
    esp.WRITE_FLASH_ATTEMPTS = 1
    require(esp.WRITE_FLASH_ATTEMPTS == 1, "esptool automatic retries must be disabled")
    reserve()  # fsync marker AND its directory before the sole write call.
    writer(
        esp,
        context["blocks"],
        flash_size="keep",
        flash_mode="keep",
        flash_freq="keep",
        compress=True,
    )
    for off, data in context["blocks"]:
        require(
            esp.flash_md5sum(off, len(data)).lower() == hashlib.md5(data).hexdigest(),
            "Changed range verification failed; no retry/reboot",
        )
    for item in context["unchanged"]:
        off, size = item["offset"], item["bytes"]
        require(
            esp.flash_md5sum(off, size).lower()
            == hashlib.md5(raw[off : off + size]).hexdigest(),
            "Unchanged range verification failed; no retry/reboot",
        )
    return {
        "written_ranges_verified": True,
        "unchanged_ranges_verified": True,
        "write_verified": True,
    }


def execute(
    context,
    port,
    result,
    connect,
    attach,
    writer,
    *,
    site_context,
    site_context_sha256,
    installation_identity,
    installation_identity_sha256,
):
    """Injectable transport; closing it never requests an application reset."""
    esp = None
    try:
        load_installation_context(
            site_context,
            site_context_sha256,
            installation_identity,
            installation_identity_sha256,
        )
        esp = connect(port, connect_attempts=2)
        require(
            ":".join(f"{v:02x}" for v in esp.read_mac()) == context["node"]["mac"],
            "Connected station MAC differs",
        )
        require(
            not esp.get_secure_boot_enabled()
            and not esp.get_flash_encryption_enabled(),
            "Unsupported live security state",
        )
        esp = esp.run_stub()
        attach(esp)
        esp.change_baud(230400)

        def reserve():
            load_installation_context(
                site_context,
                site_context_sha256,
                installation_identity,
                installation_identity_sha256,
            )
            reserve_attempt(context)
            result["write_attempt_reserved"] = True

        result.update(write_once(esp, context, writer, reserve))
    finally:
        if esp is not None:
            # Never hard_reset, including success and all failure paths.
            esp._port.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install"))
    parser.add_argument("--reviewed-plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--port")
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", required=True, type=Path)
    parser.add_argument("--installation-identity-sha256", required=True)
    args = parser.parse_args()
    load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    output = create_directory(args.output)
    result = {
        "schema_version": 1,
        "action": args.action,
        "offline_gates_passed": False,
        "write_attempt_reserved": False,
        "write_verified": False,
        "automatic_reset_requested": False,
        "physical_boot_verified": False,
        "runtime_and_sensing_qualified": False,
        "restore_qualified": False,
    }
    save(output / "serial.private.log", b"")
    with (
        (output / "serial.private.log").open("a") as log,
        contextlib.redirect_stdout(log),
        contextlib.redirect_stderr(log),
    ):
        try:
            require(
                importlib.metadata.version("esptool") == ESPT_VERSION,
                "Use pinned esptool5.1.0",
            )
            context = load_inputs(
                args.reviewed_plan,
                site_context=args.site_context,
                site_context_sha256=args.site_context_sha256,
                installation_identity=args.installation_identity,
                installation_identity_sha256=args.installation_identity_sha256,
            )
            require(
                not context["marker"].exists(),
                "Candidate already consumed its migration attempt",
            )
            result.update(
                offline_gates_passed=True,
                review_sha256=context["review_sha256"],
                candidate_sha256=context["candidate_sha256"],
                node=context["node"],
                boot_rule=context["boot_rule"],
            )
            if args.action == "install":
                require(
                    args.port in {p["port"] for p in usb_ports()},
                    "Explicit observed USB port required",
                )
                import esptool

                execute(
                    context,
                    args.port,
                    result,
                    esptool.detect_chip,
                    esptool.attach_flash,
                    esptool.cmds.write_flash,
                    site_context=args.site_context,
                    site_context_sha256=args.site_context_sha256,
                    installation_identity=args.installation_identity,
                    installation_identity_sha256=args.installation_identity_sha256,
                )
            else:
                require(args.port is None, "Offline check takes no serial port")
        except BaseException as error:
            result["failure_type"] = type(error).__name__
    save(output / "result.json", result)
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if "failure_type" in result else 0)


if __name__ == "__main__":
    main()
