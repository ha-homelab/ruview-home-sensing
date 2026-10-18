#!/usr/bin/env python3
"""Offline, private layout/NVS planning. No serial or installation capability."""

import argparse
import contextlib
import io
import json
import re
import secrets
import tempfile
from pathlib import Path

import build_profile
from fleetlib import (
    ROOT,
    binding,
    create_directory,
    inspect_application,
    load_installation_context,
    nvs_tool,
    parse_partitions,
    private_path,
    provision_values,
    public_key,
    save,
    sha,
    verify_backup,
)

FILES = {
    "esp32-csi-node.bin",
    "bootloader.bin",
    "partition-table.bin",
    "ota_data_initial.bin",
    "flasher_args.json",
    "profile.json",
    "sdkconfig.fleet-reviewed",
    "build_profile.py",
    "sdkconfig",
    "version.txt",
}
TARGET = [
    ("nvs", 1, 2, 0x9000, 0x6000),
    ("otadata", 1, 0, 0xF000, 0x2000),
    ("phy_init", 1, 1, 0x11000, 0x1000),
    ("ota_0", 0, 0x10, 0x20000, 0x200000),
    ("ota_1", 0, 0x11, 0x220000, 0x200000),
    ("spiffs", 1, 0x82, 0x420000, 0x1E0000),
]
LAYOUTS = ("blank-full-flash", "two-ota-preserve-data")


class Blocked(ValueError):
    def __init__(self, reason, **details):
        super().__init__(reason)
        self.reason, self.details = reason, details


def check(condition, reason, **details):
    if not condition:
        raise Blocked(reason, **details)


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            check(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def no_float(value):
        raise Blocked("non_integer_json_number")

    return json.loads(
        data, object_pairs_hook=unique, parse_constant=no_float, parse_float=no_float
    )


def source_hashes():
    paths = [
        "firmware/Dockerfile",
        "firmware/fetch-source.py",
        "firmware/upstream-files.json",
        "firmware/sdkconfig.home-s3-n16r8",
        "firmware/sdkconfig.home-node2-preferred-ap.example",
        "firmware/fleet/build_profile.py",
    ]
    paths += sorted(
        str(p.relative_to(ROOT)) for p in (ROOT / "firmware/patches").glob("*.patch")
    )
    return {name: sha((ROOT / name).read_bytes()) for name in paths}


def load_bundle(manifest_path, digest):
    """Read and pin every artifact once; subsequent checks use these cached bytes."""
    check(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "invalid_bundle_digest")
    manifest_raw = manifest_path.read_bytes()
    check(sha(manifest_raw) == digest, "build_manifest_digest_mismatch")
    manifest = strict_json(manifest_raw)
    check(
        set(manifest) == {"schema_version", "files", "source_sha256"},
        "unknown_bundle_schema",
    )
    check(
        type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
        "unknown_bundle_schema",
    )
    check(manifest["source_sha256"] == source_hashes(), "build_source_pins_mismatch")
    check(set(manifest["files"]) == FILES, "missing_or_extra_bundle_artifact")
    blobs = {}
    for name, record in manifest["files"].items():
        path = manifest_path.parent / name
        check(not path.is_symlink() and path.is_file(), "artifact_must_be_regular_file")
        check(set(record) == {"bytes", "sha256"}, "invalid_artifact_record")
        check(
            type(record["bytes"]) is int and 0 < record["bytes"] <= 32 * 1024 * 1024,
            "invalid_artifact_size",
        )
        check(path.stat().st_size == record["bytes"], "artifact_size_mismatch")
        blobs[name] = path.read_bytes()
        check(
            len(blobs[name]) == record["bytes"]
            and sha(blobs[name]) == record["sha256"],
            "artifact_digest_mismatch",
        )
    return manifest, blobs


def validate_bundle(blobs, node):
    profile = strict_json(blobs["profile.json"])
    build_profile.validate(profile, blobs["sdkconfig.fleet-reviewed"])
    check(
        profile["node_id"] == node["node_id"] and profile["station_mac"] == node["mac"],
        "build_profile_unit_mismatch",
    )
    check(
        blobs["version.txt"] == (profile["firmware_version"] + "\n").encode(),
        "build_version_mismatch",
    )
    check(
        sha(blobs["build_profile.py"])
        == sha((ROOT / "firmware/fleet/build_profile.py").read_bytes()),
        "build_validator_mismatch",
    )
    # Validate only the already pinned bytes, never reopen mutable bundle files.
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        for name in ("profile.json", "sdkconfig.fleet-reviewed", "sdkconfig"):
            save(directory / name, blobs[name])
        build_profile.verify_sdkconfig(directory, directory / "sdkconfig")
    config = build_profile.settings(blobs["sdkconfig"], generated=True)
    expected = {
        "CONFIG_PARTITION_TABLE_OFFSET": "0x8000",
        "CONFIG_PARTITION_TABLE_CUSTOM": "y",
        "CONFIG_PARTITION_TABLE_FILENAME": '"partitions_display.csv"',
        "CONFIG_PARTITION_TABLE_MD5": "y",
        "CONFIG_BOOTLOADER_OFFSET_IN_FLASH": "0x0",
        "CONFIG_SECURE_BOOT": "n",
        "CONFIG_NVS_ENCRYPTION": "n",
        "CONFIG_FLASH_ENCRYPTION_ENABLED": "n",
        "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE": "n",
        "CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE": "y",
        "CONFIG_ESP_PHY_INIT_DATA_IN_PARTITION": "n",
    }
    check(
        all(config.get(k) == v for k, v in expected.items()),
        "unsupported_boot_security_or_phy_config",
    )
    inspect_application(blobs["esp32-csi-node.bin"], profile["firmware_version"])
    import esptool.cmds

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        esptool.cmds.image_info(blobs["bootloader.bin"])
    info = captured.getvalue()
    check(
        "Detected image type: ESP32-S3" in info
        and "(invalid)" not in info
        and info.count("(valid)") >= 2,
        "invalid_s3_bootloader_image",
    )
    table = blobs["partition-table.bin"]
    check(len(table) in (0xC00, 0x1000), "invalid_target_table_size")
    layout = parse_partitions(table.ljust(0x1000, b"\xff"), 0x1000000, 0x8000)
    check(layout["md5_verified"], "target_partition_md5_missing")
    entries = [
        (p["name"], p["type"], p["subtype"], p["offset"], p["bytes"])
        for p in layout["partitions"]
    ]
    check(entries == TARGET, "unsupported_target_layout")
    check(
        blobs["ota_data_initial.bin"] == b"\xff" * 0x2000,
        "unsupported_initial_ota_selection",
    )
    check(0 < len(blobs["bootloader.bin"]) <= 0x8000, "bootloader_overlaps_table")
    check(
        0 < len(blobs["esp32-csi-node.bin"]) <= 0x200000,
        "application_exceeds_target_slots",
    )
    args = strict_json(blobs["flasher_args.json"])
    check(
        set(args)
        == {
            "write_flash_args",
            "flash_settings",
            "flash_files",
            "bootloader",
            "app",
            "partition-table",
            "otadata",
            "extra_esptool_args",
        },
        "unknown_flasher_arguments",
    )
    check(
        args.get("flash_files")
        == {
            "0x0": "bootloader/bootloader.bin",
            "0x20000": "esp32-csi-node.bin",
            "0x8000": "partition_table/partition-table.bin",
            "0xf000": "ota_data_initial.bin",
        },
        "unsupported_flash_file_mapping",
    )
    check(
        args.get("flash_settings")
        == {"flash_mode": "dio", "flash_size": "16MB", "flash_freq": "80m"},
        "unsupported_flash_settings",
    )
    check(
        args["write_flash_args"]
        == ["--flash_mode", "dio", "--flash_size", "16MB", "--flash_freq", "80m"],
        "unsupported_flash_arguments",
    )
    check(
        args["extra_esptool_args"]
        == {
            "after": "hard_reset",
            "before": "default_reset",
            "stub": True,
            "chip": "esp32s3",
        },
        "unsupported_extra_flash_arguments",
    )
    for name, offset, filename in (
        ("bootloader", "0x0", "bootloader/bootloader.bin"),
        ("app", "0x20000", "esp32-csi-node.bin"),
        ("partition-table", "0x8000", "partition_table/partition-table.bin"),
        ("otadata", "0xf000", "ota_data_initial.bin"),
    ):
        check(
            args[name] == {"offset": offset, "file": filename, "encrypted": "false"},
            "contradictory_flash_component",
        )
    return profile, layout


def source_layout(report, raw, selected):
    check(selected in LAYOUTS, "unsupported_source_layout_class")
    check(report["partition_table_offset"] == 0x8000, "unsupported_source_table_offset")
    layout = report["layout"]
    if selected == "blank-full-flash":
        check(
            layout["state"] == "blank_no_verified_layout" and raw == b"\xff" * len(raw),
            "blank_class_requires_entire_flash_erased",
        )
        return {}
    check(
        layout["state"] == "parsed" and layout["md5_verified"],
        "source_layout_not_verified",
    )
    parts = {p["name"]: p for p in layout["partitions"]}
    check(set(parts) == {p[0] for p in TARGET}, "unknown_source_partitions")
    for name, kind, subtype, offset, size in TARGET:
        p = parts[name]
        check(
            (p["type"], p["subtype"]) == (kind, subtype),
            "unknown_source_partition_type",
        )
        if kind == 1:
            check(
                (p["offset"], p["bytes"]) == (offset, size),
                "data_partition_relocation_requires_separate_plan",
                partition=name,
                original_offset=p["offset"],
                original_bytes=p["bytes"],
                target_offset=offset,
                target_bytes=size,
            )
    check(parts["ota_0"]["offset"] == 0x20000, "unsupported_source_application_start")
    return parts


def make_plan(
    report, raw, manifest, blobs, node, selected, network=None, *, site_context
):
    identity = report["identity"]
    check(
        identity["chip"] == "ESP32-S3"
        and type(identity["flash_bytes"]) is int
        and identity["flash_bytes"] == 0x1000000
        and type(identity.get("embedded_psram_bytes")) is int
        and identity["embedded_psram_bytes"] == 0x800000,
        "unsupported_or_unverified_hardware",
    )
    check(
        report["node_id"] == node["node_id"] and identity["mac"] == node["mac"],
        "backup_unit_mismatch",
    )
    profile, target = validate_bundle(blobs, node)
    parts = source_layout(report, raw, selected)
    tool = nvs_tool()
    old = tool.logical_values(raw[0x9000:0xF000]) if parts else {}
    stored = old.get(("security", "ota_psk"))
    check(
        stored is None or stored[0] == "string", "stored_ota_key_type_requires_review"
    )
    key = secrets.token_hex(32) if stored is None else stored[1]
    values = provision_values(
        old, node["node_id"], key, public_key(site_context), network
    )
    nvs = tool.generate(values, 0x6000)
    check(
        len(nvs) == 0x6000 and tool.logical_values(nvs) == values,
        "nvs_roundtrip_mismatch",
    )
    payloads = {
        "bootloader.bin": (0, blobs["bootloader.bin"]),
        "partition-table.bin": (0x8000, blobs["partition-table.bin"]),
        "nvs-prepared.bin": (0x9000, nvs),
        "ota_data_initial.bin": (0xF000, blobs["ota_data_initial.bin"]),
        "esp32-csi-node.bin": (0x20000, blobs["esp32-csi-node.bin"]),
    }
    ranges, output = [], {}
    for name, (offset, data) in sorted(payloads.items(), key=lambda item: item[1][0]):
        padded = data.ljust((len(data) + 4095) // 4096 * 4096, b"\xff")
        end = offset + len(padded)
        check(
            end <= len(raw)
            and (not ranges or offset >= ranges[-1]["offset"] + ranges[-1]["bytes"]),
            "unsafe_write_range_overlap",
        )
        for protected in (
            p for p in parts.values() if p["name"] in ("phy_init", "spiffs")
        ):
            check(
                end <= protected["offset"]
                or offset >= protected["offset"] + protected["bytes"],
                "write_overlaps_preserved_data",
                partition=protected["name"],
            )
        output[name] = padded
        ranges.append(
            {
                "file": "payloads/" + name,
                "offset": offset,
                "bytes": len(padded),
                "logical_bytes": len(data),
                "sha256": sha(padded),
                "before_sha256": sha(raw[offset:end]),
            }
        )
    unchanged, cursor = [], 0
    for item in ranges + [{"offset": len(raw), "bytes": 0}]:
        if item["offset"] > cursor:
            unchanged.append(
                {
                    "offset": cursor,
                    "bytes": item["offset"] - cursor,
                    "sha256": sha(raw[cursor : item["offset"]]),
                }
            )
        cursor = item["offset"] + item["bytes"]
    plan = {
        "schema_version": 1,
        "action": "offline_layout_migration_candidate",
        "status": "requires_boot_selection_and_install_review",
        "flash_write_authorized": False,
        "layout_changes_authorized": False,
        "binding": node,
        "hardware_profile": "home-s3-n16r8",
        "backup_sha256": report["flash_sha256"],
        "source_layout_class": selected,
        "source_partition_table_sha256": sha(raw[0x8000:0x9000]),
        "target_layout": target,
        "build_artifacts": manifest,
        "build_profile": profile,
        "write_ranges": ranges,
        "unchanged_ranges": unchanged,
        "nvs_preservation": {
            "logical_values_before": len(old),
            "logical_values_after": len(values),
            "all_prior_values_preserved": all(
                values.get(k) == v for k, v in old.items()
            ),
            "changed_keys_without_values": [
                {"namespace": ns, "key": key_name}
                for (ns, key_name), value in values.items()
                if old.get((ns, key_name)) != value
            ],
            "ota_key_preserved": stored is not None,
            "signing_public_key_sha256": sha(public_key(site_context)),
        },
        "intended_boot_selection": {
            "partition": "ota_0",
            "offset": 0x20000,
            "initial_otadata": "erased",
            "bootloader_selection_verified": False,
            "automatic_rollback_enabled": False,
            "inactive_slot_application_prepared": False,
        },
        "required_reviews": [
            "Verify the pinned bootloader selects ota_0 with erased OTA data and this exact table; no boot proof has occurred.",
            "Review replacement of bootloader, table, NVS and OTA selection against this same-device full backup.",
            "Review power-loss recovery through USB; this plan is not atomic and does not provide automatic rollback.",
            "Verify unique OTA credential allocation, DHCP reservation, PSRAM boot test and the chosen AP policy before qualification.",
        ],
        "runtime_and_sensing_qualified": False,
        "restore_qualified": False,
    }
    check(
        plan["nvs_preservation"]["all_prior_values_preserved"],
        "existing_nvs_value_change_requires_separate_plan",
    )
    return plan, output, key


def run(args):
    context = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    output = create_directory(args.output)
    try:
        report, raw = verify_backup(args.backup)
        manifest, blobs = load_bundle(args.build_manifest, args.bundle_sha256)
        node = binding(
            args.node,
            report["identity"]["mac"],
            context.documents["nodes.json"],
            context.identity,
        )
        network = (
            None
            if args.network_settings is None
            else strict_json(
                private_path(args.network_settings, existing=True).read_bytes()
            )
        )
        plan, payloads, key = make_plan(
            report,
            raw,
            manifest,
            blobs,
            node,
            args.source_layout,
            network,
            site_context=context,
        )
        plan["build_manifest_sha256"] = args.bundle_sha256
        plan["planner_sha256"] = sha(Path(__file__).read_bytes())
        (output / "payloads").mkdir(mode=0o700)
        for name, data in payloads.items():
            save(output / "payloads" / name, data)
        save(output / "ota-key.private.txt", (key + "\n").encode())
        load_installation_context(
            args.site_context,
            args.site_context_sha256,
            args.installation_identity,
            args.installation_identity_sha256,
        )
        save(output / "plan.json", plan)
        return 0, plan["status"]
    except Exception as error:
        reason = (
            error.reason if isinstance(error, Blocked) else "input_or_validation_failed"
        )
        save(
            output / "blocked.json",
            {
                "schema_version": 1,
                "status": "blocked",
                "reason": reason,
                "details": error.details if isinstance(error, Blocked) else {},
                "error_type": type(error).__name__,
                "flash_write_authorized": False,
                "layout_changes_authorized": False,
                "required_action": "Review the named input or preservation decision; no installation plan was authorized.",
            },
        )
        return 1, reason


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--source-layout", choices=LAYOUTS, required=True)
    parser.add_argument("--network-settings", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", required=True, type=Path)
    parser.add_argument("--installation-identity-sha256", required=True)
    code, status = run(parser.parse_args())
    print(
        json.dumps(
            {"status": status, "device_written": False, "flash_write_authorized": False}
        )
    )
    raise SystemExit(code)


if __name__ == "__main__":
    main()
