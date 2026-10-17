#!/usr/bin/env python3
"""Explicitly inspected, reviewed, single app/NVS USB write; no full backup.

This separate workflow never changes the table, bootloader, OTA selection or
eFuses. Inspection resets only with --allow-reset; installation connects without
reset. Both leave the device in ROM/stub, including after an uncertain write.
No first boot, Wi-Fi, OTA, PSRAM memtest or sensing success is inferred here.
"""

import argparse
import contextlib
import hashlib
import importlib.metadata
import json
import math
import os
import re
import secrets
import stat
import struct
import traceback
import zlib
from datetime import datetime, timezone
from pathlib import Path

from backup import one_packet_window, snapshot, usb_ports
from fleetlib import (
    ESPT_VERSION,
    ROOT,
    binding,
    create_directory,
    inspect_application,
    load_installation_context,
    mac_address,
    nvs_tool,
    parse_partitions,
    private_path,
    public_key,
    require,
    save,
    sha,
)

SECTOR = 4096
FLASH_BYTES = 16 * 1024 * 1024
TABLE_OFFSET = 0x8000
INSPECT_SCHEMA = "ruview.direct-usb.inspection.v1"
CANDIDATE_SCHEMA = "ruview.direct-usb.candidate.v1"
REVIEW_SCHEMA = "ruview.direct-usb.review.v1"
STATUS_SCHEMA = "ruview.direct-usb.pre-status.v1"
INSPECT_FILES = {
    "table.bin": SECTOR,
    "nvs-before.bin": 0x6000,
    "otadata.bin": 0x2000,
    "ota_0-header.bin": SECTOR,
    "ota_1-header.bin": SECTOR,
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def floating(text):
        value = float(text)
        require(math.isfinite(value), "Nonfinite JSON value")
        return value

    def invalid(_):
        raise ValueError("Nonfinite JSON constant")

    return json.loads(
        raw, object_pairs_hook=pairs, parse_float=floating, parse_constant=invalid
    )


def read_file(path, limit, private=True):
    path = Path(path)
    require(
        not any(p.is_symlink() for p in (path, *path.parents)),
        "Symbolic file path refused",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Regular file required")
        require(
            not private or (info.st_uid == os.getuid() and info.st_mode & 0o077 == 0),
            "Private owned file required",
        )
        require(info.st_size <= limit, "File exceeds bound")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "File exceeds bound")
    return raw


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def tool_hashes(context):
    paths = (
        "firmware/fleet/direct_usb.py",
        "firmware/fleet/fleetlib.py",
        "firmware/fleet/backup.py",
        "firmware/provision-ota-key.py",
        "firmware/vendor/esp-idf-nvs/nvs_parser.py",
        "firmware/vendor/esp-idf-nvs/SOURCE.json",
        "scripts/site_context.py",
        "scripts/installation_identity.py",
    )
    result = {name: sha(read_file(ROOT / name, 2_000_000, False)) for name in paths}
    result["config/nodes.json"] = sha(context.raw["nodes.json"])
    result["installation-identity.json"] = sha(context.identity_raw)
    return result


def hardware(identity, expected_mac):
    require(
        identity["mac"] == mac_address(expected_mac)
        and identity["chip"] == "ESP32-S3"
        and type(identity["flash_bytes"]) is int
        and identity["flash_bytes"] == FLASH_BYTES
        and type(identity.get("embedded_psram_bytes")) is int
        and identity["embedded_psram_bytes"] == 8 * 1024 * 1024,
        "Only this exact MAC and observed S3 N16R8 are supported",
    )


def layout_parts(table):
    layout = parse_partitions(table, FLASH_BYTES, TABLE_OFFSET)
    require(layout["md5_verified"] is True, "Partition table MD5 required")
    parts = layout["partitions"]
    apps = [p for p in parts if p["type"] == 0]
    require(
        len(apps) == 2
        and {(p["name"], p["subtype"]) for p in apps}
        == {("ota_0", 0x10), ("ota_1", 0x11)},
        "Exactly two OTA apps and no factory/test app required",
    )
    nvs = [p for p in parts if p["type"] == 1 and p["subtype"] == 2]
    ota = [p for p in parts if p["type"] == 1 and p["subtype"] == 0]
    require(
        len(nvs) == len(ota) == 1
        and nvs[0]["bytes"] == 0x6000
        and ota[0]["bytes"] == 0x2000,
        "One unencrypted 24 KiB NVS and 8 KiB OTA metadata required",
    )
    require(
        not any(p["type"] == 1 and p["subtype"] == 4 for p in parts),
        "NVS encryption key partition requires separate review",
    )
    return layout, {p["name"]: p for p in apps}, nvs[0], ota[0]


def header_version(raw):
    require(
        len(raw) == SECTOR
        and raw[0] == 0xE9
        and struct.unpack_from("<I", raw, 32)[0] == 0xABCD5432,
        "Current app descriptor invalid",
    )
    version = raw[48:80].split(b"\0", 1)[0].decode("ascii")
    require(bool(re.fullmatch(r"[0-9A-Za-z._+-]{1,31}", version)), "Invalid version")
    return version


def timestamp(value):
    require(isinstance(value, str), "UTC string required")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(instant.tzinfo is not None, "UTC timezone required")
    return instant.astimezone(timezone.utc)


def boot_selection(raw, headers, current_version, report, pre_status=None):
    require(len(raw) == 0x2000, "OTA metadata length invalid")
    if raw == b"\xff" * 0x2000:
        require(
            isinstance(pre_status, dict), "Erased OTA metadata needs pre-USB evidence"
        )
        require(
            pre_status.get("schema") == STATUS_SCHEMA
            and type(pre_status.get("node_id")) is int
            and pre_status["node_id"] == report["node_id"]
            and pre_status.get("expected_mac") == report["expected_mac"],
            "Pre-USB evidence unit mismatch",
        )
        age = (
            timestamp(report["started_utc"]) - timestamp(pre_status["observed_utc"])
        ).total_seconds()
        status = pre_status["status"]
        require(
            0 <= age <= 600
            and status.get("version") == current_version
            and status.get("running_partition") == "ota_0"
            and status.get("next_partition") == "ota_1",
            "Pre-USB evidence stale or running app differs",
        )
        selected, rule = "ota_0", "erased_metadata_with_fresh_same_unit_running_ota0"
    else:
        entries = []
        for offset in (0, SECTOR):
            sector = raw[offset : offset + SECTOR]
            if sector == b"\xff" * SECTOR:
                continue
            seq, state, crc = struct.unpack_from("<I20xII", sector)
            require(
                0 < seq < 0xFFFFFFFF
                and state in (2, 0xFFFFFFFF)
                and zlib.crc32(sector[:4], 0xFFFFFFFF) == crc,
                "Ambiguous, invalid or pending OTA selection refused",
            )
            entries.append(seq)
        require(bool(entries), "No stable OTA selection")
        selected = "ota_" + str((max(entries) - 1) % 2)
        rule = "crc_valid_stable_two_slot_otadata"
    require(
        header_version(headers[selected]) == current_version,
        "Selected current application version differs",
    )
    return {"partition": selected, "basis": rule, "physical_boot_verified": False}


def validate_inspection(report, blobs):
    require(
        report.get("schema") == INSPECT_SCHEMA
        and report.get("complete") is True
        and report.get("flash_write_performed") is False
        and report.get("automatic_reboot_requested") is False,
        "Complete read-only inspection required",
    )
    require(type(report.get("node_id")) is int, "Integer node identity required")
    hardware(report["identity"], report["expected_mac"])
    require(
        report["security"]
        == {"secure_boot": False, "flash_encryption": False, "secure_download": False},
        "Unencrypted unrestricted download mode required",
    )
    require(set(blobs) == set(INSPECT_FILES), "Exact minimal inspection files required")
    require(
        all(len(blobs[k]) == size for k, size in INSPECT_FILES.items())
        and report["files_sha256"] == {k: sha(v) for k, v in blobs.items()},
        "Inspection bytes changed",
    )
    layout, apps, nvs, ota = layout_parts(blobs["table.bin"])
    require(report["layout"] == layout, "Inspection layout differs")
    selected = boot_selection(
        blobs["otadata.bin"],
        {name: blobs[name + "-header.bin"] for name in apps},
        report["current_version"],
        report,
        report.get("pre_usb_status"),
    )
    require(report["boot_selection"] == selected, "Boot selection evidence differs")
    require(
        set(report["app_slot_md5"]) == set(apps)
        and all(
            re.fullmatch(r"[0-9a-f]{32}", v) for v in report["app_slot_md5"].values()
        ),
        "Both original app partition digests required",
    )
    return apps[selected["partition"]], nvs, ota


def security(esp):
    result = {
        "secure_boot": bool(esp.get_secure_boot_enabled()),
        "flash_encryption": bool(esp.get_flash_encryption_enabled()),
        "secure_download": bool(esp.secure_download_mode),
    }
    require(not any(result.values()), "Device security mode requires separate review")
    return result


def read_exact(esp, offset, size):
    raw = esp.read_flash(offset, size)
    require(type(raw) is bytes and len(raw) == size, "Short flash read")
    return raw


def inspect_device(
    esp, node_id, expected_mac, current_version, started, pre_status=None
):
    identity = snapshot(esp)
    hardware(identity, expected_mac)
    secured = security(esp)
    table = read_exact(esp, TABLE_OFFSET, SECTOR)
    layout, apps, nvs, ota = layout_parts(table)
    blobs = {
        "table.bin": table,
        "nvs-before.bin": read_exact(esp, nvs["offset"], nvs["bytes"]),
        "otadata.bin": read_exact(esp, ota["offset"], ota["bytes"]),
        **{
            name + "-header.bin": read_exact(esp, p["offset"], SECTOR)
            for name, p in apps.items()
        },
    }
    # Digests transfer no complete application/full-flash bytes. They detect an
    # app change between inspection and the reviewed single write.
    report = {
        "schema": INSPECT_SCHEMA,
        "started_utc": started,
        "node_id": node_id,
        "expected_mac": expected_mac,
        "identity": identity,
        "security": secured,
        "current_version": current_version,
        "layout": layout,
        "pre_usb_status": pre_status,
        "files_sha256": {k: sha(v) for k, v in blobs.items()},
        "app_slot_md5": {
            name: esp.flash_md5sum(p["offset"], p["bytes"]).lower()
            for name, p in apps.items()
        },
        "complete": True,
        "flash_write_performed": False,
        "automatic_reboot_requested": False,
        "full_backup_created": False,
    }
    report["boot_selection"] = boot_selection(
        blobs["otadata.bin"],
        {name: blobs[name + "-header.bin"] for name in apps},
        current_version,
        report,
        pre_status,
    )
    validate_inspection(report, blobs)
    nvs_tool().logical_values(blobs["nvs-before.bin"])
    return report, blobs


def prepared_nvs(raw, node_id, key=None, *, site_context):
    require(len(raw) == 0x6000, "Only 24 KiB NVS supported")
    require(
        type(node_id) is int and 1 <= node_id <= 10, "Explicit node identity required"
    )
    tool = nvs_tool()
    old = tool.logical_values(raw)
    require(
        old.get(("csi_cfg", "node_id")) in (None, ("uint8_t", node_id)),
        "Existing NVS node identity mismatch",
    )
    for name, kind in (
        ("ssid", "string"),
        ("password", "string"),
        ("target_ip", "string"),
        ("target_port", "uint16_t"),
    ):
        require(
            ("csi_cfg", name) in old and old[("csi_cfg", name)][0] == kind,
            "Existing network configuration required",
        )
    existing = old.get(("security", "ota_psk"))
    if existing is not None:
        require(existing[0] == "string", "Existing OTA key type unsupported")
        chosen = existing[1]
        require(key is None or key == chosen, "Existing OTA key must be preserved")
    else:
        chosen = key if key is not None else secrets.token_hex(32)
    # Firmware accepts an existing nonempty string (up to its 64-byte key limit),
    # not only newly generated hexadecimal keys. Never rotate a valid old key.
    require(
        isinstance(chosen, str)
        and 1 <= len(chosen.encode("utf-8")) <= 64
        and all(ord(c) >= 32 and ord(c) != 127 for c in chosen),
        "OTA key is not representable without alteration",
    )
    require(
        existing is not None or re.fullmatch(r"[0-9a-f]{64}", chosen),
        "New OTA key must be 32 random bytes encoded as hex",
    )
    trusted = public_key(site_context)
    require(
        old.get(("csi_cfg", "wasm_pubkey")) in (None, ("blob", trusted)),
        "Existing signing trust key differs",
    )
    require(
        old.get(("csi_cfg", "wasm_verify")) in (None, ("uint8_t", 0), ("uint8_t", 1)),
        "Existing WASM verification type invalid",
    )
    desired = dict(old)
    desired.update(
        {
            # The enclosing candidate/review binds this explicit ID to the
            # inspected physical MAC and inventory; never replace a stored ID.
            ("csi_cfg", "node_id"): ("uint8_t", node_id),
            ("security", "ota_psk"): ("string", chosen),
            ("csi_cfg", "wasm_pubkey"): ("blob", trusted),
            ("csi_cfg", "wasm_verify"): ("uint8_t", 1),
        }
    )
    changed = sorted(k for k, v in desired.items() if old.get(k) != v)
    result = tool.generate(desired, len(raw)) if changed else raw
    require(
        len(result) == len(raw) and tool.logical_values(result) == desired,
        "NVS round-trip preservation failed",
    )
    require(
        all(desired[k] == v for k, v in old.items() if k != ("csi_cfg", "wasm_verify")),
        "Unexpected existing NVS value change",
    )
    return (
        result,
        chosen,
        {
            "ota_key_preserved": existing is not None,
            "changed_keys_without_values": [list(k) for k in changed],
            "existing_logical_values": len(old),
            "signing_public_key_sha256": sha(trusted),
        },
    )


def candidate_data(report, blobs, app, app_sha, version, key, *, site_context):
    slot, nvs, _ = validate_inspection(report, blobs)
    require(sha(app) == app_sha and len(app) > 0, "Application digest mismatch")
    inspect_application(app, version)
    end = ((len(app) + SECTOR - 1) // SECTOR) * SECTOR
    require(end <= slot["bytes"], "Application sectors exceed actual selected slot")
    _, apps, _, _ = layout_parts(blobs["table.bin"])
    require(
        all(end <= part["bytes"] for part in apps.values()),
        "Application sectors must also fit the inactive slot for future OTA",
    )
    encoded, chosen, nvs_metadata = prepared_nvs(
        blobs["nvs-before.bin"], report["node_id"], key, site_context=site_context
    )
    payloads = {
        "application-sectors.bin": app.ljust(end, b"\xff"),
        "nvs-prepared.bin": encoded,
    }
    writes = [
        {
            "file": "application-sectors.bin",
            "offset": slot["offset"],
            "bytes": end,
            "sha256": sha(payloads["application-sectors.bin"]),
        }
    ]
    if encoded != blobs["nvs-before.bin"]:
        writes.append(
            {
                "file": "nvs-prepared.bin",
                "offset": nvs["offset"],
                "bytes": nvs["bytes"],
                "sha256": sha(encoded),
            }
        )
    writes.sort(key=lambda p: p["offset"])
    candidate = {
        "schema": CANDIDATE_SCHEMA,
        "node_id": report["node_id"],
        "expected_mac": report["expected_mac"],
        "hardware_profile": "home-s3-n16r8",
        "current_version": report["current_version"],
        "application_sha256": app_sha,
        "application_bytes": len(app),
        "application_version": version,
        "application_sector_bytes": end,
        "ota_slot_bytes": {name: part["bytes"] for name, part in apps.items()},
        "image_fits_both_ota_slots": True,
        "boot_selection": report["boot_selection"],
        "writes": writes,
        "nvs": nvs_metadata,
        "nvs_sha256": sha(encoded),
        "tool_hashes": tool_hashes(site_context),
        "flash_write_authorized": False,
        "full_backup_created": False,
        "automatic_reboot": False,
        "physical_boot_verified": False,
        "preservation_scope": "Existing logical NVS except explicit wasm_verify enable; no writes to bootloader/table/otadata/other partitions",
    }
    return candidate, payloads, chosen


def load_inspection(directory):
    directory = private_path(directory, existing=True)
    report = strict_json(read_file(directory / "inspection.json", 100_000))
    blobs = {
        name: read_file(directory / name, size) for name, size in INSPECT_FILES.items()
    }
    validate_inspection(report, blobs)
    return report, blobs


def prepare(args):
    site = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    report, blobs = load_inspection(args.inspection)
    require(
        report["node_id"] == args.node
        and report["expected_mac"] == mac_address(args.expected_mac),
        "Preparation unit mismatch",
    )
    binding(args.node, args.expected_mac, site.documents["nodes.json"], site.identity)
    app = read_file(args.firmware, FLASH_BYTES, False)
    candidate, payloads, key = candidate_data(
        report, blobs, app, args.sha256, args.version, None, site_context=site
    )
    load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    output = private_path(args.output, existing=True)
    for name, raw in {
        **blobs,
        **payloads,
        "application.bin": app,
        "ota-key.private.txt": key.encode(),
    }.items():
        save(output / name, raw)
    save(output / "inspection.json", report)
    candidate["inspection_sha256"] = sha(read_file(output / "inspection.json", 100_000))
    save(output / "candidate.json", candidate)
    sync_directory(output)
    return {
        "prepared": True,
        "node_id": args.node,
        "candidate_sha256": sha(read_file(output / "candidate.json", 100_000)),
        "flash_write_performed": False,
    }


def reviewed_context(
    review_path,
    *,
    site_context,
    site_context_sha256,
    installation_identity,
    installation_identity_sha256,
):
    site = load_installation_context(
        site_context,
        site_context_sha256,
        installation_identity,
        installation_identity_sha256,
    )
    review = strict_json(read_file(private_path(review_path, existing=True), 100_000))
    require(
        review.get("schema") == REVIEW_SCHEMA
        and review.get("coordinator_approved") is True
        and review.get("hardware_build_profile_reviewed") is True,
        "Explicit per-unit build and candidate review required",
    )
    path = private_path(Path(review["candidate_file"]), existing=True)
    require(path.name == "candidate.json", "Canonical candidate filename required")
    raw = read_file(path, 100_000)
    require(sha(raw) == review["candidate_sha256"], "Reviewed candidate changed")
    candidate = strict_json(raw)
    report, blobs = load_inspection(path.parent)
    app = read_file(path.parent / "application.bin", FLASH_BYTES)
    key = read_file(path.parent / "ota-key.private.txt", 64).decode("utf-8")
    calculated, payloads, _ = candidate_data(
        report,
        blobs,
        app,
        candidate["application_sha256"],
        candidate["application_version"],
        key,
        site_context=site,
    )
    calculated["inspection_sha256"] = sha(
        read_file(path.parent / "inspection.json", 100_000)
    )
    require(
        candidate == calculated,
        "Candidate differs from cached evidence/recomputed writes",
    )
    for field in (
        "node_id",
        "expected_mac",
        "application_sha256",
        "application_version",
        "hardware_profile",
    ):
        require(
            type(review.get(field)) is type(candidate[field])
            and review[field] == candidate[field],
            "Reviewed unit/application/profile mismatch",
        )
    require(
        review.get("tool_hashes") == candidate["tool_hashes"],
        "Reviewed tool hashes differ",
    )
    for name, data in payloads.items():
        require(
            read_file(path.parent / name, FLASH_BYTES) == data,
            "Prepared payload changed",
        )
    binding(
        candidate["node_id"],
        candidate["expected_mac"],
        site.documents["nodes.json"],
        site.identity,
    )
    load_installation_context(
        site_context,
        site_context_sha256,
        installation_identity,
        installation_identity_sha256,
    )
    return {
        "candidate": candidate,
        "candidate_sha256": sha(raw),
        "directory": path.parent,
        "report": report,
        "blobs": blobs,
        "payloads": payloads,
    }


def attempt_marker(context):
    # Moving/reformatting a review cannot re-arm the same canonical candidate.
    return context["directory"] / "direct-usb-attempt.json"


def reserve_attempt(context):
    marker = attempt_marker(context)
    save(
        marker,
        {
            "candidate_sha256": context["candidate_sha256"],
            "expected_mac": context["candidate"]["expected_mac"],
            "status": "reserved_outcome_may_be_unknown",
            "reserved_utc": utc_now(),
        },
    )
    sync_directory(marker.parent)


def write_once(esp, context, writer, reserve, result):
    candidate, report, blobs = context["candidate"], context["report"], context["blobs"]
    hardware(snapshot(esp), candidate["expected_mac"])
    require(security(esp) == report["security"], "Security state changed")
    slot, nvs, ota = validate_inspection(report, blobs)
    _, apps, _, _ = layout_parts(blobs["table.bin"])
    ranges = {
        "table.bin": (TABLE_OFFSET, SECTOR),
        "nvs-before.bin": (nvs["offset"], nvs["bytes"]),
        "otadata.bin": (ota["offset"], ota["bytes"]),
        **{name + "-header.bin": (p["offset"], SECTOR) for name, p in apps.items()},
    }
    for name, (offset, size) in ranges.items():
        require(
            read_exact(esp, offset, size) == blobs[name],
            "Live minimal inspection changed; obtain a new inspection",
        )
    for name, p in apps.items():
        require(
            esp.flash_md5sum(p["offset"], p["bytes"]).lower()
            == report["app_slot_md5"][name],
            "Live app partition changed",
        )
    blocks = []
    for write in candidate["writes"]:
        raw = context["payloads"][write["file"]]
        part = slot if write["file"] == "application-sectors.bin" else nvs
        require(
            write["offset"] == part["offset"]
            and len(raw) == write["bytes"] <= part["bytes"]
            and len(raw) % SECTOR == 0
            and sha(raw) == write["sha256"],
            "Write range or payload mismatch",
        )
        blocks.append((write["offset"], raw))
    require(
        len(blocks) in (1, 2) and len({offset for offset, _ in blocks}) == len(blocks),
        "Unexpected write ranges",
    )
    import esptool.loader

    # The pinned loader has two independent retry layers: whole-image reconnect
    # and per-block FatalError retries. Neither may repeat a mutation here.
    esp.WRITE_FLASH_ATTEMPTS = 1
    esptool.loader.WRITE_BLOCK_ATTEMPTS = 1
    require(
        esp.WRITE_FLASH_ATTEMPTS == 1 and esptool.loader.WRITE_BLOCK_ATTEMPTS == 1,
        "Image and block write retries must be disabled",
    )
    reserve()
    result["write_attempted"] = True
    writer(
        esp,
        blocks,
        flash_size="keep",
        flash_mode="keep",
        flash_freq="keep",
        compress=True,
    )
    for offset, raw in blocks:
        require(
            esp.flash_md5sum(offset, len(raw)).lower() == hashlib.md5(raw).hexdigest(),
            "Written sector readback mismatch; no retry",
        )
    require(
        read_exact(esp, TABLE_OFFSET, SECTOR) == blobs["table.bin"]
        and read_exact(esp, ota["offset"], ota["bytes"]) == blobs["otadata.bin"],
        "Table or OTA metadata changed",
    )
    actual_nvs = read_exact(esp, nvs["offset"], nvs["bytes"])
    require(
        actual_nvs == context["payloads"]["nvs-prepared.bin"], "NVS readback mismatch"
    )
    for name, p in apps.items():
        if name != slot["name"]:
            require(
                esp.flash_md5sum(p["offset"], p["bytes"]).lower()
                == report["app_slot_md5"][name],
                "Other app partition changed",
            )
    result.update(
        write_verified=True,
        boot_selection_bytes_preserved=True,
        nvs_bytes_verified=True,
        other_app_unchanged=True,
    )


def device_action(args, context=None):
    site = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    require(importlib.metadata.version("esptool") == ESPT_VERSION, "Use esptool 5.1.0")
    require(
        args.port in {p["port"] for p in usb_ports()},
        "Explicit observed USB port required",
    )
    if args.action == "inspect":
        require(args.allow_reset, "Inspection requires explicit --allow-reset")
        node, mac = args.node, mac_address(args.expected_mac)
    else:
        node, mac = (
            context["candidate"]["node_id"],
            context["candidate"]["expected_mac"],
        )
        require(
            not attempt_marker(context).exists(), "Candidate attempt already reserved"
        )
    binding(node, mac, site.documents["nodes.json"], site.identity)
    output = private_path(args.output, existing=True)
    save(output / "serial.private.log", b"")
    result = {
        "schema": "ruview.direct-usb.result.v1",
        "started_utc": utc_now(),
        "node_id": node,
        "expected_mac": mac,
        "write_attempted": False,
        "write_verified": False,
        "complete": False,
        "automatic_reboot_requested": False,
        "physical_boot_verified": False,
        "full_backup_created": False,
    }
    esp = None
    with (
        (output / "serial.private.log").open("a") as log,
        contextlib.redirect_stdout(log),
        contextlib.redirect_stderr(log),
    ):
        try:
            import esptool

            load_installation_context(
                args.site_context,
                args.site_context_sha256,
                args.installation_identity,
                args.installation_identity_sha256,
            )
            esp = esptool.detect_chip(
                args.port,
                connect_mode="default-reset"
                if args.action == "inspect"
                else "no-reset",
                connect_attempts=1,
            )
            require(
                esp.CHIP_NAME == "ESP32-S3"
                and ":".join(f"{x:02x}" for x in esp.read_mac()) == mac,
                "Live chip/MAC mismatch",
            )
            security(esp)
            esp = esp.run_stub()
            esptool.attach_flash(esp)
            esp.change_baud(230400)
            one_packet_window(esp)
            if args.action == "inspect":
                pre = (
                    strict_json(read_file(args.pre_usb_status, 100_000))
                    if args.pre_usb_status
                    else None
                )
                report, blobs = inspect_device(
                    esp, node, mac, args.current_version, result["started_utc"], pre
                )
                for name, data in blobs.items():
                    save(output / name, data)
                save(output / "inspection.json", report)
            else:
                result["candidate_sha256"] = context["candidate_sha256"]

                def reserve():
                    current = load_installation_context(
                        args.site_context,
                        args.site_context_sha256,
                        args.installation_identity,
                        args.installation_identity_sha256,
                    )
                    require(
                        context["candidate"]["tool_hashes"] == tool_hashes(current),
                        "Tools or approved inventory changed before reservation",
                    )
                    reserve_attempt(context)

                write_once(
                    esp,
                    context,
                    esptool.cmds.write_flash,
                    reserve,
                    result,
                )
            load_installation_context(
                args.site_context,
                args.site_context_sha256,
                args.installation_identity,
                args.installation_identity_sha256,
            )
            result["complete"] = True
        except (Exception, KeyboardInterrupt, SystemExit) as error:
            # Cancellation still needs a durable uncertain-write record and
            # serial close without reset, just like a device/parser failure.
            result["error_type"] = type(error).__name__
            traceback.print_exc()  # Private log only: parsers can mention NVS data.
        finally:
            if esp is not None:
                try:
                    esp._port.close()  # Never reset, especially after an uncertain write.
                except Exception as error:
                    result["close_error_type"] = type(error).__name__
                    result["complete"] = False
    result["finished_utc"] = utc_now()
    save(output / "result.json", result)
    sync_directory(output)
    return result


def public_status(result):
    """Only boolean outcomes leave the private evidence directory."""
    return {
        "prepared": result.get("prepared") is True,
        "complete": result.get("complete") is True,
        "write_attempted": result.get("write_attempted") is True,
        "write_verified": result.get("write_verified") is True,
        "details": "See private evidence in the selected output directory",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    inspect = actions.add_parser("inspect")
    inspect.add_argument("--port", required=True)
    inspect.add_argument("--node", type=int, required=True)
    inspect.add_argument("--expected-mac", required=True)
    inspect.add_argument("--current-version", required=True)
    inspect.add_argument("--pre-usb-status", type=Path)
    inspect.add_argument("--allow-reset", action="store_true")
    inspect.add_argument("--output", type=Path, required=True)
    plan = actions.add_parser("prepare")
    plan.add_argument("--inspection", type=Path, required=True)
    plan.add_argument("--node", type=int, required=True)
    plan.add_argument("--expected-mac", required=True)
    plan.add_argument("--firmware", type=Path, required=True)
    plan.add_argument("--sha256", required=True)
    plan.add_argument("--version", required=True)
    plan.add_argument("--output", type=Path, required=True)
    install = actions.add_parser("install")
    install.add_argument("--reviewed-plan", type=Path, required=True)
    install.add_argument("--port", required=True)
    install.add_argument("--output", type=Path, required=True)
    for action in (inspect, plan, install):
        action.add_argument("--site-context", type=Path, required=True)
        action.add_argument("--site-context-sha256", required=True)
        action.add_argument("--installation-identity", required=True, type=Path)
        action.add_argument("--installation-identity-sha256", required=True)
    args = parser.parse_args()
    output = None
    try:
        load_installation_context(
            args.site_context,
            args.site_context_sha256,
            args.installation_identity,
            args.installation_identity_sha256,
        )
        output = create_directory(args.output)
        if args.action == "prepare":
            result = prepare(args)
        else:
            context = (
                reviewed_context(
                    args.reviewed_plan,
                    site_context=args.site_context,
                    site_context_sha256=args.site_context_sha256,
                    installation_identity=args.installation_identity,
                    installation_identity_sha256=args.installation_identity_sha256,
                )
                if args.action == "install"
                else None
            )
            result = device_action(args, context)
        status = public_status(result)
        print(json.dumps(status, indent=2))
        return 0 if status["prepared"] or status["complete"] else 1
    except Exception as error:
        # Offline validation may involve private NVS. Never expose error values.
        if output is not None:
            try:
                save(output / "failure.private.log", traceback.format_exc().encode())
                sync_directory(output)
            except Exception:
                # A full/unwritable private volume must not expose the chained
                # original exception (which may contain a parsed NVS value).
                pass
        print(
            json.dumps(
                {
                    "complete": False,
                    "error_type": type(error).__name__,
                    "write_outcome": "not_determined_see_private_evidence",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
