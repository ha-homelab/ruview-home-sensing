#!/usr/bin/env python3
"""One reviewed application-only USB write, after exact private backup checks.

There is no erase-all, NVS/layout write, inactive-slot selection or retry path.
An uncertain write is left for operator recovery; never automatically repeated.
"""

import argparse
import contextlib
import hashlib
import importlib.metadata
import json
import os
import struct
import time
import zlib
from pathlib import Path

from backup import usb_ports
from fleetlib import (
    ESPT_VERSION,
    binding,
    create_directory,
    inspect_application,
    load_installation_context,
    private_path,
    require,
    save,
    sha,
    verify_backup,
)


def active_ota(raw):
    require(len(raw) >= 0x2000, "OTA metadata requires two sectors")
    valid = []
    for offset in (0, 0x1000):
        seq, state, crc = struct.unpack_from("<I20xII", raw, offset)
        if (
            0 < seq < 0xFFFFFFFF
            and state in (0, 1, 2, 0xFFFFFFFF)
            and zlib.crc32(raw[offset : offset + 4], 0xFFFFFFFF) == crc
        ):
            valid.append(seq)
    require(valid, "No validated OTA selection; no factory/layout assumption")
    return "ota_" + str((max(valid) - 1) % 2)


def approved_application(plan, backup, raw, data):
    require(
        plan.get("schema_version") == 1 and type(plan["schema_version"]) is int,
        "Expected reviewed plan schema1",
    )
    require(
        plan.get("action") == "application_only_usb"
        and plan.get("coordinator_approved") is True,
        "Explicit coordinator-approved application-only plan required",
    )
    require(
        plan.get("node_id") == backup["node_id"]
        and plan.get("expected_mac") == backup["identity"]["mac"],
        "Plan/backup unit mismatch",
    )
    require(
        plan.get("backup_sha256") == backup["flash_sha256"],
        "Plan recovery backup changed",
    )
    require(
        sha(data) == plan.get("application_sha256"), "Plan application digest changed"
    )
    parts = backup["layout"]["partitions"]
    ota_slots = [p for p in parts if p["type"] == 0 and 0x10 <= p["subtype"] <= 0x1F]
    require(
        len(ota_slots) == 2
        and {(p["name"], p["subtype"]) for p in ota_slots}
        == {("ota_0", 0x10), ("ota_1", 0x11)},
        "Only the reviewed two-slot ota_0/ota_1 layout is supported",
    )
    metadata = [p for p in parts if p["type"] == 1 and p["subtype"] == 0]
    require(len(metadata) == 1, "One verified OTA metadata partition required")
    p = metadata[0]
    active = active_ota(raw[p["offset"] : p["offset"] + p["bytes"]])
    require(
        plan.get("running_partition") == active,
        "Reviewed running partition differs from saved OTA selection",
    )
    slots = [
        p
        for p in parts
        if p["type"] == 0
        and p["name"] == active
        and p["subtype"] == 0x10 + int(active[-1])
    ]
    require(
        len(slots) == 1 and 0 < len(data) <= slots[0]["bytes"],
        "Application does not fit the verified running slot",
    )
    p = slots[0]
    require(
        plan.get("application_offset") == p["offset"],
        "No arbitrary write offset allowed",
    )
    header = raw[p["offset"] : p["offset"] + 4096]
    require(
        header[0] == 0xE9 and struct.unpack_from("<I", header, 32)[0] == 0xABCD5432,
        "Saved running app header invalid",
    )
    require(
        header[48:80].split(b"\0", 1)[0].decode("ascii")
        == plan.get("expected_current_version"),
        "Saved running application version changed",
    )
    identity = backup["identity"]
    require(
        plan.get("hardware_profile") == "home-s3-n16r8"
        and identity["chip"] == "ESP32-S3"
        and identity["flash_bytes"] == 16 * 1024 * 1024
        and identity.get("embedded_psram_bytes") == 8 * 1024 * 1024,
        "Only the reviewed S3 N16R8 hardware profile is supported",
    )
    return p


def write_once(esp, plan, backup, raw, data, writer, reserve):
    slot = approved_application(plan, backup, raw, data)
    mac = ":".join(f"{part:02x}" for part in esp.read_mac())
    require(
        mac == plan["expected_mac"] and esp.CHIP_NAME == backup["identity"]["chip"],
        "Live chip/MAC mismatch",
    )
    require(
        (1 << ((esp.flash_id() >> 16) & 255)) == backup["identity"]["flash_bytes"],
        "Live flash capacity changed",
    )
    # Full recorded bytes must still be current. A normal NVS change is a stop
    # for a fresh backup/review, not permission to overwrite newer state.
    for chunk in backup["chunks"]:
        off, size = chunk["offset"], chunk["bytes"]
        require(
            esp.flash_md5sum(off, size).lower()
            == hashlib.md5(raw[off : off + size]).hexdigest(),
            "Live flash changed since recovery backup",
        )
    offset = slot["offset"]
    end = offset + ((len(data) + 4095) // 4096) * 4096
    require(
        end <= offset + slot["bytes"], "Sector erase would cross application partition"
    )
    # esptool 5.1.0 otherwise reconnects and retries a whole image after a
    # SerialException. One durable reservation authorizes exactly one attempt.
    esp.WRITE_FLASH_ATTEMPTS = 1
    require(esp.WRITE_FLASH_ATTEMPTS == 1, "esptool write retries must be disabled")
    reserve()  # Durable one-attempt marker must precede the only write call.
    writer(
        esp,
        [(offset, data)],
        flash_size="keep",
        flash_mode="keep",
        flash_freq="keep",
        compress=True,
    )
    require(
        esp.flash_md5sum(offset, len(data)).lower() == hashlib.md5(data).hexdigest(),
        "Written application digest mismatch; no retry",
    )
    for off, size in ((0, offset), (end, len(raw) - end)):
        if size:
            require(
                esp.flash_md5sum(off, size).lower()
                == hashlib.md5(raw[off : off + size]).hexdigest(),
                "Unexpected change outside application sectors; no retry",
            )
    return {
        "application_offset": offset,
        "application_bytes": len(data),
        "application_sha256": sha(data),
        "device_digest_verified": True,
        "outside_application_sectors_unchanged": True,
        "boot_and_sensing_qualified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed-plan", type=Path, required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    require(importlib.metadata.version("esptool") == ESPT_VERSION, "Use esptool5.1.0")
    plan_path = private_path(args.reviewed_plan, existing=True)
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    backup, raw = verify_backup(plan["backup_directory"])
    data = Path(plan["application_file"]).read_bytes()
    approved_application(plan, backup, raw, data)
    binding(
        plan["node_id"],
        plan["expected_mac"],
        context.documents["nodes.json"],
        context.identity,
    )
    require(
        args.port in {p["port"] for p in usb_ports()},
        "Explicit observed USB port required",
    )
    inspect_application(data, plan["application_version"])
    marker = plan_path.parent / ("application-attempt-" + sha(plan_raw) + ".json")
    require(
        not marker.exists(), "This reviewed plan already consumed its one write attempt"
    )
    output = create_directory(args.output)
    save(output / "serial.log", b"")
    result = {
        "plan_sha256": sha(plan_raw),
        "write_attempted": False,
        "write_verified": False,
    }
    esp = None

    def reserve():
        load_installation_context(
            args.site_context,
            args.site_context_sha256,
            args.installation_identity,
            args.installation_identity_sha256,
        )
        save(
            marker,
            {
                "plan_sha256": sha(plan_raw),
                "mac": plan["expected_mac"],
                "status": "attempt_reserved_outcome_may_be_unknown",
            },
        )
        directory_fd = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        result["write_attempted"] = True

    with (
        (output / "serial.log").open("a") as log,
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
            esp = esptool.detect_chip(args.port, connect_attempts=2)
            require(
                ":".join(f"{x:02x}" for x in esp.read_mac()) == plan["expected_mac"],
                "Connected MAC mismatch",
            )
            require(
                not esp.get_secure_boot_enabled()
                and not esp.get_flash_encryption_enabled(),
                "Secure boot/encryption requires separate review",
            )
            esp = esp.run_stub()
            esptool.attach_flash(esp)
            esp.change_baud(230400)
            result.update(
                write_once(
                    esp, plan, backup, raw, data, esptool.cmds.write_flash, reserve
                )
            )
            result["write_verified"] = True
        except BaseException as error:
            result["error_type"] = type(error).__name__
        finally:
            if esp is not None:
                try:
                    if result["write_verified"] or not result["write_attempted"]:
                        esp._port.baudrate = 115200
                        esp.hard_reset()
                        result["application_reset_requested"] = True
                        if result["write_verified"]:
                            esp._port.timeout = 0.5
                            end = time.monotonic() + 20
                            boot = bytearray()
                            while time.monotonic() < end:
                                boot.extend(esp._port.read(1024))
                            save(output / "boot.private.log", bytes(boot))
                except Exception as error:
                    result["reset_error_type"] = type(error).__name__
                finally:
                    esp._port.close()
    save(output / "result.json", result)
    print(json.dumps(result, indent=2))
    raise SystemExit(
        0 if result["write_verified"] and "reset_error_type" not in result else 1
    )


if __name__ == "__main__":
    main()
