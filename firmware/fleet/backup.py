#!/usr/bin/env python3
"""Inspect or back up one explicitly selected USB receiver; never write flash.

Opening a selected port resets the board and runs the esptool RAM stub. The
operator must first identify the physical unit; listing ports does neither.
"""

import argparse
import contextlib
import importlib.metadata
import json
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from fleetlib import (
    ESPT_VERSION,
    binding,
    create_directory,
    embedded_psram,
    load_installation_context,
    mac_address,
    parse_partitions,
    require,
    save,
    sha,
)


def usb_ports():
    from serial.tools import list_ports

    return [
        {
            "port": p.device,
            "vid": p.vid,
            "pid": p.pid,
            "serial_number": p.serial_number,
            "description": p.description,
            "location": p.location,
        }
        for p in list_ports.comports()
        if p.vid in (0x303A, 0x10C4, 0x1A86, 0x0403)
    ]


def one_packet_window(esp):
    original = esp.check_command

    def check(description, op=None, data=b"", *args, **kwargs):
        if op == esp.ESP_CMDS["READ_FLASH"]:
            offset, length, block, _ = struct.unpack("<IIII", data)
            data = struct.pack("<IIII", offset, length, block, 1)
        return original(description, op, data, *args, **kwargs)

    esp.check_command = check


def snapshot(esp):
    features = esp.get_chip_features()
    flash_id = esp.flash_id()
    capacity_code = (flash_id >> 16) & 255
    require(
        19 <= capacity_code <= 27,
        "Unknown JEDEC flash capacity; no guessed backup size",
    )
    return {
        "chip": esp.CHIP_NAME,
        "description": esp.get_chip_description(),
        "mac": ":".join(f"{part:02x}" for part in esp.read_mac()),
        "features": features,
        "embedded_psram_bytes": embedded_psram(features),
        "external_psram_bytes": None,
        "psram_boot_memtest_verified": False,
        "flash_id": flash_id,
        "flash_bytes": 1 << capacity_code,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("list-ports", "identify", "backup"))
    parser.add_argument("--port")
    parser.add_argument("--node", type=int)
    parser.add_argument("--expected-mac")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--partition-offset", type=lambda text: int(text, 0))
    parser.add_argument(
        "--allow-reset",
        action="store_true",
        help="The physically identified receiver may reset into its ROM/stub, then back to its application",
    )
    parser.add_argument("--site-context", type=Path)
    parser.add_argument("--site-context-sha256")
    parser.add_argument("--installation-identity", type=Path)
    parser.add_argument("--installation-identity-sha256")
    args = parser.parse_args()
    context = None
    if args.action != "list-ports":
        if any(
            value is None
            for value in (
                args.site_context,
                args.site_context_sha256,
                args.installation_identity,
                args.installation_identity_sha256,
            )
        ):
            parser.error("Device actions require an independently pinned site context")
        context = load_installation_context(
            args.site_context,
            args.site_context_sha256,
            args.installation_identity,
            args.installation_identity_sha256,
        )
    require(
        importlib.metadata.version("esptool") == ESPT_VERSION,
        "Use the pinned esptool 5.1.0 environment",
    )
    ports = usb_ports()
    if args.action == "list-ports":
        print(json.dumps(ports, indent=2))
        return
    require(
        args.port in {p["port"] for p in ports},
        "Select a currently observed USB candidate port explicitly",
    )
    require(
        args.allow_reset
        and args.output
        and type(args.node) is int
        and 1 <= args.node <= 10,
        "Explicit node, private output and reset acknowledgment required",
    )
    inventory = context.documents["nodes.json"]
    if args.expected_mac:
        binding(args.node, mac_address(args.expected_mac), inventory, context.identity)
    require(
        args.action != "backup" or args.expected_mac,
        "Backup requires the separately identified station MAC",
    )
    require(
        args.action != "backup"
        or type(args.partition_offset) is int
        and args.partition_offset >= 0x8000
        and args.partition_offset % 0x1000 == 0,
        "Backup requires an explicitly reviewed partition-table offset",
    )
    output = create_directory(args.output)
    report = {
        "schema_version": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "esptool_version": ESPT_VERSION,
        "port": args.port,
        "node_id": args.node,
        "flash_write_performed": False,
        "complete": False,
        "chunks": [],
    }
    esp, failure = None, None
    from fleetlib import private_path

    log = private_path(output / "serial.log")
    from fleetlib import save as save_bytes

    save_bytes(log, b"")
    with (
        log.open("a") as stream,
        contextlib.redirect_stdout(stream),
        contextlib.redirect_stderr(stream),
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
            observed_mac = ":".join(f"{part:02x}" for part in esp.read_mac())
            node = binding(args.node, observed_mac, inventory, context.identity)
            require(
                not args.expected_mac or observed_mac == args.expected_mac,
                "USB board MAC does not match the selected unit",
            )
            # Encrypted/secure-download recovery is a separate workflow. Never
            # burn eFuses, override flash voltage or alter security registers.
            require(
                not esp.get_secure_boot_enabled()
                and not esp.get_flash_encryption_enabled(),
                "Secure boot/encryption requires a separate recovery review",
            )
            esp = esp.run_stub()
            esptool.attach_flash(esp)
            identity = snapshot(esp)
            require(identity["mac"] == observed_mac, "Identity changed after RAM stub")
            report.update(identity=identity, binding=node)
            if args.action == "backup":
                require(
                    args.partition_offset + 0x1000 <= identity["flash_bytes"],
                    "Partition-table offset exceeds flash",
                )
                esp.change_baud(230400)
                one_packet_window(esp)
                report.update(
                    baud=230400,
                    receive_window=1,
                    partition_table_offset=args.partition_offset,
                )
                chunks = output / "chunks"
                chunks.mkdir(mode=0o700)
                started = time.monotonic()
                data = bytearray()
                for offset in range(0, identity["flash_bytes"], 0x40000):
                    require(
                        time.monotonic() - started <= 7200,
                        "Backup deadline exceeded; partial files retained",
                    )
                    size = min(0x40000, identity["flash_bytes"] - offset)
                    chunk = esp.read_flash(
                        offset, size
                    )  # Stub verifies its MD5 for every read.
                    require(len(chunk) == size, "Short flash read")
                    save(chunks / f"{offset:08x}.bin", chunk)
                    report["chunks"].append(
                        {
                            "offset": offset,
                            "bytes": size,
                            "sha256": sha(chunk),
                            "device_md5_verified": True,
                        }
                    )
                    data.extend(chunk)
                    print(
                        f"Read and verified {len(data)}/{identity['flash_bytes']} bytes",
                        flush=True,
                    )
                save(output / "flash.bin", bytes(data))
                report["flash_sha256"] = sha(data)
                raw_table = bytes(
                    data[args.partition_offset : args.partition_offset + 0x1000]
                )
                save(output / "partition-table.bin", raw_table)
                report["layout"] = parse_partitions(
                    raw_table, len(data), args.partition_offset
                )
                for part in report["layout"]["partitions"]:
                    if part["type"] == 1 and part["subtype"] in (0, 2):
                        save(
                            output / (part["name"] + ".bin"),
                            bytes(
                                data[part["offset"] : part["offset"] + part["bytes"]]
                            ),
                        )
                report["elapsed_seconds"] = time.monotonic() - started
            load_installation_context(
                args.site_context,
                args.site_context_sha256,
                args.installation_identity,
                args.installation_identity_sha256,
            )
            report["complete"] = True
        except BaseException as error:
            failure = type(error).__name__
            report["failure_type"] = failure  # Never publish low-level payloads.
        finally:
            if esp is not None:
                try:
                    esp.hard_reset()
                    report["application_reset_requested"] = True
                except Exception as error:
                    report["reset_error_type"] = type(error).__name__
                    failure = failure or "ResetUnconfirmed"
                finally:
                    esp._port.close()
    save(
        output / ("backup.json" if args.action == "backup" else "identity.json"), report
    )
    print(
        json.dumps(
            {
                "action": args.action,
                "complete": report["complete"],
                "node_id": args.node,
                "identity": report.get("identity"),
                "flash_write_performed": False,
                "failure_type": failure,
            },
            indent=2,
        )
    )
    raise SystemExit(1 if failure else 0)


if __name__ == "__main__":
    main()
