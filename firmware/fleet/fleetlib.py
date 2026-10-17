"""Pure fleet recovery/provisioning checks. No serial, network or flash writes."""

import contextlib
import hashlib
import importlib.metadata
import importlib.util
import io
import ipaddress
import json
import os
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import installation_identity  # noqa: E402

# These names are part of the fleet tooling's shared import surface.
InstallationContext = installation_identity.InstallationContext
load_installation_context = installation_identity.load_installation_context

ESPT_VERSION = "5.1.0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect_application(data, version):
    """Inspect the exact cached bytes later hashed/written, never reopen a path."""
    require(importlib.metadata.version("esptool") == ESPT_VERSION, "Use esptool5.1.0")
    require(
        type(data) is bytes and 0 < len(data) <= 16 * 1024 * 1024, "Invalid image size"
    )
    import esptool.cmds

    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        esptool.cmds.image_info(data)
    info = output.getvalue()
    require(
        "Detected image type: ESP32-S3" in info
        and f"App version: {version}\n" in info
        and "(invalid)" not in info
        and info.count("(valid)") >= 2,
        "Firmware chip, version or image integrity mismatch",
    )


def private_path(path, *, existing=False):
    path = Path(path)
    require(not path.is_symlink(), "Private path must not be a symlink")
    resolved = path.resolve(strict=existing)
    require(
        not resolved.is_relative_to(ROOT), "Recovery material must stay outside Git"
    )
    if existing:
        require(
            not path.stat().st_mode & 0o077, "Private input must have mode 0600/0700"
        )
    return resolved


def create_directory(path):
    path = private_path(path)
    path.mkdir(mode=0o700, exist_ok=False)
    os.chmod(path, 0o700)
    return path


def save(path, data):
    if not isinstance(data, bytes):
        data = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def mac_address(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value),
        "Expected lowercase station MAC",
    )
    return value


def binding(node_id, mac, inventory, identity):
    require(
        type(node_id) is int and 1 <= node_id <= identity["policy"]["fleet_size"],
        "Node is outside the approved fleet",
    )
    mac_address(mac)
    expected_ip = str(
        ipaddress.IPv4Network(identity["fleet_ipv4_network"]).network_address
        + identity["fleet_first_host"]
        + node_id
        - 1
    )
    candidates = [n for n in inventory["nodes"] if n["name"] == f"ruview-{node_id:02d}"]
    require(len(candidates) == 1, "Expected one inventory reservation")
    node = candidates[0]
    require(node["ip"] == expected_ip, "Reserved address differs from fleet allocation")
    require(
        node.get("mac") in (None, mac), "MAC conflicts with selected inventory unit"
    )
    require(
        node.get("firmware_node_id") in (None, node_id), "Inventory node ID conflict"
    )
    require(
        not any(n.get("mac") == mac and n is not node for n in inventory["nodes"]),
        "MAC belongs to another inventory unit",
    )
    return {
        "node_id": node_id,
        "mac": mac,
        "reserved_ip": expected_ip,
        "inventory_binding_verified": node.get("identity_verified") is True,
    }


def parse_partitions(raw, flash_size, table_offset):
    """Parse the recorded ESP partition table, checking MD5, ranges and overlaps."""
    require(len(raw) == 0x1000, "Expected one partition-table sector")
    if raw == b"\xff" * len(raw):
        return {
            "state": "blank_no_verified_layout",
            "partitions": [],
            "md5_verified": False,
        }
    entries, names, seen_md5, terminated = [], set(), False, False
    for offset in range(0, 0xC00, 32):
        chunk = raw[offset : offset + 32]
        magic = struct.unpack_from("<H", chunk)[0]
        if magic == 0xFFFF:
            require(
                chunk == b"\xff" * 32 and raw[offset:] == b"\xff" * (len(raw) - offset),
                "Nonempty partition-table padding",
            )
            terminated = True
            break
        if magic == 0xEBEB:
            require(
                not seen_md5 and chunk[2:16] == b"\xff" * 14,
                "Malformed partition MD5 record",
            )
            require(
                hashlib.md5(raw[:offset]).digest() == chunk[16:],
                "Partition-table MD5 mismatch",
            )
            seen_md5 = True
            continue
        require(magic == 0x50AA and not seen_md5, "Unknown partition-table record")
        _, kind, subtype, address, size, label, flags = struct.unpack(
            "<HBBII16sI", chunk
        )
        require(b"\0" in label, "Partition label is not terminated")
        label = label.split(b"\0", 1)[0].decode("ascii")
        require(
            re.fullmatch(r"[A-Za-z0-9_-]{1,15}", label) and label not in names,
            "Invalid/duplicate partition label",
        )
        require(
            size > 0
            and address >= table_offset + 0x1000
            and address + size <= flash_size,
            "Partition exceeds verified flash/layout",
        )
        require(
            address % (0x10000 if kind == 0 else 0x1000) == 0 and size % 0x1000 == 0,
            "Unaligned partition",
        )
        require(flags == 0, "Partition flags require separate encryption review")
        require(
            not any(
                address < e["offset"] + e["bytes"] and e["offset"] < address + size
                for e in entries
            ),
            "Overlapping partitions",
        )
        names.add(label)
        entries.append(
            {
                "name": label,
                "type": kind,
                "subtype": subtype,
                "offset": address,
                "bytes": size,
            }
        )
    require(terminated and entries, "Incomplete partition table")
    return {"state": "parsed", "partitions": entries, "md5_verified": seen_md5}


def embedded_psram(features):
    matches = [
        re.fullmatch(r"Embedded PSRAM (2|4|8|16)MB(?: \([^)]*\))?", f) for f in features
    ]
    sizes = [int(m[1]) * 1024 * 1024 for m in matches if m]
    require(len(sizes) <= 1, "Conflicting embedded PSRAM observations")
    return (
        sizes[0] if sizes else None
    )  # Absence of embedded PSRAM does not disprove external RAM.


def verify_backup(directory):
    directory = private_path(directory, existing=True)
    report = json.loads((directory / "backup.json").read_text())
    require(
        report["complete"] is True and report["flash_write_performed"] is False,
        "Backup incomplete",
    )
    raw = private_path(directory / "flash.bin", existing=True).read_bytes()
    require(
        len(raw) == report["identity"]["flash_bytes"]
        and sha(raw) == report["flash_sha256"],
        "Backup digest/size mismatch",
    )
    cursor = 0
    for chunk in report["chunks"]:
        require(
            chunk["offset"] == cursor and chunk["device_md5_verified"] is True,
            "Incomplete backup coverage",
        )
        data = raw[cursor : cursor + chunk["bytes"]]
        require(
            len(data) == chunk["bytes"] and sha(data) == chunk["sha256"],
            "Backup chunk mismatch",
        )
        cursor += len(data)
    require(cursor == len(raw), "Backup chunks do not cover full physical flash")
    table_offset = report["partition_table_offset"]
    layout = parse_partitions(
        raw[table_offset : table_offset + 0x1000], len(raw), table_offset
    )
    require(
        layout == report["layout"], "Backup layout metadata differs from recorded bytes"
    )
    return report, raw


def nvs_tool():
    spec = importlib.util.spec_from_file_location(
        "fleet_nvs", ROOT / "firmware/provision-ota-key.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_key(context):
    if not isinstance(context, InstallationContext):
        raise ValueError("Approved installation context required for trust key")
    value = context.identity["policy"]["wasm_public_key_hex"]
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
        "Expected one Ed25519 public verification key",
    )
    key = bytes.fromhex(value)
    require(key != bytes(32), "All-zero verification key refused")
    return key


def provision_values(old, node_id, key, verification_key, network=None):
    """Explicit planned changes only; preserve all other logical NVS values."""
    require(type(node_id) is int and 1 <= node_id <= 255, "Invalid uint8 fleet ID")
    require(
        re.fullmatch(r"[0-9a-f]{64}", key) and len(verification_key) == 32,
        "Invalid key shape",
    )
    selected = dict(old)
    existing = selected.get(("csi_cfg", "node_id"))
    require(
        existing in (None, ("uint8_t", node_id)),
        "Stored node ID differs; no implicit rebinding",
    )
    previous_key = selected.get(("security", "ota_psk"))
    require(
        previous_key in (None, ("string", key)),
        "Existing OTA key differs; no implicit rotation",
    )
    previous_pub = selected.get(("csi_cfg", "wasm_pubkey"))
    require(
        previous_pub in (None, ("blob", verification_key)),
        "Existing signing key requires separate migration",
    )
    if network is not None:
        require(
            not any(
                ("csi_cfg", k) in selected
                for k in ("ssid", "password", "target_ip", "target_port")
            ),
            "Never replace existing network settings",
        )
        require(
            isinstance(network["ssid"], str)
            and 1 <= len(network["ssid"].encode()) <= 32,
            "Invalid private SSID",
        )
        require(
            isinstance(network["password"], str)
            and 8 <= len(network["password"].encode()) <= 63,
            "Invalid private WPA key",
        )
        import ipaddress

        ipaddress.IPv4Address(network["target_ip"])
        require(
            type(network["target_port"]) is int
            and 1 <= network["target_port"] <= 65535,
            "Invalid collector UDP port",
        )
        for name in ("ssid", "password", "target_ip"):
            selected[("csi_cfg", name)] = ("string", network[name])
        selected[("csi_cfg", "target_port")] = ("uint16_t", network["target_port"])
    require(
        all(
            ("csi_cfg", k) in selected
            for k in ("ssid", "password", "target_ip", "target_port")
        ),
        "Missing private network configuration",
    )
    selected[("csi_cfg", "node_id")] = ("uint8_t", node_id)
    selected[("security", "ota_psk")] = ("string", key)
    selected[("csi_cfg", "wasm_pubkey")] = ("blob", verification_key)
    selected[("csi_cfg", "wasm_verify")] = ("uint8_t", 1)
    return selected


def candidate_plan(report, node, image_bytes, image_sha, preferred_bssid=None):
    identity, layout = report["identity"], report["layout"]
    require(identity["mac"] == node["mac"], "Backup belongs to another board")
    require(
        identity["chip"] == "ESP32-S3"
        and identity["flash_bytes"] == 16 * 1024 * 1024
        and identity["embedded_psram_bytes"] == 8 * 1024 * 1024,
        "No reviewed build profile for this hardware; preserve evidence and design one",
    )
    if preferred_bssid:
        mac_address(preferred_bssid)
    slots = [
        p
        for p in layout["partitions"]
        if p["type"] == 0 and p["subtype"] in (0x10, 0x11)
    ]
    fits = (
        len(slots) == 2
        and {p["subtype"] for p in slots} == {0x10, 0x11}
        and all(image_bytes <= p["bytes"] for p in slots)
    )
    overlay = [
        "# Private per-board candidate overlay; not an installation authorization.",
        "# CONFIG_LED_GAMMA_VIZ is not set",
    ]
    if preferred_bssid:
        overlay += [
            "CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE=y",
            f"CONFIG_HOME_WIFI_PREFERRED_NODE_ID={node['node_id']}",
            f'CONFIG_HOME_WIFI_PREFERRED_STA_MAC="{node["mac"]}"',
            f'CONFIG_HOME_WIFI_PREFERRED_BSSID="{preferred_bssid}"',
        ]
    else:
        overlay += ["# CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE is not set"]
    return {
        "binding": node,
        "hardware": identity,
        "application_bytes": image_bytes,
        "application_sha256": image_sha,
        "existing_ota_slots": slots,
        "image_fits_both_ota_slots": fits,
        "status": "requires_reviewed_install_plan"
        if fits
        else "blocked_layout_migration_required",
        "flash_write_authorized": False,
        "layout_changes_authorized": False,
        "ap_policy": {
            "mode": "preferred_with_fallback"
            if preferred_bssid
            else "associated_auto_all_channel",
            "preferred_bssid": preferred_bssid,
        },
        "rgb_animation_enabled": False,
        "psram_boot_memtest_verified": False,
        "runtime_and_sensing_qualified": False,
    }, "\n".join(overlay) + "\n"
