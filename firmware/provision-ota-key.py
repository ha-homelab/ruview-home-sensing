#!/usr/bin/env python3
"""Prepare NVS with an OTA key offline, preserving every logical stored value.

This never connects to or writes a receiver. Input, output and key are private
operator files. Requires esp-idf-nvs-partition-gen==0.3.0 in this Python environment.
"""

import argparse
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENDOR = ROOT / "vendor/esp-idf-nvs"


def parser_module():
    source = VENDOR / "nvs_parser.py"
    expected = json.loads((VENDOR / "SOURCE.json").read_text())["files"][source.name]
    if hashlib.sha256(source.read_bytes()).hexdigest() != expected["sha256"]:
        raise ValueError("NVS parser source hash mismatch")
    spec = importlib.util.spec_from_file_location("home_nvs_parser", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def logical_values(raw):
    """Decode live values with CRC/chunk checks; never return erased entries."""
    nvs = parser_module().NVS_Partition("private", bytearray(raw))
    entries = []
    for page in sorted(nvs.pages, key=lambda p: p.header["page_index"]):
        if page.is_empty:
            if raw[page.start_address : page.start_address + 4096] != b"\xff" * 4096:
                raise ValueError("Nonempty data in erased NVS page")
            continue
        if page.header["status"] not in {"Full", "Active"}:
            raise ValueError("NVS page needs recovery before provisioning")
        crc = page.header["crc"]
        if crc["original"] != crc["computed"]:
            raise ValueError("NVS page CRC mismatch")
        for entry in page.entries:
            if entry.state != "Written":
                continue
            crc = entry.metadata["crc"]
            if not entry.key or crc["original"] != crc["computed"]:
                raise ValueError("NVS entry invalid")
            if entry.children and (
                crc["data_original"] != crc["data_computed"]
                or any(child.state != "Written" for child in entry.children)
            ):
                raise ValueError("NVS variable data invalid")
            entries.append(entry)

    namespaces = {}
    chunks = {}
    live = {}
    for entry in entries:
        meta = entry.metadata
        ns = meta["namespace"]
        if ns == 0:
            if meta["type"] != "uint8_t":
                raise ValueError("Invalid namespace entry")
            namespaces[entry.data["value"]] = entry.key
        elif meta["type"] == "blob_data":
            chunks[(ns, entry.key, meta["chunk_index"])] = entry
        else:
            live[(ns, entry.key)] = entry
    if len(set(namespaces.values())) != len(namespaces):
        raise ValueError("Duplicate namespace names")

    def payload(entry):
        data = b"".join(bytes(child.raw) for child in entry.children)
        size = entry.data["size"]
        if size > len(data):
            raise ValueError("Truncated variable value")
        return data[:size]

    result = {}
    for (ns, key), entry in live.items():
        if ns not in namespaces:
            raise ValueError("Unknown namespace")
        kind = entry.metadata["type"]
        if kind == "string":
            value = payload(entry)
            if not value.endswith(b"\0") or b"\0" in value[:-1]:
                raise ValueError("Invalid NVS string")
            value = value[:-1].decode("utf-8")
        elif kind == "blob":
            value = payload(entry)
        elif kind == "blob_index":
            start = entry.data["chunk_start"]
            count = entry.data["chunk_count"]
            value = b"".join(
                payload(chunks[(ns, key, i)]) for i in range(start, start + count)
            )
            if len(value) != entry.data["size"]:
                raise ValueError("Blob chunk sizes disagree")
            kind = "blob"
        elif re.fullmatch(r"u?int(?:8|16|32|64)_t", kind):
            value = entry.data["value"]
        else:
            raise ValueError("Unsupported NVS value type")
        result[(namespaces[ns], key)] = (kind, value)
    return result


def generate(values, size):
    # The CLI wrapper synthesizes sta.apinfo/sta.pmk/sta.apsw for Wi-Fi keys.
    # Use the exact low-level writer so a round trip never resets those values.
    if importlib.metadata.version("esp-idf-nvs-partition-gen") != "0.3.0":
        raise ValueError("Expected esp-idf-nvs-partition-gen==0.3.0")
    from esp_idf_nvs_partition_gen.nvs_partition_gen import NVS, Page

    output = io.BytesIO()
    with NVS(output, size - 4096, Page.VERSION2) as nvs:
        previous = None
        for (namespace, key), (kind, value) in sorted(values.items()):
            if namespace != previous:
                nvs.write_namespace(namespace)
                previous = namespace
            if kind == "blob":
                encoding, value = "hex2bin", value.hex()
            elif kind == "string":
                encoding = "string"
            else:
                encoding = (
                    kind.replace("uint", "u").replace("int", "i").replace("_t", "")
                )
            nvs.write_entry(key, value, encoding, namespace_idx=nvs.get_namespace_idx())
    return output.getvalue()


def prepare(raw, key):
    if len(raw) != 0x6000 or not re.fullmatch(r"[0-9a-f]{64}", key):
        raise ValueError("Expected a verified 24 KiB NVS partition and 256-bit hex key")
    old = logical_values(raw)
    if ("security", "ota_psk") in old:
        raise ValueError("OTA key already exists; refusing implicit key rotation")
    expected = dict(old)
    expected[("security", "ota_psk")] = ("string", key)
    result = generate(expected, len(raw))
    if len(result) != len(raw) or logical_values(result) != expected:
        raise ValueError("Generated NVS did not preserve all logical values")
    return result, len(old)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-nvs", type=Path, required=True)
    parser.add_argument("--output-nvs", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for path in [args.input_nvs, args.output_nvs, args.key_file]:
        if path.resolve().is_relative_to(ROOT.parent):
            raise ValueError("Private NVS/key files must be outside the repository")
    if args.output_nvs.exists():
        raise ValueError("Refusing to overwrite an existing NVS output")
    if args.key_file.exists():
        if args.key_file.stat().st_mode & 0o077:
            raise ValueError("OTA key file must be private (0600)")
        key = args.key_file.read_text().strip()
    else:
        key = secrets.token_hex(32)
        with args.key_file.open("x") as output:
            output.write(key + "\n")
    result, count = prepare(args.input_nvs.read_bytes(), key)
    with args.output_nvs.open("xb") as output:
        output.write(result)
    print(
        json.dumps(
            {
                "preserved_values": count,
                "added": "security/ota_psk",
                "bytes": len(result),
                "device_written": False,
            }
        )
    )


if __name__ == "__main__":
    main()
