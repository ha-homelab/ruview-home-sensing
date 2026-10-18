#!/usr/bin/env python3
"""Validate local module metadata and event maps without running or uploading WASM."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, low, high, label):
    require(type(value) is int and low <= value <= high, f"Invalid {label}")
    return value


def unique(values, label):
    require(len(values) == len(set(values)), f"Duplicate {label}")


def validate_artifact(package, directory):
    """Check RVF shape/hash/metadata only; Ed25519 verification is separate."""
    path = directory / package["file"]
    require(path.resolve().parent == directory.resolve(), "Package escapes directory")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == package["sha256"], "RVF hash mismatch")
    require(len(data) >= 200, "Truncated RVF")
    fields = struct.unpack_from("<IHHIIIIII", data)
    magic, version, flags, manifest_len, wasm_len, sig_len, r1, total, r2 = fields
    require(
        (magic, version, flags, manifest_len, sig_len, r1, r2)
        == (0x01465652, 1, 1, 96, 64, 0, 0),
        "Unsupported RVF header",
    )
    require(8 <= wasm_len <= 128 * 1024, "WASM exceeds firmware binary limit")
    require(total == len(data) == 32 + 96 + wasm_len + 64, "RVF length mismatch")
    require(package["wasm_bytes"] == wasm_len, "WASM size metadata mismatch")
    wasm = data[128 : 128 + wasm_len]
    require(wasm.startswith(b"\0asm\x01\0\0\0"), "Expected WASM v1")
    digest = hashlib.sha256(wasm).digest()
    require(digest.hex() == package["wasm_sha256"], "WASM hash mismatch")
    require(data[80:112] == digest, "RVF embedded payload hash mismatch")
    name = data[32:64].split(b"\0", 1)[0].decode("ascii")
    require(1 <= len(name) <= 31, "Invalid RVF module name")
    require(name == package["name"], "RVF name metadata mismatch")
    require(struct.unpack_from("<H", data, 64)[0] == 1, "Unknown RVF manifest ABI")
    capabilities = int(package["capabilities"], 0)
    budget = integer(package["max_frame_us"], 1, 10000, "frame budget")
    require(0 < capabilities <= 0x7F, "Invalid capability mask")
    require(
        struct.unpack_from("<II", data, 66) == (capabilities, budget),
        "RVF capabilities/budget metadata mismatch",
    )


def validate_event_map(package, catalog):
    algorithms = package["algorithms"]
    require(isinstance(algorithms, list) and algorithms, "No package algorithms")
    unique(algorithms, "package algorithm")
    require(all(a in catalog for a in algorithms), "Unknown package algorithm")
    expected = {(a, e) for a in algorithms for e in catalog[a]}
    package_events = package.get("package_event_ids", [])
    require(isinstance(package_events, list), "Package events must be a list")
    for event in package_events:
        integer(event, 0, 0x7FFFFFFF, "package event ID")
    unique(package_events, "package event ID")
    expected.update(("$package", e) for e in package_events)
    mapping = package.get("event_map")
    require(isinstance(mapping, list) and mapping, "Explicit event_map required")
    source_keys, wire_ids = [], []
    for row in mapping:
        event = integer(row["event_id"], 0, 0x7FFFFFFF, "source event ID")
        wire = integer(row["wire_event_id"], 0, 255, "wire event ID")
        source_keys.append((row["algorithm"], event))
        wire_ids.append(wire)
    unique(source_keys, "source event mapping")
    unique(wire_ids, "wire event mapping (aliases are forbidden)")
    require(set(source_keys) == expected, "Missing or unknown source event mapping")
    declared = package["wire_event_ids"]
    require(isinstance(declared, list), "wire_event_ids must be a list")
    for event in declared:
        integer(event, 0, 255, "declared wire event ID")
    unique(declared, "declared wire event ID")
    require(set(declared) == set(wire_ids), "Wire event inventory disagrees with map")
    return mapping, "declaration_only"


def validate_contracts(manifest, catalog, directory):
    require(manifest["schema_version"] == 1, "Unsupported package manifest")
    require(
        manifest["upstream_commit"] == catalog["upstream_commit"],
        "Package/catalog source revision mismatch",
    )
    require(
        catalog["wire_event_bits"] == 8 and catalog["esp32_slots"] == 4,
        "Unsupported firmware contract",
    )
    modules = catalog["modules"]
    unique([m["name"] for m in modules], "catalog algorithm")
    sources = {}
    for module in modules:
        ids = module["event_ids"]
        for event in ids:
            integer(event, 0, 0x7FFFFFFF, "catalog event ID")
        unique(ids, "catalog event ID")
        sources[module["name"]] = ids
    packages = manifest["packages"]
    require(
        1 <= len(packages) <= 4, "Expected 1..4 packages for the four runtime slots"
    )
    unique([p["name"] for p in packages], "immutable package name")
    unique([p["file"] for p in packages], "package file")
    results = []
    for package in packages:
        validate_artifact(package, directory)
        mapping, evidence = validate_event_map(package, sources)
        results.append(
            {
                "name": package["name"],
                "wasm_sha256": package["wasm_sha256"],
                "event_map": mapping,
                "mapping_evidence": evidence,
            }
        )
    return {
        "structural_validation_passed": True,
        "signature_verified": False,
        "actual_emit_behavior_verified": False,
        "runtime_or_accuracy_qualified": False,
        "packages": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--catalog", type=Path, default=ROOT / "config/plugin-catalog.json"
    )
    parser.add_argument("--package-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = validate_contracts(
            json.loads(args.manifest.read_text()),
            json.loads(args.catalog.read_text()),
            args.package_directory,
        )
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
