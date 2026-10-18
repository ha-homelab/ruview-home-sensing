#!/usr/bin/env python3
"""Build an Ed25519-signed RVF v1 container for the patched RuView firmware."""

import argparse
import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("wasm", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--private-key", required=True, type=Path)
    p.add_argument("--name", required=True)
    p.add_argument("--capabilities", type=lambda s: int(s, 0), default=0x6B)
    p.add_argument("--budget-us", type=int, default=10000)
    args = p.parse_args()
    wasm = args.wasm.read_bytes()
    if not wasm.startswith(b"\0asm\x01\0\0\0") or not 8 <= len(wasm) <= 128 * 1024:
        p.error("Expected a WASM v1 module of 8–131072 bytes")
    try:
        name = args.name.encode("ascii")
    except UnicodeEncodeError:
        p.error("Module name must be ASCII")
    if not 1 <= len(name) <= 31 or b"\0" in name:
        p.error("Module name must contain 1–31 non-NUL ASCII bytes")
    if not 0 < args.capabilities <= 0x7F or not 0 < args.budget_us <= 10000:
        p.error("Capabilities must be in 1..0x7f; frame budget in 1..10000 us")
    key = load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        p.error("Expected an Ed25519 private key")
    manifest = struct.pack(
        "<32sHIIHHH32sHH10s2s",
        name,
        1,
        args.capabilities,
        args.budget_us,
        0,
        0,
        1,
        hashlib.sha256(wasm).digest(),
        1,
        64,
        b"ruview",
        b"\0\0",
    )
    header = struct.pack(
        "<IHHIIIIII",
        0x01465652,
        1,
        1,
        96,
        len(wasm),
        64,
        0,
        32 + 96 + len(wasm) + 64,
        0,
    )
    signed = header + manifest + wasm
    signature = key.sign(signed)
    key.public_key().verify(signature, signed)
    rvf = signed + signature
    args.output.write_bytes(rvf)
    print(
        f"{args.output.name}: {len(rvf)} bytes; SHA256 {hashlib.sha256(rvf).hexdigest()}"
    )


if __name__ == "__main__":
    main()
