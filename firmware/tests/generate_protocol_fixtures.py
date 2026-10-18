"""Reproduce synthetic protocol fixtures; never deploy their public test key."""

import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main():
    r = Path(__file__).resolve().parents[2]
    root = r / "tests/fixtures/modules"
    root.mkdir(exist_ok=True)
    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(
            b"PUBLIC UNIT TEST FIXTURE ONLY - never provision a receiver with this key"
        ).digest()
    )
    (root / "public-key.bin").write_bytes(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    names = [
        "home-signal",
        "home-signal-v2",
        "home-signal-v3",
        "home-signal-v4",
        "home-signal-v5",
    ]
    sizes = [14783, 14652, 15826, 15826, 15825]
    cat = {"schema": "ruview.qualification-packages.v1", "packages": []}
    for idx, (name, size) in enumerate(zip(names, sizes, strict=True)):
        # Synthetic valid Wasm: only a custom section; never sensing implementation.
        body = b"\x07fixture" + bytes([idx]) * (size - 19)

        def leb(n):
            out = bytearray()
            while True:
                b = n & 127
                n >>= 7
                out.append(b | (128 if n else 0))
                if not n:
                    return bytes(out)

        wasm = b"\x00asm\x01\x00\x00\x00" + b"\x00" + leb(len(body)) + body
        assert len(wasm) == size, (len(wasm), size)
        digest = hashlib.sha256(wasm).digest()
        manifest = struct.pack(
            "<32sHIIHHH32sHH10s2s",
            name.encode(),
            1,
            0x6B,
            10000,
            0,
            0,
            1,
            digest,
            1,
            64,
            b"UNIT-TEST",
            b"\x00\x00",
        )
        header = struct.pack(
            "<IHHIIIIII", 0x01465652, 1, 1, 96, len(wasm), 64, 0, len(wasm) + 192, 0
        )
        data = header + manifest + wasm
        data += key.sign(data)
        (root / (name + ".rvf")).write_bytes(data)
        cat["packages"].append(
            dict(
                profile=name,
                name=name,
                file=name + ".rvf",
                package_sha256=hashlib.sha256(data).hexdigest(),
                wasm_sha256=digest.hex(),
                package_bytes=len(data),
                wasm_bytes=len(wasm),
            )
        )
    (root / "catalog.json").write_text(json.dumps(cat, indent=2) + "\n")
    (root / "README.md").write_text(
        "# Synthetic protocol fixtures\n\nThese RVF packages contain only an empty Wasm module with a custom data section.\nThey do not implement sensing and have never been deployed. They are signed by\na public test-only key derived from the phrase in the reproducibility helper;\nnever use this key as an installation trust anchor. The test loader supplies\nfixture authority explicitly; production code has no package or key default.\n"
    )
    # Regenerate signed fixture manifests preserving only synthetic test policy.
    mp = r / "tests/fixtures/module-manifest.json"
    d = json.loads(mp.read_text())
    byname = {x["name"]: x for x in cat["packages"]}
    for package in d["packages"]:
        c = byname[package["name"]]
        package["sha256"] = c["package_sha256"]
        package["wasm_sha256"] = c["wasm_sha256"]
        package["wasm_bytes"] = c["wasm_bytes"]
    mp.write_text(json.dumps(d, indent=2) + "\n")


if __name__ == "__main__":
    main()
