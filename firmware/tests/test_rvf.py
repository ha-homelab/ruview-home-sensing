"""Host checks against the actual patched firmware RVF parser and verifier.

Usage: python firmware/tests/test_rvf.py PATH_TO_FETCHED_FIRMWARE_SOURCE
"""

import ctypes as C
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(sys.argv.pop(1)).resolve()
ROOT = Path(__file__).resolve().parents[1]


class Parsed(C.Structure):
    _fields_ = [
        ("header", C.c_void_p),
        ("manifest", C.c_void_p),
        ("wasm_data", C.c_void_p),
        ("wasm_len", C.c_uint32),
        ("signature", C.c_void_p),
        ("test_vectors", C.c_void_p),
        ("test_vectors_len", C.c_uint32),
    ]


class RvfVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        (root / "main").mkdir()
        for name in ["rvf_parser.c", "rvf_parser.h", "CMakeLists.txt"]:
            shutil.copy(SOURCE / "main" / name, root / "main" / name)
        subprocess.run(
            ["git", "apply", str(ROOT / "patches/0001-rvf-ed25519-and-bounds.patch")],
            cwd=root,
            check=True,
        )
        stubs = root / "stubs"
        (stubs / "psa").mkdir(parents=True)
        (stubs / "esp_err.h").write_text(
            "typedef int esp_err_t;\n"
            + "\n".join(
                f"#define {name} {number}"
                for number, name in enumerate(
                    [
                        "ESP_OK",
                        "ESP_FAIL",
                        "ESP_ERR_INVALID_ARG",
                        "ESP_ERR_INVALID_SIZE",
                        "ESP_ERR_INVALID_STATE",
                        "ESP_ERR_NOT_SUPPORTED",
                        "ESP_ERR_INVALID_CRC",
                        "ESP_ERR_NOT_FOUND",
                    ]
                )
            )
        )
        (stubs / "esp_log.h").write_text(
            "#define ESP_LOGE(...) ((void)0)\n#define ESP_LOGI(...) ((void)0)\n"
        )
        (stubs / "psa/crypto.h").write_text("""#include <stddef.h>
#include <stdint.h>
typedef int psa_status_t;
#define PSA_SUCCESS 0
#define PSA_ALG_SHA_256 1
int psa_hash_compute(int, const uint8_t*, size_t, uint8_t*, size_t, size_t*);
""")
        (stubs / "hash.c").write_text("""#include "psa/crypto.h"
typedef int (*hash_cb)(const uint8_t*, size_t, uint8_t*, size_t, size_t*);
static hash_cb callback;
void set_hash_callback(hash_cb cb) { callback = cb; }
int psa_hash_compute(int alg, const uint8_t* in, size_t n, uint8_t* out, size_t cap, size_t* len) {
    return alg == PSA_ALG_SHA_256 ? callback(in, n, out, cap, len) : -1;
}
""")
        vendor = ROOT / "vendor/monocypher"
        lib = root / "rvf.so"
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-shared",
                "-fPIC",
                "-O2",
                "-I" + str(stubs),
                "-I" + str(root / "main"),
                "-I" + str(vendor),
                str(root / "main/rvf_parser.c"),
                str(stubs / "hash.c"),
                str(vendor / "monocypher.c"),
                str(vendor / "monocypher-ed25519.c"),
                "-o",
                str(lib),
            ],
            check=True,
        )
        cls.lib = C.CDLL(str(lib))
        callback_type = C.CFUNCTYPE(
            C.c_int,
            C.c_void_p,
            C.c_size_t,
            C.c_void_p,
            C.c_size_t,
            C.POINTER(C.c_size_t),
        )

        def sha256(data, length, out, cap, result_length):
            if cap < 32:
                return -1
            digest = hashlib.sha256(C.string_at(data, length)).digest()
            C.memmove(out, digest, 32)
            result_length[0] = 32
            return 0

        cls.callback = callback_type(sha256)
        cls.lib.set_hash_callback.argtypes = [callback_type]
        cls.lib.set_hash_callback(cls.callback)
        cls.lib.rvf_parse.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(Parsed)]
        cls.lib.rvf_verify_signature.argtypes = [
            C.POINTER(Parsed),
            C.c_void_p,
            C.c_void_p,
        ]
        vector = json.loads((ROOT / "tests/rvf-vector.json").read_text())
        cls.valid = bytes.fromhex(vector["rvf_hex"])
        cls.pubkey = bytes.fromhex(vector["public_key_hex"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def parse(self, blob):
        data = C.create_string_buffer(bytes(blob))
        parsed = Parsed()
        rc = self.lib.rvf_parse(data, len(blob), C.byref(parsed))
        return rc, data, parsed

    def verify(self, blob, pubkey=None):
        rc, data, parsed = self.parse(blob)
        self.assertEqual(rc, 0)
        return self.lib.rvf_verify_signature(
            C.byref(parsed), data, C.create_string_buffer(pubkey or self.pubkey)
        )

    def test_valid_ed25519_container(self):
        self.assertEqual(self.verify(self.valid), 0)

    def test_synthetic_packages_match_only_the_test_key(self):
        directory = ROOT.parent / "tests/fixtures/modules"
        key = (directory / "public-key.bin").read_bytes()
        self.assertEqual(len(key), 32)
        catalog = json.loads((directory / "catalog.json").read_text())
        for package in catalog["packages"]:
            with self.subTest(package=package["name"]):
                blob = (directory / package["file"]).read_bytes()
                self.assertEqual(
                    hashlib.sha256(blob).hexdigest(), package["package_sha256"]
                )
                self.assertEqual(self.verify(blob, key), 0)
                self.assertNotEqual(self.verify(blob, self.pubkey), 0)
                tampered = bytearray(blob)
                tampered[-1] ^= 1
                self.assertNotEqual(self.verify(tampered, key), 0)

    def test_signature_tampering_rejected(self):
        b = bytearray(self.valid)
        b[-1] ^= 1
        self.assertNotEqual(self.verify(b), 0)

    def test_wrong_key_rejected(self):
        self.assertNotEqual(self.verify(self.valid, bytes([7]) * 32), 0)

    def test_public_key_hash_forgery_rejected(self):
        body = self.valid[:-64]
        forged = body + hashlib.sha256(self.pubkey + body).digest() + bytes(32)
        self.assertNotEqual(self.verify(forged), 0)

    def test_payload_tampering_rejected(self):
        b = bytearray(self.valid)
        b[132] ^= 1
        self.assertNotEqual(self.parse(bytes(b))[0], 0)

    def test_truncation_and_trailing_bytes_rejected(self):
        for b in [
            self.valid[:31],
            self.valid[:127],
            self.valid[:-1],
            self.valid + b"X",
        ]:
            with self.subTest(length=len(b)):
                self.assertNotEqual(self.parse(b)[0], 0)

    def test_integer_overflow_rejected(self):
        b = bytearray(self.valid)
        struct.pack_into("<I", b, 20, 0xFFFFFFF0)
        struct.pack_into("<I", b, 24, (len(b) + 0xFFFFFFF0) & 0xFFFFFFFF)
        self.assertNotEqual(self.parse(bytes(b))[0], 0)

    def test_short_wasm_rejected(self):
        for length in range(8):
            b = bytearray(self.valid)
            struct.pack_into("<I", b, 12, length)
            self.assertNotEqual(self.parse(bytes(b))[0], 0)


if __name__ == "__main__":
    unittest.main()
