"""Public builds never inherit an installation trust key or silently replace it."""

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

FIRMWARE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "public_build_fetch", FIRMWARE / "fetch-source.py"
)
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class PublicBuildInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.key = self.root / "public-key.raw"
        self.key.write_bytes(bytes(range(1, 33)))
        self.pin = hashlib.sha256(self.key.read_bytes()).hexdigest()

    def test_default_does_not_enable_a_compiled_fallback_key(self):
        header = fetch.verification_header()
        self.assertIn(b"RUVIEW_WASM_PUBLIC_KEY_CONFIGURED 0", header)
        self.assertNotIn(b"HOME_WASM_PUBLIC_KEY[", header)
        patch = (FIRMWARE / "patches/0002-deployment-wasm-public-key.patch").read_text()
        self.assertIn("#if RUVIEW_WASM_PUBLIC_KEY_CONFIGURED", patch)
        self.assertIn("uploads are rejected", patch)

    def test_independent_pin_enables_only_exact_key_bytes(self):
        header = fetch.verification_header(self.key, self.pin)
        self.assertIn(b"RUVIEW_WASM_PUBLIC_KEY_CONFIGURED 1", header)
        self.assertIn(b"0x01, 0x02", header)
        for args in ((self.key, None), (None, self.pin), (self.key, "0" * 64)):
            with self.assertRaises(ValueError):
                fetch.verification_header(*args)

    def test_malformed_zero_and_symlink_keys_fail_before_context_creation(self):
        alias = self.root / "key-link"
        alias.symlink_to(self.key)
        for path, pin in ((alias, self.pin),):
            with self.assertRaises(ValueError):
                fetch.copy_build_inputs(
                    self.root / "context",
                    wasm_public_key=path,
                    wasm_public_key_sha256=pin,
                )
            self.assertFalse((self.root / "context").exists())
        for data in (b"", b"x" * 31, b"x" * 33, bytes(32)):
            self.key.write_bytes(data)
            with self.assertRaises(ValueError):
                fetch.verification_header(self.key, hashlib.sha256(data).hexdigest())

    def test_existing_context_cannot_silently_change_key(self):
        output = self.root / "context"
        fetch.copy_build_inputs(
            output, wasm_public_key=self.key, wasm_public_key_sha256=self.pin
        )
        original = (output / "home_wasm_pubkey.h").read_bytes()
        with self.assertRaisesRegex(ValueError, "different verification key"):
            fetch.copy_build_inputs(output)
        self.assertEqual((output / "home_wasm_pubkey.h").read_bytes(), original)
