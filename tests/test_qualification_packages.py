"""A package can be selected only from an independently approved explicit catalog."""

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import MappingProxyType

from module_package_fixture import DIRECTORY, DOCUMENT, HOME_SIGNAL

from firmware.qualification_packages import PACKAGES, get_package, load_packages


class PackageProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / "catalog.json"
        self.document = copy.deepcopy(DOCUMENT)
        self.write()

    def write(self):
        self.raw = json.dumps(self.document).encode()
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.pin = hashlib.sha256(self.raw).hexdigest()

    def load(self):
        return load_packages(self.path, self.pin, DIRECTORY)

    def test_no_implicit_package_or_trust_policy(self):
        self.assertEqual(dict(PACKAGES), {})
        with self.assertRaisesRegex(ValueError, "unknown_package_profile"):
            get_package("home-signal")

    def test_approved_catalog_matches_synthetic_signed_bytes(self):
        packages = self.load()
        for name, package in packages.items():
            self.assertIs(get_package(name, packages), package)
            data = package.path.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), package.package_sha256)
            self.assertEqual(len(data), package.package_bytes)
            self.assertEqual(
                hashlib.sha256(data[128:-64]).hexdigest(), package.wasm_sha256
            )
        with self.assertRaises(FrozenInstanceError):
            packages["home-signal"].name = "changed"
        with self.assertRaises(TypeError):
            packages["injected"] = HOME_SIGNAL

    def test_missing_wrong_and_self_modified_approval_rejected(self):
        for pin in (None, "", "0" * 64):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                load_packages(self.path, pin, DIRECTORY)
        self.path.write_bytes(self.raw + b" ")
        with self.assertRaisesRegex(ValueError, "approval_mismatch"):
            self.load()

    def test_traversal_duplicate_fields_and_unbounded_metadata_rejected(self):
        for mutate in (
            lambda d: d["packages"][0].update(file="../escape.rvf"),
            lambda d: d["packages"].append(d["packages"][0]),
            lambda d: d["packages"][0].update(wasm_bytes=True),
            lambda d: d["packages"][0].update(package_bytes=2**40),
            lambda d: d["packages"][0].update(wasm_sha256="not-a-hash"),
            lambda d: d.update(approve_myself=True),
        ):
            self.document = copy.deepcopy(DOCUMENT)
            mutate(self.document)
            self.write()
            with self.assertRaises(ValueError):
                self.load()
        self.raw = b'{"schema":"bad",' + self.raw[1:]
        self.path.write_bytes(self.raw)
        self.pin = hashlib.sha256(self.raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.load()

    def test_public_or_symlink_catalog_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.load()
        self.path.chmod(0o600)
        alias = self.path.with_name("alias.json")
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            load_packages(alias, self.pin, DIRECTORY)

    def test_incomplete_profile_rejected(self):
        for key in ("package_sha256", "wasm_sha256", "package_bytes", "wasm_bytes"):
            value = replace(HOME_SIGNAL, **{key: None})
            with self.assertRaisesRegex(ValueError, "package_profile_unavailable"):
                get_package(value.profile, MappingProxyType({value.profile: value}))
