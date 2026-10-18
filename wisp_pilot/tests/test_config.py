"""Offline trust-boundary tests for fictional Wisp profiles."""

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from wisp_pilot.__main__ import main
from wisp_pilot.config import load_config, validate

MAC = "02:00:00:00:00:01"
IP = "192.0.2.11"
PROFILE = {
    "schema": "wisp.pilot-config.v1",
    "bind_ip": "127.0.0.1",
    "source_port": 47010,
    "streams": 3,
    "receivers": [{"ip": IP, "mac": MAC}],
    "max_records": 100,
    "max_bytes": 1000000,
}


class ProfileFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / "profile.json"
        self.profile = copy.deepcopy(PROFILE)
        self.save_profile()

    def save_profile(self):
        self.raw = json.dumps(self.profile).encode()
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.pin = hashlib.sha256(self.raw).hexdigest()
        self.config = load_config(self.path, self.pin)


class ConfigTests(ProfileFixture):
    def test_valid_pinned_profile_preserves_exact_bytes(self):
        self.assertEqual(self.config.raw, self.raw)
        self.assertEqual(self.config.receivers, {IP: MAC})

    def test_wrong_pin_no_fallback(self):
        with self.assertRaises(ValueError):
            load_config(self.path, "0" * 64)

    def test_public_mode_and_symlink_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_config(self.path, self.pin)
        self.path.chmod(0o600)
        link = self.root / "symlink.json"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            load_config(link, self.pin)

    def test_strict_schema_bounds_and_broadcast(self):
        for key, value in (
            ("extra", 1),
            ("bind_ip", "0.0.0.0"),
            ("source_port", 47011),
            ("streams", True),
            ("max_records", True),
            ("max_bytes", 1024**3 + 1),
        ):
            with self.subTest(key=key, value=value):
                document = copy.deepcopy(PROFILE)
                document[key] = value
                with self.assertRaises(ValueError):
                    validate(document)

    def test_duplicate_and_multicast_receivers_refused(self):
        for receivers in (
            [PROFILE["receivers"][0]] * 2,
            [{"ip": "224.0.0.1", "mac": MAC}],
            [{"ip": IP, "mac": "01:00:00:00:00:01"}],
        ):
            document = copy.deepcopy(PROFILE)
            document["receivers"] = receivers
            with self.assertRaises(ValueError):
                validate(document)

    def test_duplicate_json_keys_rejected_even_with_matching_hash(self):
        self.path.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaises(ValueError):
            load_config(self.path, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_deeply_nested_input_fails_without_private_path_in_error(self):
        raw = b'{"nested":' + b"[" * 3000 + b"0" + b"]" * 3000 + b"}"
        self.path.write_bytes(raw)
        output = io.StringIO()
        with redirect_stderr(output):
            status = main(
                [
                    "validate-config",
                    "--config",
                    str(self.path),
                    "--config-sha256",
                    hashlib.sha256(raw).hexdigest(),
                ]
            )
        self.assertEqual(status, 2)
        self.assertNotIn(str(self.path), output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
