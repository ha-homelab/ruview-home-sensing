"""Deployment approval and projected ConfigMap tests without runtime I/O."""

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assumed_activity import configuration, service
from assumed_activity.core import digest
from assumed_activity.polling import DEFAULT_RUNTIME
from assumed_activity.proofs import ReceiverProofs
from assumed_activity.tests.helpers import config
from assumed_activity.tests.test_proofs import (
    APPROVED_IDENTITIES_SHA256,
    identities,
)


class RuntimeConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {"ASSUMED_ACTIVITY_COORDINATE_FRAME": config()["coordinate_frame"]}
        self.values = {
            "CONFIG": config(),
            "RECEIVERS": identities(),
            "RUNTIME": DEFAULT_RUNTIME,
        }
        for name, value in self.values.items():
            raw = (json.dumps(value, indent=2) + "\n").encode()
            path = self.root / (name + ".json")
            path.write_bytes(raw)
            self.env["ASSUMED_ACTIVITY_" + name] = str(path)
            self.env["ASSUMED_ACTIVITY_" + name + "_SHA256"] = hashlib.sha256(
                raw
            ).hexdigest()

    def assert_start_rejected(self, env, message):
        class NoCredentials(dict):
            def __getitem__(self, key):
                raise AssertionError("Credentials must not be read before approval")

        with (
            patch.object(service.os, "environ", NoCredentials(env)),
            patch.object(service, "Service") as producer,
            patch.object(service, "ThreadingHTTPServer") as server,
            self.assertRaisesRegex(ValueError, message),
        ):
            try:
                service.main()
            finally:
                producer.assert_not_called()
                server.assert_not_called()

    def test_approved_raw_files_preserve_documents_and_canonical_provenance(self):
        with patch.dict(os.environ, self.env, clear=True):
            actual = service.load_configuration()
        self.assertEqual(actual[:3], tuple(self.values.values()))
        self.assertEqual(actual[3], APPROVED_IDENTITIES_SHA256)

    def test_missing_malformed_and_stale_pins_fail_before_credentials_or_network(self):
        for name in self.values:
            for pin in (None, "", "x" * 64, "0" * 64):
                with self.subTest(name=name, pin=pin):
                    env = dict(self.env)
                    key = "ASSUMED_ACTIVITY_" + name + "_SHA256"
                    if pin is None:
                        env.pop(key)
                    else:
                        env[key] = pin
                    self.assert_start_rejected(env, "configuration_approval_")

    def test_mutated_payload_cannot_supply_its_own_authority(self):
        changed = copy.deepcopy(identities())
        changed["receivers"][0]["ip"] = "192.168.50.200"
        Path(self.env["ASSUMED_ACTIVITY_RECEIVERS"]).write_text(json.dumps(changed))
        self.assert_start_rejected(self.env, "configuration_approval_mismatch")
        # Even direct constructor users need a separately approved fingerprint.
        with self.assertRaisesRegex(ValueError, "receiver_approval_mismatch"):
            ReceiverProofs(
                changed, (1, 2, 3), expected_sha256=APPROVED_IDENTITIES_SHA256
            )

    def test_missing_or_unapproved_frame_rejected_before_credentials(self):
        for frame in (None, "", "other_xz_metres"):
            env = dict(self.env)
            if frame is None:
                env.pop("ASSUMED_ACTIVITY_COORDINATE_FRAME")
            else:
                env["ASSUMED_ACTIVITY_COORDINATE_FRAME"] = frame
            with self.subTest(frame=frame):
                self.assert_start_rejected(
                    env,
                    "coordinate_frame_approval_required|explicit_assumed_geometry_required",
                )

    def test_pure_producer_requires_independent_expected_frame(self):
        from assumed_activity.core import Producer

        with self.assertRaises(TypeError):
            Producer(config())
        with self.assertRaises(ValueError):
            Producer(config(), expected_coordinate_frame="other_xz_metres")

    def test_projected_symlink_accepts_only_approved_bytes(self):
        projected = self.root / "projected"
        projected.symlink_to(self.env["ASSUMED_ACTIVITY_RECEIVERS"])
        env = dict(self.env, ASSUMED_ACTIVITY_RECEIVERS=str(projected))
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(service.load_configuration()[1], identities())
        target = self.root / "substituted.json"
        target.write_text("{}")
        projected.unlink()
        projected.symlink_to(target)
        self.assert_start_rejected(env, "configuration_approval_mismatch")

    def test_size_and_nonregular_file_are_rejected_before_read(self):
        path = self.root / "oversized"
        path.write_bytes(b"x" * 101)
        with self.assertRaisesRegex(ValueError, "invalid_configuration_file"):
            configuration.pinned_bytes(path, "0" * 64, 100)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "invalid_configuration_file"):
            configuration.pinned_bytes(path, "0" * 64, 100)

    def test_newly_approved_data_still_cannot_expand_receiver_scope(self):
        for field, value in (
            ("ip", "127.0.0.1"),
            ("ip", "192.168.50.101/24"),
            ("node_id", 4),
        ):
            changed = copy.deepcopy(identities())
            changed["receivers"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                ReceiverProofs(changed, (1, 2, 3), expected_sha256=digest(changed))
