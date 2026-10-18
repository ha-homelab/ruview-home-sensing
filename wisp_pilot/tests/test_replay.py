"""Offline replay verifies original outcomes and advances across final silence."""

import hashlib
import io
import json
from contextlib import redirect_stderr
from unittest.mock import patch

from test_capture import CaptureFixture, raw_packet
from test_config import IP, MAC

from wisp_pilot import replay as replay_module
from wisp_pilot.__main__ import main
from wisp_pilot.replay import replay


class ReplayTests(CaptureFixture):
    def test_replay_matches_capture_and_expires_during_silence(self):
        captured = self.run_capture([(raw_packet(), (IP, 47010), 0)], seconds=5)
        with patch(
            "socket.socket", side_effect=AssertionError("replay must be offline")
        ):
            result = replay(self.output, self.root / "replay.json")
        self.assertEqual(result["result"], captured)
        self.assertEqual(
            result["result"]["quality"]["receivers"][MAC]["streams"]["raw_csi"][
                "state"
            ],
            "unavailable",
        )
        self.assertEqual((self.root / "replay.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            replay(self.output, self.root / "replay.json")

    def test_empty_capture_replays_as_unknown(self):
        self.run_capture()
        result = replay(self.output, self.root / "replay.json")
        self.assertEqual(
            result["result"]["quality"]["receivers"][MAC]["state"], "unknown"
        )

    def test_raw_tamper_and_missing_final_newline_refused(self):
        self.run_capture([(raw_packet(), (IP, 47010), 0)])
        path = self.output / "datagrams.jsonl"
        original = path.read_bytes()
        for content in (
            original.replace(b'"raw_hex":"57495350', b'"raw_hex":"00495350'),
            original.rstrip(b"\n"),
        ):
            path.write_bytes(content)
            with self.assertRaises(ValueError):
                replay(self.output, self.root / "never.json")
        self.assertFalse((self.root / "never.json").exists())

    def test_manifest_mismatch_and_config_tamper_refused(self):
        self.run_capture()
        manifest_path = self.output / "manifest.json"
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        manifest["records"] = 1
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            replay(self.output, self.root / "never.json")
        manifest_path.write_bytes(original)
        (self.output / "config.json").write_bytes(b"{}")
        with self.assertRaises(ValueError):
            replay(self.output, self.root / "never.json")

    def test_changed_recorded_decision_refused_even_with_updated_digest(self):
        self.run_capture([(raw_packet(), (IP, 47010), 0)])
        path = self.output / "datagrams.jsonl"
        row = json.loads(path.read_bytes())
        row["rejection"] = "invalid_protocol"
        changed = (json.dumps(row) + "\n").encode()
        path.write_bytes(changed)
        manifest_path = self.output / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["datagrams_sha256"] = hashlib.sha256(changed).hexdigest()
        manifest["bytes"] = len(changed)
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            replay(self.output, self.root / "never.json")

    def test_capture_symlink_is_refused(self):
        self.run_capture()
        path = self.output / "datagrams.jsonl"
        alternate = self.root / "alternate.jsonl"
        path.rename(alternate)
        path.symlink_to(alternate)
        with self.assertRaises(OSError):
            replay(self.output, self.root / "never.json")

    def test_validate_config_has_no_network_side_effect(self):
        with patch(
            "socket.socket", side_effect=AssertionError("validation must be offline")
        ):
            self.assertEqual(
                main(
                    [
                        "validate-config",
                        "--config",
                        str(self.path),
                        "--config-sha256",
                        self.pin,
                    ]
                ),
                0,
            )

    def test_manifest_boolean_count_and_unknown_fields_refused(self):
        self.run_capture()
        path = self.output / "manifest.json"
        original = json.loads(path.read_bytes())
        for key, value in (
            ("records", False),
            ("unexpected", "field"),
            ("diagnostic_only", None),
        ):
            changed = dict(original)
            changed[key] = value
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                replay(self.output, self.root / "never.json")

    def test_cli_error_does_not_echo_private_path(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = main(
                [
                    "validate-config",
                    "--config",
                    str(self.root / "private-secret.json"),
                    "--config-sha256",
                    self.pin,
                ]
            )
        self.assertEqual(result, 2)
        self.assertNotIn("private-secret", errors.getvalue())
        self.assertNotIn(str(self.root), errors.getvalue())

    def test_concurrent_growth_stops_at_byte_bound(self):
        self.profile["max_bytes"] = 1024
        self.save_profile()
        self.run_capture()
        original_fdopen = replay_module.os.fdopen

        def growing_stream(fd, *args, **kwargs):
            path = self.output / "datagrams.jsonl"
            if (
                kwargs.get("closefd") is False
                and args == ("rb",)
                and replay_module.os.fstat(fd).st_ino == path.stat().st_ino
            ):
                row = {
                    "schema": "wisp.pilot-capture.v1",
                    "record": 1,
                    "received_monotonic_ns": 1_000_000_000,
                    "received_wall_ns": 1_000_000_000,
                    "origin_ip": IP,
                    "origin_port": 47010,
                    "raw_hex": "00" * 500,
                    "truncated": False,
                    "rejection": "invalid_protocol",
                }
                path.write_text(json.dumps(row) + "\n")
            return original_fdopen(fd, *args, **kwargs)

        with patch.object(replay_module.os, "fdopen", growing_stream):
            with self.assertRaisesRegex(
                ValueError, "byte limit exceeded during replay"
            ):
                replay(self.output, self.root / "never.json")
