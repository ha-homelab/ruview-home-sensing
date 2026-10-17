"""Offline upload state-machine checks; requests are injected fakes."""

import copy
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
import urllib.error
from dataclasses import replace
from functools import partial
from pathlib import Path
from unittest.mock import patch

from module_package_fixture import bind_module
from qualification_fixture import RECEIVER, run_cli

SPEC = importlib.util.spec_from_file_location(
    "node2_upload",
    Path(__file__).resolve().parents[1] / "firmware/qualify-module-upload.py",
)
UPLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPLOAD)
bind_module(UPLOAD)
PACKAGE = (
    UPLOAD.PACKAGE.read_bytes()
)  # Explicitly injected synthetic signed protocol fixture.


class FakeDevice:
    def __init__(self, data=PACKAGE, profile=UPLOAD.HOME_SIGNAL):
        self.data = data
        self.profile = profile
        self.calls = []
        self.uptime = 100000
        self.loaded = False
        self.version = "0.8.8.5"
        self.partition = "ota_1"
        self.control_code = 403
        self.valid_error = None
        self.control_loads = False
        self.reset_after_control = False
        self.version_after_control = None
        self.version_after_upload = None
        self.max_us = 500
        self.reply_override = None
        self.slots_override = None
        self.include_callback_metrics = True
        self.callback_overrides = {}
        self.empty_callback_overrides = {}

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path == "/ota/status":
            return {"version": self.version, "running_partition": self.partition}
        if path == "/wasm/list":
            self.uptime += 200
            slots = [{"id": i, "state": "empty"} for i in range(4)]
            if self.version in ("0.8.8.7", "0.8.8.8") and self.include_callback_metrics:
                for slot in slots:
                    slot.update(
                        max_us=0,
                        max_frame_us=0,
                        max_timer_us=0,
                        frame_overruns=0,
                        timer_overruns=0,
                    )
                slots[3].update(self.empty_callback_overrides)
            if self.loaded:
                slots[0].update(
                    name=self.profile.name,
                    state="running",
                    binary_size=self.profile.wasm_bytes,
                    caps="0x006b",
                    budget_us=10000,
                    frame_count=1,
                    event_count=0,
                    error_count=0,
                    budget_faults=0,
                    mean_us=0,
                    max_us=self.max_us,
                )
                if (
                    self.version in ("0.8.8.7", "0.8.8.8")
                    and self.include_callback_metrics
                ):
                    slots[0]["max_frame_us"] = self.max_us
                slots[0].update(self.callback_overrides)
            return {
                "loaded": int(self.loaded),
                "max": 4,
                "modules": self.slots_override or slots,
                "runtime": {
                    "uptime_ms": self.uptime,
                    "worker_stack_bytes": 32768,
                    "worker_stack_min_free_bytes": 16000,
                    "internal_free_bytes": 80000,
                    "internal_min_free_bytes": 70000,
                    "internal_largest_free_block": 40000,
                },
            }
        if data != self.data:
            self.loaded = self.control_loads
            if self.version_after_control is not None:
                self.version = self.version_after_control
            if self.reset_after_control:
                self.uptime = 10
            if self.control_code == 200:
                return {"status": "ok"}
            raise urllib.error.HTTPError(
                "http://device/", self.control_code, "test", {}, None
            )
        self.loaded = True
        if self.version_after_upload is not None:
            self.version = self.version_after_upload
        if self.valid_error:
            raise self.valid_error
        return self.reply_override or {
            "status": "ok",
            "format": "rvf",
            "module_id": 0,
            "name": self.profile.name,
            "wasm_size": self.profile.wasm_bytes,
            "caps": "0x006b",
            "budget_us": 10000,
            "started": True,
        }


class RecoveryDevice(FakeDevice):
    def __init__(self, data=PACKAGE, profile=UPLOAD.HOME_SIGNAL):
        super().__init__(data, profile)
        self.version = "0.8.8.10"
        self.nonce = "1" * 32
        self.status_overrides = {}
        self.runtime_overrides = {}
        self.ping_overrides = {}
        self.reply_boot = {
            "boot_nonce_schema": UPLOAD.BOOT_SCHEMA,
            "boot_nonce": self.nonce,
        }
        self.boot_after_control = None
        self.boot_after_upload = None
        self.headers = []

    def request(self, method, path, data=None, *, expected_boot_nonce=None):
        self.headers.append((method, path, expected_boot_nonce))
        if method == "POST":
            if expected_boot_nonce != self.nonce:
                raise urllib.error.HTTPError(
                    "http://device/", 409, "boot mismatch", {}, None
                )
            try:
                reply = super().request(method, path, data)
                reply.update(self.reply_boot)
                return reply
            finally:
                changed = (
                    self.boot_after_control
                    if data != self.data
                    else self.boot_after_upload
                )
                if changed is not None:
                    self.nonce = changed
        if path == "/wasm/list":
            version = self.version
            self.version = "0.8.8.8"  # Reuse the unchanged split-counter fixture.
            try:
                result = super().request(method, path, data)
            finally:
                self.version = version
            result["runtime"].update(
                boot_nonce_schema=UPLOAD.BOOT_SCHEMA,
                boot_nonce=self.nonce,
                station_mac=RECEIVER.station_mac,
                self_ping={
                    "state": "running",
                    "supervisor_started": True,
                    **{k: 0 for k in UPLOAD.PING_STABLE_COUNTERS},
                    "attempts": 2,
                    "starts": 1,
                    "create_failures": 1,
                    "successes": self.uptime // 20,
                    "timeouts": 0,
                    "last_error": 0,
                    "last_progress_age_ms": 20,
                    "last_progress_age_basis": "session_start_or_ping_callback",
                    **self.ping_overrides,
                },
            )
            result["runtime"].update(self.runtime_overrides)
            return result
        result = super().request(method, path, data)
        result.update(
            boot_nonce_schema=UPLOAD.BOOT_SCHEMA,
            boot_nonce=self.nonce,
            station_mac=RECEIVER.station_mac,
        )
        result.update(self.status_overrides)
        return result


class UploadTests(unittest.TestCase):
    def test_11_control_and_single_valid_upload_keep_exact_boot_and_package(self):
        for profile in UPLOAD.PACKAGES.values():
            data = profile.path.read_bytes()
            device = RecoveryDevice(data, profile)
            device.version = "0.8.8.11"
            result, device, checkpoints = self.run_case(
                device, data, profile=profile, expected_version="0.8.8.11"
            )
            self.assertTrue(result["passed"], result)
            posts = [call for call in device.calls if call[0] == "POST"]
            self.assertEqual(len(posts), 2)
            self.assertEqual(posts[0][2][:-1], data[:-1])
            self.assertNotEqual(posts[0][2][-1], data[-1])
            self.assertEqual(posts[1][2], data)
            self.assertTrue(
                all(
                    nonce == "1" * 32
                    for method, _, nonce in device.headers
                    if method == "POST"
                )
            )
            self.assertEqual(result["valid_upload_reply"]["boot_nonce"], "1" * 32)
            for row in result["snapshots"]:
                self.assertEqual(row["status"]["version"], "0.8.8.11")
                self.assertEqual(row["status"]["boot_nonce"], "1" * 32)
                self.assertEqual(row["listing"]["runtime"]["boot_nonce"], "1" * 32)
                self.assertIn("frame_overruns", row["listing"]["modules"][0])
            pending = [r for r in checkpoints if r["phase"] == "valid_signed_post"]
            self.assertEqual(len(pending), 1)
            self.assertTrue(pending[0]["valid_post_attempted"])
            self.assertFalse(result["sustained_runtime_qualified"])
            self.assertFalse(result["recognition_accuracy_qualified"])

    def test_11_preflight_preserves_version_identity_empty_and_callback_gates(self):
        for field, value in (
            ("status_overrides", {"version": "0.8.8.10"}),
            ("status_overrides", {"version": "0.8.8.12"}),
            ("status_overrides", {"station_mac": "02:ac:de:77:00:01"}),
            ("runtime_overrides", {"boot_nonce": "2" * 32}),
            ("ping_overrides", {"last_progress_age_ms": 3001}),
            ("empty_callback_overrides", {"frame_overruns": 1}),
            ("loaded", True),
        ):
            with self.subTest(field=field, value=value):
                device = RecoveryDevice()
                device.version = "0.8.8.11"
                setattr(device, field, value)
                result, device, _ = self.run_case(device, expected_version="0.8.8.11")
                self.assertFalse(result["passed"])
                self.assertFalse(any(method == "POST" for method, _, _ in device.calls))

    def test_11_uncertain_or_wrong_boot_reply_never_retries_valid_upload(self):
        for field, value in (
            ("valid_error", TimeoutError("private")),
            (
                "reply_boot",
                {"boot_nonce_schema": UPLOAD.BOOT_SCHEMA, "boot_nonce": "2" * 32},
            ),
            ("boot_after_control", "2" * 32),
        ):
            with self.subTest(field=field):
                device = RecoveryDevice()
                device.version = "0.8.8.11"
                setattr(device, field, value)
                result, device, _ = self.run_case(device, expected_version="0.8.8.11")
                self.assertFalse(result["passed"])
                valid_posts = sum(
                    m == "POST" and data == PACKAGE for m, _, data in device.calls
                )
                self.assertEqual(valid_posts, 0 if field == "boot_after_control" else 1)

    def test_10_success_pins_both_posts_and_all_snapshots_to_boot(self):
        for profile in UPLOAD.PACKAGES.values():
            data = profile.path.read_bytes()
            device = RecoveryDevice(data, profile)
            result, device, checkpoints = self.run_case(
                device, data, profile=profile, expected_version="0.8.8.10"
            )
            self.assertTrue(result["passed"], result)
            posts = [call for call in device.headers if call[0] == "POST"]
            self.assertEqual(len(posts), 2)
            self.assertTrue(all(call[2] == "1" * 32 for call in posts))
            self.assertEqual(result["valid_upload_reply"]["boot_nonce"], "1" * 32)
            for row in result["snapshots"]:
                self.assertEqual(
                    row["status"]["boot_nonce"], row["listing"]["runtime"]["boot_nonce"]
                )
                self.assertEqual(
                    row["listing"]["runtime"]["self_ping"]["state"], "running"
                )
            pending = next(
                row for row in checkpoints if row["phase"] == "valid_signed_post"
            )
            self.assertEqual(pending["boot_nonce"], "1" * 32)
            self.assertTrue(pending["valid_post_attempted"])

    def test_10_status_identity_gate_precedes_every_runtime_route(self):
        for key, value in (
            ("version", "0.7.0"),
            ("station_mac", "02:ac:de:77:00:01"),
            ("station_mac", RECEIVER.station_mac.upper()),
            ("boot_nonce", None),
            ("boot_nonce", "0" * 32),
            ("boot_nonce", "A" * 32),
            ("boot_nonce_schema", "other"),
            ("running_partition", "ota_0"),
        ):
            with self.subTest(key=key, value=value):
                device = RecoveryDevice()
                device.status_overrides = {key: value}
                result, device, _ = self.run_case(device, expected_version="0.8.8.10")
                self.assertFalse(result["passed"])
                self.assertEqual(
                    [(m, p) for m, p, _ in device.calls], [("GET", "/ota/status")]
                )
        device = RecoveryDevice()
        device.boot_after_control = "2" * 32
        result, device, _ = self.run_case(device, expected_version="0.8.8.10")
        self.assertFalse(result["passed"])
        self.assertEqual(result["errors"][-1]["code"], "boot_nonce_changed")
        self.assertEqual(sum(p == "/wasm/list" for _, p, _ in device.calls), 1)
        self.assertEqual(sum(m == "POST" for m, _, _ in device.calls), 1)

    def test_10_list_identity_health_and_callback_gates_remain_binding(self):
        for overrides in (
            {"boot_nonce": "2" * 32},
            {"station_mac": "wrong"},
            {"boot_nonce_schema": None},
        ):
            device = RecoveryDevice()
            device.runtime_overrides = overrides
            result, device, _ = self.run_case(device, expected_version="0.8.8.10")
            self.assertFalse(result["passed"])
            self.assertFalse(any(m == "POST" for m, _, _ in device.calls))
        for key, value in (
            ("state", "blocked"),
            ("supervisor_started", 1),
            ("last_progress_age_ms", None),
            ("last_progress_age_ms", 3001),
            ("last_progress_age_basis", "CSI"),
            ("starts", True),
            ("last_error", False),
            ("attempts", 0),
        ):
            device = RecoveryDevice()
            device.ping_overrides = {key: value}
            result, device, _ = self.run_case(device, expected_version="0.8.8.10")
            self.assertFalse(result["passed"], (key, value))
            self.assertFalse(any(m == "POST" for m, _, _ in device.calls))
        device = RecoveryDevice()
        device.empty_callback_overrides = {"frame_overruns": 1}
        result, device, _ = self.run_case(device, expected_version="0.8.8.10")
        self.assertFalse(result["passed"])
        self.assertFalse(any(m == "POST" for m, _, _ in device.calls))

    def test_10_reply_binding_and_lost_response_never_retry_valid_post(self):
        for reply in (
            {},
            {"boot_nonce_schema": "bad", "boot_nonce": "1" * 32},
            {"boot_nonce_schema": UPLOAD.BOOT_SCHEMA, "boot_nonce": "2" * 32},
        ):
            device = RecoveryDevice()
            device.reply_boot = reply
            result, device, _ = self.run_case(device, expected_version="0.8.8.10")
            self.assertFalse(result["passed"])
            self.assertEqual(
                result["errors"][-1]["code"], "upload_reply_boot_nonce_mismatch"
            )
            self.assertEqual(
                sum(m == "POST" and d == PACKAGE for m, _, d in device.calls), 1
            )
        for failure in (TimeoutError("private"), ValueError("private")):
            device = RecoveryDevice()
            device.valid_error = failure
            device.boot_after_upload = "2" * 32
            result, device, _ = self.run_case(device, expected_version="0.8.8.10")
            self.assertFalse(result["passed"])
            self.assertEqual(result["outcome"], "valid_upload_outcome_uncertain")
            self.assertEqual(
                sum(m == "POST" and d == PACKAGE for m, _, d in device.calls), 1
            )
            self.assertEqual(sum(p == "/wasm/list" for _, p, _ in device.calls), 2)

    def test_legacy_version_mismatch_also_prevents_unsafe_runtime_read(self):
        for version in ("0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8"):
            device = FakeDevice()
            device.version = "0.7.0"
            result, device, _ = self.run_case(device, expected_version=version)
            self.assertFalse(result["passed"])
            self.assertEqual(
                [(m, p) for m, p, _ in device.calls], [("GET", "/ota/status")]
            )

    def test_10_real_request_adapter_header_and_bounded_response(self):
        import io

        class Reply(io.BytesIO):
            status = 200

        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Reply(self.body)

        opener = Opener()
        opener.body = b'{"status":"ok"}'
        with patch.object(UPLOAD.urllib.request, "build_opener", return_value=opener):
            request = UPLOAD.make_request(receiver=RECEIVER, revalidate=lambda: None)
        request("POST", "/wasm/upload", b"synthetic", expected_boot_nonce="1" * 32)
        self.assertEqual(
            dict((k.lower(), v) for k, v in opener.request.header_items())[
                "x-ruview-expected-boot-nonce"
            ],
            "1" * 32,
        )
        self.assertEqual(opener.timeout, 45)
        opener.body = b" " * (UPLOAD.MAX_DEVICE_REPLY_BYTES + 1)
        with self.assertRaisesRegex(UPLOAD.GateError, "device_reply_too_large"):
            request("GET", "/ota/status")
        for bad in ("0" * 32, "A" * 32, "x\r\nInjected: true"):
            with self.assertRaisesRegex(
                UPLOAD.GateError, "invalid_expected_boot_nonce_header"
            ):
                request("POST", "/wasm/upload", b"synthetic", expected_boot_nonce=bad)

    def test_8_rejects_missing_or_faulted_callback_evidence_before_upload(self):
        for missing, overrun in ((True, 0), (False, 1)):
            with self.subTest(missing=missing, overrun=overrun):
                device = FakeDevice()
                device.version = "0.8.8.8"
                device.include_callback_metrics = not missing
                device.empty_callback_overrides = {"timer_overruns": overrun}
                result, device, _ = self.run_case(device, expected_version="0.8.8.8")
                self.assertFalse(result["passed"])
                self.assertFalse(any(method == "POST" for method, _, _ in device.calls))

    def run_case(
        self,
        device=None,
        package=PACKAGE,
        partition="ota_1",
        profile=UPLOAD.HOME_SIGNAL,
        expected_version="0.8.8.5",
    ):
        device = device or FakeDevice()
        checkpoints = []
        clock = iter(i * 0.1 for i in range(100))
        result = UPLOAD.run_upload(
            package,
            partition,
            device.request,
            lambda r: checkpoints.append(copy.deepcopy(r)),
            lambda: next(clock),
            package=profile,
            expected_version=expected_version,
            receiver=RECEIVER,
            revalidate=lambda: None,
        )
        self.assertEqual(checkpoints[-1], result)
        return result, device, checkpoints

    def test_success_has_one_valid_post_and_pre_post_durable_attempt(self):
        result, device, checkpoints = self.run_case()
        self.assertTrue(result["passed"], result)
        posts = [c for c in device.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[1][2], PACKAGE)
        self.assertEqual(posts[0][2][:-1], PACKAGE[:-1])
        self.assertNotEqual(posts[0][2][-1], PACKAGE[-1])
        pending = [r for r in checkpoints if r["phase"] == "valid_signed_post"]
        self.assertEqual(len(pending), 1)
        self.assertTrue(pending[0]["valid_post_attempted"])
        self.assertEqual(pending[0]["outcome"], "valid_upload_outcome_uncertain")
        self.assertFalse(result["sustained_runtime_qualified"])

    def test_wrong_package_or_partition_prevents_every_request(self):
        for package, partition in ((PACKAGE[:-1], "ota_1"), (PACKAGE, "factory")):
            result, device, _ = self.run_case(package=package, partition=partition)
            self.assertFalse(result["passed"])
            self.assertEqual(device.calls, [])

    def test_expected_version_is_exact_for_all_package_profiles(self):
        for version in ("0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8"):
            for profile in UPLOAD.PACKAGES.values():
                with self.subTest(version=version, profile=profile.profile):
                    data = profile.path.read_bytes()
                    device = FakeDevice(data, profile)
                    device.version = version
                    result, _, _ = self.run_case(
                        device, package=data, profile=profile, expected_version=version
                    )
                    self.assertTrue(result["passed"], result)
                    self.assertEqual(result["expected_version"], version)
                    device = FakeDevice(data, profile)
                    device.version = "0.8.8.6" if version == "0.8.8.5" else "0.8.8.5"
                    result, device, _ = self.run_case(
                        device, package=data, profile=profile, expected_version=version
                    )
                    self.assertFalse(result["passed"])
                    self.assertEqual(
                        result["errors"][-1]["code"], "firmware_or_partition_mismatch"
                    )
                    self.assertFalse(any(c[0] == "POST" for c in device.calls))

    def test_unknown_expected_versions_fail_before_any_request(self):
        for version in (
            "0.8.8.4",
            "0.8.8.9",
            "0.8.8.13",
            "0.8.8.60",
            "latest",
            None,
            True,
        ):
            with self.subTest(version=version):
                result, device, _ = self.run_case(expected_version=version)
                self.assertFalse(result["passed"])
                self.assertEqual(
                    result["errors"][-1]["code"], "invalid_expected_version"
                )
                self.assertEqual(device.calls, [])
                with self.assertRaisesRegex(
                    UPLOAD.GateError, "invalid_expected_version"
                ):
                    UPLOAD.validate_snapshot(
                        {}, "ota_1", expected_version=version, receiver=RECEIVER
                    )

    def test_version_drift_after_control_or_upload_never_qualifies(self):
        for version in ("0.8.8.6", "0.8.8.7", "0.8.8.8"):
            for changed_at, expected_posts in (
                ("version_after_control", 1),
                ("version_after_upload", 2),
            ):
                with self.subTest(version=version, changed_at=changed_at):
                    device = FakeDevice()
                    device.version = version
                    setattr(device, changed_at, "0.8.8.5")
                    result, device, _ = self.run_case(device, expected_version=version)
                    self.assertFalse(result["passed"])
                    self.assertEqual(
                        result["errors"][-1]["code"], "firmware_or_partition_mismatch"
                    )
                    self.assertEqual(
                        len([c for c in device.calls if c[0] == "POST"]), expected_posts
                    )

    def test_7_preserves_split_metrics_in_every_snapshot(self):
        device = FakeDevice()
        device.version = "0.8.8.7"
        result, _, _ = self.run_case(device, expected_version="0.8.8.7")
        self.assertTrue(result["passed"], result)
        for snapshot in result["snapshots"]:
            for slot in snapshot["listing"]["modules"]:
                self.assertTrue(all(key in slot for key in UPLOAD.CALLBACK_KEYS))
                self.assertEqual(
                    slot["max_us"], max(slot["max_frame_us"], slot["max_timer_us"])
                )
                self.assertEqual(slot["frame_overruns"], 0)
                self.assertEqual(slot["timer_overruns"], 0)
                if slot["state"] == "empty":
                    self.assertTrue(all(slot[key] == 0 for key in UPLOAD.CALLBACK_KEYS))

    def test_7_callback_boundaries_alias_and_cumulative_overruns(self):
        for field in ("max_frame_us", "max_timer_us"):
            for value, expected_code in (
                (10000, None),
                (10001, "callback_budget_exceeded"),
            ):
                with self.subTest(field=field, value=value):
                    device = FakeDevice()
                    device.version = "0.8.8.7"
                    device.callback_overrides = {field: value, "max_us": value}
                    result, device, _ = self.run_case(
                        device, expected_version="0.8.8.7"
                    )
                    self.assertEqual(result["passed"], expected_code is None)
                    if expected_code:
                        self.assertEqual(result["errors"][-1]["code"], expected_code)
                    self.assertEqual(
                        len([c for c in device.calls if c[0] == "POST"]), 2
                    )
        for overrides, code in (
            ({"max_frame_us": 499}, "callback_maximum_mismatch"),
            ({"frame_overruns": 1}, "callback_overrun_recorded"),
            ({"timer_overruns": 1}, "callback_overrun_recorded"),
        ):
            with self.subTest(overrides=overrides):
                device = FakeDevice()
                device.version = "0.8.8.7"
                device.callback_overrides = overrides
                result, device, _ = self.run_case(device, expected_version="0.8.8.7")
                self.assertFalse(result["passed"])
                self.assertEqual(result["errors"][-1]["code"], code)
                self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 2)

    def test_7_requires_typed_nonnegative_uint32_callback_metrics(self):
        for field in (*UPLOAD.CALLBACK_KEYS, "max_us"):
            for value in (None, -1, False, True, 0.0, "0", 1 << 32):
                with self.subTest(field=field, value=value):
                    device = FakeDevice()
                    device.version = "0.8.8.7"
                    device.callback_overrides = {field: value}
                    result, device, _ = self.run_case(
                        device, expected_version="0.8.8.7"
                    )
                    self.assertFalse(result["passed"])
                    self.assertEqual(
                        result["errors"][-1]["code"], "callback_metrics_invalid"
                    )
                    self.assertEqual(
                        len([c for c in device.calls if c[0] == "POST"]), 2
                    )

    def test_7_empty_missing_or_nonzero_metrics_prevent_every_post(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                device = FakeDevice()
                device.version = "0.8.8.7"
                device.include_callback_metrics = not missing
                device.empty_callback_overrides = {"max_us": 1, "max_timer_us": 1}
                result, device, _ = self.run_case(device, expected_version="0.8.8.7")
                self.assertFalse(result["passed"])
                self.assertEqual(
                    result["errors"][-1]["code"],
                    "callback_metrics_invalid"
                    if missing
                    else "empty_callback_metrics_nonzero",
                )
                self.assertFalse(any(c[0] == "POST" for c in device.calls))

    def test_legacy_snapshots_ignore_new_metrics_and_keep_original_shape(self):
        for version in ("0.8.8.5", "0.8.8.6"):
            with self.subTest(version=version):
                device = FakeDevice()
                device.version = version
                original, _, _ = self.run_case(device, expected_version=version)
                device = FakeDevice()
                device.version = version
                device.callback_overrides = {
                    "max_frame_us": None,
                    "max_timer_us": -1,
                    "frame_overruns": 1,
                    "timer_overruns": True,
                }
                result, _, _ = self.run_case(device, expected_version=version)
                self.assertTrue(result["passed"], result)
                self.assertEqual(result["snapshots"], original["snapshots"])
                for snapshot in result["snapshots"]:
                    for slot in snapshot["listing"]["modules"]:
                        self.assertTrue(
                            all(key not in slot for key in UPLOAD.CALLBACK_KEYS)
                        )

    def test_wrong_firmware_partition_and_nonempty_state_prevent_posts(self):
        for attribute, value in (
            ("version", "0.8.8.4"),
            ("partition", "ota_0"),
            ("loaded", True),
        ):
            device = FakeDevice()
            setattr(device, attribute, value)
            result, device, _ = self.run_case(device)
            self.assertFalse(result["passed"])
            self.assertFalse(any(c[0] == "POST" for c in device.calls))

    def test_duplicate_slot_identity_prevents_posts(self):
        device = FakeDevice()
        device.slots_override = [{"id": 0, "state": "empty"} for _ in range(4)]
        result, device, _ = self.run_case(device)
        self.assertFalse(result["passed"])
        self.assertFalse(any(c[0] == "POST" for c in device.calls))

    def test_control_acceptance_other_error_or_redirect_never_send_valid_post(self):
        for code in (200, 302, 307, 400, 500):
            device = FakeDevice()
            device.control_code = code
            result, device, _ = self.run_case(device)
            self.assertFalse(result["passed"])
            self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 1)
            self.assertFalse(result["valid_post_attempted"])

    def test_corrupt_rejection_requires_empty_state_and_same_boot(self):
        for attribute in ("control_loads", "reset_after_control"):
            device = FakeDevice()
            setattr(device, attribute, True)
            result, device, _ = self.run_case(device)
            self.assertFalse(result["passed"])
            self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 1)

    def test_uncertain_or_error_response_is_not_retried_or_promoted(self):
        for exc in (
            TimeoutError("sensitive text must not appear"),
            ValueError("body may contain a token"),
            urllib.error.HTTPError("http://private/", 500, "private body", {}, None),
        ):
            device = FakeDevice()
            device.valid_error = exc
            result, device, _ = self.run_case(device)
            self.assertFalse(result["passed"])
            self.assertEqual(result["outcome"], "valid_upload_outcome_uncertain")
            self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 2)
            self.assertEqual(
                result["snapshots"][-1]["label"], "readback_after_uncertain_post"
            )
            self.assertNotIn("sensitive text", str(result))
            self.assertNotIn("private body", str(result))
            self.assertNotIn("token", str(result["errors"]))

    def test_bad_success_metadata_requires_operator_review(self):
        device = FakeDevice()
        device.reply_override = {
            "status": "ok",
            "format": "rvf",
            "name": "home-signal",
            "started": False,
        }
        result, device, _ = self.run_case(device)
        self.assertFalse(result["passed"])
        self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 2)

    def test_immediate_over_budget_is_not_qualified(self):
        device = FakeDevice()
        device.max_us = 10001
        result, _, _ = self.run_case(device)
        self.assertFalse(result["passed"])
        self.assertEqual(result["errors"][-1]["code"], "immediate_module_telemetry")

    def test_http_redirect_handler_never_returns_another_request(self):
        handler = UPLOAD.NoRedirect()
        for code in (301, 302, 303, 307, 308):
            self.assertIsNone(
                handler.redirect_request(None, None, code, "", {}, "http://elsewhere/")
            )

    def test_existing_evidence_prevents_all_requests_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_bytes(b"original evidence\n")
            argv = ["upload", "--expect-partition", "ota_1", "--output", str(output)]
            with (
                patch("sys.argv", argv),
                patch.object(UPLOAD, "make_request") as network,
            ):
                with self.assertRaises(FileExistsError):
                    run_cli(UPLOAD)
                network.assert_not_called()
            self.assertEqual(output.read_bytes(), b"original evidence\n")

    def test_invalid_package_writes_failure_without_network_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            package = Path(directory) / "invalid.rvf"
            package.write_bytes(b"invalid fixture")
            device = FakeDevice()
            argv = ["upload", "--expect-partition", "ota_1", "--output", str(output)]
            with (
                patch("sys.argv", argv),
                patch.object(
                    UPLOAD,
                    "load_package",
                    return_value=replace(UPLOAD.HOME_SIGNAL, path=package),
                ),
                patch.object(UPLOAD, "make_request", return_value=device.request),
                patch("builtins.print"),
            ):
                self.assertEqual(run_cli(UPLOAD), 1)
            report = json.loads(output.read_text())
            self.assertFalse(report["passed"])
            self.assertEqual(report["outcome"], "preflight_rejected_no_upload")
            self.assertFalse(report["valid_post_attempted"])
            self.assertEqual(device.calls, [])

    def test_explicit_other_profile_does_not_mutate_original_pins(self):
        # A synthetic RVF exercises profile plumbing with injected HTTP only;
        # it does not enable any CLI profile or claim signature verification.
        wasm = PACKAGE[128:-64] + b"\0\0\0\0"
        data = bytearray(PACKAGE[:128] + wasm + PACKAGE[-64:])
        struct.pack_into(
            "<IHHIIIIII",
            data,
            0,
            0x01465652,
            1,
            1,
            96,
            len(wasm),
            64,
            0,
            len(data),
            0,
        )
        data[32:64] = b"home-signal-v2".ljust(32, b"\0")
        data[128] ^= 1
        wasm_sha = hashlib.sha256(data[128:-64]).hexdigest()
        data[80:112] = bytes.fromhex(wasm_sha)
        data = bytes(data)
        profile = replace(
            UPLOAD.HOME_SIGNAL,
            profile="home-signal-v2",
            name="home-signal-v2",
            package_sha256=hashlib.sha256(data).hexdigest(),
            wasm_sha256=wasm_sha,
            package_bytes=len(data),
            wasm_bytes=len(wasm),
        )
        device = FakeDevice(data, profile)
        result, device, _ = self.run_case(device, package=data, profile=profile)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["package_profile"], "home-signal-v2")
        self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 2)
        self.assertEqual(UPLOAD.PACKAGE_SHA, UPLOAD.HOME_SIGNAL.package_sha256)
        self.assertEqual(UPLOAD.PACKAGE.read_bytes(), PACKAGE)
        for data_arg, profile_arg in ((PACKAGE, profile), (data, UPLOAD.HOME_SIGNAL)):
            result, device, _ = self.run_case(package=data_arg, profile=profile_arg)
            self.assertFalse(result["passed"])
            self.assertEqual(device.calls, [])
        wrong_device = FakeDevice(data, UPLOAD.HOME_SIGNAL)
        result, _, _ = self.run_case(wrong_device, package=data, profile=profile)
        self.assertFalse(result["passed"])
        self.assertEqual(
            result["errors"][-1]["code"], "upload_did_not_start_expected_module"
        )

    def test_disabled_descriptor_prevents_all_requests(self):
        disabled = replace(UPLOAD.HOME_SIGNAL, package_sha256=None)
        result, device, _ = self.run_case(profile=disabled)
        self.assertFalse(result["passed"])
        self.assertEqual(result["errors"][-1]["code"], "package_profile_unavailable")
        self.assertEqual(device.calls, [])

    def test_real_packages_require_their_explicit_profile(self):
        for profile in UPLOAD.PACKAGES.values():
            data = profile.path.read_bytes()
            UPLOAD.validate_package(data, profile)
            result, device, _ = self.run_case(
                FakeDevice(data, profile), package=data, profile=profile
            )
            self.assertTrue(result["passed"], result)
            self.assertEqual(result["package_profile"], profile.profile)
            self.assertFalse(result["sustained_runtime_qualified"])
            self.assertEqual(len([c for c in device.calls if c[0] == "POST"]), 2)
            for other in UPLOAD.PACKAGES.values():
                if other == profile:
                    continue
                with self.subTest(binary=profile.profile, profile=other.profile):
                    result, device, _ = self.run_case(package=data, profile=other)
                    self.assertFalse(result["passed"])
                    self.assertEqual(
                        result["errors"][-1]["code"], "package_sha_mismatch"
                    )
                    self.assertEqual(device.calls, [])

    def test_unavailable_cli_profile_does_not_open_report_or_create_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            argv = [
                "upload",
                "--expect-partition",
                "ota_1",
                "--output",
                str(output),
                "--package-profile",
                "home-signal-v2",
            ]
            with (
                patch("sys.argv", argv),
                patch.object(
                    UPLOAD,
                    "load_package",
                    side_effect=ValueError("package_profile_unavailable"),
                ),
                patch.object(UPLOAD, "make_request") as network,
                patch("sys.stderr"),
            ):
                with self.assertRaises(SystemExit) as exc:
                    run_cli(UPLOAD)
                self.assertEqual(exc.exception.code, 2)
                network.assert_not_called()
            self.assertFalse(output.exists())

    def test_cli_expected_version_defaults_to_5_and_passes_explicit_selection(self):
        for version, options in (
            ("0.8.8.5", []),
            ("0.8.8.6", ["--expected-version", "0.8.8.6"]),
            ("0.8.8.7", ["--expected-version", "0.8.8.7"]),
            ("0.8.8.8", ["--expected-version", "0.8.8.8"]),
            ("0.8.8.10", ["--expected-version", "0.8.8.10"]),
            ("0.8.8.11", ["--expected-version", "0.8.8.11"]),
        ):
            with (
                self.subTest(version=version),
                tempfile.TemporaryDirectory() as directory,
            ):
                output = Path(directory) / "report.json"
                device = (
                    RecoveryDevice()
                    if version in ("0.8.8.10", "0.8.8.11")
                    else FakeDevice()
                )
                device.version = version
                argv = [
                    "upload",
                    "--expect-partition",
                    "ota_1",
                    "--output",
                    str(output),
                ]
                # FakeDevice advances uptime by 200 ms per listing. Use the
                # same synthetic clock as run_case, not host scheduling/fsync.
                clock = iter(i * 0.1 for i in range(100))
                with (
                    patch("sys.argv", argv + options),
                    patch.object(UPLOAD, "make_request", return_value=device.request),
                    patch.object(
                        UPLOAD,
                        "run_upload",
                        side_effect=partial(UPLOAD.run_upload, clock=clock.__next__),
                    ),
                    patch("builtins.print"),
                ):
                    exit_code = run_cli(UPLOAD)
                report = json.loads(output.read_text())
                self.assertEqual(exit_code, 0, report["errors"])
                self.assertEqual(report["expected_version"], version)
                self.assertTrue(report["passed"])

    def test_fake_uptime_must_still_fit_elapsed_clock_tolerance(self):
        # A delayed host clock can invalidate this fixed-rate fake. The CLI
        # fixture must align its clocks rather than bypass the real guard.
        for elapsed, passed in ((0.2, True), (0.7, True), (0.701, False), (2.0, False)):
            with self.subTest(elapsed=elapsed):
                device = FakeDevice()
                device.version = "0.8.8.7"
                clock = iter(
                    [0.0, 0.0, 0.0, elapsed, elapsed, elapsed + 0.1, elapsed + 0.1]
                )
                report = UPLOAD.run_upload(
                    PACKAGE,
                    "ota_1",
                    device.request,
                    lambda _report: None,
                    clock.__next__,
                    expected_version=device.version,
                    receiver=RECEIVER,
                    revalidate=lambda: None,
                )
                self.assertEqual(report["passed"], passed, report["errors"])
                self.assertEqual(report["valid_post_attempted"], passed)
                posts = [call for call in device.calls if call[0] == "POST"]
                self.assertEqual(len(posts), 2 if passed else 1)
                if not passed:
                    self.assertEqual(
                        report["errors"][-1]["code"],
                        "uptime_disagrees_with_elapsed",
                    )
                    self.assertEqual(report["errors"][-1]["stage"], "empty_recheck")

    def test_cli_rejects_unlisted_version_before_output_or_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            argv = [
                "upload",
                "--expect-partition",
                "ota_1",
                "--output",
                str(output),
                "--expected-version",
                "0.8.8.9",
            ]
            with (
                patch("sys.argv", argv),
                patch.object(UPLOAD, "make_request") as network,
                patch("sys.stderr"),
            ):
                with self.assertRaises(SystemExit) as exc:
                    run_cli(UPLOAD)
                self.assertEqual(exc.exception.code, 2)
                network.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
