import copy
import hashlib
import importlib.util
import io
import json
import os
import signal
import stat
import tempfile
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from module_manifest_fixture import catalog, runtime_arguments

spec = importlib.util.spec_from_file_location(
    "modules", Path(__file__).resolve().parents[1] / "firmware/reconcile-modules.py"
)
modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modules)


class ReviewDiagnosticTests(unittest.TestCase):
    def test_only_fixed_guard_messages_are_exposed(self):
        self.assertEqual(
            modules.review_reason(
                ValueError("Callback overrun history needs operator review")
            ),
            "callback_overrun_history",
        )
        for error, expected in (
            (
                ValueError("private receiver response"),
                "invalid_response_or_configuration",
            ),
            (ValueError({"private": "data"}), "invalid_response_or_configuration"),
            (ValueError("known", "private"), "invalid_response_or_configuration"),
            (KeyError("private key"), "invalid_response_or_configuration"),
            (TypeError("private shape"), "invalid_response_or_configuration"),
            (TimeoutError("private URL"), "request_timeout"),
            (OSError("private path"), "io_failure"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(modules.review_reason(error), expected)
        self.assertEqual(
            len(set(modules.REVIEW_REASON_BY_MESSAGE.values())),
            len(modules.REVIEW_REASON_BY_MESSAGE) - 1,
        )

    def test_cli_keeps_failure_exit_and_continues_other_nodes_without_raw_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text('{"packages": []}')
            (root / "targets.json").write_text(
                json.dumps([{"node_id": 1}, {"node_id": 2}, {"node_id": 3}])
            )
            output = io.StringIO()
            with (
                patch(
                    "sys.argv",
                    [
                        "reconcile",
                        "--directory",
                        directory,
                        *runtime_arguments(root / "manifest.json"),
                    ],
                ),
                patch.object(modules, "make_request"),
                patch.object(
                    modules,
                    "reconcile",
                    side_effect=[
                        ValueError("private receiver response"),
                        ["disabled"],
                        ValueError("Callback overrun history needs operator review"),
                    ],
                ) as reconcile,
                patch("sys.stdout", output),
                self.assertRaises(SystemExit) as stopped,
            ):
                modules.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual(reconcile.call_count, 3)
            self.assertEqual(
                output.getvalue().splitlines(),
                [
                    "node1: review_required (ValueError; reason=invalid_response_or_configuration)",
                    "node2: disabled",
                    "node3: review_required (ValueError; reason=callback_overrun_history)",
                ],
            )


class PackageBytesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "modules"
        self.directory.mkdir()
        source = Path(__file__).resolve().parents[1] / "tests/fixtures/modules"
        self.package = catalog()["packages"][0]
        self.data = (source / self.package["file"]).read_bytes()

    def test_plain_file_and_kubernetes_projected_file_keep_signed_identity(self):
        path = self.directory / self.package["file"]
        path.write_bytes(self.data)
        self.assertEqual(modules.package_bytes(self.package, self.directory), self.data)
        path.unlink()
        generation = self.directory / "..2026_10_05_23_21_32.000000000"
        generation.mkdir()
        (generation / path.name).write_bytes(self.data)
        (self.directory / "..data").symlink_to(
            generation.name, target_is_directory=True
        )
        path.symlink_to(Path("..data") / path.name)
        self.assertEqual(modules.package_bytes(self.package, self.directory), self.data)

    def test_manifest_paths_must_be_plain_basenames(self):
        for filename in (
            "",
            ".",
            "..",
            "../package.rvf",
            "folder/package.rvf",
            "/package.rvf",
            "./package.rvf",
            "package.rvf/",
            "folder\\package.rvf",
            "bad\0name",
            None,
            4,
        ):
            with (
                self.subTest(filename=filename),
                self.assertRaisesRegex(ValueError, "basename"),
            ):
                modules.package_bytes(
                    {**self.package, "file": filename}, self.directory
                )

    def test_direct_and_projected_symlink_escapes_are_rejected_before_read(self):
        outside = self.root / self.package["file"]
        outside.write_bytes(self.data)
        path = self.directory / self.package["file"]
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "within"):
            modules.package_bytes(self.package, self.directory)
        path.unlink()
        (self.directory / "..data").symlink_to(self.root, target_is_directory=True)
        path.symlink_to(Path("..data") / path.name)
        with self.assertRaisesRegex(ValueError, "within"):
            modules.package_bytes(self.package, self.directory)

    def test_directory_and_fifo_are_not_read_as_packages(self):
        path = self.directory / self.package["file"]
        path.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            modules.package_bytes(self.package, self.directory)
        path.rmdir()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular file"):
            modules.package_bytes(self.package, self.directory)

    def test_package_hash_header_and_manifest_checks_remain_required(self):
        path = self.directory / self.package["file"]
        path.write_bytes(self.data)
        for changes, message in (
            ({"sha256": "0" * 64}, "hash mismatch"),
            ({"name": "another-package"}, "manifest mismatch"),
            ({"wasm_bytes": 1}, "manifest mismatch"),
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(ValueError, message),
            ):
                modules.package_bytes({**self.package, **changes}, self.directory)
        invalid = b"not an RVF" * 30
        path.write_bytes(invalid)
        with self.assertRaisesRegex(ValueError, "Invalid RVF"):
            modules.package_bytes(
                {**self.package, "sha256": hashlib.sha256(invalid).hexdigest()},
                self.directory,
            )


class ReconciliationTests(unittest.TestCase):
    target = {
        "enabled": True,
        "firmware_version": "0.8.8.4",
        "node_id": 2,
        "ip": "192.0.2.2",
        "restore_generation": "reviewed-1",
    }
    data = b"signed-fixture"
    package = {
        "name": "home-signal",
        "wasm_bytes": 100,
        "capabilities": "0x6b",
        "max_frame_us": 10000,
        "deployment": "qualified_for_auto_restore",
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_directory = Path(self.temp.name).resolve()

    def empty_slots(self):
        return [
            {
                "id": i,
                "state": "empty",
                "name": "",
                "caps": "0x0000",
                **dict.fromkeys(
                    (
                        "binary_size",
                        "frame_count",
                        "event_count",
                        "error_count",
                        "mean_us",
                        "max_us",
                        "budget_us",
                        "budget_faults",
                    ),
                    0,
                ),
            }
            for i in range(4)
        ]

    running = {
        "name": "home-signal",
        "state": "running",
        "binary_size": 100,
        "error_count": 0,
        "budget_faults": 0,
        "caps": "0x006b",
        "budget_us": 10000,
        "max_us": 3000,
    }

    def run_case(
        self,
        version="0.8.8.4",
        slots=None,
        started=True,
        target=None,
        packages=None,
        state_directory=...,
        upload_error=None,
        listing_override=None,
    ):
        self.calls = []

        def request(target, method, path, data):
            self.calls.append((method, path))
            if path == "/ota/status":
                return {"version": version}
            if path == "/wasm/list":
                default_slots = self.empty_slots()
                if version in ("0.8.8.7", "0.8.8.8"):
                    for slot in default_slots:
                        slot.update(
                            max_frame_us=0,
                            max_timer_us=0,
                            frame_overruns=0,
                            timer_overruns=0,
                        )
                return (
                    listing_override
                    if listing_override is not None
                    else {
                        "max": 4,
                        "loaded": 0,
                        "modules": slots if slots is not None else default_slots,
                    }
                )
            if upload_error:
                raise upload_error
            return {"name": "home-signal", "started": started}

        return modules.reconcile(
            self.target if target is None else target,
            [(self.package, b"signed-fixture")] if packages is None else packages,
            request,
            state_directory=self.state_directory
            if state_directory is ...
            else state_directory,
        )

    def test_disabled_target_never_requests_or_requires_package_qualification(self):
        self.assertEqual(
            self.run_case(
                target={"enabled": False}, packages=[({}, b"failed-fixture")]
            ),
            ["disabled"],
        )
        self.assertEqual(self.calls, [])

    def test_every_package_must_be_qualified_before_any_request(self):
        for deployment in (None, "hardware_trial_failed_no_active_instance", "pending"):
            with self.subTest(deployment=deployment):
                unqualified = {**self.package, "deployment": deployment}
                with self.assertRaisesRegex(ValueError, "not qualified"):
                    self.run_case(
                        packages=[
                            (self.package, b"qualified-fixture"),
                            (unqualified, b"unqualified-fixture"),
                        ]
                    )
                self.assertEqual(self.calls, [])

    def test_failed_or_candidate_packages_cannot_be_restored_by_inventory_flag(self):
        for status in ("hardware_trial_failed", "candidate_not_qualified_for_restore"):
            package = dict(self.package, deployment=status)
            with (
                self.subTest(status=status),
                self.assertRaisesRegex(ValueError, "not qualified"),
            ):
                self.run_case(packages=[(package, b"failed-fixture")])
            self.assertEqual(self.calls, [])

    def test_invalid_manifest_capabilities_or_budget_reject_before_request(self):
        for key, value in (
            ("capabilities", None),
            ("capabilities", "invalid"),
            ("capabilities", "0x0"),
            ("capabilities", "0x80"),
            ("capabilities", "0xffffffff"),
            ("max_frame_us", 0),
            ("max_frame_us", 10001),
            ("max_frame_us", 0xFFFFFFFF),
            ("max_frame_us", True),
            ("max_frame_us", 10000.0),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    self.run_case(
                        packages=[({**self.package, key: value}, b"signed-fixture")]
                    )
                self.assertEqual(self.calls, [])

    def test_only_qualified_firmware_receives_upload(self):
        self.assertEqual(
            self.run_case(version="0.8.8"), ["awaiting_qualified_firmware"]
        )
        self.assertEqual(len(self.calls), 1)

    def test_reboot_with_empty_slots_restores_package(self):
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(self.calls[-1], ("POST", "/wasm/upload"))
        markers = list(self.state_directory.iterdir())
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0].name, "node-2--reviewed-1.attempt.json")
        marker = json.loads(markers[0].read_text())
        self.assertEqual(marker["firmware_version"], self.target["firmware_version"])
        self.assertEqual(marker["package_sha256"], self.package["sha256"])
        self.assertEqual(stat.S_IMODE(markers[0].stat().st_mode), 0o600)

    def test_persistent_second_empty_run_after_reboot_is_blocked(self):
        self.run_case()
        before = {p.name: p.read_bytes() for p in self.state_directory.iterdir()}
        with self.assertRaises(FileExistsError):
            self.run_case()
        self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(
            {p.name: p.read_bytes() for p in self.state_directory.iterdir()}, before
        )

    def test_lost_reply_or_failed_start_permanently_consumes_generation(self):
        for outcome in ("lost", "not_started"):
            with self.subTest(outcome=outcome):
                target = {**self.target, "restore_generation": outcome}
                with self.assertRaises((TimeoutError, ValueError)):
                    self.run_case(
                        target=target,
                        started=False,
                        upload_error=TimeoutError("lost")
                        if outcome == "lost"
                        else None,
                    )
                self.assertEqual(self.calls[-1], ("POST", "/wasm/upload"))
                with self.assertRaises(FileExistsError):
                    self.run_case(target=target)
                self.assertFalse(any(method == "POST" for method, _ in self.calls))

    def test_ip_firmware_and_package_changes_do_not_rearm_generation(self):
        self.run_case()
        data = b"different signed package"
        for target, packages in (
            ({**self.target, "ip": "192.0.2.3"}, None),
            ({**self.target, "firmware_version": "0.8.8.7"}, None),
            (
                self.target,
                [
                    (
                        {
                            **self.package,
                            "name": "new-module",
                            "sha256": hashlib.sha256(data).hexdigest(),
                        },
                        data,
                    )
                ],
            ),
        ):
            with self.subTest(target=target, packages=packages):
                with self.assertRaises(FileExistsError):
                    self.run_case(
                        target=target,
                        version=target["firmware_version"],
                        packages=packages,
                    )
                self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(len(list(self.state_directory.iterdir())), 1)

    def test_operator_new_generation_is_only_explicit_rearm(self):
        self.run_case()
        self.assertEqual(
            self.run_case(target={**self.target, "restore_generation": "reviewed-2"}),
            ["home-signal:restored"],
        )
        self.assertEqual(len(list(self.state_directory.iterdir())), 2)

    def test_concurrent_reconciliation_permits_one_upload(self):
        posts = []

        def request(target, method, path, data):
            if path == "/ota/status":
                return {"version": self.target["firmware_version"]}
            if path == "/wasm/list":
                return {"max": 4, "loaded": 0, "modules": self.empty_slots()}
            posts.append(data)
            return {"name": "home-signal", "started": True}

        def attempt(_):
            try:
                return modules.reconcile(
                    self.target,
                    [(self.package, self.data)],
                    request,
                    state_directory=self.state_directory,
                )
            except FileExistsError:
                return ["already_reserved"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count(["home-signal:restored"]), 1)
        self.assertEqual(results.count(["already_reserved"]), 7)
        self.assertEqual(posts, [self.data])

    def test_marker_is_complete_and_both_fsyncs_precede_post(self):
        synced = []
        real_fsync = os.fsync

        def sync(fd):
            synced.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return real_fsync(fd)

        def request(target, method, path, data):
            if path == "/ota/status":
                return {"version": self.target["firmware_version"]}
            if path == "/wasm/list":
                return {"max": 4, "loaded": 0, "modules": self.empty_slots()}
            self.assertEqual(synced, ["file", "directory"])
            marker = json.loads(next(self.state_directory.iterdir()).read_text())
            self.assertEqual(marker["package_sha256"], hashlib.sha256(data).hexdigest())
            return {"name": "home-signal", "started": True}

        with patch.object(modules.os, "fsync", side_effect=sync):
            self.assertEqual(
                modules.reconcile(
                    self.target,
                    [(self.package, self.data)],
                    request,
                    state_directory=self.state_directory,
                ),
                ["home-signal:restored"],
            )

    def test_write_or_either_fsync_failure_prevents_post_and_keeps_marker(self):
        for failure in ("write", "file_fsync", "directory_fsync"):
            with self.subTest(failure=failure):
                target = {**self.target, "restore_generation": failure}
                if failure == "write":
                    mocked = patch.object(
                        modules.os, "write", side_effect=OSError("disk write")
                    )
                else:
                    mocked = patch.object(
                        modules.os,
                        "fsync",
                        side_effect=[OSError("sync")]
                        if failure == "file_fsync"
                        else [None, OSError("sync")],
                    )
                with mocked, self.assertRaises(OSError):
                    self.run_case(target=target)
                self.assertFalse(any(method == "POST" for method, _ in self.calls))
                with self.assertRaises(FileExistsError):
                    self.run_case(target=target)
                self.assertFalse(any(method == "POST" for method, _ in self.calls))

    def test_missing_invalid_generation_identity_or_directory_prevents_post(self):
        for field, value in (
            ("restore_generation", None),
            ("restore_generation", ""),
            ("restore_generation", "../escape"),
            ("restore_generation", "A"),
            ("restore_generation", "x" * 65),
            ("restore_generation", 1),
            ("node_id", True),
            ("node_id", 0),
            ("node_id", "2"),
            ("node_id", 256),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.run_case(target={**self.target, field: value})
                self.assertFalse(any(method == "POST" for method, _ in self.calls))
                self.assertEqual(list(self.state_directory.iterdir()), [])
        for path in (None, Path("relative"), self.state_directory / "absent"):
            with self.subTest(path=path):
                with self.assertRaises((ValueError, OSError)):
                    self.run_case(state_directory=path)
                self.assertFalse(any(method == "POST" for method, _ in self.calls))

    def test_symlink_or_existing_empty_marker_blocks_without_overwriting(self):
        victim = self.state_directory / "unrelated"
        victim.write_text("preserve")
        marker = self.state_directory / "node-2--reviewed-1.attempt.json"
        marker.symlink_to(victim)
        with self.assertRaises(FileExistsError):
            self.run_case()
        self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(victim.read_text(), "preserve")
        marker.unlink()  # Fixture setup only; production never removes a marker.
        marker.touch()
        with self.assertRaises(FileExistsError):
            self.run_case()
        self.assertEqual(marker.read_bytes(), b"")
        directory_link = self.state_directory / "link"
        directory_link.symlink_to(self.state_directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.run_case(
                target={**self.target, "restore_generation": "another"},
                state_directory=directory_link,
            )
        self.assertFalse(any(method == "POST" for method, _ in self.calls))

    def test_restore_requires_one_package_and_four_truly_empty_unique_slots(self):
        cases = [
            [],
            self.empty_slots()[:3],
            self.empty_slots() + [self.empty_slots()[0]],
        ]
        for key, value in (
            ("id", 0),
            ("id", True),
            ("state", "stopped"),
            ("name", "other"),
            ("binary_size", 1),
            ("error_count", False),
            ("budget_faults", 1),
            ("max_frame_us", 1),
        ):
            slots = self.empty_slots()
            slots[3][key] = value
            cases.append(slots)
        for slots in cases:
            with self.subTest(slots=slots), self.assertRaises(ValueError):
                self.run_case(slots=slots)
            self.assertFalse(any(method == "POST" for method, _ in self.calls))
        for field, value in (
            ("max", 3),
            ("max", True),
            ("loaded", 1),
            ("loaded", False),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.run_case(
                    listing_override={
                        "max": 4,
                        "loaded": 0,
                        "modules": self.empty_slots(),
                        field: value,
                    }
                )
            self.assertFalse(any(method == "POST" for method, _ in self.calls))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.run_case(
                packages=[
                    (self.package, self.data),
                    ({**self.package, "name": "other"}, self.data),
                ]
            )
        self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(list(self.state_directory.iterdir()), [])

    def test_invalid_package_hash_never_reserves_or_uploads(self):
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.run_case(packages=[({**self.package, "sha256": "0" * 64}, self.data)])
        self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(list(self.state_directory.iterdir()), [])

    def test_cli_uses_persistent_store_and_missing_option_cannot_upload(self):
        directory = self.state_directory / "modules"
        directory.mkdir()
        (directory / "manifest.json").write_text(
            json.dumps({"packages": [self.package]})
        )
        (directory / "targets.json").write_text(json.dumps([self.target]))
        posts = []

        def request(target, method, path, data):
            if path == "/ota/status":
                return {"version": self.target["firmware_version"]}
            if path == "/wasm/list":
                return {"max": 4, "loaded": 0, "modules": self.empty_slots()}
            posts.append(data)
            return {"name": "home-signal", "started": True}

        for options, expected_exit, expected_posts in (
            ([], 1, 0),
            (["--state-directory", str(self.state_directory)], 0, 1),
            (["--state-directory", str(self.state_directory)], 1, 1),
        ):
            with (
                self.subTest(options=options, expected_exit=expected_exit),
                patch(
                    "sys.argv",
                    [
                        "reconcile",
                        "--directory",
                        str(directory),
                        *runtime_arguments(directory / "manifest.json"),
                        *options,
                    ],
                ),
                patch.object(modules, "package_bytes", return_value=self.data),
                patch.object(modules, "make_request", return_value=request),
                patch("builtins.print"),
                self.assertRaises(SystemExit) as exit_result,
            ):
                modules.main()
            self.assertEqual(exit_result.exception.code, expected_exit)
            self.assertEqual(len(posts), expected_posts)

    def test_8_requires_callback_evidence_without_consuming_attempt(self):
        target = {**self.target, "firmware_version": "0.8.8.8"}
        for slots in (self.empty_slots(), [self.running]):
            with self.subTest(slots=slots), self.assertRaises(ValueError):
                self.run_case(target=target, version="0.8.8.8", slots=slots)
            self.assertFalse(any(method == "POST" for method, _ in self.calls))
            self.assertEqual(list(self.state_directory.iterdir()), [])

    def test_7_requires_complete_consistent_callback_diagnostics(self):
        target = {**self.target, "firmware_version": "0.8.8.7"}
        keys = ("max_frame_us", "max_timer_us", "frame_overruns", "timer_overruns")
        running = {**self.running, **dict.fromkeys(keys, 0), "max_frame_us": 3000}
        empty = self.empty_slots()
        for slot in empty:
            slot.update(dict.fromkeys(keys, 0))
        for mode in ("running", "empty"):
            for key in keys:
                for value in ("missing", None, True, -1, 1 << 32):
                    with self.subTest(mode=mode, key=key, value=value):
                        slots = (
                            [dict(running)]
                            if mode == "running"
                            else [dict(slot) for slot in empty]
                        )
                        if value == "missing":
                            slots[0].pop(key)
                        else:
                            slots[0][key] = value
                        with self.assertRaises(ValueError):
                            self.run_case(target=target, version="0.8.8.7", slots=slots)
                        self.assertFalse(
                            any(method == "POST" for method, _ in self.calls)
                        )
        for change in (
            {"frame_overruns": 1},
            {"timer_overruns": 1},
            {"max_timer_us": 3001},
            {"max_frame_us": 2999},
            {"max_frame_us": 10001, "max_us": 10001},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_case(
                    target=target, version="0.8.8.7", slots=[{**running, **change}]
                )
            self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(list(self.state_directory.iterdir()), [])
        self.assertEqual(
            self.run_case(
                target=target, version="0.8.8.7", slots=[running], state_directory=None
            ),
            ["home-signal:running"],
        )
        self.assertEqual(
            self.run_case(target=target, version="0.8.8.7", slots=empty),
            ["home-signal:restored"],
        )

    def test_running_package_is_not_uploaded_again(self):
        self.assertEqual(
            self.run_case(
                slots=[self.running],
                state_directory=None,
                target={**self.target, "restore_generation": None},
            ),
            ["home-signal:running"],
        )
        self.assertFalse(any(method == "POST" for method, _ in self.calls))
        self.assertEqual(list(self.state_directory.iterdir()), [])

    def test_running_slot_requires_manifest_identity_and_complete_fault_telemetry(self):
        for key, value in (
            ("binary_size", 101),
            ("binary_size", 100.0),
            ("caps", "0x006f"),
            ("caps", None),
            ("budget_us", 20000),
            ("budget_us", None),
            ("budget_us", 10000.0),
            ("error_count", 1),
            ("error_count", None),
            ("budget_faults", 1),
            ("budget_faults", False),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    self.run_case(slots=[{**self.running, key: value}])
                self.assertFalse(any(method != "GET" for method, _ in self.calls))

    def test_maximum_retains_overrun_evidence_when_fault_counter_clears(self):
        for maximum in (10001, 22337, -1, None, True, 3000.0):
            with self.subTest(maximum=maximum):
                with self.assertRaisesRegex(ValueError, "execution budget"):
                    self.run_case(slots=[{**self.running, "max_us": maximum}])
                self.assertFalse(any(method != "GET" for method, _ in self.calls))
        for maximum in (0, 10000):
            with self.subTest(maximum=maximum):
                self.assertEqual(
                    self.run_case(slots=[{**self.running, "max_us": maximum}]),
                    ["home-signal:running"],
                )

    def test_faulted_or_stopped_package_is_not_restarted(self):
        for state in ("error", "stopped"):
            with self.assertRaises(ValueError):
                self.run_case(slots=[{"name": "home-signal", "state": state}])
            self.assertFalse(any(method == "POST" for method, _ in self.calls))

    def test_unrelated_modules_are_never_removed(self):
        with self.assertRaises(ValueError):
            self.run_case(slots=[{"name": "other", "state": "running"}])
        self.assertFalse(any(method != "GET" for method, _ in self.calls))

    def test_upload_that_did_not_start_requires_review(self):
        with self.assertRaises(ValueError):
            self.run_case(started=False)

    def test_http_requests_install_no_proxy_and_no_redirect_handlers(self):
        with patch.object(modules.urllib.request, "build_opener") as build:
            request = modules.make_request()
        self.assertTrue(callable(request))
        handlers = build.call_args.args
        self.assertEqual(len(handlers), 2)
        self.assertIsInstance(handlers[0], urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], modules.NoRedirect)
        for method in ("GET", "POST"):
            for code in (301, 302, 303, 307, 308):
                with self.subTest(method=method, code=code):
                    req = urllib.request.Request("http://node.invalid/", method=method)
                    self.assertIsNone(
                        handlers[1].redirect_request(
                            req, None, code, "redirect", {}, "http://other.invalid/"
                        )
                    )


class BootRestorationTests(unittest.TestCase):
    mac = "02:ac:de:77:00:02"
    nonce = "1" * 32
    epoch_ns = 2_000_000_000 * 1_000_000_000

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.clock = 100.0
        self.calls = []
        self.data = b"synthetic-signed-test-package"
        self.package = {
            **ReconciliationTests.package,
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }
        self.target = {
            "enabled": True,
            "restore_mode": modules.BOOT_MODE,
            "node_id": 2,
            "mac": self.mac,
            "ip": "192.0.2.2",
            "firmware_version": "0.8.8.10",
            "package_sha256": self.package["sha256"],
        }
        self.package["qualified_boot_restore_targets"] = [
            {
                k: self.target[k]
                for k in ("node_id", "mac", "ip", "firmware_version", "restore_mode")
            }
        ]
        self.slots = ReconciliationTests.empty_slots(self)
        for slot in self.slots:
            slot.update(
                max_frame_us=0, max_timer_us=0, frame_overruns=0, timer_overruns=0
            )
        self.runtime_changes = {}
        self.status_changes = {}
        self.listing_changes = {}
        self.reply_changes = {}
        self.before_request = lambda _method, _path: None
        self.upload_error = None
        self.observed_marker_before_post = False

    def sleep(self, seconds):
        self.clock += seconds

    def request(self, target, method, path, data, *, headers=None):
        self.clock += 0.01
        self.before_request(method, path)
        self.calls.append((method, path, data, headers))
        identity = {
            "boot_nonce_schema": modules.BOOT_SCHEMA,
            "boot_nonce": self.nonce,
            "station_mac": self.mac,
        }
        if path == "/ota/status":
            return {"version": "0.8.8.10", **identity, **self.status_changes}
        if path == "/wasm/list":
            return copy.deepcopy(
                {
                    "max": 4,
                    "loaded": 0,
                    "modules": self.slots,
                    "runtime": {
                        **identity,
                        "uptime_ms": 60_000 + int(self.clock * 1000),
                        "internal_free_bytes": 100_000,
                        "internal_min_free_bytes": 80_000,
                        "internal_largest_free_block": 32_000,
                        "worker_stack_bytes": 32768,
                        "worker_stack_min_free_bytes": 31_000,
                        **self.runtime_changes,
                    },
                    **self.listing_changes,
                }
            )
        self.assertEqual(
            (method, path, headers),
            ("POST", "/wasm/upload", {modules.BOOT_HEADER: self.nonce}),
        )
        markers = list(self.root.glob("boot-*.attempt.json"))
        self.observed_marker_before_post = bool(markers)
        self.assertTrue(self.observed_marker_before_post)
        if self.upload_error:
            raise self.upload_error
        return {
            "name": self.package["name"],
            "started": True,
            "boot_nonce_schema": modules.BOOT_SCHEMA,
            "boot_nonce": self.nonce,
            **self.reply_changes,
        }

    def run_case(self, **kwargs):
        return modules.reconcile(
            self.target,
            [(self.package, self.data)],
            self.request,
            state_directory=self.root,
            monotonic=lambda: self.clock,
            sleep=self.sleep,
            wall_time_ns=lambda: self.epoch_ns + int(self.clock * 1e9),
            **kwargs,
        )

    def catalog_case(self, packages):
        return modules.reconcile(
            self.target,
            packages,
            self.request,
            state_directory=self.root,
            monotonic=lambda: self.clock,
            sleep=self.sleep,
            wall_time_ns=lambda: self.epoch_ns + int(self.clock * 1e9),
        )

    def test_catalog_selects_only_exact_target_bytes_in_either_order(self):
        other_data = b"different-signed-catalog-fixture"
        other = {
            **self.package,
            "name": "other-profile",
            "sha256": hashlib.sha256(other_data).hexdigest(),
        }
        for reverse in (False, True):
            self.nonce = ("2" if reverse else "1") * 32
            self.calls = []
            entries = [(self.package, self.data), (other, other_data)]
            if reverse:
                entries.reverse()
            self.assertEqual(self.catalog_case(entries), ["home-signal:restored"])
            self.assertEqual([p[2] for p in self.posts()], [self.data])

    def test_catalog_ambiguity_missing_and_shape_fail_before_any_request(self):
        other_data = b"different-signed-catalog-fixture"
        other = {
            **self.package,
            "name": "other-profile",
            "sha256": hashlib.sha256(other_data).hexdigest(),
        }
        wanted = (self.package, self.data)
        for entries in (
            [],
            (),
            [wanted, wanted],
            [wanted, (other, other_data), wanted],
            [(other, other_data)],
            [wanted, (other | {"name": self.package["name"]}, other_data)],
            [wanted, (other | {"sha256": self.package["sha256"]}, other_data)],
            [wanted, (other | {"sha256": "bad"}, other_data)],
            [wanted, (other | {"name": "BAD"}, other_data)],
            [wanted, {}],
            [(self.package, b"changed target bytes"), (other, other_data)],
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.catalog_case(entries)
            self.assertEqual(self.calls, [])
            self.assertEqual(list(self.root.iterdir()), [])

    def test_catalog_does_not_rearm_same_mac_nonce_for_new_package(self):
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        other_data = b"different-signed-catalog-fixture"
        previous = self.package, self.data
        self.package = {
            **self.package,
            "name": "other-profile",
            "sha256": hashlib.sha256(other_data).hexdigest(),
        }
        self.data = other_data
        self.target["package_sha256"] = self.package["sha256"]
        self.calls = []
        self.assertEqual(
            self.catalog_case([previous, (self.package, self.data)]),
            ["other-profile:boot_attempt_already_reserved"],
        )
        self.assertEqual(self.posts(), [])

    def posts(self):
        return [c for c in self.calls if c[0] == "POST"]

    def test_11_requires_new_exact_qualification_and_explicit_enablement(self):
        self.target["firmware_version"] = "0.8.8.11"
        with self.assertRaisesRegex(ValueError, "Exact boot target qualification"):
            self.run_case()
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])
        self.target["enabled"] = False
        self.assertEqual(self.run_case(), ["disabled"])
        self.assertEqual(self.calls, [])
        self.target["enabled"] = True
        self.package["qualified_boot_restore_targets"][0]["firmware_version"] = (
            "0.8.8.11"
        )
        with self.assertRaisesRegex(ValueError, "Boot firmware changed"):
            self.run_case()
        self.assertEqual(self.posts(), [])
        self.assertEqual(list(self.root.iterdir()), [])
        self.status_changes["version"] = "0.8.8.11"
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(len(self.posts()), 1)
        marker = next(self.root.glob("boot-*.attempt.json"))
        self.assertEqual(json.loads(marker.read_text())["firmware_version"], "0.8.8.11")
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(len(self.posts()), 1)

    def test_11_does_not_rearm_same_mac_nonce_after_version_change(self):
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        before = self.file_snapshot(list(self.root.iterdir()))
        self.target["firmware_version"] = "0.8.8.11"
        self.package["qualified_boot_restore_targets"][0]["firmware_version"] = (
            "0.8.8.11"
        )
        self.status_changes["version"] = "0.8.8.11"
        self.calls.clear()
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.file_snapshot(list(self.root.iterdir())), before)

    def test_12_support_does_not_qualify_old_targets_or_rearm_consumed_boot(self):
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        before = self.file_snapshot(list(self.root.iterdir()))
        self.target["firmware_version"] = "0.8.8.12"
        self.status_changes["version"] = "0.8.8.12"
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, "Exact boot target qualification"):
            self.run_case()
        self.assertEqual(self.calls, [])
        self.package["qualified_boot_restore_targets"][0]["firmware_version"] = (
            "0.8.8.12"
        )
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.file_snapshot(list(self.root.iterdir())), before)
        self.nonce = "f" * 32
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(self.posts()[0][3], {modules.BOOT_HEADER: self.nonce})

    def test_11_still_requires_exact_identity_nonce_and_callback_diagnostics(self):
        self.target["firmware_version"] = "0.8.8.11"
        self.package["qualified_boot_restore_targets"][0]["firmware_version"] = (
            "0.8.8.11"
        )
        self.status_changes["version"] = "0.8.8.11"
        for field, value in (
            ("node_id", 3),
            ("ip", "192.0.2.3"),
            ("mac", "02:ac:de:77:00:01"),
        ):
            original = self.target[field]
            self.target[field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "Exact boot target"),
            ):
                self.run_case()
            self.target[field] = original
            self.assertEqual(self.calls, [])
        self.runtime_changes["boot_nonce"] = "2" * 32
        with self.assertRaisesRegex(ValueError, "rebooted"):
            self.run_case()
        self.runtime_changes.clear()
        del self.slots[0]["max_frame_us"]
        with self.assertRaises(ValueError):
            self.run_case()
        self.assertEqual(self.posts(), [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unknown_13_cannot_enter_boot_or_legacy_restore(self):
        self.target["firmware_version"] = "0.8.8.13"
        self.package["qualified_boot_restore_targets"][0]["firmware_version"] = (
            "0.8.8.13"
        )
        self.status_changes["version"] = "0.8.8.12"
        for mode in (modules.BOOT_MODE, None):
            self.target["restore_mode"] = mode
            with (
                self.subTest(mode=mode),
                self.assertRaisesRegex(ValueError, "Unsupported firmware"),
            ):
                self.run_case()
            self.assertEqual(self.calls, [])
            self.assertEqual(list(self.root.iterdir()), [])

    def test_opt_in_once_per_mac_nonce_preserves_legacy_marker(self):
        old = self.root / "node-2--old-generation.attempt.json"
        old.write_bytes(b"legacy immutable marker")
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(len(self.posts()), 1)
        marker = next(self.root.glob("boot-*.attempt.json"))
        first = marker.read_bytes()
        contents = json.loads(first)
        self.assertEqual(contents["station_mac"], self.mac)
        self.assertEqual(contents["firmware_version"], "0.8.8.10")
        self.assertEqual(contents["package_sha256"], self.package["sha256"])
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(marker.read_bytes(), first)
        self.assertEqual(old.read_bytes(), b"legacy immutable marker")

    def fs_group_files(self):
        self.run_case()
        files = list(self.root.glob("boot-*"))
        self.assertEqual(len(files), 2)
        for path in files:
            path.chmod(0o660)
        self.calls = []
        return files

    @staticmethod
    def file_snapshot(paths):
        return {
            path.name: (
                path.read_bytes(),
                path.stat().st_uid,
                path.stat().st_gid,
                path.stat().st_mode,
                path.stat().st_nlink,
                path.stat().st_mtime_ns,
            )
            for path in paths
        }

    def test_fs_group_permissions_preserve_history_and_do_not_rearm(self):
        files = self.fs_group_files()
        before = self.file_snapshot(files)
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(self.posts(), [])
        self.nonce = "2" * 32
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(self.file_snapshot(files), before)
        newest = next(p for p in self.root.glob("*.attempt.json") if p not in files)
        self.assertEqual(stat.S_IMODE(newest.stat().st_mode), 0o600)
        self.assertTrue(self.observed_marker_before_post)

    def test_fs_group_permission_scope_rejects_other_modes_before_post(self):
        files = self.fs_group_files()
        self.nonce = "2" * 32
        for path in files:
            for mode in (
                0o604,
                0o640,
                0o620,
                0o664,
                0o666,
                0o670,
                0o1660,
                0o2660,
                0o4660,
            ):
                with self.subTest(path=path.name, mode=oct(mode)):
                    path.chmod(mode)
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            self.run_case()
                    finally:
                        path.chmod(0o660)
                    self.assertEqual(self.posts(), [])
        self.assertEqual(len(list(self.root.glob("*.attempt.json"))), 1)

    def test_fs_group_requires_current_owner_and_primary_group(self):
        files = self.fs_group_files()
        self.nonce = "2" * 32
        real_fstat = os.fstat
        for path in files:
            inode = path.stat().st_ino
            for field in (4, 5):

                def other_owner(fd, inode=inode, field=field):
                    info = real_fstat(fd)
                    if info.st_ino != inode:
                        return info
                    values = list(info)
                    values[field] += 1
                    return os.stat_result(values)

                with (
                    self.subTest(path=path.name, field=field),
                    patch.object(modules.os, "fstat", side_effect=other_owner),
                    self.assertRaisesRegex(ValueError, "Invalid boot"),
                ):
                    self.run_case()
                self.assertEqual(self.posts(), [])

    def test_fs_group_does_not_allow_hardlinks_or_symlinks(self):
        files = self.fs_group_files()
        self.nonce = "2" * 32
        for path in files:
            other = self.root / "other-file"
            os.link(path, other)
            with (
                self.subTest(path=path.name, kind="hardlink"),
                self.assertRaisesRegex(ValueError, "Invalid boot"),
            ):
                self.run_case()
            other.unlink()
            path.rename(other)
            path.symlink_to(other.name)
            try:
                with (
                    self.subTest(path=path.name, kind="symlink"),
                    self.assertRaises(OSError),
                ):
                    self.run_case()
            finally:
                path.unlink()
                other.rename(path)
            self.assertEqual(self.posts(), [])

    def test_fs_group_preserves_concurrency_and_hourly_limit(self):
        files = self.fs_group_files()
        before = self.file_snapshot(files)
        self.nonce = "2" * 32
        now = self.epoch_ns + int(self.clock * 1e9)

        def reserve(_):
            try:
                return modules.reserve_boot_attempt(
                    self.root, self.target, self.package, self.nonce, now
                )
            except BlockingIOError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(reserve, range(16))), 1)
        self.nonce = "3" * 32
        self.assertTrue(reserve(None))
        self.nonce = "4" * 32
        with self.assertRaisesRegex(ValueError, "hourly"):
            reserve(None)
        self.assertEqual(len(list(self.root.glob("*.attempt.json"))), 3)
        self.assertEqual(self.file_snapshot(files), before)

    def test_package_or_generation_changes_cannot_rearm_same_boot(self):
        self.run_case()
        self.data += b"next-reviewed-package"
        self.package["sha256"] = hashlib.sha256(self.data).hexdigest()
        self.target.update(
            package_sha256=self.package["sha256"], restore_generation="another"
        )
        self.assertEqual(self.run_case(), ["home-signal:boot_attempt_already_reserved"])
        self.assertEqual(len(self.posts()), 1)

    def test_lost_or_mismatched_response_consumes_boot_without_retry(self):
        for case in ("lost", "wrong_nonce", "missing_schema", "not_started"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                self.root = Path(folder).resolve()
                self.calls = []
                self.upload_error = (
                    TimeoutError("lost reply") if case == "lost" else None
                )
                self.reply_changes = (
                    {"boot_nonce": "2" * 32}
                    if case == "wrong_nonce"
                    else {"boot_nonce_schema": None}
                    if case == "missing_schema"
                    else {"started": False}
                    if case == "not_started"
                    else {}
                )
                with self.assertRaises((TimeoutError, ValueError)):
                    self.run_case()
                self.assertEqual(len(self.posts()), 1)
                self.assertEqual(
                    self.run_case(), ["home-signal:boot_attempt_already_reserved"]
                )
                self.assertEqual(len(self.posts()), 1)

    def test_next_boot_restores_but_fourth_boot_in_hour_is_refused(self):
        for n in range(1, 4):
            self.nonce = str(n) * 32
            self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.nonce = "4" * 32
        with self.assertRaisesRegex(ValueError, "hourly"):
            self.run_case()
        self.assertEqual(len(self.posts()), 3)
        self.clock += 3601
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(len(list(self.root.glob("*.attempt.json"))), 4)

    def test_qualification_or_target_mismatch_rejected_before_network(self):
        for mutation in (
            {"node_id": True},
            {"mac": "02:AC:DE:77:00:02"},
            {"mac": "03:ac:de:77:00:02"},
            {"ip": "node.invalid"},
            {"ip": "192.0.2.2/path"},
            {"firmware_version": "0.8.8.8"},
            {"package_sha256": "0" * 64},
            {"restore_mode": "unknown"},
            {"restore_mode": None},
            {"enabled": 1},
        ):
            original = self.target
            self.target = {**original, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.run_case()
            self.target = original
            self.assertEqual(self.calls, [])
        for approved in (
            None,
            [],
            [dict(self.package["qualified_boot_restore_targets"][0], node_id=2.0)],
        ):
            self.package["qualified_boot_restore_targets"] = approved
            with self.assertRaises(ValueError):
                self.run_case()
            self.assertEqual(self.calls, [])

    def test_reboot_within_or_between_preflight_samples_never_uploads(self):
        for kind in ("status_list", "second_sample"):
            with self.subTest(kind=kind):
                self.calls = []
                self.nonce = "1" * 32

                def flip(_method, path, kind=kind):
                    if (kind == "status_list" and len(self.calls) == 1) or (
                        kind == "second_sample" and len(self.calls) == 2
                    ):
                        self.nonce = "2" * 32

                self.before_request = flip
                with self.assertRaisesRegex(ValueError, "rebooted"):
                    self.run_case()
                self.assertEqual(self.posts(), [])
                self.assertEqual(list(self.root.iterdir()), [])

    def test_nonce_mac_and_firmware_fields_fail_closed(self):
        for change in (
            {"boot_nonce": None},
            {"boot_nonce": "0" * 32},
            {"boot_nonce": "A" * 32},
            {"boot_nonce_schema": "unknown"},
            {"station_mac": "00:00:00:00:00:00"},
            {"version": "0.8.8.9"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.status_changes = change
                self.run_case()
            self.assertEqual(self.posts(), [])
        self.status_changes = {}
        self.runtime_changes = {"boot_nonce": "2" * 32}
        with self.assertRaisesRegex(ValueError, "rebooted"):
            self.run_case()

    def test_uptime_heap_and_callback_margins_are_required(self):
        for field, bad in (
            ("uptime_ms", 59999),
            ("uptime_ms", True),
            ("internal_free_bytes", 16383),
            ("internal_min_free_bytes", 16383),
            ("internal_largest_free_block", 8191),
            ("worker_stack_min_free_bytes", 4095),
            ("worker_stack_bytes", 65536),
            ("internal_min_free_bytes", 100001),
            ("internal_largest_free_block", 100001),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.runtime_changes = {field: bad}
                self.run_case()
            self.assertEqual(self.posts(), [])
        self.runtime_changes = {}
        self.slots[0].pop("timer_overruns")
        with self.assertRaisesRegex(ValueError, "Callback"):
            self.run_case()

    def test_unstable_deadline_or_stopped_nonempty_never_mutates(self):
        self.sleep = lambda _seconds: None
        with self.assertRaisesRegex(ValueError, "stability"):
            self.run_case()
        self.assertEqual(self.posts(), [])
        self.sleep = lambda _seconds: setattr(self, "clock", self.clock + 30)
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.run_case()
        self.assertEqual(self.posts(), [])

    def test_runtime_sample_windows_accept_asymmetric_http_response_latency(self):
        original_request = self.request
        calls = 0

        def slow_first_response(target, method, path, data, **kwargs):
            nonlocal calls
            result = original_request(target, method, path, data, **kwargs)
            if path == "/wasm/list":
                calls += 1
                if calls == 1:
                    # Uptime was sampled before a slow first response. Comparing
                    # response completion times would invent an uptime jump.
                    self.clock += 1.25
            return result

        self.request = slow_first_response
        self.assertEqual(self.run_case(), ["home-signal:restored"])
        self.assertEqual(len(self.posts()), 1)

    def test_runtime_sample_windows_reject_stale_or_impossible_uptime_progress(self):
        original_request = self.request
        for delta in (0, -1, 1999, 5000):
            first_uptime = None

            def inconsistent_uptime(target, method, path, data, _delta=delta, **kwargs):
                nonlocal first_uptime
                result = original_request(target, method, path, data, **kwargs)
                if path == "/wasm/list":
                    if first_uptime is None:
                        first_uptime = result["runtime"]["uptime_ms"]
                    else:
                        result["runtime"]["uptime_ms"] = first_uptime + _delta
                return result

            self.request = inconsistent_uptime
            with (
                self.subTest(delta=delta),
                self.assertRaisesRegex(ValueError, "uptime"),
            ):
                self.run_case()
            self.assertEqual(self.posts(), [])
            self.assertEqual(list(self.root.iterdir()), [])

    def test_runtime_sample_windows_still_require_progress_during_long_wait(self):
        original_request = self.request
        first_uptime = None

        def nearly_frozen_clock(target, method, path, data, **kwargs):
            nonlocal first_uptime
            result = original_request(target, method, path, data, **kwargs)
            if path == "/wasm/list":
                if first_uptime is None:
                    first_uptime = result["runtime"]["uptime_ms"]
                else:
                    result["runtime"]["uptime_ms"] = first_uptime + 2000
            return result

        self.request = nearly_frozen_clock
        self.sleep = lambda seconds: setattr(self, "clock", self.clock + seconds + 5)
        with self.assertRaisesRegex(ValueError, "uptime"):
            self.run_case()
        self.assertEqual(self.posts(), [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_running_module_is_preserved_not_hash_attested(self):
        self.slots[0].update(ReconciliationTests.running)
        self.slots[0].update(
            max_frame_us=3000, max_timer_us=0, frame_overruns=0, timer_overruns=0
        )
        self.listing_changes = {"loaded": 1}
        self.assertEqual(self.run_case(), ["home-signal:present_no_mutation"])
        self.assertEqual(self.posts(), [])
        self.assertEqual(list(self.root.iterdir()), [])
        self.slots[0]["state"] = "stopped"
        with self.assertRaises(ValueError):
            self.run_case()
        self.assertEqual(self.posts(), [])

    def test_retained_callback_faults_remain_blocked_with_specific_reason(self):
        self.slots[0].update(ReconciliationTests.running)
        self.slots[0].update(
            max_frame_us=3000, max_timer_us=0, frame_overruns=0, timer_overruns=0
        )
        self.listing_changes = {"loaded": 1}
        # Existing state is evidence, even when today's sample looks healthy.
        marker = self.root / "retained-evidence.json"
        marker.write_text('{"failure": "earlier callback overrun"}')
        before = self.file_snapshot([marker])
        original = copy.deepcopy(self.slots)
        for changes, reason in (
            (
                {"frame_overruns": 7, "max_frame_us": 11839, "max_us": 11839},
                "callback_overrun_history",
            ),
            ({"timer_overruns": 1}, "callback_overrun_history"),
            ({"max_frame_us": 10001, "max_us": 10001}, "callback_budget_exceeded"),
            ({"max_timer_us": 10001, "max_us": 10001}, "callback_budget_exceeded"),
            ({"frame_overruns": True}, "callback_diagnostics_invalid"),
            ({"max_us": 2999}, "callback_diagnostics_invalid"),
        ):
            with self.subTest(changes=changes):
                self.slots = copy.deepcopy(original)
                self.slots[0].update(changes)
                observed = copy.deepcopy(self.slots)
                with self.assertRaises(ValueError) as failed:
                    self.run_case()
                self.assertEqual(modules.review_reason(failed.exception), reason)
                self.assertEqual(self.posts(), [])
                self.assertEqual(self.slots, observed)
                self.assertEqual(self.file_snapshot(list(self.root.iterdir())), before)

    def test_wall_clock_rollback_partial_marker_and_symlink_fail_closed(self):
        self.run_case()
        self.nonce = "2" * 32
        self.clock -= 100
        with self.assertRaisesRegex(ValueError, "backwards"):
            self.run_case()
        self.assertEqual(len(self.posts()), 1)
        marker = next(self.root.glob("*.attempt.json"))
        marker.write_bytes(b"{")
        with self.assertRaises(ValueError):
            self.run_case()
        marker.unlink()
        marker.symlink_to(self.root / "absent")
        with self.assertRaises(OSError):
            self.run_case()
        self.assertEqual(len(self.posts()), 1)

    def test_fsync_failure_reserves_unknown_and_blocks_post(self):
        real = os.fsync
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as folder:
                self.root = Path(folder).resolve()
                count = 0

                def fail(fd, fail_at=fail_at):
                    nonlocal count
                    count += 1
                    if count == fail_at:
                        raise OSError("sync failed")
                    real(fd)

                with (
                    patch.object(modules.os, "fsync", side_effect=fail),
                    self.assertRaises(OSError),
                ):
                    self.run_case()
                self.assertEqual(self.posts(), [])
                self.assertEqual(
                    self.run_case(), ["home-signal:boot_attempt_already_reserved"]
                )
                self.assertEqual(self.posts(), [])

    def test_concurrent_same_boot_gets_at_most_one_reservation(self):
        def reserve(_):
            try:
                return modules.reserve_boot_attempt(
                    self.root, self.target, self.package, self.nonce, self.epoch_ns
                )
            except BlockingIOError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve, range(16)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(list(self.root.glob("*.attempt.json"))), 1)

    def test_marker_retention_limit_never_deletes_history(self):
        self.run_case()
        self.nonce = "2" * 32
        with (
            patch.object(modules, "BOOT_MARKER_LIMIT", 1),
            self.assertRaisesRegex(ValueError, "retention"),
        ):
            self.run_case()
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(len(list(self.root.glob("*.attempt.json"))), 1)

    def test_http_boot_header_json_limit_and_no_retry(self):
        with patch.object(modules.urllib.request, "build_opener") as build:
            request = modules.make_request()
        opener = build.return_value
        opener.open.return_value = io.BytesIO(b'{"started":true}')
        self.assertEqual(
            request(
                self.target,
                "POST",
                "/wasm/upload",
                self.data,
                headers={modules.BOOT_HEADER: self.nonce},
            ),
            {"started": True},
        )
        sent = opener.open.call_args.args[0]
        self.assertEqual(sent.data, self.data)
        self.assertEqual(sent.full_url, "http://192.0.2.2:8032/wasm/upload")
        self.assertEqual(
            {key.lower(): value for key, value in sent.header_items()}[
                modules.BOOT_HEADER.lower()
            ],
            self.nonce,
        )
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
        for raw in (
            b'{"key":1,"key":2}',
            b'{"key":1e309}',
            b'{"key":NaN}',
            b'{"key":1.0}',
            b"[]",
            b"{" + b" " * 65536,
        ):
            opener.open.reset_mock()
            opener.open.return_value = io.BytesIO(raw)
            with self.subTest(raw_prefix=raw[:24]), self.assertRaises(ValueError):
                request(self.target, "GET", "/wasm/list", None)
            self.assertEqual(opener.open.call_count, 1)
        opener.open.reset_mock()
        opener.open.side_effect = TimeoutError("lost response")
        with self.assertRaises(TimeoutError):
            request(
                self.target,
                "POST",
                "/wasm/upload",
                self.data,
                headers={modules.BOOT_HEADER: self.nonce},
            )
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_http_boot_scope_and_header_reject_before_open(self):
        with patch.object(modules.urllib.request, "build_opener") as build:
            request = modules.make_request()
        for method, path, data, headers in (
            ("POST", "/wasm/upload", self.data, None),
            ("POST", "/wasm/upload", self.data, {modules.BOOT_HEADER: "0" * 32}),
            ("POST", "/system/restart", None, {modules.BOOT_HEADER: self.nonce}),
            ("GET", "/wasm/list", self.data, None),
            ("GET", "/ota/status", None, {modules.BOOT_HEADER: self.nonce}),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                request(self.target, method, path, data, headers=headers)
        build.return_value.open.assert_not_called()

    def test_absolute_alarm_expires_and_restores_without_replacing_other_timer(self):
        original = signal.getsignal(signal.SIGALRM)
        with self.assertRaisesRegex(TimeoutError, "absolute deadline"):
            with modules.boot_http_deadline():
                seconds, interval = signal.getitimer(signal.ITIMER_REAL)
                self.assertTrue(0 < seconds <= 10)
                self.assertEqual(interval, 0)
                signal.raise_signal(signal.SIGALRM)
        self.assertEqual(signal.getsignal(signal.SIGALRM), original)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        with (
            patch.object(modules.signal, "getitimer", return_value=(3.0, 0.0)),
            patch.object(modules.signal, "signal") as setter,
            self.assertRaisesRegex(ValueError, "unused process"),
        ):
            with modules.boot_http_deadline():
                self.fail("An existing deadline must not be replaced")
        setter.assert_not_called()

    def test_legacy_transport_retains_timeout_and_json_behavior(self):
        with patch.object(modules.urllib.request, "build_opener") as build:
            request = modules.make_request()
        build.return_value.open.return_value = io.BytesIO(b'{"value":1.5}')
        self.assertEqual(
            request({"ip": "192.0.2.8"}, "GET", "/ota/status", None),
            {"value": 1.5},
        )
        self.assertEqual(build.return_value.open.call_args.kwargs, {"timeout": 15})
        sent = build.return_value.open.call_args.args[0]
        self.assertNotIn(
            modules.BOOT_HEADER.lower(), {key.lower() for key, _ in sent.header_items()}
        )


if __name__ == "__main__":
    unittest.main()
