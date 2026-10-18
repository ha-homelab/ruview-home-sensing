"""Real pinned input loading around fake qualification transports only."""

import argparse
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from collector_fixture import profile_arguments
from module_package_fixture import package_arguments
from qualification_fixture import RECEIVER, context_arguments
from test_module_upload import PACKAGE, UPLOAD, FakeDevice
from test_runtime_observation import OBSERVER, fixture

from firmware.qualification_receivers import get_receiver, load_receiver


class QualificationContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.flags = context_arguments(self.root)
        self.collector_flags = profile_arguments(self.root)
        self.package_flags = package_arguments(self.root)
        self.args = argparse.Namespace(node=2)
        for key, value in zip(self.flags[::2], self.flags[1::2], strict=True):
            setattr(self.args, key[2:].replace("-", "_"), value)
        self.output = self.root / "report.json"

    def argv(self, module):
        result = [
            "qualification",
            "--node",
            "2",
            "--expected-version",
            "0.8.8.5",
            "--package-profile",
            "home-signal",
            *self.package_flags,
            "--expect-partition",
            "ota_0",
            "--output",
            str(self.output),
        ]
        if module is OBSERVER:
            result += ["--mode", "baseline", *self.collector_flags]
        return result

    def test_no_implicit_station_and_pure_selection_requires_context(self):
        for module in (OBSERVER, UPLOAD):
            self.assertFalse(hasattr(module, "RECEIVER"))
            self.assertFalse(hasattr(module, "NODE2_MAC"))
        with self.assertRaisesRegex(ValueError, "approved_installation_context"):
            get_receiver(2, None)
        self.assertEqual(load_receiver(self.args), RECEIVER)
        for node in (True, False, 1.0, "1", None, 0, 4):
            self.args.node = node
            with self.assertRaisesRegex(ValueError, "unknown_qualification_receiver"):
                load_receiver(self.args)

    def test_each_cli_requires_all_four_flags_before_package_or_transport(self):
        for module in (OBSERVER, UPLOAD):
            for missing in range(0, len(self.flags), 2):
                with (
                    self.subTest(module=module.__name__, missing=self.flags[missing]),
                    patch(
                        "sys.argv",
                        self.argv(module)
                        + self.flags[:missing]
                        + self.flags[missing + 2 :],
                    ),
                    patch("sys.stderr"),
                    patch.object(module, "load_package") as package,
                    patch.object(module.urllib.request, "build_opener") as network,
                    self.assertRaises(SystemExit),
                ):
                    module.main()
                package.assert_not_called()
                network.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_bad_pin_rejected_before_package_token_and_output(self):
        bad = self.flags.copy()
        bad[bad.index("--installation-identity-sha256") + 1] = "0" * 64
        for module in (OBSERVER, UPLOAD):
            with (
                self.subTest(module=module.__name__),
                patch("sys.argv", self.argv(module) + bad),
                patch.object(module, "load_package") as package,
                patch.object(module.urllib.request, "build_opener") as network,
                patch.object(module.os.environ, "get") as environment,
                self.assertRaises(ValueError),
            ):
                module.main()
            package.assert_not_called()
            self.assertFalse(
                any(
                    call.args and call.args[0] == "RUVIEW_API_TOKEN"
                    for call in environment.call_args_list
                )
            )
            network.assert_not_called()
            self.assertFalse(self.output.exists())

    def test_self_consistent_candidate_does_not_approve_changed_receiver(self):
        context = Path(self.args.site_context)
        node_path = context / "nodes.json"
        nodes = json.loads(node_path.read_text())
        nodes["nodes"][1]["mac"] = "02:aa:bb:00:00:ff"
        raw = json.dumps(nodes).encode()
        node_path.write_bytes(raw)
        manifest_path = context / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["nodes.json"] = hashlib.sha256(raw).hexdigest()
        raw = json.dumps(manifest).encode()
        manifest_path.write_bytes(raw)
        self.args.site_context_sha256 = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "approved receiver identity"):
            load_receiver(self.args)

    def test_request_reloads_pin_before_every_get_or_post(self):
        opener = Mock()
        with patch.object(UPLOAD.urllib.request, "build_opener", return_value=opener):
            request = UPLOAD.make_request(
                receiver=RECEIVER, revalidate=lambda: load_receiver(self.args)
            )
        (Path(self.args.site_context) / "nodes.json").write_bytes(b"{}")
        for method, path in (
            ("GET", "/ota/status"),
            ("GET", "/wasm/list"),
            ("POST", "/wasm/upload"),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                request(method, path, b"test" if method == "POST" else None)
        opener.open.assert_not_called()

    def test_revalidation_never_rearms_or_certifies_uncertain_upload(self):
        for fail_at, expected_posts in ((1, 0), (2, 1), (3, 2)):
            device = FakeDevice()
            clock = iter(i * 0.1 for i in range(100))
            checks = 0

            def revalidate(*, expected=fail_at):
                nonlocal checks
                checks += 1
                if checks == expected:
                    raise ValueError("context changed")

            with self.subTest(fail_at=fail_at):
                result = UPLOAD.run_upload(
                    PACKAGE,
                    "ota_1",
                    device.request,
                    lambda _: None,
                    clock.__next__,
                    receiver=RECEIVER,
                    revalidate=revalidate,
                )
                self.assertFalse(result["passed"])
                self.assertEqual(
                    sum(c[0] == "POST" for c in device.calls), expected_posts
                )
                self.assertEqual(result["control_post_attempted"], expected_posts > 0)
                self.assertEqual(result["valid_post_attempted"], expected_posts > 1)

    def test_observation_cannot_certify_after_context_change_and_keeps_report(self):
        report = fixture("baseline")

        async def observe(*_args, **_kwargs):
            (Path(self.args.site_context) / "nodes.json").write_bytes(b"{}")
            return report

        with (
            patch("sys.argv", self.argv(OBSERVER) + self.flags),
            patch.dict(OBSERVER.os.environ, {"RUVIEW_API_TOKEN": "synthetic-token"}),
            patch.object(OBSERVER, "observe", new=observe),
            patch("builtins.print"),
        ):
            self.assertEqual(OBSERVER.main(), 1)
        saved = json.loads(self.output.read_text())
        self.assertEqual(saved["samples"], report["samples"])
        self.assertEqual(
            saved["assessment"]["failures"], ["installation_context_changed"]
        )
        self.assertEqual(
            saved["installation_approval"]["site_context_sha256"],
            self.args.site_context_sha256,
        )

    def test_missing_report_receiver_never_uses_implicit_legacy_binding(self):
        report = fixture()
        del report["receiver"]
        self.assertIn(
            "receiver_binding_mismatch",
            OBSERVER.evaluate(report, receiver=RECEIVER)["failures"],
        )
