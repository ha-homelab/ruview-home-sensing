"""Approved endpoint profiles and offline observer transports."""

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from collector_fixture import COLLECTOR, VALUE, profile_arguments
from module_package_fixture import package_arguments
from qualification_fixture import RECEIVER, context_arguments
from test_observer_coverage import observer
from test_runtime_observation import OBSERVER, fixture

from scripts.collector_profile import load_profile, validate_profile


class CollectorProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.flags = profile_arguments(self.root)
        self.path = Path(self.flags[1])
        self.pin = self.flags[3]

    def test_exact_profile_and_https_pair_are_supported(self):
        self.assertEqual(load_profile(self.path, self.pin), COLLECTOR)
        value = VALUE | {
            "http_origin": "https://collector.example.invalid:443",
            "websocket_url": "wss://collector.example.invalid:8443/ws/sensing",
        }
        self.assertEqual(validate_profile(value).websocket_url, value["websocket_url"])

    def test_invalid_origin_paths_authority_and_schema_are_rejected(self):
        variants = [
            {"schema": "other"},
            {"extra": "ignored"},
            {"http_origin": "http://user:secret@10.77.1.9:3000"},
            {"http_origin": "http://10.77.1.9:3000/"},
            {"http_origin": "http://10.77.1.9:3000/api"},
            {"http_origin": "http://10.77.1.9:3000?"},
            {"http_origin": "http://10.77.1.9:3000#"},
            {"http_origin": "http://10.77.1.9:0"},
            {"http_origin": "http://10.77.1.9:65536"},
            {"http_origin": "http://10.77.1.9"},
            {"http_origin": "http://10.77.1.9:3000\n"},
            {"websocket_url": "ws://different.example:3001/ws/sensing"},
            {"websocket_url": "wss://10.77.1.9:3001/ws/sensing"},
            {"websocket_url": "ws://10.77.1.9:3001/another"},
            {"websocket_url": "ws://10.77.1.9:3001/ws/sensing?token=x"},
        ]
        for delta in variants:
            with self.subTest(fields=list(delta)), self.assertRaises(ValueError):
                validate_profile(VALUE | delta)

    def test_unchanged_approval_cannot_authorize_replaced_profile(self):
        self.path.write_text(json.dumps(VALUE | {"http_origin": "http://other:3000"}))
        with self.assertRaises(ValueError):
            load_profile(self.path, self.pin)
        self.path.write_bytes(b" " * 4097)
        with self.assertRaises(ValueError):
            load_profile(self.path, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_collector_missing_or_bad_pin_prevents_token_network_and_output(self):
        output = self.root / "report.json"
        for flags in ([], self.flags[:2], [*self.flags[:3], "0" * 64]):
            with (
                self.subTest(option_count=len(flags)),
                patch("sys.argv", ["observer", "--output", str(output), *flags]),
                patch("sys.stderr"),
                patch.object(observer.urllib.request, "build_opener") as network,
                patch.object(observer.os.environ, "get") as environment,
                self.assertRaises((SystemExit, ValueError)),
            ):
                observer.main()
            self.assertFalse(
                any(
                    c.args and c.args[0] == "RUVIEW_API_TOKEN"
                    for c in environment.call_args_list
                )
            )
            network.assert_not_called()
            self.assertFalse(output.exists())

    def test_runtime_missing_or_bad_profile_prevents_package_token_and_output(self):
        context = context_arguments(self.root)
        output = self.root / "runtime-report.json"
        for flags in ([], self.flags[:2], [*self.flags[:3], "0" * 64]):
            with (
                self.subTest(option_count=len(flags)),
                patch(
                    "sys.argv",
                    [
                        "observer",
                        "--node",
                        "2",
                        "--expected-version",
                        "0.8.8.5",
                        "--package-profile",
                        "home-signal",
                        *package_arguments(self.root),
                        "--mode",
                        "baseline",
                        "--expect-partition",
                        "ota_0",
                        "--output",
                        str(output),
                        *context,
                        *flags,
                    ],
                ),
                patch("sys.stderr"),
                patch.object(OBSERVER, "get_package") as package,
                patch.object(OBSERVER.urllib.request, "build_opener") as network,
                patch.object(OBSERVER.os.environ, "get") as environment,
                self.assertRaises((SystemExit, ValueError)),
            ):
                OBSERVER.main()
            package.assert_not_called()
            network.assert_not_called()
            self.assertFalse(
                any(
                    c.args and c.args[0] == "RUVIEW_API_TOKEN"
                    for c in environment.call_args_list
                )
            )
            self.assertFalse(output.exists())

    def test_runtime_cannot_certify_after_profile_changes(self):
        context = context_arguments(self.root)
        output = self.root / "runtime-report.json"
        report = fixture("baseline")

        async def observe(*_args, **_kwargs):
            self.path.write_bytes(b"{}")
            return report

        with (
            patch(
                "sys.argv",
                [
                    "observer",
                    "--node",
                    "2",
                    "--expected-version",
                    "0.8.8.5",
                    "--package-profile",
                    "home-signal",
                    *package_arguments(self.root),
                    "--mode",
                    "baseline",
                    "--expect-partition",
                    "ota_0",
                    "--output",
                    str(output),
                    *context,
                    *self.flags,
                ],
            ),
            patch.dict(OBSERVER.os.environ, {"RUVIEW_API_TOKEN": "test-only"}),
            patch.object(OBSERVER, "observe", new=observe),
            patch("builtins.print"),
        ):
            self.assertEqual(OBSERVER.main(), 1)
        saved = json.loads(output.read_text())
        self.assertEqual(saved["samples"], report["samples"])
        self.assertEqual(
            saved["assessment"]["failures"], ["installation_context_changed"]
        )
        self.assertEqual(
            saved["installation_approval"]["collector_profile_sha256"], self.pin
        )

    def run_collector(self, *, mutate=False):
        output = self.root / "report.json"
        now = 0.0
        sequence = 0
        requests = []

        def sleep(seconds):
            nonlocal now
            now += seconds

        class Reply:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(self.body)

        def open_request(request, *, timeout):
            nonlocal now, sequence
            requests.append(
                (request.full_url, timeout, request.get_header("Authorization"))
            )
            now += 0.1
            if request.full_url.endswith("/api/v1/nodes"):
                sequence += 1
                if mutate:
                    self.path.write_bytes(b"{}")
                return Reply(
                    {
                        "nodes": [
                            {
                                "node_id": n,
                                "csi_status": "active",
                                "csi_last_seen_ms": 0,
                                "csi_sequence": sequence,
                            }
                            for n in (1, 3)
                        ]
                    }
                )
            return Reply(
                {
                    "source": "esp32",
                    "nodes": [{"node_id": n, "subcarrier_count": 64} for n in (1, 3)],
                }
            )

        opener = Mock()
        opener.open.side_effect = open_request
        with (
            patch(
                "sys.argv",
                ["observer", "--duration", "5", "--output", str(output), *self.flags],
            ),
            patch.dict(observer.os.environ, {"RUVIEW_API_TOKEN": "test-only"}),
            patch.object(observer.urllib.request, "build_opener", return_value=opener),
            patch.object(observer.time, "monotonic", side_effect=lambda: now),
            patch.object(observer.time, "sleep", side_effect=sleep),
            patch("builtins.print"),
            self.assertRaises(SystemExit) as exited,
        ):
            observer.main()
        return exited.exception.code, json.loads(output.read_text()), requests

    def test_real_collector_loop_uses_approved_paths_token_and_five_second_timeout(
        self,
    ):
        code, report, requests = self.run_collector()
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["collector_profile_sha256"], self.pin)
        self.assertEqual(
            {r[0] for r in requests},
            {
                COLLECTOR.http_origin + "/api/v1/nodes",
                COLLECTOR.http_origin + "/api/v1/sensing/latest",
            },
        )
        self.assertTrue(all(r[1:] == (5, "Bearer test-only") for r in requests))

    def test_changed_profile_prevents_next_request_and_retains_failure_evidence(self):
        code, report, requests = self.run_collector(mutate=True)
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(len(requests), 1)
        self.assertIn(
            "collector_profile_changed", [e["error"] for e in report["errors"]]
        )

    def test_actual_async_observer_passes_exact_ws_url_and_original_timeouts(self):
        received = []

        class Connection:
            def __init__(self, url, **kwargs):
                received.append((url, kwargs))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        with patch("websockets.asyncio.client.connect", Connection):
            asyncio.run(
                OBSERVER.observe(
                    0,
                    "baseline",
                    0,
                    "ota_0",
                    "test-only",
                    receiver=RECEIVER,
                    collector=COLLECTOR,
                    revalidate=lambda: None,
                )
            )
        self.assertEqual(
            received,
            [
                (
                    COLLECTOR.websocket_url,
                    {
                        "additional_headers": {"Authorization": "Bearer test-only"},
                        "proxy": None,
                        "open_timeout": 5,
                        "close_timeout": 3,
                        "max_size": 1 << 20,
                    },
                )
            ],
        )
