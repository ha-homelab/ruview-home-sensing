"""Real loopback requests; no installation or external service is contacted."""

import importlib.util
import os
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.transport_security import (
    configure_mqtt_tls,
    http_opener,
    open_source,
    websocket_options,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_server_modules", ROOT / "scripts/verify-server-modules.py"
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class TransportTests(unittest.TestCase):
    def test_verifier_never_forwards_bearer_to_redirect_target(self):
        received, redirected = [], []

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                redirected.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Target) as target:
            target_thread = threading.Thread(target=target.serve_forever)
            target_thread.start()

            class Origin(BaseHTTPRequestHandler):
                def do_GET(self):
                    received.append(self.headers.get("Authorization"))
                    self.send_response(int(self.path[1:]))
                    self.send_header(
                        "Location", f"http://127.0.0.1:{target.server_port}/target"
                    )
                    self.end_headers()

                def log_message(self, *args):
                    pass

            try:
                with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
                    origin_thread = threading.Thread(target=origin.serve_forever)
                    origin_thread.start()
                    try:
                        for status in (301, 302, 303, 307, 308):
                            with self.subTest(status=status):
                                with self.assertRaises(urllib.error.HTTPError) as error:
                                    VERIFY.read_document(
                                        http_opener(),
                                        f"http://127.0.0.1:{origin.server_port}",
                                        f"/{status}",
                                        "synthetic-test-token",
                                    )
                                self.assertEqual(error.exception.code, status)
                                error.exception.close()
                    finally:
                        origin.shutdown()
                        origin_thread.join()
            finally:
                target.shutdown()
                target_thread.join()
        self.assertEqual(received, ["Bearer synthetic-test-token"] * 5)
        self.assertEqual(redirected, [])

    def test_direct_response_preserves_bounded_document_behavior(self):
        response = Mock()
        response.read.return_value = b'{"synthetic":true}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        self.assertEqual(
            VERIFY.read_document(opener, "https://example.test", "/health"),
            {"synthetic": True},
        )
        response.read.assert_called_once_with(
            VERIFY.module_observations.MAX_RESPONSE_BYTES + 1
        )
        request = opener.open.call_args.args[0]
        self.assertFalse(request.has_header("Authorization"))
        response.read.return_value = b"x" * (
            VERIFY.module_observations.MAX_RESPONSE_BYTES + 1
        )
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.read_document(opener, "https://example.test", "/health")

    def test_strict_context_is_used_for_mqtt_and_wss(self):
        with patch.dict(
            os.environ, {"RUVIEW_STRICT_TLS": "true", "MQTT_TLS": "true"}, clear=True
        ):
            client = Mock()
            configure_mqtt_tls(client)
            context = client.tls_set_context.call_args.args[0]
            self.assertGreaterEqual(context.security_level, 3)
            self.assertTrue(context.check_hostname)
            self.assertGreaterEqual(
                websocket_options("wss://example.test")["ssl"].security_level, 3
            )
            with self.assertRaises(ValueError):
                websocket_options("ws://example.test")
        with patch.dict(os.environ, {"RUVIEW_STRICT_TLS": "true"}, clear=True):
            with self.assertRaises(ValueError):
                configure_mqtt_tls(Mock())

    def test_public_download_rejects_plaintext_before_any_request(self):
        with patch("scripts.transport_security.http_opener") as build:
            for url in ("http://example.test/file", "https://user:pass@example.test"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    open_source(url, timeout=1)
            build.assert_not_called()

    def test_numpy_optional_install_matches_the_tested_pin(self):
        import tomllib

        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        extras = project["project"]["optional-dependencies"]["inference"]
        pins = (ROOT / "inference/requirements.txt").read_text().splitlines()
        self.assertTrue(all(requirement in pins for requirement in extras))

    def test_strict_policy_flag_rejects_typo(self):
        with patch.dict(os.environ, {"RUVIEW_STRICT_TLS": "tru"}, clear=True):
            with self.assertRaises(ValueError):
                http_opener()
