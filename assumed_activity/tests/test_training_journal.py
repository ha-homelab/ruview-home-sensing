import copy
import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from assumed_activity import training_journal as journal

NOW = 2_000_000_000_000_000_000


def sensing():
    return {
        "source": "esp32",
        "type": "sensing_update",
        "timestamp": NOW / 1e9,
        "nodes": [{"node_id": 7, "rssi_dbm": -50, "subcarrier_count": 64}],
        "node_features": [
            {
                "node_id": 7,
                "stale": False,
                "last_seen_ms": 20,
                "frame_rate_hz": 30,
                "features": {
                    "motion_band_power": 1.2,
                    "variance": 2.4,
                    "mean_rssi": -50.0,
                    "spectral_power": 3.1,
                    "breathing_band_power": 0.3,
                    "change_points": 2,
                    "dominant_freq_hz": 1.8,
                },
            }
        ],
    }


def worker():
    return {
        "schema": "ruview.server-modules.v1",
        "recognition_validated": False,
        "worker_run_id": "test-worker",
        "configuration_sha256": "a" * 64,
        "clock_id": "test-clock",
        "generated_at_ns": str(NOW),
        "nodes": [
            {
                "node_id": 7,
                "fresh": True,
                "age_ms": 20,
                "last_received_at_ns": str(NOW - 20_000_000),
                "last_received_monotonic_ns": "1200000000",
                "sequence": 5,
                "node_epoch": 1,
                "sequence_discontinuities": 0,
                "epoch_reason": "first_frame",
                "grid": {
                    "antennas": 1,
                    "subcarriers": 64,
                    "ppdu_type": 0,
                    "flags": 16,
                    "frequency_mhz": 2437,
                },
            }
        ],
    }


class ProjectionTests(unittest.TestCase):
    def test_wrong_source_schema_cannot_supply_training_features(self):
        for field, value in (("source", "simulated"), ("type", "unrelated")):
            source = sensing()
            source[field] = value
            result = journal.project(source, worker(), [7], NOW, 2500)[0]
            self.assertFalse(result["available"])
            self.assertEqual(result["reason"], "invalid_source_schema")

    def test_missing_worker_profile_is_unknown_not_qualification(self):
        result = journal.project(sensing(), {}, [7], NOW, 2500)[0]
        self.assertTrue(result["available"])
        self.assertIsNone(result["native_profile_compatible"])
        self.assertFalse(result["worker"]["schema_valid"])

    def test_full_features_come_from_node_features_not_diagnostic_nodes(self):
        result = journal.project(sensing(), worker(), [7], NOW, 2500)[0]
        self.assertTrue(result["available"])
        self.assertEqual(result["features"]["motion_band_power"], 1.2)
        self.assertEqual(result["features"]["breathing_band_power"], 0.3)
        self.assertEqual(result["collector_diagnostics"]["rssi_dbm"], -50)
        self.assertTrue(result["native_profile_compatible"])

    def test_missing_features_are_not_invented(self):
        source = sensing()
        source.pop("node_features")
        result = journal.project(source, worker(), [7], NOW, 2500)[0]
        self.assertFalse(result["available"])
        self.assertEqual(result["features"], {})
        self.assertEqual(result["reason"], "source_node_missing")

    def test_unavailable_stale_and_future_are_unknown(self):
        for change in ("stale", "age", "future", "missing_time"):
            with self.subTest(change=change):
                source = sensing()
                if change == "stale":
                    source["node_features"][0]["stale"] = True
                elif change == "age":
                    source["node_features"][0]["last_seen_ms"] = 3000
                elif change == "future":
                    source["timestamp"] += 10
                else:
                    source.pop("timestamp")
                self.assertFalse(
                    journal.project(source, worker(), [7], NOW, 2500)[0]["available"]
                )

    def test_nonfinite_and_nonnumeric_features_are_omitted(self):
        source = sensing()
        source["node_features"][0]["features"].update(
            variance=float("nan"), secret="unrelated-response-data", boolean=True
        )
        result = journal.project(source, worker(), [7], NOW, 2500)[0]
        self.assertFalse(result["available"])
        self.assertNotIn("variance", result["features"])
        self.assertNotIn("secret", result["features"])
        self.assertNotIn("boolean", result["features"])
        self.assertNotIn("unrelated-response-data", json.dumps(result))

    def test_stbc_profile_is_retained_but_not_native_eligible(self):
        source = worker()
        source["nodes"][0]["grid"]["flags"] = 4
        result = journal.project(sensing(), source, [7], NOW, 2500)[0]
        self.assertTrue(result["available"])
        self.assertFalse(result["native_profile_compatible"])
        self.assertEqual(result["worker"]["grid"]["flags"], 4)

    def test_duplicate_node_ids_do_not_pick_a_favorable_value(self):
        source = sensing()
        source["node_features"].append(copy.deepcopy(source["node_features"][0]))
        self.assertFalse(
            journal.project(source, worker(), [7], NOW, 2500)[0]["available"]
        )

    def test_no_proof_is_reported_as_none(self):
        result = journal.project(sensing(), worker(), [7], NOW, 2500)[0]
        self.assertIsNone(result["receiver_proof"])


class JournalTests(unittest.TestCase):
    def test_boot_identity_is_bounded_canonical_and_optional(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "boot_id"
            expected = "73d1bc57-d6da-4b4c-9c32-aeab881e8915"
            path.write_text(expected + "\n")
            self.assertEqual(journal.host_boot_id(path), expected)
            for invalid in (
                "x" * 129,
                expected.upper(),
                "00000000-0000-0000-0000-000000000000",
                "garbage",
            ):
                path.write_text(invalid)
                self.assertIsNone(journal.host_boot_id(path))
            path.unlink()
            self.assertIsNone(journal.host_boot_id(path))

    def test_rotation_hashes_and_fixed_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "new-run"
            target = journal.Journal(root, {"schema": "test"}, 1024 * 1024, 4096)
            rows = 0
            while target.append({"index": rows, "data": "a" * 1000}):
                rows += 1
            terminal = target.finish("byte_limit")
            self.assertEqual(terminal["rows"], rows)
            self.assertGreater(len(terminal["parts"]), 1)
            for part in terminal["parts"]:
                raw = (root / part["name"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), part["sha256"])
                self.assertEqual(len(raw), part["bytes"])
            self.assertLess(sum(p.stat().st_size for p in root.iterdir()), 1024 * 1024)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)

    def test_existing_directory_and_symlink_are_never_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "existing").mkdir()
            (root / "alias").symlink_to(root / "existing")
            for name in ("existing", "alias"):
                with self.assertRaises(FileExistsError):
                    journal.Journal(root / name, {}, 1024 * 1024, 4096)

    def test_oversized_row_and_excessive_part_count_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                journal.Journal(Path(temporary) / "bad", {}, 1024 * 1024, 1024)
            target = journal.Journal(Path(temporary) / "run", {}, 1024 * 1024, 4096)
            with self.assertRaises(ValueError):
                target.append({"oversized": "x" * journal.MAX_ROW})
            target.finish("test")


class TransportTests(unittest.TestCase):
    def test_same_thread_reuses_opener_without_sharing_between_threads(self):
        observations = []
        with (
            mock.patch.object(journal, "_HTTP_LOCAL", threading.local()),
            mock.patch.object(
                journal, "http_opener", side_effect=lambda: object()
            ) as factory,
        ):
            first = journal.thread_http_opener()
            self.assertIs(journal.thread_http_opener(), first)

            def observe():
                value = journal.thread_http_opener()
                observations.append((value, journal.thread_http_opener()))

            workers = [threading.Thread(target=observe) for _ in range(2)]
            for worker_thread in workers:
                worker_thread.start()
            for worker_thread in workers:
                worker_thread.join()
            self.assertEqual(factory.call_count, 3)
            self.assertTrue(all(a is b for a, b in observations))
            self.assertTrue(all(a is not first for a, _ in observations))
            self.assertIsNot(observations[0][0], observations[1][0])

    def test_tls_policy_change_rebuilds_thread_opener(self):
        with (
            mock.patch.object(journal, "_HTTP_LOCAL", threading.local()),
            mock.patch.object(
                journal, "http_opener", side_effect=lambda: object()
            ) as factory,
        ):
            with mock.patch.dict("os.environ", {"RUVIEW_STRICT_TLS": "false"}):
                first = journal.thread_http_opener()
            with mock.patch.dict("os.environ", {"RUVIEW_STRICT_TLS": "true"}):
                second = journal.thread_http_opener()
                self.assertIs(journal.thread_http_opener(), second)
            self.assertIsNot(first, second)
            self.assertEqual(factory.call_count, 2)

    def test_reused_opener_does_not_persist_authorization(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                requests.append((self.path, self.headers.get("Authorization")))
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with (
                mock.patch.object(journal, "_HTTP_LOCAL", threading.local()),
                mock.patch.object(
                    journal, "http_opener", wraps=journal.http_opener
                ) as factory,
            ):
                journal.read_json(base + "/sensing", 2, "first-test-token")
                journal.read_json(base + "/worker", 2)
                journal.read_json(base + "/sensing", 2, "second-test-token")
                self.assertEqual(factory.call_count, 1)
            self.assertEqual(
                requests,
                [
                    ("/sensing", "Bearer first-test-token"),
                    ("/worker", None),
                    ("/sensing", "Bearer second-test-token"),
                ],
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_capture_closes_at_deadline_and_scopes_token(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                requests.append((self.path, self.headers.get("Authorization")))
                value = sensing() if self.path == "/sensing" else worker()
                if self.path == "/sensing":
                    value["timestamp"] = time.time()
                raw = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "capture"
                token = Path(temporary) / "token"
                token.write_text("local-test-token")
                base = f"http://127.0.0.1:{server.server_port}"
                journal.main(
                    [
                        "--sensing-url",
                        base + "/sensing",
                        "--worker-url",
                        base + "/worker",
                        "--node",
                        "7",
                        "--output",
                        str(root),
                        "--deadline",
                        journal.utc(time.time_ns() + 800_000_000),
                        "--interval",
                        "0.25",
                        "--timeout",
                        "0.2",
                        "--min-free-bytes",
                        "0",
                        "--token-file",
                        str(token),
                    ]
                )
                terminal = json.loads((root / "terminal.json").read_text())
                self.assertEqual(terminal["reason"], "deadline")
                self.assertGreaterEqual(terminal["rows"], 2)
                rows = [
                    json.loads(line)
                    for part in terminal["parts"]
                    for line in (root / part["name"]).read_text().splitlines()
                ]
                self.assertTrue(all(row["nodes"][0]["available"] for row in rows))
                self.assertTrue(all(not row["production_replay"] for row in rows))
                self.assertNotIn(
                    "local-test-token", "".join(p.read_text() for p in root.iterdir())
                )
                self.assertTrue(
                    any(
                        path == "/sensing" and token == "Bearer local-test-token"
                        for path, token in requests
                    )
                )
                self.assertTrue(
                    all(token is None for path, token in requests if path == "/worker")
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_credentials_are_only_attached_to_explicit_request(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.getheader.return_value = "identity"
        response.read1.side_effect = [b'{"value":1}', b""]
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(journal, "http_opener", return_value=opener):
            self.assertEqual(
                journal.read_json("https://example.invalid/data", 1, "secret"),
                {"value": 1},
            )
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")
        self.assertEqual(request.get_method(), "GET")

    def test_http_exception_details_are_not_leaked(self):
        exception = urllib.error.HTTPError(
            "https://example.invalid/token-value", 401, "private-detail", {}, None
        )
        with mock.patch.object(journal, "read_json", side_effect=exception):
            value, details = journal.timed_read(
                "https://example.invalid/data", 1, 0, "secret"
            )
        exception.close()
        self.assertEqual(value, {})
        self.assertEqual(details["http_status"], 401)
        self.assertNotIn("private-detail", json.dumps(details))
        self.assertNotIn("token-value", json.dumps(details))

    def test_json_duplicates_nonfinite_and_url_credentials_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b"[]"):
            with self.assertRaises(ValueError):
                journal.decode(raw)
        for url in (
            "https://user:pass@example.invalid/x",
            "https://example.invalid/x?token=secret",
            "file:///tmp/data",
        ):
            with self.assertRaises(ValueError):
                journal.endpoint(url)


if __name__ == "__main__":
    unittest.main()
