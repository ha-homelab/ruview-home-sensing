"""Admission and integrity checks for the nonroot CAD dependency installer."""

import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "provision_native.py"
SPEC = importlib.util.spec_from_file_location("provision_native", MODULE)
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


class Response(io.BytesIO):
    def geturl(self):
        return NATIVE.ARCHIVE_PREFIX + "main/p/package.deb"


class NativeRuntimeTests(unittest.TestCase):
    def test_connection_timeout_retries_before_creating_archive(self):
        package = {
            "url": NATIVE.ARCHIVE_PREFIX + "main/p/package.deb",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        for error in (TimeoutError(), urllib.error.URLError(TimeoutError())):
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as folder:
                destination = Path(folder) / "archive.deb"
                with (
                    patch.object(NATIVE, "open_source", side_effect=[error, Response(b"abc")]) as source,
                    patch.object(NATIVE.time, "sleep") as sleep,
                ):
                    NATIVE.download(package, destination)
                self.assertEqual(destination.read_bytes(), b"abc")
                self.assertEqual(source.call_count, 2)
                sleep.assert_called_once_with(1)

    def test_connection_timeouts_exhaust_three_attempts(self):
        with (
            patch.object(NATIVE, "open_source", side_effect=urllib.error.URLError(TimeoutError())) as source,
            patch.object(NATIVE.time, "sleep") as sleep,
        ):
            with self.assertRaises(urllib.error.URLError):
                NATIVE.open_archive("https://archive.ubuntu.com/ubuntu/pool/example.deb")
        self.assertEqual(source.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_non_timeout_errors_are_not_retried(self):
        for error in (
            urllib.error.HTTPError("https://archive.ubuntu.com/", 404, "missing", {}, None),
            urllib.error.URLError("certificate verify failed"),
            ValueError("invalid redirect"),
        ):
            with (
                self.subTest(error=type(error)),
                patch.object(NATIVE, "open_source", side_effect=error) as source,
                patch.object(NATIVE.time, "sleep") as sleep,
            ):
                with self.assertRaises(type(error)):
                    NATIVE.open_archive("https://archive.ubuntu.com/ubuntu/pool/example.deb")
                source.assert_called_once()
                sleep.assert_not_called()
            if isinstance(error, urllib.error.HTTPError):
                error.close()

    def test_timeout_after_open_does_not_retry_or_extract_partial_archive(self):
        package = {
            "name": "test-package",
            "url": NATIVE.ARCHIVE_PREFIX + "main/p/package.deb",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        response = Response(b"abc")
        response.read = unittest.mock.Mock(side_effect=[b"a", TimeoutError()])
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(NATIVE, "open_source", return_value=response) as source,
            patch.object(NATIVE.time, "sleep") as sleep,
            patch.object(NATIVE.subprocess, "run") as extract,
        ):
            with self.assertRaises(TimeoutError):
                NATIVE.provision(Path(folder) / "output", [package])
            source.assert_called_once()
            sleep.assert_not_called()
            extract.assert_not_called()

    def test_committed_lock_has_unique_bounded_archives(self):
        packages = NATIVE.read_lock(NATIVE.LOCK)
        self.assertEqual(len(packages), 11)
        self.assertLess(sum(p["size"] for p in packages), 3 * 1024 * 1024)
        self.assertLessEqual(
            {"libgl1", "libx11-6", "libxrender1", "fonts-dejavu-core"},
            {p["name"] for p in packages},
        )

    def test_untrusted_archive_origin_is_rejected(self):
        document = json.loads(NATIVE.LOCK.read_text())
        document["packages"][0]["url"] = "https://outside.invalid/package.deb"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lock.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "Invalid locked"):
                NATIVE.read_lock(path)

    def test_corrupt_or_oversized_download_cannot_reach_extraction(self):
        package = {
            "name": "test-package",
            "url": NATIVE.ARCHIVE_PREFIX + "main/p/package.deb",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        for content in (b"bad", b"abcd", b"ab"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as folder:
                with (
                    patch.object(NATIVE, "open_source", return_value=Response(content)),
                    patch.object(NATIVE.subprocess, "run") as extract,
                ):
                    with self.assertRaises(ValueError):
                        NATIVE.provision(Path(folder) / "output", [package])
                    extract.assert_not_called()

    def test_exact_download_is_accepted(self):
        package = {
            "url": NATIVE.ARCHIVE_PREFIX + "main/p/package.deb",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(NATIVE, "open_source", return_value=Response(b"abc")),
        ):
            path = Path(folder) / "archive.deb"
            NATIVE.download(package, path)
            self.assertEqual(path.read_bytes(), b"abc")

    def test_every_archive_is_verified_before_extraction(self):
        package = {
            "name": "first",
            "url": NATIVE.ARCHIVE_PREFIX + "main/p/package.deb",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(
                    NATIVE,
                    "open_source",
                    side_effect=[Response(b"abc"), Response(b"bad")],
                ),
                patch.object(NATIVE.subprocess, "run") as extract,
            ):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    NATIVE.provision(
                        Path(folder) / "output",
                        [package, {**package, "name": "second"}],
                    )
                extract.assert_not_called()

    def test_redirect_outside_archive_is_rejected(self):
        package = {
            "url": NATIVE.ARCHIVE_PREFIX + "main/p/package.deb",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        response = Response(b"abc")
        response.geturl = lambda: "https://outside.invalid/package.deb"
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(NATIVE, "open_source", return_value=response):
                with self.assertRaisesRegex(ValueError, "redirected outside"):
                    NATIVE.download(package, Path(folder) / "archive.deb")


if __name__ == "__main__":
    unittest.main()
