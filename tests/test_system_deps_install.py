"""Exercise bounded, authenticated APT fetching without a network or root access."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import os
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

SPEC = importlib.util.spec_from_file_location(
    "system_deps",
    Path(__file__).resolve().parents[1] / "collector/install-system-deps.py",
)
assert SPEC and SPEC.loader
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
TEMPORARY = (
    "E: Failed to fetch https://snapshot.debian.org/example.deb "
    "TooManyRequests 503  No healthy backends [IP: 192.0.2.1 443]\n"
    "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n"
)

OPENSSL_RESET = (
    "OpenSSL system call error: error:00000000:lib(0)::reason(0)  "
    "- openssl (104: Connection reset by peer) [IP: 192.0.2.1 443]"
)


class TestFetch(unittest.TestCase):
    """Verify retries, fatal diagnostics, installation order and shared budgets."""

    def setUp(self) -> None:
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.invoke = self.enterContext(patch.object(INSTALLER, "run"))
        self.clock = self.enterContext(
            patch.object(INSTALLER.time, "monotonic", return_value=100)
        )
        self.sleep = self.enterContext(patch.object(INSTALLER.time, "sleep"))

    def test_snapshot_index_transport_failures_preserve_bounded_retry(self) -> None:
        uri = INSTALLER.SNAPSHOT + "dists/bookworm/main/binary-arm64/Packages.xz"
        for status in (503, 504):
            with self.subTest(status=status):
                self.invoke.reset_mock()
                self.sleep.reset_mock()
                self.invoke.side_effect = [
                    (100, f"E: Failed to fetch {uri} {status} Temporary failure\n"),
                    (0, ""),
                ]
                INSTALLER.fetch(["update", "--error-on=any"], 1000)
                self.assertEqual(self.invoke.call_count, 2)
                self.sleep.assert_called_once_with(5)
                for invocation in self.invoke.call_args_list:
                    self.assertIn(
                        "Acquire::IndexTargets::deb::Packages::CompressionTypes=xz",
                        invocation.args[0],
                    )
                    self.assertIn(
                        "Acquire::IndexTargets::deb::Packages::KeepCompressedAs=xz",
                        invocation.args[0],
                        "Downloaded indices must remain visible to APT's xz-only lookup",
                    )
        self.invoke.reset_mock()
        self.sleep.reset_mock()
        self.invoke.side_effect = [(100, f"E: Failed to fetch {uri} 404 Not Found\n")]
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.fetch(["update", "--error-on=any"], 1000)
        self.assertEqual(self.invoke.call_count, 1)
        self.sleep.assert_not_called()

    def test_success_keeps_checks_enabled_and_installs_offline(self) -> None:
        self.invoke.return_value = (0, "")
        INSTALLER.install(["dbus", "libdbus-1-3"])
        commands = [item.args[0] for item in self.invoke.call_args_list]
        self.assertEqual(commands[0], [INSTALLER.APT, "--version"])
        self.assertEqual(commands[1][-2:], ["update", "--error-on=any"])
        selection = ["install", "-y", "--no-install-recommends", "dbus", "libdbus-1-3"]
        cache_options = commands[2][
            len(INSTALLER.OPTIONS) + 1 : len(INSTALLER.OPTIONS) + 3
        ]
        self.assertEqual(cache_options[0], "-o")
        self.assertTrue(cache_options[1].startswith("Dir::Cache::archives="))
        self.assertFalse(Path(cache_options[1].split("=", 1)[1]).exists())
        self.assertEqual(
            commands[2],
            [
                INSTALLER.APT,
                *INSTALLER.OPTIONS,
                *cache_options,
                "--download-only",
                *selection,
            ],
        )
        self.assertEqual(
            commands[3],
            [
                INSTALLER.APT,
                *INSTALLER.OPTIONS,
                *cache_options,
                "--no-download",
                *selection,
            ],
        )
        for command in commands[1:]:
            self.assertIn("Acquire::Retries=0", command)
            self.assertNotIn("--allow-unauthenticated", command)
            self.assertNotIn("--fix-missing", command)
        self.sleep.assert_not_called()

    def test_temporary_download_retries_same_operation_then_installs(self) -> None:
        self.invoke.side_effect = [(0, ""), (0, ""), (100, TEMPORARY), (0, ""), (0, "")]
        INSTALLER.install(["dbus"])
        self.assertEqual(self.invoke.call_args_list[2], self.invoke.call_args_list[3])
        self.sleep.assert_called_once_with(5)
        self.assertIn("--no-download", self.invoke.call_args_list[-1].args[0])

    def test_observed_openssl_reset_retries_with_other_http_failures(self) -> None:
        for prefix in ("", "TooManyRequests "):
            with self.subTest(prefix=prefix):
                output = (
                    "E: Failed to fetch https://snapshot.debian.org/example.deb "
                    f"{prefix}{OPENSSL_RESET}\n"
                    "E: Failed to fetch https://snapshot.debian.org/other.deb "
                    "TooManyRequests 503 No healthy backends\n"
                    "E: Some files failed to download\n"
                )
                self.invoke.reset_mock()
                self.sleep.reset_mock()
                self.invoke.side_effect = [(100, output), (0, "")]
                INSTALLER.fetch(["--download-only", "install", "dbus"], 820)
                self.assertEqual(
                    self.invoke.call_args_list[0], self.invoke.call_args_list[1]
                )
                self.sleep.assert_called_once_with(5)

    def test_openssl_reset_retains_retry_limit(self) -> None:
        output = f"E: Failed to fetch https://snapshot.debian.org/example.deb {OPENSSL_RESET}\n"
        self.invoke.return_value = (100, output)
        with self.assertRaises(INSTALLER.TransientFetchExhaustedError):
            INSTALLER.fetch(["--download-only", "install", "dbus"], 820)
        self.assertEqual(self.invoke.call_count, INSTALLER.ATTEMPTS)
        self.assertEqual(self.sleep.call_args_list, [call(5), call(10)])

    def test_openssl_reset_does_not_accept_unknown_or_certificate_errors(self) -> None:
        for reason in (
            OPENSSL_RESET.replace(
                "104: Connection reset by peer", "13: Permission denied"
            ),
            OPENSSL_RESET.replace(
                "104: Connection reset by peer", "104: unknown failure"
            ),
            OPENSSL_RESET.replace(
                "00000000:lib(0)::reason(0)",
                "0A000086:SSL routines::certificate verify failed",
            ),
            OPENSSL_RESET.replace("system call error", "error"),
            OPENSSL_RESET.replace("192.0.2.1", "unknown-host"),
            "unknown " + OPENSSL_RESET,
            OPENSSL_RESET + "; unknown failure",
            OPENSSL_RESET + "\rignored",
            OPENSSL_RESET + "\x00",
        ):
            with self.subTest(reason=reason):
                self.assertFalse(INSTALLER.transient_reason(reason))
        for diagnostic in (
            "E: Hash Sum mismatch",
            "E: NO_PUBKEY key",
            "E: unknown failure",
            "W: unexpected warning",
            "E: Failed to fetch https://example.invalid/ 403 Forbidden",
        ):
            with self.subTest(diagnostic=diagnostic):
                output = (
                    "E: Failed to fetch https://snapshot.debian.org/example.deb "
                    f"{OPENSSL_RESET}\n{diagnostic}\n"
                )
                self.assertFalse(INSTALLER.transient_failure(output))

    def test_download_only_504_summary_retries_but_unknown_errors_still_fail(
        self,
    ) -> None:
        output = (
            "E: Failed to fetch https://snapshot.debian.org/example.deb "
            "504  Gateway Timeout [IP: 192.0.2.1 443]\n"
            "E: Some files failed to download\n"
        )
        self.invoke.side_effect = [(100, output), (0, "")]
        INSTALLER.fetch(["--download-only", "install", "dbus"], 820)
        self.assertEqual(self.invoke.call_count, 2)
        self.sleep.assert_called_once_with(5)
        self.assertFalse(INSTALLER.transient_failure(output + "E: Unknown failure\n"))
        self.assertFalse(
            INSTALLER.transient_failure("E: Some files failed to download\n")
        )

    def test_retry_limit_never_reaches_install(self) -> None:
        self.invoke.side_effect = [(0, ""), *[(100, TEMPORARY)] * 3]
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.install(["dbus"])
        self.assertEqual(self.invoke.call_count, 4)
        self.assertEqual(self.sleep.call_args_list, [call(5), call(10)])

    def test_snapshot_first_byte_timeout_retries_download(self) -> None:
        output = (
            "E: Failed to fetch https://snapshot.debian.org/example.deb "
            "TooManyRequests 503  first byte timeout [IP: 192.0.2.1 443]\n"
            "E: Some files failed to download\n"
        )
        self.invoke.side_effect = [(100, output), (0, "")]
        INSTALLER.fetch(["--download-only", "install", "dbus"], 820)
        self.assertEqual(self.invoke.call_count, 2)
        self.sleep.assert_called_once_with(5)

    def test_snapshot_backend_fetch_failed_retries_mixed_package_response(self) -> None:
        # main run 41904649056 returned these six terminal reasons together.
        reasons = (
            "TooManyRequests 503  Backend fetch failed",
            "504  Gateway Timeout",
            "503  Service Unavailable",
            "TooManyRequests 503  first byte timeout",
            "TooManyRequests 503  Backend fetch failed",
            "TooManyRequests 503  first byte timeout",
        )
        output = (
            "".join(
                f"E: Failed to fetch https://snapshot.debian.org/package{i}.deb "
                f"{reason} [IP: 192.0.2.1 443]\n"
                for i, reason in enumerate(reasons)
            )
            + "E: Some files failed to download\n"
        )
        self.invoke.side_effect = [(100, output), (0, "")]
        INSTALLER.fetch(["--download-only", "install", "dbus"], 820)
        self.assertEqual(self.invoke.call_args_list[0], self.invoke.call_args_list[1])
        self.sleep.assert_called_once_with(5)

    def test_http_status_allows_optional_server_defined_reason(self) -> None:
        for status in (408, 429, 500, 502, 503, 504):
            for prefix in (
                "",
                "TooManyRequests ",
                "Invalid response from proxy: HTTP/1.1 ",
            ):
                for phrase in ("", "  Backend fetch failed", "  New upstream wording"):
                    with self.subTest(status=status, prefix=prefix, phrase=phrase):
                        reason = f"{prefix}{status}{phrase}"
                        self.assertTrue(
                            INSTALLER.transient_failure(
                                "E: Failed to fetch https://example.invalid/503/404.deb "
                                + reason
                            )
                        )
                        self.assertEqual(INSTALLER.http_status(reason), status)

    def test_native_proxy_content_type_parameters_retry_without_weakening_errors(
        self,
    ) -> None:
        # Exact shape emitted by real APT 3.0.3 in run 41909116410, job 126853460339.
        reason = (
            "Invalid response from proxy: HTTP/1.0 503 Service Unavailable  "
            "Server: BaseHTTP/0.6 Python/3.14.8  "
            "Date: Wed, 04 Nov 2026 20:48:11 GMT  Connection: close  "
            "Content-Type: text/html;charset=utf-8  Content-Length: 492     "
            "[IP: 127.0.0.1 33263]"
        )
        output = (
            "E: Failed to fetch https://snapshot.debian.org/example.deb "
            + reason
            + "\n"
            "E: Some files failed to download\n"
        )
        self.invoke.side_effect = [(100, output), (0, "")]
        INSTALLER.fetch(["--download-only", "install", "dbus"], 820)
        self.assertEqual(self.invoke.call_args_list[0], self.invoke.call_args_list[1])
        self.sleep.assert_called_once_with(5)
        for status in (401, 403, 404, 501):
            self.assertFalse(
                INSTALLER.transient_failure(
                    output.replace("503 Service", f"{status} Service")
                )
            )
        for fatal in (
            "E: Unknown failure",
            "E: Hash Sum mismatch",
            "W: No space left on device",
        ):
            self.assertFalse(INSTALLER.transient_failure(output + fatal + "\n"))

    def test_proxy_semicolons_require_a_complete_token_valued_content_type(
        self,
    ) -> None:
        prefix = "Invalid response from proxy: HTTP/1.1 503 Service Unavailable"
        for header in (
            "Content-Type: text/html;charset=utf-8",
            'content-type: application/json; charset="utf-8"; version=1',
        ):
            self.assertTrue(INSTALLER.transient_reason(prefix + "  " + header))
        for suffix in (
            "; unknown failure",
            "  Unknown: value; unknown failure",
            "  Content-Type: text/html; unknown failure",
            "  Content-Type: text/html;charset=",
            "  Content-Type: text/html;charset=utf-8;",
            '  Content-Type: text/html;charset="unterminated',
            "  Content-Type: text/html;charset=utf-8; error=permission denied",
            "  Content-Type: text/html;charset=utf-8  unknown; failure",
            " Content-Type: text/html;charset=utf-8",
            "  Content-Type: text/html;charset=utf-8\runknown failure",
        ):
            with self.subTest(suffix=suffix):
                self.assertFalse(INSTALLER.transient_reason(prefix + suffix))
        self.assertFalse(
            INSTALLER.transient_reason(
                "503 Service Unavailable  Content-Type: text/html;charset=utf-8"
            )
        )

    def test_native_proxy_headers_preserve_signed_timeout_package_identity(
        self,
    ) -> None:
        for arch in ("amd64", "arm64"):
            for status in (503, 504):
                output = (
                    f"Err:1 {INSTALLER.SNAPSHOT.rstrip('/')} bookworm/main {arch} probe {arch} 1.0\n"
                    f"  Invalid response from proxy: HTTP/1.0 {status} Service Unavailable  "
                    "Content-Type: text/html;charset=utf-8  Content-Length: 492     "
                    "[IP: 127.0.0.1 33263]\n"
                )
                self.assertEqual(
                    INSTALLER.timed_out_packages(output, arch),
                    {f"probe_1.0_{arch}.deb"},
                )
                with self.assertRaises(INSTALLER.AptError):
                    INSTALLER.timed_out_packages(
                        output.replace("charset=utf-8", "charset="), arch
                    )

    def test_http_status_rejects_incidental_codes_and_ambiguous_diagnostics(
        self,
    ) -> None:
        reasons = (
            "version 503 Service Unavailable",
            "package 503 Connection timed out",
            "UnknownPrefix 503 Service Unavailable",
            "5030 Service Unavailable",
            "503.1 Service Unavailable",
            "503 Service Unavailable; unknown failure",
            "503 Service Unavailable [unknown suffix]",
            "503 Service Unavailable\x00",
            "503\rService Unavailable",
            "503\nService Unavailable",
            "501 Connection timed out",
            "505 Backend fetch failed",
            "599 Network Connect Timeout Error",
            "404 503 Service Unavailable",
            "503 404 Not Found",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertFalse(INSTALLER.transient_reason(reason))
        for fatal in ("Hash Sum mismatch", "NO_PUBKEY 1234", "No space left on device"):
            self.assertFalse(
                INSTALLER.transient_failure(
                    "E: Failed to fetch https://example.invalid/a.deb 503 Backend fetch failed\n"
                    + fatal
                    + "\n"
                )
            )

    def test_terminal_reason_retains_control_characters_and_network_word_boundaries(
        self,
    ) -> None:
        for reason in (
            "503 Backend fetch failed\runknown failure",
            "503 Backend fetch failed\vunknown failure",
            "503 Backend fetch failed\x1cunknown failure",
            "Could not connect\runknown failure",
            "Could not connectionsomething permanent",
            "Connection resetXYZ",
            "Temporary failure resolvingXYZ",
        ):
            with self.subTest(reason=reason):
                self.assertFalse(INSTALLER.transient_reason(reason))
                self.assertFalse(
                    INSTALLER.transient_failure(
                        "E: Failed to fetch https://example.invalid/a.deb "
                        + reason
                        + "\n"
                    )
                )

    def test_index_retry_uses_terminal_fetch_reason(self) -> None:
        output = (
            "Err:5 https://snapshot.debian.org/ bookworm/main arm64 Packages\n"
            "  TooManyRequests 503  No healthy backends [IP: 192.0.2.1 443]\n"
            "  404  NOT FOUND [IP: 192.0.2.1 443]\n"
            "  504  Gateway Timeout [IP: 192.0.2.1 443]\n"
            "E: Failed to fetch https://snapshot.debian.org/Packages "
            "504  Gateway Timeout [IP: 192.0.2.1 443]\n"
            "E: Some index files failed to download. "
            "They have been ignored, or old ones used instead.\n"
        )
        self.invoke.side_effect = [(100, output), (0, "")]
        INSTALLER.fetch(["update", "--error-on=any"], 820)
        self.assertEqual(self.invoke.call_count, 2)
        self.sleep.assert_called_once_with(5)
        for reason in ("401 Unauthorized", "403 Forbidden", "404 Not Found"):
            with self.subTest(reason=reason):
                self.assertFalse(
                    INSTALLER.transient_failure(
                        output
                        + (
                            "E: Failed to fetch https://snapshot.debian.org/other "
                            + reason
                            + "\n"
                        )
                    )
                )
                self.assertFalse(
                    INSTALLER.transient_failure(
                        output.replace(
                            "Packages 504  Gateway Timeout", "Packages " + reason
                        )
                    )
                )
        self.assertFalse(INSTALLER.transient_failure(output + "Hash Sum mismatch\n"))

    def test_progress_and_url_numbers_are_not_http_statuses(self) -> None:
        self.assertTrue(
            INSTALLER.transient_failure(
                "Get:1 https://snapshot.debian.org/ package [404 kB]\n"
                "E: Failed to fetch https://snapshot.debian.org/401/403/404/example.deb "
                "503 Service Unavailable\n"
            )
        )
        self.assertFalse(
            INSTALLER.transient_failure(
                "E: Failed to fetch https://snapshot.debian.org/503/Service_Unavailable "
                "unknown error\n"
            )
        )
        self.assertFalse(
            INSTALLER.transient_failure("E: Failed to fetch missing-reason\n")
        )

    def test_permanent_and_unknown_errors_do_not_retry_even_with_503(self) -> None:
        diagnostics = [
            "E: Hash Sum mismatch",
            "E: NO_PUBKEY 123456",
            "E: EXPKEYSIG 123456",
            "E: BADSIG 123456",
            "E: Repository is not signed",
            "E: invalid signature",
            "E: signatures couldn't be verified",
            "E: Release file is expired",
            "E: Repository does not have a Release file",
            "E: Unable to locate package x",
            "E: unmet dependencies",
            "E: held broken packages",
            "E: No space left on device",
            "E: unknown failure",
            "W: unexpected warning",
            "E: Failed to fetch https://example.invalid/a.deb 401 Unauthorized",
            "E: Failed to fetch https://example.invalid/a.deb 403 Forbidden",
            "E: Failed to fetch https://example.invalid/a.deb 404 Not Found",
            "E: Failed to fetch https://example.invalid/a.deb unidentified failure",
        ]
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                self.invoke.reset_mock()
                self.invoke.return_value = (100, TEMPORARY + diagnostic + "\n")
                with self.assertRaises(INSTALLER.AptError):
                    INSTALLER.fetch(["update", "--error-on=any"], 820)
                self.assertEqual(self.invoke.call_count, 1)
                self.sleep.assert_not_called()

    def test_incidental_numbers_and_missing_error_diagnostics_do_not_retry(
        self,
    ) -> None:
        for output in (
            "package 503 unavailable",
            "503 Service Unavailable",
            "E: Failed to fetch https://example.invalid/package503.deb unknown",
        ):
            with self.subTest(output=output):
                self.invoke.reset_mock()
                self.invoke.return_value = (100, output)
                with self.assertRaises(INSTALLER.AptError):
                    INSTALLER.fetch(["update"], 820)
                self.assertEqual(self.invoke.call_count, 1)

    def test_supported_transport_errors_are_explicit(self) -> None:
        for reason in (
            "408 Request Timeout",
            "429 Too Many Requests",
            "500 Internal Server Error",
            "502 Bad Gateway",
            "503 Service Unavailable",
            "504 Gateway Timeout",
            "Temporary failure resolving 'example.invalid'",
            "Connection timed out",
            "Could not connect to example.invalid",
            "Connection reset by peer",
            "TLS connection was non-properly terminated",
        ):
            with self.subTest(reason=reason):
                self.assertTrue(
                    INSTALLER.transient_failure(
                        "E: Failed to fetch https://example.invalid/a.deb " + reason
                    )
                )

    def test_non_apt_exit_and_command_timeout_do_not_retry(self) -> None:
        self.invoke.return_value = (137, TEMPORARY)
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.fetch(["update"], 820)
        self.assertEqual(self.invoke.call_count, 1)
        self.invoke.reset_mock()
        self.invoke.side_effect = INSTALLER.AptError("timeout")
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.fetch(["update"], 820)
        self.assertEqual(self.invoke.call_count, 1)
        self.sleep.assert_not_called()

    def test_offline_install_failure_is_never_retried(self) -> None:
        self.invoke.side_effect = [(0, ""), (0, ""), (0, ""), (100, TEMPORARY)]
        with self.assertRaisesRegex(INSTALLER.AptError, "Offline"):
            INSTALLER.install(["dbus"])
        self.assertEqual(self.invoke.call_count, 4)
        self.sleep.assert_not_called()

    def test_commands_share_one_total_deadline(self) -> None:
        self.clock.side_effect = [100, 100, 340, 580, 695]
        self.invoke.return_value = (0, "")
        INSTALLER.install(["dbus"])
        self.assertEqual(
            [item.args[1] for item in self.invoke.call_args_list], [240, 240, 120, 125]
        )

    def test_no_new_command_or_sleep_after_budget_exhaustion(self) -> None:
        self.clock.return_value = 821
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.fetch(["update"], 820)
        self.invoke.assert_not_called()
        self.clock.return_value = 100
        self.invoke.return_value = (100, TEMPORARY)
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.fetch(["update"], 104)
        self.sleep.assert_not_called()

    def test_terminal_transient_result_keeps_fallback_when_retry_time_expires(
        self,
    ) -> None:
        self.invoke.return_value = (100, TEMPORARY)
        with self.assertRaises(INSTALLER.TransientFetchExhaustedError) as caught:
            INSTALLER.fetch(["--download-only", "install", "dbus"], 104)
        self.assertEqual(caught.exception.output, TEMPORARY)
        self.assertEqual(self.invoke.call_count, 1)
        self.sleep.assert_not_called()

    def test_bad_packages_and_unavailable_apt_fail_early(self) -> None:
        for packages in (
            [],
            ["--allow-unauthenticated"],
            ["dbus=1"],
            ["dbus;true"],
            ["../dbus"],
        ):
            with self.subTest(packages=packages), self.assertRaises(INSTALLER.AptError):
                INSTALLER.install(packages)
        self.invoke.assert_not_called()
        self.invoke.return_value = (1, "")
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.install(["dbus"])
        self.assertEqual(self.invoke.call_count, 1)


class TestOfficialPoolFallback(unittest.TestCase):
    """The fallback uses native APT and exact authenticated missing-package inputs."""

    URI = INSTALLER.SNAPSHOT + "pool/main/g/gcc-14/libcc1-0_14.2.0-19_amd64.deb"
    NAME = "libcc1-0_14.2.0-19_amd64.deb"
    BODY = b"test"

    def setUp(self) -> None:
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(patch.object(INSTALLER.time, "sleep"))
        self.enterContext(patch.object(INSTALLER.time, "monotonic", return_value=100))
        self.enterContext(
            patch.object(
                INSTALLER.pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_uid=os.geteuid()),
            )
        )
        self.digest = "SHA256:" + hashlib.sha256(self.BODY).hexdigest()
        self.plan = f"'{self.URI}' {self.NAME} 4 {self.digest}\n"
        self.failed = (
            f"E: Failed to fetch {self.URI} 503 Service Unavailable\n"
            "E: Some files failed to download\n"
        )
        self.commands: list[list[str]] = []
        self.cache: Path | None = None
        self.helper_body = self.BODY
        self.helper_status = 0
        self.partial_mode = 0o700

    def execute(self, command: list[str], _timeout: float) -> tuple[int, str]:
        self.commands.append(command)
        if command[0] == "/usr/bin/dpkg":
            return 0, "amd64\n"
        if command[0] == INSTALLER.APT_HELPER:
            index = command.index("download-file")
            target = Path(command[index + 2])
            self.assertFalse(target.exists())
            self.assertEqual(
                command[index + 1],
                INSTALLER.POOL + self.URI.removeprefix(INSTALLER.SNAPSHOT),
            )
            self.assertEqual(command[index + 3 :], [self.digest, "Checksum-FileSize:4"])
            self.assertNotIn("Acquire::ForceHash=sha256", command)
            self.assertIn("Acquire::ForceHash=", command)
            self.assertIn(
                "Acquire::https::deb.debian.org::AllowRedirect=false", command
            )
            target.write_bytes(self.helper_body)
            return self.helper_status, ""
        cache = [x for x in command if x.startswith("Dir::Cache::archives=")]
        if cache:
            self.cache = Path(cache[0].split("=", 1)[1])
        if "--print-uris" in command:
            self.assertIn("Acquire::ForceHash=sha256", command)
            return 0, self.plan
        if "--download-only" in command:
            assert self.cache
            partial = self.cache / "partial"
            partial.mkdir(exist_ok=True)
            partial.chmod(self.partial_mode)
            return 100, self.failed
        if "--no-download" in command:
            assert self.cache
            self.assertEqual((self.cache / self.NAME).read_bytes(), self.BODY)
        return 0, ""

    def test_native_exact_byte_fallback_then_offline_install_and_cleanup(self) -> None:
        with patch.object(INSTALLER, "run", side_effect=self.execute):
            INSTALLER.install(["dbus"])
        self.assertEqual(sum(c[0] == INSTALLER.APT_HELPER for c in self.commands), 1)
        self.assertEqual(
            sum(
                "--download-only" in c and "--print-uris" not in c
                for c in self.commands
            ),
            3,
        )
        self.assertIn("--no-download", self.commands[-1])
        assert self.cache
        self.assertFalse(self.cache.exists())

    def test_equal_size_corruption_is_never_published_or_installed(self) -> None:
        self.helper_body = b"evil"
        with (
            patch.object(INSTALLER, "run", side_effect=self.execute),
            self.assertRaisesRegex(INSTALLER.AptError, "hash"),
        ):
            INSTALLER.install(["dbus"])
        self.assertFalse(any("--no-download" in c for c in self.commands))
        assert self.cache
        self.assertFalse(self.cache.exists())

    def test_snapshot_file_redirect_keeps_sha256_and_checks_content_address(
        self,
    ) -> None:
        sha1 = hashlib.sha1(self.BODY, usedforsecurity=False).hexdigest()
        redirected = f"https://snapshot.debian.org/file/{sha1}/{self.NAME}"
        self.failed = self.failed.replace(self.URI, redirected)
        with patch.object(INSTALLER, "run", side_effect=self.execute):
            INSTALLER.install(["dbus"])
        self.assertIn("--no-download", self.commands[-1])
        self.assertEqual(sum(c[0] == INSTALLER.APT_HELPER for c in self.commands), 1)
        assert self.cache
        self.assertFalse(self.cache.exists())

    def test_snapshot_file_wrong_content_address_cannot_publish_valid_sha256(
        self,
    ) -> None:
        redirected = f"https://snapshot.debian.org/file/{'0' * 40}/{self.NAME}"
        self.failed = self.failed.replace(self.URI, redirected)
        with (
            patch.object(INSTALLER, "run", side_effect=self.execute),
            self.assertRaisesRegex(INSTALLER.AptError, "Snapshot file identity"),
        ):
            INSTALLER.install(["dbus"])
        self.assertFalse(any("--no-download" in c for c in self.commands))
        assert self.cache
        self.assertFalse(self.cache.exists())

    def test_snapshot_file_matching_sha1_never_replaces_sha256(self) -> None:
        self.helper_body = b"evil"
        sha1 = hashlib.sha1(self.helper_body, usedforsecurity=False).hexdigest()
        self.failed = self.failed.replace(
            self.URI, f"https://snapshot.debian.org/file/{sha1}/{self.NAME}"
        )
        with (
            patch.object(INSTALLER, "run", side_effect=self.execute),
            self.assertRaisesRegex(INSTALLER.AptError, "hash"),
        ):
            INSTALLER.install(["dbus"])
        self.assertFalse(any("--no-download" in c for c in self.commands))

    def test_snapshot_file_diagnostic_has_strict_url_and_filename_identity(
        self,
    ) -> None:
        valid = f"https://snapshot.debian.org/file/{'a' * 40}/{self.NAME}"
        invalid = [
            valid.replace("https://", "http://"),
            valid.replace("snapshot.debian.org", "snapshot.debian.org.evil.invalid"),
            valid.replace("snapshot.debian.org", "user@snapshot.debian.org"),
            valid.replace("snapshot.debian.org", "snapshot.debian.org:443"),
            valid.replace("a" * 40, "a" * 39),
            valid.replace("a" * 40, "A" * 40),
            valid + "?x=1",
            valid + "#x",
            valid + "/extra",
            valid.replace(self.NAME, "%2f" + self.NAME),
            valid.replace(self.NAME, "%5c" + self.NAME),
            valid.replace(self.NAME, "%00" + self.NAME),
            valid.replace(self.NAME, "%xx" + self.NAME),
            valid.replace("amd64", "arm64"),
            valid.replace("14.2.0-19", "14.2.0-20"),
        ]
        for uri in invalid:
            with self.subTest(uri=uri), self.assertRaises(INSTALLER.AptError):
                INSTALLER.parse_plan(
                    self.plan, self.failed.replace(self.URI, uri), "amd64"
                )
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.parse_plan(
                self.plan.replace(self.URI, valid),
                self.failed.replace(self.URI, valid),
                "amd64",
            )

    def test_snapshot_file_mapping_rejects_duplicate_aliases_and_basename_collisions(
        self,
    ) -> None:
        valid = f"https://snapshot.debian.org/file/{'a' * 40}/{self.NAME}"
        redirected = self.failed.replace(self.URI, valid)
        for failed in [
            self.failed + redirected,
            redirected + redirected,
            redirected + redirected.replace("a" * 40, "b" * 40),
        ]:
            with self.subTest(failed=failed), self.assertRaises(INSTALLER.AptError):
                INSTALLER.parse_plan(self.plan, failed, "amd64")
        second = self.plan.replace("g/gcc-14/", "o/other/").replace(
            " " + self.NAME + " ", " other_1_amd64.deb "
        )
        with self.assertRaisesRegex(INSTALLER.AptError, "unique"):
            INSTALLER.parse_plan(self.plan + second, redirected, "amd64")
        # The cache filename is not the authoritative archive filename.
        wrong_archive = self.plan.replace(
            self.URI, self.URI.replace("libcc1-0_", "other_")
        )
        with self.assertRaisesRegex(INSTALLER.AptError, "unique"):
            INSTALLER.parse_plan(wrong_archive, redirected, "amd64")

    def test_snapshot_file_mapping_uses_decoded_archive_name_not_epoch_cache_name(
        self,
    ) -> None:
        uri = self.URI.replace("-19_", "+19_")
        cache_name = "2%3a" + self.NAME.replace("-19_", "+19_")
        plan = self.plan.replace(self.URI, uri).replace(
            " " + self.NAME + " ", f" {cache_name} "
        )
        filename = self.NAME.replace("-19_", "%2b19_")
        redirected = f"https://snapshot.debian.org/file/{'a' * 40}/{filename}"
        result = INSTALLER.parse_plan(
            plan, self.failed.replace(self.URI, redirected), "amd64"
        )
        self.assertEqual(
            result,
            [
                (
                    INSTALLER.POOL + uri.removeprefix(INSTALLER.SNAPSHOT),
                    cache_name,
                    4,
                    self.digest,
                )
            ],
        )

    def test_observed_arm_snapshot_redirect_can_mix_with_archive_failures(self) -> None:
        filename = "libgirepository-2.0-dev_2.84.4-3~deb13u5_arm64.deb"
        uri = INSTALLER.SNAPSHOT + "pool/main/g/glib2.0/" + filename
        redirect = (
            "https://snapshot.debian.org/file/b0760ff9af4fb94db29e03631a822f0e776c7b85/"
            + filename
        )
        plan = (
            self.plan.replace("amd64", "arm64")
            + f"'{uri}' {filename} 4 {self.digest}\n"
        )
        failed = self.failed.replace("amd64", "arm64") + (
            f"E: Failed to fetch {redirect} 503 Service Unavailable\n"
        )
        result = INSTALLER.parse_plan(plan, failed, "arm64")
        self.assertEqual(len(result), 2)
        self.assertEqual(
            result[-1],
            (
                INSTALLER.POOL + "pool/main/g/glib2.0/" + filename,
                filename,
                4,
                self.digest,
            ),
        )

    def test_openssl_reset_fallback_keeps_signed_package_plan(self) -> None:
        self.failed = self.failed.replace(
            "503 Service Unavailable", "TooManyRequests " + OPENSSL_RESET
        )
        with patch.object(INSTALLER, "run", side_effect=self.execute):
            INSTALLER.install(["dbus"])
        self.assertEqual(sum(c[0] == INSTALLER.APT_HELPER for c in self.commands), 1)
        self.assertTrue(any("--no-download" in c for c in self.commands))

    def test_helper_error_and_wrong_size_do_not_retry_or_install(self) -> None:
        for status, body in [(100, self.BODY), (0, b"too-long")]:
            with self.subTest(status=status):
                self.helper_status, self.helper_body = status, body
                self.commands.clear()
                with (
                    patch.object(INSTALLER, "run", side_effect=self.execute),
                    self.assertRaises(INSTALLER.AptError),
                ):
                    INSTALLER.install(["dbus"])
                self.assertEqual(
                    sum(c[0] == INSTALLER.APT_HELPER for c in self.commands), 1
                )
                self.assertFalse(any("--no-download" in c for c in self.commands))

    def test_sandbox_directory_must_remain_private_and_traversable(self) -> None:
        self.partial_mode = 0o755
        with (
            patch.object(INSTALLER, "run", side_effect=self.execute),
            self.assertRaisesRegex(INSTALLER.AptError, "sandbox"),
        ):
            INSTALLER.install(["dbus"])
        self.assertFalse(any(c[0] == INSTALLER.APT_HELPER for c in self.commands))

    def test_plan_rejects_untrusted_paths_hashes_architecture_and_duplicates(
        self,
    ) -> None:
        invalid = [
            self.plan.replace("https://snapshot.debian.org", "https://evil.invalid"),
            self.plan.replace("20260630T", "20260701T"),
            self.plan.replace("pool/main/", "dists/main/"),
            self.plan.replace("pool/main/", "pool/main/../"),
            self.plan.replace("pool/main/", "pool/main/%2f"),
            self.plan.replace("pool/main/", "pool/main/%xx"),
            self.plan.replace(".deb'", ".deb?q=1'"),
            self.plan.replace("amd64", "arm64"),
            self.plan.replace("SHA256:", "MD5Sum:"),
            self.plan.replace(" " + self.digest, ""),
            self.plan.replace(" 4 ", " 0 "),
            self.plan.replace(" 4 ", " 9999999999 "),
            self.plan + self.plan,
            self.plan + "W: Unauthenticated package\n",
            self.plan.replace(" " + self.NAME + " ", " ../escape.deb "),
        ]
        for index, plan in enumerate(invalid):
            if index < 8:
                # Match the mutated URI so the final set comparison cannot mask
                # missing per-line origin/path/architecture validation.
                failed = self.failed.replace(self.URI, plan.split("'")[1])
                with (
                    self.subTest(plan=plan),
                    self.assertRaisesRegex(
                        INSTALLER.AptError, "Untrusted or ambiguous"
                    ),
                ):
                    INSTALLER.parse_plan(plan, failed, "amd64")
            else:
                with self.subTest(plan=plan), self.assertRaises(INSTALLER.AptError):
                    INSTALLER.parse_plan(plan, self.failed, "amd64")

    def timeout_output(self) -> str:
        return (
            "Err:1 "
            + str(INSTALLER.SNAPSHOT).rstrip("/")
            + " bookworm/main amd64 libcc1-0 amd64 14.2.0-19\n"
            "  TooManyRequests 503  No healthy backends [IP: 192.0.2.1 443]\n"
        )

    def test_package_timeout_recovers_once_from_verified_remaining_plan(self) -> None:
        def timed_run(command: list[str], timeout: float) -> tuple[int, str]:
            result = self.execute(command, timeout)
            if "--download-only" in command and "--print-uris" not in command:
                raise INSTALLER.CommandTimeoutError(self.timeout_output())
            return result

        with patch.object(INSTALLER, "run", side_effect=timed_run):
            INSTALLER.install(["dbus"])
        self.assertEqual(sum(c[0] == INSTALLER.APT_HELPER for c in self.commands), 1)
        self.assertEqual(
            sum(
                "--download-only" in c and "--print-uris" not in c
                for c in self.commands
            ),
            1,
        )
        self.assertIn("--no-download", self.commands[-1])
        assert self.cache
        self.assertFalse(self.cache.exists())

    def test_timeout_plan_can_include_unattempted_but_authenticated_packages(
        self,
    ) -> None:
        other = self.plan.replace("libcc1-0_", "libgomp1_")
        result = INSTALLER.parse_plan(
            self.plan + other, self.timeout_output(), "amd64", timed_out=True
        )
        self.assertEqual(len(result), 2)
        with self.assertRaisesRegex(INSTALLER.AptError, "differ"):
            INSTALLER.parse_plan(other, self.timeout_output(), "amd64", timed_out=True)

    def test_timeout_requires_complete_snapshot_native_transient_package_evidence(
        self,
    ) -> None:
        good = self.timeout_output()
        proxy = good.replace(
            "TooManyRequests 503  No healthy backends",
            "Invalid response from proxy: HTTP/1.1 503 Service Unavailable",
        )
        self.assertEqual(INSTALLER.timed_out_packages(proxy, "amd64"), {self.NAME})
        bad = [
            "",
            good.rstrip("\n"),
            good.splitlines()[0],
            good.replace("snapshot.debian.org", "evil.invalid"),
            good.replace("20260630T", "20260701T"),
            good.replace("bookworm/main", "trixie/main"),
            good.replace("amd64", "arm64"),
            good.replace("libcc1-0 amd64 14.2.0-19", "Packages"),
            good.replace("503  No healthy backends", "404 Not Found"),
            good.replace(
                "503  No healthy backends", "503 Service Unavailable; unknown failure"
            ),
            good + "  404 Not Found\n",
            good + "E: Unknown failure\n",
            good + "W: Failed to fetch anything\n",
            good + "WARNING: cannot be authenticated\n",
            good + "Hash Sum mismatch\n",
            good + "No space left on device\n",
            good + good,
        ]
        for output in bad:
            with self.subTest(output=output), self.assertRaises(INSTALLER.AptError):
                INSTALLER.parse_plan(self.plan, output, "amd64", timed_out=True)

    def test_timeout_accepts_server_defined_503_and_504_reasons(self) -> None:
        good = self.timeout_output()
        for reason in (
            "503",
            "504  New upstream wording",
            "TooManyRequests 503  Backend fetch failed",
            "Invalid response from proxy: HTTP/1.1 503 Backend fetch failed",
        ):
            with self.subTest(reason=reason):
                output = good.replace(
                    "TooManyRequests 503  No healthy backends", reason
                )
                self.assertEqual(
                    INSTALLER.timed_out_packages(output, "amd64"), {self.NAME}
                )

    def test_timeout_accepts_only_observed_openssl_connection_reset(self) -> None:
        header = self.timeout_output().splitlines()[0]
        for reason in (OPENSSL_RESET, "TooManyRequests " + OPENSSL_RESET):
            with self.subTest(reason=reason):
                output = header + "\n  " + reason + "\n"
                self.assertEqual(
                    INSTALLER.timed_out_packages(output, "amd64"), {self.NAME}
                )
        for reason in (
            OPENSSL_RESET.replace(
                "(104: Connection reset by peer)", "(1: certificate verify failed)"
            ),
            OPENSSL_RESET.replace("error:00000000", "error:00000001"),
            OPENSSL_RESET + " unknown failure",
        ):
            with self.subTest(reason=reason), self.assertRaises(INSTALLER.AptError):
                INSTALLER.timed_out_packages(header + "\n  " + reason + "\n", "amd64")

    def test_timeout_reset_recovers_only_through_verified_package_plan(self) -> None:
        output = self.timeout_output().splitlines()[0] + "\n  " + OPENSSL_RESET + "\n"

        def timed_run(command: list[str], timeout: float) -> tuple[int, str]:
            result = self.execute(command, timeout)
            if "--download-only" in command and "--print-uris" not in command:
                raise INSTALLER.CommandTimeoutError(output)
            return result

        with patch.object(INSTALLER, "run", side_effect=timed_run):
            INSTALLER.install(["dbus"])
        self.assertEqual(sum(c[0] == INSTALLER.APT_HELPER for c in self.commands), 1)
        self.assertIn("--no-download", self.commands[-1])
        assert self.cache
        self.assertFalse(self.cache.exists())

    def test_timeout_status_policy_stays_narrow_and_requires_complete_reason(
        self,
    ) -> None:
        for reason in (
            "408 Request Timeout",
            "429 Too Many Requests",
            "500 Internal Server Error",
            "502 Bad Gateway",
            "501 Unknown",
            "505 Unknown",
            "599 Unknown",
            "package 503 Backend fetch failed",
            "503 Backend fetch failed; unknown failure",
            "503 Backend fetch failed\rignored",
            "503 Backend fetch failed\x00",
            "5030 Backend fetch failed",
            "503 404 Not Found",
        ):
            with self.subTest(reason=reason), self.assertRaises(INSTALLER.AptError):
                INSTALLER.timed_out_packages(
                    self.timeout_output().replace(
                        "TooManyRequests 503  No healthy backends", reason
                    ),
                    "amd64",
                )

    def test_index_timeout_never_reaches_package_fallback(self) -> None:
        with (
            patch.object(
                INSTALLER,
                "run",
                side_effect=[
                    (0, ""),
                    INSTALLER.CommandTimeoutError(self.timeout_output()),
                ],
            ),
            patch.object(INSTALLER, "fallback_packages") as fallback,
            self.assertRaises(INSTALLER.CommandTimeoutError),
        ):
            INSTALLER.install(["dbus"])
        fallback.assert_not_called()

    def test_plan_must_match_all_and_only_terminal_failed_packages(self) -> None:
        for failed in [
            self.failed.replace("libcc1-0_", "other_"),
            self.failed + self.failed.replace("libcc1-0_", "other_"),
            self.failed + self.failed,
        ]:
            with self.subTest(failed=failed), self.assertRaises(INSTALLER.AptError):
                INSTALLER.parse_plan(self.plan, failed, "amd64")
        parsed = INSTALLER.parse_plan(self.plan, self.failed, "amd64")
        self.assertEqual(parsed[0][1:], (self.NAME, 4, self.digest))

    def test_whole_plan_is_checked_before_helper_writes(self) -> None:
        self.plan += self.plan.replace("libcc1-0_", "other_")
        with (
            patch.object(INSTALLER, "run", side_effect=self.execute),
            self.assertRaises(INSTALLER.AptError),
        ):
            INSTALLER.install(["dbus"])
        self.assertFalse(any(c[0] == INSTALLER.APT_HELPER for c in self.commands))

    def test_count_and_aggregate_size_limits_are_not_per_file_only(self) -> None:
        with (
            patch.object(INSTALLER, "MAX_PACKAGES", 0),
            self.assertRaises(INSTALLER.AptError),
        ):
            INSTALLER.parse_plan(self.plan, self.failed, "amd64")
        with (
            patch.object(INSTALLER, "MAX_FALLBACK_BYTES", 3),
            self.assertRaises(INSTALLER.AptError),
        ):
            INSTALLER.parse_plan(self.plan, self.failed, "amd64")

    def test_no_fallback_on_auth_integrity_or_index_failures(self) -> None:
        original_failure = self.failed
        for failure in [
            original_failure + "E: Hash Sum mismatch\n",
            original_failure + "E: NO_PUBKEY abc\n",
            original_failure.replace("503 Service Unavailable", "403 Forbidden"),
        ]:
            with self.subTest(failure=failure):
                self.failed = failure
                self.commands.clear()
                with (
                    patch.object(INSTALLER, "run", side_effect=self.execute),
                    self.assertRaises(INSTALLER.AptError),
                ):
                    INSTALLER.install(["dbus"])
                self.assertFalse(
                    any(
                        c[0] == INSTALLER.APT_HELPER or "--print-uris" in c
                        for c in self.commands
                    )
                )


class TestConfiguredArchives(unittest.TestCase):
    """Recovery is restricted to the exact collector snapshot and suite."""

    DIGEST = "SHA256:" + hashlib.sha256(b"test").hexdigest()

    def test_archive_matches_the_committed_collector_source(self) -> None:
        root = Path(__file__).resolve().parents[1]
        docker = (root / "collector/Dockerfile").read_text()
        self.assertEqual(
            INSTALLER.ARCHIVES,
            (
                (
                    "https://snapshot.debian.org/archive/debian/20260630T000000Z/",
                    "https://deb.debian.org/debian/",
                    "pool/main/",
                    ("bookworm",),
                ),
            ),
        )
        self.assertIn(
            "deb [check-valid-until=no] "
            + INSTALLER.SNAPSHOT.rstrip("/")
            + " bookworm main",
            docker,
        )
        self.assertIn("COPY install-system-deps.py /tmp/install-system-deps.py", docker)
        self.assertIn(
            "python3 /tmp/install-system-deps.py gcc-aarch64-linux-gnu "
            "g++-aarch64-linux-gnu pkg-config cmake python3",
            docker,
        )
        workflow = (root / ".github/workflows/ci.yml").read_text()
        self.assertIn(
            'cp collector/install-system-deps.py "$RUNNER_TEMP/collector-context/install-system-deps.py"',
            workflow,
        )
        self.assertIn('Path("collector/install-system-deps.py"),', workflow)
        self.assertIn("timeout-minutes: 100", workflow)
        self.assertIn("timeout-minutes: 120", workflow)

    def test_equivalent_url_escapes_keep_exact_package_identity(self) -> None:
        for arch in ("amd64", "arm64"):
            name = f"libmount-dev_2.38.1-5+deb12u3_{arch}.deb"
            relative = "pool/main/u/util-linux/" + name
            uri = INSTALLER.SNAPSHOT + relative
            failed = f"E: Failed to fetch {uri.replace('+', '%2b')} 503 No healthy backends\n"
            self.assertEqual(
                INSTALLER.parse_plan(f"'{uri}' {name} 4 {self.DIGEST}\n", failed, arch),
                [(INSTALLER.POOL + relative, name, 4, self.DIGEST)],
            )

    def test_other_archives_snapshots_versions_and_paths_are_rejected(self) -> None:
        name = "libmount-dev_2.38.1-5+deb12u3_amd64.deb"
        uri = INSTALLER.SNAPSHOT + "pool/main/u/util-linux/" + name
        plan = f"'{uri}' {name} 4 {self.DIGEST}\n"
        invalid = [
            uri.replace("snapshot.debian.org", "evil.invalid"),
            uri.replace("20260630T", "20260701T"),
            uri.replace("/archive/debian/", "/archive/debian-security/"),
            uri.replace("pool/main/", "pool/updates/main/"),
            uri.replace("u/util-linux/", "other/source/"),
            uri.replace("u/util-linux/", "u/../util-linux/"),
            uri.replace("u/util-linux/", "u%2futil-linux/"),
            uri.replace("u/util-linux/", "u/%252e%252e/util-linux/"),
            uri.replace("deb12u3", "deb12u4"),
            uri.replace("amd64.deb", "arm64.deb"),
            uri + "?download=1",
            uri + "#fragment",
            uri.replace(".deb", "%00.deb"),
        ]
        for failed_uri in invalid:
            with self.subTest(uri=failed_uri), self.assertRaises(INSTALLER.AptError):
                INSTALLER.parse_plan(
                    plan,
                    f"E: Failed to fetch {failed_uri} 503 No healthy backends\n",
                    "amd64",
                )

    def test_observed_bookworm_timeout_is_recognized(self) -> None:
        output = (
            f"Err:1 {INSTALLER.SNAPSHOT.rstrip('/')} bookworm/main amd64 "
            "gcc-aarch64-linux-gnu amd64 4:12.2.0-3\n"
            "  503  No healthy backends [IP: 151.101.66.132 443]\n"
        )
        self.assertEqual(
            INSTALLER.timed_out_packages(output, "amd64"),
            {"gcc-aarch64-linux-gnu_4:12.2.0-3_amd64.deb"},
        )
        for value in (
            output.replace("bookworm/main", "bookworm-updates/main"),
            output.replace("bookworm/main", "bookworm-security/main"),
            output.replace("bookworm/main", "bookworm/non-free"),
            output.replace("/archive/debian/", "/archive/debian-security/"),
            output.replace("20260630T", "20260701T"),
        ):
            with self.subTest(value=value), self.assertRaises(INSTALLER.AptError):
                INSTALLER.timed_out_packages(value, "amd64")


class TestBoundedProcess(unittest.TestCase):
    """Check real child-process output and termination without invoking APT."""

    def test_maximum_sized_malformed_http_reason_has_bounded_parse_time(self) -> None:
        program = (
            "import runpy, sys; "
            "module = runpy.run_path(sys.argv[1]); "
            "reason = '503 ' + ' ' * module['MAX_OUTPUT_BYTES'] + ';'; "
            "assert module['http_status'](reason) is None; "
            "print('bounded')"
        )
        assert SPEC is not None and SPEC.origin is not None
        status, output = INSTALLER.run(
            [sys.executable, "-c", program, str(SPEC.origin)], 5
        )
        self.assertEqual((status, output.strip()), (0, "bounded"))

    def test_maximum_sized_malformed_proxy_headers_have_bounded_parse_time(
        self,
    ) -> None:
        program = (
            "import runpy, sys; "
            "module = runpy.run_path(sys.argv[1]); "
            "reason = 'Invalid response from proxy: HTTP/1.0 503 Service Unavailable  ' "
            "+ ' ' * module['MAX_OUTPUT_BYTES'] + 'Content-Type: text/html;charset=;'; "
            "assert module['http_status'](reason) is None; print('bounded')"
        )
        assert SPEC is not None and SPEC.origin is not None
        status, output = INSTALLER.run(
            [sys.executable, "-c", program, str(SPEC.origin)], 5
        )
        self.assertEqual((status, output.strip()), (0, "bounded"))

    def test_maximum_sized_malformed_openssl_error_has_bounded_parse_time(self) -> None:
        program = (
            "import runpy, sys; "
            "module = runpy.run_path(sys.argv[1]); "
            "reason = 'OpenSSL system call error: error:00000000:lib(0)::reason(0)' "
            "+ ' ' * module['MAX_OUTPUT_BYTES'] + '- unknown'; "
            "assert not module['transient_reason'](reason); print('bounded')"
        )
        assert SPEC is not None and SPEC.origin is not None
        status, output = INSTALLER.run(
            [sys.executable, "-c", program, str(SPEC.origin)], 5
        )
        self.assertEqual((status, output.strip()), (0, "bounded"))

    def test_output_and_returncode(self) -> None:
        status, output = INSTALLER.run(
            [sys.executable, "-c", "print('ok'); raise SystemExit(7)"], 5
        )
        self.assertEqual((status, output.strip()), (7, "ok"))

    def test_command_timeout_is_bounded(self) -> None:
        started = time.monotonic()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(INSTALLER.CommandTimeoutError) as caught,
        ):
            INSTALLER.run(
                [
                    sys.executable,
                    "-c",
                    "import time; print('partial evidence', flush=True); time.sleep(30)",
                ],
                0.2,
            )
        self.assertEqual(caught.exception.output, "partial evidence\n")
        self.assertLess(time.monotonic() - started, 5)

    def test_timeout_retains_buffered_fatal_diagnostics_before_recovery(self) -> None:
        output = (
            "Err:1 "
            + str(INSTALLER.SNAPSHOT).rstrip("/")
            + " bookworm/main amd64 libcc1-0 amd64 14.2.0-19\n"
            "  504 Gateway Timeout\nE: Hash Sum mismatch\n"
        )
        real_read, real_popen = os.read, INSTALLER.subprocess.Popen
        stdout_fd: int | None = None
        first = True

        def spawn(*args: object, **kwargs: object) -> object:
            nonlocal stdout_fd
            process = real_popen(*args, **kwargs)
            stdout_fd = process.stdout.fileno()
            return process

        def throttled_read(fd: int, size: int) -> bytes:
            nonlocal first
            data = real_read(fd, min(size, 32) if fd == stdout_fd else size)
            if fd == stdout_fd and data and first:
                first = False
                time.sleep(0.3)
            return data

        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch.object(INSTALLER.subprocess, "Popen", side_effect=spawn),
            patch.object(INSTALLER.os, "read", side_effect=throttled_read),
            self.assertRaises(INSTALLER.CommandTimeoutError) as caught,
        ):
            INSTALLER.run(
                [
                    sys.executable,
                    "-c",
                    "import time; print("
                    + repr(output)
                    + ",end='',flush=True); time.sleep(30)",
                ],
                0.2,
            )
        self.assertEqual(caught.exception.output, output)
        with self.assertRaises(INSTALLER.AptError):
            INSTALLER.timed_out_packages(caught.exception.output, "amd64")

    def test_output_flood_is_bounded(self) -> None:
        captured = io.StringIO()
        with (
            patch.object(INSTALLER, "MAX_OUTPUT_BYTES", 4096),
            contextlib.redirect_stdout(captured),
            self.assertRaisesRegex(INSTALLER.AptError, "output budget"),
        ):
            INSTALLER.run(
                [sys.executable, "-c", "import os; os.write(1, b'x' * 1000000)"], 5
            )
        self.assertEqual(len(captured.getvalue()), 4096)

    def test_inherited_pipe_cannot_outlive_deadline(self) -> None:
        # The direct child exits but its descendant keeps the output pipe open.
        program = (
            "import subprocess, sys; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])"
        )
        started = time.monotonic()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(INSTALLER.AptError, "time budget"),
        ):
            INSTALLER.run([sys.executable, "-c", program], 0.2)
        self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
