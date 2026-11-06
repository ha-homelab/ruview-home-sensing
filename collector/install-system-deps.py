#!/usr/bin/env python3
"""Install exact signed Bookworm snapshot packages with bounded mirror recovery.

Adapted from the shared fleet's authenticated system-dependency installer.
The official pool supplies bytes only; package selection remains with the
committed snapshot and APT's authenticated package hashes.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import pwd
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

APT = "/usr/bin/apt-get"
TOTAL_SECONDS = 720
COMMAND_SECONDS = 240
FALLBACK_RESERVE_SECONDS = 120
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
ATTEMPTS = 3
APT_HELPER = "/usr/lib/apt/apt-helper"
SNAPSHOT = "https://snapshot.debian.org/archive/debian/20260630T000000Z/"
POOL = "https://deb.debian.org/debian/"
ARCHIVES = ((SNAPSHOT, POOL, "pool/main/", ("bookworm",)),)
MAX_PACKAGES = 256
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_FALLBACK_BYTES = 512 * 1024 * 1024
OPTIONS = [
    "-o",
    "Acquire::Retries=0",
    "-o",
    "Acquire::Check-Valid-Until=false",
    # These signed snapshots publish xz package indices. Do not let a transient
    # xz failure fall through to absent plain indices and mask it as a fatal 404.
    "-o",
    "Acquire::IndexTargets::deb::Packages::CompressionTypes=xz",
    # APT also uses CompressionTypes to find local indices. Keep the downloaded
    # format instead of the default lz4 cache that an xz-only lookup cannot see.
    "-o",
    "Acquire::IndexTargets::deb::Packages::KeepCompressedAs=xz",
    "-o",
    "Acquire::http::Timeout=30",
    "-o",
    "Acquire::https::Timeout=30",
]
TRANSIENT_HTTP_STATUSES = {408, 429, 500, 502, 503, 504}
HTTP_IP_SUFFIX = re.compile(r"\[IP: [0-9a-fA-F:.]+ [0-9]+\]")
HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# APT 3 emits this errno-bearing form separately from TLS verification errors.
# Match the complete observed ECONNRESET diagnostic, not arbitrary SSL failures.
OPENSSL_CONNECTION_RESET = re.compile(
    r"(?:TooManyRequests )?OpenSSL system call error: "
    r"error:00000000:lib\(0\)::reason\(0\) +- openssl "
    r"\(104: Connection reset by peer\)"
    r"(?: \[IP: [0-9a-fA-F:.]+ [0-9]+\])?"
)
TRANSIENT_NETWORK = re.compile(
    r"(?:Temporary failure resolving|"
    r"Could not (?:resolve|connect)|Connection (?:timed out|failed|reset)|"
    r"TLS connection was non-properly terminated)\b",
    re.IGNORECASE,
)
PERMANENT = re.compile(
    r"\b(?:NO_PUBKEY|EXPKEYSIG|BADSIG)\b|Hash Sum mismatch|"
    r"not signed|invalid signature|signatures? (?:couldn't|could not|cannot) be verified|"
    r"does not have a Release file|Release file .* (?:expired|not valid)|"
    r"Unable to locate package|unmet dependencies|held broken packages|"
    r"not enough free space|No space left on device",
    re.IGNORECASE,
)
PERMANENT_STATUS = re.compile(r"\b(?:401|403|404)\b")


class AptError(RuntimeError):
    """A bounded fetch or offline installation did not complete safely."""


class CommandTimeoutError(AptError):
    """Retain bounded partial output after the whole command group is terminated."""

    def __init__(self, output: str) -> None:
        """Keep partial transport evidence distinct from every other failure."""
        super().__init__("APT command exceeded its time budget")
        self.output = output


class TransientFetchExhaustedError(AptError):
    """Only a classified transient response after retry exhaustion enables fallback."""

    def __init__(self, output: str) -> None:
        """Retain the exact final diagnostic without widening retry eligibility."""
        super().__init__("APT transient fetch attempts exhausted")
        self.output = output


def run(command: list[str], timeout: float) -> tuple[int, str]:
    """Bound output and terminate the command's process group on an interrupted read."""
    output = bytearray()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "LC_ALL": "C"},
        start_new_session=True,
    )
    assert process.stdout is not None
    with process.stdout, selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise CommandTimeoutError(output.decode("utf-8", "replace"))
                for key, _ in selector.select(timeout=0.05):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    allowance = MAX_OUTPUT_BYTES - len(output)
                    output.extend(chunk[:allowance])
                    if len(chunk) > allowance:
                        raise AptError("APT command exceeded its output budget")
            return process.returncode, output.decode("utf-8", "replace")
        except BaseException as error:
            # The HTTP helpers belong to this invocation too. Do not leave them
            # running when a retry budget, cancellation or output limit stops us.
            cleanup_deadline = time.monotonic() + 5
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
            if isinstance(error, CommandTimeoutError):
                # Include diagnostics already buffered before the group died.
                # An escaped writer or output flood must not enable recovery.
                while selector.get_map():
                    cleanup_allowance = cleanup_deadline - time.monotonic()
                    if cleanup_allowance <= 0:
                        raise AptError(
                            "APT time budget expired without output EOF"
                        ) from error
                    ready = selector.select(timeout=cleanup_allowance)
                    if not ready:
                        raise AptError(
                            "APT time budget expired without output EOF"
                        ) from error
                    for key, _ in ready:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        allowance = MAX_OUTPUT_BYTES - len(output)
                        output.extend(chunk[:allowance])
                        if len(chunk) > allowance:
                            raise AptError(
                                "APT command exceeded its output budget"
                            ) from error
                error.output = output.decode("utf-8", "replace")
            sys.stdout.write(output.decode("utf-8", "replace"))
            raise


def proxy_content_type_parameters(phrase: str) -> bool:
    """Allow semicolons only in a flattened proxy Content-Type header."""
    # APT includes the CONNECT response headers and flattens each CRLF into
    # two spaces. Token-valued MIME parameters cover the native proxy fixture;
    # unrecognized syntax remains fatal rather than widening all reason text.
    fields = phrase.split("  ")
    if ";" in fields[0]:
        return False
    for field in fields[1:]:
        if ";" not in field:
            continue
        name, separator, value = field.strip().partition(":")
        if not separator or name.lower() != "content-type":
            return False
        media, *parameters = value.split(";")
        media_parts = media.strip().split("/")
        if len(media_parts) != 2 or not all(
            HTTP_TOKEN.fullmatch(p) for p in media_parts
        ):
            return False
        for parameter in parameters:
            key, equals, item = parameter.strip().partition("=")
            item = item.strip()
            if len(item) >= 2 and item.startswith('"') and item.endswith('"'):
                item = item[1:-1]
            if (
                not equals
                or not HTTP_TOKEN.fullmatch(key.strip())
                or not HTTP_TOKEN.fullmatch(item)
            ):
                return False
    return True


def http_status(reason: str) -> int | None:
    """Parse a complete APT HTTP reason without relying on server wording."""
    # HTTP reason phrases are optional and server-defined. Parse the fixed
    # prefix/token separately to avoid backtracking over a long error body.
    proxy_response = False
    for prefix in (
        "Invalid response from proxy: HTTP/1.0 ",
        "Invalid response from proxy: HTTP/1.1 ",
    ):
        if reason.startswith(prefix):
            reason = reason.removeprefix(prefix)
            proxy_response = True
            break
    reason = reason.removeprefix("TooManyRequests ")
    if re.fullmatch(r"[1-5][0-9]{2}", reason[:3]) is None:
        return None
    status, phrase = int(reason[:3]), reason[3:]
    if not phrase:
        return status
    if phrase[0] not in " \t":
        return None
    phrase = phrase.lstrip(" \t")
    if "[" in phrase or "]" in phrase:
        text, marker, address = phrase.rpartition("[IP: ")
        if (
            not marker
            or (text and text[-1] not in " \t")
            or HTTP_IP_SUFFIX.fullmatch(marker + address) is None
        ):
            return None
        phrase = text.rstrip(" \t")
    if re.search(r"[\x00-\x1f\x7f\[\]]", phrase):
        return None
    if ";" in phrase and (
        not proxy_response or not proxy_content_type_parameters(phrase)
    ):
        return None
    return status


def transient_reason(reason: str) -> bool:
    """Accept explicit temporary HTTP or network failures, not incidental text."""
    if PERMANENT_STATUS.search(reason) or re.search(
        r"[\x00-\x08\x0a-\x1f\x7f]", reason
    ):
        return False
    status = http_status(reason)
    if status is not None:
        return status in TRANSIENT_HTTP_STATUSES
    return (
        OPENSSL_CONNECTION_RESET.fullmatch(reason) is not None
        or TRANSIENT_NETWORK.match(reason) is not None
    )


def transient_failure(output: str) -> bool:
    """Require every terminal APT diagnostic to describe a temporary fetch failure."""
    if PERMANENT.search(output):
        return False
    errors = [
        line[3:] for line in output.split("\n") if line.startswith(("E: ", "W: "))
    ]
    fetch_errors = [line for line in errors if line.startswith("Failed to fetch ")]
    summaries = (
        "Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?",
        "Some index files failed to download. They have been ignored, or old ones used instead.",
        "Some files failed to download",
    )
    # APT can print several transport responses before its terminal E:/W: reason.
    # Do not mistake intermediate status codes, package sizes or URL paths for
    # that final reason. Authentication, integrity and disk errors remain fatal.
    reasons = [
        line.removeprefix("Failed to fetch ").split(maxsplit=1) for line in fetch_errors
    ]
    return (
        bool(reasons)
        and all(len(parts) == 2 and transient_reason(parts[1]) for parts in reasons)
        and all(
            line.startswith("Failed to fetch ") or line in summaries for line in errors
        )
    )


def remaining(deadline: float) -> float:
    """Return the remaining command allowance within the whole operation's budget."""
    budget = deadline - time.monotonic()
    if budget <= 0:
        raise AptError("System dependency installation exceeded its total time budget")
    return min(COMMAND_SECONDS, budget)


def fetch(arguments: list[str], deadline: float) -> None:
    """Retry only APT fetch failures with explicit transient transport evidence."""
    for attempt in range(1, ATTEMPTS + 1):
        status, output = run([APT, *OPTIONS, *arguments], remaining(deadline))
        sys.stdout.write(output)
        if status == 0:
            return
        if status != 100 or not transient_failure(output):
            raise AptError(
                f"APT fetch failed with status {status} on attempt {attempt}"
            )
        if attempt == ATTEMPTS:
            raise TransientFetchExhaustedError(output)
        delay = 5 * attempt
        if deadline - time.monotonic() <= delay:
            raise TransientFetchExhaustedError(output)
        sys.stdout.write(
            f"Transient APT fetch failure; retrying in {delay}s ({attempt}/{ATTEMPTS})\n"
        )
        time.sleep(delay)


def timed_out_packages(output: str, architecture: str) -> set[str]:
    """Accept only complete, trusted package Err blocks after native CheckAuth."""
    if (
        architecture not in {"amd64", "arm64"}
        or not output.endswith("\n")
        or PERMANENT.search(output)
        or re.search(
            r"(?im)^(?:E:|W:|WARNING:)|unauthenticated|cannot be authenticated", output
        )
    ):
        raise AptError("Untrusted package timeout diagnostic")
    lines = output.split("\n")
    packages: set[str] = set()
    sources = "|".join(
        re.escape(snapshot.rstrip("/"))
        + r" (?:"
        + "|".join(re.escape(suite) for suite in suites)
        + r")/main"
        for snapshot, _, _, suites in ARCHIVES
    )
    header = re.compile(
        r"Err:[0-9]+ (?:"
        + sources
        + r") "
        + architecture
        + r" ([a-z0-9][a-z0-9+.-]*) ("
        + architecture
        + r"|all) ([0-9][A-Za-z0-9.+:~_-]*)"
    )
    for index, line in enumerate(lines):
        if not line.startswith("Err:"):
            continue
        match = header.fullmatch(line)
        if (
            match is None
            or index + 1 >= len(lines)
            or not lines[index + 1].startswith("  ")
        ):
            raise AptError("Unknown or incomplete package timeout diagnostic")
        if index + 2 < len(lines) and lines[index + 2].startswith("  "):
            raise AptError("Ambiguous package timeout diagnostic")
        reason = lines[index + 1][2:]
        if PERMANENT_STATUS.search(reason) or (
            http_status(reason) not in {503, 504}
            and OPENSSL_CONNECTION_RESET.fullmatch(reason) is None
        ):
            raise AptError("Non-transient package timeout diagnostic")
        name, arch, version = match.groups()
        package = f"{name}_{version}_{arch}.deb"
        if package in packages:
            raise AptError("Duplicate package timeout diagnostic")
        packages.add(package)
    if not packages:
        raise AptError("Package timeout has no trusted transient evidence")
    return packages


def package_identity(uri: str, architecture: str) -> tuple[str, str]:
    """Validate a configured archive URI and retain its exact package-relative path."""
    parsed = urlsplit(uri)
    archive = next((entry for entry in ARCHIVES if uri.startswith(entry[0])), None)
    if archive is None:
        raise AptError("Untrusted or ambiguous package download plan")
    snapshot, pool, package_prefix, _ = archive
    relative = uri.removeprefix(snapshot)
    decoded = unquote(relative)
    if (
        parsed.query
        or parsed.fragment
        or not relative.startswith(package_prefix)
        or not re.fullmatch(r"[A-Za-z0-9_./+~%:-]+", relative)
        or re.search(r"%(?:2f|5c|00)", relative, re.IGNORECASE)
        or re.search(r"%(?![0-9A-Fa-f]{2})", relative)
        or any(part in {"", ".", ".."} for part in decoded.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9_./+~:-]+", decoded)
        or not decoded.endswith(("_" + architecture + ".deb", "_all.deb"))
    ):
        raise AptError("Untrusted or ambiguous package download plan")
    # APT can exhaust another authenticated archive for the same package.
    # Keep the complete source-package path, version and architecture; only
    # equivalent URL escapes may differ within the configured archive root.
    return pool + relative, decoded.removeprefix(package_prefix)


def failed_package_uris(output: str) -> list[str]:
    """Read only the terminal fetch locations, never progress or incidental text."""
    return [
        line.partition("Failed to fetch ")[2].split(maxsplit=1)[0]
        for line in output.splitlines()
        if line.startswith(("E: Failed to fetch ", "W: Failed to fetch "))
    ]


def snapshot_file_identity(uri: str, architecture: str) -> tuple[str, str] | None:
    """Recognize a content-addressed diagnostic, never a permitted plan source."""
    prefix = "https://snapshot.debian.org/file/"
    if not uri.startswith(prefix):
        return None
    match = re.fullmatch(
        re.escape(prefix) + r"([0-9a-f]{40})/([A-Za-z0-9][A-Za-z0-9_.+~:%-]*)", uri
    )
    if match is None:
        raise AptError("Untrusted Snapshot file diagnostic")
    digest, filename = match.groups()
    decoded = unquote(filename)
    if re.search(r"%(?![0-9A-Fa-f]{2})", filename) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.+~:-]*_(?:" + architecture + r"|all)\.deb", decoded
    ):
        raise AptError("Untrusted Snapshot file diagnostic")
    return decoded, digest


def parse_plan(
    output: str, failed: str, architecture: str, *, timed_out: bool = False
) -> list[tuple[str, str, int, str]]:
    """Use only missing packages from the already authenticated Snapshot selection."""
    timeout_packages = timed_out_packages(failed, architecture) if timed_out else set()
    if architecture not in {"amd64", "arm64"} or (
        not timed_out and not transient_failure(failed)
    ):
        raise AptError("Invalid fallback architecture or preceding failure")
    failed_uris = failed_package_uris(failed)
    failures: set[str] = set()
    # APT's print-URIs exits before CheckAuth. This plan is only used after the
    # successful authenticated update and the actual, transient-only fetch.
    result: list[tuple[str, str, int, str]] = []
    uris: set[str] = set()
    identities: set[str] = set()
    names: set[str] = set()
    total = 0
    for line in output.splitlines():
        if line.startswith(("E:", "W:")):
            raise AptError("APT plan reported a diagnostic")
        if not line.startswith("'"):
            continue
        try:
            fields = shlex.split(line)
        except ValueError as error:
            raise AptError("Malformed package download plan") from error
        if len(fields) != 4:
            raise AptError("Malformed package download plan")
        uri, name, size_text, digest = fields
        destination, identity = package_identity(uri, architecture)
        if (
            identity in identities
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.+~:%-]*_(?:" + architecture + r"|all)\.deb",
                name,
            )
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.+~:-]*_(?:" + architecture + r"|all)\.deb",
                unquote(name),
            )
            or not re.fullmatch(r"[1-9][0-9]*", size_text)
            or len(size_text) > 10
            or not re.fullmatch(r"SHA256:[0-9a-f]{64}", digest)
            or uri in uris
            or name in names
        ):
            raise AptError("Untrusted or ambiguous package download plan")
        size = int(size_text)
        total += size
        if (
            size > MAX_PACKAGE_BYTES
            or total > MAX_FALLBACK_BYTES
            or len(result) >= MAX_PACKAGES
        ):
            raise AptError("Package fallback exceeds its byte or count budget")
        uris.add(uri)
        identities.add(identity)
        names.add(name)
        result.append((destination, name, size, digest))
    for uri in failed_uris:
        redirected = snapshot_file_identity(uri, architecture)
        if redirected is None:
            identity = package_identity(uri, architecture)[1]
        else:
            filename, _ = redirected
            matches = [
                item for item in identities if item.rsplit("/", 1)[-1] == filename
            ]
            if len(matches) != 1:
                raise AptError(
                    "Snapshot file diagnostic has no unique authenticated package"
                )
            identity = matches[0]
        if identity in failures:
            raise AptError("Duplicate terminal package failure")
        failures.add(identity)
    if not result or (not timed_out and identities != failures):
        raise AptError("Package plan differs from the final missing-package failures")
    if timed_out and not timeout_packages <= {unquote(name) for name in names}:
        raise AptError(
            "Timed-out package failures differ from the authenticated remaining plan"
        )
    return result


def fallback_packages(
    cache: Path,
    options: list[str],
    selection: list[str],
    deadline: float,
    failed: str,
    *,
    timed_out: bool = False,
) -> None:
    """Fetch exact authenticated bytes from one official pool without new indices."""
    status, architecture = run(
        ["/usr/bin/dpkg", "--print-architecture"], remaining(deadline)
    )
    if status:
        raise AptError("Cannot identify the native package architecture")
    status, output = run(
        [
            APT,
            *OPTIONS,
            *options,
            "-o",
            "Acquire::ForceHash=sha256",
            "--print-uris",
            "--download-only",
            *selection,
        ],
        remaining(deadline),
    )
    if status:
        raise AptError("Cannot obtain the authenticated missing-package plan")
    plan = parse_plan(output, failed, architecture.strip(), timed_out=timed_out)
    # APT may report Snapshot's final content-addressed redirect instead of the
    # archive URI. The plan alone determines where and what to download; the
    # redirect SHA-1 is an additional byte-identity check, never authentication.
    redirect_hashes = dict(
        item
        for uri in failed_package_uris(failed)
        if (item := snapshot_file_identity(uri, architecture.strip())) is not None
    )
    partial = cache / "partial"
    owner = pwd.getpwnam("_apt").pw_uid
    info = partial.lstat()
    root_info = cache.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner
        or stat.S_IMODE(info.st_mode) != 0o700
        or root_info.st_uid != os.geteuid()
        or stat.S_IMODE(root_info.st_mode) != 0o755
    ):
        raise AptError("Private APT cache does not preserve the download sandbox")
    for uri, name, size, digest in plan:
        temporary = partial / ("fallback-" + secrets.token_hex(16) + ".deb")
        destination = cache / name
        if os.path.lexists(temporary) or os.path.lexists(destination):
            raise AptError("Fallback package path already exists")
        status, output = run(
            [
                APT_HELPER,
                *OPTIONS,
                "-o",
                "Acquire::ForceHash=",
                "-o",
                "Acquire::http::AllowRedirect=false",
                "-o",
                "Acquire::https::AllowRedirect=false",
                "-o",
                "Acquire::https::deb.debian.org::AllowRedirect=false",
                "download-file",
                uri,
                str(temporary),
                digest,
                "Checksum-FileSize:" + str(size),
            ],
            remaining(deadline),
        )
        sys.stdout.write(output)
        if status:
            raise AptError("Official pool package download failed")
        descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != size
            ):
                raise AptError("Fallback package is not an exact-size regular file")
            hasher = hashlib.sha256()
            redirect_hash = redirect_hashes.get(unquote(uri.rsplit("/", 1)[-1]))
            redirect_hasher = (
                hashlib.sha1(usedforsecurity=False) if redirect_hash else None
            )
            count = 0
            while chunk := stream.read(1024 * 1024):
                remaining(deadline)
                count += len(chunk)
                if count > size:
                    raise AptError("Fallback package grew during verification")
                hasher.update(chunk)
                if redirect_hasher is not None:
                    redirect_hasher.update(chunk)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or hasher.hexdigest() != digest[7:]:
                raise AptError("Fallback package hash or identity changed")
            if (
                redirect_hasher is not None
                and redirect_hasher.hexdigest() != redirect_hash
            ):
                raise AptError(
                    "Fallback package differs from the Snapshot file identity"
                )
            # link() publishes without replacing an existing cache entry.
            os.link(temporary, destination, follow_symlinks=False)
            linked = destination.lstat()
            if (linked.st_dev, linked.st_ino) != (before.st_dev, before.st_ino):
                raise AptError("Fallback package changed before publication")
            temporary.unlink()


def install(packages: list[str]) -> None:
    """Keep authenticated snapshot resolution separate from the final offline install."""
    if not packages or any(
        not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", p) for p in packages
    ):
        raise AptError(
            "Expected package names, without options or repository overrides"
        )
    deadline = time.monotonic() + TOTAL_SECONDS
    status, output = run([APT, "--version"], remaining(deadline))
    sys.stdout.write(output)
    if status:
        raise AptError("Cannot identify the installed APT version")
    # Avoid APT's internal delayed-item retry loop (Debian #1111554/#1152704).
    # Each retry uses a new process; signature and package hash checks stay on.
    fetch(["update", "--error-on=any"], deadline)
    selection = ["install", "-y", "--no-install-recommends", *packages]
    # APT accepts an existing archive by size alone. Start empty so every input
    # is authenticated by this invocation, never inherited from a shared cache.
    with tempfile.TemporaryDirectory(prefix="ruview-apt-", dir="/tmp") as directory:
        cache = Path(directory)
        cache.chmod(0o755)  # _apt must traverse to its own partial/ directory.
        options = ["-o", "Dir::Cache::archives=" + directory + "/"]
        try:
            # Leave time for exact-byte recovery and the final offline install.
            fetch(
                [*options, "--download-only", *selection],
                deadline - FALLBACK_RESERVE_SECONDS,
            )
        except TransientFetchExhaustedError as error:
            fallback_packages(cache, options, selection, deadline, error.output)
        except CommandTimeoutError as error:
            # Only this authenticated package fetch may recover from a timeout;
            # update/authentication, helper and offline-install timeouts stay fatal.
            fallback_packages(
                cache, options, selection, deadline, error.output, timed_out=True
            )
        status, output = run(
            [APT, *OPTIONS, *options, "--no-download", *selection], remaining(deadline)
        )
        sys.stdout.write(output)
        if status:
            raise AptError(f"Offline APT installation failed with status {status}")


if __name__ == "__main__":
    try:
        install(sys.argv[1:])
    except AptError as error:
        sys.stderr.write(f"{error}\n")
        raise SystemExit(1) from error
