"""Load five reviewed private inputs using an independently supplied manifest pin."""

import hashlib
import json
import math
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

FILES = frozenset(
    {
        "nodes.json",
        "placements.json",
        "assumed-activity.json",
        "assumed-activity-receivers.json",
        "assumed-activity-runtime.json",
    }
)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_INPUT_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class SiteContext:
    manifest_sha256: str
    manifest_raw: bytes
    raw: dict[str, bytes]
    documents: dict[str, dict]


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate key in private site context")
            result[key] = value
        return result

    def number(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("Nonfinite number in private site context")
        return parsed

    return json.loads(
        raw, object_pairs_hook=pairs, parse_float=number, parse_constant=number
    )


def _directory(path):
    path = Path(os.path.abspath(path))
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Private context requires non-following directory descriptors")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            raise ValueError(
                "Private context directory must not grant group or other access"
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("Private context input must be a bounded regular file")
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise ValueError(
                "Private context inputs must not grant group or other access"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)
        after = os.fstat(fd)
        if len(raw) > limit or (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("Private context input changed or exceeded its size limit")
        return raw
    finally:
        os.close(fd)


def load_site_context(directory, expected_sha256):
    """Validate the entire pinned snapshot before a caller can perform I/O."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(
        "[a-f0-9]{64}", expected_sha256
    ):
        raise ValueError("Supply the independently approved manifest SHA256")
    fd = _directory(directory)
    try:
        manifest_raw = _read(fd, "manifest.json", MAX_MANIFEST_BYTES)
        if hashlib.sha256(manifest_raw).hexdigest() != expected_sha256:
            raise ValueError(
                "Private context manifest does not match the approved SHA256"
            )
        manifest = _json(manifest_raw)
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema", "files"}
            or manifest["schema"] != "ruview.private-site-context.v1"
            or not isinstance(manifest["files"], dict)
            or set(manifest["files"]) != FILES
            or any(
                not isinstance(h, str) or not re.fullmatch("[a-f0-9]{64}", h)
                for h in manifest["files"].values()
            )
        ):
            raise ValueError("Invalid private site context manifest")
        raw, documents = {}, {}
        for name in sorted(FILES):
            data = _read(fd, name, MAX_INPUT_BYTES)
            if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
                raise ValueError(
                    "Private context input differs from the reviewed snapshot"
                )
            value = _json(data)
            if not isinstance(value, dict):
                raise ValueError("Private context documents must be JSON objects")
            raw[name], documents[name] = data, value
        return SiteContext(expected_sha256, manifest_raw, raw, documents)
    finally:
        os.close(fd)


def load_pinned_json(path, expected_sha256, limit=MAX_INPUT_BYTES):
    """Read one private JSON object against a separately reviewed byte digest."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(
        "[a-f0-9]{64}", expected_sha256
    ):
        raise ValueError("Supply the independently approved input SHA256")
    path = Path(path)
    parent = _directory(path.parent)
    try:
        raw = _read(parent, path.name, limit)
    finally:
        os.close(parent)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Private input does not match the approved SHA256")
    document = _json(raw)
    if not isinstance(document, dict):
        raise ValueError("Private input must be a JSON object")
    return raw, document


def write_private_output(path, raw):
    """Publish a complete new private file, never replace or follow a destination."""
    path = Path(path)
    parent = _directory(path.parent)
    temporary = ".ruview-site-inputs-" + secrets.token_hex(16) + ".tmp"
    created = False
    try:
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent
        )
        created = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # The hard link is exclusive and atomic; a failed write cannot expose a
        # partial result as an apparently valid output.
        os.link(
            temporary,
            path.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
    finally:
        if created:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)
