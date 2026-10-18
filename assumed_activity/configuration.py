"""Bounded mounted-file reads authenticated by separate deployment inputs."""

import hashlib
import os
import re
import stat

from .core import require


def pinned_bytes(path, expected_sha256, limit):
    require(
        isinstance(expected_sha256, str)
        and re.fullmatch("[a-f0-9]{64}", expected_sha256) is not None,
        "configuration_approval_required",
    )
    # Kubernetes projects ConfigMap keys through symlinks. Authenticate bytes
    # after opening the projection, and never accept pipes/devices or an
    # oversized file. The expected hash is not read from this mounted directory.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_size <= limit,
            "invalid_configuration_file",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        require(
            len(raw) <= limit
            and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "configuration_changed_or_oversized",
        )
        require(
            hashlib.sha256(raw).hexdigest() == expected_sha256,
            "configuration_approval_mismatch",
        )
        return raw
    finally:
        os.close(fd)
