"""Immutable, explicitly selected signed packages for explicit receiver qualification."""

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True)
class QualificationPackage:
    profile: str
    name: str
    path: Path
    package_sha256: str | None
    wasm_sha256: str | None
    package_bytes: int | None
    wasm_bytes: int | None

    @property
    def enabled(self):
        return all(
            value is not None
            for value in (
                self.package_sha256,
                self.wasm_sha256,
                self.package_bytes,
                self.wasm_bytes,
            )
        )


# An inert default preserves import compatibility, never deployment authority.
UNCONFIGURED = QualificationPackage(
    "unconfigured", "unconfigured", Path("/unconfigured"), None, None, None, None
)
HOME_SIGNAL = UNCONFIGURED
PACKAGES = MappingProxyType({})


def _read_approved(path, expected_sha256):
    import hashlib
    import os
    import re
    import stat

    if not isinstance(expected_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_sha256
    ):
        raise ValueError("independent_package_catalog_approval_required")
    path = Path(path)
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("package_catalog_symlink_refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or not 0 < info.st_size <= 65536
        ):
            raise ValueError("private_bounded_package_catalog_required")
        raw = stream.read(65537)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("package_catalog_approval_mismatch")
    return raw


def load_packages(path, expected_sha256, directory):
    """Read an independently approved catalog; packages cannot approve themselves.

    The catalog authorizes only qualification inputs, never automatic restore.
    Package bytes remain independently verified by upload/observation checks.
    """
    import json
    import re

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_package_catalog_key")
            result[key] = value
        return result

    document = json.loads(
        _read_approved(path, expected_sha256), object_pairs_hook=unique
    )
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "packages"}
        or document["schema"] != "ruview.qualification-packages.v1"
        or not isinstance(document["packages"], list)
        or not 1 <= len(document["packages"]) <= 64
    ):
        raise ValueError("invalid_package_catalog")
    directory = Path(directory).resolve(strict=True)
    result = {}
    for row in document["packages"]:
        if not isinstance(row, dict) or set(row) != {
            "profile",
            "name",
            "file",
            "package_sha256",
            "wasm_sha256",
            "package_bytes",
            "wasm_bytes",
        }:
            raise ValueError("invalid_package_catalog_entry")
        for key in ("profile", "name"):
            if not isinstance(row[key], str) or not re.fullmatch(
                r"[A-Za-z0-9_-]{1,31}", row[key]
            ):
                raise ValueError("invalid_package_name")
        if row["profile"] in result:
            raise ValueError("duplicate_package_profile")
        filename = row["file"]
        if not isinstance(filename, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}\.rvf", filename
        ):
            raise ValueError("invalid_package_filename")
        target = directory / filename
        if target.is_symlink() or target.resolve().parent != directory:
            raise ValueError("package_path_escape")
        for key in ("package_sha256", "wasm_sha256"):
            if not isinstance(row[key], str) or not re.fullmatch(
                r"[0-9a-f]{64}", row[key]
            ):
                raise ValueError("invalid_package_digest")
        if (
            type(row["wasm_bytes"]) is not int
            or not 8 <= row["wasm_bytes"] <= 131072
            or type(row["package_bytes"]) is not int
            or row["package_bytes"] != row["wasm_bytes"] + 192
        ):
            raise ValueError("invalid_package_length")
        result[row["profile"]] = QualificationPackage(
            path=target, **{key: value for key, value in row.items() if key != "file"}
        )
    return MappingProxyType(result)


def get_package(profile, packages=PACKAGES):
    """Resolve an explicitly approved profile; the default catalog is empty."""
    if profile not in packages:
        raise ValueError("unknown_package_profile")
    package = packages[profile]
    if not package.enabled:
        raise ValueError("package_profile_unavailable")
    return package


def add_package_arguments(parser):
    parser.add_argument("--package-catalog", type=Path, required=True)
    parser.add_argument("--package-catalog-sha256", required=True)
    parser.add_argument("--package-directory", type=Path, required=True)
    parser.add_argument("--package-profile", required=True)


def load_package(args):
    return get_package(
        args.package_profile,
        load_packages(
            args.package_catalog, args.package_catalog_sha256, args.package_directory
        ),
    )
