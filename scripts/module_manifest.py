"""Read a whole private module authorization against an independent approval."""

from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .site_context import load_pinned_json
else:
    from site_context import load_pinned_json

MAX_MODULE_MANIFEST_BYTES = 64 * 1024


@dataclass(frozen=True)
class ModuleManifest:
    raw: bytes
    document: dict
    sha256: str


def load_module_manifest(path, expected_sha256):
    raw, document = load_pinned_json(path, expected_sha256, MAX_MODULE_MANIFEST_BYTES)
    if (
        type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or not isinstance(document.get("packages"), list)
        or not 1 <= len(document["packages"]) <= 3
        or not all(isinstance(p, dict) for p in document["packages"])
    ):
        raise ValueError("Invalid approved module manifest")
    return ModuleManifest(raw, document, expected_sha256)


def add_module_manifest_arguments(parser):
    parser.add_argument("--module-manifest", type=Path, required=True)
    parser.add_argument("--module-manifest-sha256", required=True)
