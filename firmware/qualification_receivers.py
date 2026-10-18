"""Explicit station bindings from an independently approved installation context."""

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.installation_identity import (  # noqa: E402
    InstallationContext,
    load_installation_context,
)


@dataclass(frozen=True)
class QualificationReceiver:
    node_id: int
    ip: str
    station_mac: str
    allowed_versions: tuple[str, ...] = ()

    @property
    def base_url(self):
        return f"http://{self.ip}:8032"

    def metadata(self):
        return {
            "node_id": self.node_id,
            "ip": self.ip,
            "station_mac": self.station_mac,
        }


def get_receiver(node_id, context):
    if type(node_id) is not int:
        raise ValueError("unknown_qualification_receiver")
    if not isinstance(context, InstallationContext):
        raise ValueError("approved_installation_context_required")
    rows = [
        item for item in context.identity["receivers"] if item["node_id"] == node_id
    ]
    if len(rows) != 1:
        raise ValueError("unknown_qualification_receiver")
    allowed = context.identity["policy"]["receiver_versions"].get(str(node_id), [])
    return QualificationReceiver(**rows[0], allowed_versions=tuple(allowed))


def add_context_arguments(parser):
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", type=Path, required=True)
    parser.add_argument("--installation-identity-sha256", required=True)


def load_receiver(args):
    context = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    return get_receiver(args.node, context)


def supports_version(receiver, version):
    """Only the independently approved installation policy authorizes a version."""
    return (
        isinstance(receiver, QualificationReceiver)
        and version in receiver.allowed_versions
    )
