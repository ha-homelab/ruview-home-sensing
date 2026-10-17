"""Authenticate identities and policy from an independently approved document."""

import ipaddress
import re
from dataclasses import dataclass

if __package__:
    from .site_context import SiteContext, load_pinned_json, load_site_context
else:
    from site_context import SiteContext, load_pinned_json, load_site_context

SCHEMA = "ruview.installation-identity.v2"


@dataclass(frozen=True)
class InstallationContext(SiteContext):
    identity_raw: bytes
    identity: dict
    identity_sha256: str


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_policy(policy):
    """Authorize explicit policy only; candidate inventory never supplies defaults."""
    require(
        isinstance(policy, dict)
        and set(policy)
        == {
            "fleet_size",
            "receiver_ids",
            "receiver_versions",
            "restore_image_sha256",
            "wasm_public_key_hex",
        },
        "An explicit independently approved installation policy is required",
    )
    size, ids = policy["fleet_size"], policy["receiver_ids"]
    require(type(size) is int and 1 <= size <= 99, "Invalid bounded fleet size")
    require(
        isinstance(ids, list)
        and 1 <= len(ids) <= 10
        and all(type(node) is int and 1 <= node <= size for node in ids)
        and ids == sorted(set(ids)),
        "Invalid approved receiver IDs",
    )
    versions = policy["receiver_versions"]
    require(
        isinstance(versions, dict)
        and set(versions) == {str(node) for node in ids}
        and all(
            isinstance(rows, list)
            and 1 <= len(rows) <= 32
            and all(
                isinstance(version, str)
                and re.fullmatch(
                    r"[0-9]+(?:\.[0-9]+){2,3}(?:[-+][A-Za-z0-9.-]+)?", version
                )
                and len(version) <= 64
                for version in rows
            )
            and len(rows) == len(set(rows))
            for rows in versions.values()
        ),
        "Every approved receiver needs an exact firmware version allowlist",
    )
    for key in ("restore_image_sha256", "wasm_public_key_hex"):
        require(
            isinstance(policy[key], str) and re.fullmatch("[a-f0-9]{64}", policy[key]),
            "Invalid approved artifact digest or verification key",
        )
    return policy


def validate_identity(value, context):
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "fleet_ipv4_network",
            "fleet_first_host",
            "receivers",
            "restore_node",
            "bridge_repository",
            "coordinate_frame",
            "policy",
        }
        and value["schema"] == SCHEMA,
        "Invalid installation identity fields",
    )
    policy = validate_policy(value["policy"])
    size = policy["fleet_size"]
    receiver_ids = policy["receiver_ids"]
    require(isinstance(value["fleet_ipv4_network"], str), "Invalid fleet network")
    network = ipaddress.IPv4Network(value["fleet_ipv4_network"], strict=True)
    require(
        network.prefixlen == 24
        and str(network) == value["fleet_ipv4_network"]
        and any(
            network.subnet_of(ipaddress.IPv4Network(cidr))
            for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ),
        "Fleet allocation must be one canonical private /24",
    )
    first = value["fleet_first_host"]
    require(type(first) is int and 1 <= first <= 255 - size, "Invalid fleet first host")
    nodes = context.documents["nodes.json"]["nodes"]
    require(isinstance(nodes, list), "Expected fleet inventory array")
    by_id = {}
    for node_id in range(1, size + 1):
        matches = [n for n in nodes if n.get("name") == f"ruview-{node_id:02d}"]
        require(len(matches) == 1, "Expected exactly one reservation per fleet ID")
        node = matches[0]
        require(
            node["ip"] == str(network.network_address + first + node_id - 1),
            "Pinned inventory differs from approved fleet allocation",
        )
        by_id[node_id] = node
    require(len(nodes) == size, "Inventory differs from approved bounded fleet size")
    receivers = value["receivers"]
    require(
        isinstance(receivers, list) and len(receivers) == len(receiver_ids),
        "Receiver count differs from approved policy",
    )
    identities = {}
    for row in receivers:
        require(
            isinstance(row, dict)
            and set(row) == {"node_id", "ip", "station_mac"}
            and type(row["node_id"]) is int
            and row["node_id"] in receiver_ids
            and row["node_id"] not in identities
            and isinstance(row["station_mac"], str)
            and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", row["station_mac"]),
            "Invalid approved receiver identity",
        )
        node = by_id[row["node_id"]]
        require(
            node["ip"] == row["ip"]
            and node["mac"] == row["station_mac"]
            and node.get("firmware_node_id") == row["node_id"]
            and node.get("identity_verified") is True,
            "Pinned inventory differs from approved receiver identity",
        )
        identities[row["node_id"]] = row
    require(
        len({row["station_mac"] for row in receivers}) == len(receiver_ids),
        "Duplicate receiver MAC",
    )
    approved = context.documents["assumed-activity-receivers.json"]["receivers"]
    require(
        isinstance(approved, list)
        and len(approved) == len(receiver_ids)
        and all(
            isinstance(row, dict)
            and set(row) == {"node_id", "ip", "station_mac"}
            and type(row["node_id"]) is int
            for row in approved
        )
        and sorted(approved, key=lambda row: row["node_id"])
        == sorted(receivers, key=lambda row: row["node_id"]),
        "Activity receiver identities differ from independent installation approval",
    )
    frame = value["coordinate_frame"]
    require(
        isinstance(frame, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}_xz_metres", frame)
        and frame == context.documents["assumed-activity.json"]["coordinate_frame"],
        "Activity frame differs from independent installation approval",
    )
    host = value["restore_node"]
    require(
        isinstance(host, str)
        and len(host) <= 253
        and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in host.split(".")
        ),
        "Invalid restore node name",
    )
    repository = value["bridge_repository"]
    require(
        isinstance(repository, str) and len(repository) <= 512,
        "Invalid bridge repository",
    )
    parts = repository.split("/")
    require(
        len(parts) >= 2
        and re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?", parts[0])
        and all(
            re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", part) for part in parts[1:]
        )
        and (":" not in parts[0] or int(parts[0].rsplit(":", 1)[1]) <= 65535),
        "Invalid bridge repository",
    )
    return value


def load_installation_context(
    directory, context_sha256, identity_path, identity_sha256
):
    # Both independent roots must authenticate before their values are used.
    raw, value = load_pinned_json(identity_path, identity_sha256, 65536)
    context = load_site_context(directory, context_sha256)
    validate_identity(value, context)
    return InstallationContext(
        context.manifest_sha256,
        context.manifest_raw,
        context.raw,
        context.documents,
        raw,
        value,
        identity_sha256,
    )


def restore_image(identity):
    return (
        identity["bridge_repository"]
        + "@sha256:"
        + validate_policy(identity["policy"])["restore_image_sha256"]
    )
