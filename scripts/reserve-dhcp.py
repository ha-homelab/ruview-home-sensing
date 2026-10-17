#!/usr/bin/env python3
"""Reserve verified RuView station MACs; default is a read-only plan."""

import argparse
import hashlib
import ipaddress
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .installation_identity import (
        InstallationContext,
        load_installation_context,
        validate_identity,
    )
    from .site_context import load_pinned_json
else:
    from installation_identity import (
        InstallationContext,
        load_installation_context,
        validate_identity,
    )
    from site_context import load_pinned_json


def ssh(command, input_text=None, *, target):
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", target, command],
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    ).stdout


def hosts(export):
    records = []
    current = None
    for line in export.splitlines():
        parts = shlex.split(line)
        if not parts:
            continue
        if parts[0] == "config":
            current = (
                {"section": parts[2] if len(parts) > 2 else None}
                if parts[1] == "host"
                else None
            )
            if current is not None:
                records.append(current)
        elif current is not None and parts[0] in ("option", "list") and len(parts) == 3:
            current.setdefault(parts[1], []).extend(parts[2].lower().split())
    return records


def load_router(path, expected_sha256):
    _, value = load_pinned_json(path, expected_sha256, 4096)
    if (
        set(value) != {"schema", "ssh_target"}
        or value["schema"] != "ruview.dhcp-router.v1"
        or not isinstance(value["ssh_target"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", value["ssh_target"])
    ):
        raise ValueError("Invalid approved DHCP router")
    return value["ssh_target"]


def plan(context, existing):
    if not isinstance(context, InstallationContext):
        raise ValueError("An approved installation context is required")
    validate_identity(context.identity, context)
    inventory = context.documents["nodes.json"]
    first = (
        ipaddress.IPv4Network(context.identity["fleet_ipv4_network"]).network_address
        + context.identity["fleet_first_host"]
    )
    last = first + context.identity["policy"]["fleet_size"] - 1
    commands = []
    existing = list(existing)
    for node in inventory["nodes"]:
        if not node.get("identity_verified") or not node.get("mac"):
            continue
        name, mac, address = node["name"], node["mac"].lower(), node["ip"]
        if not re.fullmatch(r"ruview-\d{2}", name) or not re.fullmatch(
            r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac
        ):
            raise ValueError("Invalid device identity")
        if not first <= ipaddress.IPv4Address(address) <= last:
            raise ValueError("Address outside the independently approved fleet range")
        section = name.replace("-", "_")
        desired = {"section": section, "name": [name], "mac": [mac], "ip": [address]}
        owned = next((item for item in existing if item["section"] == section), None)
        for item in existing:
            collision = (
                mac in item.get("mac", [])
                or address in item.get("ip", [])
                or name in item.get("name", [])
            )
            if collision and item != desired:
                raise ValueError(f"MAC/IP/name collision for {name}")
        if owned:
            if owned != desired:
                raise ValueError(
                    f"Existing {section} is different; review before changing"
                )
            continue
        commands.extend(
            [
                f"set dhcp.{section}=host",
                f"set dhcp.{section}.name='{name}'",
                f"set dhcp.{section}.mac='{mac}'",
                f"set dhcp.{section}.ip='{address}'",
            ]
        )
        existing.append(desired)
    return commands


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-context", required=True, type=Path)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", required=True, type=Path)
    parser.add_argument("--installation-identity-sha256", required=True)
    parser.add_argument("--router-profile", required=True, type=Path)
    parser.add_argument("--router-profile-sha256", required=True)
    parser.add_argument("--backup-dir", default="private/dhcp-backups")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    def load_context():
        return load_installation_context(
            args.site_context,
            args.site_context_sha256,
            args.installation_identity,
            args.installation_identity_sha256,
        )

    context = load_context()
    router = load_router(args.router_profile, args.router_profile_sha256)

    def revalidate():
        if (
            load_context() != context
            or load_router(args.router_profile, args.router_profile_sha256) != router
        ):
            raise ValueError("Approved DHCP inputs changed")

    def invoke(command, input_text=None):
        revalidate()
        return ssh(command, input_text, target=router)

    # Validate the selected snapshot before reading router state or credentials.
    plan(context, [])
    if invoke("uci changes dhcp").strip():
        raise SystemExit(
            "Uncommitted router DHCP changes exist; refusing to overwrite them"
        )
    original = invoke("cat /etc/config/dhcp")
    exported = invoke("uci export dhcp")
    commands = plan(context, hosts(exported))
    print("\n".join(commands) or "No DHCP changes")
    if not args.apply or not commands:
        return
    revalidate()
    backup = Path(args.backup_dir)
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = backup / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".dhcp")
    with path.open("x") as handle:
        path.chmod(0o600)
        handle.write(original)
    digest = hashlib.sha256(original.encode()).hexdigest()
    script = "\n".join(
        [
            "set -eu",
            'test -z "$(uci changes dhcp)"',
            f"test \"$(sha256sum /etc/config/dhcp | cut -d' ' -f1)\" = '{digest}'",
            "uci batch <<'RUVIEW_UCI'",
            *commands,
            "RUVIEW_UCI",
            "uci commit dhcp",
            "/etc/init.d/dnsmasq reload",
            "/etc/init.d/dnsmasq status",
        ]
    )
    print(invoke("sh -s", script))
    # Verify exact additive result, retaining all pre-existing records.
    after = hosts(invoke("uci export dhcp"))
    assert all(item in after for item in hosts(exported)), (
        "An unrelated reservation changed"
    )
    assert not plan(context, after), "Reservation readback differs"
    print(
        "Reservations verified; devices must renew their leases to adopt new addresses."
    )


if __name__ == "__main__":
    main()
