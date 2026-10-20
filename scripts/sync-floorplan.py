#!/usr/bin/env python3
"""Merge RuView receiver markers using HA's authenticated, revision-checked API."""

import argparse
import asyncio
import json
import os
from pathlib import Path

from websockets.asyncio.client import connect

if __package__:
    from .site_context import load_site_context
    from .transport_security import websocket_options
else:
    from site_context import load_site_context
    from transport_security import websocket_options


async def run(args):
    context = load_site_context(args.site_context, args.site_context_sha256)
    source = context.documents["placements.json"]
    # Check ownership and shape before opening a connection or reading a token.
    if (
        not isinstance(source.get("floor"), str)
        or not source["floor"]
        or not isinstance(source.get("items"), list)
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not item["id"].startswith("ruview_")
            for item in source["items"]
        )
        or len({item["id"] for item in source["items"]}) != len(source["items"])
    ):
        raise ValueError("Expected a floor and unique owned RuView markers")
    server = os.environ["HASS_SERVER"].rstrip("/")
    url = server.replace("https://", "wss://").replace("http://", "ws://")
    async with connect(
        url + "/api/websocket",
        max_size=100_000_000,
        proxy=None,
        **websocket_options(url),
    ) as ws:
        await ws.recv()
        await ws.send(
            json.dumps({"type": "auth", "access_token": os.environ["HA_TOKEN"]})
        )
        if json.loads(await ws.recv())["type"] != "auth_ok":
            raise SystemExit("Home Assistant authentication failed")
        await ws.send(
            json.dumps(
                {"id": 1, "type": "home_floorplan/viewer", "floor": source["floor"]}
            )
        )
        result = json.loads(await ws.recv())
        if not result.get("success"):
            raise SystemExit("Cannot read the floorplan; administrator access required")
        current = result["result"]
        by_id = {item["id"]: item for item in current["items"]}
        changes = []
        for item in source["items"]:
            if not item["id"].startswith("ruview_"):
                raise SystemExit("Only ruview_ marker IDs may be managed")
            previous = by_id.get(item["id"])
            if previous == item:
                continue
            if previous and not args.update_owned:
                raise SystemExit(
                    "Existing marker differs; review it and use --update-owned"
                )
            changes.append(item["id"])
            by_id[item["id"]] = item
        print(
            json.dumps(
                {
                    "floor": source["floor"],
                    "revision": current["revision"],
                    "changed": changes,
                }
            )
        )
        if not args.apply or not changes:
            return
        backup = Path(args.backup_dir)
        backup.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = (
            backup / f"floorplan-{source['floor']}-revision-{current['revision']}.json"
        )
        with path.open("x") as handle:
            path.chmod(0o600)
            json.dump(
                {"revision": current["revision"], "items": current["items"]}, handle
            )
        await ws.send(
            json.dumps(
                {
                    "id": 2,
                    "type": "home_floorplan/save",
                    "floor": source["floor"],
                    "revision": current["revision"],
                    "items": list(by_id.values()),
                }
            )
        )
        saved = json.loads(await ws.recv())
        if not saved.get("success"):
            raise SystemExit(
                "Save rejected (possibly a concurrent edit); backup preserved"
            )
        print("Saved revision", saved["result"]["revision"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-context", required=True, type=Path)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--backup-dir", default="private/floorplan-backups")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--update-owned", action="store_true")
    asyncio.run(run(parser.parse_args(argv)))


if __name__ == "__main__":
    main()
