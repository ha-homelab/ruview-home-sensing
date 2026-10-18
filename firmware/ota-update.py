#!/usr/bin/env python3
"""Update an inventoried receiver over private-LAN HTTP with a private OTA key."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.installation_identity import load_installation_context  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--expect-current", required=True)
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument("--installation-identity", required=True, type=Path)
    parser.add_argument("--installation-identity-sha256", required=True)
    args = parser.parse_args()
    context = load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    nodes = context.documents["nodes.json"]["nodes"]
    node = next(n for n in nodes if n.get("firmware_node_id") == args.node)
    if (
        not node.get("identity_verified")
        or not node.get("firmware_observed", {}).get("chip_and_flash_verified")
        or node.get("hardware", {}).get("chip") != "ESP32-S3"
    ):
        raise ValueError(
            "Receiver identity, chip, flash and layout must be verified first"
        )
    if args.key_file.stat().st_mode & 0o077:
        raise ValueError("OTA key file must be private (0600)")
    key = args.key_file.read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise ValueError("Expected a provisioned 256-bit hex key")
    data = args.firmware.read_bytes()
    if hashlib.sha256(data).hexdigest() != args.sha256:
        raise ValueError("Firmware SHA-256 mismatch")
    info = subprocess.check_output(
        [sys.executable, "-m", "esptool", "image-info", str(args.firmware)],
        text=True,
    )
    if (
        "Detected image type: ESP32-S3" not in info
        or f"App version: {args.version}\n" not in info
        or "(invalid)" in info
        or info.count("(valid)") < 2
    ):
        raise ValueError("Image target, version or integrity check failed")
    base = f"http://{node['ip']}:8032"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def status():
        with opener.open(base + "/ota/status", timeout=5) as response:
            return json.load(response)

    before = status()
    if before.get("version") != args.expect_current:
        raise ValueError("Unexpected current firmware version")
    target = before.get("next_partition")
    if (
        target not in {"ota_0", "ota_1"}
        or target == before.get("running_partition")
        or not 0 < len(data) <= before.get("max_size", 0)
    ):
        raise ValueError("Invalid inactive OTA slot or image size")
    load_installation_context(
        args.site_context,
        args.site_context_sha256,
        args.installation_identity,
        args.installation_identity_sha256,
    )
    request = urllib.request.Request(
        base + "/ota",
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "Authorization": "Bearer " + key,
        },
    )
    print(
        f"Uploading verified image to node {args.node} inactive slot {target}",
        flush=True,
    )
    uncertain = False
    try:
        with opener.open(request, timeout=120) as response:
            reply = json.load(response)
        if reply.get("status") != "ok":
            raise ValueError("Receiver did not confirm OTA write")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"OTA rejected: HTTP {error.code}") from None
    except (OSError, ValueError):
        # A lost response may follow a successful flash. Observe; never blindly retry.
        uncertain = True
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            after = status()
        except (OSError, ValueError):
            continue
        if (
            after.get("version") == args.version
            and after.get("running_partition") == target
        ):
            load_installation_context(
                args.site_context,
                args.site_context_sha256,
                args.installation_identity,
                args.installation_identity_sha256,
            )
            print(
                json.dumps(
                    {
                        "node_id": args.node,
                        "version": args.version,
                        "running_partition": target,
                        "application_sha256": args.sha256,
                        "upload_response_lost": uncertain,
                        "result": "boot_confirmed_not_sensing_qualification",
                    }
                ),
                flush=True,
            )
            return
    raise RuntimeError("OTA boot not confirmed; inspect receiver before retrying")


if __name__ == "__main__":
    main()
