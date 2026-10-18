"""Fictional independently approved installation inputs for offline tests."""

import hashlib
import json

from test_site_context import ContextFixture

from scripts.installation_identity import load_installation_context


class InstallationFixture(ContextFixture):
    def setUp(self):
        super().setUp()
        rows = [
            {
                "name": f"ruview-{node:02d}",
                "ip": f"10.77.0.{119 + node}",
                "mac": f"02:00:00:00:00:{node:02x}" if node <= 3 else None,
                "firmware_node_id": node if node <= 3 else None,
                "identity_verified": node <= 3,
            }
            for node in range(1, 11)
        ]
        receivers = [
            {
                "node_id": node,
                "ip": rows[node - 1]["ip"],
                "station_mac": rows[node - 1]["mac"],
            }
            for node in (1, 2, 3)
        ]
        self.documents["nodes.json"] = {"nodes": rows}
        self.documents["assumed-activity-receivers.json"] = {"receivers": receivers}
        self.documents["assumed-activity.json"] = {
            "coordinate_frame": "fictional_lab_xz_metres"
        }
        for name, value in self.documents.items():
            self.write(name, json.dumps(value).encode())
        self.pin = self.manifest()
        self.identity = {
            "schema": "ruview.installation-identity.v2",
            "fleet_ipv4_network": "10.77.0.0/24",
            "fleet_first_host": 120,
            "receivers": receivers,
            "restore_node": "example-worker",
            "bridge_repository": "registry.example.invalid/bridge",
            "coordinate_frame": "fictional_lab_xz_metres",
            "policy": {
                "fleet_size": 10,
                "receiver_ids": [1, 2, 3],
                "receiver_versions": {
                    str(node): (
                        ["0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8"]
                        if node == 2
                        else []
                    )
                    + ["0.8.8.10", "0.8.8.11", "0.8.8.12"]
                    for node in (1, 2, 3)
                },
                "restore_image_sha256": "a" * 64,
                "wasm_public_key_hex": "b" * 64,
            },
        }
        self.identity_path = self.parent / "identity.json"
        self.identity_pin = self.write_identity(self.identity)

    def write_identity(self, identity):
        raw = json.dumps(identity, sort_keys=True).encode()
        self.identity_path.write_bytes(raw)
        self.identity_path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def installed(self):
        return load_installation_context(
            self.context, self.pin, self.identity_path, self.identity_pin
        )

    def identity_args(self):
        return [
            "--installation-identity",
            str(self.identity_path),
            "--installation-identity-sha256",
            self.identity_pin,
        ]
