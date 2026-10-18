"""Independent installation approvals and real provider-free HCL validation."""

import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from installation_fixture import InstallationFixture

from scripts import installation_identity as identity

ROOT = Path(__file__).resolve().parents[1]


class IdentityTests(InstallationFixture):
    def test_approved_inputs_preserve_all_raw_site_bytes_and_fixed_image_digest(self):
        approved = self.installed()
        self.assertEqual(approved.raw, self.load().raw)
        self.assertEqual(approved.manifest_raw, self.load().manifest_raw)
        self.assertEqual(approved.identity_raw, self.identity_path.read_bytes())
        self.assertEqual(approved.identity_sha256, self.identity_pin)
        self.assertEqual(approved.identity, self.identity)
        self.assertEqual(
            identity.restore_image(approved.identity),
            self.identity["bridge_repository"] + "@sha256:" + "a" * 64,
        )

    def test_identity_pin_must_be_independent_before_reading_site_data(self):
        for pin in (None, "", "x" * 64, "0" * 64):
            with (
                self.subTest(pin=pin),
                patch.object(identity, "load_site_context") as site,
            ):
                with self.assertRaises(ValueError):
                    identity.load_installation_context(
                        self.context, self.pin, self.identity_path, pin
                    )
                site.assert_not_called()
        self.identity_path.write_text("{}")
        with self.assertRaises(ValueError):
            self.installed()

    def invalid_identities(self):
        for field, value in (
            ("schema", "unknown"),
            ("fleet_first_host", True),
            ("fleet_first_host", "120"),
            ("fleet_first_host", 246),
            ("fleet_ipv4_network", "10.77.0.0/23"),
            ("fleet_ipv4_network", "10.77.0.1/24"),
            ("fleet_ipv4_network", "192.0.2.0/24"),
            ("coordinate_frame", "other_xz_metres"),
            ("restore_node", "node\ncommand"),
            ("bridge_repository", "user:password@registry/repo"),
            ("bridge_repository", "registry/repo:latest"),
            ("bridge_repository", "registry:65536/repo"),
            ("receivers", None),
            ("receivers", {}),
            ("receivers", [None, {}, {}]),
        ):
            yield self.identity | {field: value}
        yield self.identity | {"allow_unverified": True}
        for field, value in (
            ("node_id", 4),
            ("ip", "10.77.0.200"),
            ("station_mac", "02:00:00:00:00:09"),
        ):
            candidate = copy.deepcopy(self.identity)
            candidate["receivers"][0][field] = value
            yield candidate
        candidate = copy.deepcopy(self.identity)
        candidate["receivers"] = [candidate["receivers"][0]] * 3
        yield candidate

    def test_newly_approved_identity_cannot_relax_shape_or_conflict_with_site(self):
        for candidate in self.invalid_identities():
            with self.subTest(candidate=candidate):
                pin = self.write_identity(candidate)
                with self.assertRaises((ValueError, TypeError)):
                    identity.load_installation_context(
                        self.context, self.pin, self.identity_path, pin
                    )

    def test_newly_approved_site_cannot_replace_independent_installation_identity(self):
        nodes = copy.deepcopy(self.documents["nodes.json"])
        nodes["nodes"][0]["ip"] = "10.77.0.200"
        self.write("nodes.json", json.dumps(nodes).encode())
        self.pin = self.manifest()
        with self.assertRaisesRegex(ValueError, "allocation"):
            self.installed()

    def test_activity_receiver_duplicates_and_malformed_rows_are_rejected(self):
        for rows in (
            [self.identity["receivers"][0]] * 3,
            {str(row["node_id"]): row for row in self.identity["receivers"]},
            [None, {}, {}],
        ):
            with self.subTest(rows=rows):
                self.write(
                    "assumed-activity-receivers.json",
                    json.dumps({"receivers": rows}).encode(),
                )
                self.pin = self.manifest()
                with self.assertRaises(ValueError):
                    self.installed()

    def test_identity_loader_retains_private_bounded_nofollow_guards(self):
        link = self.parent / "identity-link.json"
        link.symlink_to(self.identity_path)
        with self.assertRaises(OSError):
            identity.load_installation_context(
                self.context, self.pin, link, self.identity_pin
            )
        self.identity_path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.installed()
        self.identity_path.chmod(0o600)
        raw = b" " * 65537
        self.identity_path.write_bytes(raw)
        with self.assertRaises(ValueError):
            identity.load_installation_context(
                self.context,
                self.pin,
                self.identity_path,
                hashlib.sha256(raw).hexdigest(),
            )

    def test_policy_cannot_be_inferred_from_a_candidate_inventory(self):
        candidate = copy.deepcopy(self.identity)
        del candidate["policy"]
        self.identity_pin = self.write_identity(candidate)
        with self.assertRaises(ValueError):
            self.installed()

    def test_policy_rejects_unbounded_or_ambiguous_authorization(self):
        for field, value in (
            ("fleet_size", True),
            ("fleet_size", 100),
            ("receiver_ids", [1, 1]),
            ("receiver_ids", [11]),
            ("receiver_versions", {"1": ["*"]}),
            ("restore_image_sha256", "latest"),
            ("wasm_public_key_hex", ""),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.identity)
                candidate["policy"][field] = value
                self.identity_pin = self.write_identity(candidate)
                with self.assertRaises(ValueError):
                    self.installed()

    def test_different_fleet_requires_its_own_independent_policy_approval(self):
        candidate = copy.deepcopy(self.identity)
        candidate["policy"]["fleet_size"] = 4
        nodes = self.documents["nodes.json"]["nodes"][:4]
        self.write("nodes.json", json.dumps({"nodes": nodes}).encode())
        self.pin = self.manifest()
        with self.assertRaises(ValueError):
            self.installed()
        self.identity_pin = self.write_identity(candidate)
        self.assertEqual(self.installed().identity["policy"]["fleet_size"], 4)
