"""Offline additive DHCP planning against independently approved inputs."""

import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from qualification_fixture import context_arguments

from scripts.installation_identity import load_installation_context

SPEC = importlib.util.spec_from_file_location(
    "scripts.dhcp", Path(__file__).parents[1] / "scripts/reserve-dhcp.py"
)
dhcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dhcp)


def dhcp_arguments(directory):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = context_arguments(directory)
    router = directory / "router.json"
    router.write_text(
        json.dumps({"schema": "ruview.dhcp-router.v1", "ssh_target": "test-router"})
    )
    router.chmod(0o600)
    return [
        *flags,
        "--router-profile",
        str(router),
        "--router-profile-sha256",
        hashlib.sha256(router.read_bytes()).hexdigest(),
    ]


def record(node):
    return {
        "section": node["name"].replace("-", "_"),
        "name": [node["name"]],
        "mac": [node["mac"]],
        "ip": [node["ip"]],
    }


def export(records):
    return (
        "\n".join(
            "config host '"
            + r["section"]
            + "'\n"
            + "\n".join(
                f" option {key} '{value[0]}'"
                for key, value in r.items()
                if key != "section"
            )
            for r in records
        )
        + "\n"
    )


class ReservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.flags = dhcp_arguments(self.root)
        self.context = load_installation_context(*self.flags[1:8:2])
        self.nodes = self.context.documents["nodes.json"]["nodes"]
        self.node = self.nodes[1]
        self.verified = [
            n for n in self.nodes if n.get("identity_verified") and n.get("mac")
        ]
        self.backup = self.root / "backups"

    def test_unverified_identity_has_no_mutation(self):
        self.nodes[3]["identity_verified"] = False
        commands = dhcp.plan(self.context, [])
        self.assertFalse(any("ruview_04" in command for command in commands))

    def test_unrelated_ip_conflict_is_rejected(self):
        with self.assertRaises(ValueError):
            dhcp.plan(self.context, [{"section": None, "ip": [self.node["ip"]]}])

    def test_old_mac_reservation_is_not_overwritten(self):
        with self.assertRaises(ValueError):
            dhcp.plan(
                self.context,
                [{"section": None, "mac": [self.node["mac"]], "ip": ["10.77.1.99"]}],
            )

    def test_two_devices_cannot_share_new_address(self):
        self.nodes[2]["ip"] = self.node["ip"]
        with self.assertRaises(ValueError):
            dhcp.plan(self.context, [])

    def test_existing_exact_reservations_are_noop(self):
        existing = dhcp.hosts(export([record(n) for n in self.verified]))
        self.assertEqual(dhcp.plan(self.context, existing), [])

    def test_plan_requires_approved_context_and_exact_ten_addresses(self):
        with self.assertRaises(ValueError):
            dhcp.plan({"nodes": self.nodes}, [])
        self.nodes[-1]["ip"] = "10.77.1.200"
        with self.assertRaises(ValueError):
            dhcp.plan(self.context, [])

    def test_all_six_flags_required_before_router_or_backup_access(self):
        for missing in range(0, len(self.flags), 2):
            with (
                self.subTest(missing=self.flags[missing]),
                patch("sys.stderr"),
                patch.object(dhcp, "ssh") as ssh,
                self.assertRaises(SystemExit),
            ):
                dhcp.main(
                    self.flags[:missing]
                    + self.flags[missing + 2 :]
                    + ["--apply", "--backup-dir", str(self.backup)]
                )
            ssh.assert_not_called()
            self.assertFalse(self.backup.exists())

    def test_independent_bad_pins_rejected_before_router(self):
        for flag in (
            "--site-context-sha256",
            "--installation-identity-sha256",
            "--router-profile-sha256",
        ):
            args = self.flags.copy()
            args[args.index(flag) + 1] = "0" * 64
            with (
                self.subTest(flag=flag),
                patch.object(dhcp, "ssh") as ssh,
                self.assertRaises(ValueError),
            ):
                dhcp.main(args)
            ssh.assert_not_called()

    def test_router_target_rejects_option_user_shell_path_and_extra_fields(self):
        path = Path(self.flags[-3])
        for value in (
            "-oProxyCommand=x",
            "user@host",
            "host;cmd",
            "host name",
            "/router",
            "host\n",
            "",
            "x" * 254,
        ):
            path.write_text(
                json.dumps({"schema": "ruview.dhcp-router.v1", "ssh_target": value})
            )
            with self.subTest(value=value), self.assertRaises(ValueError):
                dhcp.load_router(path, hashlib.sha256(path.read_bytes()).hexdigest())
        path.write_text(
            json.dumps(
                {
                    "schema": "ruview.dhcp-router.v1",
                    "ssh_target": "router",
                    "extra": True,
                }
            )
        )
        with self.assertRaises(ValueError):
            dhcp.load_router(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_ssh_target_is_single_argv_element_without_shell(self):
        result = Mock(stdout="reply")
        with patch.object(dhcp.subprocess, "run", return_value=result) as run:
            self.assertEqual(dhcp.ssh("uci export dhcp", target="test-router"), "reply")
        run.assert_called_once_with(
            ["ssh", "-o", "BatchMode=yes", "test-router", "uci export dhcp"],
            input=None,
            text=True,
            capture_output=True,
            check=True,
        )

    def exercise(
        self, *, apply=False, pending=False, mutate=None, missing_unrelated=False
    ):
        unrelated = {
            "section": "other",
            "name": ["other"],
            "mac": ["02:ab:00:00:00:01"],
            "ip": ["10.77.1.5"],
        }
        before = export([unrelated])
        after = export(
            ([] if missing_unrelated else [unrelated])
            + [record(n) for n in self.verified]
        )
        calls = []
        self.last_calls = calls

        def ssh(command, input_text=None, *, target):
            calls.append((command, input_text, target))
            if command == "uci changes dhcp":
                return "pending" if pending else ""
            if command == "cat /etc/config/dhcp":
                return before
            if command == "uci export dhcp":
                if len(calls) == 3:
                    if mutate:
                        Path(self.flags[self.flags.index(mutate) + 1]).write_bytes(
                            b"{}"
                        )
                    return before
                return after
            if command == "sh -s":
                return "running"
            raise AssertionError("unexpected command")

        args = (
            self.flags
            + ["--backup-dir", str(self.backup)]
            + (["--apply"] if apply else [])
        )
        with patch.object(dhcp, "ssh", side_effect=ssh), redirect_stdout(io.StringIO()):
            dhcp.main(args)
        return calls, before

    def test_read_only_default_only_queries_router(self):
        calls, _ = self.exercise()
        self.assertEqual(
            [c[0] for c in calls],
            ["uci changes dhcp", "cat /etc/config/dhcp", "uci export dhcp"],
        )
        self.assertTrue(all(c[2] == "test-router" for c in calls))
        self.assertFalse(self.backup.exists())

    def test_apply_keeps_additive_script_remote_cas_and_private_exact_backup(self):
        calls, before = self.exercise(apply=True)
        self.assertEqual(
            [c[0] for c in calls],
            [
                "uci changes dhcp",
                "cat /etc/config/dhcp",
                "uci export dhcp",
                "sh -s",
                "uci export dhcp",
            ],
        )
        script = calls[3][1]
        self.assertIn(hashlib.sha256(before.encode()).hexdigest(), script)
        self.assertIn('test -z "$(uci changes dhcp)"', script)
        self.assertIn("uci batch <<'RUVIEW_UCI'", script)
        self.assertIn(
            "uci commit dhcp\n/etc/init.d/dnsmasq reload\n/etc/init.d/dnsmasq status",
            script,
        )
        for command in dhcp.plan(self.context, dhcp.hosts(before)):
            self.assertIn(command, script)
        backups = list(self.backup.iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), before)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_pending_router_changes_are_not_overwritten(self):
        with self.assertRaisesRegex(SystemExit, "Uncommitted router DHCP"):
            self.exercise(apply=True, pending=True)
        self.assertEqual([c[0] for c in self.last_calls], ["uci changes dhcp"])
        self.assertFalse(self.backup.exists())

    def test_input_changes_before_apply_never_create_backup_or_mutate_router(self):
        for flag in ("--router-profile", "--installation-identity"):
            original = Path(self.flags[self.flags.index(flag) + 1]).read_bytes()
            try:
                with self.subTest(flag=flag), self.assertRaises(ValueError):
                    self.exercise(apply=True, mutate=flag)
                self.assertEqual(len(self.last_calls), 3)
                self.assertNotIn("sh -s", [c[0] for c in self.last_calls])
                self.assertFalse(self.backup.exists())
            finally:
                Path(self.flags[self.flags.index(flag) + 1]).write_bytes(original)

    def test_readback_requires_every_unrelated_reservation(self):
        with self.assertRaisesRegex(AssertionError, "unrelated reservation"):
            self.exercise(apply=True, missing_unrelated=True)


if __name__ == "__main__":
    unittest.main()
