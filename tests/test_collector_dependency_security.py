"""Defensive dependency floors and fail-closed lockfile preparation."""

import difflib
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "collector"
SPEC = importlib.util.spec_from_file_location(
    "collector_dependency_security", COLLECTOR / "dependency_security.py"
)
SECURITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class DependencySecurity(unittest.TestCase):
    def test_reviewed_quinn_floors_and_authenticated_records(self):
        policy = json.loads((COLLECTOR / "dependency-security.json").read_bytes())
        expected = {
            "quinn-proto": (
                "0.11.19",
                "0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe",
            ),
            "quinn-udp": (
                "0.5.16",
                "af66907df18639dcf4db56ca65490cabc4b27a97dbadd96f2926cca73298f016",
            ),
        }
        patch_bytes = (COLLECTOR / "patches" / policy["patch"]).read_bytes()
        self.assertEqual(digest(patch_bytes), policy["patch_sha256"])
        self.assertEqual(policy["target"], "aarch64-unknown-linux-gnu")
        self.assertEqual(policy["features"], ["mqtt"])
        self.assertEqual(policy["edges"], ["normal", "build"])
        self.assertIn(
            "8d1679eb54419abe79ecb0010a73431c37b95afe",
            policy["upstream_security_commits"],
        )
        for name, (version, checksum) in expected.items():
            with self.subTest(package=name):
                self.assertEqual(policy["direct_floors"][name], version)
                records = [
                    item
                    for item in policy["added_or_updated_packages"]
                    if item["name"] == name
                ]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["version"], version)
                self.assertEqual(records[0]["checksum"], checksum)
                self.assertEqual(
                    records[0]["source"],
                    "registry+https://github.com/rust-lang/crates.io-index",
                )
                self.assertIn(f'+version = "{version}"'.encode(), patch_bytes)
                self.assertIn(f'+checksum = "{checksum}"'.encode(), patch_bytes)

    def fixture(self, root):
        source = root / "source"
        (source / "v2").mkdir(parents=True)
        (source / "ruview-dependencies").mkdir()
        collector = root / "collector"
        (collector / "patches").mkdir(parents=True)
        before = b'name = "ring"\nversion = "0.17.14"\n\nquinn = "old"\n'
        after = before.replace(b'quinn = "old"', b'quinn = "reviewed"')
        patch_bytes = (
            "diff --git a/v2/Cargo.lock b/v2/Cargo.lock\n"
            + "".join(
                difflib.unified_diff(
                    before.decode().splitlines(True),
                    after.decode().splitlines(True),
                    fromfile="a/v2/Cargo.lock",
                    tofile="b/v2/Cargo.lock",
                )
            )
        ).encode()
        lock = source / "v2/Cargo.lock"
        lock.write_bytes(before)
        policy = {
            "patch_sha256": digest(patch_bytes),
            "lock_before_sha256": digest(before),
            "lock_after_sha256": digest(after),
        }
        policy_path = collector / "dependency-security.json"
        policy_path.write_bytes(json.dumps(policy, indent=2).encode() + b"\n")
        patch_path = collector / "patches/0005-upstream-dependency-security.patch"
        patch_path.write_bytes(patch_bytes)
        return source, collector, lock, before, after, policy_path, patch_path

    def test_apply_preserves_ring_and_receipt_is_exact_policy_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source, collector, lock, _, after, policy, _ = self.fixture(Path(directory))
            with patch.object(SECURITY, "ROOT", collector):
                SECURITY.prepare_dependency_security(source)
            self.assertEqual(lock.read_bytes(), after)
            self.assertEqual(
                (
                    source / "ruview-dependencies/dependency-security-receipt.json"
                ).read_bytes(),
                policy.read_bytes(),
            )
            self.assertTrue(
                lock.read_bytes().startswith(b'name = "ring"\nversion = "0.17.14"\n')
            )

    def test_changed_input_or_already_patched_lock_never_runs_git(self):
        for use_after in (False, True):
            with (
                self.subTest(already_patched=use_after),
                tempfile.TemporaryDirectory() as directory,
            ):
                source, collector, lock, before, after, _, _ = self.fixture(
                    Path(directory)
                )
                changed = after if use_after else before + b"# unreviewed\n"
                lock.write_bytes(changed)
                with (
                    patch.object(SECURITY, "ROOT", collector),
                    patch.object(SECURITY.subprocess, "run") as run,
                    self.assertRaises(ValueError),
                ):
                    SECURITY.prepare_dependency_security(source)
                run.assert_not_called()
                self.assertEqual(lock.read_bytes(), changed)

    def test_changed_patch_never_mutates_lock_or_runs_git(self):
        with tempfile.TemporaryDirectory() as directory:
            source, collector, lock, before, _, _, patch_path = self.fixture(
                Path(directory)
            )
            patch_path.write_bytes(patch_path.read_bytes() + b"# unreviewed\n")
            with (
                patch.object(SECURITY, "ROOT", collector),
                patch.object(SECURITY.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                SECURITY.prepare_dependency_security(source)
            run.assert_not_called()
            self.assertEqual(lock.read_bytes(), before)

    def test_failed_dry_run_never_attempts_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            source, collector, lock, before, _, _, _ = self.fixture(Path(directory))
            with (
                patch.object(SECURITY, "ROOT", collector),
                patch.object(
                    SECURITY.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(
                        1, ["git", "apply", "--check"]
                    ),
                ) as run,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                SECURITY.prepare_dependency_security(source)
            self.assertEqual(run.call_count, 1)
            self.assertIn("--check", run.call_args.args[0])
            self.assertEqual(lock.read_bytes(), before)

    def test_unexpected_output_gets_no_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            source, collector, lock, _, after, policy_path, _ = self.fixture(
                Path(directory)
            )
            policy = json.loads(policy_path.read_bytes())
            policy["lock_after_sha256"] = "0" * 64
            policy_path.write_text(json.dumps(policy))
            with (
                patch.object(SECURITY, "ROOT", collector),
                self.assertRaises(ValueError),
            ):
                SECURITY.prepare_dependency_security(source)
            self.assertEqual(lock.read_bytes(), after)
            self.assertFalse(
                (
                    source / "ruview-dependencies/dependency-security-receipt.json"
                ).exists()
            )


if __name__ == "__main__":
    unittest.main()
