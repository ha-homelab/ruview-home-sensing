"""Deterministic exact-tree releases exclude local and historical data."""

import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "build_release", Path(__file__).resolve().parents[1] / "scripts/build-release.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "fixture@example.invalid")
        self.run_git("config", "user.name", "Synthetic Fixture")
        (self.root / "tool.py").write_text("print('original')\n")
        self.run_git("add", "tool.py")
        self.run_git("commit", "-qm", "Synthetic source")
        self.revision = self.run_git("rev-parse", "HEAD").decode().strip()

    def run_git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args])

    def test_archive_is_deterministic_and_only_contains_exact_commit(self):
        (self.root / "tool.py").write_text("uncommitted\n")
        (self.root / "untracked.txt").write_text("private fixture\n")
        first, manifest = release.build(self.root, self.revision)
        second, _ = release.build(self.root, self.revision)
        self.assertEqual(first, second)
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            self.assertEqual(set(archive.getnames()), {"tool.py", release.MANIFEST})
            self.assertEqual(
                archive.extractfile("tool.py").read(), b"print('original')\n"
            )
            self.assertEqual(json.load(archive.extractfile(release.MANIFEST)), manifest)
            for member in archive.getmembers():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual((member.uname, member.gname), ("", ""))

    def test_symlinks_and_mutable_revisions_are_rejected(self):
        with self.assertRaises(ValueError):
            release.build(self.root, "HEAD")
        (self.root / "link").symlink_to("tool.py")
        self.run_git("add", "link")
        self.run_git("commit", "-qm", "Synthetic symlink")
        revision = self.run_git("rev-parse", "HEAD").decode().strip()
        with self.assertRaises(ValueError):
            release.build(self.root, revision)

    def test_unsafe_paths_are_rejected(self):
        for name in (
            "../escape",
            "/escape",
            "a//b",
            "a/./b",
            ".git/config",
            "a\\b",
            "a\nb",
        ):
            with self.subTest(name=name):
                self.assertFalse(release.safe_path(name))


if __name__ == "__main__":
    unittest.main()
