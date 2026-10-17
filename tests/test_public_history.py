"""Public history checks use raw identities and never display email values."""

import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "public_history",
    Path(__file__).resolve().parents[1] / "scripts/check-public-history.py",
)
history = importlib.util.module_from_spec(spec)
spec.loader.exec_module(history)

NOREPLY = "123+example@users.noreply.github.com"
PRIVATE = "example.person@example.invalid"


class PublicHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.repo = self.directory / "repo"
        self.repo.mkdir()
        self.run_git("init", "--initial-branch=main")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("config", "user.name", "Example Contributor")
        self.run_git("config", "user.email", NOREPLY)

    def run_git(self, *arguments, env=None):
        return (
            subprocess.check_output(
                ["git", "-C", str(self.repo), *arguments],
                env=env,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )

    def commit(self, author=NOREPLY, committer=NOREPLY, message="Synthetic change"):
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="Example Contributor",
            GIT_AUTHOR_EMAIL=author,
            GIT_COMMITTER_NAME="Example Contributor",
            GIT_COMMITTER_EMAIL=committer,
        )
        self.run_git("commit", "--allow-empty", "-m", message, env=env)
        return self.run_git("rev-parse", "HEAD")

    def test_noreply_accounts_and_message_text_are_accepted(self):
        self.commit(message=PRIVATE)
        self.commit(
            author="41898282+github-actions[bot]@users.noreply.github.com",
            committer="noreply@github.com",
        )
        self.assertEqual(history.inspect_history(self.repo), (2, []))

    def test_history_reports_each_role_without_address_values(self):
        first = self.commit(author=PRIVATE)
        second = self.commit(committer=PRIVATE)
        output = io.StringIO()
        with (
            patch.object(history, "ROOT", self.repo),
            contextlib.redirect_stdout(output),
        ):
            result = history.main([])
        self.assertEqual(result, 1)
        self.assertIn(f"{first}: author", output.getvalue())
        self.assertIn(f"{second}: committer", output.getvalue())
        self.assertNotIn(PRIVATE, output.getvalue())
        self.assertNotIn("Example Contributor", output.getvalue())

    def test_exact_revision_excludes_unreachable_commits(self):
        first = self.commit()
        self.commit(author=PRIVATE)
        self.assertEqual(history.inspect_history(self.repo, first), (1, []))

    def test_merge_reaches_both_parent_histories(self):
        self.commit()
        self.run_git("checkout", "-b", "topic")
        side = self.commit(author=PRIVATE)
        self.run_git("checkout", "main")
        self.commit()
        self.run_git("merge", "--no-ff", "topic", "-m", "Synthetic merge")
        count, failures = history.inspect_history(self.repo)
        self.assertEqual(count, 4)
        self.assertEqual(failures, [(side, "author")])

    def test_mailmap_cannot_hide_original_identity(self):
        commit = self.commit(author=PRIVATE)
        (self.repo / ".mailmap").write_text(f"Example <{NOREPLY}> <{PRIVATE}>\n")
        self.assertEqual(history.inspect_history(self.repo), (1, [(commit, "author")]))

    def test_replacement_object_cannot_hide_original_identity(self):
        original = self.commit(author=PRIVATE)
        replacement = self.commit()
        self.run_git("replace", original, replacement)
        self.assertEqual(
            history.inspect_history(self.repo, original), (1, [(original, "author")])
        )

    def test_shallow_repository_is_not_reported_as_complete(self):
        self.commit(author=PRIVATE)
        self.commit()
        shallow = self.directory / "shallow"
        subprocess.run(
            ["git", "clone", "--depth=1", self.repo.as_uri(), str(shallow)],
            check=True,
            capture_output=True,
        )
        with self.assertRaisesRegex(history.HistoryError, "Full history is required"):
            history.inspect_history(shallow)

    def test_missing_revision_and_nonrepository_errors_do_not_echo_input(self):
        self.commit()
        for root, revision in (
            (self.repo, "0" * 40),
            (self.repo, PRIVATE),
            (self.directory, "HEAD"),
        ):
            with self.subTest(revision=revision):
                output = io.StringIO()
                with (
                    patch.object(history, "ROOT", root),
                    contextlib.redirect_stderr(output),
                ):
                    result = history.main(["--revision", revision])
                self.assertEqual(result, 2)
                self.assertNotIn(PRIVATE, output.getvalue())

    def test_noreply_lookalike_domains_and_empty_addresses_fail(self):
        for address in (
            "example@users.noreply.github.com.invalid",
            "noreply@github.com.invalid",
            "person@github.com",
            "@users.noreply.github.com",
            "",
        ):
            with self.subTest(address=address):
                self.assertIsNone(history.NOREPLY.fullmatch(address.encode()))
