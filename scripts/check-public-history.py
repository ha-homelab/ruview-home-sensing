#!/usr/bin/env python3
"""Check reachable commit identities before publishing this repository.

Only GitHub noreply author and committer email addresses are permitted. Commit
messages and public account names are outside this check. Diagnostics never
include email addresses, names, commit messages, or Git's error output.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBJECT_ID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})")
NOREPLY = re.compile(
    rb"(?:noreply@github\.com|[^<>\s@\x00-\x1f\x7f-\xff]+@users\.noreply\.github\.com)",
    re.IGNORECASE,
)


class HistoryError(Exception):
    """A fixed, non-sensitive diagnostic for an incomplete history check."""


def git(root, *arguments):
    try:
        result = subprocess.run(
            ["git", "--no-pager", "--no-replace-objects", "-C", str(root), *arguments],
            capture_output=True,
            check=False,
        )
    except OSError:
        raise HistoryError("Git could not be executed") from None
    if result.returncode:
        raise HistoryError("Git could not read the requested commit history")
    return result.stdout


def inspect_history(root, revision="HEAD"):
    """Return (commit count, [(commit ID, role), ...]) without identity values."""
    if revision != "HEAD" and not re.fullmatch(
        r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", revision
    ):
        raise HistoryError("Revision must be HEAD or a complete commit object ID")
    if git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise HistoryError(
            "Full history is required; fetch with depth 0 before checking"
        )
    commit = git(
        root, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"
    ).strip()
    if not OBJECT_ID.fullmatch(commit):
        raise HistoryError("Git did not resolve a complete commit object ID")
    # Lowercase %ae/%ce deliberately read original identities, not .mailmap
    # aliases. Disable replacement objects and avoid any message/notes output.
    records = git(
        root,
        "log",
        "--format=%H%x00%ae%x00%ce",
        "--no-use-mailmap",
        "--no-decorate",
        "--no-color",
        "--no-notes",
        "--no-show-signature",
        commit.decode("ascii"),
        "--",
    ).splitlines()
    if not records:
        raise HistoryError("No reachable commits were checked")
    failures = []
    for record in records:
        fields = record.split(b"\0")
        if len(fields) != 3 or not OBJECT_ID.fullmatch(fields[0]):
            raise HistoryError("Git returned malformed commit identity metadata")
        for role, address in zip(("author", "committer"), fields[1:], strict=True):
            if not NOREPLY.fullmatch(address):
                failures.append((fields[0].decode("ascii"), role))
    return len(records), failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD", help="HEAD or a full commit ID")
    args = parser.parse_args(argv)
    try:
        count, failures = inspect_history(ROOT, args.revision)
    except HistoryError as error:
        print(f"History check incomplete: {error}", file=sys.stderr)
        return 2
    for commit, role in failures:
        print(f"{commit}: {role} email is not a GitHub noreply identity")
    print(f"Checked {count} reachable commits; {len(failures)} identity findings")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
