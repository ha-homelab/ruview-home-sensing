"""Select committed histories without treating a generated PR merge as user code."""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")


def revisions_for_event(environment):
    event = environment.get("HISTORY_EVENT", "")
    if event == "pull_request":
        revisions = (
            environment.get("HISTORY_PR_HEAD", ""),
            environment.get("HISTORY_PR_BASE", ""),
        )
    elif event in {"push", "workflow_dispatch", "merge_group"}:
        revisions = (environment.get("HISTORY_REVISION", ""),)
    else:
        raise ValueError("Unsupported event for public history validation")
    if any(not SHA.fullmatch(revision) for revision in revisions):
        raise ValueError("Complete event commit identities are required")
    return tuple(dict.fromkeys(revisions))


def check_event(environment, run=None):
    runner = subprocess.run if run is None else run
    revisions = revisions_for_event(environment)
    failed = False
    for revision in revisions:
        result = runner(
            [
                sys.executable,
                str(ROOT / "scripts/check-public-history.py"),
                "--revision",
                revision,
            ],
            cwd=ROOT,
            check=False,
        )
        failed = failed or result.returncode != 0
    return int(failed)


def main():
    try:
        return check_event(os.environ)
    except ValueError as error:
        print(f"History event check incomplete: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
