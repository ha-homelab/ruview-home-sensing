"""Execute the committed CI gate with complete, failed and uncertain results."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = [
    "assumed-activity-container",
    "bridge-container",
    "collector-build",
    "enclosure",
    "firmware-build",
    "packages",
    "public-boundary",
    "scope",
    "security",
    "validate",
]
ALWAYS = ["public-boundary", "scope", "security"]


class WorkflowScopeTests(unittest.TestCase):
    def results(self, docs=False):
        result = {name: {"result": "success"} for name in EXPECTED}
        result["scope"]["outputs"] = {
            "run": "false" if docs else "true",
            "reason": "documentation-only" if docs else "non-documentation-change",
        }
        if docs:
            for name in set(EXPECTED) - set(ALWAYS):
                result[name]["result"] = "skipped"
        return result

    def run_gate(self, result):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        gate = workflow.split(
            "      - name: Require the exact selected validation path\n", 1
        )[1]
        script = textwrap.dedent(gate.split("        run: |\n", 1)[1])
        return subprocess.run(
            [sys.executable, "-c", script],
            env={**os.environ, "RESULTS": json.dumps(result)},
            capture_output=True,
            text=True,
            timeout=10,
        ).returncode

    def test_complete_full_and_documentation_paths(self):
        self.assertEqual(self.run_gate(self.results()), 0)
        self.assertEqual(self.run_gate(self.results(True)), 0)

    def test_failed_cancelled_missing_and_unexpected_results_fail(self):
        for docs in (False, True):
            baseline = self.results(docs)
            for name in EXPECTED:
                bad = copy.deepcopy(baseline)
                del bad[name]
                self.assertNotEqual(self.run_gate(bad), 0)
                for status in ("failure", "cancelled"):
                    bad = copy.deepcopy(baseline)
                    bad[name]["result"] = status
                    self.assertNotEqual(self.run_gate(bad), 0)
            self.assertNotEqual(
                self.run_gate({**baseline, "unexpected": {"result": "success"}}), 0
            )

    def test_unknown_scope_and_unexpected_skips_fail(self):
        for outputs in ({}, {"run": "false"}, {"run": "false", "reason": "git-error"}):
            bad = self.results(True)
            bad["scope"]["outputs"] = outputs
            self.assertNotEqual(self.run_gate(bad), 0)
        for name in ALWAYS:
            bad = self.results(True)
            bad[name]["result"] = "skipped"
            self.assertNotEqual(self.run_gate(bad), 0)
        for name in EXPECTED:
            bad = self.results()
            bad[name]["result"] = "skipped"
            self.assertNotEqual(self.run_gate(bad), 0)


if __name__ == "__main__":
    unittest.main()
