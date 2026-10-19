"""Privileged metadata callers require exact reviewed bytes, not just names."""

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "check_workflows", Path(__file__).resolve().parents[1] / "check_workflows.py"
)
WORKFLOWS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKFLOWS)


class MetadataCallerTests(unittest.TestCase):
    def callers(self):
        return {
            name: (WORKFLOWS.ROOT / ".github/workflows" / name).read_bytes()
            for name in WORKFLOWS.METADATA_CALLERS
        }

    def test_exact_reviewed_callers_are_accepted(self):
        self.assertEqual(
            set(WORKFLOWS.METADATA_CALLERS), {"auto-approve.yml", "auto-merge.yml"}
        )
        for name, raw in self.callers().items():
            with self.subTest(name=name):
                self.assertEqual(WORKFLOWS.workflow_errors(name, raw), [])

    def test_changed_code_pins_runners_and_secrets_are_rejected(self):
        for name, raw in self.callers().items():
            modifications = {
                "checkout": raw
                + b"\n  checkout:\n    uses: actions/checkout@"
                + b"a" * 40
                + b"\n",
                "run": raw + b"\n  steps:\n    - run: echo changed\n",
                "pin": raw.replace(WORKFLOWS.TOOLKIT.encode(), b"b" * 40),
                "runner": raw.replace(b"ubuntu-24.04", b"self-hosted"),
                "inherit": raw + b"\nsecrets: inherit\n",
                "comment": raw + b"\n# byte changes need review too\n",
            }
            for change, candidate in modifications.items():
                with self.subTest(name=name, change=change):
                    errors = WORKFLOWS.workflow_errors(name, candidate)
                    self.assertTrue(errors)
                    self.assertIn("independently reviewed bytes", errors[0])

    def test_renamed_and_unlisted_privileged_callers_are_rejected(self):
        for raw in self.callers().values():
            for name in ("renamed.yml", "renamed.yaml"):
                with self.subTest(name=name):
                    self.assertTrue(WORKFLOWS.workflow_errors(name, raw))
        self.assertTrue(
            WORKFLOWS.workflow_errors("inline.yml", b"on: [pull_request_target]\n")
        )

    def test_review_hash_never_exempts_generic_pin_and_secret_checks(self):
        name = "auto-approve.yml"
        for raw, expected in (
            (b"secrets: inherit\n", "must not inherit"),
            (b"secrets : 'inherit'\n", "must not inherit"),
            (b"job: {secrets: inherit}\n", "must not inherit"),
            (b'"secrets": "inherit"\n', "must not inherit"),
            (b"uses: actions/checkout@main\n", "immutable commit"),
            (b"runs-on: self-hosted\n", "literal hosted image"),
            (
                b"uses: victron-venus/venus-os-ci-toolkit/action@" + b"b" * 40,
                "toolkit revisions differ",
            ),
        ):
            with (
                self.subTest(expected=expected),
                patch.dict(
                    WORKFLOWS.METADATA_CALLERS, {name: hashlib.sha256(raw).hexdigest()}
                ),
            ):
                self.assertTrue(
                    any(
                        expected in item
                        for item in WORKFLOWS.workflow_errors(name, raw)
                    )
                )

    def test_workflow_and_composite_pins_remain_independently_fixed(self):
        toolkit = "victron-venus/venus-os-ci-toolkit/"
        for path, expected, other in (
            (
                ".github/workflows/security-scan.yml",
                WORKFLOWS.TOOLKIT,
                WORKFLOWS.TOOLKIT_ACTIONS,
            ),
            ("actions/setup-python", WORKFLOWS.TOOLKIT_ACTIONS, WORKFLOWS.TOOLKIT),
        ):
            with self.subTest(path=path):
                accepted = f"uses: {toolkit}{path}@{expected}\n".encode()
                self.assertEqual(WORKFLOWS.workflow_errors("ci.yml", accepted), [])
                for changed in (other, "a" * 40, "main"):
                    rejected = f"uses: {toolkit}{path}@{changed}\n".encode()
                    self.assertTrue(WORKFLOWS.workflow_errors("ci.yml", rejected))

    def test_main_checks_yaml_as_well_as_yml_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / ".github/workflows"
            directory.mkdir(parents=True)
            (directory / "unlisted.yaml").write_text("on:\n  pull_request_target:\n")
            with patch.object(WORKFLOWS, "ROOT", root), self.assertRaises(SystemExit):
                WORKFLOWS.main()


if __name__ == "__main__":
    unittest.main()
