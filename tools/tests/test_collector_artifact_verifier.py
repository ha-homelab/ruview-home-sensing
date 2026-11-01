"""Exercise the actual CI verifier with synthetic artifacts, without an image.

The minimal ELF header and notices only isolate receipt validation. They are
not evidence of an application build, a valid executable or runtime behavior.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CollectorArtifactVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.artifacts = self.directory / "collector-artifacts"
        self.artifacts.mkdir()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - name: Verify the produced image and extract", 1)[
            1
        ]
        self.verifier = textwrap.dedent(
            step.split("          python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[
                0
            ]
        )
        binary = bytearray(20)
        binary[:6] = b"\x7fELF\x02\x01"
        binary[18:20] = (183).to_bytes(2, "little")
        (self.artifacts / "sensing-server").write_bytes(binary)
        self.write_test_log(15)

        ring_policy = json.loads(
            (ROOT / "collector/ring-policy/source.json").read_text()
        )
        ring_patch_hash = hashlib.sha256(
            (ROOT / "collector/ring-policy/exact-minimum.patch").read_bytes()
        ).hexdigest()
        (self.artifacts / "ring-policy-receipt.json").write_text(
            json.dumps(ring_policy | {"patch_sha256": ring_patch_hash})
        )
        ring_licenses = self.artifacts / "ring-licenses"
        ring_licenses.mkdir()
        for name in ring_policy["licenses"]:
            (ring_licenses / name.replace("/", "__")).write_text("synthetic notice")

        notices = self.artifacts / "collector-licenses"
        notices.mkdir()
        (notices / "README.txt").write_text("synthetic notices")
        (notices / "LICENSE").write_bytes(b"synthetic notice")
        document = {
            "file": "LICENSE",
            "sha256": hashlib.sha256(b"synthetic notice").hexdigest(),
        }
        (notices / "index.json").write_text(
            json.dumps(
                {
                    "target": "aarch64-unknown-linux-gnu",
                    "features": ["mqtt"],
                    "edges": ["normal", "build"],
                    "package_count": 1,
                    "packages": [{"name": "synthetic", "documents": [document]}],
                    "additional_documents": [document],
                }
            )
        )
        self.policy_bytes = (ROOT / "collector/dependency-security.json").read_bytes()
        self.dependency_receipt = self.artifacts / "dependency-security-receipt.json"
        self.dependency_receipt.write_bytes(self.policy_bytes)
        self.source_inputs = self.artifacts / "source-inputs.json"
        self.source_inputs.write_text(
            json.dumps(
                {
                    "cargo_lock_sha256": json.loads(self.policy_bytes)[
                        "lock_after_sha256"
                    ]
                }
            )
        )

    def write_test_log(self, suites):
        (self.artifacts / "build.log").write_text(
            "test result: ok. 1 passed; 0 failed;\n" * suites
            + "Actual ring policy checked:\n"
        )

    def verify(self):
        receipt = self.artifacts / "build-receipt.json"
        receipt.unlink(missing_ok=True)
        return subprocess.run(
            [sys.executable, "-c", self.verifier],
            cwd=ROOT,
            env=os.environ | {"RUNNER_TEMP": str(self.directory)},
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_exact_dependency_receipt_is_bound_into_build_evidence(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads((self.artifacts / "build-receipt.json").read_text())
        policy = json.loads(self.policy_bytes)
        self.assertEqual(
            actual["dependency_security_receipt_sha256"],
            hashlib.sha256(self.policy_bytes).hexdigest(),
        )
        self.assertEqual(
            actual["dependency_security_patch_sha256"], policy["patch_sha256"]
        )
        self.assertEqual(
            actual["secured_cargo_lock_sha256"], policy["lock_after_sha256"]
        )
        self.assertFalse(actual["arm64_runtime_executed"])

    def test_malformed_and_mismatched_dependency_receipts_are_rejected(self):
        altered = json.loads(self.policy_bytes)
        altered["lock_after_sha256"] = "0" * 64
        for value in (b"NOT JSON", json.dumps(altered).encode()):
            with self.subTest(value=value):
                self.dependency_receipt.write_bytes(value)
                result = self.verify()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Unexpected dependency security receipt", result.stderr)
                self.assertFalse((self.artifacts / "build-receipt.json").exists())

    def test_missing_dependency_receipt_is_rejected(self):
        self.dependency_receipt.unlink()
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.artifacts / "build-receipt.json").exists())

    def test_prepared_lock_mismatch_or_missing_hash_is_rejected(self):
        for source_inputs in ({"cargo_lock_sha256": "0" * 64}, {}):
            with self.subTest(source_inputs=source_inputs):
                self.source_inputs.write_text(json.dumps(source_inputs))
                result = self.verify()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Prepared Cargo.lock does not match", result.stderr)
                self.assertFalse((self.artifacts / "build-receipt.json").exists())

    def test_missing_source_evidence_is_rejected(self):
        self.source_inputs.unlink()
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.artifacts / "build-receipt.json").exists())

    def test_missing_native_suites_are_rejected(self):
        for count in (6, 14):
            with self.subTest(count=count):
                self.write_test_log(count)
                result = self.verify()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "Missing or empty native collector regression suite", result.stderr
                )
                self.assertFalse((self.artifacts / "build-receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
