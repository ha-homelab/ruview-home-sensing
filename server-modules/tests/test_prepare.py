import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "worker_prepare", Path(__file__).resolve().parents[1] / "prepare.py"
)
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class PreparationTests(unittest.TestCase):
    def test_release_evidence_does_not_create_a_circular_binary_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/main.rs").write_text("fn main() {}\n")
            (root / "Cargo.lock").write_text("version=4\n")
            with patch.object(PREPARE, "HERE", root):
                before = PREPARE.worker_inputs()
                (root / "release-evidence.json").write_text('{"deployed":true}')
                (root / "fixtures").mkdir()
                (root / "fixtures/live.json").write_text('{"sequence":42}')
                self.assertEqual(before, PREPARE.worker_inputs())
                (root / "src/main.rs").write_text(
                    'fn main() { println!("changed"); }\n'
                )
                self.assertNotEqual(before, PREPARE.worker_inputs())

    def test_prepare_refuses_the_application_checkout_before_any_mutation(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            PREPARE.prepare(PREPARE.ROOT / "must-not-be-created", offline=True)

    def test_build_driver_changes_invalidate_prepared_source_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root / "build.sh"
            driver.write_text("cargo test --locked --all-targets\n")
            with patch.object(PREPARE, "HERE", root):
                before = PREPARE.worker_inputs()
                driver.write_text(
                    "cargo test --manifest-path ../upstream/Cargo.toml "
                    "--target-dir target --locked --no-default-features --features std --lib sec_tailgating::tests\n"
                    "cargo test --locked --all-targets\n"
                )
                after = PREPARE.worker_inputs()
                self.assertNotEqual(before["build.sh"], after["build.sh"])
                self.assertEqual(after["build.sh"], PREPARE.sha(driver.read_bytes()))


if __name__ == "__main__":
    unittest.main()
