"""Artifact license inventory must retain exact nested notices and fail closed."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "license_bundle", Path(__file__).parents[1] / "license_bundle.py"
)
assert SPEC and SPEC.loader
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class LicenseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for label, names in bundle.REQUIRED.items():
            for name in names:
                self.write(label, name, f"Copyright fixture {label}/{name}\n".encode())
        self.output = self.root / "artifact"

    def write(self, label, name, data):
        path = self.root / label / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_bundle(self):
        return bundle.build_bundle(
            self.root / "idf", self.root / "project", self.output
        )

    def test_retains_exact_nested_and_managed_component_notices(self):
        expected = b"Nested upstream notice\r\nOriginal attribution\n"
        self.write("idf", "components/nested/submodule/NOTICE.txt", expected)
        self.write("project", "managed_components/vendor__led/LICENCE", expected)
        self.write("idf", "components/nested/LICENSES/BSD-2-Clause.txt", expected)
        self.write("idf", "components/nested/COPYRIGHT", expected)
        self.write("project", "build/ignored/LICENSE", b"not source")
        self.write("idf", ".git/ignored/LICENSE", b"not source")
        manifest = self.run_bundle()
        rows = {row["path"]: row for row in manifest["files"]}
        for path in (
            "idf/components/nested/submodule/NOTICE.txt",
            "project/managed_components/vendor__led/LICENCE",
            "idf/components/nested/LICENSES/BSD-2-Clause.txt",
            "idf/components/nested/COPYRIGHT",
        ):
            self.assertEqual((self.output / path).read_bytes(), expected)
            self.assertEqual(rows[path]["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertFalse(any("/ignored/" in path for path in rows))
        self.assertEqual(
            json.loads((self.output / "manifest.json").read_text()), manifest
        )
        self.assertNotIn(str(self.root), json.dumps(manifest))

    def test_missing_required_radio_license_fails_before_output(self):
        (self.root / "idf/components/esp_phy/lib/LICENSE").unlink()
        with self.assertRaisesRegex(ValueError, "Required license missing"):
            self.run_bundle()
        self.assertFalse(self.output.exists())

    def test_empty_required_license_fails_before_output(self):
        self.write("idf", "LICENSE", b" \n")
        with self.assertRaisesRegex(ValueError, "Empty license"):
            self.run_bundle()
        self.assertFalse(self.output.exists())

    def test_external_symlink_cannot_copy_unrelated_files(self):
        outside = self.root / "unrelated"
        outside.write_text("must not be copied")
        (self.root / "idf/NOTICE").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.run_bundle()
        self.assertFalse(self.output.exists())

    def test_existing_destination_and_recursive_destination_are_rejected(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "already exist"):
            self.run_bundle()
        with self.assertRaisesRegex(ValueError, "outside"):
            bundle.build_bundle(
                self.root / "idf",
                self.root / "project",
                self.root / "idf/new-output",
            )


if __name__ == "__main__":
    unittest.main()
