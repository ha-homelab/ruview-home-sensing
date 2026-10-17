"""Publication checks reject private payloads without echoing their contents."""

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "boundary", Path(__file__).resolve().parents[1] / "scripts/check-public-boundary.py"
)
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


class PublicationBoundaryTests(unittest.TestCase):
    def test_location_labels_are_rejected_in_documents_and_fixtures(self):
        data = ("kit" + "chen").encode()
        for path in ("README.md", "tests/fixtures/example.json"):
            self.assertIn("location-label", boundary.inspect_file(path, data, {}))

    def test_private_location_in_filename_is_rejected(self):
        name = "docs/" + "kit" + "chen" + ".md"
        self.assertIn("location-label", boundary.inspect_file(name, b"neutral", {}))

    def test_private_material_and_unreviewed_binary_are_rejected(self):
        self.assertIn(
            "private-path", boundary.inspect_file("config/nodes.json", b"{}", {})
        )
        self.assertIn(
            "unreviewed-binary", boundary.inspect_file("model.bin", b"\0abc", {})
        )
        self.assertIn("unsafe-path", boundary.inspect_file("../secret", b"x", {}))

    def test_generic_document_and_synthetic_zone_are_accepted(self):
        self.assertEqual(
            boundary.inspect_file("README.md", b"zone_a example.invalid", {}), []
        )


class SourceArchiveBoundaryTests(unittest.TestCase):
    def archive(self, names):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "source.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name in names:
                entry = tarfile.TarInfo(name)
                entry.size = 2
                archive.addfile(entry, io.BytesIO(b"{}"))
        return path

    def test_unwrapped_source_keeps_complete_private_path(self):
        files = list(boundary.archive_files(self.archive(["config/nodes.json"])))
        self.assertEqual(files[0][0], "config/nodes.json")
        self.assertIn("private-path", boundary.inspect_file(*files[0], {}))

    def test_traversal_and_duplicate_entries_fail_closed(self):
        for names in (["../README.md"], ["/README.md"], ["README.md", "README.md"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                list(boundary.archive_files(self.archive(names)))

    def test_wrapper_is_explicit(self):
        path = self.archive(["source/README.md"])
        self.assertEqual(list(boundary.archive_files(path))[0][0], "source/README.md")
        self.assertEqual(list(boundary.archive_files(path, 1))[0][0], "README.md")
