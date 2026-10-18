import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RECIPE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wisp_prepare", RECIPE / "prepare.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


def archive(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, raw, kind in members:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = len(raw)
            tar.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


GOOD = [
    ("LICENSE", b"fictional license for test", tarfile.REGTYPE),
    ("firmware/components/wisp/__init__.py", b"# test", tarfile.REGTYPE),
]


class PreparationTests(unittest.TestCase):
    def test_reproducible_archive_and_manifest_cover_every_input(self):
        files = PREPARE.unpack_source(archive(GOOD))
        raw = PREPARE.bundle(files, b"# fictional template")
        self.assertEqual(raw, PREPARE.bundle(files, b"# fictional template"))
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            receipt = json.load(tar.extractfile("build-inputs.json"))
            self.assertEqual(receipt["source_commit"], PREPARE.COMMIT)
            self.assertEqual(len(receipt["sha256"]), 3)
            for name, digest in receipt["sha256"].items():
                self.assertEqual(
                    hashlib.sha256(tar.extractfile(name).read()).hexdigest(), digest
                )
            self.assertTrue(all(m.isfile() and m.mode == 0o600 for m in tar))
            self.assertNotIn("secrets.yaml", tar.getnames())

    def test_rejects_archive_paths_symlinks_unexpected_members_and_duplicates(self):
        bad = [
            ("../escape", b"x", tarfile.REGTYPE),
            ("/absolute", b"x", tarfile.REGTYPE),
            ("firmware/components/wisp/link", b"", tarfile.SYMTYPE),
            ("secrets.yaml", b"secret", tarfile.REGTYPE),
            GOOD[0],
        ]
        for member in bad:
            with self.subTest(member=member[0]), self.assertRaises(ValueError):
                PREPARE.unpack_source(archive(GOOD + [member]))

    def test_missing_component_or_license_is_rejected(self):
        for members in (GOOD[:1], GOOD[1:]):
            with self.assertRaises(ValueError):
                PREPARE.unpack_source(archive(members))

    def test_wrong_head_and_dirty_source_rejected(self):
        with (
            patch.object(PREPARE, "git", return_value=b"0" * 40),
            self.assertRaises(ValueError),
        ):
            PREPARE.require_source(Path("fixture"))
        with (
            patch.object(
                PREPARE,
                "git",
                side_effect=[PREPARE.COMMIT.encode(), b"?? secrets.yaml"],
            ),
            self.assertRaises(ValueError),
        ):
            PREPARE.require_source(Path("fixture"))

    def test_exclusive_output_preserves_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "inputs.tar"
            path.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                PREPARE.write_private_output(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"existing")

    def test_template_keeps_pilot_boundaries(self):
        template = (RECIPE / "node-esp32s3.yaml").read_text()
        self.assertIn("type: local", template)
        self.assertIn("grid_channel: !secret grid_channel", template)
        self.assertIn("bssid: !secret wifi_bssid", template)
        self.assertIn("channel: !secret grid_channel", template)
        self.assertIn("key: !secret api_encryption_key", template)
        self.assertIn("password: !secret ota_password", template)
        self.assertIn("light.turn_off: pilot_rgb", template)
        self.assertIn("restore_mode: ALWAYS_OFF", template)
        for field in (
            "dashboard_import:",
            "web_server:",
            "http_request:",
            "packages:",
            "captive_portal:",
            "interval:",
        ):
            self.assertNotIn("\n" + field, template)


if __name__ == "__main__":
    unittest.main()
