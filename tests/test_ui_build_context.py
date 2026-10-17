"""Actual private tar preparation with fictional geometry; no image builds."""

import hashlib
import io
import json
import tarfile
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from test_evidence_context import ExportFixture, load

build = load("scripts/prepare-ui-build.py", "ui_build_context")


class UIBuildTests(ExportFixture):
    def setUp(self):
        super().setUp()
        self.floorplan_url = "https://floorplan.example.invalid/"
        self.geometry_profile = dict(self.profile)
        self.profile["floorplan_url"] = self.floorplan_url
        self.profile_path.write_text(json.dumps(self.profile))
        self.profile_pin = hashlib.sha256(self.profile_path.read_bytes()).hexdigest()
        self.base = "registry.example.invalid/collector@sha256:" + "a" * 64

    def command(self):
        return [*super().command(), "--base-image", self.base]

    def test_real_cli_preserves_copy_files_and_is_deterministic(self):
        build.main(self.command())
        first = self.output.read_bytes()
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        with tarfile.open(fileobj=io.BytesIO(first)) as archive:
            entries = archive.getmembers()
            expected = {
                "Dockerfile",
                "build-context.json",
                *build.ASSETS,
                "ui/home-floor/floor-config.js",
            }
            self.assertEqual({entry.name for entry in entries}, expected)
            for entry in entries:
                self.assertTrue(entry.isfile())
                self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 0))
                self.assertEqual(
                    (entry.uname, entry.gname, entry.mode), ("", "", 0o644)
                )
            files = {entry.name: archive.extractfile(entry).read() for entry in entries}
        for name in build.ASSETS:
            if name == build.PANEL_OUTPUT:
                expected = (
                    (build.ROOT / "collector" / build.PANEL_SOURCE)
                    .read_bytes()
                    .replace(b"@@FLOORPLAN_URL@@", self.floorplan_url.encode())
                )
            else:
                expected = (build.ROOT / "collector" / name).read_bytes()
            self.assertEqual(files[name], expected)
        source = build.source_snapshot()
        expected_dockerfile = source["Dockerfile.ui"].replace(
            build.BASE_TEMPLATE.encode(),
            f"FROM --platform=linux/arm64 {self.base}\n".encode(),
        )
        self.assertEqual(files["Dockerfile"], expected_dockerfile)
        self.assertNotIn(b"ARG BASE_IMAGE", files["Dockerfile"])
        expected_geometry = build.export.render(
            self.model,
            self.model_path.read_bytes(),
            self.geometry_profile,
            self.load(),
            "a" * 40,
        )
        self.assertEqual(files["ui/home-floor/floor-config.js"], expected_geometry)
        receipt = json.loads(files.pop("build-context.json"))
        self.assertEqual(receipt["base_image"], self.base)
        self.assertEqual(receipt["approvals"]["context_manifest_sha256"], self.pin)
        self.assertEqual(
            receipt["generation_sources_sha256"],
            {
                name: hashlib.sha256((build.ROOT / name).read_bytes()).hexdigest()
                for name in build.GENERATION_FILES
            },
        )
        self.assertEqual(
            receipt["build_files_sha256"],
            {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
        )
        second = self.parent / "second.tar"
        args = self.command()
        args[args.index("--output") + 1] = str(second)
        build.main(args)
        self.assertEqual(first, second.read_bytes())
        with self.assertRaises(FileExistsError):
            build.main(self.command())
        self.assertEqual(first, self.output.read_bytes())

    def test_missing_bad_or_changed_approvals_never_publish(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build.main([])
        for flag in ("--model-sha256", "--profile-sha256", "--site-context-sha256"):
            args = self.command()
            args[args.index(flag) + 1] = "0" * 64
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                build.main(args)
            self.assertFalse(self.output.exists())
        original = build.archive
        for path in (self.context / "nodes.json", self.model_path, self.profile_path):
            raw = path.read_bytes()

            def changed(*args, path=path):
                result = original(*args)
                path.write_bytes(b"{}")
                return result

            with patch.object(build, "archive", changed), self.assertRaises(ValueError):
                build.main(self.command())
            self.assertFalse(self.output.exists())
            path.write_bytes(raw)

    def test_build_link_is_required_and_invalid_origins_cannot_publish(self):
        rejected = [
            None,
            True,
            "",
            "http://floorplan.example.invalid/",
            "https://user:password@floorplan.example.invalid/",
            "https://floorplan.example.invalid/?key=private",
            "https://floorplan.example.invalid/#private",
            "https://floorplan.example.invalid/path/",
            "https://floorplan.example.invalid",
            "//floorplan.example.invalid/",
            "https://floorplan.example.invalid/\n",
            "https://floorplan.example.invalid/';alert(1)//",
            "javascript:alert(1)",
            "https://floorplan.example.invalid:99999/",
            "https://floorplan.example.invalid:0443/",
            "https://127.1/",
            "https://2130706433/",
            "https://bad..example.invalid/",
            "https://floorplan.example.invalid./",
            "https://FLOORPLAN.example.invalid/",
        ]
        for url in rejected:
            value = dict(self.geometry_profile, floorplan_url=url)
            raw = json.dumps(value).encode()
            self.profile_path.write_bytes(raw)
            self.profile_pin = hashlib.sha256(raw).hexdigest()
            with self.subTest(url=url), self.assertRaises(ValueError):
                build.main(self.command())
            self.assertFalse(self.output.exists())
        self.profile_path.write_text(json.dumps(self.geometry_profile))
        self.profile_pin = hashlib.sha256(self.profile_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "including floorplan_url"):
            build.main(self.command())
        self.assertFalse(self.output.exists())
        for url in (self.floorplan_url, "https://192.0.2.10:8443/"):
            self.assertEqual(build.floorplan_url(url), url)

    def test_link_template_must_have_exactly_one_placeholder(self):
        for replacement in (b"", b"@@FLOORPLAN_URL@@@@FLOORPLAN_URL@@"):
            source = build.source_snapshot()
            source[build.PANEL_SOURCE] = source[build.PANEL_SOURCE].replace(
                b"@@FLOORPLAN_URL@@", replacement
            )
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ValueError, "link template"),
            ):
                build.archive(
                    source, b"geometry", self.base, {}, {}, self.floorplan_url
                )

    def test_tags_injection_credentials_and_invalid_references_are_rejected(self):
        for value in (
            "collector:latest",
            "registry.example.invalid/collector:latest",
            self.base + "\nRUN id",
            self.base + " ",
            self.base + "\x00",
            "user:password@" + self.base,
            "https://" + self.base,
            "registry:99999/collector@sha256:" + "a" * 64,
            "registry/../collector@sha256:" + "a" * 64,
            "registry//collector@sha256:" + "a" * 64,
            "registry/collector@sha256:" + "A" * 64,
            "registry/collector@sha256:" + "a" * 63,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build.immutable_base(value)
        self.assertEqual(build.immutable_base(self.base), self.base)
        alternate = "192.0.2.1:5050/collector@sha256:" + "b" * 64
        self.assertEqual(build.immutable_base(alternate), alternate)

    def test_source_symlinks_oversize_or_concurrent_change_fail_closed(self):
        root = self.parent / "source"
        for name, raw in build.source_snapshot().items():
            path = root / "collector" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        for name, raw in build.read_sources(build.GENERATION_FILES).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        target = root / "collector" / build.ASSETS[0]
        before = target.read_bytes()
        target.unlink()
        target.symlink_to(self.model_path)
        with patch.object(build, "ROOT", root), self.assertRaises(OSError):
            build.source_snapshot()
        target.unlink()
        target.write_bytes(before)
        with (
            patch.object(build, "ROOT", root),
            patch.object(build, "MAX_SOURCE_BYTES", 1),
        ):
            with self.assertRaises(ValueError):
                build.source_snapshot()
        original = build.archive

        def changed(*args):
            result = original(*args)
            target.write_bytes(before + b"\n")
            return result

        with patch.object(build, "ROOT", root), patch.object(build, "archive", changed):
            with self.assertRaises(ValueError):
                build.main(self.command())
        self.assertFalse(self.output.exists())
        target.write_bytes(before)
        target = root / "scripts/site_context.py"
        before = target.read_bytes()
        with patch.object(build, "ROOT", root), patch.object(build, "archive", changed):
            with self.assertRaises(ValueError):
                build.main(self.command())
        self.assertFalse(self.output.exists())

    def test_failed_write_cannot_publish_partial_tar_and_private_paths_are_required(
        self,
    ):
        with patch(
            "scripts.site_context.os.link", side_effect=OSError("failed commit")
        ):
            with self.assertRaises(OSError):
                build.main(self.command())
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.parent.glob(".ruview-site-inputs-*.tmp")), [])
        link = self.parent / "redirect"
        link.symlink_to(self.parent, target_is_directory=True)
        args = self.command()
        args[args.index("--output") + 1] = str(link / "context.tar")
        with self.assertRaises(OSError):
            build.main(args)
        self.assertFalse((self.parent / "context.tar").exists())
        args[args.index("--output") + 1] = str(build.ROOT / "private-context.tar")
        with self.assertRaises(ValueError):
            build.main(args)

    def test_template_and_source_inventory_changes_require_explicit_review(self):
        source = build.source_snapshot()
        source["Dockerfile.ui"] = source["Dockerfile.ui"].replace(
            b"ARG BASE_IMAGE", b"ARG OTHER"
        )
        with self.assertRaises(ValueError):
            build.archive(source, b"geometry", self.base, {}, {}, self.floorplan_url)
        expected = {
            Path(name).name
            for name in build.SOURCE_FILES
            if name.startswith("ui/home-floor/")
        }
        actual = {
            path.name for path in (build.ROOT / "collector/ui/home-floor").iterdir()
        }
        self.assertEqual(actual, expected)
