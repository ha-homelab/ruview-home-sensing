"""Public binary notice membership, source integrity and failure boundaries."""

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "collector_licenses",
    Path(__file__).resolve().parents[1] / "collector" / "bundle_licenses.py",
)
licenses = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(licenses)


class CollectorLicenseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workspace = self.root / "source" / "v2"
        self.workspace.mkdir(parents=True)
        self.registry = self.root / "cargo" / "registry" / "src" / "index"
        self.registry.mkdir(parents=True)
        self.overrides = self.root / "overrides"
        self.overrides.mkdir()
        (self.overrides / "sources.json").write_text('{"packages":[]}')
        self.staging = self.root / "registry-staging"
        self.staging.mkdir()

    def package(self, name="example", version="1.0.0", *, local=False):
        folder = (
            self.workspace / "crates" if local else self.registry
        ) / f"{name}-{version}"
        folder.mkdir(parents=True)
        manifest = folder / "Cargo.toml"
        manifest.write_text(
            f'[package]\nname="{name}"\nversion="{version}"\nlicense="MIT"\n'
        )
        return {
            "name": name,
            "version": version,
            "license": "MIT",
            "source": None
            if local
            else "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": str(manifest),
            "checksum": None if local else "a" * 64,
            "file_checksums": None,
        }

    def notice(self, package, name="LICENSE", text="Original upstream notice\n"):
        path = Path(package["manifest_path"]).parent / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_selected_graph_excludes_unselected_registry_package(self):
        own = self.package(licenses.PACKAGE, local=True)
        dep = self.package()
        self.package("not-selected")
        dep_root = Path(dep["manifest_path"]).parent
        cache = self.root / "cargo/registry/cache/index/example-1.0.0.crate"
        cache.parent.mkdir(parents=True)
        with tarfile.open(cache, "w:gz") as archive:
            archive.add(dep_root / "Cargo.toml", arcname="example-1.0.0/Cargo.toml")
        checksum = hashlib.sha256(cache.read_bytes()).hexdigest()
        (self.workspace / "Cargo.lock").write_text(
            f'[[package]]\nname="{licenses.PACKAGE}"\nversion="1.0.0"\n'
            '[[package]]\nname="example"\nversion="1.0.0"\n'
            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum="{checksum}"\n'
        )
        tree = (
            f"{licenses.PACKAGE} v1.0.0 ({Path(own['manifest_path']).parent})\n"
            "example v1.0.0\nexample v1.0.0 (*)\n"
        )
        actual = licenses.selected_packages(
            tree, self.workspace, self.root / "cargo", self.staging
        )
        self.assertEqual({p["name"] for p in actual}, {licenses.PACKAGE, "example"})
        self.assertEqual(
            Path(
                next(p["manifest_path"] for p in actual if p["name"] == "example")
            ).parent,
            self.staging / "example-1.0.0",
        )

    def test_authenticated_archive_still_cannot_escape_staging(self):
        cache = self.root / "cargo/registry/cache/index/example-1.0.0.crate"
        cache.parent.mkdir(parents=True)
        with tarfile.open(cache, "w:gz") as archive:
            for name, data in (
                ("example-1.0.0/Cargo.toml", b'[package]\nname="example"\n'),
                ("example-1.0.0/../../LICENSE", b"out of scope"),
            ):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        locked = {
            "name": "example",
            "version": "1.0.0",
            "checksum": hashlib.sha256(cache.read_bytes()).hexdigest(),
        }
        with self.assertRaisesRegex(ValueError, "archive is absent"):
            licenses.registry_source(
                {**locked, "checksum": "0" * 64}, self.root / "cargo", self.staging
            )
        self.assertFalse((self.staging / "example-1.0.0").exists())
        with self.assertRaisesRegex(ValueError, "Unexpected path"):
            licenses.registry_source(locked, self.root / "cargo", self.staging)
        self.assertFalse((self.root / "LICENSE").exists())

    def test_nested_spdx_directory_and_third_party_notice_preserved(self):
        package = self.package()
        apache = self.notice(package, "LICENSES/Apache-2.0.txt", "Apache terms")
        vendor = self.notice(package, "vendor/NOTICE", "Vendor terms")
        self.notice(package, "src/ordinary.rs", "not a notice")
        self.notice(package, "src/notice.rs", "application code, not legal terms")
        self.assertEqual(
            {p for _, p in licenses.notice_files(package, self.workspace)},
            {apache, vendor},
        )

    def test_registry_notice_changed_after_cargo_verification_is_rejected(self):
        package = self.package()
        self.notice(package, text="Modified terms")
        package["file_checksums"] = {
            "LICENSE": hashlib.sha256(b"Original terms").hexdigest()
        }
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            licenses.notice_files(package, self.workspace)

    def test_notice_cannot_escape_authenticated_source(self):
        package = self.package()
        outside = self.root / "outside-license"
        outside.write_text("unrelated terms")
        (Path(package["manifest_path"]).parent / "LICENSE").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes"):
            licenses.notice_files(package, self.workspace)

    def test_local_crate_inherits_original_repository_license(self):
        package = self.package(local=True)
        notice = self.workspace.parent / "LICENSE"
        notice.write_text("Original repository terms")
        self.assertEqual(licenses.notice_files(package, self.workspace)[0][1], notice)

    def test_nested_workspace_keeps_its_own_license_declaration(self):
        nested = self.workspace.parent / "vendor/rufield"
        crate = nested / "crates/example"
        crate.mkdir(parents=True)
        (nested / "Cargo.toml").write_text(
            '[workspace.package]\nlicense="Apache-2.0"\n'
        )
        (self.workspace / "Cargo.toml").write_text(
            '[workspace.package]\nlicense="MIT"\n'
        )
        owner, metadata = licenses.inherited_package(crate, self.workspace.parent)
        self.assertEqual(owner, nested)
        self.assertEqual(metadata["license"], "Apache-2.0")

    def test_recovered_notice_requires_exact_crate_and_original_bytes(self):
        package = self.package()
        notice = self.overrides / "terms.txt"
        notice.write_text("Recovered original terms")
        document = {
            "path": "terms.txt",
            "sha256": hashlib.sha256(notice.read_bytes()).hexdigest(),
            "url": "https://example.test/pinned/commit/LICENSE",
        }
        record = {
            "name": "example",
            "version": "1.0.0",
            "crate_sha256": "a" * 64,
            "documents": [document],
        }
        (self.overrides / "sources.json").write_text(json.dumps({"packages": [record]}))
        self.assertEqual(
            licenses.source_documents(package, self.workspace, self.overrides),
            [(document["url"], notice)],
        )
        package["checksum"] = "b" * 64
        with self.assertRaises(licenses.MissingNotices):
            licenses.source_documents(package, self.workspace, self.overrides)
        package["checksum"] = "a" * 64
        notice.write_text("Changed terms")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            licenses.source_documents(package, self.workspace, self.overrides)

    def test_bundle_hashes_original_documents_and_fails_atomically(self):
        package = self.package()
        self.notice(package)
        project = self.root / "PROJECT"
        project.write_text("Original project terms")
        rust = self.root / "RUST"
        rust.write_text("Original Rust terms")
        output = self.root / "bundle"
        licenses.build_bundle(
            [package], self.workspace, output, [project], rust, self.overrides
        )
        index = json.loads((output / "index.json").read_text())
        self.assertEqual(index["package_count"], 1)
        documents = index["packages"][0]["documents"] + index["additional_documents"]
        for document in documents:
            self.assertEqual(
                hashlib.sha256((output / document["file"]).read_bytes()).hexdigest(),
                document["sha256"],
            )
        missing = self.package("missing")
        incomplete = self.root / "incomplete"
        with self.assertRaises(licenses.MissingNotices):
            licenses.build_bundle(
                [package, missing],
                self.workspace,
                incomplete,
                [project],
                rust,
                self.overrides,
            )
        self.assertFalse(incomplete.exists())

    def test_empty_or_non_cargo_graph_is_not_a_successful_inventory(self):
        for tree in ("", "not a cargo tree"):
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                licenses.selected_packages(
                    tree, self.workspace, self.root / "cargo", self.staging
                )

    def test_runtime_stage_does_not_execute_arm64_commands(self):
        dockerfile = (
            Path(__file__).resolve().parents[1] / "collector/Dockerfile"
        ).read_text()
        final = dockerfile.split("FROM runtime-base\n", 1)[1]
        self.assertNotIn("\nRUN ", final)
        self.assertIn(
            "COPY --from=build /source/ruview-dependencies/binary-licenses/", final
        )


if __name__ == "__main__":
    unittest.main()
