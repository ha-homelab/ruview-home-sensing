import contextlib
import hashlib
import importlib.util
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "worker_package_runtime",
    Path(__file__).resolve().parents[1] / "package-runtime.py",
)
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def elf_header(machine=62):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", header, 18, machine)
    return header


class RuntimePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.binary = self.root / "worker"
        self.binary.write_bytes(elf_header())
        self.destination = self.root / "runtime"
        self.sentinel = self.root / "keep"
        self.sentinel.write_bytes(b"earlier evidence")
        self.libraries = self.root / "libraries"
        self.libraries.mkdir()
        self.libc = self.libraries / "libc.so.6"
        self.libc.write_bytes(b"exact libc fixture")
        self.loader = self.libraries / "ld-linux-x86-64.so.2"
        self.loader.write_bytes(b"exact loader fixture")

    def tool_outputs(self, *, linkage=None, versions=None):
        outputs = {
            ("readelf", "-h"): "ELF header evidence\n",
            ("readelf", "-d"): "(NEEDED) Shared library: [libc.so.6]\n",
            ("readelf", "--version-info"): (
                "GLIBC_2.9 GLIBC_2.17 GLIBC_2.36\n" if versions is None else versions
            ),
            ("ldd",): (
                f"libc.so.6 => {self.libc} (0x1234)\n{self.loader} (0x2345)\n"
                if linkage is None
                else linkage
            ),
        }

        def read(args, *, text):
            self.assertTrue(text)
            self.assertEqual(args[-1], str(self.binary))
            return outputs[tuple(args[:-1])]

        return read

    def run_package(self, machine="x86_64", *, linkage=None, versions=None):
        with (
            patch.object(PACKAGE.platform, "system", return_value="Linux"),
            patch.object(PACKAGE.platform, "machine", return_value=machine),
            patch.object(PACKAGE, "LIBRARY_PREFIXES", (str(self.libraries) + "/",)),
            patch.object(
                PACKAGE.subprocess,
                "check_output",
                side_effect=self.tool_outputs(linkage=linkage, versions=versions),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            PACKAGE.package(self.binary, self.destination)

    def assert_no_output(self):
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.sentinel.read_bytes(), b"earlier evidence")

    def test_native_architecture_allowlist(self):
        for machine, host, expected in [
            (62, "x86_64", "amd64"),
            (62, "AMD64", "amd64"),
            (183, "aarch64", "arm64"),
            (183, "arm64", "arm64"),
        ]:
            with self.subTest(machine=machine, host=host):
                self.binary.write_bytes(elf_header(machine))
                with (
                    patch.object(PACKAGE.platform, "system", return_value="Linux"),
                    patch.object(PACKAGE.platform, "machine", return_value=host),
                ):
                    self.assertEqual(PACKAGE.native_architecture(self.binary), expected)

    def test_invalid_elf_never_runs_tools_or_creates_output(self):
        invalid = {
            "not ELF": b"MZ" + bytes(62),
            "truncated": elf_header()[:63],
            "ELF32": elf_header(),
            "big endian": elf_header(),
            "invalid identification version": elf_header(),
            "unsupported machine": elf_header(3),
        }
        invalid["ELF32"][4] = 1
        invalid["big endian"][5] = 2
        invalid["invalid identification version"][6] = 0
        for name, header in invalid.items():
            with self.subTest(name=name):
                self.binary.write_bytes(header)
                with patch.object(PACKAGE.subprocess, "check_output") as tool:
                    with self.assertRaises(ValueError):
                        PACKAGE.package(self.binary, self.destination)
                    tool.assert_not_called()
                self.assert_no_output()

    def test_foreign_or_unsupported_host_never_runs_ldd(self):
        for machine, system, host in [
            (62, "Linux", "aarch64"),
            (183, "Linux", "x86_64"),
            (62, "Linux", "riscv64"),
            (183, "Darwin", "arm64"),
        ]:
            with self.subTest(machine=machine, system=system, host=host):
                self.binary.write_bytes(elf_header(machine))
                with (
                    patch.object(PACKAGE.platform, "system", return_value=system),
                    patch.object(PACKAGE.platform, "machine", return_value=host),
                    patch.object(PACKAGE.subprocess, "check_output") as tool,
                ):
                    with self.assertRaisesRegex(ValueError, "native"):
                        PACKAGE.package(self.binary, self.destination)
                    tool.assert_not_called()
                self.assert_no_output()

    def test_both_architectures_record_exact_runtime_closure(self):
        for machine, host, expected, loader in [
            (62, "x86_64", "amd64", "ld-linux-x86-64.so.2"),
            (183, "aarch64", "arm64", "ld-linux-aarch64.so.1"),
        ]:
            with self.subTest(architecture=expected):
                self.destination = self.root / expected
                self.binary.write_bytes(elf_header(machine) + b"worker payload")
                self.loader = self.libraries / loader
                self.loader.write_bytes(b"exact loader fixture")
                self.run_package(host)
                metadata = json.loads(
                    (self.destination / "runtime-metadata.json").read_text()
                )
                self.assertEqual(metadata["architecture"], expected)
                self.assertEqual(metadata["maximum_glibc"], "2.36")
                self.assertEqual(metadata["needed"], ["libc.so.6"])
                self.assertEqual(metadata["binary_bytes"], self.binary.stat().st_size)
                self.assertEqual(
                    metadata["binary_sha256"],
                    hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                )
                rootfs = self.destination / "rootfs"
                expected_files = {
                    "app/ruview-server-modules": self.binary,
                    str(self.libc).lstrip("/"): self.libc,
                    str(self.loader).lstrip("/"): self.loader,
                }
                self.assertEqual(
                    set(metadata["runtime_file_sha256"]), set(expected_files)
                )
                for name, source in expected_files.items():
                    self.assertEqual((rootfs / name).read_bytes(), source.read_bytes())
                    self.assertEqual(
                        metadata["runtime_file_sha256"][name],
                        hashlib.sha256(source.read_bytes()).hexdigest(),
                    )
                self.assertIn(
                    "FROM scratch", (self.destination / "Dockerfile").read_text()
                )

    def test_invalid_linkage_leaves_no_output(self):
        outside = self.root / "outside.so"
        outside.write_bytes(b"not an allowed dependency")
        escaped = self.libraries / "escaped.so"
        escaped.symlink_to(outside)
        for linkage, message in [
            ("libc.so.6 => not found\n", "Unresolved"),
            (f"{self.libc} (0x1)\n", "Missing dynamic loader"),
            (f"{self.loader} (0x1)\n{outside} (0x2)\n", "Unexpected"),
            (f"{self.loader} (0x1)\n{escaped} (0x2)\n", "Unexpected"),
            (
                f"{self.loader} (0x1)\n{self.libraries / 'missing.so'} (0x2)\n",
                "Unexpected",
            ),
        ]:
            with self.subTest(linkage=linkage):
                with self.assertRaisesRegex(ValueError, message):
                    self.run_package(linkage=linkage)
                self.assert_no_output()

    def test_missing_glibc_evidence_leaves_no_output(self):
        with self.assertRaisesRegex(ValueError, "Missing GLIBC"):
            self.run_package(versions="No version information found\n")
        self.assert_no_output()

    def test_existing_output_is_preserved_before_running_tools(self):
        self.destination.mkdir()
        evidence = self.destination / "receipt.json"
        evidence.write_bytes(b"original receipt")
        with patch.object(PACKAGE.subprocess, "check_output") as tool:
            with self.assertRaisesRegex(ValueError, "must be new"):
                PACKAGE.package(self.binary, self.destination)
            tool.assert_not_called()
        self.assertEqual(list(self.destination.iterdir()), [evidence])
        self.assertEqual(evidence.read_bytes(), b"original receipt")


if __name__ == "__main__":
    unittest.main()
