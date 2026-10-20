#!/usr/bin/env python3
"""Retain SDK and prepared-project license texts beside firmware artifacts."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

NOTICE_NAME = re.compile(
    r"(?:^|[-_.])(licen[sc]e|copying|notice|copyright)(?:$|[-_.]|\d)", re.I
)
EXCLUDED_DIRS = {".git", "__pycache__", "build"}
MAX_FILES = 2000
MAX_BYTES = 32 * 1024 * 1024
REQUIRED = {
    "idf": (
        "LICENSE",
        "components/esp_wifi/lib/LICENSE",
        "components/esp_phy/lib/LICENSE",
        "components/esp_coex/lib/LICENSE",
        "components/freertos/FreeRTOS-Kernel/LICENSE.md",
        "components/lwip/lwip/COPYING",
        "components/mbedtls/mbedtls/LICENSE",
        "components/newlib/COPYING.NEWLIB",
        "components/wpa_supplicant/COPYING",
    ),
    "project": (
        "licenses/RuView-LICENSE",
        "components/monocypher/LICENCE.md",
        "components/wasm3/wasm3-src/LICENSE",
    ),
}


def build_bundle(idf_root: Path, project_root: Path, output: Path) -> dict:
    """Copy exact texts, including nested submodules, without editing licenses."""
    if output.exists():
        raise ValueError("License bundle destination must not already exist")
    records = []
    contents = {}
    total = 0
    for label, supplied_root in (("idf", idf_root), ("project", project_root)):
        root = supplied_root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("License source must be a directory")
        if output.resolve().is_relative_to(root):
            raise ValueError("License bundle must be outside its source trees")
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS)
            for name in sorted(files):
                source = Path(directory) / name
                in_license_directory = any(
                    part.lower() in {"licenses", "licences"}
                    for part in source.relative_to(root).parts[:-1]
                )
                if not NOTICE_NAME.search(name) and not in_license_directory:
                    continue
                resolved = source.resolve(strict=True)
                if not resolved.is_relative_to(root) or not resolved.is_file():
                    raise ValueError("License source escapes its source tree")
                relative = source.relative_to(root).as_posix()
                data = resolved.read_bytes()
                if not data.strip():
                    raise ValueError(f"Empty license text: {label}/{relative}")
                total += len(data)
                if len(contents) >= MAX_FILES or total > MAX_BYTES:
                    raise ValueError("License bundle exceeds its bounded inventory")
                target = f"{label}/{relative}"
                contents[target] = data
                records.append(
                    {
                        "path": target,
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
        for relative in REQUIRED[label]:
            if f"{label}/{relative}" not in contents:
                raise ValueError(f"Required license missing: {label}/{relative}")
    manifest = {
        "schema": 1,
        "scope": (
            "License, licence, copying, copyright and notice files from the exact SDK "
            "checkout, its nested submodules and the prepared project. "
            "The inventory can include unused components; inclusion does not "
            "claim that a component is linked or its complete source is supplied."
        ),
        "files": sorted(records, key=lambda item: item["path"]),
    }
    output.mkdir(parents=True)
    for relative, data in contents.items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idf-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_bundle(args.idf_root, args.project_root, args.output)
    print(f"Retained {len(manifest['files'])} firmware license/notice files")


if __name__ == "__main__":
    main()
