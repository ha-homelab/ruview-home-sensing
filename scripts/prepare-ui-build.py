#!/usr/bin/env python3
"""Prepare a private, deterministic UI build context; never build or deploy it."""

import argparse
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.site_context import (  # noqa: E402
    load_pinned_json,
    load_site_context,
    write_private_output,
)

spec = importlib.util.spec_from_file_location(
    "ruview_floor_export", ROOT / "collector/ui/export-floor-config.py"
)
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)

ASSETS = (
    "ui/DashboardTab.js",
    "ui/services/health.service.js",
    "ui/home-floor/home-floor.js",
    "ui/home-floor/node-state.mjs",
)
PANEL_OUTPUT = "ui/home-floor/home-floor.js"
PANEL_SOURCE = PANEL_OUTPUT + ".in"
SOURCE_FILES = (
    "Dockerfile.ui",
    *(PANEL_SOURCE if name == PANEL_OUTPUT else name for name in ASSETS),
)
GENERATION_FILES = (
    "scripts/prepare-ui-build.py",
    "collector/ui/export-floor-config.py",
    "scripts/site_context.py",
)
MAX_SOURCE_BYTES = 2 * 1024 * 1024
BASE_TEMPLATE = "ARG BASE_IMAGE\nFROM --platform=linux/arm64 ${BASE_IMAGE}\n"


def immutable_base(value):
    """Accept a registry/repository digest, never a Dockerfile fragment or tag."""
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("An explicit registry/repository@sha256 digest is required")
    repository, separator, digest = value.partition("@sha256:")
    parts = repository.split("/")
    if (
        separator != "@sha256:"
        or re.fullmatch("[a-f0-9]{64}", digest) is None
        or len(parts) < 2
        or re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?", parts[0])
        is None
        or any(
            re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", part) is None
            for part in parts[1:]
        )
        or (":" in parts[0] and int(parts[0].rsplit(":", 1)[1]) > 65535)
    ):
        raise ValueError("An explicit registry/repository@sha256 digest is required")
    return value


def floorplan_url(value):
    """Permit only an explicit canonical HTTPS origin, safe in the fixed JS literal."""
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not re.fullmatch(r"https://[a-z0-9.-]+(?::[1-9][0-9]{0,4})?/", value)
    ):
        raise ValueError("An explicit canonical HTTPS floorplan origin is required")
    parsed = urlsplit(value)
    host = parsed.hostname
    if (
        host is None
        or len(host) > 253
        or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) is None
            for part in host.split(".")
        )
        or (parsed.port is not None and parsed.port > 65535)
    ):
        raise ValueError("Invalid floorplan origin")
    if re.fullmatch(r"[0-9.]+", host) and str(ipaddress.IPv4Address(host)) != host:
        raise ValueError("A canonical floorplan address is required")
    return value


def build_profile(profile):
    if set(profile) != {"model_id", "floor", "zone_labels", "floorplan_url"}:
        raise ValueError(
            "An approved UI build profile including floorplan_url is required"
        )
    url = floorplan_url(profile["floorplan_url"])
    return {key: value for key, value in profile.items() if key != "floorplan_url"}, url


def read_sources(names):
    """Read only fixed source paths, with no symlink components or special files."""
    result = {}
    for name in names:
        path = ROOT / name
        parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                )
                os.close(parent)
                parent = child
            fd = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size > MAX_SOURCE_BYTES
                ):
                    raise ValueError("UI source must be a bounded regular file")
                with os.fdopen(fd, "rb", closefd=False) as source:
                    raw = source.read(MAX_SOURCE_BYTES + 1)
                after = os.fstat(fd)
                if len(raw) > MAX_SOURCE_BYTES or (
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("UI source changed or exceeded its size limit")
                result[name] = raw
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    return result


def source_snapshot():
    return {
        name.removeprefix("collector/"): raw
        for name, raw in read_sources(
            ["collector/" + name for name in SOURCE_FILES]
        ).items()
    }


def archive(source, geometry, base, provenance, generation, url):
    template = source["Dockerfile.ui"].decode("utf-8")
    if template.count(BASE_TEMPLATE) != 1:
        raise ValueError("Review the changed UI Dockerfile before preparing a context")
    dockerfile = template.replace(
        BASE_TEMPLATE, f"FROM --platform=linux/arm64 {immutable_base(base)}\n", 1
    ).encode()
    panel = source[PANEL_SOURCE]
    if panel.count(b"@@FLOORPLAN_URL@@") != 1:
        raise ValueError(
            "Review the changed UI link template before preparing a context"
        )
    panel = panel.replace(b"@@FLOORPLAN_URL@@", floorplan_url(url).encode("ascii"))
    files = {
        "Dockerfile": dockerfile,
        **{name: panel if name == PANEL_OUTPUT else source[name] for name in ASSETS},
    }
    files["ui/home-floor/floor-config.js"] = geometry
    receipt = {
        "schema": "ruview.private-ui-build.v1",
        "base_image": base,
        "approvals": provenance,
        "source_files_sha256": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in source.items()
        },
        "generation_sources_sha256": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in generation.items()
        },
        "build_files_sha256": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
        },
    }
    files["build-context.json"] = (
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name, raw in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            # COPY must retain readable static assets; the enclosing private
            # archive is mode 0600 and must never be published as an artifact.
            entry.mode = 0o644
            # TarInfo defaults fix uid/gid/mtime to zero and names to empty.
            output.addfile(entry, io.BytesIO(raw))
    return buffer.getvalue()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--site-context", type=Path, required=True)
    parser.add_argument("--site-context-sha256", required=True)
    parser.add_argument(
        "--source-revision", required=True, help="Approved model commit"
    )
    parser.add_argument("--base-image", required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="New private tar file"
    )
    args = parser.parse_args(argv)
    base = immutable_base(args.base_image)
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("Private build contexts must stay outside the source checkout")
    context = load_site_context(args.site_context, args.site_context_sha256)
    model_bytes, model = load_pinned_json(
        args.model, args.model_sha256, export.MAX_MODEL_BYTES
    )
    _, profile = load_pinned_json(args.profile, args.profile_sha256)
    geometry_profile, url = build_profile(profile)
    source = source_snapshot()
    generation = read_sources(GENERATION_FILES)
    geometry = export.render(
        model, model_bytes, geometry_profile, context, args.source_revision
    )
    raw = archive(
        source,
        geometry,
        base,
        {
            "context_manifest_sha256": args.site_context_sha256,
            "model_sha256": args.model_sha256,
            "profile_sha256": args.profile_sha256,
            "model_source_revision": args.source_revision,
        },
        generation,
        url,
    )
    # Re-read the exact approvals and source before publishing complete bytes.
    load_site_context(args.site_context, args.site_context_sha256)
    load_pinned_json(args.model, args.model_sha256, export.MAX_MODEL_BYTES)
    load_pinned_json(args.profile, args.profile_sha256)
    if source_snapshot() != source or read_sources(GENERATION_FILES) != generation:
        raise ValueError("UI source changed while preparing the context")
    write_private_output(args.output, raw)


if __name__ == "__main__":
    main()
