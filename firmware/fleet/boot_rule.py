"""Reviewed IDF first-attempt rule, not proof that an installed image boots."""

from pathlib import Path

import build_profile
from fleetlib import require, sha
from plan_migration import TARGET, strict_json

IDF_COMMIT = "67c1de1eebe095d554d281952fde63c16ee2dca0"
IDF_IMAGE = "espressif/idf:v5.4@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb"
IDF_SOURCES = {
    "components/bootloader_support/src/bootloader_utility.c": "5ae38992cce9e7a9f919a9923bf6acbbf6f74a24d4f4c13ce3cf6c488cbe8401",
    "components/bootloader_support/src/bootloader_common_loader.c": "b036254d126187fcfcc4a630e6b21658afeaa93e30456576ab62e856a9204c24",
    "components/bootloader/subproject/main/bootloader_start.c": "02825e360f143711c497b539ad734eab9b38e067f9c0accd9147f8bbe466a7c1",
}
BOOT_ARTIFACTS = (
    "bootloader.bin",
    "partition-table.bin",
    "ota_data_initial.bin",
    "sdkconfig",
)
DISABLED = (
    "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK",
    "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE",
    "CONFIG_BOOTLOADER_FACTORY_RESET",
    "CONFIG_BOOTLOADER_APP_TEST",
    "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP",
    "CONFIG_BOOTLOADER_SKIP_VALIDATE_ON_POWER_ON",
    "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS",
)


def read_regular(path, limit):
    path = Path(path)
    require(
        path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
        "Regular non-symbolic evidence required",
    )
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Evidence exceeds bound")
    return data


def verify_sources(directory):
    actual = {
        name: sha(read_regular(Path(directory) / name, 100_000)) for name in IDF_SOURCES
    }
    require(actual == IDF_SOURCES, "Actual builder IDF boot sources differ")
    return actual


def verify_boot_rule(blobs, layout, evidence_bytes, expected_sha, source_directory):
    """Bind exported builder source/receipt to these exact cached bundle bytes.

    The receipt must be collected from the actual successful build and reviewed
    by the coordinator. This is not a signature or a reproducible-build proof.
    Reference source copies alone cannot establish the binary's build lineage.
    """
    require(sha(evidence_bytes) == expected_sha, "Build evidence digest differs")
    evidence = strict_json(evidence_bytes)
    require(
        set(evidence)
        == {
            "schema_version",
            "idf_commit",
            "idf_image",
            "idf_sources_sha256",
            "bootloader_sources_unmodified",
            "build_exit_code",
            "artifacts_sha256",
        },
        "Unknown boot build evidence schema",
    )
    require(
        type(evidence["schema_version"]) is int
        and evidence["schema_version"] == 1
        and evidence["idf_commit"] == IDF_COMMIT
        and evidence["idf_image"] == IDF_IMAGE
        and evidence["bootloader_sources_unmodified"] is True
        and type(evidence["build_exit_code"]) is int
        and evidence["build_exit_code"] == 0,
        "Pinned successful unmodified IDF build evidence required",
    )
    sources = verify_sources(source_directory)
    require(evidence["idf_sources_sha256"] == sources, "Build source evidence differs")
    artifacts = {name: sha(blobs[name]) for name in BOOT_ARTIFACTS}
    require(evidence["artifacts_sha256"] == artifacts, "Boot build artifacts differ")
    require(
        [
            (p["name"], p["type"], p["subtype"], p["offset"], p["bytes"])
            for p in layout["partitions"]
        ]
        == TARGET
        and layout["md5_verified"] is True,
        "Exact reviewed no-factory two-OTA table required",
    )
    require(
        blobs["ota_data_initial.bin"] == b"\xff" * 0x2000, "OTA metadata not erased"
    )
    config = build_profile.settings(blobs["sdkconfig"], generated=True)
    # Dependent Kconfig options can be absent when their parent is disabled.
    require(
        all(config.get(key, "n") == "n" for key in DISABLED),
        "Boot selection override enabled",
    )
    return {
        "rule": "idf54-erased-otadata-no-factory-first-attempt-ota0",
        "idf_commit": IDF_COMMIT,
        "idf_sources_sha256": sources,
        "build_evidence_sha256": expected_sha,
        "artifacts_sha256": artifacts,
        "first_attempt_partition": "ota_0",
        "first_attempt_offset": 0x20000,
        "fallback_possible_if_image_fails": True,
        "first_boot_may_write_otadata": True,
        "physical_boot_verified": False,
    }
