#!/usr/bin/env python3
"""Private per-board build inputs and sdkconfig checks; no device or key access.

This stdlib-only helper can also run in a copied worker build cache. A build profile
does not authorize installation or assert that its flash layout fits a board.
"""

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

PROFILE_KEYS = {
    "schema_version",
    "profile",
    "hardware_profile",
    "firmware_version",
    "node_id",
    "station_mac",
    "ap_policy",
    "preferred_bssid",
    "overlay_sha256",
    "plan_sha256",
    "flash_write_authorized",
    "layout_changes_authorized",
}
CONFIG_NAME = "sdkconfig.fleet-reviewed"
PREFERRED_CONFIG_NAME = "sdkconfig.home-node2-preferred-ap"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mac(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value)
        and value != "00:00:00:00:00:00"
        and not int(value[:2], 16) & 1,
        "Expected lowercase unicast MAC",
    )
    return value


def version(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){2,3}", value),
        "Version must contain three or four numeric components",
    )
    return value


def settings(data, *, generated=False):
    result = {}
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        disabled = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if disabled:
            key, value = disabled[1], "n"
        elif line.startswith("#"):
            continue
        else:
            match = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.*)", line)
            require(match is not None, "Invalid sdkconfig assignment")
            key, value = match[1], match[2]
        # ESP-IDF can repeat identical compatibility aliases in generated
        # sdkconfig. Overlays must stay unique; conflicting repeats never pass.
        require(
            key not in result or (generated and result[key] == value),
            "Duplicate/conflicting sdkconfig key",
        )
        result[key] = value
    return result


def expected_overlay(profile):
    expected = {
        "CONFIG_LED_GAMMA_VIZ": "n",
        "CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE": "n",
    }
    # Recovery v1 changes the upload protocol. Never enable it implicitly in
    # a historical build carrying an older version string.
    if profile["firmware_version"] in {"0.8.8.10", "0.8.8.11", "0.8.8.12"}:
        expected["CONFIG_HOME_RUNTIME_RECOVERY_V1"] = "y"
    if profile["ap_policy"] == "preferred_with_fallback":
        expected.update(
            {
                "CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE": "y",
                "CONFIG_HOME_WIFI_PREFERRED_NODE_ID": str(profile["node_id"]),
                "CONFIG_HOME_WIFI_PREFERRED_STA_MAC": json.dumps(
                    profile["station_mac"]
                ),
                "CONFIG_HOME_WIFI_PREFERRED_BSSID": json.dumps(
                    profile["preferred_bssid"]
                ),
            }
        )
    return expected


def read_preferred_overlay(path, expected_sha256):
    """Authenticate the exact private overlay before parsing or using its values."""
    require(
        isinstance(expected_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_sha256),
        "An independently approved preferred-AP SHA256 is required",
    )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(metadata.st_mode)
                and not metadata.st_mode & 0o077
                and 0 < metadata.st_size <= 65536,
                "Preferred-AP input must be a private bounded regular file",
            )
            raw = stream.read(65537)
    except OSError:
        raise ValueError(
            "Cannot read the required private preferred-AP input"
        ) from None
    require(
        len(raw) <= 65536 and sha(raw) == expected_sha256,
        "Preferred-AP approval mismatch",
    )
    return raw, preferred_profile(raw)


def preferred_profile(overlay):
    """Retain the legacy node-2/version/radio contract without source identities."""
    config = settings(overlay)
    try:
        station = json.loads(config["CONFIG_HOME_WIFI_PREFERRED_STA_MAC"])
        bssid = json.loads(config["CONFIG_HOME_WIFI_PREFERRED_BSSID"])
    except (KeyError, TypeError, ValueError):
        raise ValueError(
            "Preferred-AP input requires explicit quoted identities"
        ) from None
    profile = {
        "firmware_version": "0.8.8.8",
        "node_id": 2,
        "station_mac": mac(station),
        "preferred_bssid": mac(bssid),
        "ap_policy": "preferred_with_fallback",
    }
    require(
        config == expected_overlay(profile),
        "Preferred-AP input differs from the exact legacy radio/RGB contract",
    )
    return profile


def configure_preferred(path, expected_sha256, project):
    overlay, profile = read_preferred_overlay(path, expected_sha256)
    require(project.is_dir(), "Expected prepared IDF project")
    require(not (project / "sdkconfig").exists(), "Use a fresh sdkconfig")
    target = project / PREFERRED_CONFIG_NAME
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(overlay)
    (project / "version.txt").write_text(profile["firmware_version"] + "\n")


def verify_preferred(path, expected_sha256, config):
    _, profile = read_preferred_overlay(path, expected_sha256)
    verify_configuration(profile, settings(config.read_bytes(), generated=True))


def validate(profile, overlay):
    require(set(profile) == PROFILE_KEYS, "Unknown/missing build profile fields")
    require(
        type(profile["schema_version"]) is int and profile["schema_version"] == 1,
        "Unknown build profile schema",
    )
    require(
        profile["profile"] == "fleet-reviewed"
        and profile["hardware_profile"] == "home-s3-n16r8",
        "Unsupported build profile",
    )
    require(
        type(profile["node_id"]) is int and 1 <= profile["node_id"] <= 10,
        "Invalid physical unit ID",
    )
    mac(profile["station_mac"])
    version(profile["firmware_version"])
    require(
        profile["ap_policy"]
        in ("preferred_with_fallback", "associated_auto_all_channel"),
        "Unknown AP policy",
    )
    if profile["ap_policy"] == "preferred_with_fallback":
        mac(profile["preferred_bssid"])
    else:
        require(
            profile["preferred_bssid"] is None, "Automatic AP policy cannot pin an AP"
        )
    require(
        profile["flash_write_authorized"] is False
        and profile["layout_changes_authorized"] is False,
        "Build inputs cannot authorize installation",
    )
    for key in ("overlay_sha256", "plan_sha256"):
        require(
            isinstance(profile[key], str)
            and re.fullmatch(r"[0-9a-f]{64}", profile[key]),
            "Invalid provenance digest",
        )
    require(
        sha(overlay) == profile["overlay_sha256"], "Reviewed overlay digest mismatch"
    )
    require(
        settings(overlay) == expected_overlay(profile),
        "Overlay differs from exact reviewed AP/RGB allowlist",
    )
    return profile


def prepare(plan_bytes, overlay, firmware_version):
    plan = json.loads(plan_bytes)
    hardware = plan["hardware"]
    require(
        hardware["chip"] == "ESP32-S3"
        and type(hardware["flash_bytes"]) is int
        and hardware["flash_bytes"] == 16 * 1024 * 1024
        and type(hardware.get("embedded_psram_bytes")) is int
        and hardware["embedded_psram_bytes"] == 8 * 1024 * 1024,
        "No reviewed hardware build profile",
    )
    require(hardware["mac"] == plan["binding"]["mac"], "Plan hardware/binding mismatch")
    require(
        plan["flash_write_authorized"] is False
        and plan["layout_changes_authorized"] is False
        and plan["rgb_animation_enabled"] is False,
        "Invalid candidate plan scope",
    )
    profile = {
        "schema_version": 1,
        "profile": "fleet-reviewed",
        "hardware_profile": "home-s3-n16r8",
        "firmware_version": version(firmware_version),
        "node_id": plan["binding"]["node_id"],
        "station_mac": plan["binding"]["mac"],
        "ap_policy": plan["ap_policy"]["mode"],
        "preferred_bssid": plan["ap_policy"]["preferred_bssid"],
        "overlay_sha256": sha(overlay),
        "plan_sha256": sha(plan_bytes),
        "flash_write_authorized": False,
        "layout_changes_authorized": False,
    }
    return validate(profile, overlay)


def public_file(path, data):
    if path.exists():
        require(
            not path.is_symlink() and path.read_bytes() == data,
            "Refusing to replace different build inputs",
        )
        return
    with path.open("xb") as stream:
        stream.write(data)


def export(directory, profile, overlay):
    validate(profile, overlay)
    directory.mkdir(parents=True, exist_ok=True)
    public_file(directory / "build_profile.py", Path(__file__).read_bytes())
    public_file(
        directory / "profile.json",
        (json.dumps(profile, sort_keys=True, indent=2) + "\n").encode(),
    )
    public_file(directory / CONFIG_NAME, overlay)


def load(directory):
    overlay = (directory / CONFIG_NAME).read_bytes()
    profile = json.loads((directory / "profile.json").read_text())
    return validate(profile, overlay), overlay


def configure(directory, project):
    profile, overlay = load(directory)
    require(project.is_dir(), "Expected prepared IDF project")
    # A cached generated sdkconfig would take precedence over new defaults.
    require(
        not (project / "sdkconfig").exists(),
        "Use a fresh sdkconfig or separately clear generated cached configuration",
    )
    (project / CONFIG_NAME).write_bytes(overlay)
    (project / "version.txt").write_text(profile["firmware_version"] + "\n")


def verify_sdkconfig(directory, config):
    profile, _ = load(directory)
    verify_configuration(profile, settings(config.read_bytes(), generated=True))


def verify_configuration(profile, actual):
    require(
        actual.get("CONFIG_HOME_RUNTIME_RECOVERY_V1", "n")
        == (
            "y"
            if profile["firmware_version"] in {"0.8.8.10", "0.8.8.11", "0.8.8.12"}
            else "n"
        ),
        "Recovery protocol differs from the explicitly reviewed version",
    )
    required = {
        **expected_overlay(profile),
        "CONFIG_IDF_TARGET": '"esp32s3"',
        "CONFIG_ESPTOOLPY_FLASHSIZE": '"16MB"',
        "CONFIG_ESPTOOLPY_FLASHMODE_DIO": "y",
        "CONFIG_ESPTOOLPY_FLASHFREQ_80M": "y",
        "CONFIG_SPIRAM": "y",
        "CONFIG_SPIRAM_MODE_OCT": "y",
        "CONFIG_SPIRAM_MEMTEST": "y",
        "CONFIG_ESP_WIFI_STATIC_TX_BUFFER": "y",
        "CONFIG_ESP_WIFI_TX_BUFFER_TYPE": "0",
        "CONFIG_HOME_CSI_ASSOCIATED_ONLY": "y",
        "CONFIG_WASM_ENABLE": "y",
        "CONFIG_WASM_VERIFY_SIGNATURE": "y",
        "CONFIG_WASM_MAX_MODULES": "4",
        "CONFIG_DISPLAY_ENABLE": "n",
        "CONFIG_CSI_MOCK_ENABLED": "n",
    }
    require(
        all(actual.get(key) == value for key, value in required.items()),
        "Generated sdkconfig differs from reviewed hardware/radio/runtime/RGB profile",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("prepare")
    for key in ("plan", "overlay", "output"):
        command.add_argument("--" + key, type=Path, required=True)
    command.add_argument("--version", required=True)
    command = sub.add_parser("configure")
    command.add_argument("directory", type=Path)
    command.add_argument("project", type=Path)
    command = sub.add_parser("verify")
    command.add_argument("directory", type=Path)
    command.add_argument("sdkconfig", type=Path)
    for name in ("check-preferred", "configure-preferred", "verify-preferred"):
        command = sub.add_parser(name)
        command.add_argument("overlay", type=Path)
        command.add_argument("expected_sha256")
        if name == "configure-preferred":
            command.add_argument("project", type=Path)
        elif name == "verify-preferred":
            command.add_argument("sdkconfig", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        overlay = args.overlay.read_bytes()
        export(
            args.output, prepare(args.plan.read_bytes(), overlay, args.version), overlay
        )
    elif args.command == "configure":
        configure(args.directory, args.project)
    elif args.command == "verify":
        verify_sdkconfig(args.directory, args.sdkconfig)
    elif args.command == "check-preferred":
        read_preferred_overlay(args.overlay, args.expected_sha256)
    elif args.command == "configure-preferred":
        configure_preferred(args.overlay, args.expected_sha256, args.project)
    else:
        verify_preferred(args.overlay, args.expected_sha256, args.sdkconfig)


if __name__ == "__main__":
    main()
