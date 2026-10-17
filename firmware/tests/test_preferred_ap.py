#!/usr/bin/env python3
"""Exercise the actual optional Wi-Fi policy and ESP-IDF adapter on a host.

No radios, devices, firmware builds or credentials are used. ESP-IDF API seams
are mocked; every policy/core/JSON line comes from the patched pinned source.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    lock = json.loads((ROOT / "upstream-files.json").read_text())
    compiler = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        for item in lock["files"]:
            relative = Path(item["path"])
            require(
                not relative.is_absolute() and ".." not in relative.parts, "Unsafe path"
            )
            source = args.source / relative
            require(
                hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"],
                f"Unpinned source: {relative}",
            )
            destination = work / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            if patch.name > "0013-preferred-ap-recovery.patch":
                continue
            subprocess.run(
                ["git", "apply", "--exclude=components/wasm3/wasm3-src/*", str(patch)],
                cwd=work,
                check=True,
            )
        main_source = (work / "main/main.c").read_text()
        require(
            "if (home_wifi_policy_event(event_base, event_id, event_data)) return;"
            in main_source,
            "Managed events also reach legacy connection logic",
        )
        require(
            "if (!wifi_policy_managed) ESP_ERROR_CHECK(esp_wifi_start());"
            in main_source,
            "Managed start has two owners",
        )
        require(
            "home_wifi_policy_targeted() ? pdMS_TO_TICKS(60000) : portMAX_DELAY"
            in main_source,
            "Wrong-node/MAC startup no longer preserves legacy wait",
        )
        ota = (work / "main/ota_update.c").read_text()
        require(
            ota.index("httpd_start(&server")
            < ota.index("home_wifi_policy_register_http(server)"),
            "Status registered before HTTP server starts",
        )
        require("CONFIG_WASM_ENABLE" not in ota, "WiFi status depends on WASM")
        stub = work / "stubs"
        stub.mkdir()
        shutil.copyfile(FIXTURES / "preferred-ap-idf.h", stub / "preferred-ap-idf.h")
        for name in (
            "esp_wifi.h",
            "esp_event.h",
            "esp_http_server.h",
            "esp_netif.h",
            "esp_timer.h",
            "sdkconfig.h",
            "freertos/FreeRTOS.h",
            "freertos/event_groups.h",
            "freertos/task.h",
        ):
            target = stub / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('#include "preferred-ap-idf.h"\n')
        profiles = (
            (
                "enabled-s3",
                1,
                "CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE",
                "CONFIG_IDF_TARGET_ESP32S3",
                "CONFIG_HOME_CSI_ASSOCIATED_ONLY",
            ),
            (
                "disabled-s3",
                0,
                "CONFIG_IDF_TARGET_ESP32S3",
                "CONFIG_HOME_CSI_ASSOCIATED_ONLY",
            ),
            (
                "ambient-s3",
                0,
                "CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE",
                "CONFIG_IDF_TARGET_ESP32S3",
            ),
            (
                "associated-c6",
                0,
                "CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE",
                "CONFIG_IDF_TARGET_ESP32C6",
                "CONFIG_HOME_CSI_ASSOCIATED_ONLY",
            ),
        )
        max_json = 0
        for name, enabled, *defines in profiles:
            binary = work / name
            command = [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-pthread",
                "-I" + str(stub),
                "-I" + str(work / "main"),
                f"-DEXPECT_ACTIVE={enabled}",
                "-DCONFIG_HOME_WIFI_PREFERRED_NODE_ID=2",
                '-DCONFIG_HOME_WIFI_PREFERRED_BSSID="02:00:00:00:01:02"',
                '-DCONFIG_HOME_WIFI_PREFERRED_STA_MAC="02:00:00:00:00:02"',
            ]
            command.extend("-D" + define + "=1" for define in defines)
            command += [
                str(FIXTURES / "preferred-ap-host.c"),
                str(work / "main/home_wifi_policy_core.c"),
                "-o",
                str(binary),
            ]
            subprocess.run(command, check=True)
            lines = subprocess.check_output([str(binary)], text=True).splitlines()
            if enabled:
                require(len(lines) == 3, "Missing actual JSON cases")
                documents = [json.loads(line) for line in lines]
                require(documents[0]["boot_scan"]["count"] == 16, "Scan bound changed")
                require(documents[1]["attempts"] == 2**32 - 1, "Counter truncated")
                require(
                    documents[1]["next_attempt_ms"] == 2**64 - 1, "Timestamp truncated"
                )
                require(
                    len(documents[1]["boot_scan"]["aps"]) == 16,
                    "Maximum scan JSON truncated",
                )
                require(
                    documents[2]["association"]["bssid"] is None,
                    "Stale AP data exposed on error",
                )
                require(
                    documents[2]["effective"]["valid"] is False,
                    "Failed config read reported valid",
                )
                max_json = max(map(len, lines))
        print(
            f"PASS: four profiles; actual adapter failures, scan/deadline/reconnect races, security retention, "
            f"20,000-event mailbox, saturation and JSON under ASan/UBSan ({max_json}/4096 bytes)"
        )


if __name__ == "__main__":
    main()
