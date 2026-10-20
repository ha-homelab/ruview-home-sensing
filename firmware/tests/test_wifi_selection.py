#!/usr/bin/env python3
"""Exercise the patched STA initializer and actual /wasm/list handler on a host.

The compile profiles verify selection and cipher scope without simulating RF quality.
The response tests use the real runtime structures and JSON handler, maximum
valid field widths, and a stub for the read-only AP snapshot. They do not qualify
ESP32 timing, association success, or antenna performance.
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


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine, pinned firmware source")
    args = parser.parse_args()
    lock = {
        entry["path"]: entry["sha256"]
        for entry in json.loads((ROOT / "upstream-files.json").read_text())["files"]
    }
    compiler = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        (work / "main").mkdir()
        for name in (
            "main.c",
            "wasm_runtime.c",
            "wasm_runtime.h",
            "wasm_upload.c",
            "ota_update.c",
            "Kconfig.projbuild",
        ):
            relative = "main/" + name
            source = args.source / relative
            require(
                hashlib.sha256(source.read_bytes()).hexdigest() == lock[relative],
                f"Source is not the pinned upstream file: {relative}",
            )
            shutil.copy(source, work / relative)
        for patch in (
            "0003-wasm-runtime-lifecycle.patch",
            "0006-http-task-stack.patch",
            "0007-wasm-native-worker.patch",
            "0010-associated-ap-selection.patch",
            "0011-wasm-lifecycle-and-callback-telemetry.patch",
            "0020-wifi-cipher-policy.patch",
        ):
            subprocess.run(
                ["git", "apply", str(ROOT / "patches" / patch)], cwd=work, check=True
            )

        config = (work / "main/Kconfig.projbuild").read_text()
        policy_config = config.split("config HOME_WIFI_ALLOW_LEGACY_SECURITY", 1)[1]
        require(
            "default n" in policy_config.split("endmenu", 1)[0],
            "Insecure legacy policy must be disabled by default",
        )
        source = (work / "main/main.c").read_text()
        start = source.index("    wifi_config_t wifi_config = {")
        end = source.index("    /* Copy runtime SSID/password", start)
        initializer = source[start:end]
        harness = work / "selection.c"
        harness.write_text(
            """#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) abort(); } while (0)
enum { WIFI_FAST_SCAN = 0, WIFI_ALL_CHANNEL_SCAN = 1 };
enum { WIFI_CONNECT_AP_BY_SIGNAL = 0, WIFI_CONNECT_AP_BY_SECURITY = 1 };
enum { WIFI_AUTH_OPEN = 0, WIFI_AUTH_WPA_PSK = 2, WIFI_AUTH_WPA2_PSK = 3 };
typedef struct {
    uint8_t ssid[32], password[64];
    int scan_method;
    bool bssid_set;
    uint8_t bssid[6], channel;
    int sort_method;
    struct { int8_t rssi; int authmode; } threshold;
} wifi_sta_config_t;
typedef union { wifi_sta_config_t sta; } wifi_config_t;
int main(void) {
"""
            + initializer
            + """
    CHECK(wifi_config.sta.scan_method ==
          (EXPECT_ALL_CHANNELS ? WIFI_ALL_CHANNEL_SCAN : WIFI_FAST_SCAN));
    CHECK(wifi_config.sta.sort_method == WIFI_CONNECT_AP_BY_SIGNAL);
#if defined(CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY) && CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY
    CHECK(wifi_config.sta.threshold.authmode == WIFI_AUTH_WPA_PSK);
#else
    CHECK(wifi_config.sta.threshold.authmode == WIFI_AUTH_WPA2_PSK);
#endif
    CHECK(wifi_config.sta.threshold.rssi == 0);
    CHECK(wifi_config.sta.channel == 0 && !wifi_config.sta.bssid_set);
    for (unsigned i = 0; i < sizeof(wifi_config.sta.bssid); ++i)
        CHECK(wifi_config.sta.bssid[i] == 0);
    for (unsigned i = 0; i < sizeof(wifi_config.sta.ssid); ++i)
        CHECK(wifi_config.sta.ssid[i] == 0);
    for (unsigned i = 0; i < sizeof(wifi_config.sta.password); ++i)
        CHECK(wifi_config.sta.password[i] == 0);
    return 0;
}
"""
        )
        profiles = (
            (
                "associated-s3",
                1,
                "CONFIG_HOME_CSI_ASSOCIATED_ONLY",
                "CONFIG_IDF_TARGET_ESP32S3",
            ),
            ("ambient-s3", 0, "CONFIG_IDF_TARGET_ESP32S3"),
            (
                "associated-c6",
                0,
                "CONFIG_HOME_CSI_ASSOCIATED_ONLY",
                "CONFIG_IDF_TARGET_ESP32C6",
            ),
        )
        for name, expected, *defines in profiles:
            for legacy in (None, 0, 1):
                binary = work / name
                flags = (
                    []
                    if legacy is None
                    else [f"-DCONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY={legacy}"]
                )
                subprocess.run(
                    [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror"]
                    + ["-D" + define + "=1" for define in defines]
                    + flags
                    + [
                        f"-DEXPECT_ALL_CHANNELS={expected}",
                        str(harness),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                )
                subprocess.run([str(binary)], check=True)

        (work / "main/esp_err.h").write_text(
            "#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n"
        )
        (work / "main/edge_processing.h").write_text(
            "#pragma once\ntypedef struct { int unused; } edge_vitals_pkt_t;\n"
        )
        source = (work / "main/wasm_upload.c").read_text()
        start = source.index("static const char *state_name(")
        end = source.index(
            "/* ======================================================================",
            start,
        )
        handler = source[start:end]
        require(
            "static esp_err_t wasm_list_handler(" in handler, "Handler not extracted"
        )
        response_source = work / "response.c"
        response_source.write_text(
            """#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>
#define ESP_FAIL -1
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#include "wasm_runtime.h"
#define CHECK(x) do { if (!(x)) abort(); } while (0)
typedef struct { int unused; } httpd_req_t;
typedef struct { uint8_t bssid[6], primary; int8_t rssi; } wifi_ap_record_t;
static int ap_result, ap_reads;
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap) {
    ++ap_reads;
    memset(ap, 0xa5, sizeof(*ap)); /* Errors deliberately leave stale data. */
    if (ap_result == ESP_OK) {
        const uint8_t mac[6] = {0xab, 0xcd, 0xef, 0x01, 0x23, 0x45};
        memcpy(ap->bssid, mac, sizeof(mac));
        ap->primary = 13;
        ap->rssi = INT8_MIN;
    }
    return ap_result;
}
void wasm_runtime_get_info(wasm_module_info_t *info, uint8_t *count) {
    memset(info, 0, sizeof(*info) * WASM_MAX_MODULES);
    *count = WASM_MAX_MODULES;
    for (unsigned i = 0; i < WASM_MAX_MODULES; ++i) {
        info[i].id = i;
        info[i].state = WASM_MODULE_RUNNING;
        memset(info[i].module_name, 'm', sizeof(info[i].module_name) - 1);
        info[i].binary_size = UINT32_MAX;
        info[i].frame_count = 1; /* Maximum mean_us while total_us is uint32. */
        info[i].event_count = UINT32_MAX;
        info[i].error_count = UINT32_MAX;
        info[i].total_us = UINT32_MAX;
        info[i].max_us = UINT32_MAX;
        info[i].budget_faults = UINT32_MAX;
        info[i].max_frame_us = UINT32_MAX;
        info[i].max_timer_us = UINT32_MAX;
        info[i].frame_overruns = UINT32_MAX;
        info[i].timer_overruns = UINT32_MAX;

        info[i].capabilities = UINT32_MAX;
        info[i].manifest_budget_us = UINT32_MAX;
    }
}
void wasm_runtime_get_resources(wasm_resource_info_t *resources) {
    memset(resources, 0xff, sizeof(*resources));
}
static esp_err_t httpd_resp_send_err(httpd_req_t *req, int status, const char *message) {
    (void)req; (void)status; (void)message; abort();
}
static esp_err_t httpd_resp_set_type(httpd_req_t *req, const char *type) {
    (void)req;
    CHECK(strcmp(type, "application/json") == 0);
    return ESP_OK;
}
static esp_err_t httpd_resp_send(httpd_req_t *req, const char *body, int length) {
    (void)req;
    CHECK(length > 0 && length < 4096);
    CHECK((size_t)length == strlen(body));
    CHECK(fwrite(body, 1, length, stdout) == (size_t)length);
    putchar('\n');
    return ESP_OK;
}
""".replace("putchar('\n')", "putchar('\\n')")
            + handler
            + """
int main(void) {
    char small[4]; size_t used = 0;
    CHECK(append_json(small, sizeof(small), &used, "%s", "abc"));
    CHECK(used == 3);
    CHECK(!append_json(small, sizeof(small), &used, "%s", "def"));
    CHECK(used == 3); /* A truncated append must never advance its offset. */
    used = sizeof(small);
    CHECK(!append_json(small, sizeof(small), &used, "%s", "x"));
    httpd_req_t req = {0};
    const int results[] = {ESP_OK, 0x300f, -1, INT_MIN};
    for (unsigned i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        ap_result = results[i];
        CHECK(wasm_list_handler(&req) == ESP_OK);
        CHECK(ap_reads == (int)i + 1);
    }
    return 0;
}
"""
        )
        binary = work / "response"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I" + str(work / "main"),
                str(response_source),
                "-o",
                str(binary),
            ],
            check=True,
        )
        output = subprocess.check_output([str(binary)], text=True).splitlines()
        require(len(output) == 4, "Missing AP cases")
        for line, error in zip(output, (0, 0x300F, -1, -(2**31)), strict=True):
            document = json.loads(line)
            require(document["loaded"] == document["max"] == 4, "Slot metadata changed")
            require(len(document["modules"]) == 4, "Truncated module slots")
            for index, module in enumerate(document["modules"]):
                require(module["id"] == index, "Incorrect slot ID")
                require(module["name"] == "m" * 31, "Truncated maximum module name")
                require(module["mean_us"] == 2**32 - 1, "Truncated maximum counter")
                for field in (
                    "max_frame_us",
                    "max_timer_us",
                    "frame_overruns",
                    "timer_overruns",
                ):
                    require(module[field] == 2**32 - 1, "Truncated callback telemetry")
            require(document["runtime"]["uptime_ms"] == 2**64 - 1, "Uptime truncated")
            expected = {
                "associated": error == 0,
                "bssid": "ab:cd:ef:01:23:45" if error == 0 else None,
                "channel": 13 if error == 0 else None,
                "rssi_dbm": -128 if error == 0 else None,
                "ap_info_error": error,
            }
            require(document["wifi"] == expected, "Incorrect AP/error/null snapshot")
        print(
            "Nine actual-source STA/security profiles and four full-slot AP JSON cases passed "
            f"under ASan/UBSan; maximum response {max(map(len, output))}/4096 bytes."
        )


if __name__ == "__main__":
    main()
