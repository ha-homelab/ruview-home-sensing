#!/usr/bin/env python3
"""Execute actual GET handlers with failed response writes.

The pre-fix handlers must reproduce the swallowed error. The fixed handlers
must return the exact SDK error so HTTPD can close the failed session. JSON,
boot identity and retained module counters must remain unchanged. No device,
network socket, flash operation or firmware build is involved.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from test_runtime_diagnostics import function

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "patches/0019-http-status-result.patch"

PRELUDE = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include "wasm_runtime.h"
#include "home_csi_ping.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#define OTA_BOOT_NONCE_SCHEMA "ruview.boot-nonce.v1"
typedef struct { int unused; } httpd_req_t;
typedef struct { char version[32], date[16], time[16]; } esp_app_desc_t;
typedef struct { char label[16]; uint32_t size; } esp_partition_t;
typedef struct { uint8_t bssid[6], primary; int8_t rssi; } wifi_ap_record_t;
static const esp_app_desc_t app={.version="0.8.8.13",.date="Oct 15 2026",.time="00:00:00"};
static const esp_partition_t running={.label="ota_0",.size=2097152};
static const esp_partition_t update={.label="ota_1",.size=2097152};
static bool partitions_present=true, associated=true;
static wasm_module_info_t slots[WASM_MAX_MODULES];
static wasm_resource_info_t resources;
static uint8_t loaded;
static int response_result, send_calls;
static char response[8192];
static size_t response_size;
static const esp_app_desc_t *esp_app_get_description(void) { return &app; }
static const esp_partition_t *esp_ota_get_running_partition(void) { return partitions_present?&running:NULL; }
static const esp_partition_t *esp_ota_get_next_update_partition(const esp_partition_t *unused) {
 CHECK(unused==NULL); return partitions_present?&update:NULL;
}
static const char *ota_boot_nonce(void) { return "7d16ee5045ebd8e6ec68acfba422205a"; }
static const char *ota_boot_station_mac(void) { return "14:c1:9f:26:57:14"; }
static int64_t esp_timer_get_time(void) { return 120000000; }
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *out) {
 CHECK(out); memset(out,0xa5,sizeof(*out));
 if (!associated) return ESP_FAIL;
 const uint8_t bssid[6]={0x02,0xac,0xde,0x77,0x00,0x03};
 memcpy(out->bssid,bssid,6); out->primary=11; out->rssi=-57; return ESP_OK;
}
void wasm_runtime_get_info(wasm_module_info_t *out,uint8_t *count) {
 CHECK(out && count); memcpy(out,slots,sizeof(slots)); *count=loaded;
}
void wasm_runtime_get_resources(wasm_resource_info_t *out) { CHECK(out); *out=resources; }
#if CONFIG_HOME_RUNTIME_RECOVERY_V1
void csi_self_ping_get_status(csi_self_ping_status_t *out) {
 CHECK(out); memset(out,0,sizeof(*out)); out->state=CSI_PING_RUNNING;
 out->supervisor_started=true; out->starts=1; out->successes=100; out->timeouts=3;
 out->last_progress_ms=119999;
}
#endif
static esp_err_t httpd_resp_set_type(httpd_req_t *req,const char *type) {
 CHECK(req && strcmp(type,"application/json")==0); return ESP_OK;
}
static esp_err_t httpd_resp_send(httpd_req_t *req,const char *body,ssize_t length) {
 CHECK(req && body && length>0 && (size_t)length<sizeof(response));
 ++send_calls; response_size=(size_t)length;
 memcpy(response,body,response_size); response[response_size]='\0';
 return response_result;
}
static esp_err_t httpd_resp_send_err(httpd_req_t *req,int status,const char *message) {
 (void)req; (void)status; (void)message; CHECK(false); return ESP_FAIL;
}
"""

SCENARIOS = r"""
static void exercise(esp_err_t (*handler)(httpd_req_t *)) {
 httpd_req_t request={0};
 wasm_module_info_t saved[WASM_MAX_MODULES]; memcpy(saved,slots,sizeof(saved));
 wasm_resource_info_t saved_resources=resources;
 response_result=ESP_OK; send_calls=0;
 CHECK(handler(&request)==ESP_OK && send_calls==1);
 char successful[sizeof(response)]; memcpy(successful,response,response_size+1);
 size_t successful_size=response_size;
 puts(successful);
 /* Generic, send-specific and header-specific SDK failures must not become
    success. An error causes no retry or replacement response in the handler. */
 const int failures[]={ESP_FAIL,0x7002,0x7003};
 for (unsigned i=0;i<sizeof(failures)/sizeof(failures[0]);++i) {
  response_result=failures[i]; send_calls=0;
  int result=handler(&request);
  CHECK(result==(EXPECT_LEGACY?ESP_OK:failures[i]) && send_calls==1);
  CHECK(response_size==successful_size && memcmp(response,successful,response_size+1)==0);
  CHECK(memcmp(saved,slots,sizeof(saved))==0 && memcmp(&saved_resources,&resources,sizeof(resources))==0);
 }
 response_result=ESP_OK; send_calls=0;
 CHECK(handler(&request)==ESP_OK && send_calls==1);
 CHECK(response_size==successful_size && memcmp(response,successful,response_size+1)==0);
}
int main(void) {
 resources.uptime_ms=120000; resources.worker_stack_bytes=20480;
 resources.worker_stack_min_free_bytes=16000; resources.internal_min_free_bytes=30000;
 resources.internal_free_bytes=40000; resources.internal_largest_free_block=20000;
 for (unsigned variant=0;variant<2;++variant) {
  associated=partitions_present=variant==0;
  loaded=variant==0?WASM_MAX_MODULES:0; memset(slots,0,sizeof(slots));
  for (unsigned i=0;i<WASM_MAX_MODULES;++i) {
   slots[i].id=(uint8_t)i;
   if (loaded) {
    slots[i].state=WASM_MODULE_RUNNING; slots[i].binary_size=12345;
    strcpy(slots[i].module_name,"home-signal-v5");
    slots[i].frame_count=100; slots[i].event_count=12; slots[i].error_count=2;
    slots[i].total_us=100000; slots[i].max_us=11839; slots[i].manifest_budget_us=10000;
    slots[i].max_frame_us=11839; slots[i].frame_overruns=7;
    slots[i].max_timer_us=9000; slots[i].timer_overruns=1; slots[i].budget_faults=3;
   }
  }
  exercise(ota_status_handler); exercise(wasm_list_handler);
 }
 return 0;
}
"""


def run_handlers(work, legacy, recovery):
    ota = (work / "main/ota_update.c").read_text()
    wasm = (work / "main/wasm_upload.c").read_text()
    helpers = function(wasm, "static const char *state_name(")
    helpers += function(wasm, "static bool append_json(")
    helpers += "\n#if CONFIG_HOME_RUNTIME_RECOVERY_V1\n"
    helpers += function(wasm, "static const char *self_ping_state_name(")
    helpers += function(wasm, "static bool append_self_ping_json(")
    helpers += "\n#endif\n"
    harness = (
        PRELUDE
        + helpers
        + function(ota, "static esp_err_t ota_status_handler(")
        + function(wasm, "static esp_err_t wasm_list_handler(")
        + SCENARIOS
    )
    source = work / f"status-{legacy}-{recovery}.c"
    source.write_text(harness)
    binary = source.with_suffix("")
    subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-function",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            f"-DEXPECT_LEGACY={int(legacy)}",
            f"-DCONFIG_HOME_RUNTIME_RECOVERY_V1={recovery}",
            "-I" + str(work / "main"),
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    documents = [json.loads(line) for line in result.stdout.splitlines()]
    if len(documents) != 4:
        raise ValueError("Missing successful handler responses")
    for ota_body, wasm_body in zip(documents[::2], documents[1::2], strict=True):
        if bool("boot_nonce" in ota_body) != bool(recovery):
            raise ValueError("OTA boot identity presence changed")
        if bool("boot_nonce" in wasm_body["runtime"]) != bool(recovery):
            raise ValueError("Module boot identity presence changed")
        if recovery and ota_body["boot_nonce"] != wasm_body["runtime"]["boot_nonce"]:
            raise ValueError("GET boot identity mismatch")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    lock = json.loads((ROOT / "upstream-files.json").read_text())["files"]
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        for item in lock:
            relative = Path(item["path"])
            source = args.source / relative
            if hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
                raise ValueError(
                    "Source differs from pinned upstream: " + str(relative)
                )
            target = work / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            if patch.name >= FIX.name:
                break
            subprocess.run(
                ["git", "apply", "--exclude=components/wasm3/wasm3-src/*", str(patch)],
                cwd=work,
                check=True,
            )
        (work / "main/esp_err.h").write_text(
            "#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n"
        )
        (work / "main/edge_processing.h").write_text(
            "#pragma once\ntypedef struct { int unused; } edge_vitals_pkt_t;\n"
        )
        (work / "main/sdkconfig.h").write_text("")
        before = {recovery: run_handlers(work, True, recovery) for recovery in (0, 1)}
        subprocess.run(["git", "apply", str(FIX)], cwd=work, check=True)
        for recovery in (0, 1):
            after = run_handlers(work, False, recovery)
            if after != before[recovery]:
                raise ValueError("Successful GET response bytes changed")
        print("Pre-fix GET handlers reproduced swallowed response errors.")
        print(
            "Fixed actual handlers propagate exact errors; successful JSON, boot identity and retained faults unchanged (recovery disabled/enabled)."
        )


if __name__ == "__main__":
    main()
