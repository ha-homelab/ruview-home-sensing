"""Host execution of the actual opt-in boot/restart/upload/status handlers.

Pinned pristine source is patched locally; no radio, key store, socket, firmware
write or device is touched. Entropy and timers are deterministic host doubles.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from test_runtime_diagnostics import function

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE -2
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define HTTPD_400_BAD_REQUEST 400
#define HTTPD_403_FORBIDDEN 403
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#define HTTPD_RESP_USE_STRLEN -1
#define HTTPD_SOCK_ERR_TIMEOUT -3
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define WIFI_IF_STA 0
#define ESP_TIMER_TASK 0
#define WASM_MAX_MODULES 4
#define MAX_UPLOAD_SIZE 200000
#define OTA_PSK_MAX_LEN 65
#define CONFIG_WASM_ENABLE 1
typedef int esp_err_t;
typedef struct { const char *expected, *auth; int content_len; } httpd_req_t;
typedef void *esp_timer_handle_t;
typedef struct { void (*callback)(void*); void *arg; int dispatch_method; const char *name; } esp_timer_create_args_t;
typedef struct { const char *version,*date,*time; } esp_app_desc_t;
typedef struct { size_t size; const char *label; } esp_partition_t;
static const esp_app_desc_t app={"0.8.8.10","Oct 6 2026","22:00:00"};
static const esp_partition_t running={2097152,"ota_0"}, update={2097152,"ota_1"};
static char s_ota_psk[OTA_PSK_MAX_LEN]="synthetic-test-key";
static char response[8192];
static int response_code=200, send_result=ESP_OK, header_result=ESP_OK;
static int allocations, receives, parses, loads, starts, mutations, auth_reads;
#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1
static int rng_calls, mac_calls, mac_result, entropy_base=1;
static uint8_t mocked_mac[6]={0x02,0xac,0xde,0x77,0x00,0x01};
static bool zero_entropy;
static int timer_creates,timer_starts,create_result,start_result,restarts;
static uint64_t armed_delay;
static void (*armed_callback)(void*);
static void *armed_argument;
static esp_err_t esp_wifi_get_mac(int iface,uint8_t *out) { CHECK(iface==WIFI_IF_STA); ++mac_calls; memcpy(out,mocked_mac,6);return mac_result; }
static void esp_fill_random(void *out,size_t n) { CHECK(n==16); ++rng_calls; for(size_t i=0;i<n;i++) ((uint8_t*)out)[i]=zero_entropy?0:(uint8_t)(entropy_base+i); }
static esp_err_t esp_timer_create(const esp_timer_create_args_t *a,esp_timer_handle_t *out) { ++timer_creates; CHECK(a->dispatch_method==ESP_TIMER_TASK);if(create_result)return create_result; armed_callback=a->callback;armed_argument=a->arg;*out=(void*)1;return ESP_OK; }
static esp_err_t esp_timer_start_once(esp_timer_handle_t timer,uint64_t us) { CHECK(timer==(void*)1); ++timer_starts;if(start_result)return start_result;armed_delay=us;return ESP_OK; }
static void esp_restart(void) { ++restarts; }
static size_t httpd_req_get_hdr_value_len(httpd_req_t *r,const char *name) { CHECK(!strcmp(name,"X-RuView-Expected-Boot-Nonce"));return r->expected?strlen(r->expected):0; }
#endif
static esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r,const char *name,char *out,size_t cap) {
 const char *value=r->expected;
 if(!strcmp(name,"Authorization")) { ++auth_reads;value=r->auth; }
 if(!value || strlen(value)>=cap || header_result!=ESP_OK)return ESP_FAIL;
 memcpy(out,value,strlen(value)+1);return ESP_OK;
}
static esp_err_t httpd_resp_send_err(httpd_req_t *r,int code,const char *message) { (void)r;response_code=code;snprintf(response,sizeof(response),"%s",message);return ESP_OK; }
#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1
static esp_err_t httpd_resp_set_status(httpd_req_t *r,const char *status) { (void)r;response_code=atoi(status);return ESP_OK; }
#endif
static esp_err_t httpd_resp_set_type(httpd_req_t *r,const char *type) { (void)r;CHECK(!strcmp(type,"application/json"));return ESP_OK; }
static esp_err_t httpd_resp_send(httpd_req_t *r,const char *body,int n) { (void)r;if(n==HTTPD_RESP_USE_STRLEN)n=(int)strlen(body);CHECK(n>=0 && (size_t)n<sizeof(response));CHECK((size_t)n==strlen(body));memcpy(response,body,(size_t)n+1);return send_result; }
static const esp_app_desc_t *esp_app_get_description(void) { return &app; }
static const esp_partition_t *esp_ota_get_running_partition(void) { return &running; }
static const esp_partition_t *esp_ota_get_next_update_partition(void *unused) { (void)unused;return &update; }
static const char *esp_err_to_name(int error) { (void)error;return "synthetic_error"; }
static void *heap_caps_malloc(size_t n,int caps) { CHECK(caps==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));++allocations;return malloc(n); }
static int httpd_req_recv(httpd_req_t *r,char *out,size_t size) { CHECK(size==(size_t)r->content_len);++receives;memset(out,0x55,size);return (int)size; }
typedef struct { char module_name[32];uint32_t capabilities,max_frame_us; } rvf_manifest_t;
static rvf_manifest_t manifest={"home-signal-v3",0,10000};
typedef struct { const uint8_t *wasm_data,*signature;uint32_t wasm_len;rvf_manifest_t *manifest; } rvf_parsed_t;
typedef struct { bool wasm_pubkey_valid;uint8_t wasm_pubkey[32]; } nvs_config_t;
nvs_config_t g_nvs_config={.wasm_pubkey_valid=true};
static bool rvf_is_rvf(const uint8_t *b,uint32_t n) { CHECK(b && n);++parses;return true; }
static bool rvf_is_raw_wasm(const uint8_t *b,uint32_t n) { (void)b;(void)n;return false; }
static esp_err_t rvf_parse(const uint8_t *b,uint32_t n,rvf_parsed_t *out) { out->wasm_data=b;out->wasm_len=n;out->signature=b;out->manifest=&manifest;return ESP_OK; }
static esp_err_t rvf_verify_signature(rvf_parsed_t *p,const uint8_t *b,const uint8_t *key) { CHECK(p && b && key);return ESP_OK; }
static esp_err_t wasm_runtime_load(const uint8_t *b,uint32_t n,uint8_t *id) { CHECK(b && n);++loads;++mutations;*id=0;return ESP_OK; }
static void wasm_runtime_set_manifest(uint8_t id,const char *name,uint32_t caps,uint32_t budget) { CHECK(id==0 && name && caps==0 && budget==10000);++mutations; }
static esp_err_t wasm_runtime_start(uint8_t id) { CHECK(id==0);++starts;++mutations;return ESP_OK; }
typedef enum { WASM_MODULE_EMPTY,WASM_MODULE_LOADED,WASM_MODULE_RUNNING,WASM_MODULE_STOPPED,WASM_MODULE_ERROR } wasm_module_state_t;
typedef struct { uint8_t id;wasm_module_state_t state;char module_name[32];uint32_t binary_size,capabilities,frame_count,event_count,error_count,total_us,max_us,manifest_budget_us,budget_faults,max_frame_us,max_timer_us,frame_overruns,timer_overruns; } wasm_module_info_t;
typedef struct { uint64_t uptime_ms;uint32_t worker_stack_bytes,worker_stack_min_free_bytes,internal_min_free_bytes,internal_free_bytes,internal_largest_free_block; } wasm_resource_info_t;
typedef struct { uint8_t bssid[6],primary;int rssi; } wifi_ap_record_t;
static bool maximum_width;
/* SELF_PING_TYPES */
#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1
static int health_mode, getter_calls;
static int64_t esp_timer_get_time(void) { return health_mode==3?-1:maximum_width?INT64_MAX:123456000; }
static void csi_self_ping_get_status(csi_self_ping_status_t *p) {
 ++getter_calls;memset(p,maximum_width?0xff:0,sizeof(*p));
 p->state=maximum_width?CSI_PING_INIT_FAILED:CSI_PING_RUNNING;p->supervisor_started=true;
 p->last_error=maximum_width?INT32_MIN:0;
 p->last_progress_ms=maximum_width?1:health_mode==1?0:health_mode==2?123457:123400;
}
#endif
static void wasm_runtime_get_info(wasm_module_info_t *out,uint8_t *count) {
 memset(out,maximum_width?0xff:0,sizeof(*out)*4);
 for(int i=0;i<4;i++) { out[i].id=i;out[i].state=maximum_width?WASM_MODULE_RUNNING:WASM_MODULE_EMPTY;
  if(maximum_width) { memset(out[i].module_name,'a',31);out[i].module_name[31]=0; } }
 *count=maximum_width?4:0;
}
static void wasm_runtime_get_resources(wasm_resource_info_t *r) { if(maximum_width) { memset(r,0xff,sizeof(*r));return; } *r=(wasm_resource_info_t){.uptime_ms=123456,.worker_stack_bytes=8192,.worker_stack_min_free_bytes=6000,.internal_min_free_bytes=50000,.internal_free_bytes=80000,.internal_largest_free_block=65000}; }
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *a) { *a=(wifi_ap_record_t){.bssid={0x02,0xac,0xde,0x77,0x10,0x01},.primary=6,.rssi=-30};return ESP_OK; }
"""

TESTS = r"""
static void request_reset(void) { response_code=200;response[0]=0;send_result=ESP_OK;header_result=ESP_OK;allocations=receives=parses=loads=starts=mutations=auth_reads=0; }
#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1
static void new_boot(void) {
 s_boot_identity_attempted=false;s_boot_identity_error=ESP_ERR_INVALID_STATE;
 memset(s_boot_nonce,0,sizeof(s_boot_nonce));memset(s_boot_station_mac,0,sizeof(s_boot_station_mac));
 s_restart_timer=NULL;s_restart_pending=false;timer_creates=timer_starts=restarts=0;armed_delay=0;armed_callback=NULL;
 create_result=start_result=ESP_OK;zero_entropy=false;mac_result=ESP_OK;request_reset();
}
static void no_upload(void) { CHECK(allocations==0 && receives==0 && parses==0 && loads==0 && starts==0 && mutations==0); }
static void rejected_upload(const char *nonce) {
 request_reset();httpd_req_t r={.expected=nonce,.content_len=100};
 CHECK(wasm_upload_handler(&r)==ESP_FAIL && response_code==409);no_upload();
}
#endif
int main(void) {
 httpd_req_t r={.content_len=8};
#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1
 new_boot();CHECK(ota_boot_nonce()==NULL && ota_boot_station_mac()==NULL);rejected_upload(NULL);
 CHECK(ota_boot_identity_init()==ESP_OK);CHECK(rng_calls==1 && mac_calls==1);
 CHECK(!strcmp(ota_boot_nonce(),"0102030405060708090a0b0c0d0e0f10"));
 CHECK(!strcmp(ota_boot_station_mac(),"02:ac:de:77:00:01"));
 char previous[33];strcpy(previous,ota_boot_nonce());
 entropy_base=64;mocked_mac[5]=0x5d;CHECK(ota_boot_identity_init()==ESP_OK);
 CHECK(rng_calls==1 && mac_calls==1 && !strcmp(previous,ota_boot_nonce()));
 CHECK(!strcmp(ota_boot_station_mac(),"02:ac:de:77:00:01"));
 rejected_upload(NULL);rejected_upload("");rejected_upload("00000000000000000000000000000000");
 rejected_upload("0102030405060708090A0B0C0D0E0F10");rejected_upload("0102030405060708090a0b0c0d0e0f100");
 request_reset();header_result=ESP_FAIL;r.expected=previous;CHECK(wasm_upload_handler(&r)==ESP_FAIL && response_code==409);no_upload();
 request_reset();r.expected=previous;r.content_len=0;CHECK(wasm_upload_handler(&r)==ESP_FAIL && response_code==400);no_upload();
 r.content_len=8;request_reset();CHECK(wasm_upload_handler(&r)==ESP_OK);CHECK(loads==1 && starts==1 && mutations==3 && allocations==1 && receives==1);
 CHECK(strstr(response,previous) && strstr(response,OTA_BOOT_NONCE_SCHEMA));puts(response);
 request_reset();CHECK(ota_status_handler(&r)==ESP_OK);CHECK(strstr(response,previous));puts(response);
 request_reset();CHECK(wasm_list_handler(&r)==ESP_OK);CHECK(strstr(response,previous));puts(response);
 maximum_width=true;request_reset();CHECK(wasm_list_handler(&r)==ESP_OK);CHECK(strstr(response,previous) && strlen(response)<4096);puts(response);maximum_width=false;
 const char *states[]={"wait_ip","backoff","running","stopping","retiring","blocked","init_failed"};
 for(int i=0;i<7;i++) CHECK(!strcmp(self_ping_state_name((csi_self_ping_state_t)i),states[i]));
 CHECK(!strcmp(self_ping_state_name((csi_self_ping_state_t)999),"unknown"));
 for(health_mode=1;health_mode<=3;health_mode++) {
  request_reset();CHECK(wasm_list_handler(&r)==ESP_OK);
  CHECK(strstr(response,"\"last_progress_age_ms\":null"));no_upload();
 }
 health_mode=0;CHECK(getter_calls==5);
 new_boot();CHECK(ota_boot_identity_init()==ESP_OK);CHECK(strcmp(previous,ota_boot_nonce()));rejected_upload(previous);
 r.expected=ota_boot_nonce();r.content_len=0;r.auth=NULL;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==403);CHECK(timer_creates==0);no_upload();
 r.auth="Bearer wrong";request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==403);CHECK(timer_creates==0);
 r.auth="Bearer synthetic-test-key";r.expected=previous;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==409);CHECK(timer_creates==0);
 r.expected=ota_boot_nonce();r.content_len=1;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==400);CHECK(timer_creates==0);
 r.content_len=-1;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==400);CHECK(timer_creates==0);
 r.content_len=0;create_result=ESP_FAIL;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==500);CHECK(timer_starts==0 && !s_restart_pending && restarts==0);
 create_result=ESP_OK;start_result=ESP_FAIL;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==500);CHECK(!s_restart_pending && restarts==0);
 start_result=ESP_OK;request_reset();CHECK(ota_restart_handler(&r)==ESP_OK);CHECK(s_restart_pending && armed_delay==1000000 && restarts==0);no_upload();puts(response);
 int scheduled=timer_starts;request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==409 && timer_starts==scheduled);
 armed_callback(armed_argument);CHECK(restarts==1);no_upload();
 new_boot();CHECK(ota_boot_identity_init()==ESP_OK);r.expected=ota_boot_nonce();request_reset();send_result=ESP_FAIL;
 CHECK(ota_restart_handler(&r)==ESP_FAIL && s_restart_pending && armed_delay==1000000);armed_callback(armed_argument);CHECK(restarts==1);no_upload();
 new_boot();s_ota_psk[0]=0;CHECK(ota_boot_identity_init()==ESP_OK);r.expected=ota_boot_nonce();request_reset();CHECK(ota_restart_handler(&r)==ESP_FAIL && response_code==403 && timer_creates==0);
 new_boot();zero_entropy=true;CHECK(ota_boot_identity_init()!=ESP_OK);CHECK(ota_boot_nonce()==NULL && ota_boot_station_mac()==NULL);int old_calls=rng_calls;zero_entropy=false;CHECK(ota_boot_identity_init()!=ESP_OK && rng_calls==old_calls);rejected_upload("00000000000000000000000000000000");
 new_boot();mac_result=-77;old_calls=rng_calls;CHECK(ota_boot_identity_init()==-77 && rng_calls==old_calls);CHECK(ota_boot_nonce()==NULL);
 new_boot();memset(mocked_mac,0,6);CHECK(ota_boot_identity_init()!=ESP_OK);CHECK(ota_boot_station_mac()==NULL);
 new_boot();mocked_mac[0]=1;CHECK(ota_boot_identity_init()!=ESP_OK);CHECK(ota_boot_nonce()==NULL);
#else
 request_reset();CHECK(wasm_upload_handler(&r)==ESP_OK && loads==1 && !strstr(response,"boot_nonce"));puts(response);
 request_reset();CHECK(ota_status_handler(&r)==ESP_OK && !strstr(response,"boot_nonce"));puts(response);
 request_reset();CHECK(wasm_list_handler(&r)==ESP_OK && !strstr(response,"boot_nonce"));puts(response);
 CHECK(auth_reads==0);
#endif
 return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned source directory")
    args = parser.parse_args()
    lock = {
        x["path"]: x["sha256"]
        for x in json.loads((ROOT / "upstream-files.json").read_text())["files"]
    }
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "main").mkdir()
        for name in ("ota_update.c", "ota_update.h", "wasm_upload.c"):
            relative = "main/" + name
            original = args.source / relative
            if hashlib.sha256(original.read_bytes()).hexdigest() != lock[relative]:
                raise ValueError("Pristine source pin mismatch: " + relative)
            shutil.copy(original, work / relative)
        for prefix in ("0006", "0007", "0010", "0011", "0012", "0013", "0014", "0015"):
            patch = next((ROOT / "patches").glob(prefix + "-*.patch"))
            subprocess.run(
                [
                    "git",
                    "apply",
                    "--include=main/ota_update.c",
                    "--include=main/ota_update.h",
                    "--include=main/wasm_upload.c",
                    "--include=main/home_csi_ping.h",
                    str(patch),
                ],
                cwd=work,
                check=True,
            )
        ota = (work / "main/ota_update.c").read_text()
        upload = (work / "main/wasm_upload.c").read_text()
        header = (work / "main/ota_update.h").read_text()
        definitions = "\n".join(re.findall(r"^#define OTA_BOOT_.*$", header, re.M))
        start = ota.index(
            "#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1\n/* Initialized once"
        )
        end = ota.index("#endif /* CONFIG_HOME_RUNTIME_RECOVERY_V1 */", start) + len(
            "#endif /* CONFIG_HOME_RUNTIME_RECOVERY_V1 */"
        )
        boot = ota[start:end]
        server = function(ota, "static esp_err_t ota_start_server(")
        if server.index("ota_boot_identity_init()") >= server.index("httpd_start("):
            raise ValueError("Boot identity must initialize before server starts")
        if '.uri = "/system/restart", .method = HTTP_POST' not in server:
            raise ValueError("Restart route not exact POST")
        ping_header = (work / "main/home_csi_ping.h").read_text()
        ping_types = ping_header[
            ping_header.index("typedef enum {") : ping_header.index(
                "/* One bounded supervisor"
            )
        ]
        ping_types = (
            "#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1\n"
            + ping_types
            + "#endif\n"
        )
        body = (
            PRELUDE.replace("/* SELF_PING_TYPES */", ping_types)
            + "\n"
            + definitions
            + "\n"
            + boot
            + "\n"
        )
        body += function(ota, "static bool ota_check_auth(")
        body += function(ota, "static esp_err_t ota_status_handler(")
        body += "#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1\n"
        body += function(ota, "static void ota_restart_callback(")
        body += function(ota, "static esp_err_t ota_restart_handler(")
        body += "#endif\n"
        for name in (
            "static uint8_t *receive_body(",
            "static esp_err_t wasm_upload_handler(",
            "static const char *state_name(",
            "static bool append_json(",
        ):
            body += function(upload, name)
        body += "#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1\n"
        body += function(upload, "static const char *self_ping_state_name(")
        body += function(upload, "static bool append_self_ping_json(")
        body += "#endif\n"
        body += function(upload, "static esp_err_t wasm_list_handler(")
        body += TESTS
        cfile = work / "boot.c"
        cfile.write_text(body)
        outputs = {}
        for enabled in (None, 0, 1):
            exe = work / ("mode-" + str(enabled))
            command = [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-function",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(cfile),
                "-o",
                str(exe),
            ]
            if enabled is not None:
                command.append(f"-DCONFIG_HOME_RUNTIME_RECOVERY_V1={enabled}")
            subprocess.run(command, check=True, timeout=30)
            completed = subprocess.run(
                [str(exe)], capture_output=True, text=True, check=True, timeout=10
            )
            rows = [json.loads(line) for line in completed.stdout.splitlines()]
            outputs[enabled] = rows
        legacy, modern = outputs[None], outputs[1]
        if outputs[0] != legacy:
            raise ValueError("Explicit zero flag must preserve undefined protocol")
        for row in (legacy[2], outputs[0][2], modern[2], modern[3]):
            if row["wifi"] != {
                "associated": True,
                "bssid": "02:ac:de:77:10:01",
                "channel": 6,
                "rssi_dbm": -30,
                "ap_info_error": 0,
            }:
                raise ValueError(
                    "Actual association telemetry differs from synthetic AP"
                )
        for row in legacy:
            if "boot_nonce" in json.dumps(row):
                raise ValueError("Legacy protocol changed")
        nonce = modern[0]["boot_nonce"]
        if not re.fullmatch("[0-9a-f]{32}", nonce) or nonce == "0" * 32:
            raise ValueError("Noncanonical nonce")
        if (
            modern[1]["boot_nonce"] != nonce
            or modern[2]["runtime"]["boot_nonce"] != nonce
        ):
            raise ValueError("Upload/status/runtime boot identity disagreement")
        for row in (modern[1], modern[2]["runtime"]):
            if (
                row["station_mac"] != "02:ac:de:77:00:01"
                or row["boot_nonce_schema"] != "ruview.boot-nonce.v1"
            ):
                raise ValueError("Actual status schema/MAC mismatch")
        if (
            len(modern[3]["modules"]) != 4
            or modern[3]["loaded"] != 4
            or any(
                row["frame_count"] != 2**32 - 1 or len(row["name"]) != 31
                for row in modern[3]["modules"]
            )
        ):
            raise ValueError("Maximum-width JSON metadata truncated")
        normal_ping = modern[2]["runtime"]["self_ping"]
        max_ping = modern[3]["runtime"]["self_ping"]
        if (
            normal_ping["last_progress_age_ms"] != 56
            or normal_ping["last_progress_age_basis"]
            != "session_start_or_ping_callback"
        ):
            raise ValueError("Watchdog age semantics changed")
        counters = (
            "attempts",
            "starts",
            "create_failures",
            "start_failures",
            "stop_failures",
            "delete_failures",
            "stalls",
            "successes",
            "timeouts",
            "ends",
            "network_epoch",
        )
        if (
            any(max_ping[key] != 2**32 - 1 for key in counters)
            or max_ping["last_error"] != -(2**31)
            or max_ping["state"] != "init_failed"
            or max_ping["last_progress_age_ms"] != (2**63 - 1) // 1000 - 1
            or modern[3]["runtime"]["uptime_ms"] != 2**64 - 1
        ):
            raise ValueError("Maximum-width self-ping/runtime fields truncated")
        for old, new in zip(legacy, modern[:3], strict=True):
            new = json.loads(json.dumps(new))
            obj = new["runtime"] if "runtime" in new else new
            for key in ("boot_nonce_schema", "boot_nonce", "station_mac", "self_ping"):
                obj.pop(key, None)
            if old != new:
                raise ValueError("Unexpected legacy field change")
        print(
            "PASS: actual handlers, undefined/zero/enabled feature modes, immutable identity/new-boot rejection, pre-receive guard, JSON agreement and bounded self-ping diagnostics, key/nonce/body restart gates, timer/send failures, zero entropy/MAC fail-closed; host ASan/UBSan only."
        )


if __name__ == "__main__":
    main()
