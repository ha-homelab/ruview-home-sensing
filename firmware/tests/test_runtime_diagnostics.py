#!/usr/bin/env python3
"""Test actual patched lifecycle handlers and callback accounting with host mocks.

Synthetic wall-clock values prove accounting boundaries, not ESP32 performance.
No firmware, module, socket, or hardware operation is performed by this test.
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


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    position = opening + 1
    while depth:
        depth += (source[position] == "{") - (source[position] == "}")
        position += 1
    return source[start:position] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    lock = {
        row["path"]: row["sha256"]
        for row in json.loads((ROOT / "upstream-files.json").read_text())["files"]
    }
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "main").mkdir()
        for name in (
            "main.c",
            "ota_update.c",
            "wasm_upload.c",
            "wasm_runtime.c",
            "wasm_runtime.h",
        ):
            relative = "main/" + name
            source = args.source / relative
            if hashlib.sha256(source.read_bytes()).hexdigest() != lock[relative]:
                raise ValueError("Source differs from pinned upstream: " + relative)
            shutil.copy(source, work / relative)
        for number in ("0003", "0006", "0007", "0010", "0011"):
            patch = next((ROOT / "patches").glob(number + "-*.patch"))
            subprocess.run(["git", "apply", str(patch)], cwd=work, check=True)
        (work / "main/esp_err.h").write_text(
            "#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n"
        )
        (work / "main/edge_processing.h").write_text(
            "#pragma once\ntypedef struct { int flags; } edge_vitals_pkt_t;\n"
        )
        runtime = (work / "main/wasm_runtime.c").read_text()
        slot_start = runtime.index("typedef struct {")
        slot_end = runtime.index("} wasm_slot_t;", slot_start) + len("} wasm_slot_t;")
        telemetry = (
            r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wasm_runtime.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); abort(); } } while (0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define pdTRUE 1
#define portMAX_DELAY -1
#define WORK_FRAME 1
typedef void *IM3Runtime, *IM3Module, *IM3Function;
typedef const char *M3Result;
"""
            + runtime[slot_start:slot_end]
            + r"""
static wasm_slot_t s_slots[WASM_MAX_MODULES];
static atomic_bool s_worker_ready = true;
static bool busy;
static int s_mutex;
static int64_t clock_us, s_last_vitals_us;
static edge_vitals_pkt_t s_last_vitals;
static const edge_vitals_pkt_t *s_cur_vitals;
static const float *s_cur_phases, *s_cur_amplitudes, *s_cur_variances;
static uint16_t s_cur_n_sc;
static uint8_t s_cur_slot_id;
static uint32_t frame_time, timer_time;
static M3Result callback_result;
static unsigned sends;
typedef struct { int op; IM3Function function; int32_t n_sc; uint32_t *execution_us; } wasm_work_t;
static int xSemaphoreTake(int mutex, int delay) { (void)mutex; (void)delay; return !busy; }
static void xSemaphoreGive(int mutex) { (void)mutex; }
static int64_t esp_timer_get_time(void) { return clock_us; }
static M3Result worker_run(wasm_work_t work) {
    CHECK(work.op == WORK_FRAME);
    clock_us += 500000; /* Queue/scheduler delay excluded by the real worker. */
    *work.execution_us = frame_time;
    s_slots[s_cur_slot_id].n_events = 1;
    return callback_result;
}
static M3Result m3_CallV(IM3Function fn) {
    CHECK(fn != NULL); clock_us += timer_time;
    s_slots[s_cur_slot_id].n_events = 1;
    return callback_result;
}
static void send_wasm_output(uint8_t id) {
    CHECK(id == 0); ++sends;
    clock_us += 700000; /* Slow transport after either callback must not count. */
}
"""
            + function(runtime, "void wasm_runtime_on_frame(")
            + function(runtime, "static void worker_run_timer(void)\n{")
            + function(runtime, "void wasm_runtime_get_info(")
            + r"""
static void frame(uint32_t elapsed) {
    frame_time = elapsed; wasm_runtime_on_frame(NULL, NULL, NULL, 64, NULL);
}
static void timer(uint32_t elapsed) { timer_time = elapsed; worker_run_timer(); }
static void snapshot(void) {
    wasm_module_info_t info[WASM_MAX_MODULES]; uint8_t count = 99;
    memset(info, 0xff, sizeof(info)); wasm_runtime_get_info(info, &count);
    CHECK(count == 1);
    CHECK(info[0].max_frame_us == s_slots[0].max_frame_us);
    CHECK(info[0].max_timer_us == s_slots[0].max_timer_us);
    CHECK(info[0].frame_overruns == s_slots[0].frame_overruns);
    CHECK(info[0].timer_overruns == s_slots[0].timer_overruns);
    for (unsigned i=1; i<WASM_MAX_MODULES; ++i) {
        CHECK(info[i].max_frame_us == 0 && info[i].max_timer_us == 0);
        CHECK(info[i].frame_overruns == 0 && info[i].timer_overruns == 0);
    }
}
int main(void) {
    wasm_slot_t *s = &s_slots[0];
    s->state = WASM_MODULE_RUNNING; s->fn_on_frame = s; s->fn_on_timer = s;
    s->manifest_budget_us = 10000;
    frame(10000); timer(10000); /* The exact budget is allowed. */
    CHECK(s->max_us == 10000 && s->frame_overruns == 0 && s->timer_overruns == 0);
    frame(12000); timer(23000);
    CHECK(s->max_frame_us == 12000 && s->max_timer_us == 23000 && s->max_us == 23000);
    CHECK(s->frame_overruns == 1 && s->timer_overruns == 1 && s->budget_faults == 2);
    frame(5000); CHECK(s->budget_faults == 2); /* Half-budget is not a reset. */
    frame(4999); CHECK(s->budget_faults == 0);
    CHECK(s->frame_overruns == 1 && s->timer_overruns == 1);
    timer(11000); timer(1); CHECK(s->budget_faults == 1); /* Fast timer never resets. */
    CHECK(s->timer_overruns == 2 && s->max_timer_us == 23000);
    CHECK(s->frame_count == 4 && s->total_us == 31999); /* Mean remains frame-only. */
    CHECK(sends == 8); snapshot();
    busy = true; frame(99000); timer(99000); busy = false;
    CHECK(s->max_us == 23000 && s->frame_count == 4 && s->budget_faults == 1);
    callback_result = "trap";
    frame(25000); /* Legacy frame-error path skips timing/budget accounting. */
    CHECK(s->error_count == 1 && s->max_frame_us == 12000 && s->frame_overruns == 1);
    timer(24000); /* Timer-error path already accounts time; retain this behavior. */
    CHECK(s->error_count == 2 && s->max_timer_us == 24000 && s->timer_overruns == 3);
    callback_result = NULL;
    s->frame_overruns = s->timer_overruns = UINT32_MAX;
    frame(12000); timer(12000);
    CHECK(s->frame_overruns == UINT32_MAX && s->timer_overruns == UINT32_MAX);
    frame(1); CHECK(s->budget_faults == 0);
    for (unsigned i=0; i<10; ++i) timer(10001);
    CHECK(s->state == WASM_MODULE_ERROR && s->budget_faults == 10);
    unsigned frames = s->frame_count; frame(90000); timer(90000);
    CHECK(s->frame_count == frames && s->max_us == 24000);
    snapshot();
    puts("Actual frame/timer accounting, cumulative saturation, old fault semantics and empty-slot snapshots passed.");
    return 0;
}
"""
        )
        upload = (work / "main/wasm_upload.c").read_text()
        ota = (work / "main/ota_update.c").read_text()
        routing = (
            r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wasm_runtime.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); abort(); } } while (0)
#define HTTPD_400_BAD_REQUEST 400
#define HTTP_GET 1
#define HTTP_POST 2
#define HTTP_DELETE 3
#define ESP_ERR_INVALID_ARG -2
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define OTA_PORT 8032
typedef struct { const char *uri; } httpd_req_t;
typedef void *httpd_handle_t;
typedef esp_err_t (*handler_t)(httpd_req_t *);
typedef struct { const char *uri; int method; handler_t handler; void *user_ctx; } httpd_uri_t;
typedef bool (*matcher_t)(const char *, const char *, size_t);
typedef struct { int server_port, stack_size, max_uri_handlers, recv_wait_timeout; matcher_t uri_match_fn; } httpd_config_t;
#define HTTPD_DEFAULT_CONFIG() ((httpd_config_t){0})
static httpd_uri_t routes[12]; static unsigned route_count, calls, failures;
static int last_id = -1, result;
static matcher_t configured_matcher;
/* Only the documented trailing-star pattern used by these actual routes is
 * mocked. The real IDF matcher is not reimplemented or qualified here. */
static bool httpd_uri_match_wildcard(const char *pattern, const char *uri, size_t n) {
    size_t p = strlen(pattern);
    return p && pattern[p-1] == '*' ? n >= p-1 && !strncmp(pattern,uri,p-1)
                                  : n == p && !strncmp(pattern,uri,p);
}
static esp_err_t httpd_start(httpd_handle_t *server, httpd_config_t *config) {
    CHECK(config->uri_match_fn == httpd_uri_match_wildcard);
    CHECK(config->stack_size == 12288 && config->max_uri_handlers == 12);
    configured_matcher = config->uri_match_fn; *server = (void*)1; return ESP_OK;
}
static esp_err_t httpd_register_uri_handler(httpd_handle_t server, const httpd_uri_t *route) {
    CHECK(server && route_count < 12); routes[route_count++] = *route; return ESP_OK;
}
static esp_err_t httpd_resp_send_err(httpd_req_t *r, int code, const char *message) {
    (void)r; CHECK(code == 400 && message); ++failures; return ESP_OK;
}
static esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *type) { (void)r; (void)type; return ESP_OK; }
static esp_err_t httpd_resp_send(httpd_req_t *r, const char *body, int n) { (void)r; CHECK(n>0 && body); return ESP_OK; }
static const char *esp_err_to_name(int code) { (void)code; return "mock"; }
esp_err_t wasm_runtime_start(uint8_t id) { ++calls; last_id=id; return result; }
esp_err_t wasm_runtime_stop(uint8_t id) { ++calls; last_id=id; return result; }
esp_err_t wasm_runtime_unload(uint8_t id) { ++calls; last_id=id; return result; }
static esp_err_t ota_status_handler(httpd_req_t *r) { (void)r; return ESP_OK; }
static esp_err_t ota_upload_handler(httpd_req_t *r) { (void)r; return ESP_OK; }
static esp_err_t wasm_list_handler(httpd_req_t *r) { (void)r; return ESP_OK; }
static esp_err_t wasm_upload_handler(httpd_req_t *r) { (void)r; return ESP_OK; }
"""
            + function(upload, "static int parse_module_id_from_uri(")
            + "".join(
                function(upload, "static esp_err_t " + name + "(")
                for name in (
                    "wasm_start_handler",
                    "wasm_stop_handler",
                    "wasm_delete_handler",
                )
            )
            + function(upload, "esp_err_t wasm_upload_register(")
            + function(ota, "static esp_err_t ota_start_server(")
            + r"""
static int dispatch(int method, const char *uri) {
    httpd_req_t request = {.uri=uri};
    for (unsigned i=0; i<route_count; ++i) {
        if (routes[i].method == method && configured_matcher(routes[i].uri,uri,strlen(uri)))
            return routes[i].handler(&request);
    }
    return 404;
}
int main(void) {
    httpd_handle_t server=NULL; CHECK(ota_start_server(&server)==ESP_OK);
    CHECK(wasm_upload_register(server)==ESP_OK && route_count==7);
    const char *prefixes[]={"/wasm/start/", "/wasm/stop/", "/wasm/"};
    const int methods[]={HTTP_POST,HTTP_POST,HTTP_DELETE};
    const char *invalid[]={"", "*", "abc", "+0", "-1", " 0", "00", "01", "4", "0junk", "0/", "0?x=1", "0#x", "0%00", "9999999999999999999999999999999999999"};
    for (unsigned p=0; p<3; ++p) {
        for (unsigned id=0; id<WASM_MAX_MODULES; ++id) {
            char uri[64]; snprintf(uri,sizeof(uri),"%s%u",prefixes[p],id);
            unsigned before=calls; CHECK(dispatch(methods[p],uri)==ESP_OK);
            CHECK(calls==before+1 && last_id==(int)id);
        }
        for (unsigned i=0; i<sizeof(invalid)/sizeof(invalid[0]); ++i) {
            char uri[128]; snprintf(uri,sizeof(uri),"%s%s",prefixes[p],invalid[i]);
            unsigned before=calls, errors=failures;
            CHECK(dispatch(methods[p],uri)==ESP_FAIL);
            CHECK(calls==before && failures==errors+1);
        }
    }
    CHECK(parse_module_id_from_uri(NULL,"/wasm/")==-1);
    CHECK(parse_module_id_from_uri("/wasm/0",NULL)==-1);
    CHECK(parse_module_id_from_uri("/","/wasm/")==-1);
    CHECK(parse_module_id_from_uri("/else/0","/wasm/")==-1);
    CHECK(dispatch(HTTP_GET,"/wasm/stop/0")==404);
    result=ESP_FAIL; CHECK(dispatch(HTTP_POST,"/wasm/stop/0")==ESP_FAIL);
    puts("Actual HTTP setup/routes and numeric lifecycle handlers reject invalid IDs without acting; valid0..3 dispatch passed.");
    return 0;
}
"""
        )
        for name, source in (("telemetry", telemetry), ("routing", routing)):
            cfile = work / (name + ".c")
            cfile.write_text(source)
            binary = work / name
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                    "-I" + str(work / "main"),
                    str(cfile),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
