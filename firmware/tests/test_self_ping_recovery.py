#!/usr/bin/env python3
"""Host-execute actual optional self-ping lifecycle; no radio/firmware build.

ESP-IDF5.4 seams reproduce asynchronous stop/end/delete. These deterministic
checks establish state and ownership, not RF throughput or task timing on ESP32.
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


STUB = r"""
#ifndef SELF_PING_TEST_IDF_H
#define SELF_PING_TEST_IDF_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "line %d: %s\n", __LINE__, #c); abort(); } } while (0)
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_NO_MEM 0x101
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(p) do { CHECK(*(p) == 0); *(p) = 1; } while (0)
#define portEXIT_CRITICAL(p) do { CHECK(*(p) == 1); *(p) = 0; } while (0)
#define pdMS_TO_TICKS(n) (n)
#define pdPASS 1
static uint64_t fake_ms;
static int fake_task_result = pdPASS, fake_task_count;
static int64_t esp_timer_get_time(void) { return (int64_t)(fake_ms * 1000); }
static void vTaskDelay(unsigned ticks) { (void)ticks; abort(); }
static int xTaskCreate(void (*fn)(void *), const char *name, unsigned stack,
                       void *arg, unsigned priority, void *handle) {
    CHECK(fn && name && stack == 4096 && !arg && priority == 1 && !handle);
    ++fake_task_count; return fake_task_result;
}
typedef const void *esp_event_base_t;
static const int wifi_event_id, ip_event_id;
#define WIFI_EVENT ((esp_event_base_t)&wifi_event_id)
#define IP_EVENT ((esp_event_base_t)&ip_event_id)
#define WIFI_EVENT_STA_DISCONNECTED 5
#define IP_EVENT_STA_LOST_IP 6
#define IP_EVENT_STA_GOT_IP 7
#define ESP_EVENT_ANY_ID -1
typedef void *esp_event_handler_instance_t;
static int fake_reg_calls, fake_regs, fake_reg_fail;
static esp_err_t esp_event_handler_instance_register(esp_event_base_t base, int id,
    void (*fn)(void *, esp_event_base_t, int32_t, void *), void *arg, void **out) {
    CHECK(base && fn && !arg); (void)id; ++fake_reg_calls;
    if (fake_reg_calls == fake_reg_fail) return ESP_FAIL;
    ++fake_regs; *out = (void *)(uintptr_t)fake_reg_calls; return ESP_OK;
}
static esp_err_t esp_event_handler_instance_unregister(esp_event_base_t base, int id, void *handle) {
    CHECK(base && handle && fake_regs > 0); (void)id; --fake_regs; return ESP_OK;
}
typedef int esp_netif_t;
typedef struct { uint32_t addr; } esp_ip4_addr_t;
typedef struct { esp_ip4_addr_t ip, gw; } esp_netif_ip_info_t;
typedef struct { int unused; } wifi_ap_record_t;
static esp_netif_t fake_netif;
static bool fake_up, fake_associated;
static uint32_t fake_ip, fake_gateway;
static esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) {
    CHECK(strcmp(key,"WIFI_STA_DEF") == 0); return &fake_netif;
}
static bool esp_netif_is_netif_up(esp_netif_t *net) { CHECK(net); return fake_up; }
static esp_err_t esp_netif_get_ip_info(esp_netif_t *net, esp_netif_ip_info_t *out) {
    CHECK(net && out); out->ip.addr = fake_ip; out->gw.addr = fake_gateway; return ESP_OK;
}
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *out) {
    CHECK(out); return fake_associated ? ESP_OK : ESP_FAIL;
}
static char *esp_ip4addr_ntoa(const esp_ip4_addr_t *ip, char *out, int len) {
    snprintf(out,(size_t)len,"%u",ip->addr); return out;
}
typedef struct { uint32_t addr; } ip_addr_t;
static int ipaddr_aton(const char *text, ip_addr_t *out) {
    out->addr = (uint32_t)strtoul(text, NULL, 10); return 1;
}
typedef void *esp_ping_handle_t;
typedef struct {
    ip_addr_t target_addr;
    uint32_t count, interval_ms, timeout_ms, data_size, task_stack_size;
} esp_ping_config_t;
#define ESP_PING_DEFAULT_CONFIG() (esp_ping_config_t){.timeout_ms=1000}
#define ESP_PING_COUNT_INFINITE 0
typedef struct {
    void *cb_args;
    void (*on_ping_success)(esp_ping_handle_t,void *);
    void (*on_ping_timeout)(esp_ping_handle_t,void *);
    void (*on_ping_end)(esp_ping_handle_t,void *);
} esp_ping_callbacks_t;
typedef struct {
    esp_ping_callbacks_t cb;
    bool started, active, stop_requested, ended, deleted;
} fake_session_t;
static fake_session_t sessions[32];
static unsigned created, deleted, starts_called, stops_called, active;
static int new_fail, start_fail, stop_fail, delete_fail;
static bool change_during_create;
static void test_network_changed(void);
static esp_err_t esp_ping_new_session(const esp_ping_config_t *cfg,
    const esp_ping_callbacks_t *cb, esp_ping_handle_t *out) {
    CHECK(active == 0 && cfg->target_addr.addr == fake_gateway);
    CHECK(cfg->interval_ms == 20 && cfg->timeout_ms == 1000 && cfg->data_size == 1);
    CHECK(cfg->count == ESP_PING_COUNT_INFINITE && cfg->task_stack_size == 4096);
    CHECK(created < 32 && cb->cb_args == NULL);
    if (new_fail > 0) { --new_fail; return ESP_ERR_NO_MEM; }
    sessions[created].cb = *cb; *out = &sessions[created++];
    if (change_during_create) test_network_changed();
    return ESP_OK;
}
static esp_err_t esp_ping_start(esp_ping_handle_t handle) {
    fake_session_t *p = handle;
    CHECK(p && !p->started && !p->deleted && active == 0);
    ++starts_called;
    if (start_fail > 0) { --start_fail; return ESP_FAIL; }
    p->started = p->active = true; ++active; return ESP_OK;
}
static esp_err_t esp_ping_stop(esp_ping_handle_t handle) {
    fake_session_t *p = handle; CHECK(p && !p->deleted); ++stops_called;
    if (stop_fail > 0) { --stop_fail; return ESP_FAIL; }
    p->stop_requested = true; return ESP_OK;
}
static esp_err_t esp_ping_delete_session(esp_ping_handle_t handle) {
    fake_session_t *p = handle;
    CHECK(p && !p->deleted && !p->active && (!p->started || p->ended));
    if (delete_fail > 0) { --delete_fail; return ESP_FAIL; }
    p->deleted = true; ++deleted; return ESP_OK;
}
#endif
"""

HARNESS = r"""
#include "home_csi_ping.c"
static void test_network_changed(void) {
    network_event(NULL, IP_EVENT, IP_EVENT_STA_LOST_IP, NULL);
}
static void reset(void) {
    CHECK(s_mux == 0);
    memset(&s_status,0,sizeof(s_status)); memset(&s_work,0,sizeof(s_work));
    s_handle=NULL; s_end_seen=s_initializing=false; s_last_progress=0;
    s_successes=s_timeouts=s_ends=s_network_epoch=0; s_ip_event=0;
    s_session_epoch=s_failure_streak=0; s_stop_deadline=s_stop_retry=0;
    s_stop_requested=s_start_failed=s_delete_failed=false;
    s_wifi_handler=s_ip_handler=NULL;
    fake_ms=0; fake_task_count=0; fake_task_result=pdPASS;
    fake_reg_calls=fake_regs=fake_reg_fail=0;
    fake_up=fake_associated=true; fake_ip=121; fake_gateway=1;
    memset(sessions,0,sizeof(sessions)); created=deleted=starts_called=stops_called=active=0;
    new_fail=start_fail=stop_fail=delete_fail=0; change_during_create=false;
}
static void at(uint64_t ms) { fake_ms=ms; tick(ms); }
static void ack(unsigned index) {
    fake_session_t *p=&sessions[index]; CHECK(p->active && p->stop_requested);
    p->active=false; --active; p->ended=true; p->cb.on_ping_end(p,p->cb.cb_args);
}
static void echo(unsigned index, bool success, uint64_t ms) {
    fake_ms=ms; fake_session_t *p=&sessions[index];
    (success ? p->cb.on_ping_success : p->cb.on_ping_timeout)(p,p->cb.cb_args);
}
static void delayed_ip(void) {
    reset(); fake_up=false; fake_gateway=0;
    CHECK(home_csi_ping_start()==ESP_OK); CHECK(home_csi_ping_start()==ESP_OK);
    at(0); at(60000); CHECK(created==0 && fake_task_count==1 && fake_regs==2);
    fake_up=true; fake_gateway=1;
    network_event(NULL,IP_EVENT,IP_EVENT_STA_GOT_IP,NULL);
    at(61000); CHECK(active==1 && created==1 && s_work.state==CSI_PING_RUNNING);
    at(62000); CHECK(created==1);
}
static void create_retry(void) {
    reset(); new_fail=2; at(0); at(999); CHECK(s_work.attempts==1 && created==0);
    at(1000); at(2999); CHECK(s_work.attempts==2);
    at(3000); CHECK(created==1 && active==1 && s_work.create_failures==2);
}
static void start_retry(void) {
    reset(); start_fail=1; at(0);
    CHECK(created==1 && active==0 && stops_called==1 && s_work.start_failures==1);
    at(1000); CHECK(deleted==1 && s_handle==NULL);
    at(2999); CHECK(created==1); at(3000); CHECK(created==2 && active==1);
}
static void lost_ip_end_barrier(void) {
    reset(); at(0); network_event(NULL,IP_EVENT,IP_EVENT_STA_LOST_IP,NULL);
    at(1000); CHECK(stops_called==1 && active==1);
    network_event(NULL,IP_EVENT,IP_EVENT_STA_GOT_IP,NULL);
    at(5000); at(100000); CHECK(s_work.state==CSI_PING_BLOCKED && created==1 && deleted==0);
    ack(0); at(100001); CHECK(deleted==1 && active==0);
    at(102001); CHECK(created==2 && active==1);
    echo(0,true,102002); sessions[0].cb.on_ping_end(&sessions[0],NULL);
    CHECK(s_successes==0 && s_ends==1 && !s_end_seen);
}
static void gateway_and_fast_reconnect(void) {
    reset(); at(0); fake_gateway=2; at(1000); ack(0); at(1001); at(3001);
    CHECK(created==2 && active==1 && s_work.target_ipv4==2);
    network_event(NULL,WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,NULL);
    network_event(NULL,IP_EVENT,IP_EVENT_STA_GOT_IP,NULL);
    at(4000); CHECK(stops_called==2); ack(1); at(4001); at(8001);
    CHECK(created==3 && active==1);
}
static void no_echo_is_progress(void) {
    reset(); at(0);
    for (unsigned i=1;i<=120;++i) { echo(0,false,i*1000); at(i*1000); }
    CHECK(created==1 && stops_called==0 && active==1 && s_timeouts==120);
    csi_self_ping_status_t status; csi_self_ping_get_status(&status);
    CHECK(status.timeouts==120 && status.last_progress_ms==120000 && status.starts==1);
}
static void real_stall_and_stop_failure(void) {
    reset(); at(0); stop_fail=1; at(10000);
    CHECK(s_work.stalls==1 && s_work.stop_failures==1 && active==1);
    at(10999); CHECK(stops_called==1); at(11000); CHECK(stops_called==2);
    at(14000); CHECK(s_work.state==CSI_PING_BLOCKED && created==1);
    ack(0); at(14001); at(16001); CHECK(active==1 && created==2);
}
static void start_failure_and_failed_stop(void) {
    reset(); start_fail=stop_fail=1; at(0); at(999);
    CHECK(stops_called==1 && !deleted); at(1000); CHECK(stops_called==2);
    at(1001); CHECK(deleted==1); at(3001); CHECK(created==2 && active==1);
}
static void delete_failure_blocks(void) {
    reset(); at(0); fake_associated=false; at(1000); ack(0); delete_fail=1;
    at(1001); fake_associated=true; at(100000); CHECK(created==1 && deleted==0);
    CHECK(s_work.state==CSI_PING_BLOCKED && s_work.delete_failures==1);
}
static void create_race_does_not_start(void) {
    reset(); change_during_create=true; at(0);
    CHECK(created==1 && deleted==1 && starts_called==0 && active==0);
}
static void bounded_failure_backoff(void) {
    reset(); new_fail=20;
    uint64_t schedule[]={0,1000,3000,7000,15000,31000,61000,91000};
    for(unsigned i=0;i<sizeof(schedule)/sizeof(schedule[0]);++i) at(schedule[i]);
    CHECK(s_work.attempts==8 && s_work.next_retry_ms==121000 && active==0);
}
static void initializer_cleanup(void) {
    reset(); fake_reg_fail=2; CHECK(home_csi_ping_start()==ESP_FAIL);
    CHECK(fake_regs==0 && fake_task_count==0 && !s_status.supervisor_started);
    fake_reg_fail=0; fake_task_result=0; CHECK(home_csi_ping_start()==ESP_ERR_NO_MEM);
    CHECK(fake_regs==0 && !s_status.supervisor_started);
    fake_task_result=pdPASS; CHECK(home_csi_ping_start()==ESP_OK);
    CHECK(fake_regs==2 && s_status.supervisor_started);
}
static void callback_clock_and_saturation(void) {
    reset(); at(100); echo(0,true,101); tick(100);
    CHECK(stops_called==0); s_successes=UINT32_MAX; echo(0,true,102);
    CHECK(s_successes==UINT32_MAX);
}
int main(void) {
    (void)TAG;
    delayed_ip(); create_retry(); start_retry(); lost_ip_end_barrier();
    gateway_and_fast_reconnect(); no_echo_is_progress(); real_stall_and_stop_failure();
    start_failure_and_failed_stop(); delete_failure_blocks(); create_race_does_not_start();
    bounded_failure_backoff(); initializer_cleanup(); callback_clock_and_saturation();
    puts("13 actual-source self-ping lifecycle cases PASS"); return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    lock = json.loads((ROOT / "upstream-files.json").read_text())
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
        legacy_body = None
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            if patch.name > "0014-self-ping-recovery.patch":
                continue
            if patch.name.startswith("0014-"):
                text = (work / "main/csi_collector.c").read_text()
                start = text.index("static esp_ping_handle_t s_self_ping = NULL;")
                end = text.index("\nvoid csi_collector_set_node_id", start)
                legacy_body = text[start:end]
            subprocess.run(
                ["git", "apply", "--exclude=components/wasm3/wasm3-src/*", str(patch)],
                cwd=work,
                check=True,
            )
        source = (work / "main/csi_collector.c").read_text()
        require(legacy_body and legacy_body in source, "Legacy implementation changed")
        require(
            "#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1\n"
            "static void csi_start_self_ping(void)" in source,
            "Recovery integration is not explicitly gated",
        )
        stub = work / "stubs"
        stub.mkdir()
        (stub / "idf.h").write_text(STUB)
        (stub / "sdkconfig.h").write_text("")
        for name in (
            "esp_err.h",
            "esp_event.h",
            "esp_log.h",
            "esp_netif.h",
            "esp_timer.h",
            "esp_wifi.h",
            "freertos/FreeRTOS.h",
            "freertos/task.h",
            "lwip/ip_addr.h",
            "ping/ping_sock.h",
        ):
            dest = stub / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text('#include "idf.h"\n')
        harness = work / "test.c"
        harness.write_text(HARNESS)
        compiler = os.environ.get("CC", "cc")
        common = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(stub),
            "-I" + str(work / "main"),
        ]
        executable = work / "test"
        subprocess.run(
            common
            + [
                "-DCONFIG_HOME_RUNTIME_RECOVERY_V1=1",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(harness),
                "-o",
                str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)
        # Disabled TU must need no additional SDK headers or link symbols.
        for flag in ([], ["-DCONFIG_HOME_RUNTIME_RECOVERY_V1=0"]):
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(stub)]
                + flag
                + [
                    "-c",
                    str(work / "main/home_csi_ping.c"),
                    "-o",
                    str(work / "disabled.o"),
                ],
                check=True,
            )
        print("Disabled/undefined recovery profiles PASS; legacy body preserved")


if __name__ == "__main__":
    main()
