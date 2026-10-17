#!/usr/bin/env python3
"""Execute the actual OTA handler with deterministic socket/flash failure mocks.

No real sockets, OTA partitions, credentials, flash, or devices are accessed.
The test covers bounded receive time and boot-selection ordering, not radio or
flash-driver timing; synchronous operations cannot be interrupted by a deadline.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    original = args.source / "main/ota_update.c"
    lock = json.loads((ROOT / "upstream-files.json").read_text())["files"]
    expected = next(row["sha256"] for row in lock if row["path"] == "main/ota_update.c")
    if hashlib.sha256(original.read_bytes()).hexdigest() != expected:
        raise ValueError("OTA source differs from pinned upstream")
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "main").mkdir()
        shutil.copy(original, work / "main/ota_update.c")
        for number in ("0006", "0011", "0012"):
            patch = next((ROOT / "patches").glob(number + "-*.patch"))
            subprocess.run(
                ["git", "apply", "--include=main/ota_update.c", str(patch)],
                cwd=work,
                check=True,
            )
        source = (work / "main/ota_update.c").read_text()
        limits = "\n".join(
            re.findall(r"^#define OTA_RECEIVE_.*$", source, re.MULTILINE)
        )
        if len(limits.splitlines()) != 2:
            raise ValueError("Receive deadline constants missing")
        harness = (
            r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); abort(); } } while (0)
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define HTTPD_400_BAD_REQUEST 400
#define HTTPD_403_FORBIDDEN 403
#define HTTPD_408_REQ_TIMEOUT 408
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#define HTTPD_SOCK_ERR_TIMEOUT -3
#define OTA_WITH_SEQUENTIAL_WRITES -1
#define SOL_SOCKET 1
#define SO_RCVTIMEO 2
#define pdMS_TO_TICKS(n) (n)
typedef int esp_err_t, esp_ota_handle_t;
typedef struct { int content_len; } httpd_req_t;
typedef struct { size_t size; const char *label; } esp_partition_t;
static esp_partition_t partition = {.size=1000000,.label="ota_1"};
static bool authorized, have_partition;
static int fd_value, socket_result, begin_result, write_result, end_result, boot_result;
static int begin_calls, abort_calls, end_calls, boot_calls, restarts, status;
static int recv_calls, written_bytes, read_bytes, socket_calls;
static int64_t clock_us, begin_time, write_time;
static struct { int result; int64_t elapsed; } steps[400];
static unsigned step_count, step_index;
static bool ota_check_auth(httpd_req_t *r) { (void)r; return authorized; }
static const esp_partition_t *esp_ota_get_next_update_partition(void *unused) {
    (void)unused; return have_partition ? &partition : NULL;
}
static int httpd_req_to_sockfd(httpd_req_t *r) { (void)r; return fd_value; }
static int setsockopt(int fd, int level, int option, const void *value, size_t length) {
    CHECK(fd==7 && level==SOL_SOCKET && option==SO_RCVTIMEO);
    CHECK(length==sizeof(struct timeval)); const struct timeval *t=value;
    CHECK(t->tv_sec==1 && t->tv_usec==0); ++socket_calls; return socket_result;
}
static int64_t esp_timer_get_time(void) { return clock_us; }
static esp_err_t esp_ota_begin(const esp_partition_t *p, int mode, esp_ota_handle_t *h) {
    CHECK(p==&partition && mode==OTA_WITH_SEQUENTIAL_WRITES);
    ++begin_calls; *h=42; clock_us+=begin_time; return begin_result;
}
static int httpd_req_recv(httpd_req_t *r, char *buf, size_t length) {
    CHECK(step_index<step_count && length>0 && length<=1024);
    CHECK(length<=(size_t)(r->content_len-read_bytes)); ++recv_calls;
    int result=steps[step_index].result; clock_us+=steps[step_index++].elapsed;
    if (result>0) { CHECK((size_t)result<=length); memset(buf,0xa5,result); read_bytes+=result; }
    return result;
}
static esp_err_t esp_ota_write(esp_ota_handle_t h, const void *buf, size_t n) {
    CHECK(h==42 && buf && n>0); written_bytes+=(int)n; clock_us+=write_time; return write_result;
}
static esp_err_t esp_ota_abort(esp_ota_handle_t h) { CHECK(h==42 && end_calls==0); ++abort_calls; return ESP_OK; }
static esp_err_t esp_ota_end(esp_ota_handle_t h) { CHECK(h==42 && abort_calls==0); ++end_calls; return end_result; }
static esp_err_t esp_ota_set_boot_partition(const esp_partition_t *p) {
    CHECK(p==&partition && end_calls==1 && end_result==ESP_OK && abort_calls==0);
    ++boot_calls; return boot_result;
}
const char *esp_err_to_name(int code) { (void)code; return "mock"; }
static esp_err_t httpd_resp_send_err(httpd_req_t *r, int code, const char *message) {
    (void)r; CHECK(message); status=code; return ESP_OK;
}
static esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *type) { (void)r; (void)type; return ESP_OK; }
static esp_err_t httpd_resp_send(httpd_req_t *r, const char *body, int n) {
    (void)r; CHECK(body && n>0); status=200; return ESP_OK;
}
static void vTaskDelay(int ticks) { CHECK(ticks==1000); }
static void esp_restart(void) { ++restarts; }
"""
            + limits
            + "\n"
            + function(source, "static esp_err_t ota_upload_handler(")
            + r"""
static void reset(void) {
    authorized=have_partition=true; fd_value=7;
    socket_result=begin_result=write_result=end_result=boot_result=0;
    begin_calls=abort_calls=end_calls=boot_calls=restarts=status=0;
    recv_calls=written_bytes=read_bytes=socket_calls=0;
    clock_us=100; begin_time=write_time=0; step_count=step_index=0;
}
static void step(int result, int64_t elapsed) { CHECK(step_count<400); steps[step_count].result=result; steps[step_count++].elapsed=elapsed; }
static int run(int bytes) { httpd_req_t r={.content_len=bytes}; return ota_upload_handler(&r); }
static void unchanged_boot(void) { CHECK(boot_calls==0 && restarts==0); }
static void deadline(void) { CHECK(status==408 && abort_calls==1 && end_calls==0); unchanged_boot(); }
int main(void) {
    reset(); authorized=false; CHECK(run(1024)==ESP_FAIL); CHECK(status==403 && !begin_calls && !socket_calls); unchanged_boot();
    reset(); have_partition=false; CHECK(run(1024)==ESP_FAIL); CHECK(status==500 && !begin_calls); unchanged_boot();
    reset(); CHECK(run(0)==ESP_FAIL); CHECK(status==400 && !begin_calls); unchanged_boot();
    reset(); CHECK(run(1000001)==ESP_FAIL); CHECK(status==400 && !begin_calls); unchanged_boot();
    reset(); fd_value=-1; CHECK(run(1024)==ESP_FAIL); CHECK(!begin_calls && !socket_calls); unchanged_boot();
    reset(); socket_result=-1; CHECK(run(1024)==ESP_FAIL); CHECK(socket_calls==1 && !begin_calls); unchanged_boot();
    reset(); begin_result=-1; CHECK(run(1024)==ESP_FAIL); CHECK(begin_calls==1 && !abort_calls && !recv_calls); unchanged_boot();
    reset(); for (int i=0;i<15;i++) step(HTTPD_SOCK_ERR_TIMEOUT,1000000);
    CHECK(run(1024)==ESP_FAIL); CHECK(recv_calls==15 && written_bytes==0); deadline();
    reset(); step(512,1000000); for (int i=0;i<15;i++) step(HTTPD_SOCK_ERR_TIMEOUT,1000000);
    CHECK(run(1024)==ESP_FAIL); CHECK(written_bytes==512); deadline();
    reset(); step(1024,15000000); CHECK(run(1024)==ESP_FAIL); CHECK(written_bytes==0); deadline();
    reset(); for (int i=0;i<22;i++) step(1,14000000);
    CHECK(run(22)==ESP_FAIL); CHECK(recv_calls==22 && written_bytes==21); deadline(); /* Progress cannot defeat total bound. */
    reset(); begin_time=300000000; CHECK(run(1024)==ESP_FAIL); CHECK(!recv_calls); deadline();
    reset(); step(1024,1); write_time=300000000; CHECK(run(1024)==ESP_FAIL); CHECK(written_bytes==1024); deadline();
    reset(); step(512,1); step(0,1); CHECK(run(1024)==ESP_FAIL); CHECK(abort_calls==1 && written_bytes==512 && status==500); unchanged_boot();
    reset(); step(-2,1); CHECK(run(1024)==ESP_FAIL); CHECK(abort_calls==1 && !written_bytes); unchanged_boot();
    reset(); step(1024,1); write_result=-1; CHECK(run(1024)==ESP_FAIL); CHECK(abort_calls==1 && !end_calls); unchanged_boot();
    reset(); step(1024,1); end_result=-1; CHECK(run(1024)==ESP_FAIL); CHECK(end_calls==1 && !abort_calls); unchanged_boot();
    reset(); step(1024,1); boot_result=-1; CHECK(run(1024)==ESP_FAIL); CHECK(boot_calls==1 && !restarts && !abort_calls);
    reset(); for (int i=0;i<14;i++) step(HTTPD_SOCK_ERR_TIMEOUT,1000000);
    step(1024,999999); CHECK(run(1024)==ESP_OK); CHECK(boot_calls==1 && restarts==1 && !abort_calls && status==200);
    reset(); for (int i=0;i<9;i++) step(1024,10000000); step(51,10000000);
    CHECK(run(9*1024+51)==ESP_OK); CHECK(written_bytes==9*1024+51 && recv_calls==10 && boot_calls==1 && restarts==1); /* 100s is supported. */
    puts("20 actual OTA handler scenarios passed: bounded idle/total, partial/error abort, auth/socket fail-closed, final chunk and slow success.");
    return 0;
}
"""
        )
        cfile = work / "ota.c"
        cfile.write_text(harness)
        binary = work / "ota-test"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(cfile),
                "-o",
                str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
