#!/usr/bin/env python3
"""Execute the patched HTTP socket callback and server configuration on a host.

The ESP-IDF 5.4 open_fn contract accepts (httpd_handle_t, int) and closes a
session on non-ESP_OK. Socket, HTTP, and boot functions below are deterministic
doubles; this test proves wiring/error behavior, not wireless latency.
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

PRELUDE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define OTA_PORT 8032
#define HTTP_GET 0
#define HTTP_POST 1
typedef int esp_err_t;
typedef void *httpd_handle_t;
typedef esp_err_t (*httpd_open_func_t)(httpd_handle_t, int);
typedef struct {
 int server_port, stack_size, max_uri_handlers, recv_wait_timeout;
 int (*uri_match_fn)(void);
 httpd_open_func_t open_fn;
} httpd_config_t;
typedef struct { const char *uri; int method; int (*handler)(void); void *user_ctx; } httpd_uri_t;
#define HTTPD_DEFAULT_CONFIG() ((httpd_config_t){.stack_size=4096,.recv_wait_timeout=5})
static httpd_config_t observed;
static int start_result, socket_result, socket_calls, last_fd, starts, registrations;
static int boot_result, boot_calls, stop_calls, wifi_result, wifi_calls;
static httpd_handle_t fake_server=(void*)0x1234;
static int mock_setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
 CHECK(fd>=0 && level==IPPROTO_TCP && option==TCP_NODELAY);
 CHECK(length==sizeof(int) && *(const int*)value==1);
 ++socket_calls;last_fd=fd;return socket_result;
}
#define setsockopt mock_setsockopt
static esp_err_t httpd_start(httpd_handle_t *out,const httpd_config_t *config) {
 ++starts;observed=*config;
 if(start_result) return start_result;
 *out=fake_server;return ESP_OK;
}
static esp_err_t httpd_stop(httpd_handle_t server) { CHECK(server==fake_server);++stop_calls;return ESP_OK; }
static esp_err_t httpd_register_uri_handler(httpd_handle_t server,const httpd_uri_t *uri) {
 CHECK(server==fake_server && uri->uri && uri->handler);++registrations;return ESP_OK;
}
static int httpd_uri_match_wildcard(void) { return 0; }
static int ota_status_handler(void) { return 0; }
static int ota_upload_handler(void) { return 0; }
static int ota_restart_handler(void) { return 0; }
static esp_err_t ota_boot_identity_init(void) { ++boot_calls;return boot_result; }
static esp_err_t home_wifi_policy_register_http(httpd_handle_t server) {
 CHECK(server==fake_server);++wifi_calls;return wifi_result;
}
"""

TESTS = r"""
int main(void) {
 httpd_handle_t server=NULL;
 CHECK(ota_start_server(&server)==ESP_OK && server==fake_server);
 CHECK(starts==1 && socket_calls==0 && stop_calls==0);
 CHECK(observed.server_port==8032 && observed.stack_size==12288);
 CHECK(observed.recv_wait_timeout==30 && observed.max_uri_handlers==12);
 CHECK(observed.uri_match_fn==httpd_uri_match_wildcard);
 CHECK(observed.open_fn==ota_http_open);
 CHECK(registrations==(CONFIG_HOME_RUNTIME_RECOVERY_V1?3:2) && wifi_calls==1);
 CHECK(boot_calls==(CONFIG_HOME_RUNTIME_RECOVERY_V1?1:0));
 /* File descriptor zero is valid; configure every new session separately. */
 CHECK(observed.open_fn(server,0)==ESP_OK && socket_calls==1 && last_fd==0);
 CHECK(observed.open_fn(server,9)==ESP_OK && socket_calls==2 && last_fd==9);
 socket_result=-1;
 CHECK(observed.open_fn(server,10)==ESP_FAIL && socket_calls==3);
 CHECK(observed.open_fn(server,-1)==ESP_FAIL && socket_calls==3);
 socket_result=0;
 CHECK(observed.open_fn(server,11)==ESP_OK && socket_calls==4);
 /* Server-start failure and null output retain the existing behavior. */
 start_result=-2;server=fake_server;
 CHECK(ota_start_server(&server)==-2 && server==NULL);
 CHECK(ota_start_server(NULL)==-2 && socket_calls==4);
#if CONFIG_HOME_RUNTIME_RECOVERY_V1
 int previous_starts=starts;boot_result=-3;server=fake_server;
 CHECK(ota_start_server(&server)==-3 && server==NULL && starts==previous_starts);
#endif
 puts("HTTP_NODELAY_HOST_PASS");
 return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    original = args.source / "main/ota_update.c"
    lock = json.loads((ROOT / "upstream-files.json").read_text())["files"]
    expected = next(r["sha256"] for r in lock if r["path"] == "main/ota_update.c")
    if hashlib.sha256(original.read_bytes()).hexdigest() != expected:
        raise ValueError("OTA source differs from pinned upstream")
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "main").mkdir()
        shutil.copy(original, work / "main/ota_update.c")
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            subprocess.run(
                ["git", "apply", "--include=main/ota_update.c", str(patch)],
                cwd=work,
                check=True,
            )
        source = (work / "main/ota_update.c").read_text()
        harness = (
            PRELUDE
            + function(source, "static esp_err_t ota_http_open(")
            + function(source, "static esp_err_t ota_start_server(")
            + TESTS
        )
        path = work / "http-nodelay.c"
        path.write_text(harness)
        for recovery in (0, 1):
            binary = work / f"http-nodelay-{recovery}"
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wno-unused-function",
                    "-Wno-unused-variable",
                    f"-DCONFIG_HOME_RUNTIME_RECOVERY_V1={recovery}",
                    str(path),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
