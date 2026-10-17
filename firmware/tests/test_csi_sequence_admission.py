#!/usr/bin/env python3
"""Compile the actual old/new CSI callbacks with deterministic time and UDP mocks.

The old callback must reproduce a sequence hole from an intentional cadence skip.
The fixed callback must avoid that hole without hiding failed send attempts or
skipping edge processing. No radios, sockets, firmware builds or devices are used.
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
FIX = ROOT / "patches/0017-csi-sequence-after-admission.patch"

PREAMBLE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while (0)
#define CONFIG_CSI_FRAME_HE_TAGGING 1
#define CONFIG_SOC_WIFI_HE_SUPPORT 0
#define TAG "test"
#define CSI_MAGIC 0xC5110001u
#define CSI_HEADER_SIZE 20
#define CSI_MAX_FRAME_SIZE (CSI_HEADER_SIZE + 4 * 256 * 2)
#define EDGE_DSP_MIN_INTERVAL_US 50000
typedef struct {
    int8_t *buf; uint16_t len; uint8_t mac[6];
    struct { uint8_t channel, sig_mode, cwb, stbc; int8_t rssi, noise_floor; } rx_ctrl;
} wifi_csi_info_t;
static uint32_t s_sequence, s_cb_count, s_send_ok, s_send_fail, s_rate_skip, s_early_drop, s_edge_rate_skip;
static uint8_t s_node_id=2, s_filter_mac[6];
static bool s_filter_mac_set;
static int64_t s_last_process_us, s_last_send_us, s_next_edge_enqueue_us;
static int64_t clock_us, copy_delay, log_delay;
static int send_result, attempts, delivered, edge_calls, sync_calls;
static uint32_t sent_sequences[32], delivered_sequences[32];
static int64_t send_times[32];
static uint8_t last_frame[CSI_MAX_FRAME_SIZE];
static size_t last_length;
static int64_t esp_timer_get_time(void) { return clock_us; }
static void fake_log(const char *tag, const char *format, ...) {
    (void)tag; (void)format; clock_us+=log_delay; log_delay=0;
}
#define ESP_LOGI(...) fake_log(__VA_ARGS__)
#define ESP_LOGW(...) fake_log(__VA_ARGS__)
static void *timed_memcpy(void *dst, const void *src, size_t n) {
    void *result=memcpy(dst,src,n);
    if (n==128) { clock_us+=copy_delay; copy_delay=0; }
    return result;
}
#define memcpy timed_memcpy
static bool c6_sync_espnow_is_valid(void) { return false; }
static bool c6_sync_espnow_is_leader(void) { return false; }
static uint64_t c6_sync_espnow_get_epoch_us(void) { return 0; }
static int64_t c6_sync_espnow_get_offset_us_smoothed(void) { return 0; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static int stream_sender_send(const uint8_t *frame, size_t n) {
    CHECK(attempts<32 && n<=sizeof(last_frame));
    sent_sequences[attempts]=le32(frame+12); send_times[attempts++]=clock_us;
    memcpy(last_frame,frame,n); last_length=n;
    if (send_result>0) delivered_sequences[delivered++]=le32(frame+12);
    return send_result;
}
static int stream_sender_send_priority(const uint8_t *frame, size_t n) {
    CHECK(n==32 && le32(frame)==0xC511A110u); ++sync_calls; return 32;
}
static int edge_enqueue_csi(const uint8_t *p, uint16_t n, int8_t rssi, uint8_t channel) {
    CHECK(p && n>0 && rssi==-55 && channel==11); ++edge_calls; return 0;
}
"""

SCENARIOS = r"""
static int8_t iq[128];
static wifi_csi_info_t info;
static void reset(void) {
    s_sequence=s_cb_count=s_send_ok=s_send_fail=s_rate_skip=s_early_drop=s_edge_rate_skip=0;
    s_last_process_us=s_last_send_us=s_next_edge_enqueue_us=0; s_filter_mac_set=false;
    clock_us=copy_delay=log_delay=0; send_result=148;
    attempts=delivered=edge_calls=sync_calls=0; last_length=0;
    memset(&info,0,sizeof(info)); for (int i=0;i<128;i++) iq[i]=(int8_t)i;
    info.buf=iq; info.len=128; info.rx_ctrl.channel=11;
    info.rx_ctrl.rssi=-55; info.rx_ctrl.noise_floor=-96;
}
static void callback(int64_t t) { clock_us=t; wifi_csi_callback(NULL,&info); }
static void verify_frame(void) {
    CHECK(last_length==148 && le32(last_frame)==CSI_MAGIC);
    CHECK(last_frame[4]==2 && last_frame[5]==1 && last_frame[6]==64 && last_frame[7]==0);
    CHECK(le32(last_frame+8)==2462 && (int8_t)last_frame[16]==-55 && (int8_t)last_frame[17]==-96);
    CHECK(last_frame[18]==0 && last_frame[19]==0 && memcmp(last_frame+20,iq,128)==0);
}
int main(void) {
    /* Constant serialization cost must not turn the exact 50 Hz boundary
       into 25 Hz. Admission retains the original post-serialization clock. */
    for (int cost=1;cost<=1000;cost*=10) {
        reset();
        for (int frame=1;frame<=20;frame++) {
            copy_delay=cost; callback((int64_t)frame*20000);
            CHECK(attempts==frame && sent_sequences[frame-1]==(uint32_t)(frame-1));
            CHECK(send_times[frame-1]==(int64_t)frame*20000+cost);
        }
        CHECK(s_rate_skip==0 && s_sequence==20 && delivered==20);
    }
    /* Earlier serialization delay admits the next callback at the early gate,
       but its second gate must reject it without allocating a sequence. */
    reset(); copy_delay=1000; callback(20000); callback(40000); callback(60000);
    CHECK(attempts==2 && delivered==2 && s_rate_skip==1 && sent_sequences[0]==0);
    CHECK(send_times[0]==21000 && send_times[1]==60000);
#ifdef EXPECT_LEGACY
    CHECK(sent_sequences[1]==2 && s_sequence==3);
    puts("Legacy callback reproduced cadence-only sequence hole: delivered 0,2; no send failure.");
#else
    CHECK(sent_sequences[1]==1 && s_sequence==2 && s_send_fail==0); verify_frame();
    /* Serialization alone must not allocate a sequence; only admitted
       sends may do so. The callback is the sole production caller. */
    reset(); uint8_t encoded[CSI_MAX_FRAME_SIZE];
    CHECK(csi_serialize_frame(&info,encoded,sizeof(encoded))==148);
    CHECK(le32(encoded+12)==0 && s_sequence==0);
    CHECK(csi_serialize_frame(&info,encoded,sizeof(encoded))==148);
    CHECK(le32(encoded+12)==0 && s_sequence==0);
    /* Logging delay produces the same double-gate interaction. */
    reset(); log_delay=1000; callback(20000); callback(40000); callback(60000);
    CHECK(attempts==2 && sent_sequences[1]==1 && s_rate_skip==1 && s_sequence==2);
    /* Negative, zero and consecutive sender-backoff failures remain visible. */
    for (int failure=-1;failure<=0;failure++) {
        reset(); callback(20000); send_result=failure; callback(40000);
        send_result=148; callback(60000);
        CHECK(attempts==3 && delivered==2 && delivered_sequences[0]==0 && delivered_sequences[1]==2);
        CHECK(s_send_fail==1 && s_send_ok==2 && s_sequence==3 && s_rate_skip==0);
    }
    reset(); callback(20000); send_result=-1; callback(40000); callback(60000);
    send_result=148; callback(80000);
    CHECK(delivered==2 && delivered_sequences[1]==3 && s_send_fail==2 && s_sequence==4);
    /* Edge enqueue and sync remain active when final admission rejects CSI. */
    reset(); s_cb_count=19; s_last_send_us=1; callback(20000);
    CHECK(attempts==0 && s_sequence==0 && s_rate_skip==1 && edge_calls==1 && sync_calls==1);
    /* Existing early gate and MAC filter do not allocate sequence numbers. */
    reset(); callback(19999); CHECK(s_early_drop==1 && attempts==0 && edge_calls==0 && s_sequence==0);
    callback(20000); CHECK(attempts==1 && s_sequence==1);
    callback(39999); CHECK(s_early_drop==2 && s_sequence==1);
    callback(40000); CHECK(attempts==2 && s_sequence==2 && s_rate_skip==0);
    reset(); s_filter_mac_set=true; s_filter_mac[0]=1; callback(20000);
    CHECK(s_sequence==0 && attempts==0 && edge_calls==0);
    /* Invalid serialization does not consume a sequence or attempt a send. */
    reset(); info.buf=NULL; callback(20000); CHECK(s_sequence==0 && attempts==0);
    reset(); info.len=CSI_MAX_FRAME_SIZE; callback(20000); CHECK(s_sequence==0 && attempts==0);
    /* Unsigned wrap and a failed wraparound attempt remain distinguishable. */
    reset(); s_sequence=UINT32_MAX; callback(20000); callback(40000);
    CHECK(sent_sequences[0]==UINT32_MAX && sent_sequences[1]==0 && s_sequence==1);
    reset(); s_sequence=UINT32_MAX; send_result=-1; callback(20000); send_result=148; callback(40000);
    CHECK(sent_sequences[0]==UINT32_MAX && delivered_sequences[0]==0 && s_send_fail==1 && s_sequence==1);
    puts("Fixed actual CSI callback passed cadence, payload, real failures/backoff, edge/sync, filters, invalid frames and wrap regression scenarios.");
#endif
    return 0;
}
"""


def compile_and_run(work, source, legacy):
    limits = "\n".join(
        re.findall(r"^#define CSI_MIN_(?:PROCESS|SEND)_INTERVAL_US.*$", source, re.M)
    )
    if len(limits.splitlines()) != 2:
        raise ValueError("CSI admission constants missing")
    harness = (
        PREAMBLE
        + limits
        + "\n"
        + function(source, "size_t csi_serialize_frame(")
        + function(source, "static void wifi_csi_callback(")
        + SCENARIOS
    )
    cfile = work / ("legacy.c" if legacy else "fixed.c")
    cfile.write_text(harness)
    binary = cfile.with_suffix("")
    subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            *(["-DEXPECT_LEGACY", "-Wno-unused-function"] if legacy else []),
            str(cfile),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    args = parser.parse_args()
    path = "main/csi_collector.c"
    original = args.source / path
    lock = json.loads((ROOT / "upstream-files.json").read_text())["files"]
    expected = next(row["sha256"] for row in lock if row["path"] == path)
    if hashlib.sha256(original.read_bytes()).hexdigest() != expected:
        raise ValueError("CSI source differs from pinned upstream")
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "main").mkdir()
        shutil.copy(original, work / path)
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            if patch.name >= FIX.name:
                break
            subprocess.run(
                ["git", "apply", f"--include={path}", str(patch)],
                cwd=work,
                check=True,
            )
        compile_and_run(work, (work / path).read_text(), legacy=True)
        subprocess.run(["git", "apply", str(FIX)], cwd=work, check=True)
        compile_and_run(work, (work / path).read_text(), legacy=False)


if __name__ == "__main__":
    main()
