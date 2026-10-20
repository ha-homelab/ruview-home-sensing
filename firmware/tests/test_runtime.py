#!/usr/bin/env python3
"""Exercise the patched runtime with real WASM3 and the signed home module on a host.

Host timings and synthetic watermarks do not qualify ESP32 performance. This
checks dedicated execution context, eager compilation, bounded asynchronous timer
requests, realistic frame widths, slot recovery and concurrent lifecycle calls
under AddressSanitizer. Padded table-zero and malformed table-index fixtures cover
an independent pinned-WASM3 compatibility issue exposed by eager compilation.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WASM3_COMMIT = "6b8bcb1e07bf26ebef09a7211b0a37a446eafd52"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("wasm3", type=Path)
    parser.add_argument(
        "--wasm",
        type=Path,
        required=True,
        help="Explicit unsigned WASM test artifact built from pinned public sources",
    )
    parser.add_argument(
        "--gesture-restart",
        action="store_true",
        help="Require the selected gesture profile to reset across actual WASM stop/start calls",
    )
    parser.add_argument(
        "--gesture-restart-profile",
        choices=("home-signal-v3", "home-signal-v4", "home-signal-v5"),
        default="home-signal-v3",
        help="Select the exact gesture warmup contract for the restart fixture",
    )
    args = parser.parse_args()
    if args.gesture_restart_profile != "home-signal-v3" and not args.gesture_restart:
        parser.error("--gesture-restart-profile requires --gesture-restart")
    wasm3 = args.wasm3.resolve()
    commit = subprocess.check_output(
        ["git", "-C", str(wasm3), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != WASM3_COMMIT:
        parser.error("WASM3 must be checked out at the pinned commit")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "main").mkdir()
        for name in (
            "wasm_runtime.c",
            "wasm_runtime.h",
            "wasm_upload.c",
            "rvf_parser.h",
        ):
            shutil.copy(args.source / "main" / name, root / "main" / name)
        subprocess.run(
            ["git", "apply", str(ROOT / "patches/0003-wasm-runtime-lifecycle.patch")],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "apply", str(ROOT / "patches/0007-wasm-native-worker.patch")],
            cwd=root,
            check=True,
        )
        subprocess.run(
            [
                "git",
                "apply",
                "--include=main/wasm_runtime.*",
                str(ROOT / "patches/0011-wasm-lifecycle-and-callback-telemetry.patch"),
            ],
            cwd=root,
            check=True,
        )
        shutil.copy(ROOT / "tests/freertos_host.h", root / "main/freertos_host.h")
        runtime = root / "main/wasm_runtime.c"
        instrumented = runtime.read_text().replace(
            '#include "m3_env.h"',
            '#include "m3_env.h"\nextern void test_assert_worker(void);\n'
            "extern void test_timer_executing(void);",
        )
        instrumented = instrumented.replace(
            "M3Result result = m3_CallV(slot->fn_on_timer);",
            "test_timer_executing();\n        M3Result result = m3_CallV(slot->fn_on_timer);",
        )
        if args.gesture_restart:
            # Repeated gesture IDs can be suppressed by the UDP deadband.
            # Count actual guest import calls, preserving the transport filter.
            instrumented = instrumented.replace(
                "static m3ApiRawFunction(host_csi_emit_event)",
                "extern void test_gesture_emit(int event_type);\n"
                "static m3ApiRawFunction(host_csi_emit_event)",
            ).replace(
                "    wasm_slot_t *slot = &s_slots[s_cur_slot_id];\n"
                "    if (slot->n_events < WASM_MAX_EVENTS)",
                "    test_gesture_emit(event_type);\n"
                "    wasm_slot_t *slot = &s_slots[s_cur_slot_id];\n"
                "    if (slot->n_events < WASM_MAX_EVENTS)",
            )
        runtime.write_text(instrumented)
        # Instrument the pinned interpreter copy, leaving the checkout unchanged.
        wasm3_copy = root / "components/wasm3/wasm3-src/source"
        shutil.copytree(wasm3 / "source", wasm3_copy)
        subprocess.run(
            ["git", "apply", str(ROOT / "patches/0008-wasm3-table-index.patch")],
            cwd=root,
            check=True,
        )
        compiler = wasm3_copy / "m3_compile.c"
        text = compiler.read_text().replace(
            "M3Result  CompileFunction  (IM3Function io_function)\n{",
            "extern void test_compiling(void);\n"
            "M3Result  CompileFunction  (IM3Function io_function)\n{\n    test_compiling();",
        )
        compiler.write_text(text)
        environment = wasm3_copy / "m3_env.c"
        text = environment.read_text().replace(
            "IM3Environment  m3_NewEnvironment  ()\n{",
            "extern int test_fail_environment;\n"
            "IM3Environment  m3_NewEnvironment  ()\n{\n"
            "    if (test_fail_environment) return NULL;",
        )
        environment.write_text(text)
        headers = {
            "sdkconfig.h": "#define CONFIG_WASM_ENABLE 1\n#define WASM3_AVAILABLE 1\n#define CONFIG_FREERTOS_UNICORE 0\n",
            "esp_err.h": """#pragma once
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 1
#define ESP_ERR_INVALID_SIZE 2
#define ESP_ERR_NO_MEM 3
#define ESP_ERR_INVALID_STATE 4
""",
            "nvs_config.h": "typedef struct { int unused; } nvs_config_t;\n",
            "csi_collector.h": "#include <stdint.h>\nstatic inline uint8_t csi_collector_get_node_id(void) { return 2; }\n",
            "stream_sender.h": "#include <stddef.h>\n#include <stdint.h>\nint stream_sender_send(const uint8_t*, size_t);\n",
            "edge_processing.h": """#pragma once
#include <stdint.h>
#define EDGE_PHASE_HISTORY_LEN 256
typedef struct {
    uint16_t breathing_rate, heartrate;
    uint8_t flags, n_persons;
    float motion_energy;
} edge_vitals_pkt_t;
static inline void edge_get_phase_history(const float **buf, uint16_t *len, uint16_t *idx) {
    *buf = 0; *len = 0; *idx = 0;
}
""",
            "esp_log.h": """#include <stdio.h>
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGW(tag, ...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while(0)
#define ESP_LOGE ESP_LOGW
""".replace("fputc('\n'", "fputc('\\n'"),
            "esp_timer.h": """#include <stdint.h>
#include <time.h>
static inline int64_t esp_timer_get_time(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
""",
            "esp_heap_caps.h": """#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_INTERNAL 4
static inline void *heap_caps_malloc(size_t n, int caps) { return malloc(n); }
static inline size_t heap_caps_get_minimum_free_size(int caps) { return 80000; }
static inline size_t heap_caps_get_free_size(int caps) { return 120000; }
static inline size_t heap_caps_get_largest_free_block(int caps) { return 90000; }
""",
            "freertos/FreeRTOS.h": '#include "freertos_host.h"\n',
            "freertos/semphr.h": '#include "freertos_host.h"\n',
            "freertos/task.h": '#include "freertos_host.h"\n',
            "freertos/queue.h": '#include "freertos_host.h"\n',
        }
        for name, text in headers.items():
            path = root / "main" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        wasm = args.wasm.read_bytes()
        if not wasm.startswith(b"\0asm\x01\0\0\0") or not 8 <= len(wasm) <= 128 * 1024:
            parser.error(
                "Expected a WASM v1 binary within the firmware's 128 KiB limit"
            )
        print(
            f"Host test artifact: {len(wasm)} bytes, SHA256 {hashlib.sha256(wasm).hexdigest()}",
            flush=True,
        )
        (root / "module.wasm").write_bytes(wasm)
        (root / "harness.c").write_text(r"""
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include "wasm_runtime.h"
#include "nvs_config.h"
#include "freertos_host.h"
#include "wasm3.h"
nvs_config_t g_nvs_config;
pthread_t test_worker_thread;
atomic_int test_task_creations, test_self_deletes, test_compile_calls, test_timer_calls;
static atomic_int hold_execution, execution_blocked;
int test_fail_task_create, test_fail_environment;
void test_assert_worker(void) { assert(pthread_equal(pthread_self(), test_worker_thread)); }
void test_compiling(void) { test_assert_worker(); test_compile_calls++; }
void test_timer_executing(void) { test_assert_worker(); test_timer_calls++; }
M3Result m3_Yield(void) {
    test_assert_worker();
    if (hold_execution) {
        execution_blocked=1;
        while (hold_execution) {
            struct timespec delay={.tv_nsec=1000000}; nanosleep(&delay,NULL);
        }
    }
    return m3Err_none;
}

static atomic_int packets, stop_workers, anomaly_packets, gesture_emissions;
void test_gesture_emit(int event_type) {
    test_assert_worker();
    if (event_type==1) gesture_emissions++;
}
int stream_sender_send(const uint8_t *buf, size_t n) {
    const wasm_output_pkt_t *p = (const void*)buf;
    assert(n >= 8 && p->magic == WASM_OUTPUT_MAGIC && p->node_id == 2);
    assert(p->event_count <= WASM_MAX_EVENTS);
    for (int i=0; i<p->event_count; i++) {
        assert(isfinite(p->events[i].value));
        if (p->events[i].event_type==3) anomaly_packets++;
    }
    packets++; return (int)n;
}
static void frame_values(int n, int step, float amplitude_scale) {
    float phase[192], amplitude[192], variance[192];
    for (int i=0; i<n; i++) {
        phase[i]=sinf(0.1f*i + step*0.3f);
        amplitude[i]=(10 + cosf(step*0.2f + i*0.5f))*amplitude_scale;
        variance[i]=0.1f + 0.01f*(step % 13);
    }
    edge_vitals_pkt_t v = {.motion_energy=1.25f, .flags=1};
    wasm_runtime_on_frame(phase, amplitude, variance, n, &v);
}
static void frame(void) {
    static atomic_int frame_number;
    int step = frame_number++;
    /* DSP admits <=128; test its boundaries and the wider public runtime API. */
    static const int widths[]={0,1,32,64,127,128,129,192};
    int n=widths[step % (sizeof(widths)/sizeof(widths[0]))];
    frame_values(n,step,1.0f);
}
static void *one_frame(void *unused) { frame(); return NULL; }
static void *frames(void *unused) { while (!stop_workers) frame(); return NULL; }
static void *timers(void *unused) { while (!stop_workers) wasm_runtime_on_timer(); return NULL; }
int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *f=fopen(argv[1], "rb"); assert(f); fseek(f,0,SEEK_END);
    long n=ftell(f); rewind(f); uint8_t *data=malloc(n); assert(fread(data,1,n,f)==n); fclose(f);
    /* A failed worker allocation must leave CSI calls harmless and loading closed. */
    test_fail_task_create=1;
    assert(wasm_runtime_init()==ESP_ERR_NO_MEM);
    frame(); wasm_runtime_on_timer();
    uint8_t failed_id;
    assert(wasm_runtime_load(data,n,&failed_id)==ESP_ERR_INVALID_STATE);
    test_fail_task_create=0;
    test_fail_environment=1;
    assert(wasm_runtime_init()==ESP_ERR_NO_MEM);
    for (int j=0; j<100 && test_self_deletes==0; j++) {
        struct timespec delay={.tv_nsec=1000000}; nanosleep(&delay,NULL);
    }
    assert(test_self_deletes==1);
    frame(); wasm_runtime_on_timer();
    assert(wasm_runtime_load(data,n,&failed_id)==ESP_ERR_INVALID_STATE);
    test_fail_environment=0;
    assert(wasm_runtime_init()==ESP_OK);
    assert(test_task_creations==2);
    wasm_resource_info_t resources;
    wasm_runtime_get_resources(&resources);
    assert(resources.worker_stack_bytes==32768);
    assert(resources.worker_stack_min_free_bytes==12345 && resources.uptime_ms>0);
    assert(resources.internal_free_bytes==120000 && resources.internal_largest_free_block==90000);
    assert(resources.internal_min_free_bytes==80000);
    uint8_t id; wasm_module_info_t info[WASM_MAX_MODULES]; uint8_t count;
    /* CALL_INDIRECT_FIXTURES */
    assert(wasm_runtime_load(indirect_zero,sizeof(indirect_zero),&id)==ESP_OK);
    assert(wasm_runtime_start(id)==ESP_OK);
    frame();
    wasm_runtime_get_info(info,&count);
    assert(count==1 && info[id].frame_count==1 && info[id].error_count==0);
    assert(wasm_runtime_unload(id)==ESP_OK);
    assert(wasm_runtime_load(indirect_nonzero,sizeof(indirect_nonzero),&id)!=ESP_OK);
    assert(wasm_runtime_load(indirect_overflow,sizeof(indirect_overflow),&id)!=ESP_OK);
    assert(wasm_runtime_load(indirect_highbits,sizeof(indirect_highbits),&id)!=ESP_OK);
    const uint8_t invalid[]={0,97,115,109,1,0,0,0,255,255,255};
    for (int i=0; i<8; i++) {
        assert(wasm_runtime_load(invalid,sizeof(invalid),&id)!=ESP_OK);
        assert(wasm_runtime_load(data,n,&id)==ESP_OK);
        int compiled_before_start=test_compile_calls;
        assert(compiled_before_start>0);
        assert(wasm_runtime_set_manifest(id,"home-signal",0x6b,10000)==ESP_OK);
        assert(wasm_runtime_start(id)==ESP_OK);
        for (int j=0; j<40; j++) frame();
        int timers_before=test_timer_calls;
        wasm_runtime_on_timer();
        for (int j=0; j<100 && test_timer_calls==timers_before; j++) {
            struct timespec delay={.tv_nsec=1000000}; nanosleep(&delay,NULL);
        }
        assert(test_timer_calls>timers_before);
        assert(test_compile_calls==compiled_before_start); /* No lazy compiler in callbacks. */
        wasm_runtime_get_info(info,&count);
        assert(count==1 && info[id].frame_count==40 && info[id].error_count==0);
        assert(wasm_runtime_unload(id)==ESP_OK);
    }
    assert(packets>0);
    /* Run one persistent instance past gesture cooldown/window wrap AND the
     * anomaly baseline at frame100. Synthetic amplitudes then exercise the
     * post-baseline energy-spike path through the actual WASM interpreter.
     * Host timings/resource mocks do not establish the ESP32 10ms budget. */
    assert(wasm_runtime_load(data,n,&id)==ESP_OK);
    assert(wasm_runtime_set_manifest(id,"home-signal",0x6b,10000)==ESP_OK);
    int compiled_before_warmup=test_compile_calls;
    int anomalies_before=anomaly_packets;
    assert(wasm_runtime_start(id)==ESP_OK);
    for (int j=0; j<1208; j++) {
        frame_values(64,j,j>=100 && j%100==0 ? 8.0f : 1.0f);
    }
    wasm_runtime_get_info(info,&count);
    assert(count==1 && info[id].state==WASM_MODULE_RUNNING);
    assert(info[id].frame_count==1208 && info[id].error_count==0);
    assert(info[id].budget_faults==0);
    assert(anomaly_packets>anomalies_before);
    assert(test_compile_calls==compiled_before_warmup);
    assert(wasm_runtime_unload(id)==ESP_OK);
    /* GESTURE_RESTART_CHECK */
    /* Hold one real interpreter invocation. Timer calls must return immediately,
     * coalesce into the bounded queue, and never borrow a returning stack frame. */
    assert(wasm_runtime_load(data,n,&id)==ESP_OK);
    assert(wasm_runtime_set_manifest(id,"home-signal",0x6b,10000)==ESP_OK);
    assert(wasm_runtime_start(id)==ESP_OK);
    hold_execution=1; execution_blocked=0;
    pthread_t held; pthread_create(&held,NULL,one_frame,NULL);
    for (int j=0; j<100 && !execution_blocked; j++) {
        struct timespec delay={.tv_nsec=1000000}; nanosleep(&delay,NULL);
    }
    assert(execution_blocked);
    int timer_before=test_timer_calls;
    struct timespec before,after; clock_gettime(CLOCK_MONOTONIC,&before);
    for (int j=0; j<1000; j++) wasm_runtime_on_timer();
    frame(); /* DSP trylock must also skip while the worker holds this frame. */
    clock_gettime(CLOCK_MONOTONIC,&after);
    assert((after.tv_sec-before.tv_sec)*1e9 + after.tv_nsec-before.tv_nsec < 1e9);
    hold_execution=0; pthread_join(held,NULL);
    wasm_runtime_get_info(info,&count);
    assert(count==1 && info[id].frame_count==1 && info[id].error_count==0);
    assert(test_timer_calls<=timer_before+1);
    assert(wasm_runtime_unload(id)==ESP_OK);
    pthread_t a,b; pthread_create(&a,NULL,frames,NULL); pthread_create(&b,NULL,timers,NULL);
    for (int i=0; i<30; i++) {
        assert(wasm_runtime_load(data,n,&id)==ESP_OK);
        assert(wasm_runtime_set_manifest(id,"home-signal",0x6b,10000)==ESP_OK);
        assert(wasm_runtime_start(id)==ESP_OK);
        assert(wasm_runtime_unload(id)==ESP_OK);
    }
    stop_workers=1; pthread_join(a,NULL); pthread_join(b,NULL);
    wasm_runtime_get_info(info,&count); assert(count==0);
    puts("Dedicated worker, eager compile, 1208-frame warmup, asynchronous timers, resource reporting, recovery and concurrent lifecycle checks passed.");
    free(data); return 0;
}
""")

        def indirect_fixture(table_index):
            def section(kind, payload):
                assert len(payload) < 128
                return bytes([kind, len(payload)]) + bytes(payload)

            body = bytes([0, 0x41, 0, 0x11, 0]) + table_index + b"\x0b"
            return (
                b"\0asm\x01\0\0\0"
                + section(1, [2, 0x60, 0, 0, 0x60, 1, 0x7F, 0])
                + section(3, [2, 0, 1])
                + section(4, [1, 0x70, 0, 1])
                + section(7, b"\x01\x08on_frame\x00\x01")
                + section(9, [1, 0, 0x41, 0, 0x0B, 1, 0])
                + section(10, bytes([2, 2, 0, 0x0B, len(body)]) + body)
            )

        fixtures = []
        for name, index in (
            ("zero", b"\x80\x80\x80\x80\x00"),
            ("nonzero", b"\x81\x80\x80\x80\x00"),
            ("overflow", b"\x80\x80\x80\x80\x80\x00"),
            ("highbits", b"\x80\x80\x80\x80\x10"),
        ):
            values = ",".join(str(value) for value in indirect_fixture(index))
            fixtures.append(f"const uint8_t indirect_{name}[] = {{{values}}};")
        harness = root / "harness.c"
        harness.write_text(
            harness.read_text().replace(
                "/* CALL_INDIRECT_FIXTURES */", "\n".join(fixtures)
            )
        )
        if args.gesture_restart:
            warmup = {"home-signal-v3": 12, "home-signal-v4": 16, "home-signal-v5": 24}[
                args.gesture_restart_profile
            ]
            restart_check = (
                (
                    f'    const char *gesture_test_name = "{args.gesture_restart_profile}";\n'
                    f"    const int gesture_test_warmup = {warmup};\n"
                    f"    const int gesture_test_frame_count = {9 + 2 * warmup};\n"
                )
                + """
    assert(wasm_runtime_load(data,n,&id)==ESP_OK);
    assert(wasm_runtime_set_manifest(id,gesture_test_name,0x6b,10000)==ESP_OK);
    assert(wasm_runtime_start(id)==ESP_OK);
    int gestures_before=gesture_emissions;
    int compiled_before_restart=test_compile_calls;
    /* Constant first phase: first job starts at frame 9.
     * Require the selected profile's exact fresh warmup after stopping mid-job.
     * Stop again during cooldown, and require the same fresh behavior. */
    for (int j=0; j<9; j++) frame_values(64,0,1.0f);
    assert(gesture_emissions==gestures_before);
    for (int restart=0; restart<2; restart++) {
        assert(wasm_runtime_stop(id)==ESP_OK);
        for (int j=0; j<20; j++) frame_values(64,0,1.0f);
        assert(gesture_emissions==gestures_before+restart);
        assert(wasm_runtime_start(id)==ESP_OK);
        for (int j=0; j<gesture_test_warmup-1; j++) {
            frame_values(64,0,1.0f);
            assert(gesture_emissions==gestures_before+restart);
        }
        frame_values(64,0,1.0f);
        assert(gesture_emissions==gestures_before+restart+1);
    }
    wasm_runtime_get_info(info,&count);
    assert(info[id].frame_count==gesture_test_frame_count && info[id].error_count==0);
    assert(test_compile_calls==compiled_before_restart);
    assert(wasm_runtime_unload(id)==ESP_OK);
    puts("Actual WASM pending-gesture and cooldown stop/start reset checks passed.");
"""
            )
            harness.write_text(
                harness.read_text().replace(
                    "/* GESTURE_RESTART_CHECK */", restart_check
                )
            )
        executable = root / "test-runtime"
        command = [
            "cc",
            "-std=c11",
            "-Werror=int-conversion",
            "-Werror=incompatible-pointer-types",
            "-Werror=implicit-function-declaration",
            "-Werror=return-type",
            "-Werror=format",
            "-D_POSIX_C_SOURCE=200809L",
            "-D_DEFAULT_SOURCE",
            "-D_DARWIN_C_SOURCE",
            # Match the firmware component's interpreter configuration.
            "-Dd_m3HasFloat=1",
            "-Dd_m3Use32BitSlots=1",
            "-Dd_m3MaxFunctionStackHeight=512",
            "-Dd_m3CodePageAlignSize=4096",
            "-Dd_m3LogOutput=0",
            "-Dd_m3FixedHeap=0",
            "-DM3_NO_MUSTTAIL=1",
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-pthread",
            "-I" + str(root / "main"),
            "-I" + str(wasm3_copy),
            str(root / "main/wasm_runtime.c"),
            str(root / "harness.c"),
            *map(str, sorted(wasm3_copy.glob("*.c"))),
            "-lm",
            "-o",
            str(executable),
        ]
        subprocess.run(command, check=True)
        subprocess.run(
            [str(executable), str(root / "module.wasm")],
            check=True,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"},
            timeout=90,
        )


if __name__ == "__main__":
    main()
