#!/usr/bin/env python3
"""Exercise actual patched WASM3 word handling and mmWave parsing on a host.

The test uses optimized strict-aliasing builds, both WASM3 slot sizes, real
WebAssembly execution, and synthetic 32/64-bit code cells. No device is used.
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
PIN = "6b8bcb1e07bf26ebef09a7211b0a37a446eafd52"
FIX = ROOT / "patches/0021-alias-safe-words.patch"


def leb(value, signed=False):
    result = []
    while True:
        byte = value & 127
        value >>= 7
        done = value == 0 and (not signed or not byte & 64)
        done |= signed and value == -1 and bool(byte & 64)
        result.append(byte if done else byte | 128)
        if done:
            return bytes(result)


def module_bytes():
    # Repeated constants exercise the existing constant-slot reuse paths.
    cases = []
    for width in (32, 64):
        for value in (0, 1, -1, -(1 << (width - 1)), (1 << (width - 1)) - 1):
            cases.append((width, value))
    types = b"\x02\x60\x00\x01\x7f\x60\x00\x01\x7e"
    functions = leb(len(cases)) + bytes(width == 64 for width, _ in cases)
    exports, bodies = leb(len(cases)), leb(len(cases))
    for index, (width, value) in enumerate(cases):
        name = f"f{index}".encode()
        exports += leb(len(name)) + name + b"\x00" + leb(index)
        const, xor = (b"\x41", b"\x73") if width == 32 else (b"\x42", b"\x85")
        body = b"\x00" + const + leb(value, True) + const + leb(17, True)
        body += const + leb(value, True) + xor + xor + b"\x0b"
        bodies += leb(len(body)) + body
    result = b"\x00asm\x01\x00\x00\x00"
    for section, content in ((1, types), (3, functions), (7, exports), (10, bodies)):
        result += bytes([section]) + leb(len(content)) + content
    return result


def compile_run(work, name, source, extra=()):
    path = work / f"{name}.c"
    path.write_text(source)
    executable = work / name
    subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-O2",
            "-fstrict-aliasing",
            "-Wstrict-aliasing=2",
            "-Werror=strict-aliasing",
            str(path),
            *extra,
            "-o",
            str(executable),
        ],
        check=True,
    )
    subprocess.run([str(executable)], check=True, timeout=30)


PREAMBLE = """
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s\\n", #x); abort(); } } while (0)
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Pristine pinned firmware source")
    parser.add_argument("wasm3", type=Path, help="Pinned WASM3 Git checkout")
    args = parser.parse_args()
    commit = subprocess.check_output(
        ["git", "-C", str(args.wasm3), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != PIN:
        parser.error("WASM3 source must match the pinned commit")
    lock = {
        row["path"]: row["sha256"]
        for row in json.loads((ROOT / "upstream-files.json").read_text())["files"]
    }
    radar = args.source / "main/mmwave_sensor.c"
    if hashlib.sha256(radar.read_bytes()).hexdigest() != lock["main/mmwave_sensor.c"]:
        parser.error("mmWave source differs from the pinned upstream file")
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        wasm = work / "components/wasm3/wasm3-src/source"
        wasm.mkdir(parents=True)
        # Read Git blobs, not potentially modified files in the supplied checkout.
        for path in (args.wasm3 / "source").iterdir():
            if path.suffix in (".c", ".h"):
                content = subprocess.check_output(
                    ["git", "-C", str(args.wasm3), "show", f"{PIN}:source/{path.name}"]
                )
                (wasm / path.name).write_bytes(content)
        (work / "main").mkdir()
        shutil.copy(radar, work / "main/mmwave_sensor.c")
        subprocess.run(["git", "apply", str(FIX)], cwd=work, check=True)
        code = (wasm / "m3_code.c").read_text()
        for width in (32, 64):
            source = (
                PREAMBLE
                + f"""
typedef uint32_t u32; typedef uint64_t u64;
#define M3_SIZEOF_PTR {width // 8}
#define d_m3Assert CHECK
typedef struct {{ struct {{ unsigned lineIndex, numLines; }} info;
    uint{width}_t code[8]; }} M3CodePage, *IM3CodePage;
"""
                + function(code, "void  EmitWord32")
                + function(code, "void  EmitWord64")
                + """
int main(void) {
    M3CodePage page; memset(&page, 0xa5, sizeof(page));
    page.info.lineIndex=0; page.info.numLines=8;
    uint32_t small=0x89abcdef; uint64_t large=UINT64_C(0xfedcba9876543210);
    unsigned char before[sizeof(page.code)]; memcpy(before,page.code,sizeof(before));
    memcpy(before,&small,sizeof(small));
    EmitWord32(&page,small); CHECK(page.info.lineIndex==1);
    CHECK(memcmp(before,page.code,sizeof(before))==0);
    memcpy(before+sizeof(page.code[0]),&large,sizeof(large));
    EmitWord64(&page,large); CHECK(page.info.lineIndex==1+8/sizeof(page.code[0]));
    CHECK(memcmp(before,page.code,sizeof(before))==0);
    return 0;
}
"""
            )
            compile_run(
                work, f"code-cells-{width}", source, ["-Werror=unused-variable"]
            )
        module = ",".join(str(byte) for byte in module_bytes())
        interpreter = (
            PREAMBLE
            + '#include "wasm3.h"\n'
            + f"unsigned char module[]={{{module}}};\n"
            + """
int main(void) {
    IM3Environment env=m3_NewEnvironment(); CHECK(env);
    IM3Runtime runtime=m3_NewRuntime(env,4096,NULL); CHECK(runtime);
    IM3Module parsed=NULL; CHECK(!m3_ParseModule(env,&parsed,module,sizeof(module)));
    CHECK(!m3_LoadModule(runtime,parsed)); CHECK(!m3_CompileModule(parsed));
    for (int i=0; i<10; ++i) {
        char name[16]; snprintf(name,sizeof(name),"f%d",i);
        IM3Function fn=NULL; CHECK(!m3_FindFunction(&fn,runtime,name));
        CHECK(!m3_CallV(fn));
        if (i<5) { uint32_t value=0; CHECK(!m3_GetResultsV(fn,&value)); CHECK(value==17); }
        else { uint64_t value=0; CHECK(!m3_GetResultsV(fn,&value)); CHECK(value==17); }
    }
    m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return 0;
}
"""
        )
        for slots in (1, 0):
            compile_run(
                work,
                f"interpreter-slots-{32 if slots else 64}",
                interpreter,
                [
                    "-I" + str(wasm),
                    f"-Dd_m3Use32BitSlots={slots}",
                    "-DM3_NO_MUSTTAIL=1",
                    *map(str, sorted(wasm.glob("*.c"))),
                    "-lm",
                ],
            )
        # Real parser, unchanged normal/engineering semantics and malformed guard.
        radar_source = (
            PREAMBLE
            + """
#define LD2410_REPORT_HEAD 0xaa
static struct { unsigned frame_count; int64_t last_update_us;
    bool person_present; unsigned target_count; float distance_cm; } s_state;
static int64_t esp_timer_get_time(void) { return 123; }
"""
            + function(
                (work / "main/mmwave_sensor.c").read_text(),
                "static void ld2410_process_frame",
            )
            + """
int main(void) {
    for (unsigned mode=1; mode<=2; ++mode) {
        for (unsigned target=0; target<=3; ++target) {
            uint8_t packet[12]={0}; packet[0]=mode; packet[1]=0xaa; packet[2]=target;
            packet[3]=123; packet[6]=45;
            ld2410_process_frame(packet,sizeof(packet));
            CHECK(s_state.person_present==(target!=0));
            CHECK(s_state.target_count==(target!=0));
            CHECK(s_state.distance_cm==(target==0?0:target==2?45:123));
        }
    }
    uint8_t bad[12]={0}; ld2410_process_frame(bad,sizeof(bad));
    CHECK(s_state.distance_cm==123); ld2410_process_frame(bad,1);
    CHECK(s_state.distance_cm==123); CHECK(s_state.frame_count==10);
    CHECK(s_state.last_update_us==123); return 0;
}
"""
        )
        compile_run(work, "radar-parser", radar_source, ["-Werror=unused-variable"])
    print(
        "PASS: 32/64-bit code cells; 20 real WASM executions across both slot sizes; 10 radar frames"
    )


if __name__ == "__main__":
    main()
