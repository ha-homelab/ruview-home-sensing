#!/usr/bin/env python3
"""Host regression of exact pinned phase/variance/Top-K production fragments.

This is a focused C slice, not the complete DSP/FreeRTOS pipeline or device
qualification. The observation hook checks logical current-grid bounds before
an uninitialized phases[] tail could be read. No radio/socket/build operation.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "e5966db2fcfb196956ac70653db0ad2416690656fcd967ea4286474664ca2942"
HEADER_SHA = "67e41cc782858f8529f758fcc6120b51365c1be2aaaa5f5872afe2c5c0bf85a2"
PATCH = ROOT / "patches/0023-current-grid-top-k.patch"


def checked(path, expected):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Pristine pinned source identity required: " + str(path))
    return raw.decode()


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth, position = 1, opening + 1
    while depth:
        depth += (source[position] == "{") - (source[position] == "}")
        position += 1
    return source[start:position] + "\n"


PREAMBLE = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "GRID_CHECK:%s\n", #x); exit(42); } } while (0)
"""
STATE = r"""
static edge_config_t s_cfg;
static edge_welford_t s_subcarrier_var[EDGE_MAX_SUBCARRIERS];
static float s_prev_phase[EDGE_MAX_SUBCARRIERS];
static bool s_phase_initialized;
static uint8_t s_top_k[EDGE_TOP_K], s_top_k_count;
static uint32_t s_frame_count;
static unsigned updates;
static float last_phase;
static void grid_check(uint16_t bins) {
    CHECK(s_top_k_count <= bins);
    for (unsigned k = 0; k < s_top_k_count; k++) CHECK(s_top_k[k] < bins);
}
"""
CASES = r"""
static void reset_state(uint8_t k) {
    memset(&s_cfg, 0, sizeof(s_cfg));
    s_cfg.top_k_count = k;
    memset(s_prev_phase, 0, sizeof(s_prev_phase));
    memset(s_top_k, 0, sizeof(s_top_k));
    for (unsigned sc = 0; sc < EDGE_MAX_SUBCARRIERS; sc++) welford_reset(&s_subcarrier_var[sc]);
    s_phase_initialized = false; s_top_k_count = 0; s_frame_count = 0; updates = 0;
}
static edge_ring_slot_t warmup(bool primary) {
    reset_state(EDGE_TOP_K);
    edge_ring_slot_t slot = {0}; slot.iq_len = 256;
    for (unsigned frame = 1; frame <= 101; frame++) {
        for (unsigned sc = 0; sc < EDGE_MAX_SUBCARRIERS; sc++) {
            slot.iq_data[2*sc] = 100; slot.iq_data[2*sc+1] = 0;
        }
        int sign = frame % 2 ? 1 : -1;
        slot.iq_data[255] = (uint8_t)(int8_t)(sign * (primary ? 100 : 50));
        if (!primary) slot.iq_data[1] = (uint8_t)(int8_t)(sign * 100);
        process_current_grid(&slot);
        CHECK(updates == (frame < 101 ? 1u : 2u));
    }
    CHECK(s_top_k[primary ? 0 : 1] == 127);
    return slot;
}
static void shrink_case(bool primary) {
    edge_ring_slot_t slot = warmup(primary);
    slot.iq_len = 128; process_current_grid(&slot);
    CHECK(s_frame_count == 102); CHECK(updates == 3); CHECK(s_top_k_count == EDGE_TOP_K);
    /* A valid growth must NOT change the existing periodic-selection contract. */
    uint8_t prior[EDGE_TOP_K]; memcpy(prior, s_top_k, sizeof(prior));
    slot.iq_len = 256; process_current_grid(&slot);
    CHECK(updates == 3); CHECK(memcmp(prior, s_top_k, sizeof(prior)) == 0);
    slot.iq_len = 2; process_current_grid(&slot); CHECK(s_top_k_count == 1); CHECK(s_top_k[0] == 0);
    slot.iq_len = 128; process_current_grid(&slot); CHECK(s_top_k_count == 1);
    unsigned before = s_frame_count;
    const uint16_t rejected[] = {0, 1, 258, 384, 512, 1024};
    for (unsigned i = 0; i < sizeof(rejected)/sizeof(rejected[0]); i++) {
        slot.iq_len = rejected[i]; process_current_grid(&slot); CHECK(s_frame_count == before);
    }
}
static void boundaries(void) {
    const uint16_t bins[] = {1, 2, 7, 8, 9, 63, 64, 65, 127, 128};
    const uint8_t counts[] = {0, 1, 8, 255};
    for (unsigned ki = 0; ki < sizeof(counts)/sizeof(counts[0]); ki++) {
        reset_state(counts[ki]); edge_ring_slot_t slot = {0};
        for (unsigned repeat = 0; repeat < 5; repeat++) {
            for (unsigned j = 0; j < sizeof(bins)/sizeof(bins[0]); j++) {
                slot.iq_len = 2*bins[j]; process_current_grid(&slot);
                CHECK(s_top_k_count <= EDGE_TOP_K); CHECK(s_top_k_count <= bins[j]);
                if (s_top_k_count) CHECK(isfinite(last_phase));
            }
        }
    }
}
int main(int argc, char **argv) {
    if (argc == 2) shrink_case(strcmp(argv[1], "primary") == 0);
    else { shrink_case(true); shrink_case(false); boundaries(); }
    puts("PASS: current-grid slice bounds, primary/secondary shrink, cadence, growth and rejected long grids");
    return 0;
}
"""


def harness(source, header):
    types = ""
    for name in ("edge_ring_slot_t", "edge_welford_t", "edge_config_t"):
        types += (
            re.search(r"typedef struct \{[^{}]*\} " + name + r";", header)[0] + "\n"
        )
    macros = "\n".join(
        re.search(r"^#define " + name + r"\s+[^\n]+", header, re.M)[0]
        for name in ("EDGE_TOP_K", "EDGE_MAX_SUBCARRIERS", "EDGE_MAX_IQ_BYTES")
    )
    helpers = "".join(
        function(source, signature)
        for signature in (
            "static inline float extract_phase(",
            "static inline float unwrap_phase(",
            "static inline void welford_reset(",
            "static inline void welford_update(",
            "static inline double welford_variance(",
        )
    )
    selection = function(source, "static void update_top_k(")
    # Counter instrumentation only; the production selection body stays exact.
    selection = selection.replace("{", "{\n    updates++;", 1)
    frame = function(source, "static void process_frame(")
    start = frame.index("    uint16_t n_subcarriers")
    guard_end = frame.index("    s_latest_rssi")
    phases = frame.index("    /* --- Step 1-2:")
    primary_end = frame.index("    /* Store in phase history ring buffer. */")
    body = frame[start:guard_end] + frame[phases:primary_end]
    body = body.replace(
        "    /* --- Step 5:", "    grid_check(n_subcarriers);\n\n    /* --- Step 5:", 1
    )
    body += "    last_phase = primary_phase; CHECK(isfinite(last_phase));\n"
    return (
        PREAMBLE
        + macros
        + "\n"
        + types
        + STATE
        + helpers
        + selection
        + "static void process_current_grid(const edge_ring_slot_t *slot) {\n"
        + body
        + "}\n"
        + CASES
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source", type=Path, help="Pristine pinned firmware source directory"
    )
    args = parser.parse_args()
    source = checked(args.source / "main/edge_processing.c", SOURCE_SHA)
    header = checked(args.source / "main/edge_processing.h", HEADER_SHA)
    results = []
    with tempfile.TemporaryDirectory(prefix="ruview-grid-host-") as temporary:
        work = Path(temporary)
        (work / "main").mkdir()
        target = work / "main/edge_processing.c"
        target.write_text(source)
        subprocess.run(
            ["git", "apply", "--check", str(PATCH)], cwd=work, check=True, timeout=10
        )
        subprocess.run(["git", "apply", str(PATCH)], cwd=work, check=True, timeout=10)
        fixed = target.read_text()
        duplicate = subprocess.run(
            ["git", "apply", "--check", str(PATCH)],
            cwd=work,
            capture_output=True,
            timeout=10,
        )
        if duplicate.returncode == 0:
            raise AssertionError("Duplicate patch unexpectedly accepted")
        for name, text, flags in (
            (
                "before",
                source,
                ["-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
            ),
            (
                "after",
                fixed,
                ["-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
            ),
            ("optimized", fixed, ["-O2", "-fstrict-aliasing"]),
        ):
            c_file = work / (name + ".c")
            c_file.write_text(harness(text, header))
            executable = work / name
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *flags,
                    str(c_file),
                    "-lm",
                    "-o",
                    str(executable),
                ],
                check=True,
                timeout=30,
            )
            cases = ("primary", "secondary") if name == "before" else (None,)
            for case in cases:
                result = subprocess.run(
                    [str(executable), *([case] if case else [])],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if name == "before":
                    if (
                        result.returncode != 42
                        or "GRID_CHECK:s_top_k[k] < bins" not in result.stderr
                    ):
                        raise AssertionError(
                            "Old source did not reproduce the specific current-grid defect: "
                            + result.stderr
                        )
                elif result.returncode != 0:
                    raise AssertionError(result.stderr)
                results.append(
                    {
                        "variant": name,
                        "case": case,
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "generated_c_sha256": hashlib.sha256(
                            c_file.read_bytes()
                        ).hexdigest(),
                    }
                )
    print(
        json.dumps(
            {
                "scope": "exact phase/variance/Top-K production slice; not complete DSP or device qualification",
                "source_sha256": SOURCE_SHA,
                "header_sha256": HEADER_SHA,
                "patch_sha256": hashlib.sha256(PATCH.read_bytes()).hexdigest(),
                "results": results,
                "temporary_build_inputs_and_binaries_removed": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
