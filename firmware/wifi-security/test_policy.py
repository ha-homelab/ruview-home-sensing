#!/usr/bin/env python3
"""Compile the real injected entry guard against pinned IDF enum definitions."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("wifi_policy_apply", ROOT / "apply.py")
APPLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPLY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wpa", type=Path)
    parser.add_argument("types", type=Path)
    parser.add_argument("defs", type=Path)
    args = parser.parse_args()
    lock = json.loads((ROOT / "source.json").read_text())
    for path, key in ((args.types, "types_sha256"), (args.defs, "defs_sha256")):
        if hashlib.sha256(path.read_bytes()).hexdigest() != lock[key]:
            raise ValueError("Unexpected ESP-IDF declarations")
    result = APPLY.patched_source(args.wpa.read_bytes()).decode()
    # A modified upstream file must fail before anything can be overwritten.
    try:
        APPLY.patched_source(args.wpa.read_bytes() + b"\n")
    except ValueError:
        pass
    else:
        raise AssertionError("Unpinned input accepted")
    enum = re.search(
        r"typedef enum \{\s*WIFI_CIPHER_TYPE_NONE.*?\} wifi_cipher_type_t;",
        args.types.read_text(),
        re.S,
    ).group()
    protos = "\n".join(
        line
        for line in args.defs.read_text().splitlines()
        if line.startswith("#define WPA_PROTO_")
    )
    # Compile the injected production prefix through the first original side
    # effect (PMK-cache inspection). Rejection must never reach that operation.
    entry = result.split(APPLY.ENTRY + "\n{\n", 1)[1]
    prolog = entry.split("    bool use_pmk_cache", 1)[0]
    assert APPLY.GUARD in prolog
    policy = (ROOT / "policy.c.inc").read_text()
    harness = (
        r"""
#include <stdio.h>
#include <stdlib.h>
#define BIT(n) (1U << (n))
#define CHECK(x) do { if (!(x)) abort(); } while (0)
#define MSG_ERROR 0
#define wpa_printf(...) ((void)0)
"""
        + enum
        + "\n"
        + protos
        + "\n"
        + r"""
#if !defined(CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY) || !CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY
"""
        + policy
        + "#endif\n"
        + r"""
struct wpa_sm { unsigned proto; } gWpaSm;
static unsigned continuation;
static int production_entry(unsigned pairwise_cipher, unsigned group_cipher) {
"""
        + prolog
        + r"""
    /* The unextracted remainder consumes these on the legacy path too. */
    (void)sm;
    (void)pairwise_cipher;
    (void)group_cipher;
    ++continuation;
    return res;
}
int main(void) {
    unsigned checked = 0;
    for (unsigned proto = 0; proto <= 15; ++proto) {
        for (unsigned pairwise = 0; pairwise <= 255; ++pairwise) {
            for (unsigned group = 0; group <= 255; ++group) {
                gWpaSm.proto = proto;
                continuation = 0;
                int actual = production_entry(pairwise, group);
#if defined(CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY) && CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY
                int expected = 1;
#else
                int p = pairwise == WIFI_CIPHER_TYPE_CCMP || pairwise == WIFI_CIPHER_TYPE_GCMP || pairwise == WIFI_CIPHER_TYPE_GCMP256;
                int g = group == WIFI_CIPHER_TYPE_CCMP || group == WIFI_CIPHER_TYPE_GCMP || group == WIFI_CIPHER_TYPE_GCMP256;
                int expected = proto == WPA_PROTO_RSN && p && g;
#endif
                CHECK(actual == (expected ? 0 : -1));
                CHECK(continuation == (unsigned)expected);
                ++checked;
            }
        }
    }
    printf("%u actual guard cases passed\n", checked);
}
"""
    )
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "guard.c"
        binary = Path(temp) / "guard"
        source.write_text(harness)
        for flags in (
            [],
            ["-DCONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY=0"],
            ["-DCONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY=1"],
        ):
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *flags,
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)
    print("Pinned source refusal, enum mapping and pre-handshake guard passed")


if __name__ == "__main__":
    main()
