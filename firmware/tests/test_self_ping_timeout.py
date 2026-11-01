#!/usr/bin/env python3
"""Host-execute the selected legacy/recovery ping configuration after all patches.

Reproduces the old 1000 ms receive wait, then verifies that unanswered probes are
configured to wait at most one requested interval. The recovery lifecycle cases
still exercise stop/end ownership, loss and backoff. No radio, achieved packet
rate, CSI yield, firmware image or device behavior is qualified by these mocks.
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

from test_self_ping_recovery import HARNESS, STUB

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "patches/0022-self-ping-receive-budget.patch"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def selected_ping(source):
    """Keep the production preprocessor selection, not a rewritten initializer."""
    marker = (
        "#if defined(CONFIG_HOME_RUNTIME_RECOVERY_V1) && CONFIG_HOME_RUNTIME_RECOVERY_V1\n"
        "static void csi_start_self_ping(void)"
    )
    start = source.index(marker)
    end = source.index("\nvoid csi_collector_set_node_id", start)
    rate_start = source.index("#ifndef CONFIG_CSI_SELF_PING_HZ\n")
    rate_end = source.index(
        "\n", source.index("#define CSI_SELF_PING_INTERVAL_MS", rate_start)
    )
    return source[rate_start:rate_end] + "\n" + source[start:end]


def execute(work, source, rate, recovery, fixed):
    stub = work / "stubs"
    requested_rate = 50 if rate is None else rate
    interval = 1000 // requested_rate
    timeout = interval if fixed else 1000
    body = STUB.replace(
        "CHECK(cfg->interval_ms == 20 && cfg->timeout_ms == 1000 && cfg->data_size == 1);",
        f"CHECK(cfg->interval_ms == {interval} && cfg->timeout_ms == {timeout} && cfg->data_size == 1);\n"
        "    CHECK(cfg->timeout_ms > 0);",
    )
    require(body != STUB, "Mock configuration assertion not found")
    (stub / "idf.h").write_text(body)
    integration = selected_ping(source)
    if recovery == 1:
        harness = HARNESS.replace(
            '#include "home_csi_ping.c"',
            '#include "home_csi_ping.c"\n' + integration,
        ).replace(
            "    (void)TAG;",
            "    (void)TAG;\n"
            "    reset(); csi_start_self_ping(); csi_start_self_ping();\n"
            "    CHECK(fake_task_count == 1 && s_status.supervisor_started);",
        )
    else:
        harness = (
            '#include "idf.h"\n'
            + integration
            + r"""
static void test_network_changed(void) { abort(); }
int main(void) {
    fake_gateway=1;
    csi_start_self_ping(); csi_start_self_ping();
    CHECK(created==1 && starts_called==1 && active==1);
    /* A timeout callback must not create a second owner/session. */
    for (unsigned i=0;i<100;++i)
        sessions[0].cb.on_ping_timeout(&sessions[0], sessions[0].cb.cb_args);
    CHECK(created==1 && starts_called==1 && active==1 && stops_called==0);
    return 0;
}
"""
        )
    cfile = work / "timeout.c"
    cfile.write_text(harness)
    compiler = os.environ.get("CC", "cc")
    flags = [] if rate is None else [f"-DCONFIG_CSI_SELF_PING_HZ={rate}"]
    if recovery is not None:
        flags.append(f"-DCONFIG_HOME_RUNTIME_RECOVERY_V1={recovery}")
    result = subprocess.run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-function",
            "-Wno-unused-variable",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I" + str(stub),
            "-I" + str(work / "main"),
            *flags,
            str(cfile),
            "-o",
            str(work / "timeout"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if requested_rate not in range(10, 51):
        require(
            result.returncode != 0 and "10-50 Hz" in result.stderr,
            "Invalid recovery rate was not rejected",
        )
        return
    require(result.returncode == 0, result.stderr)
    subprocess.run([str(work / "timeout")], check=True, timeout=10)


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
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            if patch.name >= FIX.name:
                break
            subprocess.run(
                ["git", "apply", "--exclude=components/wasm3/wasm3-src/*", str(patch)],
                cwd=work,
                check=True,
                timeout=10,
            )
        config = (work / "main/Kconfig.projbuild").read_text()
        rate_config = config.split("config CSI_SELF_PING_HZ\n", 1)[1].split(
            "\n    config ", 1
        )[0]
        require(
            re.search(r"range\s+10\s+50\b", rate_config), "Kconfig rate bounds changed"
        )
        require(
            re.search(r"default\s+50\b", rate_config), "Kconfig default rate changed"
        )
        stub = work / "stubs"
        stub.mkdir()
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
            target = stub / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('#include "idf.h"\n')
        before = (work / "main/csi_collector.c").read_text()
        for recovery in (0, 1):
            execute(work, before, 50, recovery, fixed=False)
        print("Reproduced pre-fix 1000 ms wait with 20 ms interval in both paths")
        # Exercise the final assembled source, including future patch successors.
        for patch in sorted((ROOT / "patches").glob("*.patch")):
            if patch.name < FIX.name:
                continue
            subprocess.run(
                ["git", "apply", "--exclude=components/wasm3/wasm3-src/*", str(patch)],
                cwd=work,
                check=True,
                timeout=10,
            )
        after = (work / "main/csi_collector.c").read_text()
        for rate in (None, 10, 50):
            for recovery in (None, 0, 1):
                execute(work, after, rate, recovery, fixed=True)
        for invalid_rate in (9, 51):
            for recovery in (None, 0, 1):
                execute(work, after, invalid_rate, recovery, fixed=True)
        print(
            "Nine final-source rate/profile cases and six invalid-rate rejections PASS; "
            "recovery lifecycle/loss ownership cases retained; no RF rate qualification"
        )


if __name__ == "__main__":
    main()
