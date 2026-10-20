#!/usr/bin/env python3
"""Bounded loopback capture.v2 integration; no production packets or labels."""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from fleet_service_smoke import close_process_group, packet
from service_smoke import check, port, save_json


def wait_for_capture_status(session, status, command, budget):
    while True:
        value = command(session, "status")
        check(value["status"] != "error", "status error")
        # A closing session cannot become active again under the same ID.
        if status == "active" and value["status"] in ("closing", "closed"):
            raise ValueError(
                f"capture session {session}: expected {status}, actual {value['status']}; "
                "required state was skipped"
            )
        if value["status"] == status:
            return value
        time.sleep(min(0.05, budget()))


def main(binary, output, uid=None):
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    credentials = {}
    if uid is not None:
        check(
            os.geteuid() == 0 and uid == 10001,
            "UID smoke requires root launcher and UID10001",
        )
        os.chown(output, 0, uid)
        output.chmod(
            0o2775
        )  # Kubernetes fsGroup parent; worker creates its own0700 children.
        credentials = {"user": uid, "group": uid, "extra_groups": []}
    directory = output / "sessions"
    admin = output / "admin"
    socket_path = admin / "control.sock"
    udp, http = port(socket.SOCK_DGRAM), port(socket.SOCK_STREAM)
    deadline = time.monotonic() + 60
    log = (output / "service.log").open("xb")
    worker = subprocess.Popen(
        [
            str(binary),
            "--listen-udp",
            f"127.0.0.1:{udp}",
            "--listen-http",
            f"127.0.0.1:{http}",
            "--allow-source",
            "127.0.0.1",
            "--capture-directory",
            str(directory),
            "--capture-admin-socket",
            str(socket_path),
        ],
        stdout=log,
        stderr=log,
        start_new_session=True,
        **credentials,
    )
    restart_worker = None
    restart_log = None
    summary = {"schema": "ruview.capture.synthetic-smoke.v2", "passed": False}
    exports = {}
    sequence = 0
    received = 0
    trace = (output / "controls.jsonl").open("x")

    def budget():
        remaining = deadline - time.monotonic()
        check(remaining > 0, "capture smoke deadline")
        return min(3, remaining)

    def latest():
        with urllib.request.urlopen(
            f"http://127.0.0.1:{http}/v1/latest", timeout=budget()
        ) as response:
            return json.loads(response.read(1_048_577))

    def command(session, op, **fields):
        value = {
            "schema": "ruview.capture.control.v2",
            "op": op,
            "session_id": session,
            **fields,
        }
        result = subprocess.run(
            [str(binary), "capture-control", str(socket_path), json.dumps(value)],
            capture_output=True,
            timeout=budget(),
            check=True,
            **credentials,
        )
        check(len(result.stdout) <= 16384, "control response bound")
        value = json.loads(result.stdout)
        trace.write(json.dumps({"request": op, "reply": value}) + "\n")
        trace.flush()
        return value

    def await_status(session, status):
        return wait_for_capture_status(session, status, command, budget)

    def send(count):
        nonlocal sequence, received
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(count):
                sock.sendto(packet(2, sequence), ("127.0.0.1", udp))
                sequence += 1
                received += 1
                time.sleep(0.04)  # Minimum spacing; never catch up after descheduling.
        while True:
            snapshot = latest()
            if snapshot["counters"]["received"] == received:
                break
            time.sleep(min(0.05, budget()))
        save_json(output / f"latest-{sequence}.json", snapshot)
        check(snapshot["counters"]["queue_dropped"] == 0, "engine queue loss")

    def export(session, kind):
        result = subprocess.run(
            [str(binary), "capture-export", str(directory), session, kind],
            capture_output=True,
            check=True,
            **credentials,
            timeout=budget(),
        )
        check(len(result.stdout) <= 1_048_576, "smoke export bound")
        key = f"{session}-{kind}"
        exports[key] = exports.get(key, 0) + 1
        suffix = "" if exports[key] == 1 else f"-{exports[key]}"
        with (output / f"{key}{suffix}.export").open("xb") as retained:
            retained.write(result.stdout)
        return result.stdout

    try:
        until = time.monotonic() + 8
        while not socket_path.exists():
            check(
                time.monotonic() < until and worker.poll() is None,
                "worker/admin startup",
            )
            time.sleep(0.025)
        send(3)  # Historic frames are deliberately excluded from session counters.
        first = "11111111-1111-4111-8111-111111111111"
        command(first, "start", node_ids=[2], duration_ms=10000, max_bytes=1048576)
        opening_reply = await_status(first, "active")
        opening = json.loads(export(first, "opening"))
        check(opening == opening_reply["opening"], "opening export unchanged")
        send(8)
        command(first, "stop")
        closed = await_status(first, "closed")["terminal"]
        check(
            closed["complete"] and closed["end_reason"] == "manual_stop",
            "clean explicit stop",
        )
        raw = export(first, "raw")
        check(
            json.loads(export(first, "terminal")) == closed, "terminal export unchanged"
        )
        rows = [json.loads(line) for line in raw.splitlines()]
        check(
            len(rows) == 8 and [row["sequence"] for row in rows] == list(range(3, 11)),
            "session exact source cut",
        )
        check(
            [row["capture_sequence"] for row in rows] == list(range(1, 9)),
            "capture ordinals",
        )
        check(
            [row["ingress_sequence"] for row in rows] == list(range(4, 12)),
            "receiver ordinals",
        )
        check(
            closed["raw"]["sha256"] == hashlib.sha256(raw).hexdigest(),
            "terminal original hash",
        )
        check(
            closed["writer_finished_clock"]["monotonic_ns"]
            >= closed["end_boundary"]["clock"]["monotonic_ns"],
            "writer finished after receiver barrier",
        )
        check(
            directory.stat().st_uid == (uid if uid is not None else os.geteuid()),
            "capture directory actual UID",
        )
        check(directory.stat().st_mode & 0o777 == 0o700, "capture child private mode")
        for row in rows:
            check(
                opening["start_boundary"]["clock"]["monotonic_ns"]
                <= row["received_monotonic_ns"]
                <= closed["end_boundary"]["clock"]["monotonic_ns"],
                "original receiver clock interval",
            )
            check(
                row["schema"] == "ruview.csi.frame.v2"
                and row["session_id"] == first == row["capture_id"],
                "v2 identity",
            )
            check(
                row["worker_run_id"] == opening["worker_run_id"] != first,
                "distinct worker identity",
            )
            original = packet(2, row["sequence"])
            check(
                bytes.fromhex(row["raw_datagram_hex"]) == original,
                "original wire bytes",
            )
            check(
                row["raw_datagram_sha256"] == hashlib.sha256(original).hexdigest(),
                "original wire hash",
            )
        check(
            command(first, "start", node_ids=[2], duration_ms=1000, max_bytes=1048576)[
                "error"
            ]
            == "session_id_already_used",
            "no UUID reuse",
        )
        second = "33333333-3333-4333-8333-333333333333"
        command(second, "start", node_ids=[2], duration_ms=300, max_bytes=1048576)
        await_status(second, "active")
        send(1)
        closed_duration = await_status(second, "closed")["terminal"]
        check(
            closed_duration["complete"]
            and closed_duration["end_reason"] == "duration_elapsed",
            "clean duration closure",
        )
        check(
            closed_duration["counters"]["written"] == 1, "duration session-local count"
        )
        export(second, "raw")
        third = "44444444-4444-4444-8444-444444444444"
        command(third, "start", node_ids=[2], duration_ms=10000, max_bytes=1024)
        await_status(third, "active")
        send(1)
        failed = await_status(third, "closed")["terminal"]
        check(
            not failed["complete"] and failed["end_reason"] == "byte_limit",
            "hard storage cap incomplete",
        )
        check(
            failed["raw"]["bytes"] == 0
            and failed["counters"]["byte_limit_rejected"] == 1,
            "no oversized write",
        )
        export(third, "raw")
        send(2)  # Recording termination must leave the sole receiver/engine alive.
        check(worker.poll() is None, "worker remains alive")
        # Reproduce a Kubernetes replacement overlap, not merely a sequential restart.
        # Both processes run as the same UID, using the same persisted session directory
        # and distinct ephemeral socket parents. No capture file or lock is removed.
        originals = {}
        for session in (first, second, third):
            for kind in ("opening", "terminal", "raw"):
                data = export(session, kind)
                path = (
                    directory
                    / session
                    / ("raw.jsonl" if kind == "raw" else kind + ".json")
                )
                originals[str(path.relative_to(directory))] = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "inode": path.stat().st_ino,
                }
        save_json(output / "originals-before-overlap.json", originals)
        lock_before = (directory / ".capture.lock").stat()
        new_udp, new_http = port(socket.SOCK_DGRAM), port(socket.SOCK_STREAM)
        new_socket = output / "admin-restart" / "control.sock"
        restart_log = (output / "restart-service.log").open("xb")
        restart_worker = subprocess.Popen(
            [
                str(binary),
                "--listen-udp",
                f"127.0.0.1:{new_udp}",
                "--listen-http",
                f"127.0.0.1:{new_http}",
                "--allow-source",
                "127.0.0.1",
                "--capture-directory",
                str(directory),
                "--capture-admin-socket",
                str(new_socket),
            ],
            stdout=restart_log,
            stderr=restart_log,
            start_new_session=True,
            **credentials,
        )
        until = min(deadline, time.monotonic() + 8)
        while (
            b"capture storage lock busy: bounded owner wait"
            not in (output / "restart-service.log").read_bytes()
        ):
            check(
                time.monotonic() < until and restart_worker.poll() is None,
                "replacement must actually observe the original owner's busy lock",
            )
            time.sleep(0.025)
        check(
            worker.poll() is None and not new_socket.exists(),
            "busy replacement must not create a second admin socket",
        )
        summary["overlap"] = {
            "old_pid": worker.pid,
            "new_pid": restart_worker.pid,
            "busy_observed": True,
            "original_alive_while_busy": True,
            "replacement_socket_absent_while_busy": True,
            "same_uid": directory.stat().st_uid,
        }
        summary["original_cleanup"] = close_process_group(worker)
        worker, restart_worker = restart_worker, None
        udp, http, socket_path = new_udp, new_http, new_socket
        until = min(deadline, time.monotonic() + 8)
        while not socket_path.exists():
            check(
                time.monotonic() < until and worker.poll() is None,
                "replacement must acquire storage after original owner exits",
            )
            time.sleep(0.025)
        check(
            b"capture storage lock acquired after bounded owner wait"
            in (output / "restart-service.log").read_bytes(),
            "actual retry acquisition",
        )
        lock_after = (directory / ".capture.lock").stat()
        check(
            (lock_after.st_dev, lock_after.st_ino)
            == (lock_before.st_dev, lock_before.st_ino),
            "same original lock inode retained",
        )
        for name, expected in originals.items():
            path = directory / name
            data = path.read_bytes()
            check(
                hashlib.sha256(data).hexdigest() == expected["sha256"]
                and len(data) == expected["bytes"]
                and path.stat().st_ino == expected["inode"],
                "original capture bytes and inode preserved across overlap",
            )
        # Export old evidence from the new image process too; an old run is not a new session.
        for session in (first, second, third):
            for kind in ("opening", "terminal", "raw"):
                export(session, kind)
        check(
            command(first, "start", node_ids=[2], duration_ms=1000, max_bytes=1048576)[
                "error"
            ]
            == "session_id_already_used",
            "old UUID remains consumed after restart",
        )
        fourth = "55555555-5555-4555-8555-555555555555"
        command(fourth, "start", node_ids=[2], duration_ms=200, max_bytes=1048576)
        recovered = await_status(fourth, "closed")["terminal"]
        check(
            recovered["complete"]
            and recovered["end_reason"] == "duration_elapsed"
            and recovered["raw"]["frames"] == 0,
            "new bounded session works after overlap",
        )
        check(
            recovered["worker_run_id"] != opening["worker_run_id"],
            "new real worker run",
        )
        export(fourth, "opening")
        export(fourth, "terminal")
        export(fourth, "raw")
        additional_sessions = tuple(
            f"00000000-0000-4000-8000-{index:012d}" for index in range(5, 9)
        )
        for session in additional_sessions:
            command(session, "start", node_ids=[2], duration_ms=200, max_bytes=1048576)
            extra = await_status(session, "closed")["terminal"]
            check(
                extra["complete"]
                and extra["end_reason"] == "duration_elapsed"
                and extra["raw"]["frames"] == 0
                and extra["worker_run_id"] == recovered["worker_run_id"],
                "sessions five through eight close without replacing earlier evidence",
            )
        retained_sessions = (first, second, third, fourth, *additional_sessions)
        ninth = "99999999-9999-4999-8999-999999999999"
        check(
            command(
                ninth,
                "start",
                node_ids=[2],
                duration_ms=1000,
                max_bytes=1048576,
            )["error"]
            == "session_count_limit",
            "ninth session must be refused at eight-session storage quota",
        )
        check(
            not (directory / ninth).exists(),
            "refused ninth session creates no directory",
        )
        summary["overlap"].update(
            recovered=True,
            new_worker_run_id=recovered["worker_run_id"],
            lock_inode_preserved=True,
            original_files_preserved=len(originals),
        )
        # All eight retained attempts, including the intentional byte-cap failure,
        # must survive the following real same-socket process restart unchanged.
        for session in retained_sessions:
            for kind in ("opening", "terminal", "raw"):
                data = export(session, kind)
                name = f"{session}/" + (
                    "raw.jsonl" if kind == "raw" else kind + ".json"
                )
                path = directory / name
                expected = originals.get(name)
                actual = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "inode": path.stat().st_ino,
                }
                check(
                    expected is None or expected == actual,
                    "earlier exports remain unchanged",
                )
                originals[name] = actual
        check(len(originals) == 24, "eight attempts retain all three original files")
        save_json(output / "originals-before-same-socket.json", originals)
        # A container restart in the same Pod keeps the socket emptyDir too.
        # Preserve the stale inode until the replacement safely diagnoses it.
        same_socket_before = socket_path.stat()
        summary["overlap_replacement_cleanup"] = close_process_group(worker)
        check(
            socket_path.exists(), "terminated process leaves its original socket name"
        )
        restart_log.close()
        restart_log = (output / "same-socket-service.log").open("xb")
        worker = subprocess.Popen(
            [
                str(binary),
                "--listen-udp",
                f"127.0.0.1:{udp}",
                "--listen-http",
                f"127.0.0.1:{http}",
                "--allow-source",
                "127.0.0.1",
                "--capture-directory",
                str(directory),
                "--capture-admin-socket",
                str(socket_path),
            ],
            stdout=restart_log,
            stderr=restart_log,
            start_new_session=True,
            **credentials,
        )
        until = min(deadline, time.monotonic() + 8)
        while (
            b"capture abandoned owned socket reclaimed after exclusive storage lock"
            not in (output / "same-socket-service.log").read_bytes()
            or not socket_path.exists()
        ):
            check(
                time.monotonic() < until and worker.poll() is None,
                "same-socket replacement must recover the retained abandoned socket",
            )
            time.sleep(0.025)
        check(
            command(first, "start", node_ids=[2], duration_ms=1000, max_bytes=1048576)[
                "error"
            ]
            == "session_id_already_used",
            "same-socket restart retains original UUID",
        )
        reply = command(
            ninth,
            "start",
            node_ids=[2],
            duration_ms=1000,
            max_bytes=1048576,
        )
        check(
            reply["error"] == "session_count_limit", "same-socket restart retains quota"
        )
        check(
            not (directory / ninth).exists(),
            "restart refuses ninth before directory creation",
        )
        snapshot = latest()
        check(
            snapshot["worker_run_id"]
            not in (opening["worker_run_id"], recovered["worker_run_id"]),
            "same-socket process has a distinct real worker run",
        )
        for session in retained_sessions:
            for kind in ("opening", "terminal", "raw"):
                data = export(session, kind)
                name = f"{session}/" + (
                    "raw.jsonl" if kind == "raw" else kind + ".json"
                )
                check(
                    hashlib.sha256(data).hexdigest() == originals[name]["sha256"]
                    and len(data) == originals[name]["bytes"]
                    and (directory / name).stat().st_ino == originals[name]["inode"],
                    "same-socket restart preserves all eight attempts' exact files",
                )
        summary["same_socket_restart"] = {
            "recovered": True,
            "socket_path_unchanged": True,
            "old_socket_inode": same_socket_before.st_ino,
            "new_socket_inode": socket_path.stat().st_ino,
            "new_worker_run_id": snapshot["worker_run_id"],
            "retained_sessions": 8,
            "original_files_preserved": len(originals),
            "lock_inode_preserved": (directory / ".capture.lock").stat().st_ino
            == lock_before.st_ino,
        }
        check(
            summary["same_socket_restart"]["lock_inode_preserved"],
            "storage lock never replaced",
        )
        summary.update(
            passed=True,
            sent_frames=received,
            retained_sessions=8,
            refused_session_id=ninth,
            worker_run_id=opening["worker_run_id"],
            worker_uid=directory.stat().st_uid,
            rootfs_readonly_tested=False,
        )
    except BaseException as error:
        summary.update(passed=False, failure=type(error).__name__ + ": " + str(error))
    finally:
        trace.close()
        try:
            summary["cleanup"] = close_process_group(worker)
        except BaseException as error:
            summary.update(passed=False, cleanup_error=str(error))
        if restart_worker is not None:
            try:
                summary["unpromoted_replacement_cleanup"] = close_process_group(
                    restart_worker
                )
            except BaseException as error:
                summary.update(passed=False, replacement_cleanup_error=str(error))
        if restart_log is not None:
            restart_log.close()
        log.close()
        save_json(output / "summary.json", summary)
    check(
        summary["passed"],
        "capture socket integration failed; original evidence retained",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--uid", type=int)
    args = parser.parse_args()
    main(args.binary.resolve(), args.output.resolve(), args.uid)
