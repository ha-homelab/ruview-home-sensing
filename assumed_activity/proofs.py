"""Fresh receiver identity for aggregate activity, never raw-frame eligibility.

An uptime observation occurs within its HTTP request interval. The continuity
test uses those intervals with 2 ms for integer-millisecond quantization; it
does not assume a round-trip time. Proof timestamps never replace source time.
"""

import ipaddress
import re

from .core import digest, indexed, integer, number, require, timestamp

REFRESH_SECONDS = 5
MAX_PROOF_BYTES = 65536


def configuration(value, node_ids, expected_sha256):
    require(
        isinstance(expected_sha256, str) and digest(value) == expected_sha256,
        "receiver_approval_mismatch",
    )
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "receivers"}
        and value["schema"] == "ruview.assumed-activity.receiver-identities.v1",
        "invalid_receiver_identity_config",
    )
    rows = indexed(value["receivers"])
    require(set(rows) == set(node_ids) == {1, 2, 3}, "receiver_identity_nodes")
    for row in rows.values():
        require(
            set(row) == {"node_id", "ip", "station_mac"}
            and isinstance(row["ip"], str)
            and isinstance(row["station_mac"], str)
            and re.fullmatch("(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", row["station_mac"])
            is not None,
            "receiver_identity_binding",
        )
        address = ipaddress.IPv4Address(row["ip"])
        require(
            str(address) == row["ip"]
            and any(
                address in ipaddress.IPv4Network(network)
                for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            ),
            "receiver_identity_binding",
        )
    require(
        len({row["ip"] for row in rows.values()}) == 3
        and len({row["station_mac"] for row in rows.values()}) == 3,
        "receiver_identity_binding",
    )
    return rows


def observation(reading, expected_mac, timeout):
    start = number(reading["started"], "invalid_proof_start")
    finish = number(reading["finished"], "invalid_proof_finish")
    require(0 <= finish - start <= timeout, "proof_request_deadline")
    wall_start = integer(reading["started_at_ns"], "invalid_proof_wall_start")
    wall_finish = integer(reading["finished_at_ns"], "invalid_proof_wall_finish")
    require(
        wall_start <= wall_finish
        and abs((wall_finish - wall_start) / 1e9 - (finish - start)) <= 0.05,
        "proof_wall_clock_discontinuity",
    )
    runtime, wifi = reading["document"]["runtime"], reading["document"]["wifi"]
    require(
        runtime["boot_nonce_schema"] == "ruview.boot-nonce.v1"
        and runtime["station_mac"] == expected_mac
        and isinstance(runtime["boot_nonce"], str)
        and re.fullmatch("[0-9a-f]{32}", runtime["boot_nonce"])
        and runtime["boot_nonce"] != "0" * 32,
        "invalid_receiver_boot_identity",
    )
    require(
        wifi["associated"] is True
        and type(wifi["ap_info_error"]) is int
        and wifi["ap_info_error"] == 0
        and isinstance(wifi["bssid"], str)
        and re.fullmatch("(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", wifi["bssid"])
        and wifi["bssid"] != "00:00:00:00:00:00"
        and int(wifi["bssid"][:2], 16) & 1 == 0,
        "invalid_receiver_radio_identity",
    )
    channel = integer(wifi["channel"], "invalid_receiver_channel", 1, 14)
    uptime = integer(runtime["uptime_ms"], "invalid_receiver_uptime")
    return {
        "identity": (expected_mac, runtime["boot_nonce"], wifi["bssid"], channel),
        "uptime_ms": uptime,
        "started": start,
        "finished": finish,
        "started_at_ns": wall_start,
        "finished_at_ns": wall_finish,
    }


def continuous(previous, current):
    require(current["started"] >= previous["finished"], "proof_time_reversal")
    delta = (current["uptime_ms"] - previous["uptime_ms"]) / 1000
    require(
        delta >= 0
        and current["started"] - previous["finished"] - 0.002
        <= delta
        <= current["finished"] - previous["started"] + 0.002,
        "receiver_uptime_discontinuity",
    )


def worker_state(worker, node):
    row = indexed(worker["nodes"])[node]
    return {
        "worker": tuple(
            worker[k] for k in ("worker_run_id", "configuration_sha256", "clock_id")
        ),
        "counter": integer(row["sequence_discontinuities"], "invalid_discontinuities"),
        "sequence": integer(row["sequence"], "invalid_sequence", 0, 2**32 - 1),
        "epoch": integer(row["node_epoch"], "invalid_node_epoch"),
        "token": timestamp(row["last_received_monotonic_ns"]),
    }


def suspect(previous, current):
    return previous is not None and (
        current["counter"] != previous["counter"]
        or (current["sequence"] - previous["sequence"]) % 2**32 >= 2**31
    )


class ReceiverProofs:
    def __init__(
        self,
        config,
        node_ids,
        timeout=2,
        reset_gap=10,
        refresh_reservation=None,
        *,
        expected_sha256,
    ):
        self.receivers = configuration(config, node_ids, expected_sha256)
        self.config_sha = digest(config)
        self.timeout, self.reset_gap = timeout, reset_gap
        self.refresh_reservation = (
            timeout if refresh_reservation is None else refresh_reservation
        )
        self.states = {}

    def requests(self, worker, mono):
        result = {}
        for node, receiver in self.receivers.items():
            old = self.states.get(node)
            try:
                current = worker_state(worker, node)
                needed = (
                    old is None
                    or old["failed"]
                    or current["worker"] != old["worker_state"]["worker"]
                    or suspect(old["worker_state"], current)
                    # Resolution waits for the other receiver requests too.
                    # Refresh before that wait can consume the cached lifetime.
                    or mono - old["proof"]["finished"] + self.refresh_reservation
                    >= REFRESH_SECONDS
                    or mono < old["proof"]["finished"]
                    or (
                        old["burst_at"] is not None
                        and mono - old["burst_at"] <= self.reset_gap
                    )
                )
                if needed:
                    result[node] = f"http://{receiver['ip']}:8032/wasm/list"
            except (KeyError, TypeError, ValueError):
                continue
        return result

    def resolve(self, worker, readings, mono):
        contexts = {}
        for node, receiver in self.receivers.items():
            old = self.states.get(node)
            context = {"accept": False, "reason": "receiver_proof_unavailable"}
            try:
                current = worker_state(worker, node)
                raw_suspect = suspect(old["worker_state"] if old else None, current)
                fresh = node in readings
                proof = (
                    observation(readings[node], receiver["station_mac"], self.timeout)
                    if fresh
                    else old["proof"]
                )
                require(
                    0 <= mono - proof["finished"] <= REFRESH_SECONDS,
                    "receiver_proof_stale",
                )
                same = old is not None and proof["identity"] == old["proof"]["identity"]
                if fresh and same:
                    continuous(old["proof"], proof)
                worker_same = (
                    old is not None
                    and current["worker"] == old["worker_state"]["worker"]
                )
                burst = (
                    old is not None
                    and old["burst_at"] is not None
                    and 0 <= mono - old["burst_at"] <= self.reset_gap
                )
                require(not raw_suspect or fresh, "post_scalar_proof_required")
                accept = same and worker_same and (not raw_suspect or burst)
                # Keep the start of the continuously verified epoch, rather
                # than moving the lower bound past delayed but fresh scalars.
                # Each subsequent proof still checks the latest uptime pair.
                anchor = old["burst_anchor"] if burst else old["proof"] if old else None
                # During a discontinuity burst each scalar needs a new post-read
                # proof, including polls where the counter temporarily stays put.
                require(not burst or fresh, "post_scalar_proof_required")
                context = {
                    "accept": accept,
                    "reason": "receiver_identity_priming"
                    if not accept
                    else "verified_receiver_epoch",
                    "identity": proof["identity"],
                    "allow_reordering": same and worker_same,
                    "bracket_after_ns": anchor["finished_at_ns"]
                    if accept and (raw_suspect or burst)
                    else None,
                    "bracket_before_ns": proof["started_at_ns"]
                    if accept and (raw_suspect or burst)
                    else None,
                    "diagnostic": {
                        "status": "verified" if accept else "priming",
                        "station_mac": proof["identity"][0],
                        "boot_nonce": proof["identity"][1],
                        "bssid": proof["identity"][2],
                        "channel": proof["identity"][3],
                        "uptime_ms": proof["uptime_ms"],
                        "age_ms": (mono - proof["finished"]) * 1000,
                        "request_duration_ms": (proof["finished"] - proof["started"])
                        * 1000,
                        "refreshed": fresh,
                    },
                }
                self.states[node] = {
                    "proof": proof,
                    "worker_state": current,
                    "failed": False,
                    "burst_anchor": anchor
                    if same and worker_same and (raw_suspect or burst)
                    else None,
                    "burst_at": mono
                    if raw_suspect and same and worker_same
                    else old["burst_at"]
                    if same and worker_same
                    else None,
                }
            except (KeyError, TypeError, ValueError):
                if old:
                    old["failed"] = True
            contexts[node] = context
        return contexts
