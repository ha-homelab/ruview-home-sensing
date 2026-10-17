"""Read-only source polling and expiring HTTP/MQTT activity envelopes."""

import copy
import ipaddress
import json
import math
import os
import signal
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from ruview_http import decode_http_body

from .configuration import pinned_bytes
from .core import Producer, digest, encoded, require
from .polling import ReceiverReads, SourceReads, runtime_configuration
from .proofs import (
    MAX_PROOF_BYTES,
    ReceiverProofs,
)
from .proofs import (
    configuration as receiver_configuration,
)

MAX_DOCUMENT = 2 * 1024 * 1024
STATE = "ruview/home/assumed_activity/state"
ATTRIBUTES = "ruview/home/assumed_activity/attributes"
AVAILABILITY = "ruview/home/assumed_activity/availability"
DISCOVERY = "homeassistant/sensor/ruview_assumed_zone_activity/config"
DIAGNOSTIC_HISTORY = 32
MAX_COUNTER = 2**63 - 1
NODE_REASONS = frozenset(
    "invalid_source ineligible_raw_grid invalid_frequency stale_node invalid_worker_age "
    "invalid_collector_age future_node invalid_frame_rate invalid_signal_metric "
    "invalid_source_timestamp invalid_sequence invalid_node_epoch invalid_discontinuities "
    "invalid_epoch_reason receiver_proof_required receiver_proof_unavailable "
    "receiver_identity_priming receiver_radio_grid_mismatch scalar_outside_receiver_proofs "
    "no_new_sample recent_ambient_comparison collecting_recent_ambient_baseline".split()
)
EPOCH_REASONS = frozenset(
    "receipt_clock_discontinuity grid_changed sequence_backwards_boot_unknown "
    "sequence_conflict_boot_unknown sequence_gap "
    "receipt_gap bounded_history_renewal first_frame awaiting_csi".split()
)


def read_failure(error):
    """Fixed codes only; HTTPError/URLError and parser text may contain secrets."""
    if isinstance(error, urllib.error.HTTPError):
        return "http", "http_status"
    if isinstance(error, socket.gaierror) or (
        isinstance(error, urllib.error.URLError)
        and isinstance(error.reason, socket.gaierror)
    ):
        return "transport", "dns_error"
    if isinstance(error, TimeoutError) or (
        isinstance(error, urllib.error.URLError)
        and isinstance(error.reason, TimeoutError)
    ):
        return "transport", "timeout"
    if isinstance(error, (OSError, urllib.error.URLError)):
        return "transport", "network_error"
    if isinstance(error, json.JSONDecodeError):
        return "decode", "invalid_json"
    if isinstance(error, UnicodeError):
        return "decode", "invalid_encoding"
    allowed = {
        "source_redirect_refused": "http",
        "source_http_status": "http",
        "document_too_large": "body",
        "unsupported_content_encoding": "decode",
        "invalid_gzip_body": "decode",
        "nonfinite_json": "decode",
        "duplicate_json_key": "decode",
        "object_required": "decode",
    }
    code = error.args[0] if len(error.args) == 1 else None
    if type(error) is ValueError and type(code) is str and code in allowed:
        return allowed[code], code
    return "read", "unclassified_read_error"


def milliseconds(seconds):
    return (
        round(seconds * 1000, 6)
        if math.isfinite(seconds) and 0 <= seconds <= 86400
        else None
    )


def observed_read(reader, args, submitted):
    started = time.monotonic()
    details = {"outcome": "ok", "stage": "complete", "reason": None}
    try:
        value = reader(*args)
    except Exception as error:
        value = {}
        stage, reason = read_failure(error)
        details.update(outcome="error", stage=stage, reason=reason)
        if (
            isinstance(error, urllib.error.HTTPError)
            and type(error.code) is int
            and 100 <= error.code <= 599
        ):
            details["http_status"] = error.code
    details.update(
        queue_ms=milliseconds(started - submitted),
        request_ms=milliseconds(time.monotonic() - started),
    )
    return value, details


def source_ages(values, now_ns):
    """Descriptive signed ages, not another acceptance decision."""
    result = {"worker_ms": None, "collector_ms": None}
    worker, collector = values[1:]
    if isinstance(worker, dict):
        stamp = worker.get("generated_at_ns")
        if (
            type(stamp) is str
            and stamp.isascii()
            and stamp.isdecimal()
            and len(stamp) <= 20
        ):
            result["worker_ms"] = (now_ns - int(stamp)) / 1e6
    if isinstance(collector, dict):
        stamp = collector.get("timestamp")
        if type(stamp) in (int, float) and 1 <= stamp <= 1e11 and math.isfinite(stamp):
            result["collector_ms"] = (now_ns - int(stamp * 1e9)) / 1e6
    return result


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def document(raw):
    require(len(raw) <= MAX_DOCUMENT, "document_too_large")

    def invalid_constant(_value):
        raise ValueError("nonfinite_json")

    value = json.loads(
        raw, object_pairs_hook=unique_pairs, parse_constant=invalid_constant
    )
    require(isinstance(value, dict), "object_required")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("source_redirect_refused")


def base_url(value):
    parsed = urlsplit(value)
    require(
        parsed.scheme in ("http", "https")
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment,
        "invalid_source_url",
    )
    return value.rstrip("/")


def read_json(url, timeout, token=None, max_document=MAX_DOCUMENT):
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Cache-Control": "no-cache",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        require(response.status == 200, "source_http_status")
        raw = response.read(max_document + 1)
        raw = decode_http_body(
            raw, response.getheader("Content-Encoding"), max_document
        )
        return document(raw)


def read_receiver(url, timeout):
    # Receiver identity endpoints are unauthenticated; never send the collector token.
    return read_json(url, timeout, max_document=MAX_PROOF_BYTES)


def timed_receiver(reader, url, timeout):
    start, wall_start = time.monotonic(), time.time_ns()
    value = reader(url, timeout)
    finish, wall_finish = time.monotonic(), time.time_ns()
    return {
        "document": value,
        "started": start,
        "finished": finish,
        "started_at_ns": wall_start,
        "finished_at_ns": wall_finish,
    }


def discovery(policy):
    return {
        "name": "RuView assumed zone activity",
        "default_entity_id": "sensor.ruview_assumed_zone_activity",
        "unique_id": "ruview_assumed_zone_activity",
        "state_topic": STATE,
        "json_attributes_topic": STATE,
        "value_template": (
            "{{ value_json.state if "
            "value_json.generated_at_ns | int <= (as_timestamp(now()) * 1000000000) "
            "< value_json.expires_at_ns | int else 'unknown' }}"
        ),
        "availability_topic": AVAILABILITY,
        "payload_available": "online",
        "payload_not_available": "offline",
        "expire_after": math.ceil(policy["ttl_seconds"]),
        "icon": "mdi:access-point-network",
        "device": {
            "identifiers": ["ruview_assumed_activity"],
            "name": "RuView assumed activity experiment",
            "manufacturer": "RuView",
            "model": "Unsupervised signal anomalies with assumed geometry",
        },
    }


class Publisher:
    def __init__(self, client, policy):
        self.client, self.policy = client, policy
        self.connected = False
        client.on_connect = self.on_connect
        client.on_disconnect = self.on_disconnect
        client.on_message = self.on_message
        client.will_set(AVAILABILITY, "offline", qos=1, retain=True)

    def announce(self):
        self.client.publish(
            DISCOVERY, encoded(discovery(self.policy)), qos=1, retain=True
        )
        self.client.publish(AVAILABILITY, "online", qos=1, retain=True)

    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = reason_code == 0
        if self.connected:
            client.subscribe("homeassistant/status", qos=1)
            self.announce()

    def on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = False

    def on_message(self, client, userdata, message):
        if message.topic == "homeassistant/status" and message.payload == b"online":
            self.announce()

    def publish(self, envelope):
        if self.connected:
            payload = encoded(envelope)
            # QoS 0: never accumulate old live envelopes for a reconnect replay.
            self.client.publish(ATTRIBUTES, payload, qos=0, retain=False)
            self.client.publish(STATE, payload, qos=0, retain=False)

    def close(self):
        if self.connected:
            self.client.publish(AVAILABILITY, "offline", qos=1, retain=True)
        self.client.disconnect()
        self.client.loop_stop()


class Service:
    def __init__(
        self,
        config,
        collector_url,
        worker_url,
        token,
        publisher,
        reader=read_json,
        receiver_config=None,
        proof_reader=read_receiver,
        runtime_config=None,
        source_executor=None,
        expected_receiver_sha256=None,
        *,
        expected_coordinate_frame,
    ):
        policy = Producer(
            config, expected_coordinate_frame=expected_coordinate_frame
        ).policy
        self.runtime = runtime_configuration(runtime_config)
        self.proofs = (
            ReceiverProofs(
                receiver_config,
                [r["node_id"] for r in config["receivers"]],
                self.runtime["receiver_http_timeout_seconds"],
                policy["reset_gap_seconds"],
                refresh_reservation=self.runtime["receiver_phase_budget_seconds"],
                expected_sha256=expected_receiver_sha256,
            )
            if receiver_config is not None
            else None
        )
        self.producer = Producer(
            config,
            self.proofs.config_sha if self.proofs else None,
            expected_coordinate_frame=expected_coordinate_frame,
        )
        self.proof_reader = proof_reader
        self.receiver_reads = ReceiverReads(
            [r["node_id"] for r in config["receivers"]],
            lambda url, timeout, submitted: observed_read(
                timed_receiver, (self.proof_reader, url, timeout), submitted
            ),
        )
        self.collector_url, self.worker_url = (
            base_url(collector_url),
            base_url(worker_url),
        )
        require(
            isinstance(token, str) and token.strip() and "\n" not in token,
            "api_token_required",
        )
        self.token, self.publisher, self.reader = token, publisher, reader
        self.source_reads = SourceReads(
            ("worker_health", "worker_latest", "collector_latest"),
            lambda target, timeout, submitted: observed_read(
                self.reader, (target[0], timeout, target[1]), submitted
            ),
            executor=source_executor,
            clock=lambda: time.monotonic(),
        )
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.last_completed = None
        self.started = time.monotonic()
        self.poll_count = 0
        self.diagnostic_history = deque(maxlen=DIAGNOSTIC_HISTORY)
        self.diagnostic_counts = dict.fromkeys(
            (
                "polls",
                "source_read_failures",
                "proof_read_failures",
                "core_rejections",
                "node_rejections",
            ),
            0,
        )
        self.last_accepted = {}

    def record_diagnostics(
        self,
        result,
        reads,
        proof_reads,
        before_ages,
        values,
        started,
        source_done,
        proof_done,
        mono,
    ):
        worker = values[1]
        context = (
            [
                worker.get(k)
                for k in ("worker_run_id", "configuration_sha256", "clock_id")
            ]
            if isinstance(worker, dict)
            else []
        )
        context_sha = (
            digest(context)
            if len(context) == 3
            and all(type(v) is str and 0 < len(v) <= 256 for v in context)
            else None
        )
        nodes = []
        for row in result["nodes"]:
            node = row["node_id"]
            previous = self.last_accepted.get(node)
            accepted = row["status"] in ("ready", "warming_up")
            nodes.append(
                {
                    "node_id": node,
                    "status": row["status"],
                    "reason": row["reason"]
                    if row["reason"] in NODE_REASONS
                    else "unclassified_node_reason",
                    "baseline_samples": row["baseline_samples"],
                    "source_age_ms": row["source_age_ms"],
                    "node_epoch": row.get("node_epoch"),
                    "epoch_reason": row.get("epoch_reason")
                    if row.get("epoch_reason") in EPOCH_REASONS
                    else None,
                    "sequence_discontinuities": row.get("sequence_discontinuities"),
                    "accepted_gap_ms": milliseconds(mono - previous[0])
                    if accepted and previous
                    else None,
                    "history_rebuilt": bool(
                        accepted and previous and row["baseline_samples"] == 0
                    ),
                }
            )
            if accepted:
                self.last_accepted[node] = (mono, row["baseline_samples"])
        increments = {
            "polls": 1,
            "source_read_failures": sum(
                r["outcome"] == "error" for r in reads.values()
            ),
            "proof_read_failures": sum(
                r["outcome"] == "error" for r in proof_reads.values()
            ),
            "core_rejections": int(self.producer.last_rejection is not None),
            "node_rejections": sum(n["status"] == "unknown" for n in nodes),
        }
        for key, increment in increments.items():
            self.diagnostic_counts[key] = min(
                MAX_COUNTER, self.diagnostic_counts[key] + increment
            )
        self.diagnostic_history.append(
            {
                "poll_count": self.poll_count,
                "generated_at_ns": result["generated_at_ns"],
                "state": result["state"],
                "core_rejection": self.producer.last_rejection,
                "source_reads": reads,
                "proof_reads": proof_reads,
                "source_age_before_proofs_ms": before_ages,
                "source_age_at_evaluation_ms": source_ages(
                    values, int(result["generated_at_ns"])
                ),
                "source_phase_ms": milliseconds(source_done - started),
                "proof_phase_ms": milliseconds(proof_done - source_done),
                "evaluation_ms": milliseconds(time.monotonic() - mono),
                "worker_context_sha256": context_sha,
                "nodes": nodes,
            }
        )

    def poll_once(self):
        started = time.monotonic()
        timeout = self.producer.policy["http_timeout_seconds"]
        requests = {
            "worker_health": (self.worker_url + "/health", None),
            "worker_latest": (self.worker_url + "/v1/latest", None),
            "collector_latest": (
                self.collector_url + "/api/v1/sensing/latest",
                self.token,
            ),
        }
        # A socket timeout does not bound DNS or a slowly trickling body. Use
        # one wall-clock budget for the whole phase and discard late replies.
        readings, reads = self.source_reads.collect(requests, timeout, timeout)
        values = [readings[name] for name in requests]
        source_done = time.monotonic()
        before_ages = source_ages(values, time.time_ns())
        proofs = None
        proof_reads = {}
        if self.proofs is not None:
            readings, proof_reads = self.receiver_reads.collect(
                self.proofs.requests(values[1], time.monotonic()),
                self.runtime["receiver_http_timeout_seconds"],
                self.runtime["receiver_phase_budget_seconds"],
            )
            proofs = self.proofs.resolve(values[1], readings, time.monotonic())
        proof_done = time.monotonic()
        now_ns, mono = time.time_ns(), time.monotonic()
        with self.lock:
            result = self.producer.update(*values, now_ns, mono, proofs=proofs)
            self.last_completed = mono
            self.poll_count += 1
            self.record_diagnostics(
                result,
                reads,
                proof_reads,
                before_ages,
                values,
                started,
                source_done,
                proof_done,
                mono,
            )
        self.publisher.publish(result)
        return result

    def close(self):
        self.source_reads.close()
        self.receiver_reads.close()

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            self.poll_once()
            self.stop.wait(
                max(
                    0,
                    self.producer.policy["poll_seconds"] - (time.monotonic() - started),
                )
            )

    def response(self, path, *, local=False):
        with self.lock:
            # Polling may publish newer state while this reader waits for the lock.
            # Sample time after acquiring that state, never before it.
            now_ns, mono = time.time_ns(), time.monotonic()
            if path == "/internal/diagnostics" and local:
                return 200, {
                    "schema": "ruview.assumed-activity.internal-diagnostics.v1",
                    "runtime_configuration": dict(self.runtime),
                    "runtime_configuration_sha256": digest(self.runtime),
                    "history_limit": DIAGNOSTIC_HISTORY,
                    "counters": dict(self.diagnostic_counts),
                    "polls": copy.deepcopy(list(self.diagnostic_history)),
                }
            if path == "/v1/activity":
                return 200, self.producer.snapshot(now_ns, mono)
            if path == "/health":
                last = (
                    self.last_completed
                    if self.last_completed is not None
                    else self.started
                )
                healthy = 0 <= mono - last <= 30 and not self.stop.is_set()
                return (200 if healthy else 503), {
                    "status": "ok" if healthy else "stalled",
                    "poll_count": self.poll_count,
                    "poll_age_seconds": max(0, mono - last),
                    "mqtt_connected": self.publisher.connected,
                    "recognition_validated": False,
                }
        return 404, {"error": "not_found"}


def handler_for(service):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, value = service.response(
                self.path, local=self.client_address[0] in ("127.0.0.1", "::1")
            )
            payload = encoded(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass

    return Handler


def http_bind():
    """Validate the listener before constructing clients or starting any I/O."""
    try:
        address = ipaddress.IPv4Address(
            os.environ.get("ASSUMED_ACTIVITY_BIND_ADDRESS", "0.0.0.0")
        )
    except ipaddress.AddressValueError:
        raise ValueError("invalid_http_bind_address") from None
    require(
        not address.is_multicast and int(address) != 0xFFFFFFFF,
        "invalid_http_bind_address",
    )
    port = int(os.environ.get("ASSUMED_ACTIVITY_HTTP_PORT", "5017"))
    require(1 <= port <= 65535, "invalid_http_port")
    return str(address), port


def load_configuration():
    values = []
    # Authenticate every raw file before interpreting any configuration or
    # reading credentials. Deployment hashes came from the approved manifest.
    for suffix, name, limit in (
        ("CONFIG", "assumed-activity.json", MAX_DOCUMENT),
        ("RECEIVERS", "assumed-activity-receivers.json", MAX_PROOF_BYTES),
        ("RUNTIME", "assumed-activity-runtime.json", MAX_PROOF_BYTES),
    ):
        values.append(
            pinned_bytes(
                os.environ.get("ASSUMED_ACTIVITY_" + suffix, "/config/" + name),
                os.environ.get("ASSUMED_ACTIVITY_" + suffix + "_SHA256"),
                limit,
            )
        )
    config, receiver_config, runtime = map(document, values)
    runtime_config = runtime_configuration(runtime)
    expected_coordinate_frame = os.environ.get("ASSUMED_ACTIVITY_COORDINATE_FRAME")
    Producer(config, expected_coordinate_frame=expected_coordinate_frame)
    approved_receiver_sha256 = digest(receiver_config)
    receiver_configuration(
        receiver_config,
        [row["node_id"] for row in config["receivers"]],
        approved_receiver_sha256,
    )
    return (
        config,
        receiver_config,
        runtime_config,
        approved_receiver_sha256,
        expected_coordinate_frame,
    )


def main():
    bind = http_bind()
    (
        config,
        receiver_config,
        runtime_config,
        approved_receiver_sha256,
        expected_coordinate_frame,
    ) = load_configuration()
    import paho.mqtt.client as mqtt

    policy = Producer(
        config, expected_coordinate_frame=expected_coordinate_frame
    ).policy
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2, client_id="ruview-assumed-activity"
    )
    client.username_pw_set(os.environ["MQTT_USERNAME"], os.environ["MQTT_PASSWORD"])
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    publisher = Publisher(client, policy)
    service = Service(
        config,
        os.environ.get("RUVIEW_URL", "http://ruview.ruview.svc.cluster.local:3000"),
        os.environ.get(
            "RUVIEW_MODULES_URL",
            "http://ruview-server-modules.ruview.svc.cluster.local:5016",
        ),
        os.environ["RUVIEW_API_TOKEN"],
        publisher,
        receiver_config=receiver_config,
        expected_receiver_sha256=approved_receiver_sha256,
        runtime_config=runtime_config,
        expected_coordinate_frame=expected_coordinate_frame,
    )
    server = ThreadingHTTPServer(bind, handler_for(service))
    server.daemon_threads = True
    server.timeout = 0.5
    client.connect_async(
        os.environ["RUVIEW_MQTT_HOST"],
        int(os.environ.get("RUVIEW_MQTT_PORT", "1883")),
        keepalive=20,
    )
    client.loop_start()
    poller = threading.Thread(target=service.run, name="activity-poller", daemon=True)
    poller.start()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: service.stop.set())
    try:
        while not service.stop.is_set():
            server.handle_request()
    finally:
        service.stop.set()
        server.server_close()
        publisher.close()
        poller.join(timeout=10)
        service.close()
