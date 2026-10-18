"""Bounded polling phases, with at most one outstanding read per endpoint."""

import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

from .core import require

DEFAULT_RUNTIME = {
    "schema": "ruview.assumed-activity.runtime.v1",
    "receiver_http_timeout_seconds": 1.0,
    "receiver_phase_budget_seconds": 1.0,
}


def runtime_configuration(value=None):
    value = dict(DEFAULT_RUNTIME) if value is None else value
    require(
        isinstance(value, dict)
        and set(value) == set(DEFAULT_RUNTIME)
        and value["schema"] == DEFAULT_RUNTIME["schema"],
        "invalid_runtime_configuration",
    )
    for key in ("receiver_http_timeout_seconds", "receiver_phase_budget_seconds"):
        require(
            type(value[key]) in (int, float)
            and math.isfinite(value[key])
            and 0.1 <= value[key] <= 1.5,
            "invalid_" + key,
        )
    require(
        value["receiver_http_timeout_seconds"]
        <= value["receiver_phase_budget_seconds"],
        "receiver_timeout_exceeds_phase_budget",
    )
    return dict(value)


def unavailable(reason):
    return {
        "outcome": "error",
        "stage": "deadline",
        "reason": reason,
        "queue_ms": None,
        "request_ms": None,
    }


def elapsed_ms(start, finish):
    value = finish - start
    return (
        round(value * 1000, 6) if math.isfinite(value) and 0 <= value <= 86400 else None
    )


def discarded_outcome(detail):
    """Keep late-read diagnostics bounded; never retain a document or error text."""
    outcome = detail.get("outcome")
    reason = detail.get("reason")
    allowed_reasons = {
        "http_status",
        "timeout",
        "dns_error",
        "network_error",
        "invalid_json",
        "invalid_encoding",
        "source_redirect_refused",
        "source_http_status",
        "document_too_large",
        "unsupported_content_encoding",
        "invalid_gzip_body",
        "nonfinite_json",
        "duplicate_json_key",
        "object_required",
        "unclassified_read_error",
    }
    return {
        "outcome": outcome if outcome in ("ok", "error") else "unknown",
        "reason": None
        if outcome == "ok"
        else (
            reason
            if type(reason) is str and reason in allowed_reasons
            else "unclassified_read_error"
        ),
    }


class ReadProgress:
    """Timing only: a worker may publish its start, but never an accepted result."""

    def __init__(self, submitted, deadline):
        self.submitted, self.deadline = submitted, deadline
        self.started = None
        self.lock = threading.Lock()

    def start(self, now):
        with self.lock:
            self.started = now

    def snapshot(self, now, *, completed=False):
        with self.lock:
            started = self.started
        return {
            "state": "completed"
            if completed
            else "queued"
            if started is None
            else "running",
            "queue_ms": None
            if started is None
            else elapsed_ms(self.submitted, started),
            "request_elapsed_ms": None if started is None else elapsed_ms(started, now),
            "submitted_elapsed_ms": elapsed_ms(self.submitted, now),
            "deadline_overrun_ms": elapsed_ms(self.deadline, now),
        }


class BoundedReads:
    """The poller owns futures; workers publish only a start time and their result.

    A deadline stops waiting, not the underlying socket. Late results are never
    reused. The separate fixed-size executor and in-flight map bound outstanding
    work even if a receiver indefinitely trickles bytes. Socket timeouts still
    apply; process termination remains the final boundary for stuck I/O.
    """

    def __init__(
        self,
        node_ids,
        read,
        executor=None,
        clock=time.monotonic,
        waiter=wait,
        *,
        kind="receiver",
    ):
        require(kind in ("receiver", "source"), "invalid_poll_kind")
        self.kind = kind
        self.nodes = frozenset(node_ids)
        require(0 < len(self.nodes) <= 16, "invalid_" + kind + "_pool")
        self.read, self.clock, self.waiter = read, clock, waiter
        self.executor = executor or ThreadPoolExecutor(
            max_workers=len(self.nodes), thread_name_prefix=kind + "-get"
        )
        self.owns_executor = executor is None
        self.inflight = {}
        self.progress = {}
        self.discarded_reads = {}
        self.closed = False

    def job(self, url, timeout, submitted, progress):
        progress.start(self.clock())
        value, details = self.read(url, timeout, submitted)
        return value, details, self.clock()

    def collect(self, requests, timeout, budget):
        require(not self.closed, self.kind + "_pool_closed")
        require(set(requests) <= self.nodes, "unexpected_" + self.kind + "_request")
        deadline = self.clock() + budget
        # Every retained future belongs to an expired poll, never this one.
        for node, future in list(self.inflight.items()):
            if future.done():
                if not future.cancelled():
                    # The payload remains discarded, even if the result was valid.
                    # Do not suppress fatal worker errors while reading diagnostics.
                    _, detail, completed = future.result()
                    self.discarded_reads[node] = self.progress[node].snapshot(
                        completed, completed=True
                    )
                    self.discarded_reads[node].update(discarded_outcome(detail))
                del self.inflight[node]
                del self.progress[node]
        current, readings, details = {}, {}, {}
        for node, url in requests.items():
            readings[node] = {}  # Explicitly invalidate a cached proof on failure.
            if node in self.inflight:
                details[str(node)] = unavailable(
                    "previous_" + self.kind + "_request_pending"
                )
                details[str(node)]["deadline_progress"] = self.progress[node].snapshot(
                    self.clock()
                )
                continue
            submitted = self.clock()
            progress = self.progress[node] = ReadProgress(submitted, deadline)
            future = self.executor.submit(self.job, url, timeout, submitted, progress)
            self.inflight[node] = current[node] = future
        if current:
            self.waiter(list(current.values()), timeout=max(0, deadline - self.clock()))
        for node, future in current.items():
            details[str(node)] = unavailable(self.kind + "_phase_deadline")
            if future.done() and not future.cancelled():
                value, detail, completed = future.result()
                del self.inflight[node]
                if completed <= deadline:
                    readings[node], details[str(node)] = value, detail
                else:
                    details[str(node)]["deadline_progress"] = self.progress[
                        node
                    ].snapshot(completed, completed=True)
                    details[str(node)]["discarded_outcome"] = discarded_outcome(detail)
                del self.progress[node]
            elif future.cancel():
                details[str(node)]["deadline_progress"] = self.progress[node].snapshot(
                    self.clock()
                )
                del self.inflight[node]
                del self.progress[node]
            else:
                details[str(node)]["deadline_progress"] = self.progress[node].snapshot(
                    self.clock()
                )
        for node in requests:
            if node in self.discarded_reads:
                # Keep at most one timing/outcome per node, including when an
                # invalid source temporarily prevents another receiver read.
                details[str(node)]["discarded_previous_read"] = (
                    self.discarded_reads.pop(node)
                )
        return readings, details

    def close(self):
        self.closed = True
        if self.owns_executor:
            self.executor.shutdown(wait=False, cancel_futures=True)


class ReceiverReads(BoundedReads):
    """Receiver identity reads retain their existing deadline contract."""


class SourceReads(BoundedReads):
    """Collector and worker reads cannot stall publication or build a queue."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, kind="source")
