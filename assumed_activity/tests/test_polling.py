"""Controlled futures prove deadline isolation without network timing assumptions."""

import copy
import threading
import unittest
from concurrent.futures import Future

from assumed_activity.polling import ReceiverReads, SourceReads, runtime_configuration


class ControlledExecutor:
    def __init__(self):
        self.jobs = []

    def submit(self, fn, *args):
        future = Future()
        future.set_running_or_notify_cancel()
        self.jobs.append((future, fn, args))
        return future

    def finish(self, index):
        future, fn, args = self.jobs[index]
        future.set_result(fn(*args))


class PollingTests(unittest.TestCase):
    pool_class = ReceiverReads
    kind = "receiver"

    def setUp(self):
        self.now = 0.0
        self.executor = ControlledExecutor()
        self.waits = []
        self.on_wait = lambda: None

        def wait(futures, timeout):
            self.waits.append((len(futures), timeout))
            self.on_wait()

        self.pool = self.pool_class(
            (1, 2, 3),
            lambda url, timeout, submitted: ({"url": url}, {"outcome": "ok"}),
            executor=self.executor,
            clock=lambda: self.now,
            waiter=wait,
        )

    def test_one_shared_deadline_and_independent_healthy_results(self):
        def finish():
            self.now = 0.25
            self.executor.finish(1)
            self.executor.finish(2)
            self.now = 1.0

        self.on_wait = finish
        readings, details = self.pool.collect({1: "one", 2: "two", 3: "three"}, 1, 1)
        self.assertEqual(self.waits, [(3, 1.0)])
        self.assertEqual(readings[1], {})
        self.assertEqual(details["1"]["reason"], self.kind + "_phase_deadline")
        self.assertEqual(readings[2], {"url": "two"})
        self.assertEqual(readings[3], {"url": "three"})
        self.assertEqual(set(self.pool.inflight), {1})

    def test_pending_does_not_queue_and_late_result_never_reused(self):
        self.pool.collect({1: "old"}, 1, 1)
        for _ in range(100):
            readings, details = self.pool.collect({1: "new"}, 1, 1)
            self.assertEqual(readings[1], {})
            self.assertEqual(
                details["1"]["reason"], "previous_" + self.kind + "_request_pending"
            )
        self.assertEqual(len(self.executor.jobs), 1)
        self.now = 8.0
        self.executor.finish(0)
        self.on_wait = lambda: self.executor.finish(1)
        readings, _ = self.pool.collect({1: "fresh"}, 1, 1)
        self.assertEqual(readings[1], {"url": "fresh"})
        self.assertEqual(len(self.executor.jobs), 2)

    def test_completed_but_after_deadline_is_rejected(self):
        def finish():
            self.now = 1.001
            self.executor.finish(0)

        self.on_wait = finish
        readings, details = self.pool.collect({1: "one"}, 1, 1)
        self.assertEqual(readings[1], {})
        self.assertEqual(details["1"]["reason"], self.kind + "_phase_deadline")
        progress = details["1"]["deadline_progress"]
        self.assertEqual(progress["state"], "completed")
        self.assertEqual(progress["deadline_overrun_ms"], 1.0)
        self.assertEqual(details["1"]["discarded_outcome"]["outcome"], "ok")
        self.assertFalse(self.pool.inflight)
        self.assertFalse(self.pool.progress)

    def test_deadline_distinguishes_unscheduled_read_from_running_io(self):
        # An executor-starved job has not entered the reader at the phase boundary.
        self.on_wait = lambda: setattr(self, "now", 1.2)
        readings, details = self.pool.collect({1: "queued"}, 1.0, 1.2)
        self.assertEqual(readings, {1: {}})
        self.assertEqual(
            details["1"]["deadline_progress"],
            {
                "state": "queued",
                "queue_ms": None,
                "request_elapsed_ms": None,
                "submitted_elapsed_ms": 1200.0,
                "deadline_overrun_ms": 0.0,
            },
        )

        # Exercise actual worker-thread entry; the phase expires while I/O waits.
        self.now = 0.0
        started, release = threading.Event(), threading.Event()

        def read(*_):
            started.set()
            if not release.wait(2):
                raise RuntimeError("test release missing")
            return {"late_payload": True}, {"outcome": "ok"}

        def wait_for_start(_futures, timeout):
            self.assertTrue(started.wait(2))
            self.now = timeout

        pool = self.pool_class(
            (1,), read, clock=lambda: self.now, waiter=wait_for_start
        )
        try:
            readings, details = pool.collect({1: "running"}, 1.0, 1.2)
            self.assertEqual(readings, {1: {}})
            self.assertEqual(details["1"]["reason"], self.kind + "_phase_deadline")
            self.assertEqual(
                details["1"]["deadline_progress"],
                {
                    "state": "running",
                    "queue_ms": 0.0,
                    "request_elapsed_ms": 1200.0,
                    "submitted_elapsed_ms": 1200.0,
                    "deadline_overrun_ms": 0.0,
                },
            )
            self.assertEqual(set(pool.inflight), {1})
        finally:
            release.set()
            pool.close()

    def test_discarded_late_result_reports_timing_never_payload_or_error_text(self):
        self.on_wait = lambda: setattr(self, "now", 1.2)
        self.pool.collect({1: "old"}, 1.0, 1.2)
        self.now = 1.3
        self.pool.read = lambda *_: (
            {"secret_payload": True},
            {"outcome": "error", "reason": "secret_error", "extra": "secret_extra"},
        )
        self.executor.finish(0)
        # Missing source input may suppress receiver requests for this poll.
        # Keep only bounded diagnostics until that endpoint is requested again.
        self.pool.collect({}, 1.0, 1.2)
        self.assertEqual(set(self.pool.discarded_reads), {1})
        self.assertFalse(self.pool.inflight)
        self.assertFalse(self.pool.progress)
        self.pool.read = lambda url, *_: ({"url": url}, {"outcome": "ok"})
        self.on_wait = lambda: self.executor.finish(1)
        readings, details = self.pool.collect({1: "fresh"}, 1.0, 1.2)
        self.assertEqual(readings, {1: {"url": "fresh"}})
        discarded = details["1"]["discarded_previous_read"]
        self.assertEqual(discarded["state"], "completed")
        self.assertEqual(discarded["queue_ms"], 1300.0)
        self.assertEqual(discarded["deadline_overrun_ms"], 100.0)
        self.assertEqual(discarded["outcome"], "error")
        self.assertEqual(discarded["reason"], "unclassified_read_error")
        self.assertNotIn("secret", str(details))
        self.assertFalse(self.pool.inflight)
        self.assertFalse(self.pool.progress)
        self.assertFalse(self.pool.discarded_reads)

    def test_previous_pending_progress_is_bounded_and_still_invalidates(self):
        self.pool.collect({1: "old"}, 1.0, 1.2)
        for _ in range(100):
            self.now += 1
            readings, details = self.pool.collect({1: "new"}, 1.0, 1.2)
            self.assertEqual(readings, {1: {}})
            self.assertEqual(details["1"]["deadline_progress"]["state"], "queued")
            self.assertEqual(set(self.pool.progress), {1})
            self.assertEqual(set(self.pool.inflight), {1})
        self.assertEqual(len(self.executor.jobs), 1)

    def test_late_fatal_worker_error_is_not_silently_discarded(self):
        for error in (KeyboardInterrupt, SystemExit):
            with self.subTest(error=error):
                self.setUp()
                self.pool.collect({1: "one"}, 1, 1)
                self.executor.jobs[0][0].set_exception(error())
                with self.assertRaises(error):
                    self.pool.collect({}, 1, 1)

    def test_queue_time_consumes_shared_budget(self):
        original = self.executor.submit

        def slow_submit(*args):
            self.now += 0.2
            return original(*args)

        self.executor.submit = slow_submit
        self.pool.collect({1: "one", 2: "two", 3: "three"}, 1, 1)
        self.assertAlmostEqual(self.waits[0][1], 0.4)

    def test_closed_or_unconfigured_nodes_rejected_before_submission(self):
        with self.assertRaisesRegex(ValueError, "unexpected_" + self.kind + "_request"):
            self.pool.collect({4: "four"}, 1, 1)
        self.pool.close()
        with self.assertRaisesRegex(ValueError, self.kind + "_pool_closed"):
            self.pool.collect({1: "one"}, 1, 1)
        self.assertFalse(self.executor.jobs)

    def test_strict_runtime_configuration(self):
        good = runtime_configuration()
        self.assertEqual(good["receiver_phase_budget_seconds"], 1)
        self.assertEqual(runtime_configuration(copy.deepcopy(good)), good)
        for value in (True, "1", float("nan"), float("inf"), 0, 1.501):
            for key in (
                "receiver_http_timeout_seconds",
                "receiver_phase_budget_seconds",
            ):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    runtime_configuration(good | {key: value})
        for bad in (None, {}, good | {"extra": 1}, good | {"schema": "unknown"}):
            if bad is not None:
                with self.assertRaises(ValueError):
                    runtime_configuration(bad)
        with self.assertRaisesRegex(
            ValueError, "receiver_timeout_exceeds_phase_budget"
        ):
            runtime_configuration(good | {"receiver_phase_budget_seconds": 0.5})


class SourcePollingTests(PollingTests):
    pool_class = SourceReads
    kind = "source"


if __name__ == "__main__":
    unittest.main()
