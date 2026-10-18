"""Exercise the capture smoke's real wait loop without starting a worker."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(f"{name}.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


with patch.dict(sys.modules, {"service_smoke": load("service_smoke")}):
    with patch.dict(sys.modules, {"fleet_service_smoke": load("fleet_service_smoke")}):
        SMOKE = load("capture_service_smoke")


class CaptureStatusTests(unittest.TestCase):
    session = "33333333-3333-4333-8333-333333333333"

    def test_skipped_active_fails_immediately_even_with_successful_terminal(self):
        for actual in ("closing", "closed"):
            with self.subTest(actual=actual):
                command = Mock(
                    return_value={
                        "status": actual,
                        "terminal": {
                            "complete": True,
                            "end_reason": "duration_elapsed",
                            "counters": {"written": 1},
                        },
                    }
                )
                budget = Mock(side_effect=AssertionError("must not keep waiting"))
                with (
                    patch.object(SMOKE.time, "sleep") as sleep,
                    self.assertRaisesRegex(
                        ValueError,
                        f"{self.session}: expected active, actual {actual}",
                    ),
                ):
                    SMOKE.wait_for_capture_status(
                        self.session, "active", command, budget
                    )
                command.assert_called_once_with(self.session, "status")
                budget.assert_not_called()
                sleep.assert_not_called()

    def test_normal_transitions_return_the_exact_expected_reply(self):
        cases = (
            ("active", ["starting", "active"]),
            ("closed", ["starting", "active", "closing", "closed"]),
            ("closed", ["closed"]),
        )
        for expected, statuses in cases:
            with self.subTest(expected=expected, statuses=statuses):
                replies = [
                    {"status": status, "index": i} for i, status in enumerate(statuses)
                ]
                command = Mock(side_effect=replies)
                budget = Mock(return_value=3)
                with patch.object(SMOKE.time, "sleep") as sleep:
                    result = SMOKE.wait_for_capture_status(
                        self.session, expected, command, budget
                    )
                self.assertIs(result, replies[-1])
                self.assertEqual(
                    command.call_args_list,
                    [call(self.session, "status")] * len(statuses),
                )
                self.assertEqual(budget.call_count, len(statuses) - 1)
                self.assertEqual(
                    sleep.call_args_list, [call(0.05)] * (len(statuses) - 1)
                )

    def test_control_error_reply_still_fails_without_another_wait(self):
        command = Mock(return_value={"status": "error", "error": "unknown_session"})
        budget = Mock()
        with (
            patch.object(SMOKE.time, "sleep") as sleep,
            self.assertRaisesRegex(ValueError, "status error"),
        ):
            SMOKE.wait_for_capture_status(self.session, "closed", command, budget)
        command.assert_called_once_with(self.session, "status")
        budget.assert_not_called()
        sleep.assert_not_called()

    def test_command_timeout_propagates_unchanged(self):
        failure = subprocess.TimeoutExpired(["synthetic-control"], 0.141)
        command = Mock(side_effect=failure)
        budget = Mock()
        with (
            patch.object(SMOKE.time, "sleep") as sleep,
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            SMOKE.wait_for_capture_status(self.session, "active", command, budget)
        self.assertIs(raised.exception, failure)
        command.assert_called_once_with(self.session, "status")
        budget.assert_not_called()
        sleep.assert_not_called()

    def test_exhausted_budget_still_fails_instead_of_retrying(self):
        failure = ValueError("capture smoke deadline")
        command = Mock(return_value={"status": "active"})
        budget = Mock(side_effect=failure)
        with (
            patch.object(SMOKE.time, "sleep") as sleep,
            self.assertRaises(ValueError) as raised,
        ):
            SMOKE.wait_for_capture_status(self.session, "closed", command, budget)
        self.assertIs(raised.exception, failure)
        command.assert_called_once_with(self.session, "status")
        budget.assert_called_once_with()
        sleep.assert_not_called()

    def test_remaining_budget_still_caps_sleep(self):
        reply = {"status": "closed"}
        command = Mock(side_effect=[{"status": "closing"}, reply])
        budget = Mock(return_value=0.02)
        with patch.object(SMOKE.time, "sleep") as sleep:
            result = SMOKE.wait_for_capture_status(
                self.session, "closed", command, budget
            )
        self.assertIs(result, reply)
        sleep.assert_called_once_with(0.02)
        budget.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
