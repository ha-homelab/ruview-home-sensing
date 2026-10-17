"""Regression checks for the trust boundary between event metadata and history."""

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    "check_history_event",
    Path(__file__).resolve().parents[1] / "check_history_event.py",
)
EVENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVENT)

HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40


class HistoryEventTests(unittest.TestCase):
    def test_pull_request_checks_both_real_histories_not_generated_merge(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command[-1])
            return SimpleNamespace(returncode=0)

        self.assertEqual(
            EVENT.check_event(
                {
                    "HISTORY_EVENT": "pull_request",
                    "HISTORY_PR_HEAD": HEAD,
                    "HISTORY_PR_BASE": BASE,
                    "HISTORY_REVISION": MERGE,
                },
                run,
            ),
            0,
        )
        self.assertEqual(calls, [HEAD, BASE])

    def test_either_base_or_contribution_failure_rejects_publication(self):
        for rejected in (HEAD, BASE):
            with self.subTest(rejected=rejected):
                self.assertEqual(
                    EVENT.check_event(
                        {
                            "HISTORY_EVENT": "pull_request",
                            "HISTORY_PR_HEAD": HEAD,
                            "HISTORY_PR_BASE": BASE,
                        },
                        lambda command, rejected=rejected, **kwargs: SimpleNamespace(
                            returncode=int(command[-1] == rejected)
                        ),
                    ),
                    1,
                )

    def test_push_dispatch_and_queue_keep_full_event_revision(self):
        for event in ("push", "workflow_dispatch", "merge_group"):
            with self.subTest(event=event):
                self.assertEqual(
                    EVENT.revisions_for_event(
                        {"HISTORY_EVENT": event, "HISTORY_REVISION": HEAD}
                    ),
                    (HEAD,),
                )

    def test_missing_base_cannot_fall_back_to_synthetic_merge(self):
        with self.assertRaisesRegex(ValueError, "Complete event commit"):
            EVENT.revisions_for_event(
                {
                    "HISTORY_EVENT": "pull_request",
                    "HISTORY_PR_HEAD": HEAD,
                    "HISTORY_REVISION": MERGE,
                }
            )

    def test_untrusted_or_incomplete_revision_is_rejected_before_execution(self):
        for revision in ("", "HEAD", "-x", "a" * 39, "a" * 41, HEAD + "\n"):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "Complete event commit"):
                    EVENT.revisions_for_event(
                        {"HISTORY_EVENT": "push", "HISTORY_REVISION": revision}
                    )

    def test_privileged_and_unknown_events_fail_closed(self):
        for event in ("", "pull_request_target", "issue_comment"):
            with self.subTest(event=event):
                with self.assertRaisesRegex(ValueError, "Unsupported event"):
                    EVENT.revisions_for_event(
                        {"HISTORY_EVENT": event, "HISTORY_REVISION": HEAD}
                    )


if __name__ == "__main__":
    unittest.main()
