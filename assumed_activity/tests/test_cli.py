"""The documented help command must never launch a configured service."""

import contextlib
import io
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from assumed_activity import service


class ActivityCliTests(unittest.TestCase):
    def test_help_and_invalid_arguments_do_not_start_runtime(self):
        for arguments, status in ((["--help"], 0), (["--unknown-option"], 2)):
            with (
                self.subTest(arguments=arguments),
                patch.object(service, "main") as runtime,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as exit_result,
            ):
                service.cli(arguments)
            self.assertEqual(exit_result.exception.code, status)
            runtime.assert_not_called()

    def test_no_arguments_preserve_runtime_entrypoint(self):
        with patch.object(service, "main") as runtime:
            service.cli([])
        runtime.assert_called_once_with()

    def test_module_help_works_without_installation_configuration(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("ASSUMED_ACTIVITY_", "RUVIEW_", "MQTT_"))
        }
        result = subprocess.run(
            [sys.executable, "-m", "assumed_activity", "--help"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ASSUMED_ACTIVITY_", result.stdout)
        self.assertIn("docs/interfaces.md", result.stdout)


if __name__ == "__main__":
    unittest.main()
