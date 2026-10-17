import base64
import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "provision_secret", ROOT / "scripts" / "provision-secret.py"
)
provision = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provision)


class ProvisionSecretTests(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "RUVIEW_API_TOKEN": "fixture-api-token",
            "MQTT_USERNAME": "fixture-mqtt-user",
            "MQTT_PASSWORD": "fixture-mqtt-password",
        }
        self.run = Mock(return_value=SimpleNamespace(stdout="{}"))
        self.random = Mock(return_value="fixture-new-signing-seed")
        self.enterContext(
            patch.object(provision, "os", SimpleNamespace(environ=self.environment))
        )
        self.enterContext(patch.object(provision.subprocess, "run", self.run))
        self.enterContext(patch.object(provision.secrets, "token_hex", self.random))

    def payload(self):
        return json.loads(self.run.call_args_list[-1].kwargs["input"])

    def prior_seed(self, value):
        self.run.return_value.stdout = json.dumps(
            {
                "data": {
                    "WDP_RUFIELD_SIGNING_SEED": base64.b64encode(
                        value.encode()
                    ).decode()
                }
            }
        )

    def test_missing_or_unsafe_context_has_no_side_effects(self):
        forbidden = Mock()
        forbidden.get.side_effect = AssertionError(
            "credentials read before context validation"
        )
        with patch.object(provision, "os", SimpleNamespace(environ=forbidden)):
            for argv in (
                [],
                ["--context", ""],
                ["--context=-other-context"],
                ["--context", "two names"],
                ["--context", "name\nnext"],
                ["--context", "name\x00"],
                ["--context", "name\x7f"],
                ["--context", "a" * 257],
            ):
                with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        provision.main(argv)
                    self.assertEqual(error.exception.code, 2)
        forbidden.get.assert_not_called()
        self.run.assert_not_called()
        self.random.assert_not_called()

    def test_explicit_context_binds_read_and_apply_with_stdin_only_credentials(self):
        context = "fixture-user@fixture-cluster:region/primary"
        provision.main(["--context", context])
        self.assertEqual(self.run.call_count, 2)
        read, write = self.run.call_args_list
        self.assertEqual(
            read.args[0],
            [
                "kubectl",
                "--context",
                context,
                "-n",
                "ruview",
                "get",
                "secret",
                "ruview-secrets",
                "-o",
                "json",
                "--ignore-not-found",
            ],
        )
        self.assertEqual(
            read.kwargs, {"capture_output": True, "text": True, "check": True}
        )
        self.assertEqual(
            write.args[0],
            [
                "kubectl",
                "--context",
                context,
                "apply",
                "--server-side",
                "--field-manager=ruview-secrets",
                "-f",
                "-",
            ],
        )
        self.assertTrue(write.kwargs["check"])
        self.assertTrue(write.kwargs["text"])
        self.assertEqual(
            self.payload(),
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "type": "Opaque",
                "metadata": {"namespace": "ruview", "name": "ruview-secrets"},
                "stringData": {
                    **self.environment,
                    "WDP_RUFIELD_SIGNING_SEED": "fixture-new-signing-seed",
                },
            },
        )
        for value in self.environment.values():
            self.assertNotIn(value, str(read.args))
            self.assertNotIn(value, str(write.args))

    def test_existing_signing_seed_is_preserved(self):
        self.prior_seed("fixture-existing-seed")
        provision.main(["--context", "fixture-cluster"])
        self.assertEqual(
            self.payload()["stringData"]["WDP_RUFIELD_SIGNING_SEED"],
            "fixture-existing-seed",
        )
        self.random.assert_not_called()

    def test_explicit_signing_seed_override_is_preserved(self):
        self.prior_seed("fixture-existing-seed")
        self.environment["WDP_RUFIELD_SIGNING_SEED"] = "fixture-explicit-seed"
        provision.main(["--context", "fixture-cluster"])
        self.assertEqual(
            self.payload()["stringData"]["WDP_RUFIELD_SIGNING_SEED"],
            "fixture-explicit-seed",
        )
        self.random.assert_not_called()

    def test_missing_seed_is_generated_once(self):
        provision.main(["--context", "fixture-cluster"])
        self.random.assert_called_once_with(32)

    def test_missing_credentials_prevent_kubectl_and_seed_generation(self):
        del self.environment["MQTT_PASSWORD"]
        with self.assertRaisesRegex(
            SystemExit, "Missing environment variables: MQTT_PASSWORD"
        ):
            provision.main(["--context", "fixture-cluster"])
        self.run.assert_not_called()
        self.random.assert_not_called()

    def test_failed_secret_read_cannot_apply_or_rotate(self):
        self.run.side_effect = subprocess.CalledProcessError(1, "fixture-kubectl")
        with self.assertRaises(subprocess.CalledProcessError):
            provision.main(["--context", "fixture-cluster"])
        self.assertEqual(self.run.call_count, 1)
        self.random.assert_not_called()

    def test_failed_apply_is_not_retried(self):
        self.run.side_effect = [
            SimpleNamespace(stdout="{}"),
            subprocess.CalledProcessError(1, "fixture-kubectl"),
        ]
        with self.assertRaises(subprocess.CalledProcessError):
            provision.main(["--context", "fixture-cluster"])
        self.assertEqual(self.run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
