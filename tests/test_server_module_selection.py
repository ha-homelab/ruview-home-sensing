"""Observer release selection stays explicit; no service calls."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "strict_worker_verifier",
    Path(__file__).resolve().parents[1] / "scripts/verify-server-modules.py",
)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class SelectionTests(unittest.TestCase):
    def test_only_exact_explicit_selection_matches(self):
        for selected in (20, 21):
            value = {"catalog_count": 64, "selected_algorithm_count": selected}
            verifier.validate_catalog(value, selected)
            with self.assertRaisesRegex(verifier.VerificationError, "Wrong adapters"):
                verifier.validate_catalog(value, 41 - selected)
        for field, bad in (
            ("catalog_count", 63),
            ("catalog_count", 64.0),
            ("selected_algorithm_count", True),
            ("selected_algorithm_count", 21.0),
        ):
            value = {"catalog_count": 64, "selected_algorithm_count": 21, field: bad}
            with self.subTest(field=field, value=bad), self.assertRaises(ValueError):
                verifier.validate_catalog(value, 21)
        for bad in (True, 0, 22):
            with self.subTest(expected=bad), self.assertRaises(ValueError):
                verifier.validate_catalog({}, bad)


if __name__ == "__main__":
    unittest.main()
