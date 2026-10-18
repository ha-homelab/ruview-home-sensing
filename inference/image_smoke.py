"""Offline container acceptance: pinned runtime, CLI imports, synthetic suite."""

import json
import os
import platform
import subprocess
import sys
import unittest
from pathlib import Path


def main():
    import numpy

    from scripts import reference_clock

    checks = {
        "python_3_13": sys.version_info[:2] == (3, 13),
        "linux_amd64": platform.system() == "Linux" and platform.machine() == "x86_64",
        "nonroot": os.getuid() != 0 and os.getgid() != 0,
        "numpy_2_5_3": numpy.__version__ == "2.5.3",
        "bytecode_disabled": sys.dont_write_bytecode,
        "blas_threads_bounded": all(
            os.environ.get(name) == "1"
            for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")
        ),
        "clock_helper_present": callable(reference_clock.validate_identity),
        "synthetic_fixture_present": Path(
            "server-modules/tests/fixtures/capture-v2.synthetic.json"
        ).is_file(),
    }
    if not all(checks.values()):
        print(json.dumps({"passed": False, "checks": checks}))
        return 1
    for module in (
        "inference",
        "inference.stream",
        "inference.reference_session",
        "inference.zone_annotations",
        "inference.zone_model",
        "inference.qualification",
        "inference.fall_detection",
        "inference.fall_evaluation",
    ):
        subprocess.run(
            [sys.executable, "-m", module, "--help"],
            check=True,
            timeout=60,
            stdout=subprocess.DEVNULL,
        )
    suite = unittest.defaultTestLoader.discover("inference/tests", top_level_dir=".")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    passed = result.wasSuccessful() and not result.skipped and result.testsRun > 0
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "tests_run": result.testsRun,
                "skipped": len(result.skipped),
                "scope": "synthetic offline software tests only",
                "recognition_validated": False,
                "publish_to_ha": False,
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
