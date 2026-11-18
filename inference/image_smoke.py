"""Offline container acceptance: pinned runtime, CLI imports, synthetic suite."""

import importlib.util
import json
import os
import platform
import subprocess
import sys
import sysconfig
import unittest
from pathlib import Path


def locked_numpy_version():
    lock = Path(__file__).with_name("requirements-image.txt")
    (pin,) = (
        line.split()[0]
        for line in lock.read_text().splitlines()
        if line.startswith("numpy==")
    )
    return pin.removeprefix("numpy==")


def has_checked_hash_caches(source):
    for optimization in ("", "1"):
        cache = Path(
            importlib.util.cache_from_source(str(source), optimization=optimization)
        )
        if not cache.is_file():
            return False
        with cache.open("rb") as stream:
            if stream.read(8) != importlib.util.MAGIC_NUMBER + b"\x03\x00\x00\x00":
                return False
    return True


def main():
    import numpy

    from scripts import reference_clock

    checks = {
        "base_python_version": platform.python_version()
        == os.environ.get("PYTHON_VERSION"),
        "linux_amd64": platform.system() == "Linux" and platform.machine() == "x86_64",
        "nonroot": os.getuid() != 0 and os.getgid() != 0,
        "locked_numpy_version": numpy.__version__ == locked_numpy_version(),
        "stdlib_checked_hash_caches": has_checked_hash_caches(
            Path(sysconfig.get_path("stdlib")) / "json" / "__init__.py"
        ),
        "inference_checked_hash_caches": has_checked_hash_caches(
            Path(__file__).with_name("__init__.py")
        ),
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
