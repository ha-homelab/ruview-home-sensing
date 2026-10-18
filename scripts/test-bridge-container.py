"""Build and smoke-test the bridge on native ARM64, without device/network I/O."""

import json
import platform
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def verify_image(image, architecture):
    manifest = json.loads(
        run("docker", "buildx", "imagetools", "inspect", "--raw", image)
    )
    if "manifests" in manifest or "layers" not in manifest:
        raise ValueError(f"{architecture} must pin an image manifest, not an index")
    run("docker", "pull", f"--platform=linux/{architecture}", image)
    actual = run("docker", "image", "inspect", "--format", "{{.Architecture}}", image)
    if actual != architecture:
        raise ValueError(f"Expected {architecture}, got {actual}")


def main():
    if platform.machine() not in {"aarch64", "arm64"}:
        raise RuntimeError("Run the container smoke test on a native ARM64 host")
    dockerfile = (ROOT / "Dockerfile").read_text()
    dependency = re.search(r"^ARG DEPENDENCY_IMAGE=(\S+)$", dockerfile, re.M).group(1)
    runtime = re.search(r"^FROM --platform=linux/arm64 (\S+)$", dockerfile, re.M).group(
        1
    )
    if dependency == runtime:
        raise ValueError(
            "Legacy cross-build stages need distinct architecture manifests"
        )
    verify_image(dependency, "amd64")
    verify_image(runtime, "arm64")
    version = re.fullmatch(r"python:(\d+\.\d+)-alpine@sha256:[0-9a-f]{64}", runtime)
    if not version or dependency.split("@", 1)[0] != runtime.split("@", 1)[0]:
        raise ValueError("Build and runtime Python versions must match")
    expected_version = tuple(map(int, version.group(1).split(".")))
    image = "ruview-bridge:ci"
    # Only universal, hash-checked wheels are installed. Override the legacy
    # AMD64 dependency stage to use the exact runtime image on this ARM host.
    run(
        "docker",
        "build",
        "--platform=linux/arm64",
        "--build-arg",
        "DEPENDENCY_PLATFORM=linux/arm64",
        "--build-arg",
        f"DEPENDENCY_IMAGE={runtime}",
        "-t",
        image,
        ".",
    )
    run(
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--entrypoint=python",
        image,
        "-c",
        "import os, platform, sys; "
        "import bridge, module_observations, ruview_http; "
        "from ruview_home_assistant import bridge as public_bridge; "
        "from ruview_home_assistant import module_observations as public_modules; "
        "from ruview_home_assistant import ruview_http as public_http; "
        "assert bridge is public_bridge; "
        "assert module_observations is public_modules; "
        "assert ruview_http is public_http; "
        "import paho.mqtt.client as mqtt; "
        "from websockets.sync.client import connect; "
        f"assert sys.version_info[:2] == {expected_version!r}; "
        "assert platform.machine() == 'aarch64'; "
        "assert os.getuid() == 10001; "
        "assert callable(connect); "
        "mqtt.Client(mqtt.CallbackAPIVersion.VERSION2); "
        "print('ARM64 bridge and runtime dependencies loaded successfully')",
    )
    print("Native ARM64 container smoke test passed")


if __name__ == "__main__":
    main()
