"""Build/import the private activity container natively with runtime I/O disabled."""

import importlib.util
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "bridge_container", ROOT / "scripts/test-bridge-container.py"
)
container = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(container)


def main():
    if platform.machine() not in {"x86_64", "AMD64"}:
        raise RuntimeError("Run the activity smoke test on a native AMD64 host")
    image = "ruview-assumed-activity:ci"
    container.run(
        "docker",
        "build",
        "--platform=linux/amd64",
        "-f",
        "assumed_activity/Dockerfile",
        "-t",
        image,
        ".",
    )
    container.run(
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
        "import importlib.metadata, os, platform; "
        "from assumed_activity import service; "
        "from ruview_home_assistant.ruview_http import decode_http_body; "
        "import ruview_http; "
        "assert os.getuid() == 10001; "
        "assert platform.machine() == 'x86_64'; "
        "assert service.decode_http_body is decode_http_body; "
        "assert ruview_http.decode_http_body is decode_http_body; "
        "print('Private activity service uses public HTTP decoder ' + "
        "importlib.metadata.version('ruview-home-assistant'))",
    )
    print("Native AMD64 activity container smoke test passed")


if __name__ == "__main__":
    main()
