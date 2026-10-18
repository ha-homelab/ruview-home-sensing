"""Verify installed, hash-pinned public code through the compatibility facade."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Isolated mode ignores PYTHONPATH/user-site. The sole explicit source path is
# this compatibility facade; the public package must resolve from installed metadata.
PROBE = r"""
import gzip
import importlib.metadata
import json
import re
import sys
from pathlib import Path

def offline(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise RuntimeError("Network access forbidden in installed adapter check")

sys.addaudithook(offline)
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
sys.dont_write_bytecode = True
import bridge
import module_observations
import ruview_http
from ruview_home_assistant import bridge as public_bridge
from ruview_home_assistant import module_observations as public_modules
from ruview_home_assistant import ruview_http as public_http
import paho.mqtt.client
from websockets.sync.client import connect
from assumed_activity import service

pin = (root / "requirements-public.txt").read_text()
version = re.search(r"/ruview_home_assistant-([^/]+)-py3-none-any.whl", pin)[1]
expected_hash = re.search(r"--hash=sha256:([a-f0-9]{64})", pin)[1]
dist = importlib.metadata.distribution("ruview-home-assistant")
assert dist.version == version, (dist.version, version)
provenance = json.loads(dist.read_text("direct_url.json"))
assert provenance["archive_info"]["hashes"]["sha256"] == expected_hash
for private, public, filename in (
    (bridge, public_bridge, "bridge.py"),
    (module_observations, public_modules, "module_observations.py"),
    (ruview_http, public_http, "ruview_http.py"),
):
    assert private is public
    actual = Path(public.__file__).resolve()
    expected = Path(dist.locate_file("ruview_home_assistant/" + filename)).resolve()
    assert actual == expected, (actual, expected)
    assert actual != root / filename, actual
assert service.decode_http_body is public_http.decode_http_body
assert callable(connect)
raw = b'{"synthetic":true}'
assert ruview_http.decode_http_body(gzip.compress(raw), "gzip", 64) == raw
websocket = "ws://127.0.0.1:3001/ws/sensing"
config = bridge.Config.from_env({"RUVIEW_WS_URL": websocket})
assert config.websocket_url == "ws://127.0.0.1:3001/ws/sensing"
assert config.topic_prefix == "ruview/home"
assert bridge.observations({}, {}, {}, 1000) == {}
assert bridge.MAX_AGE_MS == 10000
assert bridge.MODULE_POLL_SECONDS == 0.5
print("Installed public adapter " + dist.version + ": hashes, facades and offline imports verified")
"""


def main():
    subprocess.run([sys.executable, "-I", "-c", PROBE, str(ROOT)], check=True)


if __name__ == "__main__":
    main()
