"""Verify installed, hash-pinned public code through the compatibility facade."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Isolated mode ignores PYTHONPATH/user-site. The sole explicit source path is
# this compatibility facade; the public package must resolve from installed metadata.
PROBE = r"""
import copy
import gzip
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from unittest.mock import Mock, patch

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

# Exercise the installed implementation, including its observation-time handoff:
# slow module work must not renew CSI, inference, or snapshot freshness.
age_keys = ("csi_age_ms", "inference_age_ms", "snapshot_age_ms")
for age_key in age_keys:
    for initial_age, expected_availability in ((9900, "offline"), (100, "online")):
        clock = [100.0]
        client = Mock()
        client.publish.return_value.rc = 0
        adapter = bridge.Bridge(client, bridge.Config(node_ids=(1,)))
        adapter.last_discovery = 100.0
        adapter.rediscover.clear()
        adapter.edge_falls.ingest(
            {"type": "edge_vitals", "node_id": 1, "fall_detected": True}, 100.0
        )
        current = {
            1: {
                "presence": "ON",
                "motion": "ON",
                "classification": "present_moving",
                "signal": -60,
                **dict.fromkeys(age_keys, 0),
            }
        }
        current[1][age_key] = initial_age
        original = copy.deepcopy(current)

        def slow_modules(*args):
            clock[0] += 0.2

        adapter.update_modules = slow_modules
        with patch(
            "ruview_home_assistant.bridge.time.monotonic",
            side_effect=lambda: clock[0],
        ):
            adapter.update_observations(current, observed_at=100.0)
        messages = {call.args[0]: call.args[1] for call in client.publish.call_args_list}
        base = "ruview/home/node1/"
        for suffix in ("availability", "fall/availability"):
            assert messages[base + suffix] == expected_availability, (age_key, messages)
        assert (base + "state" in messages) == (expected_availability == "online")
        if expected_availability == "online":
            attributes = json.loads(messages[base + "attributes"])
            assert abs(attributes[age_key] - 300) < 0.001, attributes
        assert current == original, (current, original)

# An independent edge lease can expire while the primary observation stays fresh.
clock = [100.0]
client = Mock()
adapter = bridge.Bridge(client, bridge.Config(node_ids=(1,)))
adapter.last_discovery = 100.0
adapter.rediscover.clear()
adapter.edge_falls.ingest(
    {"type": "edge_vitals", "node_id": 1, "fall_detected": True}, 90.1
)
current = {
    1: {
        "presence": "ON",
        "motion": "ON",
        "classification": "present_moving",
        "signal": -60,
        **dict.fromkeys(age_keys, 0),
    }
}

def slow_publish(topic, *args, **kwargs):
    if topic == "ruview/home/node1/state":
        clock[0] += 0.2
    return Mock(rc=0)

client.publish.side_effect = slow_publish
with patch("ruview_home_assistant.bridge.time.monotonic", side_effect=lambda: clock[0]):
    adapter.update_observations(current, observed_at=100.0)
messages = {call.args[0]: call.args[1] for call in client.publish.call_args_list}
assert messages["ruview/home/node1/availability"] == "online", messages
assert messages["ruview/home/node1/fall/availability"] == "offline", messages
print(
    "Installed public adapter " + dist.version
    + ": hashes, facades, freshness and offline imports verified"
)
"""


def main():
    subprocess.run([sys.executable, "-I", "-c", PROBE, str(ROOT)], check=True)


if __name__ == "__main__":
    main()
