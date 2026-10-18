"""Fictional collector profile, independently selected from receiver fixtures."""

import hashlib
import json
from pathlib import Path

from scripts.collector_profile import validate_profile

VALUE = {
    "schema": "ruview.collector-profile.v1",
    "http_origin": "http://10.77.1.9:3000",
    "websocket_url": "ws://10.77.1.9:3001/ws/sensing",
}
COLLECTOR = validate_profile(VALUE)


def profile_arguments(directory):
    path = Path(directory).resolve() / "collector-profile.json"
    raw = (json.dumps(VALUE, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return [
        "--collector-profile",
        str(path),
        "--collector-profile-sha256",
        hashlib.sha256(raw).hexdigest(),
    ]
