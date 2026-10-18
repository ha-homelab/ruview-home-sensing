"""Validate collector endpoints read by the existing pinned private-file loader."""

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from .site_context import load_pinned_json
else:
    from site_context import load_pinned_json


@dataclass(frozen=True)
class CollectorProfile:
    http_origin: str
    websocket_url: str


def validate_profile(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "http_origin", "websocket_url"}
        or value["schema"] != "ruview.collector-profile.v1"
    ):
        raise ValueError("invalid_collector_profile")
    parsed = []
    for key in ("http_origin", "websocket_url"):
        text = value[key]
        if (
            not isinstance(text, str)
            or not 1 <= len(text) <= 1024
            or any(ord(c) <= 32 or ord(c) >= 127 for c in text)
        ):
            raise ValueError("invalid_collector_endpoint")
        url = urlsplit(text)
        if (
            url.username is not None
            or url.password is not None
            or not url.hostname
            or not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", url.hostname)
            or url.port is None
            or not 1 <= url.port <= 65535
            or url.query
            or url.fragment
            or "?" in text
            or "#" in text
            or url.geturl() != text
        ):
            raise ValueError("invalid_collector_endpoint")
        parsed.append(url)
    http, websocket = parsed
    if (
        (http.scheme, websocket.scheme) not in (("http", "ws"), ("https", "wss"))
        or http.path != ""
        or websocket.path != "/ws/sensing"
        or http.hostname != websocket.hostname
    ):
        raise ValueError("inconsistent_collector_endpoints")
    return CollectorProfile(value["http_origin"], value["websocket_url"])


def load_profile(path, expected_sha256):
    _, value = load_pinned_json(path, expected_sha256, 4096)
    return validate_profile(value)


def add_profile_arguments(parser):
    parser.add_argument("--collector-profile", type=Path, required=True)
    parser.add_argument("--collector-profile-sha256", required=True)
