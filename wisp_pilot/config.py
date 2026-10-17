"""Explicit, independently pinned private receiver allowlists for a Wisp pilot."""

import ipaddress
import re
from dataclasses import dataclass

from scripts.site_context import load_pinned_json

SCHEMA = "wisp.pilot-config.v1"
MAX_CONFIG_BYTES = 65536
MAX_CAPTURE_BYTES = 1024**3
MAX_RECORDS = 1_000_000


@dataclass(frozen=True)
class Config:
    raw: bytes
    sha256: str
    document: dict

    @property
    def receivers(self):
        return {r["ip"]: r["mac"] for r in self.document["receivers"]}


def _ipv4(value):
    if not isinstance(value, str):
        raise ValueError("IPv4 values must be strings")
    address = ipaddress.IPv4Address(value)
    if address.is_multicast or address.is_unspecified or value == "255.255.255.255":
        raise ValueError("An explicit unicast IPv4 address is required")
    return value


def validate(document):
    """Validate an explicit allowlist; no discovery or installation defaults."""
    fields = {
        "schema",
        "bind_ip",
        "source_port",
        "streams",
        "receivers",
        "max_records",
        "max_bytes",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError("Unexpected pilot profile fields")
    if document["schema"] != SCHEMA:
        raise ValueError("Unsupported pilot profile schema")
    _ipv4(document["bind_ip"])
    if type(document["source_port"]) is not int or document["source_port"] != 47010:
        raise ValueError("Wisp source_port must be 47010")
    if type(document["streams"]) is not int or document["streams"] != 3:
        raise ValueError("Both raw CSI and link reports (streams=3) are required")
    for name, lower, upper in (
        ("max_records", 1, MAX_RECORDS),
        ("max_bytes", 1024, MAX_CAPTURE_BYTES),
    ):
        if type(document[name]) is not int or not lower <= document[name] <= upper:
            raise ValueError(f"{name} must be an integer in {lower}..{upper}")
    receivers = document["receivers"]
    if not isinstance(receivers, list) or not 1 <= len(receivers) <= 16:
        raise ValueError("An explicit allowlist of 1..16 receivers is required")
    ips, macs = set(), set()
    for receiver in receivers:
        if not isinstance(receiver, dict) or set(receiver) != {"ip", "mac"}:
            raise ValueError("Each receiver requires only ip and mac")
        address = _ipv4(receiver["ip"])
        mac = receiver["mac"]
        if not isinstance(mac, str) or not re.fullmatch(
            r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac
        ):
            raise ValueError(
                "Receiver MAC must be lowercase colon-separated hexadecimal"
            )
        if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
            raise ValueError("Receiver MAC must be a nonzero unicast address")
        if address in ips or mac in macs:
            raise ValueError("Duplicate receiver IP or MAC")
        ips.add(address)
        macs.add(mac)
    return document


def load_config(path, expected_sha256):
    raw, document = load_pinned_json(path, expected_sha256, limit=MAX_CONFIG_BYTES)
    return Config(raw, expected_sha256, validate(document))
