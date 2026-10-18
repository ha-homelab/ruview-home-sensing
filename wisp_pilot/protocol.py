"""Strict, bounded Wisp v1 decoder for the raw/link diagnostic pilot.

Wire contract: albert-canfield/wisp 56813ac, docs/PROTOCOL.md and
firmware/components/wisp/core_{raw_packet,links,csi_record}.h. This independent
implementation deliberately rejects extensions rather than guessing semantics.
Motion, confirmation and breathing bits are upstream firmware assertions. This
decoder does not independently verify a person or physical corroboration.
"""

from __future__ import annotations

import re
import struct

MAX_DATAGRAM_BYTES = 4096
MAX_CSI_BYTES = 384
MAX_LINKS = 20
MAX_PAIRS = 16
_HEADER = struct.Struct("<4sBBH")
_RAW = struct.Struct("<I6s6sIbbBBBBBBH")
_REPORT = struct.Struct("<I6sBBI")
_LINK = struct.Struct("<6sBbHHBB")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")


class ProtocolError(ValueError):
    """Malformed, unsupported, or ambiguous pilot datagram."""


def normalize_mac(value: str) -> str:
    """Canonical nonzero unicast address, including locally administered MACs."""
    if not isinstance(value, str) or _MAC.fullmatch(value) is None:
        raise ProtocolError("invalid_mac")
    raw = bytes.fromhex(value.replace(":", ""))
    if raw == bytes(6) or raw[0] & 1:
        raise ProtocolError("invalid_mac")
    return raw.hex(":")


def _mac(raw: bytes) -> str:
    return normalize_mac(raw.hex(":"))


def subscribe_packet(streams: int = 3) -> bytes:
    """Request only raw CSI/link reports; caller must renew the 10 s lease."""
    if type(streams) is not int or streams not in (1, 2, 3):
        raise ProtocolError("unsupported_streams")
    return b"WSUB\x01" + bytes((streams,))


def parse_packet(data: bytes) -> dict:
    """Decode exactly one supported datagram; retain all signed CSI samples."""
    if not isinstance(data, bytes):
        raise ProtocolError("packet_must_be_bytes")
    if not _HEADER.size <= len(data) <= MAX_DATAGRAM_BYTES:
        raise ProtocolError("invalid_datagram_size")
    magic, version, packet_type, header_len = _HEADER.unpack_from(data)
    if magic != b"WISP":
        raise ProtocolError("invalid_magic")
    if version != 1:
        raise ProtocolError("unsupported_version")
    if packet_type not in (1, 2):
        raise ProtocolError("unsupported_packet_type")
    expected_header = 38 if packet_type == 1 else 24
    if header_len != expected_header:
        raise ProtocolError("unsupported_header_length")
    if len(data) < header_len:
        raise ProtocolError("truncated_header")
    return _raw(data) if packet_type == 1 else _report(data)


def _raw(data: bytes) -> dict:
    (
        sequence,
        receiver,
        transmitter,
        timestamp,
        rssi,
        noise,
        channel,
        secondary,
        signal_mode,
        mcs,
        bandwidth,
        flags,
        count,
    ) = _RAW.unpack_from(data, 8)
    if count < 2 or count > MAX_CSI_BYTES or count % 2 or len(data) != 38 + count:
        raise ProtocolError("invalid_csi_length")
    if not 1 <= channel <= 14 or secondary not in (0, 1, 2):
        raise ProtocolError("unsupported_channel")
    if signal_mode not in (0, 1, 3) or bandwidth not in (0, 1) or flags & ~7:
        raise ProtocolError("unsupported_radio_metadata")
    receiver_mac, transmitter_mac = _mac(receiver), _mac(transmitter)
    if receiver_mac == transmitter_mac:
        raise ProtocolError("self_link")
    return {
        "packet_type": "raw_csi",
        "sequence": sequence,
        "receiver_mac": receiver_mac,
        "transmitter_mac": transmitter_mac,
        "device_timestamp_us": timestamp,
        "rssi_dbm": rssi,
        "noise_floor_dbm": noise,
        "channel": channel,
        "secondary_channel": secondary,
        "signal_mode": signal_mode,
        "mcs": mcs,
        "bandwidth": bandwidth,
        "flags": flags,
        "first_word_invalid": bool(flags & 2),
        "iq": [byte if byte < 128 else byte - 256 for byte in data[38:]],
        "iq_order": "imaginary_real",
    }


def _report(data: bytes) -> dict:
    sequence, receiver, count, flags, uptime = _REPORT.unpack_from(data, 8)
    receiver_mac = _mac(receiver)
    if count > MAX_LINKS:
        raise ProtocolError("too_many_links")
    if flags & ~3 or flags & 2 and not flags & 1:
        raise ProtocolError("unsupported_report_flags")
    end = 24 + count * _LINK.size
    if len(data) < end:
        raise ProtocolError("truncated_links")
    links, seen = [], set()
    for offset in range(24, end, _LINK.size):
        transmitter, kind, rssi, score, spread, frames, link_flags = _LINK.unpack_from(
            data, offset
        )
        transmitter_mac = _mac(transmitter)
        if transmitter_mac == receiver_mac:
            raise ProtocolError("self_link")
        if transmitter_mac in seen:
            raise ProtocolError("duplicate_link")
        seen.add(transmitter_mac)
        if kind not in (0, 1) or link_flags & ~7:
            raise ProtocolError("unsupported_link_metadata")
        if (rssi == -128) != (frames == 0):
            raise ProtocolError("inconsistent_rssi_sentinel")
        if link_flags & 2 and (not flags & 1 or not link_flags & 1):
            raise ProtocolError("inconsistent_confirmation")
        if link_flags & 4 and link_flags & 1:
            raise ProtocolError("inconsistent_breathing")
        if score == 65535 and link_flags & 1:
            raise ProtocolError("unknown_motion_score")
        links.append(
            {
                "transmitter_mac": transmitter_mac,
                "kind": "ap" if kind == 0 else "node",
                "rssi_dbm": None if rssi == -128 else rssi,
                "motion_score": None if score == 65535 else score / 100,
                # The pinned encoder uses the same NaN sentinel for both.
                "spread_percent": None if spread == 65535 else spread / 100,
                "frames": frames,
                "motion": bool(link_flags & 1),
                "confirmed_motion": bool(link_flags & 2),
                "breathing": bool(link_flags & 4),
            }
        )
    pairs = []
    if flags & 1:
        if len(data) <= end:
            raise ProtocolError("missing_pair_count")
        pair_count = data[end]
        if pair_count > MAX_PAIRS:
            raise ProtocolError("too_many_pairs")
        if len(data) != end + 1 + pair_count * 12:
            raise ProtocolError("invalid_pairs_length")
        seen_pairs = set()
        for offset in range(end + 1, len(data), 12):
            a, b = _mac(data[offset : offset + 6]), _mac(data[offset + 6 : offset + 12])
            if a >= b or (a, b) in seen_pairs:
                raise ProtocolError("unordered_or_duplicate_pair")
            seen_pairs.add((a, b))
            pairs.append([a, b])
    elif len(data) != end:
        raise ProtocolError("unexpected_trailing_bytes")
    return {
        "packet_type": "link_report",
        "sequence": sequence,
        "receiver_mac": receiver_mac,
        "uptime_s": uptime,
        "flags": flags,
        "links": links,
        "confirmed_pairs": pairs,
        "pairs_truncated": bool(flags & 2),
    }
