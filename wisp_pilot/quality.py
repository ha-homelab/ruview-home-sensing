"""Pure, replayable transport diagnostics, never an occupancy classifier."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field

from .protocol import MAX_LINKS, MAX_PAIRS, normalize_mac

_STREAMS = ("raw_csi", "link_report")
_MASK = (1 << 32) - 1
_HALF = 1 << 31


def _integer(value, name: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or maximum is not None and value > maximum:
        raise ValueError(f"invalid_{name}")
    return value


def _delta(new: int, old: int) -> int:
    return (new - old) & _MASK


@dataclass
class _Stream:
    sequence: int | None = None
    last_ns: int | None = None
    uptime_s: int | None = None
    candidate: tuple[int, int, int] | None = None
    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    out_of_order: int = 0
    gap_events: int = 0
    discontinuities: int = 0
    restart_candidates: int = 0
    possible_restarts: int = 0
    first_word_invalid: int = 0
    channel_changes: int = 0
    channel: int | None = None


@dataclass
class _Receiver:
    streams: dict[str, _Stream] = field(
        default_factory=lambda: {name: _Stream() for name in _STREAMS}
    )
    links: dict = field(default_factory=dict)
    confirmed_pairs: list = field(default_factory=list)
    pairs_truncated: bool = False


class QualityObserver:
    """Observe decoded packets with separate raw/report sequence domains.

    Only forward sequence progress refreshes a stream. A stream that has never
    progressed is unknown; elapsed receipt freshness is unavailable. A report
    with lower uptime is quarantined. After staleness, two progressing lower-
    uptime reports allow a *possible* restart and invalidate the old raw epoch.
    UDP cannot distinguish every delayed/replayed sequence from a true reboot;
    these counters describe discontinuities, not measured packet loss or boots.
    """

    def __init__(
        self, expected_receivers: list[str], freshness_ns: int = 3_000_000_000
    ):
        _integer(freshness_ns, "freshness_ns")
        if not freshness_ns:
            raise ValueError("invalid_freshness_ns")
        if (
            not isinstance(expected_receivers, list)
            or not 1 <= len(expected_receivers) <= 64
        ):
            raise ValueError("invalid_expected_receivers")
        names = [normalize_mac(name) for name in expected_receivers]
        if len(set(names)) != len(names):
            raise ValueError("duplicate_expected_receiver")
        self.freshness_ns = freshness_ns
        self._receivers = {name: _Receiver() for name in names}
        self._last_event_ns: int | None = None
        self._received = 0
        self._accepted = 0
        self._unexpected = 0

    def ingest(self, packet: dict, received_monotonic_ns: int) -> None:
        """Accept parse_packet output; invalid identities/clocks/bounds raise.

        Complete wire semantics are validated by parse_packet, not reconstructed
        here. No upstream motion or confirmation flag is independently verified.
        """
        now = _integer(received_monotonic_ns, "received_monotonic_ns")
        if self._last_event_ns is not None and now < self._last_event_ns:
            raise ValueError("monotonic_clock_reversed")
        if not isinstance(packet, dict) or packet.get("packet_type") not in _STREAMS:
            raise ValueError("invalid_packet_type")
        name = normalize_mac(packet.get("receiver_mac"))
        sequence = _integer(packet.get("sequence"), "sequence", _MASK)
        kind = packet["packet_type"]
        if kind == "link_report":
            uptime = _integer(packet.get("uptime_s"), "uptime_s", _MASK)
            if not isinstance(packet.get("links"), list) or not isinstance(
                packet.get("confirmed_pairs"), list
            ):
                raise ValueError("invalid_report")
            if (
                len(packet["links"]) > MAX_LINKS
                or len(packet["confirmed_pairs"]) > MAX_PAIRS
            ):
                raise ValueError("invalid_report_bounds")
        else:
            uptime = None
            if not _integer(packet.get("channel"), "channel", 14):
                raise ValueError("invalid_channel")
        self._last_event_ns = now
        self._received += 1
        if name not in self._receivers:
            self._unexpected += 1
            return
        receiver = self._receivers[name]
        stream = receiver.streams[kind]
        stream.received += 1
        restarted = False
        if stream.sequence is not None:
            delta = _delta(sequence, stream.sequence)
            uptime_regressed = (
                uptime is not None
                and stream.uptime_s is not None
                and _delta(uptime, stream.uptime_s) >= _HALF
            )
            if uptime_regressed:
                restarted = self._consider_restart(stream, sequence, uptime, now)
                if not restarted:
                    stream.out_of_order += 1
                    return
            elif delta == 0:
                stream.duplicates += 1
                return
            elif delta >= _HALF:
                stream.out_of_order += 1
                return
            elif delta > 1:
                stream.gap_events += 1
                stream.discontinuities += 1
        if restarted:
            raw = receiver.streams["raw_csi"]
            raw.sequence = None
            raw.last_ns = None
            raw.channel = None
            raw.discontinuities += 1
        stream.candidate = None
        stream.sequence, stream.last_ns, stream.uptime_s = sequence, now, uptime
        stream.accepted += 1
        self._accepted += 1
        if kind == "raw_csi":
            channel = packet["channel"]
            if stream.channel is not None and channel != stream.channel:
                stream.channel_changes += 1
                stream.discontinuities += 1
            stream.channel = channel
            stream.first_word_invalid += int(bool(packet.get("first_word_invalid")))
        else:
            # Retain only the current bounded link report, not unbounded MAC history.
            receiver.links = {
                link["transmitter_mac"]: deepcopy(link) for link in packet["links"]
            }
            receiver.confirmed_pairs = deepcopy(packet["confirmed_pairs"])
            receiver.pairs_truncated = bool(packet["pairs_truncated"])

    def _consider_restart(
        self, stream: _Stream, sequence: int, uptime: int, now: int
    ) -> bool:
        if stream.last_ns is None or now - stream.last_ns <= self.freshness_ns:
            return False
        previous = stream.candidate
        stream.candidate = (sequence, uptime, now)
        stream.restart_candidates += 1
        if previous is None:
            return False
        previous_sequence, previous_uptime, previous_ns = previous
        delta = _delta(sequence, previous_sequence)
        if (
            now <= previous_ns
            or now - previous_ns > self.freshness_ns
            or not 0 < delta < _HALF
            or not 0
            <= uptime - previous_uptime
            <= (now - previous_ns) // 1_000_000_000 + 2
        ):
            return False
        stream.possible_restarts += 1
        stream.discontinuities += 1
        return True

    def _state(self, stream: _Stream, now: int) -> tuple[str, int | None]:
        if stream.last_ns is None:
            return "unknown", None
        age = now - stream.last_ns
        return ("fresh" if age <= self.freshness_ns else "unavailable"), age

    def snapshot(self, now_ns: int) -> dict:
        """Return detached JSON-safe diagnostics at a caller-supplied monotonic time."""
        now = _integer(now_ns, "now_ns")
        if self._last_event_ns is not None and now < self._last_event_ns:
            raise ValueError("snapshot_precedes_latest_packet")
        receivers = {}
        for name, receiver in self._receivers.items():
            streams = {}
            for kind, stream in receiver.streams.items():
                state, age = self._state(stream, now)
                streams[kind] = {
                    "state": state,
                    "age_ns": age,
                    "last_sequence": stream.sequence,
                    "received": stream.received,
                    "accepted": stream.accepted,
                    "duplicates": stream.duplicates,
                    "out_of_order": stream.out_of_order,
                    "gap_events": stream.gap_events,
                    "discontinuities": stream.discontinuities,
                    "restart_candidates": stream.restart_candidates,
                    "possible_restarts": stream.possible_restarts,
                    "first_word_invalid": stream.first_word_invalid,
                    "channel_changes": stream.channel_changes,
                }
            ages = [
                item["age_ns"]
                for item in streams.values()
                if item["age_ns"] is not None
            ]
            receiver_state = (
                "unknown"
                if not ages
                else "fresh"
                if min(ages) <= self.freshness_ns
                else "unavailable"
            )
            report_state = streams["link_report"]["state"]
            links = {}
            for transmitter, link in receiver.links.items():
                link_state = report_state
                if report_state == "fresh" and (
                    link["frames"] == 0
                    or link["motion_score"] is None
                    or link["spread_percent"] is None
                ):
                    link_state = "unknown"
                links[transmitter] = {
                    "state": link_state,
                    "report_age_ns": streams["link_report"]["age_ns"],
                    "kind": link["kind"],
                    "frames": link["frames"],
                    "motion_score": link["motion_score"],
                    "rssi_dbm": link["rssi_dbm"],
                    "spread_percent": link["spread_percent"],
                    "reported_motion": link["motion"],
                    "reported_confirmed_motion": link["confirmed_motion"],
                    "reported_breathing": link["breathing"],
                }
            receivers[name] = {
                "state": receiver_state,
                "age_ns": min(ages) if ages else None,
                "streams": streams,
                "links": links,
                "reported_confirmed_pairs": deepcopy(receiver.confirmed_pairs),
                "pairs_truncated": receiver.pairs_truncated,
            }
        return {
            "schema_version": 1,
            "diagnostic_only": True,
            "freshness_ns": self.freshness_ns,
            "expected_receivers": len(receivers),
            "received_packets": self._received,
            "accepted_packets": self._accepted,
            "rejected_packets": self._received - self._accepted,
            "unexpected_receiver_packets": self._unexpected,
            "receivers": receivers,
        }
