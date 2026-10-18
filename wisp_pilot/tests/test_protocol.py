"""Wire fixtures are fictional; no installed receiver addresses."""

import struct
import unittest

from wisp_pilot.protocol import (
    MAX_DATAGRAM_BYTES,
    ProtocolError,
    parse_packet,
    subscribe_packet,
)

A = bytes.fromhex("020000000001")
B = bytes.fromhex("020000000002")
C = bytes.fromhex("020000000003")


def raw_packet(**overrides):
    fields = dict(
        sequence=1,
        receiver=A,
        transmitter=B,
        timestamp=9,
        rssi=-51,
        noise=-96,
        channel=6,
        secondary=0,
        mode=1,
        mcs=2,
        bandwidth=0,
        flags=2,
        iq=b"\x80\x7f\xff\x00",
    )
    fields.update(overrides)
    iq = fields.pop("iq")
    return (
        struct.pack("<4sBBH", b"WISP", 1, 1, 38)
        + struct.pack("<I6s6sIbbBBBBBBH", *fields.values(), len(iq))
        + iq
    )


def link_entry(**overrides):
    fields = dict(
        transmitter=B, kind=1, rssi=-55, score=210, spread=175, frames=8, flags=3
    )
    fields.update(overrides)
    return struct.pack("<6sBbHHBB", *fields.values())


def report_packet(sequence=1, uptime=30, links=None, flags=1, pairs=None):
    links = [link_entry()] if links is None else links
    pairs = [(A, B)] if pairs is None else pairs
    data = struct.pack(
        "<4sBBHI6sBBI", b"WISP", 1, 2, 24, sequence, A, len(links), flags, uptime
    )
    data += b"".join(links)
    if flags & 1:
        data += bytes((len(pairs),)) + b"".join(a + b for a, b in pairs)
    return data


class ProtocolTests(unittest.TestCase):
    def test_raw_signed_order_and_invalid_word_are_preserved(self):
        parsed = parse_packet(raw_packet())
        self.assertEqual(parsed["iq"], [-128, 127, -1, 0])
        self.assertEqual(parsed["iq_order"], "imaginary_real")
        self.assertTrue(parsed["first_word_invalid"])
        self.assertEqual(parsed["receiver_mac"], "02:00:00:00:00:01")
        self.assertEqual(parsed["device_timestamp_us"], 9)
        self.assertEqual(parsed["rssi_dbm"], -51)
        self.assertEqual(parsed["noise_floor_dbm"], -96)

    def test_report_scaling_pairs_and_sentinels(self):
        parsed = parse_packet(
            report_packet(links=[link_entry(rssi=-128, frames=0, score=65535, flags=0)])
        )
        link = parsed["links"][0]
        self.assertIsNone(link["rssi_dbm"])
        self.assertIsNone(link["motion_score"])
        self.assertEqual(link["spread_percent"], 1.75)
        self.assertEqual(
            parsed["confirmed_pairs"], [["02:00:00:00:00:01", "02:00:00:00:00:02"]]
        )
        self.assertFalse(parsed["pairs_truncated"])
        self.assertEqual(parse_packet(report_packet())["links"][0]["motion_score"], 2.1)

    def test_legacy_report_and_breathing_only_flag(self):
        parsed = parse_packet(report_packet(links=[link_entry(flags=4)], flags=0))
        self.assertTrue(parsed["links"][0]["breathing"])
        self.assertFalse(parsed["links"][0]["motion"])
        self.assertEqual(parsed["confirmed_pairs"], [])

    def test_initial_warmup_and_shared_nan_encoder_sentinel(self):
        # Initial LinkMotion: score NaN, zero-initialized variance gives spread 0.
        warmup = parse_packet(
            report_packet(links=[link_entry(score=65535, spread=0, flags=0)])
        )
        self.assertIsNone(warmup["links"][0]["motion_score"])
        self.assertEqual(warmup["links"][0]["spread_percent"], 0.0)
        # core_links.h to_u16_ also maps a NaN spread to 65535.
        unknown = parse_packet(
            report_packet(links=[link_entry(score=65535, spread=65535, flags=0)])
        )
        self.assertIsNone(unknown["links"][0]["spread_percent"])

    def test_no_frames_may_retain_prior_score_and_motion(self):
        # Firmware scores each second but emits intervals every 200 ms.
        parsed = parse_packet(report_packet(links=[link_entry(rssi=-128, frames=0)]))
        self.assertTrue(parsed["links"][0]["confirmed_motion"])
        self.assertEqual(parsed["links"][0]["motion_score"], 2.1)

    def test_every_truncated_prefix_and_trailing_byte_rejected(self):
        for complete in (raw_packet(), report_packet()):
            for cut in range(len(complete)):
                with (
                    self.subTest(length=len(complete), cut=cut),
                    self.assertRaises(ProtocolError),
                ):
                    parse_packet(complete[:cut])
            with self.assertRaises(ProtocolError):
                parse_packet(complete + b"\0")

    def test_header_version_kind_and_envelope_limits(self):
        raw = raw_packet()
        bad = [
            b"NOPE" + raw[4:],
            raw[:4] + b"\x02" + raw[5:],
            raw[:5] + b"\x03" + raw[6:],
            raw[:6] + struct.pack("<H", 39) + raw[8:],
            b"x" * (MAX_DATAGRAM_BYTES + 1),
            bytearray(raw),
        ]
        for packet in bad:
            with self.subTest(packet=packet[:12]), self.assertRaises(ProtocolError):
                parse_packet(packet)

    def test_raw_metadata_and_csi_bounds(self):
        for overrides in (
            {"channel": 0},
            {"channel": 15},
            {"secondary": 3},
            {"mode": 2},
            {"bandwidth": 2},
            {"flags": 8},
            {"iq": b""},
            {"iq": b"\0"},
            {"iq": bytes(386)},
            {"receiver": bytes(6)},
            {"transmitter": A},
            {"transmitter": bytes.fromhex("010000000001")},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ProtocolError):
                parse_packet(raw_packet(**overrides))
        self.assertEqual(len(parse_packet(raw_packet(iq=bytes(384)))["iq"]), 384)

    def test_link_ambiguities_are_rejected(self):
        bad = [
            report_packet(links=[link_entry(), link_entry()]),
            report_packet(links=[link_entry(transmitter=A)]),
            report_packet(links=[link_entry(kind=2)]),
            report_packet(links=[link_entry(rssi=-128)]),
            report_packet(links=[link_entry(frames=0)]),
            report_packet(links=[link_entry(flags=8)]),
            report_packet(links=[link_entry(flags=2)]),
            report_packet(links=[link_entry(flags=5)]),
            report_packet(links=[link_entry(score=65535)]),
            report_packet(flags=0),
            report_packet(flags=2),
            report_packet(flags=4),
        ]
        for packet in bad:
            with self.subTest(packet=packet), self.assertRaises(ProtocolError):
                parse_packet(packet)

    def test_pairs_and_link_count_bounded(self):
        bad = [
            report_packet(pairs=[(B, A)]),
            report_packet(pairs=[(A, A)]),
            report_packet(pairs=[(A, B), (A, B)]),
            report_packet(pairs=[(A, B)] * 17),
            report_packet(links=[link_entry()] * 21),
        ]
        for packet in bad:
            with self.subTest(packet=packet), self.assertRaises(ProtocolError):
                parse_packet(packet)
        self.assertTrue(parse_packet(report_packet(flags=3))["pairs_truncated"])
        self.assertEqual(parse_packet(report_packet(links=[], pairs=[]))["links"], [])

    def test_subscription_is_explicit_and_no_hive(self):
        self.assertEqual(subscribe_packet(), b"WSUB\x01\x03")
        for mask in (1, 2, 3):
            self.assertEqual(subscribe_packet(mask)[-1], mask)
        for mask in (0, 4, 7, 255, True, 1.0, None):
            with self.subTest(mask=mask), self.assertRaises(ProtocolError):
                subscribe_packet(mask)


if __name__ == "__main__":
    unittest.main()
