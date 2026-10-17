import copy
import unittest

from radar.ld2450 import (
    AXES,
    FOOTER,
    HEADER,
    Configuration,
    ObservationAdapter,
    StreamDecoder,
    decode_report,
    signed_magnitude,
)

FRAME = "example_lab_xz_metres"

# Manufacturer V1.03 section 2.3 worked example, not a household recording.
EXAMPLE = bytes.fromhex(
    "aa ff 03 00 0e 03 b1 86 10 00 40 01 "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 cc"
)
EMPTY = HEADER + bytes(24) + FOOTER
M = 1_000_000_000
U = 1_800_000_000_000_000_000


def synthetic_config():
    return {
        "schema": "ruview.ld2450.configuration.v1",
        "model": "HLK-LD2450",
        "sensor_id": "synthetic-radar",
        "hardware_confirmed": True,
        "hardware_identity": "synthetic-only",
        "serial_endpoint_id": "synthetic-uart",
        "firmware_version": "synthetic-test-version",
        "tracking_mode": "multi",
        "coordinate_frame": FRAME,
        "floorplan_sha256": "a" * 64,
        "ttl_ms": 1000,
        "survey": {
            "status": "measured",
            "mounting": "upright_level",
            "axis_convention": AXES,
            "axes_verified": True,
            "origin_xz_m": [10.0, 20.0],
            "yaw_deg": 90.0,
            "mounting_height_m": 1.5,
            "transform_uncertainty_m": 0.2,
            "evidence_sha256": "b" * 64,
        },
    }


class ProtocolTests(unittest.TestCase):
    def test_manufacturer_example_and_wire_units(self):
        (t,) = decode_report(EXAMPLE)
        self.assertEqual((t.slot, t.x_mm, t.y_mm, t.speed_cm_s), (1, -782, 1713, -16))
        self.assertEqual(t.distance_resolution_mm, 320)

    def test_sign_bit_is_not_twos_complement(self):
        for hex_value, expected in [
            ("0000", 0),
            ("0080", 0),
            ("ffff", 32767),
            ("ff7f", -32767),
            ("0180", 1),
            ("0100", -1),
        ]:
            self.assertEqual(signed_magnitude(bytes.fromhex(hex_value)), expected)

    def test_unused_slots_and_three_independent_slots(self):
        self.assertEqual(decode_report(EMPTY), ())
        record = EXAMPLE[4:12]
        result = decode_report(HEADER + record * 3 + FOOTER)
        self.assertEqual([t.slot for t in result], [1, 2, 3])
        # A nonzero record is retained even at x=y=0; no invented occupancy gate.
        result = decode_report(HEADER + bytes(6) + b"\x01\x00" + bytes(16) + FOOTER)
        self.assertEqual(len(result), 1)

    def test_exact_length_and_framing(self):
        for raw in [
            EXAMPLE[:-1],
            EXAMPLE + b"\x00",
            b"\x00" + EXAMPLE[1:],
            EXAMPLE[:-2] + b"xx",
        ]:
            with self.assertRaises(ValueError):
                decode_report(raw)

    def test_all_fragment_boundaries_preserve_original_receipt(self):
        for boundary in range(1, 30):
            decoder = StreamDecoder()
            self.assertEqual(decoder.feed(EXAMPLE[:boundary], M, U), [])
            (report,) = decoder.feed(EXAMPLE[boundary:], M + 500, U + 500)
            self.assertEqual(report.raw, EXAMPLE)
            self.assertEqual(report.first_byte_monotonic_ns, M)
            self.assertEqual(report.first_byte_utc_ns, U)
            self.assertEqual(report.last_byte_monotonic_ns, M + 500)

    def test_noise_bad_footer_and_coalescing_are_bounded(self):
        decoder = StreamDecoder()
        damaged = EXAMPLE[:-2] + b"xx"
        reports = decoder.feed(b"noise" + damaged + EXAMPLE + EMPTY + HEADER[:2], M, U)
        self.assertEqual([r.raw for r in reports], [EXAMPLE, EMPTY])
        self.assertEqual(decoder.invalid_frames, 1)
        self.assertGreater(decoder.discarded_bytes, 5)
        self.assertLess(len(decoder.buffer), 30)
        with self.assertRaises(ValueError):
            decoder.feed(b"x" * 4097, M, U)


class AdapterTests(unittest.TestCase):
    def adapter(self):
        adapter = ObservationAdapter(
            synthetic_config(), expected_coordinate_frame="example_lab_xz_metres"
        )
        adapter.connect("synthetic-connection-1")
        return adapter

    def test_no_hardware_no_config_and_no_data_are_unavailable(self):
        adapter = ObservationAdapter(expected_coordinate_frame="example_lab_xz_metres")
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M, utc_ns=U)["reason"],
            "configuration_missing",
        )
        with self.assertRaises(ValueError):
            adapter.connect("epoch")
        adapter = ObservationAdapter(
            synthetic_config(), expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M, utc_ns=U)["reason"], "hardware_unavailable"
        )
        with self.assertRaises(ValueError):
            adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
        adapter.connect("new")
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M, utc_ns=U)["reason"],
            "waiting_for_uart_report",
        )

    def test_survey_rotation_units_and_no_pose_fall_or_person_identity(self):
        adapter = self.adapter()
        adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
        result = adapter.snapshot(monotonic_ns=M + 100, utc_ns=U + 100)
        self.assertEqual(result["status"], "available")
        (t,) = result["targets"]
        self.assertAlmostEqual(t["house_xz_m"][0], 8.287)
        self.assertAlmostEqual(t["house_xz_m"][1], 19.218)
        self.assertEqual(t["speed_m_s"], -0.16)
        self.assertEqual(t["sensor_xy_mm"], [-782, 1713])
        for key in [
            "body_pose_available",
            "body_height_available",
            "fall_detection_available",
            "person_identity_available",
            "recognition_validated",
        ]:
            self.assertIs(result[key], False)
        self.assertNotIn("person_id", t)
        self.assertNotIn("z_m", t)
        self.assertEqual(result["observed_at_ns"], str(U))

    def test_stale_boundary_and_empty_report_do_not_claim_empty_room(self):
        adapter = self.adapter()
        adapter.feed(EMPTY, monotonic_ns=M, utc_ns=U)
        result = adapter.snapshot(monotonic_ns=M, utc_ns=U)
        self.assertEqual(result["reason"], "no_targets_reported_not_empty_room")
        self.assertEqual(result["reported_target_count"], 0)
        result = adapter.snapshot(monotonic_ns=2 * M, utc_ns=U + M)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["targets"], [])
        self.assertNotIn("reported_target_count", result)

    def test_fragment_completion_does_not_rebase_old_first_byte(self):
        adapter = self.adapter()
        adapter.feed(EXAMPLE[:10], monotonic_ns=M, utc_ns=U)
        adapter.feed(EXAMPLE[10:], monotonic_ns=2 * M, utc_ns=U + M)
        self.assertEqual(
            adapter.snapshot(monotonic_ns=2 * M, utc_ns=U + M)["reason"],
            "stale_uart_report",
        )

    def test_noise_does_not_renew_lease_and_bad_frame_clears_prior(self):
        adapter = self.adapter()
        adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
        adapter.feed(b"noise", monotonic_ns=M + 100, utc_ns=U + 100)
        result = adapter.snapshot(monotonic_ns=M + 200, utc_ns=U + 200)
        self.assertEqual(result["observed_at_ns"], str(U))
        adapter.feed(EXAMPLE[:-2] + b"xx", monotonic_ns=M + 300, utc_ns=U + 300)
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M + 300, utc_ns=U + 300)["reason"],
            "invalid_uart_frame",
        )

    def test_disconnect_and_reconnect_clear_old_partial_and_report(self):
        adapter = self.adapter()
        adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
        adapter.feed(EXAMPLE[:15], monotonic_ns=M + 1, utc_ns=U + 1)
        adapter.disconnect()
        with self.assertRaises(ValueError):
            adapter.connect("synthetic-connection-1")
        with self.assertRaises(ValueError):
            adapter.feed(EXAMPLE, monotonic_ns=M + 2, utc_ns=U + 2)
        adapter.connect("synthetic-connection-2")
        adapter.feed(EXAMPLE[15:], monotonic_ns=M + 3, utc_ns=U + 3)
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M + 3, utc_ns=U + 3)["targets"], []
        )

    def test_clock_discontinuity_requires_explicit_reconnect(self):
        for mono, utc in [(M - 1, U), (M + 1, U + M)]:
            adapter = self.adapter()
            adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
            result = adapter.snapshot(monotonic_ns=mono, utc_ns=utc)
            self.assertEqual(result["status"], "unavailable")
            with self.assertRaises(ValueError):
                adapter.feed(EXAMPLE, monotonic_ns=M + 2, utc_ns=U + 2)

    def test_bad_chunk_disconnects_without_old_data_reuse(self):
        adapter = self.adapter()
        adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
        with self.assertRaises(ValueError):
            adapter.feed(b"x" * 4097, monotonic_ns=M + 1, utc_ns=U + 1)
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M + 2, utc_ns=U + 2)["targets"], []
        )
        with self.assertRaises(ValueError):
            adapter.feed(EXAMPLE, monotonic_ns=M + 3, utc_ns=U + 3)

    def test_later_bad_frame_in_same_chunk_invalidates_earlier_valid_frame(self):
        adapter = self.adapter()
        adapter.feed(EXAMPLE + EXAMPLE[:-2] + b"xx", monotonic_ns=M, utc_ns=U)
        self.assertEqual(
            adapter.snapshot(monotonic_ns=M, utc_ns=U)["status"], "unavailable"
        )

    def test_single_target_mode_mismatch_and_forward_utc_expiry(self):
        config = synthetic_config()
        config["tracking_mode"] = "single"
        adapter = ObservationAdapter(
            config, expected_coordinate_frame="example_lab_xz_metres"
        )
        adapter.connect("single")
        with self.assertRaises(ValueError):
            adapter.feed(HEADER + EXAMPLE[4:12] * 3 + FOOTER, monotonic_ns=M, utc_ns=U)
        adapter = self.adapter()
        adapter.feed(EXAMPLE, monotonic_ns=M, utc_ns=U)
        result = adapter.snapshot(monotonic_ns=M + 950_000_000, utc_ns=U + M)
        self.assertEqual(result["status"], "unavailable")

    def test_invalid_or_proposed_configuration_never_projects(self):
        base = synthetic_config()
        mutations = [
            (None, "model", "other-model"),
            (None, "hardware_confirmed", False),
            (None, "coordinate_frame", "pixels"),
            (None, "ttl_ms", True),
            (None, "ttl_ms", 5001),
            (None, "floorplan_sha256", "unknown"),
            ("survey", "status", "proposed"),
            ("survey", "mounting", "tilted"),
            ("survey", "axes_verified", False),
            ("survey", "origin_xz_m", [float("nan"), 0]),
            ("survey", "yaw_deg", float("inf")),
            ("survey", "mounting_height_m", 0),
            ("survey", "transform_uncertainty_m", 0),
            ("survey", "evidence_sha256", "missing"),
        ]
        for group, key, value in mutations:
            config = copy.deepcopy(base)
            (config[group] if group else config)[key] = value
            with self.subTest(group=group, key=key), self.assertRaises(ValueError):
                ObservationAdapter(
                    config, expected_coordinate_frame="example_lab_xz_metres"
                )

    def test_configuration_is_immutable_and_hash_binds_survey(self):
        config = synthetic_config()
        first = Configuration.load(
            config, expected_coordinate_frame="example_lab_xz_metres"
        )
        config["survey"]["yaw_deg"] = 0
        second = Configuration.load(
            config, expected_coordinate_frame="example_lab_xz_metres"
        )
        self.assertNotEqual(first.sha256, second.sha256)
        self.assertEqual(first.yaw_deg, 90)


if __name__ == "__main__":
    unittest.main()
