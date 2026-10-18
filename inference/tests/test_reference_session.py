"""Synthetic human-reference fixtures; no household labels or live calls."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference import reference_session as ref


def stamp(second):
    return {
        "host_id": "a" * 64,
        "boot_id": "synthetic-boot",
        "utc_before_ns": 1_000_000_000_000 + second * 1_000_000_000,
        "utc_after_ns": 1_000_000_000_001 + second * 1_000_000_000,
        "monotonic_ns": 100_000_000_000 + second * 1_000_000_000,
    }


def binding():
    fixture = (
        Path(__file__).resolve().parents[2]
        / "server-modules/tests/fixtures/capture-v2.synthetic.json"
    )
    result = json.loads(fixture.read_bytes())["opening"]
    result["node_ids"] = [1, 2, 3]
    return result


def profile(node):
    return {
        "schema": "ruview.commissioning.profile.v1",
        "node_id": node,
        "placement_revision": "synthetic",
        "room_id": "L" if node == 1 else "K",
        "orientation_reference": "synthetic",
        "antenna_path": "internal",
        "ap_bssid": "00:00:00:00:00:00",
        "firmware_version": "synthetic",
        "inference_revision": "synthetic",
        "evidence_reference": "synthetic only",
        "firmware_sha256": "f" * 64,
        "floorplan_sha256": "e" * 64,
        "receiver_position_ha_m": [1, 1.5, 2],
        "frequency_mhz": 2462,
        "module_sha256s": [],
        "placement_confirmed": True,
    }


def points():
    return {
        "schema": "ruview.reference_points.v1",
        "coordinate_frame": "example_lab_xz_metres",
        "floorplan_sha256": "e" * 64,
        "coordinate_reference": "synthetic pelvis floor projection",
        "measurement_method": "synthetic ruler fixture",
        "points": [
            {
                "point_id": "P1",
                "room_id": "K",
                "house_xy_m": [2.1, 4.2],
                "status": "measured",
                "spatial_uncertainty_m": 0.05,
                "measurement_evidence": "synthetic only, not an actual survey",
            }
        ],
    }


def observation(**changes):
    result = {
        "person_count": 1,
        "posture": "standing",
        "point_id": "P1",
        "room_id": "K",
        "source": "manual_observation",
        "provenance": "synthetic observer",
        "time_uncertainty_ns": 700_000_000,
        "truth_uncertainty": "",
        "frame_evidence_reference": None,
    }
    result.update(changes)
    return result


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.directory = self.base / "session"
        self.make()

    def make(self, calibration=None):
        self.metadata = ref.initialize(
            self.directory,
            binding(),
            [profile(n) for n in [1, 2, 3]],
            calibration or points(),
            {
                "transition_margin_ns": 5_000_000_000,
                "max_clock_step_ns": 10_000_000,
                "max_stamp_bracket_ns": 1_000_000,
            },
            "synthetic reviewer",
            stamp(0),
            expected_coordinate_frame="example_lab_xz_metres",
        )

    def mark(self, second, event, trial="trial1", value=None, reason=None):
        return ref.mark(
            self.directory,
            trial,
            event,
            observation() if value is None and event in ("begin", "end") else value,
            reason,
            stamp(second),
            expected_coordinate_frame="example_lab_xz_metres",
        )

    def closed(self, value=None):
        self.mark(1, "begin", value=value)
        self.mark(21, "end", value=value)

    def review(self):
        return ref.review(
            self.directory,
            "synthetic reviewer",
            "synthetic review",
            True,
            stamp(25),
            expected_coordinate_frame="example_lab_xz_metres",
        )

    def test_real_endpoint_bounds_and_explicit_three_node_expansion(self):
        self.closed()
        self.review()
        result = ref.export(
            self.directory,
            self.base / "export",
            [1, 2, 3],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        labels = [
            json.loads(s)
            for s in (self.base / "export/labels.jsonl").read_text().splitlines()
        ]
        self.assertEqual(result["label_count"], 3)
        for label in labels:
            self.assertEqual(label["schema"], "ruview.ground_truth.v2")
            self.assertEqual(label["session_id"], label["capture_id"])
            self.assertNotEqual(label["session_id"], label["worker_run_id"])
            self.assertEqual(
                label["start_ns"], stamp(1)["utc_after_ns"] + 5_000_000_000
            )
            self.assertEqual(
                label["end_ns"], stamp(21)["utc_before_ns"] - 5_000_000_000
            )
            self.assertEqual(label["time_uncertainty_ns"], 700_000_000)
            self.assertEqual(label["room_id"], "K")  # Node1 receiver is in L.
            self.assertEqual(label["house_xy_m"], [2.1, 4.2])
            self.assertEqual(label["spatial_uncertainty_m"], 0.05)
            self.assertFalse(label["reference_lineage"]["clock_offset_applied"])
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (self.directory / "events/000000.json").stat().st_mode & 0o777, 0o600
        )
        self.assertEqual(
            (self.base / "export/labels.jsonl").stat().st_mode & 0o777, 0o600
        )

    def test_session_and_export_are_exactly_private_under_setgid_parent(self):
        parent = self.base / "setgid-parent"
        parent.mkdir(mode=0o700)
        parent.chmod(0o2700)
        self.directory = parent / "session"
        self.make()
        self.closed()
        self.review()
        output = parent / "export"
        ref.export(
            self.directory,
            output,
            [1],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o2700)
        for directory in (self.directory, self.directory / "events", output):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in (self.directory / "metadata.json", output / "labels.jsonl"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_private_directory_creation_does_not_repair_existing_names(self):
        existing = self.base / "existing"
        existing.mkdir(mode=0o750)
        existing.chmod(0o2750)
        marker = existing / "marker"
        marker.write_bytes(b"unchanged")
        link = self.base / "linked"
        link.symlink_to(existing, target_is_directory=True)
        for destination in (existing, link):
            with self.subTest(destination=destination.name):
                with patch.object(ref.os, "fchmod") as chmod:
                    with self.assertRaises(FileExistsError):
                        ref.create_private_directory(destination)
                    chmod.assert_not_called()
                self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o2750)
                self.assertEqual(marker.read_bytes(), b"unchanged")

    def test_existing_session_modes_still_fail_closed_without_repair(self):
        for mode in (0o750, 0o2700):
            with self.subTest(mode=oct(mode)):
                self.directory.chmod(mode)
                with self.assertRaisesRegex(
                    ValueError, "session directory must be 0700"
                ):
                    self.mark(1, "begin")
                self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), mode)

    def test_private_directory_replaced_before_open_is_not_chmodded(self):
        real_open = os.open
        for mode in (0o700, 0o750):
            with self.subTest(mode=oct(mode)):
                destination = self.base / f"new-private-{mode}"
                original = self.base / f"original-private-{mode}"

                def replace_before_open(
                    path,
                    flags,
                    *,
                    destination=destination,
                    original=original,
                    mode=mode,
                ):
                    destination.rename(original)
                    destination.mkdir(mode=mode)
                    destination.chmod(mode)
                    return real_open(path, flags)

                with (
                    patch.object(ref.os, "open", side_effect=replace_before_open),
                    patch.object(ref.os, "fchmod") as chmod,
                ):
                    with self.assertRaisesRegex(
                        ValueError, "changed before initialization"
                    ):
                        ref.create_private_directory(destination)
                    chmod.assert_not_called()
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), mode)

    def test_private_directory_replaced_after_open_only_chmods_original_inode(self):
        real_fchmod = os.fchmod
        for mode in (0o700, 0o750):
            with self.subTest(mode=oct(mode)):
                destination = self.base / f"new-private-{mode}"
                original = self.base / f"original-private-{mode}"

                def replace_before_chmod(
                    fd,
                    requested_mode,
                    *,
                    destination=destination,
                    original=original,
                    mode=mode,
                ):
                    destination.rename(original)
                    destination.mkdir(mode=mode)
                    destination.chmod(mode)
                    real_fchmod(fd, requested_mode)

                with patch.object(ref.os, "fchmod", side_effect=replace_before_chmod):
                    with self.assertRaisesRegex(
                        ValueError, "changed during initialization"
                    ):
                        ref.create_private_directory(destination)
                self.assertEqual(stat.S_IMODE(original.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), mode)

    def test_unreviewed_unknown_nodes_and_repeat_output_fail(self):
        self.closed()
        with self.assertRaises(FileNotFoundError):
            ref.export(
                self.directory,
                self.base / "out",
                [1],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaisesRegex(ValueError, "explicit reference-truth"):
            ref.review(
                self.directory,
                "reviewer",
                "evidence",
                False,
                stamp(25),
                expected_coordinate_frame="example_lab_xz_metres",
            )
        self.review()
        with self.assertRaisesRegex(ValueError, "profile"):
            ref.export(
                self.directory,
                self.base / "out",
                [4],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ref.export(
                self.directory,
                self.base / "out",
                [1, 1],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        ref.export(
            self.directory,
            self.base / "out",
            [1],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        with self.assertRaises(FileExistsError):
            ref.export(
                self.directory,
                self.base / "out",
                [1],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaisesRegex(ValueError, "closed"):
            self.mark(30, "begin", trial="late")

    def test_reviewed_event_or_profile_replacement_rejected(self):
        self.closed()
        self.review()
        path = self.directory / "events/000001.json"
        row = json.loads(path.read_bytes())
        row["observation"]["provenance"] = "changed"
        path.write_bytes(ref.encoded(row))
        with self.assertRaisesRegex(ValueError, "review no longer"):
            ref.export(
                self.directory,
                self.base / "out",
                [1],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        path = self.directory / "metadata.json"
        meta = json.loads(path.read_bytes())
        meta["profiles"]["1"]["firmware_sha256"] = "0" * 64
        path.write_bytes(ref.encoded(meta))
        with self.assertRaisesRegex(ValueError, "profile hashes"):
            ref.export(
                self.directory,
                self.base / "out2",
                [1],
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_interruption_late_exclusion_and_uncertain_truth(self):
        self.closed()
        self.mark(22, "exclude", reason="second person noticed")
        self.mark(
            30,
            "begin",
            trial="uncertain",
            value=observation(truth_uncertainty="not visible"),
        )
        self.mark(50, "end", trial="uncertain")
        result = self.review()
        self.assertEqual(result["included"], [])
        self.assertEqual(len(result["excluded"]), 2)
        with self.assertRaisesRegex(ValueError, "no reviewed"):
            ref.export(
                self.directory,
                self.base / "out",
                [1],
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_unclosed_overlapping_mismatched_and_short_intervals_excluded(self):
        self.mark(1, "begin", trial="open")
        self.mark(2, "begin", trial="overlap")
        self.mark(22, "end", trial="overlap")
        self.mark(23, "interrupt", trial="open", reason="cancel")
        self.mark(30, "begin", trial="changed")
        self.mark(50, "end", trial="changed", value=observation(posture="seated"))
        self.mark(60, "begin", trial="short")
        self.mark(61, "end", trial="short")
        result = self.review()
        self.assertEqual(result["included"], [])
        self.assertEqual(len(result["excluded"]), 4)
        self.assertIn(
            "overlapping human trials", [r["reason"] for r in result["excluded"]]
        )

    def test_negative_and_multiple_people_remain_without_single_body_targets(self):
        for second, count in [(1, 0), (30, 2)]:
            value = observation(person_count=count, posture=None, point_id=None)
            self.mark(second, "begin", trial=f"count{count}", value=value)
            self.mark(second + 20, "end", trial=f"count{count}", value=value)
        self.review()
        ref.export(
            self.directory,
            self.base / "out",
            [2],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        labels = [
            json.loads(s)
            for s in (self.base / "out/labels.jsonl").read_text().splitlines()
        ]
        self.assertEqual([r["person_count"] for r in labels], [0, 2])
        self.assertTrue(
            all("posture" not in r and "house_xy_m" not in r for r in labels)
        )

    def test_proposed_point_not_converted_to_measurement(self):
        meta_path = self.directory / "metadata.json"
        meta = json.loads(meta_path.read_bytes())
        meta["calibration"]["points"][0]["status"] = "proposed"
        meta["calibration_sha256"] = ref.digest(meta["calibration"])
        meta_path.write_bytes(ref.encoded(meta))  # Synthetic pre-first-event setup.
        self.closed()
        result = self.review()
        self.assertEqual(result["included"], [])
        self.assertEqual(
            result["excluded"][0]["reason"],
            "point is proposed, not physically measured",
        )

    def test_clock_step_and_host_change_remain_recorded_and_invalidate_later_trials(
        self,
    ):
        self.mark(1, "begin")
        bad = stamp(21)
        bad["utc_before_ns"] += 1_000_000_000
        bad["utc_after_ns"] += 1_000_000_000
        row = ref.mark(
            self.directory,
            "trial1",
            "end",
            observation(),
            stamp=bad,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(row["clock_error"], "UTC/monotonic disagreement")
        self.mark(30, "begin", trial="later")
        self.mark(50, "end", trial="later")
        result = self.review()
        self.assertEqual(result["included"], [])
        self.assertTrue(all("clock" in r["reason"] for r in result["excluded"]))

    def test_camera_requires_frame_reference_without_collecting_image(self):
        with self.assertRaisesRegex(ValueError, "camera frame"):
            self.mark(1, "begin", value=observation(source="camera_annotation"))
        value = observation(
            source="camera_annotation",
            frame_evidence_reference="synthetic private-frame hash ref",
        )
        self.closed(value)
        self.assertEqual(len(self.review()["included"]), 1)

    def test_uncertainty_never_default_zero_and_invalid_people_rejected(self):
        for changes in (
            {"time_uncertainty_ns": 0},
            {"person_count": True},
            {"person_count": 2},
            {"posture": "falling"},
        ):
            with self.assertRaises(ValueError):
                self.mark(1, "begin", value=observation(**changes))
        self.assertEqual(list((self.directory / "events").iterdir()), [])

    def test_single_writer_atomic_write_and_nonfinite_bounds(self):
        with ref.locked(self.directory):
            with self.assertRaises(BlockingIOError):
                self.mark(1, "begin")
        with patch(
            "inference.reference_session.os.link",
            side_effect=OSError("fake disk failure"),
        ):
            with self.assertRaises(OSError):
                self.mark(1, "begin")
        self.assertEqual(list((self.directory / "events").iterdir()), [])
        for value in (
            b'{"x":1,"x":2}',
            b'{"x":1e309}',
            b'{"x":NaN}',
            b" " * (ref.MAX_FILE + 1),
        ):
            with self.assertRaises(ValueError):
                ref.strict(value)

    def test_fifo_and_symlink_inputs_fail_without_blocking(self):
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular bounded"):
            ref.read(fifo)
        link = self.base / "link"
        link.symlink_to(self.directory / "metadata.json")
        with self.assertRaises(OSError):
            ref.read(link)

    def test_capture_worker_identity_and_calibration_mismatch_rejected(self):
        b = binding()
        b["session_id"] = b["worker_run_id"]
        with self.assertRaises(ValueError):
            ref.validate_binding(b)
        c = points()
        c["coordinate_frame"] = "image_pixels"
        with self.assertRaisesRegex(ValueError, "frame"):
            ref.validate_points(c, expected_coordinate_frame="example_lab_xz_metres")
        c = points()
        c["points"][0]["spatial_uncertainty_m"] = 0
        with self.assertRaisesRegex(ValueError, "uncertainty"):
            ref.validate_points(c, expected_coordinate_frame="example_lab_xz_metres")

    def test_original_capture_opening_is_byte_bound_and_profiles_cover_scope(self):
        path = self.directory / "capture-opening.json"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "opening changed"):
            self.mark(1, "begin")
        with self.assertRaisesRegex(ValueError, "exact capture node scope"):
            ref.initialize(
                self.base / "wrongscope",
                binding(),
                [profile(1)],
                points(),
                self.metadata["policy"],
                "synthetic",
                stamp(0),
                expected_coordinate_frame="example_lab_xz_metres",
            )
        self.assertFalse((self.base / "wrongscope").exists())

    def test_clock_finding_recomputed_and_same_trial_cannot_be_reused(self):
        self.closed()
        self.mark(30, "begin")
        self.mark(50, "end")
        result = self.review()
        self.assertEqual(result["included"], [])
        self.assertEqual(len(result["excluded"]), 2)
        path = self.directory / "events/000003.json"
        row = json.loads(path.read_bytes())
        row["clock_error"] = "invented finding"
        path.write_bytes(ref.encoded(row))
        with self.assertRaisesRegex(ValueError, "clock finding changed"):
            ref.export(
                self.directory,
                self.base / "out",
                [1],
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_capture_opening_strict_types_and_event_index_bool_alias_rejected(self):
        for changes in (
            {"deadline_monotonic_ns": float(binding()["deadline_monotonic_ns"])},
            {"node_ids": [2, 1, 3]},
            {"node_ids": [17]},
            {"node_ids": [True, 2, 3]},
            {"clock_id": "different-run"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ref.validate_binding({**binding(), **changes})
        self.closed()
        self.review()
        for index in (0, 1):
            path = self.directory / "events" / f"{index:06d}.json"
            original = path.read_bytes()
            event = json.loads(original)
            event["index"] = bool(index)
            path.write_bytes(ref.encoded(event))
            try:
                with self.assertRaisesRegex(ValueError, "event index"):
                    ref.state(
                        self.directory,
                        expected_coordinate_frame="example_lab_xz_metres",
                    )
            finally:
                path.write_bytes(original)

    def test_verify_export_rechecks_originals_and_is_read_only(self):
        self.closed()
        self.review()
        output = self.base / "export"
        expected = ref.export(
            self.directory,
            output,
            [1, 2, 3],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        before = {str(p): p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        with patch(
            "inference.reference_session.write_bytes",
            side_effect=AssertionError("write"),
        ):
            labels, receipt = ref.verify_export(
                self.directory,
                output,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        self.assertEqual(receipt, expected)
        self.assertEqual(len(labels), 3)
        self.assertEqual(
            labels[0]["reference_lineage"]["opening_sha256"],
            ref.raw_hash((self.directory / "capture-opening.json").read_bytes()),
        )
        self.assertEqual(
            labels[0]["reference_lineage"]["label_clock"],
            {k: stamp(0)[k] for k in ("host_id", "boot_id")},
        )
        self.assertEqual(
            before,
            {str(p): p.read_bytes() for p in self.base.rglob("*") if p.is_file()},
        )

    def test_forged_export_labels_and_self_consistent_checksum_cannot_replace_source(
        self,
    ):
        self.closed()
        self.review()
        output = self.base / "export"
        ref.export(
            self.directory,
            output,
            [1],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        label = json.loads((output / "labels.jsonl").read_bytes())
        label["posture"] = "lying"
        raw = (json.dumps(label, sort_keys=True) + "\n").encode()
        (output / "labels.jsonl").write_bytes(raw)
        receipt = json.loads((output / "receipt.json").read_bytes())
        receipt["labels_sha256"] = ref.raw_hash(raw)
        (output / "receipt.json").write_bytes(ref.encoded(receipt))
        with self.assertRaisesRegex(ValueError, "receipt changed"):
            ref.verify_export(
                self.directory,
                output,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_verifier_rejects_original_event_review_and_opening_tampering(self):
        self.closed()
        self.review()
        output = self.base / "export"
        ref.export(
            self.directory,
            output,
            [1],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        for relative in ("events/000001.json", "review.json", "capture-opening.json"):
            with self.subTest(relative=relative):
                path = self.directory / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                try:
                    with self.assertRaises(ValueError):
                        ref.verify_export(
                            self.directory,
                            output,
                            expected_coordinate_frame="example_lab_xz_metres",
                        )
                finally:
                    path.write_bytes(original)
        (output / "labels.jsonl").write_bytes(
            (output / "labels.jsonl").read_bytes() + b"\n"
        )
        with self.assertRaisesRegex(ValueError, "labels differ"):
            ref.verify_export(
                self.directory,
                output,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_partial_export_has_no_receipt_and_cannot_be_verified(self):
        self.closed()
        self.review()
        output = self.base / "export"
        original = ref.write

        def fail_receipt(path, value):
            if path.name == "receipt.json":
                raise OSError("synthetic full disk")
            return original(path, value)

        with patch("inference.reference_session.write", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                ref.export(
                    self.directory,
                    output,
                    [1],
                    expected_coordinate_frame="example_lab_xz_metres",
                )
        self.assertTrue((output / "labels.jsonl").exists())
        self.assertFalse((output / "receipt.json").exists())
        with self.assertRaises(FileNotFoundError):
            ref.verify_export(
                self.directory,
                output,
                expected_coordinate_frame="example_lab_xz_metres",
            )

    def test_export_byte_bound_fails_before_any_output_and_metadata_scope_rechecked(
        self,
    ):
        self.closed()
        self.review()
        with patch("inference.reference_session.MAX_EXPORT_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "size exceeds bound"):
                ref.export(
                    self.directory,
                    self.base / "export",
                    [1, 2, 3],
                    expected_coordinate_frame="example_lab_xz_metres",
                )
        self.assertFalse((self.base / "export").exists())
        path = self.directory / "metadata.json"
        meta = json.loads(path.read_bytes())
        meta["model_qualified"] = True
        path.write_bytes(ref.encoded(meta))
        with self.assertRaisesRegex(ValueError, "scope changed"):
            ref.state(self.directory, expected_coordinate_frame="example_lab_xz_metres")

    def test_wall_clock_backtrack_boot_change_and_no_automatic_labels(self):
        self.assertFalse((self.directory / "review.json").exists())
        self.assertEqual(list((self.directory / "events").iterdir()), [])
        with self.assertRaisesRegex(ValueError, "no human observations"):
            self.review()
        self.mark(1, "begin")
        other = stamp(21)
        other["boot_id"] = "other-boot"
        event = ref.mark(
            self.directory,
            "trial1",
            "end",
            observation(),
            stamp=other,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(event["clock_error"], "label host/boot changed")
        self.assertEqual(self.review()["included"], [])


if __name__ == "__main__":
    unittest.main()
