"""Synthetic protocol exchanges and reference clocks; no measurements or SSH."""

import copy
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from inference import reference_session as ref
from inference.model import features, predict, train, validate_model
from inference.pipeline import WindowBuilder, digest, pair_window
from inference.reference_alignment import (
    align_label,
    make_alignment,
    probe,
    validate_alignment,
    validate_paired_alignment,
)
from inference.tests import test_capture_session
from inference.tests.process_support import PROCESS_TIMEOUT_SECONDS
from inference.tests.test_pipeline import label, profile
from inference.tests.test_pipeline import window as legacy_window
from scripts.reference_clock import (
    READY_SCHEMA,
    REMOTE_MONOTONIC_DOMAIN,
    SCHEMA,
    Assessment,
)

LOCAL = {"host_id": "b" * 64, "boot_id": "synthetic-reference-boot"}
REMOTE = {"host_id": "c" * 64, "boot_id": "synthetic-boot"}


def stamp(utc, mono):
    return {"utc_before_ns": utc, "monotonic_ns": mono, "utc_after_ns": utc + 2}


def measured_fixture(base, start, offset=50_000_000):
    """Use actual Assessment math, with explicitly synthetic original exchanges."""
    ready = {
        "schema": READY_SCHEMA,
        "identity": REMOTE,
        "monotonic_domain": REMOTE_MONOTONIC_DOMAIN,
    }
    ready_raw = test_capture_session.encoded(ready) + b"\n"
    first = stamp(base + start, start + 90_000_000_000)
    report = {
        "schema": "ruview.reference_clock.measurement.v1",
        "probe_run_id": "66666666-6666-4666-8666-666666666666",
        "started_at_ns": base + start - 20_000_000,
        "finished_at_ns": base + start + 1_020_000_000,
        "passed": True,
        "read_only": True,
        "calibration_applied": False,
        "recognition_validated": False,
        "camera_or_recording_started": False,
        "midpoint_assumes_symmetric_network": False,
        "clocks_between_probes_verified": False,
        "ssh_process_cleaned_up": True,
        "local_identity": LOCAL,
        "remote_identity": REMOTE,
        "local_monotonic_domain": "python_time_monotonic_local_host",
        "remote_monotonic_domain": REMOTE_MONOTONIC_DOMAIN,
        "settings": {
            "host": "synthetic-mp",
            "hostname": None,
            "no_proxyjump": False,
            "samples": 2,
            "interval_ms": 0,
            "sample_timeout_ms": 1000,
            "startup_timeout_ms": 1000,
            "deadline_seconds": 10,
            "max_clock_step_ms": 1,
        },
        "readiness": {
            "passed": True,
            "remote": ready,
            "is_offset_sample": False,
            "response_bytes": len(ready_raw),
            "response_sha256": hashlib.sha256(ready_raw).hexdigest(),
            "local_process_started": stamp(
                base + start - 20_000_000, first["monotonic_ns"] - 20_000_000
            ),
            "local_wait_started": stamp(
                base + start - 19_000_000, first["monotonic_ns"] - 19_000_000
            ),
            "local_receive": stamp(
                base + start - 1_000_000, first["monotonic_ns"] - 1_000_000
            ),
        },
        "samples": [],
    }
    assessment = Assessment(1_000_000)
    for index in range(2):
        utc, mono = (
            base + start + index * 1_000_000_000,
            start + 90_000_000_000 + index * 1_000_000_000,
        )
        nonce = f"{index + 1:032x}"
        remote = {
            "schema": SCHEMA,
            "nonce": nonce,
            "identity": REMOTE,
            "monotonic_domain": REMOTE_MONOTONIC_DOMAIN,
            "stamp": stamp(utc + 9_000_000 + offset, mono + 9_000_000 + 123_000_000),
        }
        remote_raw = test_capture_session.encoded(remote) + b"\n"
        sample = {
            "index": index,
            "nonce": nonce,
            "local_send": stamp(utc, mono),
            "local_receive": stamp(utc + 10_000_000, mono + 10_000_000),
            "remote": remote,
            "response_bytes": len(remote_raw),
            "response_sha256": hashlib.sha256(remote_raw).hexdigest(),
        }
        assessment.push(sample)
        report["samples"].append(sample)
    report.update(assessment.finish())
    return report


class ReferenceAlignmentTests(unittest.TestCase):
    def setUp(self):
        self.capture = test_capture_session.CaptureSessionTests()
        self.capture.setUp()
        self.addCleanup(self.capture.doCleanups)
        self.capture.prepare_context()
        with self.capture.context() as (_, evidence):
            self.evidence = copy.deepcopy(evidence)
        self.before = measured_fixture(self.capture.base, 8_000_000_000)
        self.after = measured_fixture(self.capture.base, 12_000_000_000)

    def alignment(self, before=None, after=None, evidence=None, allowance=1_000_000):
        return make_alignment(
            test_capture_session.encoded(self.before if before is None else before),
            test_capture_session.encoded(self.after if after is None else after),
            self.evidence if evidence is None else evidence,
            between_probe_allowance_ns=allowance,
            assumption_reference="synthetic reviewed tolerance; not clock calibration",
        )

    def window(self):
        builder = WindowBuilder(
            duration_ms=200, min_frames=3, profiles=[profile(n) for n in (1, 2, 3)]
        )
        for row in self.capture.rows:
            result = builder.push(row)
            if result is not None:
                return result
        raise AssertionError("synthetic fixture should contain a complete native window")

    def original(self, value):
        original = label(value)
        original.update(
            schema="ruview.ground_truth.v2",
            capture_id=self.evidence["capture_id"],
            worker_run_id=self.evidence["worker_run_id"],
            clock_id=self.evidence["clock_id"],
            start_ns=self.capture.base + 9_800_000_000,
            end_ns=self.capture.base + 11_500_000_000,
            time_uncertainty_ns=10_000_000,
            reference_lineage={
                "opening_sha256": self.evidence["opening_sha256"],
                "metadata_sha256": "d" * 64,
                "review_sha256": "e" * 64,
                "label_clock": LOCAL,
                "clock_offset_applied": False,
            },
        )
        return original

    def paired(self):
        value, alignment = self.window(), self.alignment()
        original = self.original(value)
        adjusted = align_label(
            original,
            alignment,
            self.evidence,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        result = pair_window(
            value,
            [adjusted],
            alignment["label_to_csi_clock_offset_ns"],
            adjusted["time_uncertainty_ns"],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertIsNotNone(result)
        result.update(
            capture_evidence=self.evidence,
            time_alignment=alignment,
            original_label=original,
        )
        return result

    def test_cli_original_capture_reviewed_export_and_clock_pairing_end_to_end(self):
        """Exercise real CLIs and exporter, using synthetic clocks/observations only."""
        root = self.capture.root
        profiles = [profile(n) for n in (1, 2, 3)]
        reference, exported = root / "reference", root / "reference-export"

        def local_stamp(offset):
            return {
                **LOCAL,
                **stamp(self.capture.base + offset, 90_000_000_000 + offset),
            }

        ref.initialize(
            reference,
            self.capture.opening,
            profiles,
            None,
            {
                "transition_margin_ns": 10_000_000,
                "max_clock_step_ns": 1_000_000,
                "max_stamp_bracket_ns": 1_000_000,
            },
            "synthetic observer only",
            local_stamp(9_100_000_000),
            opening_raw=(root / "opening.json").read_bytes(),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        observation = {
            "person_count": 1,
            "posture": "standing",
            "point_id": None,
            "room_id": "K",
            "source": "manual_observation",
            "provenance": "synthetic observation; no real person or household labels",
            "time_uncertainty_ns": 10_000_000,
            "truth_uncertainty": "",
            "frame_evidence_reference": None,
        }
        for event, offset in (("begin", 9_200_000_000), ("end", 11_600_000_000)):
            ref.mark(
                reference,
                "synthetic-trial",
                event,
                observation,
                stamp=local_stamp(offset),
                expected_coordinate_frame="example_lab_xz_metres",
            )
        ref.review(
            reference,
            "synthetic reviewer",
            "synthetic reference review only",
            True,
            local_stamp(11_700_000_000),
            expected_coordinate_frame="example_lab_xz_metres",
        )
        ref.export(
            reference,
            exported,
            [1, 2, 3],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        for name, value in (
            ("profiles", profiles),
            ("before", self.before),
            ("after", self.after),
        ):
            (root / (name + ".json")).write_bytes(test_capture_session.encoded(value))
        originals = {
            name: (root / name).read_bytes()
            for name in ("opening.json", "terminal.json", "raw.jsonl")
        }
        common = [
            "--frames",
            str(root / "raw.jsonl"),
            "--opening",
            str(root / "opening.json"),
            "--terminal",
            str(root / "terminal.json"),
        ]

        def cli(command, arguments, expected=0):
            if command == "pair-session":
                arguments = [
                    *arguments,
                    "--expected-coordinate-frame",
                    "example_lab_xz_metres",
                ]
            result = subprocess.run(
                [sys.executable, "-m", "inference", command, *arguments],
                cwd=Path(__file__).resolve().parents[2],
                env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"},
                capture_output=True,
                text=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
            if expected == 0:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout)
            return result

        manifest, verified = root / "indexed.json", root / "indexed-report.json"
        cli(
            "index-session",
            common
            + [
                "--manifest-output",
                str(manifest),
                "--report-output",
                str(verified),
                "--provenance-reference",
                "synthetic cross-language fixture only",
                "--classification",
                "synthetic",
                "--max-clock-step-ns",
                "1000000",
                "--max-receipt-gap-ns",
                "70000000",
            ],
        )
        cli(
            "verify-session",
            common
            + [
                "--manifest",
                str(manifest),
                "--report-output",
                str(root / "reverified.json"),
            ],
        )
        self.assertEqual(verified.read_bytes(), (root / "reverified.json").read_bytes())
        paired, report = root / "paired.jsonl", root / "paired-report.json"
        pair_args = common + [
            "--manifest",
            str(manifest),
            "--capture-report",
            str(verified),
            "--profiles",
            str(root / "profiles.json"),
            "--reference-directory",
            str(reference),
            "--reference-export",
            str(exported),
            "--clock-before",
            str(root / "before.json"),
            "--clock-after",
            str(root / "after.json"),
            "--clock-assumption-reference",
            "synthetic explicit drift allowance",
            "--between-probe-allowance-ns",
            "1000000",
            "--max-label-uncertainty-ns",
            "100000000",
            "--window-ms",
            "200",
            "--min-frames",
            "3",
        ]
        output_args = ["--output", str(paired), "--report-output", str(report)]
        cli("pair-session", pair_args + output_args)
        rows = [json.loads(line) for line in paired.read_bytes().splitlines()]
        result = json.loads(report.read_bytes())
        self.assertTrue(rows)
        self.assertEqual({row["window"]["node_id"] for row in rows}, {1, 2, 3})
        self.assertEqual(result["counts"]["paired_windows"], len(rows))
        self.assertEqual(result["counts"]["source_frames"], 60)
        self.assertFalse(result["recognition_validated"])
        self.assertFalse(result["publish_to_ha"])
        for row in rows:
            self.assertEqual(row["schema"], "ruview.csi.paired.v2")
            self.assertEqual(
                row["capture_evidence"]["status"], "verified_closed_capture"
            )
            self.assertTrue(row["capture_evidence"]["synthetic_only"])
            self.assertEqual(row["window"]["capture_id"], self.evidence["capture_id"])
            self.assertEqual(
                row["window"]["worker_run_id"], self.evidence["worker_run_id"]
            )
            self.assertEqual(row["original_label"]["time_uncertainty_ns"], 10_000_000)
            self.assertGreater(row["label"]["time_uncertainty_ns"], 10_000_000)
            self.assertNotIn("house_xy_m", row["label"])
            validate_paired_alignment(
                row, expected_coordinate_frame="example_lab_xz_metres"
            )
        retained = paired.read_bytes()
        cli("pair-session", pair_args + output_args, expected=1)
        self.assertEqual(paired.read_bytes(), retained)
        for name, raw in originals.items():
            self.assertEqual((root / name).read_bytes(), raw)
        for path in (manifest, verified, paired, report):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        labels = exported / "labels.jsonl"
        labels.write_bytes(labels.read_bytes().replace(b'"standing"', b'"seated"'))
        forbidden = root / "tampered-export-pairs.jsonl"
        cli(
            "pair-session",
            pair_args
            + [
                "--output",
                str(forbidden),
                "--report-output",
                str(root / "tampered-export-report.json"),
            ],
            expected=1,
        )
        self.assertFalse(forbidden.exists())

    def test_recomputed_measured_brackets_preserve_offset_sign_and_uncertainty(self):
        for offset in (50_000_000, -50_000_000):
            before = measured_fixture(self.capture.base, 8_000_000_000, offset)
            after = measured_fixture(self.capture.base, 12_000_000_000, offset)
            alignment = self.alignment(before, after)
            self.assertLess(alignment["offset_bounds_ns"]["lower"], offset)
            self.assertGreater(alignment["offset_bounds_ns"]["upper"], offset)
            self.assertEqual(alignment["label_to_csi_clock_offset_ns"] > 0, offset > 0)
            self.assertEqual(
                alignment["before_report_sha256"],
                hashlib.sha256(test_capture_session.encoded(before)).hexdigest(),
            )
            self.assertEqual(alignment["receiver_host_clock"], REMOTE)
            self.assertFalse(alignment["clocks_between_probes_verified"])
            self.assertFalse(alignment["calibration_applied"])

    def test_probes_must_bracket_original_capture_in_correct_direction(self):
        for before, after in (
            (self.after, self.before),
            (self.after, self.after),
            (self.before, self.before),
        ):
            with (
                self.subTest(
                    before=before["started_at_ns"], after=after["started_at_ns"]
                ),
                self.assertRaises(ValueError),
            ):
                self.alignment(before, after)

    def test_local_boot_remote_boot_and_monotonic_domains_cannot_change(self):
        for kind in (
            "local_boot",
            "local_host",
            "remote_boot",
            "remote_domain",
            "local_domain",
        ):
            after = copy.deepcopy(self.after)
            if kind == "local_boot":
                after["local_identity"]["boot_id"] = "another-boot"
            elif kind == "local_host":
                after["local_identity"]["host_id"] = "f" * 64
            elif kind == "remote_boot":
                after["remote_identity"]["boot_id"] = "another-boot"
            elif kind == "remote_domain":
                after["samples"][0]["remote"]["monotonic_domain"] = "worker_start"
            else:
                after["local_monotonic_domain"] = "worker_start"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.alignment(after=after)

    def test_original_exchange_recalculation_rejects_changed_summaries_or_samples(self):
        for kind in ("summary", "sample", "nonce", "partial", "passed"):
            value = copy.deepcopy(self.before)
            if kind == "summary":
                value["observed_offset_envelope_ns"]["lower"] += 1
            elif kind == "sample":
                value["samples"][0]["round_trip_ns"] += 1
            elif kind == "nonce":
                value["samples"][0]["nonce"] = "f" * 32
            elif kind == "partial":
                value["samples"].pop()
            else:
                value["passed"] = 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                probe(test_capture_session.encoded(value))

    def test_readiness_schema_domain_and_typed_sample_settings_required(self):
        for kind in ("ready_schema", "ready_domain", "ready_missing", "samples_float"):
            value = copy.deepcopy(self.before)
            if kind == "ready_schema":
                value["readiness"]["remote"]["schema"] = "not-the-ready-contract"
            elif kind == "ready_domain":
                value["readiness"]["remote"]["monotonic_domain"] = "worker_start"
            elif kind == "ready_missing":
                del value["readiness"]["remote"]["schema"]
            else:
                value["settings"]["samples"] = 2.0
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                probe(test_capture_session.encoded(value))

    def test_annotation_plus_measured_clock_uncertainty_must_fit_explicit_budget(self):
        value, alignment = self.window(), self.alignment()
        original = self.original(value)
        retained = copy.deepcopy(original)
        adjusted = align_label(
            original,
            alignment,
            self.evidence,
            expected_coordinate_frame="example_lab_xz_metres",
        )
        total = original["time_uncertainty_ns"] + alignment["clock_uncertainty_ns"]
        self.assertEqual(original, retained)
        self.assertEqual(adjusted["time_uncertainty_ns"], total)
        self.assertEqual(adjusted["start_ns"], original["start_ns"])
        self.assertIsNone(
            pair_window(
                value,
                [adjusted],
                alignment["label_to_csi_clock_offset_ns"],
                total - 1,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        )
        self.assertIsNotNone(
            pair_window(
                value,
                [adjusted],
                alignment["label_to_csi_clock_offset_ns"],
                total,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        )

    def test_reference_clock_opening_and_capture_identity_must_match(self):
        value, alignment = self.window(), self.alignment()
        for kind in (
            "local_boot",
            "opening",
            "already_shifted",
            "capture",
            "before_bracket",
            "after_bracket",
        ):
            original = self.original(value)
            if kind == "local_boot":
                original["reference_lineage"]["label_clock"] = {
                    **LOCAL,
                    "boot_id": "wrong",
                }
            elif kind == "opening":
                original["reference_lineage"]["opening_sha256"] = "f" * 64
            elif kind == "already_shifted":
                original["reference_lineage"]["clock_offset_applied"] = True
            elif kind == "capture":
                original["session_id"] = original["capture_id"] = (
                    "77777777-7777-4777-8777-777777777777"
                )
            elif kind == "before_bracket":
                original["start_ns"] = alignment["label_interval_ns"]["start"] - 1
            else:
                original["end_ns"] = alignment["label_interval_ns"]["end"] + 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                align_label(
                    original,
                    alignment,
                    self.evidence,
                    expected_coordinate_frame="example_lab_xz_metres",
                )

    def test_rehashed_alignment_cannot_change_capture_binding_or_uncertainty_math(self):
        for key, value in (
            ("opening_sha256", "f" * 64),
            ("clock_uncertainty_ns", 1),
            ("label_to_csi_clock_offset_ns", 1),
            ("between_probe_allowance_ns", True),
        ):
            alignment = self.alignment()
            alignment[key] = value
            alignment["alignment_sha256"] = digest(
                {k: v for k, v in alignment.items() if k != "alignment_sha256"}
            )
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_alignment(alignment, self.evidence)

    def test_training_revalidates_retained_alignment_before_accepting_labels(self):
        record = self.paired()
        self.assertEqual(
            validate_paired_alignment(
                record, expected_coordinate_frame="example_lab_xz_metres"
            ),
            record,
        )
        for kind in ("uncertainty", "offset", "original"):
            altered = copy.deepcopy(record)
            if kind == "uncertainty":
                altered["label"]["time_uncertainty_ns"] -= 1
            elif kind == "offset":
                altered["alignment"]["label_to_csi_clock_offset_ns"] += 1
            else:
                altered["original_label"]["posture"] = "seated"
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(
                    ValueError, "paired annotation|paired label offset"
                ),
            ):
                train(
                    [altered],
                    "posture",
                    [altered["window"]["session_id"]],
                    min_train=1,
                    min_eval=1,
                    expected_coordinate_frame="example_lab_xz_metres",
                )

    def test_verified_two_capture_lineage_survives_fit_checkpoint_and_prediction(self):
        """All packets, clocks and posture targets here are explicitly synthetic."""
        captures = (
            "11111111-1111-4111-8111-111111111111",
            "33333333-3333-4333-8333-333333333333",
        )
        records = []
        for number, capture_id in enumerate(captures):
            fixture = test_capture_session.CaptureSessionTests()
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            start, ingress = (
                10_000_000_000 + number * 20_000_000_000,
                120 + number * 120,
            )
            fixture.opening.update(
                session_id=capture_id,
                capture_id=capture_id,
                node_ids=[2],
                limits={"duration_ms": 10_000, "max_bytes": 1_000_000},
                start_boundary=fixture.boundary(start, ingress),
                deadline_monotonic_ns=start + 10_000_000_000,
            )
            template = copy.deepcopy(next(r for r in fixture.rows if r["node_id"] == 2))
            fixture.rows = []
            for index in range(120):
                row = copy.deepcopy(template)
                row.update(
                    session_id=capture_id,
                    capture_id=capture_id,
                    capture_sequence=index + 1,
                    ingress_sequence=ingress + index + 1,
                    sequence=number * 120 + index,
                    received_at_ns=fixture.base
                    + start
                    + 1_000_000
                    + index * 50_000_000,
                    received_monotonic_ns=start + 1_000_000 + index * 50_000_000,
                    iq=[10 + index // 5, 0] * 64,
                )
                fixture.rehash_packet(row)
                fixture.rows.append(row)
            for key in (
                "session_id",
                "capture_id",
                "node_ids",
                "limits",
                "start_boundary",
                "deadline_monotonic_ns",
                "worker_start_clock",
            ):
                fixture.terminal[key] = copy.deepcopy(fixture.opening[key])
            fixture.terminal.update(
                end_boundary=fixture.boundary(start + 6_000_000_000, ingress + 120),
                writer_finished_clock=fixture.clock(start + 6_010_000_000),
            )
            fixture.terminal["counters"].update(admitted=120, enqueued=120, written=120)
            fixture.terminal["raw"]["frames"] = 120
            fixture.manifest.update(session_id=capture_id, capture_id=capture_id)
            fixture.write_files()
            fixture.prepare_context()
            with fixture.context([2]) as (_, evidence):
                evidence = copy.deepcopy(evidence)
            alignment = make_alignment(
                test_capture_session.encoded(
                    measured_fixture(fixture.base, start - 2_000_000_000)
                ),
                test_capture_session.encoded(
                    measured_fixture(fixture.base, start + 8_000_000_000)
                ),
                evidence,
                between_probe_allowance_ns=1_000_000,
                assumption_reference="synthetic explicit timing fixture, not clock calibration",
            )
            builder = WindowBuilder(
                duration_ms=200, min_frames=3, profiles=[profile(2)]
            )
            legacy_builder = WindowBuilder(
                duration_ms=200, min_frames=3, profiles=[profile(2)]
            )
            windows = 0
            for row in fixture.rows:
                old_row = {
                    k: v
                    for k, v in row.items()
                    if k
                    not in (
                        "capture_id",
                        "worker_run_id",
                        "capture_sequence",
                        "ingress_sequence",
                    )
                }
                old_row["schema"] = "ruview.csi.frame.v1"
                old = legacy_builder.push(old_row)
                value = builder.push(row)
                if value is None:
                    self.assertIsNone(old)
                    continue
                self.assertEqual(features(value), features(old))
                original = label(value, "standing" if windows % 2 else "seated")
                original.update(
                    schema="ruview.ground_truth.v2",
                    capture_id=capture_id,
                    worker_run_id=evidence["worker_run_id"],
                    clock_id=evidence["clock_id"],
                    start_ns=value["timestamps_ns"][0]
                    - alignment["label_to_csi_clock_offset_ns"]
                    - 30_000_000,
                    end_ns=value["timestamps_ns"][-1]
                    - alignment["label_to_csi_clock_offset_ns"]
                    + 30_000_000,
                    time_uncertainty_ns=10_000_000,
                    reference_lineage={
                        "opening_sha256": evidence["opening_sha256"],
                        "metadata_sha256": "d" * 64,
                        "review_sha256": "e" * 64,
                        "label_clock": LOCAL,
                        "clock_offset_applied": False,
                    },
                )
                adjusted = align_label(
                    original,
                    alignment,
                    evidence,
                    expected_coordinate_frame="example_lab_xz_metres",
                )
                paired = pair_window(
                    value,
                    [adjusted],
                    alignment["label_to_csi_clock_offset_ns"],
                    100_000_000,
                    expected_coordinate_frame="example_lab_xz_metres",
                )
                self.assertIsNotNone(paired)
                paired.update(
                    capture_evidence=evidence,
                    original_label=original,
                    time_alignment=alignment,
                )
                validate_paired_alignment(
                    paired, expected_coordinate_frame="example_lab_xz_metres"
                )
                records.append(paired)
                windows += 1
            self.assertEqual(windows, 24)
        original_digest = digest(records)
        fitted = train(
            records,
            "posture",
            [captures[1]],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertEqual(digest(records), original_digest)
        self.assertEqual(fitted["dataset_sha256"], original_digest)
        self.assertEqual(fitted["training_sessions"], [captures[0]])
        self.assertEqual(fitted["evaluation_sessions"], [captures[1]])
        self.assertEqual(fitted["training_windows"], 24)
        self.assertEqual(fitted["evaluation_windows"], 24)
        self.assertEqual(fitted["classes"], ["seated", "standing"])
        self.assertEqual(fitted["status"], "candidate_unqualified")
        self.assertFalse(fitted["publish_to_ha"])
        lineage = fitted["capture_lineage"]
        self.assertEqual(lineage["schema"], "ruview.csi.capture_lineage.v2")
        self.assertEqual(lineage["status"], "verified_closed_capture")
        self.assertEqual(
            [r["capture_id"] for r in lineage["recordings"]], list(captures)
        )
        self.assertEqual(len({r["worker_run_id"] for r in lineage["recordings"]}), 1)
        self.assertTrue(all(r["synthetic_only"] for r in lineage["recordings"]))
        validate_model(fitted, expected_coordinate_frame="example_lab_xz_metres")
        record = records[-1]
        prediction = predict(
            fitted,
            record["window"],
            record["capture_evidence"],
            expected_coordinate_frame="example_lab_xz_metres",
        )
        self.assertIn(prediction["prediction"], fitted["classes"])
        self.assertEqual(prediction["model_capture_lineage"], lineage)
        self.assertFalse(prediction["publish_to_ha"])
        self.assertIsNone(prediction["confidence"])
        self.assertEqual(prediction["validation"], "unverified")
        with self.assertRaisesRegex(ValueError, "capture modes"):
            predict(
                fitted,
                record["window"],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        wrong_class = {**record["capture_evidence"], "synthetic_only": False}
        with self.assertRaisesRegex(ValueError, "classification"):
            predict(
                fitted,
                record["window"],
                wrong_class,
                expected_coordinate_frame="example_lab_xz_metres",
            )
        with self.assertRaises(ValueError):
            predict(
                fitted,
                legacy_window(),
                record["capture_evidence"],
                expected_coordinate_frame="example_lab_xz_metres",
            )
        self.assertEqual(
            digest(features(legacy_window())),
            "086b5315eacda12f63092c45a8a6b41d1c9956f9c4820971bcf19d6d5e6323a7",
        )


if __name__ == "__main__":
    unittest.main()
