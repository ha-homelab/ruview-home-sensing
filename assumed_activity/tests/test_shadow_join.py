import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from assumed_activity import shadow_join as joiner
from assumed_activity import training_journal as journal

BOOT = "73d1bc57-d6da-4b4c-9c32-aeab881e8915"
UTC = 2_000_000_000_000_000_000
LEGACY = {
    "name": "legacy-rssi",
    "version": 1,
    "features": ["node_7_rssi_dbm"],
    "identity": {"source": "test"},
}


def observation(index=1, epoch=1, reason="first_frame"):
    return {
        "schema": journal.SCHEMA,
        "kind": "observation",
        "index": index,
        "run_id": "shadow-run",
        "configuration_sha256": "c" * 64,
        "monotonic_ns": index * 1_000_000_000,
        "utc_ns": UTC + index * 1_000_000_000,
        "captured_at_utc": journal.utc(UTC + index * 1_000_000_000),
        "clock_epoch": 0,
        "late_interval": False,
        "nodes": [
            {
                "node_id": 7,
                "available": True,
                "features": {"motion_band_power": 3.0, "variance": 7.0},
                "collector_diagnostics": {
                    "subcarrier_count": 64,
                    "frequency_mhz": None,
                    "channel": None,
                },
                "worker": {
                    "worker_run_id": "worker-a",
                    "configuration_sha256": "a" * 64,
                    "clock_id": "clock-a",
                    "schema_valid": True,
                    "grid": {
                        "antennas": 1,
                        "subcarriers": 64,
                        "flags": 16,
                        "ppdu_type": 0,
                        "frequency_mhz": 2437,
                    },
                    "node_epoch": epoch,
                    "epoch_reason": reason,
                    "sequence_discontinuities": 0,
                },
                "native_profile_compatible": True,
                "receiver_proof": None,
            }
        ],
    }


def example():
    instant = journal.utc(UTC + 2_000_000_000)
    return {
        "schema": "ruview.shadow-motion-example.v1",
        "example_id": "reference-1",
        "observed_at_utc": instant,
        "interval_start_utc": instant,
        "interval_end_utc": instant,
        "feature_contract": copy.deepcopy(LEGACY),
        "features": {"node_7_rssi_dbm": -50},
        "quality": {"eligible": True, "reasons": []},
        "maintenance_excluded": False,
        "references": [
            {
                "source_group": "independent-test",
                "independent": True,
                "derived_from_ruview": False,
                "kind": "motion",
                "state": "on",
                "available": True,
                "observed_at_utc": instant,
            }
        ],
        "provenance": {
            "capture_metadata_sha256": "m" * 64,
            "receipt_monotonic_ns": 2_000_000_000,
            "capture_run_id": "reference-run",
            "transport_confirmed_at_utc": instant,
        },
    }


def config():
    return {
        "schema": "ruview.shadow-join-config.v1",
        "expected_boot_id": BOOT,
        "expected_clock_epoch": 0,
        "node_ids": [7],
        "feature_keys": ["motion_band_power", "variance"],
        "expected_profiles": {"7": joiner.profile_identity(observation()["nodes"][0])},
        "journal_metadata_sha256": "b" * 64,
        "reference_feature_contract_sha256": joiner.sha(LEGACY),
        "max_lag_seconds": 1.5,
        "max_clock_disagreement_ms": 100,
    }


def joined(observations=None, references=None, settings=None, boot=BOOT):
    return joiner.join(
        references or [example()],
        observations or [observation()],
        {"m" * 64: {"boot_id": BOOT, "run_id": "reference-run"}},
        {"boot_id": boot, "monotonic_clock": "CLOCK_MONOTONIC"},
        settings or config(),
    )


class JoinTests(unittest.TestCase):
    def test_stream_failure_after_last_join_still_fails_the_export(self):
        def records():
            yield observation()
            yield observation(3)
            raise ValueError("late source verification failed")

        with self.assertRaisesRegex(ValueError, "late source"):
            joined(records())

    def test_previous_sample_preserves_references_and_lineages(self):
        original = example()
        rows, receipt = joined(references=[original])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["references"], original["references"])
        self.assertEqual(
            rows[0]["features"],
            {"node_7_motion_band_power": 3.0, "node_7_variance": 7.0},
        )
        self.assertEqual(rows[0]["provenance"]["feature_lag_ns"], 1_000_000_000)
        self.assertEqual(
            rows[0]["provenance"]["original_reference_example_sha256"],
            joiner.sha(original),
        )
        self.assertFalse(rows[0]["provenance"]["native_profile_qualified"])
        self.assertFalse(receipt["publish_to_ha"])

    def test_future_or_old_observations_never_fill_a_gap(self):
        for value, expected in (
            (3, "no_earlier_feature_observation"),
            (0, "feature_observation_too_old"),
        ):
            rows, receipt = joined([observation(index=value)])
            self.assertEqual(rows, [])
            self.assertEqual(receipt["discarded"], {expected: 1})

    def test_gap_and_clock_epoch_reject_latest_without_falling_back(self):
        for key, value in (
            ("late_interval", True),
            ("_index_gap", True),
            ("clock_epoch", 1),
        ):
            later = observation(index=2)
            later[key] = value
            rows, _ = joined([observation(), later])
            self.assertEqual(rows, [])

    def test_boot_mismatch_is_a_hard_error(self):
        with self.assertRaisesRegex(ValueError, "journal_boot_mismatch"):
            joined(boot="bde14e34-94d0-40c9-bd0a-a2c102369f29")
        settings = config()
        settings["expected_boot_id"] = "unknown"
        with self.assertRaisesRegex(ValueError, "shared_boot"):
            joined(settings=settings)

    def test_wall_clock_disagreement_rejected(self):
        row = observation()
        row["utc_ns"] += 900_000_000
        rows, receipt = joined([row])
        self.assertEqual(rows, [])
        self.assertIn("wall_monotonic_alignment_disagrees", receipt["discarded"])

    def test_profile_changes_and_missing_features_rejected(self):
        changed = observation()
        changed["nodes"][0]["worker"]["grid"]["frequency_mhz"] = 2462
        self.assertEqual(joined([changed])[0], [])
        changed = observation()
        del changed["nodes"][0]["features"]["variance"]
        self.assertEqual(joined([changed])[0], [])
        changed["nodes"][0]["features"]["variance"] = float("nan")
        self.assertEqual(joined([changed])[0], [])

    def test_bounded_history_epoch_renewal_is_not_a_radio_change(self):
        rows, _ = joined(
            [observation(), observation(2, epoch=2, reason="bounded_history_renewal")]
        )
        self.assertEqual(len(rows), 1)
        rows, receipt = joined(
            [observation(), observation(2, epoch=2, reason="grid_changed")]
        )
        self.assertEqual(rows, [])
        self.assertIn("node_epoch_requires_new_binding", receipt["discarded"])

    def test_explicit_unknown_native_profile_does_not_invent_qualification(self):
        row = observation()
        row["nodes"][0]["worker"]["grid"] = {"flags": None}
        row["nodes"][0]["native_profile_compatible"] = None
        settings = config()
        settings["expected_profiles"]["7"] = joiner.profile_identity(row["nodes"][0])
        rows, _ = joined([row], settings=settings)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["provenance"]["native_profile_qualified"])


class PrefixTests(unittest.TestCase):
    def test_reference_export_rechecks_original_prefix_and_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, source = root / "export", root / "source"
            export.mkdir()
            segment = source / "segment-test"
            segment.mkdir(parents=True)
            meta = {
                "schema": "ruview.ha-reference-capture.v1",
                "run_id": "reference-run",
                "boot_id": BOOT,
            }
            raw_meta = joiner.canonical(meta)
            (segment / "metadata.json").write_bytes(raw_meta)
            original = b'{"test":"verified-prefix"}\n'
            part = segment / "events-0000.jsonl"
            part.write_bytes(original)
            row = example()
            row["provenance"]["capture_metadata_sha256"] = hashlib.sha256(
                raw_meta
            ).hexdigest()
            payload = joiner.canonical(row) + b"\n"
            (export / "examples.jsonl").write_bytes(payload)
            receipt = {
                "schema": "ruview.shadow-legacy-export.v1",
                "rows": 1,
                "examples_sha256": hashlib.sha256(payload).hexdigest(),
                "prefixes": [
                    {
                        "segment": segment.name,
                        "part": part.name,
                        "prefix_bytes": len(original),
                        "prefix_sha256": hashlib.sha256(original).hexdigest(),
                    }
                ],
            }
            (export / "receipt.json").write_bytes(joiner.canonical(receipt))
            rows, metadata, _ = joiner.reference_export(export, source)
            self.assertEqual(rows, [row])
            self.assertEqual(
                metadata[row["provenance"]["capture_metadata_sha256"]], meta
            )
            part.write_bytes(original.replace(b"verified", b"modified"))
            with self.assertRaisesRegex(ValueError, "source_prefix_mismatch"):
                joiner.reference_export(export, source)

    def test_active_complete_prefix_is_verified_without_consuming_partial_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = {"example": True}
            meta = {
                "schema": "ruview.shadow-journal.v1",
                "run_id": "shadow-run",
                "configuration": cfg,
                "configuration_sha256": joiner.sha(cfg),
                "boot_id": BOOT,
                "monotonic_clock": "CLOCK_MONOTONIC",
            }
            raw_meta = joiner.canonical(meta)
            (root / "metadata.json").write_bytes(raw_meta)
            (root / "status.json").write_text('{"closed_parts": []}')
            row = observation()
            row["configuration_sha256"] = meta["configuration_sha256"]
            complete = joiner.canonical(row) + b"\n"
            (root / "observations-0000.jsonl").write_bytes(complete + b'{"partial":')
            rows, actual_meta, receipt = joiner.journal_export(
                root, hashlib.sha256(raw_meta).hexdigest()
            )
            rows = list(rows)
            self.assertEqual(len(rows), 1)
            self.assertTrue(receipt["verification_complete"])
            self.assertEqual(actual_meta, meta)
            self.assertTrue(receipt["provisional"])
            self.assertEqual(
                receipt["prefixes"][0]["prefix_sha256"],
                hashlib.sha256(complete).hexdigest(),
            )
            self.assertEqual(receipt["prefixes"][0]["prefix_bytes"], len(complete))

    def test_wrong_metadata_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "metadata.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "metadata_hash"):
                joiner.journal_export(root, "0" * 64)


if __name__ == "__main__":
    unittest.main()
