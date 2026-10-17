"""Synthetic input documents; never represent observed occupants or live activity."""

import json
from pathlib import Path

BASE_NS = 1_790_000_000_000_000_000
FIXTURES = Path(__file__).parent / "fixtures"


def config(short=True):
    value = json.loads((FIXTURES / "assumed-activity.config.json").read_text())
    if short:
        value["policy"] = {"min_baseline_samples": 3, "min_baseline_seconds": 2}
    return value


def inputs(index, values=(10, 10, 10)):
    now = BASE_NS + index * 1_000_000_000
    worker = {
        "schema": "ruview.server-modules.v1",
        "recognition_validated": False,
        "worker_run_id": "synthetic-worker-not-live",
        "configuration_sha256": "a" * 64,
        "clock_id": "synthetic-clock-not-live",
        "generated_at_ns": str(now),
        "nodes": [
            {
                "node_id": node,
                "grid": {
                    "antennas": 1,
                    "subcarriers": 64,
                    "ppdu_type": 0,
                    "flags": 16,
                    "frequency_mhz": 2462,
                },
                "node_epoch": 1,
                "epoch_reason": "first_frame",
                "sequence_discontinuities": 0,
                "fresh": True,
                "age_ms": 10,
                "last_received_at_ns": str(now - 10_000_000),
                "last_received_monotonic_ns": str((index + 1) * 1_000_000_000),
                "sequence": 1000 + index * 30,
            }
            for node in (1, 2, 3)
        ],
    }
    sensing = {
        "source": "esp32",
        "type": "sensing_update",
        "timestamp": now / 1e9,
        "node_features": [
            {
                "node_id": node,
                "stale": False,
                "last_seen_ms": 10,
                "frame_rate_hz": 30,
                "features": {"motion_band_power": value, "variance": value},
            }
            for node, value in zip((1, 2, 3), values, strict=True)
        ],
    }
    return {"status": "ok"}, worker, sensing, now, float(index)
