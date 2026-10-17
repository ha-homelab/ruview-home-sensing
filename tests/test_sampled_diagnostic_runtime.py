"""Pure synthetic sampling and fake HTTP tests; no live service/device actions."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import module_observations as modules

SPEC = importlib.util.spec_from_file_location(
    "sampled_runtime",
    Path(__file__).resolve().parents[1] / "scripts/sample-server-modules.py",
)
sampler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sampler)


def snapshot(
    index,
    *,
    epoch=1,
    epoch_frames=None,
    reason="first_frame",
    missing=0,
    running=True,
    queue=0,
):
    mono = 10_000_000_000 + index * 1_000_000_000
    utc = 1_790_000_000_000_000_000 + mono
    total = 100 + index * 32 - missing
    return {
        "schema": "ruview.server-modules.v1",
        "worker_run_id": "synthetic-run",
        "clock_id": "synthetic-boot/synthetic-run",
        "configuration_sha256": "a" * 64,
        "generated_at_ns": str(utc + 10_000_000),
        "monotonic_origin": "worker_start",
        "recognition_validated": False,
        "freshness_limit_ms": 2000,
        "catalog_count": 64,
        "selected_algorithm_count": 21,
        "events": [],
        "counters": {
            **dict.fromkeys(sampler.COUNTERS, 0),
            "received": 3 * total,
            "queue_dropped": queue,
        },
        "nodes": [
            {
                "node_id": n,
                "node_epoch": epoch,
                "epoch_reason": reason,
                "epoch_frames": total if epoch_frames is None else epoch_frames,
                "sequence": 100 + index * 32,
                "fresh": True,
                "age_ms": 10,
                "last_received_monotonic_ns": str(mono),
                "last_received_at_ns": str(utc),
                "grid": {
                    "antennas": 1,
                    "subcarriers": 64,
                    "frequency_mhz": 2462,
                    "ppdu_type": 0,
                    "flags": 16,
                },
                "frames": total,
                "duplicates": 0,
                "missing_sequences": missing,
                "sequence_discontinuities": 0,
                "algorithms": [
                    {
                        "algorithm": f"synthetic-{a}",
                        "algorithm_version": "synthetic1",
                        "source_sha256": "b" * 64,
                        "availability": ("running" if running else "warming_up")
                        if a < 21
                        else "unavailable",
                        "reason": "synthetic_fixture_only",
                        "processed_frames": index + 1 if running and a < 21 else 0,
                        "emitted_events": 0,
                        "max_execution_us": 5 if running and a < 21 else 0,
                    }
                    for a in range(64)
                ],
            }
            for n in (1, 2, 3)
        ],
    }


def catalog_pin():
    identities = sorted(
        (a["algorithm"], a["algorithm_version"], a["source_sha256"])
        for a in snapshot(0)["nodes"][0]["algorithms"]
    )
    return hashlib.sha256(
        json.dumps(identities, separators=(",", ":")).encode()
    ).hexdigest()


def assessment():
    return sampler.Assessment(
        "synthetic-run", "synthetic-boot/synthetic-run", "a" * 64, catalog_pin()
    )


def push(a, value, index, *, core=None):
    try:
        decoded = modules.decode(value, int(value["generated_at_ns"]))
        current = modules.current(
            decoded,
            0,
            core
            if core is not None
            else {n: {"csi_age_ms": 10, "inference_age_ms": 10} for n in (1, 2, 3)},
        )
        return a.push(value, decoded, current, index)
    except Exception as error:
        return {"contract_pass": False, "failure": a.failed(index, error)}


class AssessmentTests(unittest.TestCase):
    def test_stable_scope_and_historical_queue_baseline_never_prove_continuity(self):
        a = assessment()
        for i in range(3):
            self.assertTrue(push(a, snapshot(i, queue=1), i)["contract_pass"])
        r = a.finish(3, True)
        self.assertTrue(r["sampled_diagnostic_execution"])
        self.assertEqual(r["worker_counters"]["baseline"]["queue_dropped"], 1)
        self.assertEqual(r["worker_counters"]["delta"]["queue_dropped"], 0)
        self.assertFalse(r["continuity_proven"])
        self.assertFalse(r["strict_qualification_pass"])
        self.assertFalse(r["all_selected_algorithms_running_claim"])

    def test_hidden_gap_is_recorded_and_recovery_needs_new_closing_pair(self):
        a = assessment()
        push(a, snapshot(0), 0)
        push(a, snapshot(1), 1)
        row = push(
            a,
            snapshot(
                2,
                epoch=3,
                epoch_frames=7,
                reason="sequence_gap",
                missing=2,
                running=False,
            ),
            2,
        )
        self.assertTrue(row["contract_pass"])
        self.assertEqual(row["nodes"]["2"]["unobserved_epoch_transitions"], 1)
        self.assertFalse(row["nodes"]["2"]["transition_reasons_qualified"])
        self.assertFalse(a.finish(3, True)["sampled_diagnostic_execution"])
        push(
            a,
            snapshot(
                3,
                epoch=3,
                epoch_frames=39,
                reason="sequence_gap",
                missing=2,
                running=False,
            ),
            3,
        )
        push(
            a,
            snapshot(4, epoch=3, epoch_frames=71, reason="sequence_gap", missing=2),
            4,
        )
        self.assertFalse(a.finish(5, True)["sampled_diagnostic_execution"])
        push(
            a,
            snapshot(5, epoch=3, epoch_frames=103, reason="sequence_gap", missing=2),
            5,
        )
        result = a.finish(6, True)
        self.assertTrue(result["sampled_diagnostic_execution"])
        self.assertEqual(
            result["per_node"]["2"]["state_sample_counts"]["warming_up"], 2
        )
        self.assertEqual(result["per_node"]["2"]["unobserved_epoch_transitions"], 1)
        self.assertFalse(result["unobserved_transitions_qualified"])

    def test_stale_withdrawal_is_retained_and_breaks_running_streak(self):
        a = assessment()
        push(a, snapshot(0), 0)
        push(a, snapshot(1), 1, core={1: {"csi_age_ms": 2001, "inference_age_ms": 10}})
        r = a.finish(2, True)
        self.assertTrue(r["contract_pass"])
        self.assertFalse(r["closing_all_nodes_fresh_running"])
        for n in ("1", "2", "3"):
            self.assertEqual(r["per_node"][n]["closing_running_advancing_streak"], 0)
        push(a, snapshot(2), 2)
        self.assertFalse(a.finish(3, True)["sampled_diagnostic_execution"])
        push(a, snapshot(3), 3)
        self.assertTrue(a.finish(4, True)["sampled_diagnostic_execution"])

    def test_cached_repetitions_and_closing_warmup_cannot_qualify(self):
        a = assessment()
        for i in range(3):
            push(a, snapshot(0), i)
        self.assertFalse(a.finish(3, True)["sampled_diagnostic_execution"])
        a = assessment()
        push(a, snapshot(0), 0)
        push(a, snapshot(1), 1)
        push(
            a,
            snapshot(
                2,
                epoch=2,
                epoch_frames=3,
                reason="sequence_gap",
                missing=1,
                running=False,
            ),
            2,
        )
        self.assertFalse(a.finish(3, True)["sampled_diagnostic_execution"])

    def test_observed_fault_and_new_drop_are_latched_across_recovery(self):
        for kind in ("fault", "overrun", "drop"):
            with self.subTest(kind=kind):
                a = assessment()
                push(a, snapshot(0, queue=1), 0)
                value = snapshot(1, queue=2 if kind == "drop" else 1)
                if kind == "fault":
                    value["nodes"][0]["algorithms"][0]["availability"] = "faulted"
                elif kind == "overrun":
                    value["nodes"][0]["algorithms"][0]["max_execution_us"] = 50001
                push(a, value, 1)
                for i in (2, 3):
                    push(a, snapshot(i, queue=2 if kind == "drop" else 1), i)
                r = a.finish(4, True)
                self.assertFalse(r["sampled_diagnostic_execution"])
                if kind != "drop":
                    self.assertTrue(r["any_observed_faults"])
                else:
                    self.assertEqual(r["worker_counters"]["delta"]["queue_dropped"], 1)

    def test_wrong_identity_schema_catalog_grid_clock_and_accounting_latch(self):
        mutations = [
            lambda v: v.update(worker_run_id="other"),
            lambda v: v.update(configuration_sha256="c" * 64),
            lambda v: v.update(selected_algorithm_count=20),
            lambda v: v.update(catalog_count=True),
            lambda v: v["nodes"].append(copy.deepcopy(v["nodes"][0])),
            lambda v: v["nodes"][0]["algorithms"][0].update(source_sha256="c" * 64),
            lambda v: v["nodes"][0]["grid"].update(frequency_mhz=2412),
            lambda v: v["nodes"][0].update(last_received_at_ns="1790000015000000000"),
            lambda v: v["nodes"][0].update(sequence=99),
            lambda v: v["nodes"][0].update(frames=101),
            lambda v: v["nodes"][0].update(sequence_discontinuities=1),
            lambda v: v["nodes"][0].update(node_epoch=2, epoch_reason="grid_changed"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                a = assessment()
                push(a, snapshot(0), 0)
                value = snapshot(1)
                mutate(value)
                row = push(a, value, 1)
                self.assertFalse(row["contract_pass"])
                push(a, snapshot(2), 2)
                push(a, snapshot(3), 3)
                self.assertFalse(a.finish(4, True)["contract_pass"])
                self.assertFalse(a.finish(4, True)["sampled_diagnostic_execution"])

    def test_consistently_substituted_opening_catalog_does_not_become_trusted(self):
        a = assessment()
        for i in range(2):
            value = snapshot(i)
            for n in value["nodes"]:
                n["algorithms"][0]["source_sha256"] = "c" * 64
            self.assertFalse(push(a, value, i)["contract_pass"])
        self.assertFalse(a.finish(2, True)["sampled_diagnostic_execution"])

    def test_wrap_is_valid_but_incomplete_capture_cannot_pass(self):
        a = assessment()
        for i in range(2):
            value = snapshot(i)
            for n in value["nodes"]:
                n["sequence"] = (2**32 - 10 + i * 32) % 2**32
            self.assertTrue(push(a, value, i)["contract_pass"])
        self.assertFalse(a.finish(2, False)["sampled_diagnostic_execution"])
        self.assertTrue(a.finish(2, True)["sampled_diagnostic_execution"])


class CollectionTests(unittest.TestCase):
    def test_same_sample_fixture_and_elapsed_lease_withdrawal(self):
        value = snapshot(0)
        base = int(value["generated_at_ns"])
        context = {
            "worker": "http://worker",
            "collector": "http://collector",
            "token": "secret",
            "assessment": assessment(),
            "placements": {n: {} for n in (1, 2, 3)},
            "start_wall_ns": base,
            "start_mono_ns": 10_000_000_000,
        }
        clock = [10.0]

        def get(_base, path, token, _deadline, stamps):
            stamps.append({"endpoint": path})
            if path == "/v1/latest":
                self.assertIsNone(token)
                return value
            if path == "/health":
                return {
                    "status": "ok",
                    "recognition_validated": False,
                    "source": "esp32",
                }
            self.assertEqual(token, "secret")
            return {"source": "esp32", "nodes": [{"node_id": n} for n in (1, 2, 3)]}

        core = {n: {"csi_age_ms": 10, "inference_age_ms": 10} for n in (1, 2, 3)}
        with (
            patch.object(sampler, "get", get),
            patch.object(sampler, "observations", return_value=core),
            patch.object(sampler.time, "monotonic", lambda: clock[0]),
            patch.object(sampler.time, "monotonic_ns", lambda: int(clock[0] * 1e9)),
            patch.object(
                sampler.time, "time_ns", lambda: base + int((clock[0] - 10) * 1e9)
            ),
        ):
            row = sampler.collect_sample(0, context, 100)
        self.assertTrue(row["contract_pass"])
        self.assertIs(row["worker_fixture"], value)
        for candidate in row["ha_candidate_fixture"]:
            self.assertEqual(candidate["attributes"]["sequence"], 100)
            self.assertEqual(
                candidate["attributes"]["published_at_ns"],
                row["ha_candidate_created_at_ns"],
            )

        # Advancing local time during later GETs must age the original snapshot,
        # rather than stamp the old worker response fresh at candidate creation.
        def delayed_get(*args):
            result = get(*args)
            if args[1] == "/api/v1/sensing/latest":
                clock[0] += 2.1
            return result

        context["assessment"] = assessment()
        with (
            patch.object(sampler, "get", delayed_get),
            patch.object(sampler, "observations", return_value=core),
            patch.object(sampler.time, "monotonic", lambda: clock[0]),
            patch.object(sampler.time, "monotonic_ns", lambda: int(clock[0] * 1e9)),
            patch.object(
                sampler.time, "time_ns", lambda: base + int((clock[0] - 10) * 1e9)
            ),
        ):
            row = sampler.collect_sample(0, context, 100)
        self.assertTrue(row["contract_pass"])
        self.assertEqual(row["ha_candidate_fixture"], [])
        self.assertTrue(all(n["withdrawal_observed"] for n in row["nodes"].values()))

    def test_fixed_ninety_samples_do_not_retry_or_extend_after_failure(self):
        calls = []

        def collect(i, ctx, _deadline):
            calls.append(i)
            if i == 2:
                return {
                    "sample_index": i,
                    "failure": ctx["assessment"].failed(
                        i, sampler.GateError("Synthetic failure")
                    ),
                }
            return {"sample_index": i, **push(ctx["assessment"], snapshot(i), i)}

        env = {
            "RUVIEW_NODE_IDS": "1,2,3",
            "RUVIEW_NODE_PLACEMENTS": "{}",
            "RUVIEW_API_TOKEN": "test-secret",
        }
        args = [
            "sample",
            "--expected-worker-run-id",
            "synthetic-run",
            "--expected-clock-id",
            "synthetic-boot/synthetic-run",
            "--expected-config-sha256",
            "a" * 64,
            "--expected-catalog-sha256",
            catalog_pin(),
        ]
        out = io.StringIO()
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(
                sampler, "node_placements", return_value={n: {} for n in (1, 2, 3)}
            ),
            patch.object(sampler, "collect_sample", collect),
            patch.object(sampler.signal, "signal"),
            patch.object(sampler.signal, "setitimer"),
            patch.object(sampler.time, "sleep"),
            patch("sys.argv", args),
            redirect_stdout(out),
        ):
            code = sampler.main()
        result = json.loads(out.getvalue())
        self.assertEqual(calls, list(range(90)))
        self.assertEqual(code, 1)
        self.assertTrue(result["capture_complete"])
        self.assertFalse(result["contract_pass"])
        self.assertFalse(result["sampled_diagnostic_execution"])
        self.assertNotIn("test-secret", out.getvalue())

    def test_deadline_preserves_streamed_prefix_and_cannot_claim_completion(self):
        calls = []

        def collect(i, ctx, _deadline):
            calls.append(i)
            if i == 3:
                raise sampler.CaptureDeadline()
            return {"sample_index": i, **push(ctx["assessment"], snapshot(i), i)}

        env = {
            "RUVIEW_NODE_IDS": "1,2,3",
            "RUVIEW_NODE_PLACEMENTS": "{}",
            "RUVIEW_API_TOKEN": "secret",
        }
        args = [
            "sample",
            "--expected-worker-run-id",
            "synthetic-run",
            "--expected-clock-id",
            "synthetic-boot/synthetic-run",
            "--expected-config-sha256",
            "a" * 64,
            "--expected-catalog-sha256",
            catalog_pin(),
        ]
        out = io.StringIO()
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(
                sampler, "node_placements", return_value={n: {} for n in (1, 2, 3)}
            ),
            patch.object(sampler, "collect_sample", collect),
            patch.object(sampler.signal, "signal"),
            patch.object(sampler.signal, "setitimer"),
            patch.object(sampler.time, "sleep"),
            patch("sys.argv", args),
            redirect_stdout(out),
        ):
            code = sampler.main()
        result = json.loads(out.getvalue())
        self.assertEqual(calls, [0, 1, 2, 3])
        self.assertEqual(len(result["samples"]), 3)
        self.assertFalse(result["capture_complete"])
        self.assertFalse(result["sampled_diagnostic_execution"])
        self.assertEqual(code, 1)
        self.assertIn("sampled_duration_s", result)

    def test_failed_preflight_makes_no_requests_and_retains_failure(self):
        out = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.argv", ["sample"]),
            patch.object(sampler, "get") as get,
            redirect_stdout(out),
        ):
            self.assertEqual(sampler.main(), 1)
        get.assert_not_called()
        r = json.loads(out.getvalue())
        self.assertFalse(r["capture_complete"])
        self.assertFalse(r["sampled_diagnostic_execution"])

    def test_bounded_get_auth_no_redirect_truncation_and_overflow(self):
        class Response:
            status, length = 200, 2

            def read1(self, _n):
                return b"{}"

            def isclosed(self):
                return True

        instances = []

        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.sock, self.closed = self, False
                instances.append(self)

            def connect(self):
                pass

            def settimeout(self, value):
                self.timeout = value

            def request(self, method, path, headers):
                self.requested = (method, path, headers)

            def getresponse(self):
                return Response()

            def close(self):
                self.closed = True

        with patch.object(sampler.http.client, "HTTPConnection", Connection):
            stamps = []
            self.assertEqual(
                sampler.get(
                    "http://worker",
                    "/v1/latest",
                    None,
                    sampler.time.monotonic() + 9,
                    stamps,
                ),
                {},
            )
            self.assertEqual(instances[-1].requested, ("GET", "/v1/latest", {}))
            self.assertEqual(stamps[0]["response_bytes"], 2)
            self.assertTrue(instances[-1].closed)
            Response.status = 302
            with self.assertRaises(sampler.GateError):
                sampler.get(
                    "http://worker",
                    "/v1/latest",
                    None,
                    sampler.time.monotonic() + 9,
                    [],
                )
            Response.status, Response.length = 200, 3
            with self.assertRaises(sampler.GateError):
                sampler.get(
                    "http://worker",
                    "/v1/latest",
                    None,
                    sampler.time.monotonic() + 9,
                    [],
                )
        for bad in (b'{"v":1e309}', b'{"v":NaN}', b'{"v":1,"v":2}'):
            with self.assertRaises(sampler.GateError):
                sampler.strict_json(bad)


if __name__ == "__main__":
    unittest.main()
