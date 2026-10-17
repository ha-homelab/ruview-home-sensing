"""Synthetic receiver epochs; no device requests or occupied-room claims."""

import copy
import unittest
from unittest.mock import MagicMock, patch

from assumed_activity import service
from assumed_activity.core import Producer, digest
from assumed_activity.proofs import (
    MAX_PROOF_BYTES,
    ReceiverProofs,
    configuration,
    continuous,
    observation,
)
from assumed_activity.tests.helpers import BASE_NS, config, inputs

# Independent fictional test installation, never a production fallback.
RECEIVERS = {
    1: ("192.168.50.101", "02:00:00:00:00:01"),
    2: ("192.168.50.102", "02:00:00:00:00:02"),
    3: ("192.168.50.103", "02:00:00:00:00:03"),
}


def identities():
    return {
        "schema": "ruview.assumed-activity.receiver-identities.v1",
        "receivers": [
            {"node_id": n, "ip": ip, "station_mac": mac}
            for n, (ip, mac) in RECEIVERS.items()
        ],
    }


APPROVED_IDENTITIES_SHA256 = digest(identities())


def reading(node, index, nonce="a" * 32, bssid="02:ac:de:77:00:03", channel=11):
    return {
        "started": index + 0.1,
        "finished": index + 0.2,
        "started_at_ns": BASE_NS + index * 10**9 + 100_000_000,
        "finished_at_ns": BASE_NS + index * 10**9 + 200_000_000,
        "document": {
            "runtime": {
                "boot_nonce_schema": "ruview.boot-nonce.v1",
                "boot_nonce": nonce,
                "station_mac": RECEIVERS[node][1],
                "uptime_ms": 100_150 + index * 1000,
            },
            "wifi": {
                "associated": True,
                "ap_info_error": 0,
                "bssid": bssid,
                "channel": channel,
            },
        },
    }


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.proofs = ReceiverProofs(
            identities(), (1, 2, 3), expected_sha256=APPROVED_IDENTITIES_SHA256
        )
        self.producer = Producer(
            config(),
            self.proofs.config_sha,
            expected_coordinate_frame=config()["coordinate_frame"],
        )

    def step(self, index, mutate_worker=None, mutate_readings=None, delay=0.2):
        h, w, s, now, _ = inputs(index)
        if mutate_worker:
            mutate_worker(w)
        reads = {n: reading(n, index) for n in RECEIVERS}
        if mutate_readings:
            mutate_readings(reads)
        contexts = self.proofs.resolve(w, reads, index + delay)
        return self.producer.update(
            h, w, s, now + int(delay * 1e9), index + delay, contexts
        )

    def ready(self):
        for i in range(5):
            value = self.step(i)
        self.assertEqual(value["state"], "quiet")

    def test_bootstrap_and_repeated_backward_counters_can_recover(self):
        first = self.step(0)
        self.assertEqual(first["state"], "unknown")
        self.assertFalse(self.producer.history)
        for i in range(1, 5):
            self.step(i)

        def counter(i):
            def mutate(w):
                for n in w["nodes"]:
                    n.update(
                        sequence_discontinuities=i - 4,
                        sequence=1000 - i,
                        node_epoch=i,
                        epoch_reason="sequence_backwards_boot_unknown",
                    )

            return mutate

        first_suspect = self.step(5, counter(5))
        self.assertEqual(first_suspect["state"], "unknown")
        count = len(self.producer.history[1]["samples"])
        for i in range(6, 40):
            result = self.step(i, counter(i))
            self.assertEqual(result["state"], "quiet", (i, result))
        self.assertEqual(len(self.producer.history[1]["samples"]), count + 34)
        self.assertEqual(
            result["effective_policy"],
            Producer(
                config(), expected_coordinate_frame=config()["coordinate_frame"]
            ).policy,
        )
        self.assertEqual(
            result["configuration_sha256"],
            Producer(
                config(), expected_coordinate_frame=config()["coordinate_frame"]
            ).config_sha,
        )

    def test_changed_boot_or_radio_reprime_and_never_reuse_old_baseline(self):
        for field in ("boot_nonce", "bssid", "channel"):
            with self.subTest(field=field):
                self.setUp()
                self.ready()

                def changed(reads, field=field):
                    target = reads[1]["document"]
                    if field == "boot_nonce":
                        target["runtime"][field] = "b" * 32
                    elif field == "bssid":
                        target["wifi"][field] = "02:ac:de:77:00:09"
                    else:
                        target["wifi"][field] = 6

                self.assertEqual(
                    self.step(5, mutate_readings=changed)["state"], "unknown"
                )

                def grid(w, field=field):
                    if field == "channel":
                        w["nodes"][0]["grid"]["frequency_mhz"] = 2437

                result = self.step(6, grid, changed)
                self.assertEqual(result["nodes"][0]["status"], "warming_up")
                self.assertEqual(len(self.producer.history[1]["samples"]), 1)

    def test_delayed_fresh_scalars_recover_with_continuous_burst_anchor(self):
        for delay in (1.2, 2.2):
            self.setUp()
            self.ready()
            for i in range(5, 65):
                h, w, s, now, _ = inputs(i)
                for row in w["nodes"]:
                    row.update(
                        sequence_discontinuities=i - 4,
                        sequence=1000 - i,
                        node_epoch=i,
                        epoch_reason="sequence_backwards_boot_unknown",
                        last_received_at_ns=str(now - int(delay * 1e9)),
                    )
                contexts = self.proofs.resolve(
                    w, {n: reading(n, i) for n in RECEIVERS}, i + 0.2
                )
                result = self.producer.update(
                    h, w, s, now + 200_000_000, i + 0.2, contexts
                )
                if i >= 8:
                    self.assertEqual(result["state"], "quiet", (i, delay, result))
            self.assertGreater(len(self.producer.history[1]["samples"]), 50)

    def test_proofs_never_bypass_other_reset_or_freshness_guards(self):
        mutations = [
            lambda w: w.update(worker_run_id="changed"),
            lambda w: w.update(clock_id="changed"),
            lambda w: w["nodes"][0].update(node_epoch=0),
            lambda w: w["nodes"][0].update(node_epoch=2, epoch_reason="receipt_gap"),
            lambda w: w["nodes"][0].update(last_received_monotonic_ns="1"),
        ]
        for mutation in mutations:
            self.setUp()
            self.ready()
            result = self.step(5, mutation)
            self.assertNotEqual(result["state"], "quiet")
        self.setUp()
        self.ready()
        result = self.step(5, delay=2.6)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(len(self.producer.history[1]["samples"]), 4)
        result = self.step(20)
        self.assertEqual(result["state"], "warming_up")

    def test_post_scalar_bracket_and_proof_failure_do_not_append(self):
        self.ready()

        def counter(w):
            for n in w["nodes"]:
                n.update(sequence_discontinuities=1)

        self.step(5, counter)
        count = len(self.producer.history[1]["samples"])

        def missing(reads):
            reads[1] = {}

        self.assertEqual(self.step(6, counter, missing)["state"], "unknown")
        self.assertEqual(len(self.producer.history[1]["samples"]), count)
        h, w, s, now, _ = inputs(7)
        counter(w)
        contexts = self.proofs.resolve(w, {n: reading(n, 7) for n in RECEIVERS}, 7.2)
        contexts[1]["bracket_after_ns"] = BASE_NS + 7 * 10**9
        value = self.producer.update(h, w, s, now + 200_000_000, 7.2, contexts)
        self.assertEqual(value["nodes"][0]["reason"], "scalar_outside_receiver_proofs")
        self.assertEqual(len(self.producer.history[1]["samples"]), count)

    def test_conflicting_sequence_resets_history_despite_verified_same_boot(self):
        self.ready()
        previous_generation = self.producer.history[1]["generation"]

        def conflict(worker):
            worker["nodes"][0].update(
                node_epoch=2,
                epoch_reason="sequence_conflict_boot_unknown",
                sequence_discontinuities=1,
            )

        # A new discontinuity still needs a second same-boot observation.
        first = self.step(5, conflict)
        self.assertEqual(first["nodes"][0]["reason"], "receiver_identity_priming")
        self.assertEqual(self.producer.history[1]["generation"], previous_generation)
        # The continuous proof permits known reordering, never conflicting bytes.
        following = self.step(6, conflict)
        self.assertEqual(following["nodes"][0]["status"], "warming_up")
        self.assertEqual(following["nodes"][0]["baseline_samples"], 0)
        self.assertGreater(self.producer.history[1]["generation"], previous_generation)
        self.assertEqual(len(self.producer.history[1]["samples"]), 1)
        self.assertTrue(all(row["status"] == "ready" for row in following["nodes"][1:]))

    def test_exact_identity_validation_and_uptime_intervals(self):
        for mutate in (
            lambda r: r["document"]["runtime"].update(station_mac=RECEIVERS[2][1]),
            lambda r: r["document"]["runtime"].update(boot_nonce="bad"),
            lambda r: r["document"]["runtime"].update(boot_nonce="0" * 32),
            lambda r: r["document"]["runtime"].update(uptime_ms=True),
            lambda r: r["document"]["wifi"].update(associated=False),
            lambda r: r["document"]["wifi"].update(channel=True),
            lambda r: r["document"]["wifi"].update(bssid="00:00:00:00:00:00"),
            lambda r: r["document"]["wifi"].update(bssid="01:00:00:00:00:01"),
            lambda r: r["document"]["wifi"].update(bssid="ff:ff:ff:ff:ff:ff"),
            lambda r: r.update(finished=5),
            lambda r: r.update(finished_at_ns=BASE_NS - 1),
        ):
            value = reading(1, 0)
            mutate(value)
            with self.assertRaises(ValueError):
                observation(value, RECEIVERS[1][1], 2)
        a = observation(reading(1, 0), RECEIVERS[1][1], 2)
        b = observation(reading(1, 1), RECEIVERS[1][1], 2)
        continuous(a, b)
        for uptime in (a["uptime_ms"] - 1, a["uptime_ms"], a["uptime_ms"] + 2000):
            bad = dict(b, uptime_ms=uptime)
            with self.assertRaises(ValueError):
                continuous(a, bad)
        for field, value in (("ip", "127.0.0.1"), ("station_mac", RECEIVERS[2][1])):
            bad = identities()
            bad["receivers"][0][field] = value
            with self.assertRaises(ValueError):
                configuration(bad, (1, 2, 3), APPROVED_IDENTITIES_SHA256)

    def test_request_rate_periodic_refresh_and_body_auth_limit(self):
        self.assertEqual(len(self.proofs.requests(inputs(0)[1], 0)), 3)
        self.step(0)
        self.assertEqual(self.proofs.requests(inputs(1)[1], 1), {})
        self.assertEqual(len(self.proofs.requests(inputs(6)[1], 6)), 3)
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = b"{}"
        response.getheader.return_value = None
        with patch.object(service.urllib.request, "build_opener", return_value=opener):
            service.read_receiver("http://192.168.77.120:8032/wasm/list", 2)
        request = opener.open.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        response.read.assert_called_once_with(MAX_PROOF_BYTES + 1)
        response.read.return_value = b" " * (MAX_PROOF_BYTES + 1)
        with patch.object(service.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                service.read_receiver("http://192.168.77.120:8032/wasm/list", 2)

    def test_refresh_reserves_wait_for_other_receiver_requests(self):
        self.step(0)
        self.step(1)
        worker = inputs(6)[1]
        worker["nodes"][1]["sequence_discontinuities"] = 1
        # The cached proofs finished at 1.2. At 6.1 they are still only 4.9s
        # old, but they would expire while node 2's required refresh completes.
        requested = self.proofs.requests(worker, 6.1)
        self.assertEqual(set(requested), {1, 2, 3})
        contexts = self.proofs.resolve(
            worker, {n: reading(n, 6) for n in requested}, 6.25
        )
        self.assertTrue(contexts[1]["accept"])
        self.assertTrue(contexts[3]["accept"])
        # The scheduling change must not admit the first suspect scalar.
        self.assertFalse(contexts[2]["accept"])
        self.assertEqual(contexts[2]["reason"], "receiver_identity_priming")

        next_worker = inputs(7)[1]
        next_worker["nodes"][1]["sequence_discontinuities"] = 1
        # The ongoing burst still requires a fresh proof, even though the
        # counter has not changed and the previous proof is under one second old.
        self.assertEqual(set(self.proofs.requests(next_worker, 7.1)), {2})
        following = self.proofs.resolve(next_worker, {2: reading(2, 7)}, 7.25)
        self.assertTrue(all(c["accept"] for c in following.values()))
        self.assertIsNotNone(following[2]["bracket_before_ns"])

    def test_refresh_reservation_tracks_timeout_without_changing_validity(self):
        for timeout in (0.1, 1, 2, 5):
            with self.subTest(timeout=timeout):
                proofs = ReceiverProofs(
                    identities(),
                    (1, 2, 3),
                    timeout=timeout,
                    expected_sha256=APPROVED_IDENTITIES_SHA256,
                )
                # Use exactly representable times for the strict deadline edge.
                reads = {n: reading(n, 0) for n in RECEIVERS}
                for value in reads.values():
                    value.update(
                        started=1.9375,
                        finished=2.0,
                        started_at_ns=BASE_NS + 1_937_500_000,
                        finished_at_ns=BASE_NS + 2_000_000_000,
                    )
                worker = inputs(0)[1]
                proofs.resolve(worker, reads, 2.0)
                if timeout < 5:
                    self.assertEqual(proofs.requests(worker, 7 - timeout - 0.001), {})
                self.assertEqual(set(proofs.requests(worker, 7 - timeout)), {1, 2, 3})
                # A late scheduling cycle cannot turn an expired cache into proof.
                expired = proofs.resolve(worker, {}, 7.0001)
                self.assertTrue(all(not c["accept"] for c in expired.values()))

    def test_phase_reservation_can_exceed_socket_timeout(self):
        self.proofs = ReceiverProofs(
            identities(),
            (1, 2, 3),
            timeout=0.5,
            refresh_reservation=1.0,
            expected_sha256=APPROVED_IDENTITIES_SHA256,
        )
        self.step(0)
        self.step(1)
        worker = inputs(5)[1]
        self.assertEqual(self.proofs.requests(worker, 5.199), {})
        self.assertEqual(set(self.proofs.requests(worker, 5.201)), {1, 2, 3})

    def test_proactive_refresh_failure_never_falls_back_to_cached_proof(self):
        for failure in ("missing", "timeout", "invalid_identity"):
            with self.subTest(failure=failure):
                self.setUp()
                self.step(0)
                self.step(1)
                old = copy.deepcopy(self.proofs.states[1]["proof"])
                worker = inputs(5)[1]
                self.assertEqual(set(self.proofs.requests(worker, 5)), {1, 2, 3})
                reads = {n: reading(n, 5) for n in RECEIVERS}
                mono = 5.25
                if failure == "missing":
                    reads[1] = {}
                elif failure == "timeout":
                    reads[1].update(
                        finished=7.11, finished_at_ns=BASE_NS + 7_110_000_000
                    )
                    mono = 7.11  # The request lasted 2.01s, above the 2s limit.
                else:
                    reads[1]["document"]["runtime"]["boot_nonce"] = "0" * 32
                contexts = self.proofs.resolve(worker, reads, mono)
                self.assertFalse(contexts[1]["accept"])
                self.assertEqual(contexts[1]["reason"], "receiver_proof_unavailable")
                self.assertEqual(self.proofs.states[1]["proof"], old)
                self.assertTrue(self.proofs.states[1]["failed"])
                # Failed evidence is retried next poll, not silently reused.
                self.assertIn(1, self.proofs.requests(worker, mono + 0.1))

    def test_steady_polling_refreshes_periodically_without_a_request_storm(self):
        refreshes = {n: [] for n in RECEIVERS}
        for index in range(60):
            worker = inputs(index)[1]
            requested = self.proofs.requests(worker, index)
            for node in requested:
                refreshes[node].append(index)
            contexts = self.proofs.resolve(
                worker, {n: reading(n, index) for n in requested}, index + 0.2
            )
            if index:
                self.assertTrue(all(c["accept"] for c in contexts.values()))
            # A successfully refreshed proof must not immediately request again.
            if requested:
                self.assertEqual(self.proofs.requests(worker, index + 0.2), {})
        for ticks in refreshes.values():
            self.assertGreaterEqual(len(ticks), 12)
            self.assertLessEqual(len(ticks), 20)
            self.assertTrue(
                all(b - a >= 3 for a, b in zip(ticks, ticks[1:], strict=False))
            )

    def test_service_integration_proof_calls_are_separate_and_bounded(self):
        original = inputs(0)

        def source(url, timeout, token):
            return copy.deepcopy(
                original[0]
                if url.endswith("/health")
                else original[1]
                if url.endswith("/v1/latest")
                else original[2]
            )

        calls = []

        def board(url, timeout):
            calls.append((url, timeout))
            node = next(n for n, (ip, _) in RECEIVERS.items() if ip in url)
            return reading(node, 0)["document"]

        instance = service.Service(
            config(),
            "http://collector",
            "http://worker",
            "synthetic",
            MagicMock(),
            source,
            identities(),
            board,
            expected_receiver_sha256=APPROVED_IDENTITIES_SHA256,
            expected_coordinate_frame=config()["coordinate_frame"],
        )
        with (
            patch.object(service.time, "monotonic", return_value=0.2),
            patch.object(service.time, "time_ns", return_value=BASE_NS + 200_000_000),
        ):
            result = instance.poll_once()
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(len(calls), 3)
        self.assertEqual(
            {u for u, _ in calls},
            {f"http://{ip}:8032/wasm/list" for ip, _ in RECEIVERS.values()},
        )
        self.assertEqual(
            result["receiver_identity_configuration_sha256"], self.proofs.config_sha
        )


if __name__ == "__main__":
    unittest.main()
