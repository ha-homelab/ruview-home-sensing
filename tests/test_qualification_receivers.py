"""Qualification remains bound to one explicit station across all three boards."""

import asyncio
import copy
import unittest
from unittest.mock import Mock

from collector_fixture import COLLECTOR
from qualification_fixture import get_test_receiver as get_receiver
from test_module_upload import UPLOAD, RecoveryDevice
from test_runtime_observation import OBSERVER, fixture


def rebind(value, receiver):
    if isinstance(value, list):
        return [rebind(item, receiver) for item in value]
    if isinstance(value, dict):
        result = {key: rebind(item, receiver) for key, item in value.items()}
        if "node_id" in result:
            result["node_id"] = receiver.node_id
        if "station_mac" in result:
            result["station_mac"] = receiver.station_mac
        return result
    return value


class QualificationReceiverTests(unittest.TestCase):
    def test_only_exact_integer_inventory_ids_are_accepted(self):
        for value in (True, False, "1", 1.0, None, 0, 4, -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                get_receiver(value)

    def test_observer_12_preserves_station_and_csi_identity(self):
        for node_id in (1, 2, 3):
            receiver = get_receiver(node_id)
            with (
                self.subTest(node=node_id),
            ):
                report = rebind(fixture(version="0.8.8.12"), receiver)
                report["receiver"] = receiver.metadata()
                result = OBSERVER.evaluate(
                    report, expected_version="0.8.8.12", receiver=receiver
                )
                self.assertTrue(result["passed"], result)
                for field in ("station_mac", "node_id", "ip"):
                    wrong = copy.deepcopy(report)
                    wrong["receiver"][field] = "wrong"
                    self.assertFalse(
                        OBSERVER.evaluate(
                            wrong, expected_version="0.8.8.12", receiver=receiver
                        )["passed"]
                    )
                wrong = copy.deepcopy(report)
                wrong["samples"][0]["csi"]["node_id"] = 4
                self.assertFalse(
                    OBSERVER.evaluate(
                        wrong, expected_version="0.8.8.12", receiver=receiver
                    )["passed"]
                )
                wrong = copy.deepcopy(report)
                wrong["samples"][0]["status"]["station_mac"] = "00:00:00:00:00:00"
                self.assertFalse(
                    OBSERVER.evaluate(
                        wrong, expected_version="0.8.8.12", receiver=receiver
                    )["passed"]
                )

    def test_observer_requests_selected_address_and_filters_collector(self):
        for node_id in (1, 2, 3):
            receiver = get_receiver(node_id)
            sample = rebind(fixture("baseline", "0.8.8.12"), receiver)["samples"][0]
            calls = []

            def get(url, auth=False, *, calls=calls, sample=sample):
                calls.append((url, auth))
                if url.endswith("/ota/status"):
                    return sample["status"]
                if url.endswith("/wasm/list"):
                    return sample["listing"]
                return {"nodes": [sample["csi"], {"node_id": 99}]}

            with (
                self.subTest(node=node_id),
            ):
                result = OBSERVER.read_sample(
                    get,
                    lambda: 0.5,
                    "ota_0",
                    expected_version="0.8.8.12",
                    receiver=receiver,
                    collector=COLLECTOR,
                )
                self.assertEqual(result["csi"]["node_id"], node_id)
                self.assertEqual(calls[0][0], receiver.base_url + "/ota/status")
                self.assertEqual(calls[1][0], receiver.base_url + "/wasm/list")

    def test_12_upload_rejects_wrong_station_before_any_mutation(self):
        for node_id in (1, 2, 3):
            receiver = get_receiver(node_id)
            for valid in (True, False):
                device = RecoveryDevice()
                device.version = "0.8.8.12"
                mac = receiver.station_mac if valid else "00:00:00:00:00:00"
                device.status_overrides["station_mac"] = mac
                device.runtime_overrides["station_mac"] = mac
                with (
                    self.subTest(node=node_id, valid=valid),
                ):
                    result = UPLOAD.run_upload(
                        UPLOAD.PACKAGE.read_bytes(),
                        "ota_1",
                        device.request,
                        lambda report: None,
                        expected_version="0.8.8.12",
                        receiver=receiver,
                        revalidate=lambda: None,
                    )
                    self.assertEqual(result["receiver"], receiver.metadata())
                    self.assertEqual(result["passed"], valid, result)
                    self.assertEqual(
                        len([call for call in device.calls if call[0] == "POST"]),
                        2 if valid else 0,
                    )

    def test_legacy_mode_cannot_contact_or_qualify_other_receivers(self):
        for node_id in (1, 3):
            receiver = get_receiver(node_id)
            for version in ("0.8.8.5", "0.8.8.6", "0.8.8.7", "0.8.8.8"):
                with (
                    self.subTest(node=node_id, version=version),
                ):
                    request = Mock(
                        side_effect=AssertionError("network must not be reached")
                    )
                    with self.assertRaisesRegex(
                        ValueError, "receiver_version_not_supported"
                    ):
                        OBSERVER.read_sample(
                            request,
                            lambda: 0,
                            "ota_1",
                            expected_version=version,
                            receiver=receiver,
                            collector=COLLECTOR,
                        )
                    with self.assertRaisesRegex(
                        ValueError, "receiver_version_not_supported"
                    ):
                        asyncio.run(
                            OBSERVER.observe(
                                315,
                                "baseline",
                                0,
                                "ota_1",
                                "unused",
                                expected_version=version,
                                receiver=receiver,
                                revalidate=lambda: None,
                                collector=COLLECTOR,
                            )
                        )
                    report = rebind(fixture(version=version), receiver)
                    report["receiver"] = receiver.metadata()
                    result = OBSERVER.evaluate(
                        report, expected_version=version, receiver=receiver
                    )
                    self.assertFalse(result["passed"])
                    result = UPLOAD.run_upload(
                        UPLOAD.PACKAGE.read_bytes(),
                        "ota_1",
                        request,
                        lambda report: None,
                        expected_version=version,
                        receiver=receiver,
                        revalidate=lambda: None,
                    )
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["valid_post_attempted"])
                    request.assert_not_called()
