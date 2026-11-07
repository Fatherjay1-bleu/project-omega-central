"""Fail-closed readiness contracts; run with unittest on the isolated branch.

These tests do not call the deployed service and do not process customer data.
"""
import unittest
from unittest.mock import patch

from public_demo import application
from sentinel.orchestrator import EngineError


class NativeHealthFailClosedTests(unittest.TestCase):
    def setUp(self):
        application.config["TESTING"] = True
        self.client = application.test_client()

    def test_native_engine_error_returns_sanitized_503(self):
        with patch("public_demo.analyze_event", side_effect=EngineError("private/internal/path")):
            response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"status": "unavailable"})
        self.assertNotIn(b"private/internal/path", response.data)

    def test_unexpected_native_score_denies_readiness(self):
        with patch("public_demo.analyze_event", return_value={"score": 999, "risk": "LOW"}):
            response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"status": "unavailable"})

    def test_unexpected_native_risk_denies_readiness(self):
        with patch("public_demo.analyze_event", return_value={"score": 6, "risk": "HIGH"}):
            response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)

    def test_success_requires_expected_native_result(self):
        with patch("public_demo.analyze_event", return_value={"score": 6, "risk": "LOW"}) as probe:
            response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {
            "status": "ok", "engine": "native-c-cpp", "synthetic": True
        })
        self.assertEqual(probe.call_count, 1)

    def test_malformed_native_result_returns_sanitized_503(self):
        for invalid in ({}, {"score": 6}, {"risk": "LOW"}, None, ["invalid"]):
            with self.subTest(invalid=invalid):
                with patch("public_demo.analyze_event", return_value=invalid):
                    response = self.client.get("/health")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.get_json(), {"status": "unavailable"})

    def test_mutating_health_request_is_rejected_without_engine_execution(self):
        with patch("public_demo.analyze_event") as probe:
            response = self.client.post("/health", json={"severity": 9})
        self.assertEqual(response.status_code, 405)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
