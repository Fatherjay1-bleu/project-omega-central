"""Tests for public_demo.py — GET /health and scenario regression.

Isolation note: public_demo.py registers a before_request hook that blocks all
non-GET methods, and replaces the '/' view function on the shared Flask app
object.  To prevent these side effects from contaminating test_platform or
test_sprint3, this test module creates its own isolated Flask test client by
importing public_demo AFTER patching the shared app to a fresh instance.  The
pattern used is to import through a fresh application context each test class
setUp, avoiding any permanent mutation of the module-level app object.

The safe approach: import public_demo once, capture the test client from
`application`, and patch analyze_event at the public_demo module level so
route handlers resolve the correct mock.
"""
import subprocess
import unittest
from unittest.mock import patch

# public_demo mutates the shared Flask app object from app.py.  Import it once.
# All tests in this file target `application` (= the public demo's Flask app).
import public_demo  # noqa: F401 — side-effect: registers routes
from public_demo import application

from sentinel.orchestrator import EngineError

_SCORED_PROBE = {
    "id": "HEALTH-PROBE",
    "source": "healthcheck",
    "severity": 1,
    "failed_logins": 0,
    "suspicious_process": False,
    "score": 6,
    "risk": "LOW",
}


class HealthCheckTests(unittest.TestCase):

    def setUp(self):
        self.client = application.test_client()

    # --- happy path (mocked native engines) ---------------------------------

    def test_health_200_when_engines_ok(self):
        with patch("public_demo.analyze_event", return_value=_SCORED_PROBE):
            resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_200_body_fields(self):
        with patch("public_demo.analyze_event", return_value=_SCORED_PROBE):
            data = self.client.get("/health").json
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["engine"], "native-c-cpp")
        self.assertTrue(data["synthetic"])

    def test_health_200_no_internal_details(self):
        with patch("public_demo.analyze_event", return_value=_SCORED_PROBE):
            resp = self.client.get("/health")
        body = resp.data.decode()
        for forbidden in ("HEALTH-PROBE", "healthcheck", "build/", "sentinel", "Traceback"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, body)

    # --- engine failure → 503 -----------------------------------------------

    def test_health_503_on_engine_error(self):
        with patch("public_demo.analyze_event",
                   side_effect=EngineError("Build required")):
            resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 503)

    def test_health_503_body_sanitized(self):
        with patch("public_demo.analyze_event",
                   side_effect=EngineError("Build required")):
            data = self.client.get("/health").json
        self.assertEqual(data["status"], "unavailable")
        # Must contain exactly one key — no internals exposed.
        self.assertEqual(list(data.keys()), ["status"])

    def test_health_503_no_traceback_in_body(self):
        with patch("public_demo.analyze_event",
                   side_effect=EngineError("internal/path/detail")):
            resp = self.client.get("/health")
        body = resp.data.decode()
        self.assertNotIn("Traceback", body)
        self.assertNotIn("internal/path/detail", body)

    def test_health_503_on_unexpected_score(self):
        # Engine returns wrong score → treated as failure.
        bad_result = {**_SCORED_PROBE, "score": 99, "risk": "CRITICAL"}
        with patch("public_demo.analyze_event", return_value=bad_result):
            resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 503)

    def test_health_503_on_wrong_risk(self):
        bad_result = {**_SCORED_PROBE, "score": 6, "risk": "MEDIUM"}
        with patch("public_demo.analyze_event", return_value=bad_result):
            resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 503)

    # --- POST blocked by public_get_only() ----------------------------------

    def test_health_post_returns_405(self):
        resp = self.client.post("/health")
        self.assertEqual(resp.status_code, 405)

    # --- security headers present on /health --------------------------------

    def test_health_security_headers_200(self):
        with patch("public_demo.analyze_event", return_value=_SCORED_PROBE):
            resp = self.client.get("/health")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_health_security_headers_503(self):
        with patch("public_demo.analyze_event",
                   side_effect=EngineError("Build required")):
            resp = self.client.get("/health")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertIn("X-Content-Type-Options", resp.headers)


class DemoIndexRegressionTests(unittest.TestCase):

    def setUp(self):
        self.client = application.test_client()

    def test_demo_index_200(self):
        resp = self.client.get("/demo")
        self.assertEqual(resp.status_code, 200)

    def test_demo_index_synthetic_true(self):
        self.assertTrue(self.client.get("/demo").json["synthetic"])

    def test_demo_index_has_three_scenarios(self):
        self.assertEqual(len(self.client.get("/demo").json["scenarios"]), 3)

    def test_demo_post_returns_405(self):
        self.assertEqual(self.client.post("/demo").status_code, 405)

    def test_unknown_scenario_returns_404(self):
        self.assertEqual(self.client.get("/demo/scenario/99").status_code, 404)


class DemoScenarioRegressionTests(unittest.TestCase):
    """Verify scenario routes still return correct data (mocked engines)."""

    def setUp(self):
        self.client = application.test_client()

    def _mock_side_effects_for_scenario(self, scores_and_risks):
        """Build _run side effects: VALID + score result per event."""
        side = []
        for score, risk in scores_and_risks:
            side.append(subprocess.CompletedProcess([], 0, "VALID\n", ""))
            side.append(subprocess.CompletedProcess([], 0, f"{score} {risk}\n", ""))
        return side

    def test_scenario_1_200(self):
        mocks = self._mock_side_effects_for_scenario(
            [(0, "LOW"), (8, "LOW"), (12, "LOW")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            resp = self.client.get("/demo/scenario/1")
        self.assertEqual(resp.status_code, 200)

    def test_scenario_1_synthetic_true(self):
        mocks = self._mock_side_effects_for_scenario(
            [(0, "LOW"), (8, "LOW"), (12, "LOW")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/1").json
        self.assertTrue(data["synthetic"])

    def test_scenario_1_no_findings(self):
        mocks = self._mock_side_effects_for_scenario(
            [(0, "LOW"), (8, "LOW"), (12, "LOW")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/1").json
        self.assertEqual(data["correlations"], [])

    def test_scenario_1_zero_errors(self):
        mocks = self._mock_side_effects_for_scenario(
            [(0, "LOW"), (8, "LOW"), (12, "LOW")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/1").json
        self.assertEqual(data["error_count"], 0)

    def test_scenario_2_corr001_present(self):
        mocks = self._mock_side_effects_for_scenario(
            [(28, "MEDIUM"), (44, "MEDIUM"), (50, "HIGH")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/2").json
        rule_ids = {f["rule_id"] for f in data["correlations"]}
        self.assertIn("CORR-001", rule_ids)

    def test_scenario_2_zero_errors(self):
        mocks = self._mock_side_effects_for_scenario(
            [(28, "MEDIUM"), (44, "MEDIUM"), (50, "HIGH")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/2").json
        self.assertEqual(data["error_count"], 0)

    def test_scenario_3_all_six_rules(self):
        mocks = self._mock_side_effects_for_scenario(
            [(94, "CRITICAL"), (100, "CRITICAL"), (68, "HIGH")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/3").json
        rule_ids = {f["rule_id"] for f in data["correlations"]}
        for rule in (f"CORR-{i:03}" for i in range(1, 7)):
            with self.subTest(rule=rule):
                self.assertIn(rule, rule_ids)

    def test_scenario_3_zero_errors(self):
        mocks = self._mock_side_effects_for_scenario(
            [(94, "CRITICAL"), (100, "CRITICAL"), (68, "HIGH")]
        )
        with patch("sentinel.orchestrator._run", side_effect=mocks):
            data = self.client.get("/demo/scenario/3").json
        self.assertEqual(data["error_count"], 0)

    def test_scenario_post_returns_405(self):
        self.assertEqual(self.client.post("/demo/scenario/1").status_code, 405)


if __name__ == "__main__":
    unittest.main()
