"""Sprint 3 tests — ingestor, v3 route, new correlation rules, demo scenarios."""
import json
import subprocess
import unittest
from unittest.mock import patch

from app import app
from sentinel.batch import MAX_BATCH_SIZE
from sentinel.correlator import correlate
from sentinel.ingestor import (
    IngestionError,
    MAX_CONTENT_LENGTH,
    check_origin,
    ingest_and_analyze,
    validate_body,
)
from sentinel.orchestrator import EngineError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _good_event(event_id="T-001", **overrides):
    return {
        "id": event_id,
        "source": "test-host",
        "severity": 1,
        "failed_logins": 0,
        "suspicious_process": False,
        **overrides,
    }


def _scored(event_id, source, severity, failed_logins, suspicious, score, risk):
    return {
        "id": event_id,
        "source": source,
        "severity": severity,
        "failed_logins": failed_logins,
        "suspicious_process": suspicious,
        "score": score,
        "risk": risk,
    }


def _mock_good_run(stdout, returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, "")


# ---------------------------------------------------------------------------
# Ingestor unit tests
# ---------------------------------------------------------------------------

class IngestorOriginTests(unittest.TestCase):

    def test_no_origin_headers_allowed(self):
        # Non-browser clients (no Origin / Sec-Fetch-Site) must not be blocked.
        check_origin(None, None)   # must not raise

    def test_loopback_origin_allowed(self):
        check_origin("http://127.0.0.1:5000", None)
        check_origin("http://localhost:5000", None)

    def test_external_origin_rejected(self):
        with self.assertRaises(IngestionError) as ctx:
            check_origin("https://evil.example.com", None)
        self.assertEqual(ctx.exception.http_status, 403)

    def test_sec_fetch_site_same_origin_allowed(self):
        check_origin(None, "same-origin")

    def test_sec_fetch_site_none_allowed(self):
        check_origin(None, "none")

    def test_sec_fetch_site_cross_site_rejected(self):
        with self.assertRaises(IngestionError) as ctx:
            check_origin(None, "cross-site")
        self.assertEqual(ctx.exception.http_status, 403)

    def test_sec_fetch_site_same_site_rejected(self):
        # 'same-site' is still a different origin under strict policy.
        with self.assertRaises(IngestionError) as ctx:
            check_origin(None, "same-site")
        self.assertEqual(ctx.exception.http_status, 403)

    def test_error_message_does_not_echo_origin(self):
        try:
            check_origin("https://attacker.example.com", None)
        except IngestionError as exc:
            self.assertNotIn("attacker.example.com", str(exc))


class IngestorBodyTests(unittest.TestCase):

    def test_none_body_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body(None)
        self.assertEqual(ctx.exception.http_status, 400)

    def test_list_body_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body([])
        self.assertEqual(ctx.exception.http_status, 400)

    def test_string_body_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body("events")
        self.assertEqual(ctx.exception.http_status, 400)

    def test_missing_events_key_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body({})
        self.assertEqual(ctx.exception.http_status, 400)

    def test_events_not_list_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body({"events": "not a list"})
        self.assertEqual(ctx.exception.http_status, 400)

    def test_events_dict_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body({"events": {}})
        self.assertEqual(ctx.exception.http_status, 400)

    def test_oversized_events_array_raises_400(self):
        with self.assertRaises(IngestionError) as ctx:
            validate_body({"events": [{}] * (MAX_BATCH_SIZE + 1)})
        self.assertEqual(ctx.exception.http_status, 400)

    def test_valid_empty_array_returns_empty_list(self):
        result = validate_body({"events": []})
        self.assertEqual(result, [])

    def test_valid_array_returns_events(self):
        events = [_good_event()]
        result = validate_body({"events": events})
        self.assertEqual(result, events)

    def test_error_messages_do_not_expose_internals(self):
        bad_inputs = [None, [], "text", {}, {"events": "bad"}, {"events": {}}]
        for bad in bad_inputs:
            with self.subTest(bad=bad):
                try:
                    validate_body(bad)
                except IngestionError as exc:
                    msg = str(exc)
                    self.assertNotIn("Traceback", msg)
                    self.assertNotIn("Exception", msg)

    def test_engine_error_propagates_from_ingest_and_analyze(self):
        with patch("sentinel.orchestrator._run",
                   side_effect=EngineError("Build required")):
            with self.assertRaises(EngineError):
                ingest_and_analyze({"events": [_good_event()]})

    def test_max_content_length_constant(self):
        self.assertEqual(MAX_CONTENT_LENGTH, 256 * 1024)


# ---------------------------------------------------------------------------
# POST /api/v3/analyze route tests
# ---------------------------------------------------------------------------

class V3RouteTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def _post(self, body, content_type="application/json",
              origin=None, sec_fetch_site=None):
        headers = {"Content-Type": content_type}
        if origin is not None:
            headers["Origin"] = origin
        if sec_fetch_site is not None:
            headers["Sec-Fetch-Site"] = sec_fetch_site
        if isinstance(body, (dict, list)):
            data = json.dumps(body)
        else:
            data = body
        return self.client.post("/api/v3/analyze", data=data, headers=headers)

    def _mock_scored_events(self):
        return [
            {"id": "T-001", "source": "h1", "severity": 1,
             "failed_logins": 0, "suspicious_process": False, "score": 6, "risk": "LOW"},
        ]

    # --- content-type enforcement -------------------------------------------

    def test_wrong_content_type_returns_400(self):
        resp = self._post({"events": []}, content_type="text/plain")
        self.assertEqual(resp.status_code, 400)

    def test_json_content_type_accepted(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            resp = self._post({"events": []})
        self.assertEqual(resp.status_code, 200)

    # --- origin / Sec-Fetch-Site checks -------------------------------------

    def test_external_origin_rejected_403(self):
        resp = self._post({"events": []}, origin="https://evil.example.com")
        self.assertEqual(resp.status_code, 403)

    def test_cross_site_sec_fetch_rejected_403(self):
        resp = self._post({"events": []}, sec_fetch_site="cross-site")
        self.assertEqual(resp.status_code, 403)

    def test_no_origin_headers_accepted(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            resp = self._post({"events": []})
        self.assertEqual(resp.status_code, 200)

    def test_same_origin_sec_fetch_accepted(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            resp = self._post({"events": []}, sec_fetch_site="same-origin")
        self.assertEqual(resp.status_code, 200)

    # --- body validation ----------------------------------------------------

    def test_malformed_json_returns_400(self):
        resp = self._post("{bad json", content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    def test_body_not_object_returns_400(self):
        resp = self._post([1, 2, 3])
        self.assertEqual(resp.status_code, 400)

    def test_missing_events_key_returns_400(self):
        resp = self._post({})
        self.assertEqual(resp.status_code, 400)

    def test_events_not_list_returns_400(self):
        resp = self._post({"events": "bad"})
        self.assertEqual(resp.status_code, 400)

    def test_events_over_500_returns_400(self):
        resp = self._post({"events": [{}] * (MAX_BATCH_SIZE + 1)})
        self.assertEqual(resp.status_code, 400)

    # --- response structure -------------------------------------------------

    def test_empty_events_returns_200(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            resp = self._post({"events": []})
        self.assertEqual(resp.status_code, 200)

    def test_empty_events_response_keys(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            data = self._post({"events": []}).json
        for key in ("synthetic", "total_events", "risk_distribution",
                    "events", "correlations", "success_count",
                    "error_count", "errors"):
            with self.subTest(key=key):
                self.assertIn(key, data)

    def test_empty_batch_synthetic_true(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            data = self._post({"events": []}).json
        self.assertTrue(data["synthetic"])

    def test_empty_batch_total_events_zero(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            data = self._post({"events": []}).json
        self.assertEqual(data["total_events"], 0)

    def test_all_invalid_batch_synthetic_true(self):
        # All-invalid → scored=[], errors populated; synthetic must still be True.
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult(
                [], [{"index": 0, "id": None, "reason": "Event did not pass schema validation."}]
            )
            data = self._post({"events": [{"bad": True}]}).json
        self.assertTrue(data["synthetic"])

    def test_valid_scored_events_appear_in_response(self):
        scored = self._mock_scored_events()
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult(scored, [])
            data = self._post({"events": scored}).json
        self.assertEqual(data["success_count"], 1)
        self.assertEqual(data["total_events"], 1)

    def test_engine_failure_returns_503(self):
        with patch("app.ingest_and_analyze",
                   side_effect=EngineError("Build required")):
            resp = self._post({"events": [_good_event()]})
        self.assertEqual(resp.status_code, 503)

    # --- error sanitization -------------------------------------------------

    def test_400_error_body_no_traceback(self):
        resp = self._post({})
        self.assertNotIn(b"Traceback", resp.data)

    def test_400_error_body_no_exception_class(self):
        resp = self._post({})
        self.assertNotIn(b"IngestionError", resp.data)
        self.assertNotIn(b"ValueError", resp.data)

    def test_403_error_body_does_not_echo_origin(self):
        resp = self._post({"events": []}, origin="https://attacker.example.com")
        self.assertNotIn(b"attacker.example.com", resp.data)

    def test_503_error_body_no_traceback(self):
        with patch("app.ingest_and_analyze",
                   side_effect=EngineError("Build required")):
            resp = self._post({"events": [_good_event()]})
        self.assertNotIn(b"Traceback", resp.data)

    # --- security headers on v3 ---------------------------------------------

    def test_v3_security_headers_200(self):
        with patch("app.ingest_and_analyze") as m:
            from sentinel.batch import BatchResult
            m.return_value = BatchResult([], [])
            resp = self._post({"events": []})
        self.assertEqual(resp.headers.get("Content-Security-Policy"), "default-src 'self'")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_v3_security_headers_400(self):
        resp = self._post({})
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertIn("X-Content-Type-Options", resp.headers)

    def test_v3_security_headers_503(self):
        with patch("app.ingest_and_analyze",
                   side_effect=EngineError("Build required")):
            resp = self._post({"events": [_good_event()]})
        self.assertIn("Content-Security-Policy", resp.headers)


# ---------------------------------------------------------------------------
# New correlation rules — CORR-005 and CORR-006
# ---------------------------------------------------------------------------

class CorrelatorSprint3Tests(unittest.TestCase):

    def _sc(self, event_id, severity, score, risk, **kw):
        return {
            "id": event_id, "source": "h1",
            "severity": severity, "failed_logins": kw.get("failed_logins", 0),
            "suspicious_process": kw.get("suspicious_process", False),
            "score": score, "risk": risk,
        }

    # --- CORR-005 -----------------------------------------------------------

    def test_corr005_fires_when_all_severity_gte_7(self):
        events = [
            self._sc("E1", 7, 42, "MEDIUM"),
            self._sc("E2", 9, 54, "HIGH"),
            self._sc("E3", 10, 60, "HIGH"),
        ]
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertIn("CORR-005", rule_ids)

    def test_corr005_fires_for_single_event_at_threshold(self):
        events = [self._sc("E1", 7, 42, "MEDIUM")]
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertIn("CORR-005", rule_ids)

    def test_corr005_does_not_fire_when_one_below_threshold(self):
        events = [
            self._sc("E1", 7, 42, "MEDIUM"),
            self._sc("E2", 6, 36, "MEDIUM"),
        ]
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertNotIn("CORR-005", rule_ids)

    def test_corr005_does_not_fire_for_empty_list(self):
        # correlate([]) returns [] before any rule runs.
        self.assertEqual(correlate([]), [])

    def test_corr005_finding_type(self):
        events = [self._sc("E1", 8, 48, "MEDIUM")]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-005"]
        self.assertEqual(findings[0].finding_type, "ALL_SOURCES_HIGH_SEVERITY")

    def test_corr005_description_no_causal_language(self):
        events = [self._sc("E1", 7, 42, "MEDIUM")]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-005"]
        desc = findings[0].description.lower()
        for forbidden in ("attack", "comprom", "coordin", "lateral", "breach"):
            with self.subTest(word=forbidden):
                self.assertNotIn(forbidden, desc)

    # --- CORR-006 -----------------------------------------------------------

    def test_corr006_fires_at_score_100(self):
        events = [self._sc("E1", 10, 100, "CRITICAL")]
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertIn("CORR-006", rule_ids)

    def test_corr006_does_not_fire_at_score_99(self):
        events = [self._sc("E1", 10, 99, "CRITICAL")]
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertNotIn("CORR-006", rule_ids)

    def test_corr006_does_not_fire_at_score_80(self):
        events = [self._sc("E1", 10, 80, "CRITICAL")]
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertNotIn("CORR-006", rule_ids)

    def test_corr006_fires_once_per_max_score_event(self):
        events = [
            self._sc("E1", 10, 100, "CRITICAL"),
            self._sc("E2", 10, 100, "CRITICAL"),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-006"]
        self.assertEqual(len(findings), 2)

    def test_corr006_finding_type(self):
        events = [self._sc("E1", 10, 100, "CRITICAL")]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-006"]
        self.assertEqual(findings[0].finding_type, "MAX_SCORE_REACHED")

    def test_corr006_description_does_not_claim_factor_saturation(self):
        # CORR-006 must not claim all scoring factors are saturated.
        events = [self._sc("E1", 10, 100, "CRITICAL")]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-006"]
        desc = findings[0].description.lower()
        for forbidden in ("all factors", "saturat", "all scoring", "maximum in every"):
            with self.subTest(phrase=forbidden):
                self.assertNotIn(forbidden, desc)

    def test_corr006_description_mentions_ceiling(self):
        events = [self._sc("E1", 10, 100, "CRITICAL")]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-006"]
        self.assertIn("ceiling", findings[0].description.lower())

    # --- all six rules fire simultaneously ----------------------------------

    def test_all_six_rules_fire(self):
        events = [
            # CORR-001: login storm; CORR-003+004+005+006 contributor
            self._sc("E1", 9, 100, "CRITICAL", failed_logins=12, suspicious_process=True),
            # CORR-002: second suspicious; CORR-003+004+005+006 contributor
            self._sc("E2", 8, 100, "CRITICAL",  failed_logins=0,  suspicious_process=True),
        ]
        # E1: src="h1", E2: src="h1" — same source, so CORR-003 won't fire here.
        # Use distinct sources:
        events[1] = {**events[1], "source": "h2"}
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertIn("CORR-001", rule_ids)
        self.assertIn("CORR-002", rule_ids)
        self.assertIn("CORR-003", rule_ids)
        self.assertIn("CORR-004", rule_ids)
        self.assertIn("CORR-005", rule_ids)
        self.assertIn("CORR-006", rule_ids)


# ---------------------------------------------------------------------------
# Demo scenario fixture tests (mocked native engines)
# ---------------------------------------------------------------------------

class DemoScenarioTests(unittest.TestCase):
    """Verify demo fixtures parse correctly and produce expected scores/findings.

    Native engines are mocked so these tests run without compiled binaries.
    The mock returns the exact score each event should produce per the formula:
      score = min(100, severity*6 + min(failed_logins,10)*2 + suspicious*20)
    """

    def _mock_run_for_scores(self, scores):
        """Build a side_effect list: one VALID result then one score result per event."""
        side = []
        for score in scores:
            risk = ("CRITICAL" if score >= 80 else "HIGH" if score >= 50
                    else "MEDIUM" if score >= 25 else "LOW")
            side.append(subprocess.CompletedProcess([], 0, "VALID\n", ""))
            side.append(subprocess.CompletedProcess([], 0, f"{score} {risk}\n", ""))
        return side

    def _load_and_analyze(self, path, scores):
        from sentinel.orchestrator import analyze_event
        import json, pathlib
        events = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        with patch("sentinel.orchestrator._run", side_effect=self._mock_run_for_scores(scores)):
            return [analyze_event(e) for e in events]

    # --- Scenario 1: Normal low-risk operations ----------------------------

    def test_scenario1_parses(self):
        import json, pathlib
        events = json.loads(pathlib.Path("data/demo_scenario_1.json").read_text(encoding="utf-8"))
        self.assertEqual(len(events), 3)

    def test_scenario1_exact_scores(self):
        # Expected: 0, 8, 12 — all LOW, no rules fire.
        scored = self._load_and_analyze("data/demo_scenario_1.json", [0, 8, 12])
        self.assertEqual([(e["score"], e["risk"]) for e in scored],
                         [(0, "LOW"), (8, "LOW"), (12, "LOW")])

    def test_scenario1_no_findings(self):
        scored = self._load_and_analyze("data/demo_scenario_1.json", [0, 8, 12])
        self.assertEqual(correlate(scored), [])

    # --- Scenario 2: Suspicious authentication activity --------------------

    def test_scenario2_parses(self):
        import json, pathlib
        events = json.loads(pathlib.Path("data/demo_scenario_2.json").read_text(encoding="utf-8"))
        self.assertEqual(len(events), 3)

    def test_scenario2_exact_scores(self):
        # S2-001: 3*6 + 5*2 = 28 MEDIUM
        # S2-002: 4*6 + 10*2 = 44 MEDIUM
        # S2-003: 5*6 + min(12,10)*2 = 30+20 = 50 HIGH
        scored = self._load_and_analyze("data/demo_scenario_2.json", [28, 44, 50])
        self.assertEqual([(e["score"], e["risk"]) for e in scored],
                         [(28, "MEDIUM"), (44, "MEDIUM"), (50, "HIGH")])

    def test_scenario2_corr001_fires_for_logins_gte_10(self):
        scored = self._load_and_analyze("data/demo_scenario_2.json", [28, 44, 50])
        corr001 = [f for f in correlate(scored) if f.rule_id == "CORR-001"]
        # S2-002 (10 logins) and S2-003 (12 logins) both trigger CORR-001.
        self.assertEqual(len(corr001), 2)
        triggering_ids = {f.event_ids[0] for f in corr001}
        self.assertIn("DEMO-S2-002", triggering_ids)
        self.assertIn("DEMO-S2-003", triggering_ids)

    def test_scenario2_no_corr004(self):
        # 1 of 3 events is HIGH/CRITICAL = 33% < 50%, CORR-004 must not fire.
        scored = self._load_and_analyze("data/demo_scenario_2.json", [28, 44, 50])
        rule_ids = {f.rule_id for f in correlate(scored)}
        self.assertNotIn("CORR-004", rule_ids)

    def test_scenario2_no_corr005(self):
        # Severities 3, 4, 5 — not all >= 7, CORR-005 must not fire.
        scored = self._load_and_analyze("data/demo_scenario_2.json", [28, 44, 50])
        rule_ids = {f.rule_id for f in correlate(scored)}
        self.assertNotIn("CORR-005", rule_ids)

    # --- Scenario 3: Multiple high-risk indicators -------------------------

    def test_scenario3_parses(self):
        import json, pathlib
        events = json.loads(pathlib.Path("data/demo_scenario_3.json").read_text(encoding="utf-8"))
        self.assertEqual(len(events), 3)

    def test_scenario3_exact_scores(self):
        # S3-001: 9*6 + min(15,10)*2 + 20 = 54+20+20 = 94 CRITICAL
        # S3-002: 10*6 + min(12,10)*2 + 20 = 60+20+20 = 100 CRITICAL
        # S3-003: 8*6 + 0 + 20 = 48+20 = 68 HIGH
        scored = self._load_and_analyze("data/demo_scenario_3.json", [94, 100, 68])
        self.assertEqual([(e["score"], e["risk"]) for e in scored],
                         [(94, "CRITICAL"), (100, "CRITICAL"), (68, "HIGH")])

    def test_scenario3_all_six_rules_fire(self):
        scored = self._load_and_analyze("data/demo_scenario_3.json", [94, 100, 68])
        rule_ids = {f.rule_id for f in correlate(scored)}
        for rule in ("CORR-001", "CORR-002", "CORR-003",
                     "CORR-004", "CORR-005", "CORR-006"):
            with self.subTest(rule=rule):
                self.assertIn(rule, rule_ids)

    def test_scenario3_corr006_fires_for_s3_002_only(self):
        scored = self._load_and_analyze("data/demo_scenario_3.json", [94, 100, 68])
        corr006 = [f for f in correlate(scored) if f.rule_id == "CORR-006"]
        self.assertEqual(len(corr006), 1)
        self.assertEqual(corr006[0].event_ids, ["DEMO-S3-002"])


if __name__ == "__main__":
    unittest.main()
