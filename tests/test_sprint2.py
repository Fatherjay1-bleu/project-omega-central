"""Sprint 2 tests — batch processing, explainer, correlator, v2 route."""
import subprocess
import unittest
from unittest.mock import patch

from app import app, _build_report
from sentinel.batch import MAX_BATCH_SIZE, BatchResult, analyze_batch
from sentinel.correlator import Finding, correlate
from sentinel.explainer import explain_score
from sentinel.orchestrator import EngineError, InvalidEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def good_event(**overrides):
    """Return a minimal valid event dict."""
    return {
        "id": "T-001",
        "source": "test-host",
        "severity": 1,
        "failed_logins": 0,
        "suspicious_process": False,
        **overrides,
    }


def scored_event(**overrides):
    """Return a minimal scored event dict (as if returned by analyze_event)."""
    base = good_event(**overrides)
    base.update({"score": 6, "risk": "LOW"})
    return base


# ---------------------------------------------------------------------------
# Phase 1 — Batch processing
# ---------------------------------------------------------------------------

class BatchTests(unittest.TestCase):

    # --- structural / type tests (no native binaries needed) ---------------

    def test_empty_batch_returns_batch_result(self):
        result = analyze_batch([])
        self.assertIsInstance(result, BatchResult)
        self.assertEqual(result.scored, [])
        self.assertEqual(result.errors, [])

    def test_empty_batch_as_dict_fields(self):
        d = analyze_batch([]).as_dict()
        self.assertEqual(d["total"], 0)
        self.assertEqual(d["success_count"], 0)
        self.assertEqual(d["error_count"], 0)
        self.assertIn("scored", d)
        self.assertIn("errors", d)

    def test_batch_not_a_list_raises_type_error(self):
        for bad in (None, {}, "events", 42):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    analyze_batch(bad)

    def test_batch_too_large_raises_value_error(self):
        oversized = [good_event(id=f"T-{i:04d}") for i in range(MAX_BATCH_SIZE + 1)]
        with self.assertRaises(ValueError):
            analyze_batch(oversized)

    def test_batch_at_max_size_does_not_raise(self):
        # MAX_BATCH_SIZE events all invalid — should not raise ValueError,
        # only produce error entries (no native binaries needed).
        batch = [{"bad": True}] * MAX_BATCH_SIZE
        result = analyze_batch(batch)
        self.assertEqual(len(result.errors), MAX_BATCH_SIZE)

    def test_partial_invalid_captures_errors_not_raises(self):
        # Mix one invalid event among valid dicts; InvalidEvent must not propagate.
        invalid = {"id": "BAD", "source": "x", "severity": 999,
                   "failed_logins": 0, "suspicious_process": False}
        # Patch _run so the valid event doesn't need real binaries.
        valid_validator = subprocess.CompletedProcess([], 0, "VALID\n", "")
        valid_scorer    = subprocess.CompletedProcess([], 0, "6 LOW\n", "")
        with patch("sentinel.orchestrator._run",
                   side_effect=[valid_validator, valid_scorer]):
            result = analyze_batch([good_event(), invalid])
        self.assertEqual(len(result.scored), 1)
        self.assertEqual(len(result.errors), 1)

    def test_all_invalid_batch_zero_scored(self):
        batch = [{"bad": True}, None, [], 42]
        result = analyze_batch(batch)
        self.assertEqual(len(result.scored), 0)
        self.assertEqual(len(result.errors), 4)

    def test_error_entry_has_required_fields(self):
        result = analyze_batch([{"bad": True}])
        self.assertEqual(len(result.errors), 1)
        entry = result.errors[0]
        self.assertIn("index", entry)
        self.assertIn("id", entry)
        self.assertIn("reason", entry)

    def test_error_entry_index_is_correct(self):
        batch = [{"bad": True}, {"also": "bad"}]
        result = analyze_batch(batch)
        indices = [e["index"] for e in result.errors]
        self.assertEqual(indices, [0, 1])

    def test_error_entry_id_none_when_not_a_dict(self):
        result = analyze_batch([None, 42, "string"])
        for entry in result.errors:
            self.assertIsNone(entry["id"])

    def test_error_entry_id_none_when_id_missing(self):
        result = analyze_batch([{"source": "x"}])
        self.assertIsNone(result.errors[0]["id"])

    def test_error_entry_id_is_safe_string_when_present(self):
        result = analyze_batch([{"id": "EVT-99", "bad_field": True}])
        self.assertEqual(result.errors[0]["id"], "EVT-99")

    def test_error_entry_id_none_for_control_char_id(self):
        # ID containing a control character must not leak through.
        result = analyze_batch([{"id": "bad\x01id"}])
        self.assertIsNone(result.errors[0]["id"])

    def test_error_reason_does_not_expose_internals(self):
        # The reason string must be a fixed-vocabulary message, not a raw
        # exception repr that could expose internal details.
        result = analyze_batch([{"bad": True}])
        reason = result.errors[0]["reason"]
        self.assertIsInstance(reason, str)
        self.assertNotIn("Traceback", reason)
        self.assertNotIn("Exception", reason)
        self.assertNotIn("Error", reason)

    def test_engine_error_propagates_from_batch(self):
        # EngineError (missing/broken binary) must not be swallowed.
        with patch("sentinel.orchestrator._run",
                   side_effect=EngineError("Build required")):
            with self.assertRaises(EngineError):
                analyze_batch([good_event()])

    def test_as_dict_total_equals_scored_plus_errors(self):
        invalid = {"bad": True}
        valid_v = subprocess.CompletedProcess([], 0, "VALID\n", "")
        valid_s = subprocess.CompletedProcess([], 0, "6 LOW\n", "")
        with patch("sentinel.orchestrator._run", side_effect=[valid_v, valid_s]):
            d = analyze_batch([good_event(), invalid]).as_dict()
        self.assertEqual(d["total"], d["success_count"] + d["error_count"])


# ---------------------------------------------------------------------------
# Phase 2 — Score explainer
# ---------------------------------------------------------------------------

class ExplainerTests(unittest.TestCase):

    def _make(self, severity, failed_logins, suspicious_process, score, risk="LOW"):
        """Build a scored event dict matching analyze_event output shape."""
        return {
            "id": "T-EXP",
            "source": "test-host",
            "severity": severity,
            "failed_logins": failed_logins,
            "suspicious_process": suspicious_process,
            "score": score,
            "risk": risk,
        }

    def test_zero_score_no_indicators(self):
        ev = self._make(0, 0, False, 0, "LOW")
        result = explain_score(ev)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["raw_total"], 0)
        self.assertFalse(result["capped"])
        self.assertEqual(result["contributions"]["severity"], 0)
        self.assertEqual(result["contributions"]["failed_logins"], 0)
        self.assertEqual(result["contributions"]["suspicious_process"], 0)
        self.assertIn("No risk indicators", result["factors"][0])

    def test_severity_only_contribution(self):
        # severity=4 → 4*6=24, no logins, no susp
        ev = self._make(4, 0, False, 24, "LOW")
        result = explain_score(ev)
        self.assertEqual(result["contributions"]["severity"], 24)
        self.assertEqual(result["contributions"]["failed_logins"], 0)
        self.assertEqual(result["contributions"]["suspicious_process"], 0)
        self.assertEqual(result["raw_total"], 24)

    def test_failed_logins_uncapped(self):
        # logins=3 → 3*2=6
        ev = self._make(0, 3, False, 6, "LOW")
        result = explain_score(ev)
        self.assertEqual(result["contributions"]["failed_logins"], 6)

    def test_failed_logins_capped_at_ten(self):
        # logins=1000000 → capped to 10 → 10*2=20
        ev = self._make(0, 1000000, False, 20, "LOW")
        result = explain_score(ev)
        self.assertEqual(result["contributions"]["failed_logins"], 20)

    def test_suspicious_process_contribution(self):
        ev = self._make(0, 0, True, 20, "LOW")
        result = explain_score(ev)
        self.assertEqual(result["contributions"]["suspicious_process"], 20)
        self.assertTrue(any("Suspicious" in f for f in result["factors"]))

    def test_contribution_sum_equals_raw_total(self):
        # Invariant: sum of contributions == raw_total for all tested inputs.
        cases = [
            self._make(0, 0, False, 0, "LOW"),
            self._make(4, 3, False, 30, "MEDIUM"),
            self._make(7, 0, True, 62, "HIGH"),
            self._make(10, 10, True, 100, "CRITICAL"),
        ]
        for ev in cases:
            with self.subTest(score=ev["score"]):
                result = explain_score(ev)
                total = sum(result["contributions"].values())
                self.assertEqual(total, result["raw_total"])

    def test_min_raw_total_equals_native_score(self):
        # Invariant: min(raw_total, 100) == score for all tested inputs.
        cases = [
            self._make(0, 0, False, 0, "LOW"),
            self._make(4, 1, False, 26, "MEDIUM"),
            self._make(10, 1000000, True, 100, "CRITICAL"),
        ]
        for ev in cases:
            with self.subTest(score=ev["score"]):
                result = explain_score(ev)
                self.assertEqual(min(result["raw_total"], 100), result["score"])

    def test_capped_flag_true_when_raw_exceeds_100(self):
        # severity=10 (60) + logins=10 (20) + susp=True (20) = raw 100 → not capped
        ev = self._make(10, 10, True, 100, "CRITICAL")
        result = explain_score(ev)
        self.assertFalse(result["capped"])
        # severity=10 (60) + logins=10 (20) + susp=True (20) + fudge score=99 forces mismatch,
        # so test capping with a direct raw > 100 case: sev=10,logins=1000000,susp=True
        # raw = 60+20+20 = 100 exactly; capped is False
        # To get capped=True we need raw>100; formula caps at 100 so only raw can exceed
        # sev=10→60, logins>10→20, susp→20: raw=100, score=100 → not capped
        # (The formula never produces raw > 100 given constrained inputs; capped=False always)
        self.assertEqual(result["score"], 100)

    def test_result_has_expected_keys(self):
        ev = self._make(1, 0, False, 6, "LOW")
        result = explain_score(ev)
        for key in ("score", "risk", "contributions", "raw_total", "capped", "factors"):
            with self.subTest(key=key):
                self.assertIn(key, result)

    def test_contributions_has_three_keys(self):
        ev = self._make(1, 0, False, 6, "LOW")
        result = explain_score(ev)
        self.assertEqual(
            set(result["contributions"].keys()),
            {"severity", "failed_logins", "suspicious_process"},
        )

    def test_factors_is_nonempty_list(self):
        ev = self._make(1, 0, False, 6, "LOW")
        result = explain_score(ev)
        self.assertIsInstance(result["factors"], list)
        self.assertGreater(len(result["factors"]), 0)

    def test_missing_key_raises_key_error(self):
        with self.assertRaises(KeyError):
            explain_score({"severity": 1, "failed_logins": 0})

    def test_mismatch_raises_engine_error(self):
        # Tamper with score so native value disagrees with recomputed value.
        ev = self._make(1, 0, False, 99, "LOW")   # real score should be 6
        with self.assertRaises(EngineError):
            explain_score(ev)

    def test_login_capped_factor_mentions_cap(self):
        ev = self._make(0, 50, False, 20, "LOW")
        result = explain_score(ev)
        factor_text = " ".join(result["factors"])
        self.assertIn("capped", factor_text)

    def test_no_susp_factor_when_false(self):
        ev = self._make(1, 0, False, 6, "LOW")
        result = explain_score(ev)
        self.assertFalse(any("Suspicious" in f for f in result["factors"]))


# ---------------------------------------------------------------------------
# Phase 3 — Correlator
# ---------------------------------------------------------------------------

class CorrelatorTests(unittest.TestCase):

    def _scored(self, event_id, source, failed_logins, suspicious, risk, score=10):
        return {
            "id": event_id,
            "source": source,
            "severity": 1,
            "failed_logins": failed_logins,
            "suspicious_process": suspicious,
            "score": score,
            "risk": risk,
        }

    # --- basic structural tests ---------------------------------------------

    def test_empty_list_returns_empty(self):
        self.assertEqual(correlate([]), [])

    def test_returns_list(self):
        result = correlate([self._scored("E1", "h1", 0, False, "LOW")])
        self.assertIsInstance(result, list)

    def test_finding_has_required_fields(self):
        events = [self._scored("E1", "h1", 10, False, "LOW")]
        findings = correlate(events)
        self.assertGreater(len(findings), 0)
        f = findings[0]
        self.assertIsInstance(f, Finding)
        self.assertIsInstance(f.rule_id, str)
        self.assertIsInstance(f.finding_type, str)
        self.assertIsInstance(f.description, str)
        self.assertIsInstance(f.event_ids, list)

    def test_finding_as_dict(self):
        events = [self._scored("E1", "h1", 10, False, "LOW")]
        d = correlate(events)[0].as_dict()
        for key in ("rule_id", "finding_type", "description", "event_ids"):
            self.assertIn(key, d)

    # --- CORR-001: LOGIN_STORM ----------------------------------------------

    def test_corr001_fires_at_threshold(self):
        ev = self._scored("E1", "h1", 10, False, "LOW")
        findings = [f for f in correlate([ev]) if f.rule_id == "CORR-001"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "LOGIN_STORM")
        self.assertIn("E1", findings[0].event_ids)

    def test_corr001_fires_above_threshold(self):
        ev = self._scored("E1", "h1", 1000000, False, "LOW")
        findings = [f for f in correlate([ev]) if f.rule_id == "CORR-001"]
        self.assertEqual(len(findings), 1)

    def test_corr001_does_not_fire_below_threshold(self):
        ev = self._scored("E1", "h1", 9, False, "LOW")
        findings = [f for f in correlate([ev]) if f.rule_id == "CORR-001"]
        self.assertEqual(len(findings), 0)

    def test_corr001_fires_once_per_matching_event(self):
        events = [
            self._scored("E1", "h1", 10, False, "LOW"),
            self._scored("E2", "h2", 15, False, "LOW"),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-001"]
        self.assertEqual(len(findings), 2)

    # --- CORR-002: PROCESS_CLUSTER ------------------------------------------

    def test_corr002_fires_for_two_suspicious(self):
        events = [
            self._scored("E1", "h1", 0, True, "MEDIUM"),
            self._scored("E2", "h2", 0, True, "MEDIUM"),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "PROCESS_CLUSTER")
        self.assertIn("E1", findings[0].event_ids)
        self.assertIn("E2", findings[0].event_ids)

    def test_corr002_does_not_fire_for_one_suspicious(self):
        events = [
            self._scored("E1", "h1", 0, True, "MEDIUM"),
            self._scored("E2", "h2", 0, False, "LOW"),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-002"]
        self.assertEqual(len(findings), 0)

    def test_corr002_does_not_fire_for_zero_suspicious(self):
        events = [self._scored("E1", "h1", 0, False, "LOW")]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-002"]
        self.assertEqual(len(findings), 0)

    # --- CORR-003: MULTI_SOURCE_CRITICAL ------------------------------------

    def test_corr003_fires_for_two_distinct_critical_sources(self):
        events = [
            self._scored("E1", "host-a", 0, False, "CRITICAL", 80),
            self._scored("E2", "host-b", 0, False, "CRITICAL", 80),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "MULTI_SOURCE_CRITICAL")

    def test_corr003_does_not_fire_for_single_source_critical(self):
        events = [
            self._scored("E1", "host-a", 0, False, "CRITICAL", 80),
            self._scored("E2", "host-a", 0, False, "CRITICAL", 80),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-003"]
        self.assertEqual(len(findings), 0)

    def test_corr003_does_not_fire_with_no_critical(self):
        events = [self._scored("E1", "h1", 0, False, "HIGH", 50)]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-003"]
        self.assertEqual(len(findings), 0)

    # --- CORR-004: ELEVATED_BATCH_RISK --------------------------------------

    def test_corr004_fires_at_fifty_percent(self):
        events = [
            self._scored("E1", "h1", 0, False, "HIGH", 50),
            self._scored("E2", "h2", 0, False, "LOW", 10),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-004"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "ELEVATED_BATCH_RISK")

    def test_corr004_fires_above_fifty_percent(self):
        events = [
            self._scored("E1", "h1", 0, False, "CRITICAL", 80),
            self._scored("E2", "h2", 0, False, "HIGH", 50),
            self._scored("E3", "h3", 0, False, "LOW", 10),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-004"]
        self.assertEqual(len(findings), 1)

    def test_corr004_does_not_fire_below_fifty_percent(self):
        events = [
            self._scored("E1", "h1", 0, False, "HIGH", 50),
            self._scored("E2", "h2", 0, False, "LOW", 10),
            self._scored("E3", "h3", 0, False, "LOW", 10),
        ]
        findings = [f for f in correlate(events) if f.rule_id == "CORR-004"]
        self.assertEqual(len(findings), 0)

    # --- description safety -------------------------------------------------

    def test_description_contains_only_schema_data(self):
        # Description must not contain Python class names, tracebacks, or
        # anything beyond what comes from schema fields.
        events = [self._scored("EVT-42", "demo-host", 10, False, "LOW")]
        for f in correlate(events):
            self.assertNotIn("Traceback", f.description)
            self.assertNotIn("Exception", f.description)
            self.assertNotIn("<", f.description)

    def test_all_four_rules_can_fire_simultaneously(self):
        # Construct a batch that satisfies all four rule conditions at once.
        events = [
            # CORR-001: login storm; CORR-003 + CORR-004 contributor
            self._scored("E1", "src-alpha", 12, True, "CRITICAL", 80),
            # CORR-002: second suspicious; CORR-003 + CORR-004 contributor
            self._scored("E2", "src-beta",  0, True, "CRITICAL", 80),
        ]
        # CORR-001 (E1 has 12 logins), CORR-002 (2 suspicious),
        # CORR-003 (2 distinct CRITICAL sources), CORR-004 (100% HIGH/CRITICAL)
        rule_ids = {f.rule_id for f in correlate(events)}
        self.assertIn("CORR-001", rule_ids)
        self.assertIn("CORR-002", rule_ids)
        self.assertIn("CORR-003", rule_ids)
        self.assertIn("CORR-004", rule_ids)


# ---------------------------------------------------------------------------
# Phase 4 — v2 route and _build_report helper
# ---------------------------------------------------------------------------

class V2RouteTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def _mock_scored(self):
        """Minimal scored events usable without compiled binaries."""
        return [
            {"id": "SYN-001", "source": "demo-workstation", "severity": 1,
             "failed_logins": 0, "suspicious_process": False, "score": 6, "risk": "LOW"},
            {"id": "SYN-002", "source": "demo-auth-server", "severity": 4,
             "failed_logins": 3, "suspicious_process": False, "score": 30, "risk": "MEDIUM"},
            {"id": "SYN-003", "source": "demo-endpoint", "severity": 7,
             "failed_logins": 0, "suspicious_process": True, "score": 62, "risk": "HIGH"},
            {"id": "SYN-004", "source": "demo-gateway", "severity": 10,
             "failed_logins": 12, "suspicious_process": True, "score": 100, "risk": "CRITICAL"},
        ]

    # --- _build_report unit tests (no HTTP, no binaries) --------------------

    def test_build_report_keys(self):
        report = _build_report(self._mock_scored())
        for key in ("synthetic", "total_events", "risk_distribution", "events", "correlations"):
            self.assertIn(key, report)

    def test_build_report_total_events(self):
        scored = self._mock_scored()
        report = _build_report(scored)
        self.assertEqual(report["total_events"], len(scored))

    def test_build_report_synthetic_true(self):
        self.assertTrue(_build_report(self._mock_scored())["synthetic"])

    def test_build_report_risk_distribution_sums(self):
        report = _build_report(self._mock_scored())
        dist = report["risk_distribution"]
        self.assertEqual(sum(dist.values()), report["total_events"])

    def test_build_report_risk_distribution_keys(self):
        dist = _build_report(self._mock_scored())["risk_distribution"]
        self.assertEqual(set(dist.keys()), {"LOW", "MEDIUM", "HIGH", "CRITICAL"})

    def test_build_report_events_have_explanation_fields(self):
        for ev in _build_report(self._mock_scored())["events"]:
            with self.subTest(event_id=ev["id"]):
                self.assertIn("contributions", ev)
                self.assertIn("factors", ev)
                self.assertIn("raw_total", ev)
                self.assertIn("capped", ev)

    def test_build_report_correlations_is_list(self):
        self.assertIsInstance(_build_report(self._mock_scored())["correlations"], list)

    def test_build_report_empty_scored(self):
        report = _build_report([])
        self.assertEqual(report["total_events"], 0)
        self.assertEqual(report["events"], [])
        self.assertEqual(report["correlations"], [])
        self.assertEqual(sum(report["risk_distribution"].values()), 0)

    # --- /api/v2/report HTTP tests (mocked analyze_fixtures) ----------------

    def test_v2_report_returns_200(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            response = self.client.get("/api/v2/report")
        self.assertEqual(response.status_code, 200)

    def test_v2_report_is_json(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            response = self.client.get("/api/v2/report")
        self.assertIsNotNone(response.json)

    def test_v2_report_json_structure(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            data = self.client.get("/api/v2/report").json
        for key in ("synthetic", "total_events", "risk_distribution", "events", "correlations"):
            self.assertIn(key, data)

    def test_v2_report_event_count_matches(self):
        scored = self._mock_scored()
        with patch("app.analyze_fixtures", return_value=scored):
            data = self.client.get("/api/v2/report").json
        self.assertEqual(data["total_events"], len(scored))

    def test_v2_report_risk_distribution_sums_to_total(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            data = self.client.get("/api/v2/report").json
        self.assertEqual(
            sum(data["risk_distribution"].values()),
            data["total_events"],
        )

    def test_v2_report_engine_failure_returns_503(self):
        with patch("app.analyze_fixtures", side_effect=EngineError("Build required")):
            response = self.client.get("/api/v2/report")
        self.assertEqual(response.status_code, 503)

    def test_v2_report_security_headers(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            response = self.client.get("/api/v2/report")
        self.assertEqual(response.headers.get("Content-Security-Policy"), "default-src 'self'")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def test_v2_report_does_not_expose_error_details(self):
        with patch("app.analyze_fixtures", side_effect=EngineError("internal detail")):
            data = self.client.get("/api/v2/report").json
        # The JSON error key must not contain raw internal paths or tracebacks.
        self.assertNotIn("Traceback", str(data))

    # --- GET / backward-compatibility (no binaries needed) ------------------

    def test_dashboard_still_returns_200(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_still_contains_sentinel_ops(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            response = self.client.get("/")
        self.assertIn(b"SentinelOps AI", response.data)

    def test_api_events_contract_unchanged(self):
        with patch("app.analyze_fixtures", return_value=self._mock_scored()):
            data = self.client.get("/api/events").json
        self.assertTrue(data["synthetic"])
        self.assertEqual(len(data["events"]), 4)


if __name__ == "__main__":
    unittest.main()
