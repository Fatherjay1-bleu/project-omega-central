import subprocess
import unittest
from unittest.mock import patch

from app import app
from sentinel.orchestrator import (
    EngineError, InvalidEvent, _run, analyze_event, analyze_fixtures,
)


def event(**updates):
    return {"id": "TEST-001", "source": "synthetic-host", "severity": 1,
            "failed_logins": 0, "suspicious_process": False, **updates}


class NativeTests(unittest.TestCase):
    def test_validator_valid_boundaries(self):
        for payload in ("0 0 0\n", "10 1000000 1\n"):
            with self.subTest(payload=payload):
                result = _run("validator", payload)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, "VALID"))

    def test_both_engines_reject_malformed(self):
        for name in ("validator", "scorer"):
            for payload in ("", "hello", "1 2", "1 2 0 extra", "-1 0 0",
                            "11 0 0", "1 -1 0", "1 1000001 0", "1 0 2",
                            "1.5 0 0", "1 0.5 0", "nan 0 0", "inf 0 0"):
                with self.subTest(engine=name, payload=payload):
                    self.assertNotEqual(_run(name, payload).returncode, 0)

    def test_score_thresholds(self):
        for severity, failures, suspicious, score, risk in (
            (0, 0, False, 0, "LOW"), (4, 0, False, 24, "LOW"),
            (4, 1, False, 26, "MEDIUM"), (8, 0, False, 48, "MEDIUM"),
            (8, 1, False, 50, "HIGH"), (10, 9, False, 78, "HIGH"),
            (10, 10, False, 80, "CRITICAL"), (10, 1000000, True, 100, "CRITICAL"),
        ):
            with self.subTest(score=score):
                result = analyze_event(event(severity=severity, failed_logins=failures,
                                             suspicious_process=suspicious))
                self.assertEqual((result["score"], result["risk"]), (score, risk))


class OrchestrationTests(unittest.TestCase):
    def test_malformed_events(self):
        invalid = [None, [], {}, event(severity=True), event(severity=11),
                   event(severity=1.5), event(failed_logins=-1),
                   event(failed_logins=1000001), event(failed_logins="2"),
                   event(suspicious_process=1), event(id=""),
                   event(source="x\n"), event(source="x" * 129), event(extra=1)]
        for value in invalid:
            with self.subTest(value=value), patch("sentinel.orchestrator._run") as native:
                with self.assertRaises(InvalidEvent):
                    analyze_event(value)
                native.assert_not_called()

    def test_missing_and_stalled_engine(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("engine", 5)):
            with self.subTest(error=error), patch("subprocess.run", side_effect=error):
                with self.assertRaises(EngineError):
                    analyze_event(event())

    def test_fail_closed_on_engine_errors(self):
        valid = subprocess.CompletedProcess([], 0, "VALID\n", "")
        invalid_results = [(1, "50 HIGH"), (0, "101 CRITICAL"),
                           (0, "50 LOW"), (0, "garbage"), (0, "nan LOW")]
        for code, output in invalid_results:
            bad = subprocess.CompletedProcess([], code, output, "")
            with self.subTest(output=output), patch("sentinel.orchestrator._run", side_effect=[valid, bad]):
                with self.assertRaises(EngineError):
                    analyze_event(event())
        with patch("sentinel.orchestrator._run", return_value=subprocess.CompletedProcess([], 1, "INVALID", "")):
            with self.assertRaises(EngineError):
                analyze_event(event())

    def test_synthetic_fixtures(self):
        self.assertEqual([item["risk"] for item in analyze_fixtures()],
                         ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_corrupt_fixture_json(self):
        with patch("sentinel.orchestrator.Path.read_text", return_value="not json"):
            with self.assertRaises(EngineError):
                analyze_fixtures()

    def test_invalid_fixture_event(self):
        bad = '[{"id":"X","source":"Y","severity":99,"failed_logins":0,"suspicious_process":false}]'
        with patch("sentinel.orchestrator.Path.read_text", return_value=bad):
            with self.assertRaises(EngineError):
                analyze_fixtures()


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_dashboard(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SentinelOps AI", response.data)
        self.assertIn(b"SYN-004", response.data)

    def test_json(self):
        response = self.client.get("/api/events")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["synthetic"])
        self.assertEqual(len(response.json["events"]), 4)

    def test_engine_failure_is_service_unavailable(self):
        with patch("app.analyze_fixtures", side_effect=EngineError("Build required")):
            self.assertEqual(self.client.get("/").status_code, 503)
            self.assertEqual(self.client.get("/api/events").status_code, 503)

    def test_html_escapes_event_text(self):
        result = {**event(source="<script>alert(1)</script>"), "score": 6, "risk": "LOW"}
        with patch("app.analyze_fixtures", return_value=[result]):
            response = self.client.get("/")
            self.assertIn(b"&lt;script&gt;", response.data)
            self.assertNotIn(b"<script>", response.data)

    def test_security_headers(self):
        for path in ("/", "/api/events"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.headers.get("Content-Security-Policy"), "default-src 'self'")
                self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
                self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def test_security_headers_on_error_response(self):
        with patch("app.analyze_fixtures", side_effect=EngineError("Build required")):
            response = self.client.get("/")
            self.assertEqual(response.status_code, 503)
            self.assertIn("Content-Security-Policy", response.headers)
            self.assertIn("X-Content-Type-Options", response.headers)


if __name__ == "__main__":
    unittest.main()
