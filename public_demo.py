"""Read-only public demo entrypoint. Only packaged synthetic events are analyzed.

This is intentionally separate from the local development app: the public
deployment serves GET requests only and offers three deterministic scenarios.
No externally supplied events are accepted or recorded.
"""
import json
from pathlib import Path

from flask import jsonify, render_template, request
from werkzeug.exceptions import MethodNotAllowed

from app import app as application, _build_report
from sentinel.batch import analyze_batch
from sentinel.orchestrator import EngineError, analyze_event

# ---------------------------------------------------------------------------
# Fixed synthetic probe event for the native-engine health check.
# Chosen so the expected score is unambiguous:
#   severity=1 → 1*6=6, failed_logins=0 → 0, suspicious_process=False → 0
#   score = 6, risk = LOW
# ---------------------------------------------------------------------------
_HEALTH_PROBE = {
    "id":                "HEALTH-PROBE",
    "source":            "healthcheck",
    "severity":          1,
    "failed_logins":     0,
    "suspicious_process": False,
}
_HEALTH_EXPECTED_SCORE = 6
_HEALTH_EXPECTED_RISK  = "LOW"

SCENARIOS = {
    1: ("Normal activity", "Low-risk events with no correlation findings."),
    2: ("Authentication incident", "Repeated failed logins trigger CORR-001."),
    3: ("High-risk cluster", "All six correlation rule types are exercised."),
}
DATA_DIR = Path(__file__).resolve().parent / "data"


@application.before_request
def public_get_only():
    # No external event ingestion or other state-changing HTTP methods.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        raise MethodNotAllowed(valid_methods=["GET", "HEAD", "OPTIONS"])


@application.get("/demo")
def demo_index():
    return jsonify(
        synthetic=True,
        notice="Read-only demonstration; only prepackaged synthetic events are processed.",
        dashboard="/",
        scenarios=[
            {"number": number, "title": title, "description": description,
             "url": f"/demo/scenario/{number}"}
            for number, (title, description) in SCENARIOS.items()
        ],
    )


@application.get("/demo/scenario/<int:number>")
def demo_scenario(number):
    if number not in SCENARIOS:
        return jsonify(error="Unknown demonstration scenario."), 404
    path = DATA_DIR / f"demo_scenario_{number}.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    batch = analyze_batch(events)
    report = _build_report(batch.scored)
    return jsonify(
        scenario=number,
        title=SCENARIOS[number][0],
        description=SCENARIOS[number][1],
        **report,
        success_count=len(batch.scored),
        error_count=len(batch.errors),
        errors=batch.errors,
    )


@application.get("/health")
def health():
    """Native-engine readiness check.

    Passes a fixed synthetic probe event through the real C validator and C++
    scorer.  Returns 200 when both engines accept the probe and produce the
    expected score.  Returns 503 when either engine is unavailable, times out,
    or returns unexpected output.

    No external input is accepted.  No internal details, paths, or diagnostics
    are included in any response.
    """
    try:
        result = analyze_event(_HEALTH_PROBE)
        if result["score"] != _HEALTH_EXPECTED_SCORE or result["risk"] != _HEALTH_EXPECTED_RISK:
            raise EngineError("Native engine returned an unexpected result for the health probe.")
    except EngineError:
        return jsonify(status="unavailable"), 503
    return jsonify(status="ok", engine="native-c-cpp", synthetic=True), 200


# Reuse the app's existing '/' route while presenting the interactive console
# only in the public demo. Local development routes and unit tests stay intact.
def interactive_console():
    return render_template("console.html")


application.view_functions["dashboard"] = interactive_console

