"""Loopback-only demonstration dashboard; all displayed events are synthetic."""
from flask import Flask, jsonify, render_template
from sentinel.correlator import correlate
from sentinel.explainer import explain_score
from sentinel.orchestrator import EngineError, analyze_fixtures

app = Flask(__name__)


@app.errorhandler(EngineError)
def engine_error(error):
    return jsonify(error=str(error)), 503


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _build_report(scored):
    """Build the v2 report payload from a list of scored event dicts.

    Pure Python — no I/O, no HTTP calls.  Raises EngineError if any
    explanation is inconsistent with the native score.
    """
    explained = [{**ev, **explain_score(ev)} for ev in scored]
    findings  = [f.as_dict() for f in correlate(scored)]
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for ev in scored:
        risk_counts[ev["risk"]] += 1
    return {
        "synthetic":        True,
        "total_events":     len(scored),
        "risk_distribution": risk_counts,
        "events":           explained,
        "correlations":     findings,
    }


@app.get("/")
def dashboard():
    scored = analyze_fixtures()
    report = _build_report(scored)
    return render_template("dashboard.html", events=scored, report=report)


@app.get("/api/events")
def events_api():
    return jsonify(events=analyze_fixtures(), synthetic=True)


@app.get("/api/v2/report")
def v2_report():
    scored = analyze_fixtures()
    return jsonify(_build_report(scored))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
