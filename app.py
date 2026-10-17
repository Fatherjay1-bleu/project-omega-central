"""Loopback-only demonstration dashboard; all displayed events are synthetic."""
from flask import Flask, jsonify, render_template, request
from sentinel.correlator import correlate
from sentinel.explainer import explain_score
from sentinel.ingestor import IngestionError, MAX_CONTENT_LENGTH, ingest_and_analyze
from sentinel.orchestrator import EngineError, analyze_fixtures

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


@app.errorhandler(EngineError)
def engine_error(error):
    return jsonify(error=str(error)), 503


@app.errorhandler(IngestionError)
def ingestion_error(error):
    return jsonify(error=str(error)), error.http_status


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Request body too large."), 413


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


@app.post("/api/v3/analyze")
def v3_analyze():
    body = request.get_json(force=False, silent=True)
    origin         = request.headers.get("Origin")
    sec_fetch_site = request.headers.get("Sec-Fetch-Site")
    batch = ingest_and_analyze(body, origin, sec_fetch_site)
    scored = batch.scored
    if scored:
        report = _build_report(scored)
    else:
        report = {
            "synthetic":         True,
            "total_events":      0,
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "events":            [],
            "correlations":      [],
        }
    return jsonify(
        synthetic      = report["synthetic"],
        total_events   = report["total_events"],
        risk_distribution = report["risk_distribution"],
        events         = report["events"],
        correlations   = report["correlations"],
        success_count  = len(batch.scored),
        error_count    = len(batch.errors),
        errors         = batch.errors,
    ), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
