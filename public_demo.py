"""Read-only public demo entrypoint. Only packaged synthetic events are analyzed.

This is intentionally separate from the local development app: the public
deployment serves GET requests only and offers three deterministic scenarios.
No externally supplied events are accepted or recorded.
"""
import json
from pathlib import Path

from flask import jsonify, request
from werkzeug.exceptions import MethodNotAllowed

from app import app as application, _build_report
from sentinel.batch import analyze_batch

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
