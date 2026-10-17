"""Loopback-only demonstration dashboard; all displayed events are synthetic."""
from flask import Flask, jsonify, render_template
from sentinel.orchestrator import EngineError, analyze_fixtures

app = Flask(__name__)


@app.errorhandler(EngineError)
def engine_error(error):
    return jsonify(error=str(error)), 503


@app.get("/")
def dashboard():
    events = analyze_fixtures()
    return render_template("dashboard.html", events=events)


@app.get("/api/events")
def events_api():
    return jsonify(events=analyze_fixtures(), synthetic=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
