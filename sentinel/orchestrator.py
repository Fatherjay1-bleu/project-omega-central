"""Validate untrusted records before invoking the native engines."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {"id", "source", "severity", "failed_logins", "suspicious_process"}


class InvalidEvent(ValueError):
    pass


class EngineError(RuntimeError):
    pass


def _run(name, payload):
    binary = ROOT / "build" / (name + (".exe" if os.name == "nt" else ""))
    try:
        return subprocess.run([str(binary)], input=payload, text=True,
                              capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EngineError(f"Cannot run {name}; run the build script first.") from exc


def analyze_event(event):
    if not isinstance(event, dict) or set(event) != FIELDS:
        raise InvalidEvent("Event must contain exactly the documented fields.")
    for field in ("id", "source"):
        value = event[field]
        if (not isinstance(value, str) or not value.strip() or len(value) > 128
                or any(ord(char) < 32 for char in value)):
            raise InvalidEvent(f"{field} must be printable text of 1–128 characters.")
    for field, maximum in (("severity", 10), ("failed_logins", 1000000)):
        if type(event[field]) is not int or not 0 <= event[field] <= maximum:
            raise InvalidEvent(f"{field} must be an integer from 0 to {maximum}.")
    if type(event["suspicious_process"]) is not bool:
        raise InvalidEvent("suspicious_process must be a boolean.")
    payload = f'{event["severity"]} {event["failed_logins"]} {int(event["suspicious_process"])}\n'
    validation = _run("validator", payload)
    if validation.returncode != 0 or validation.stdout.strip() != "VALID":
        raise EngineError("Native validator rejected a schema-valid event.")
    result = _run("scorer", payload)
    try:
        score_text, risk = result.stdout.split()
        score = int(score_text)
        expected = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        if result.returncode != 0 or not 0 <= score <= 100 or risk != expected:
            raise ValueError("Invalid score")
    except ValueError as exc:
        raise EngineError("Native scorer returned an invalid result.") from exc
    return {**event, "score": score, "risk": risk}


def analyze_fixtures():
    try:
        events = json.loads((ROOT / "data" / "events.json").read_text(encoding="utf-8"))
        return [analyze_event(event) for event in events]
    except (json.JSONDecodeError, InvalidEvent) as exc:
        raise EngineError("Fixture data is unavailable.") from exc
