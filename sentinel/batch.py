"""Batch analysis: validate and score a list of synthetic event dicts."""
from sentinel.orchestrator import InvalidEvent, analyze_event

# Maximum events accepted per batch; prevents runaway iteration.
MAX_BATCH_SIZE = 500

_SAFE_ID_MAX_LEN = 128


def _safe_event_id(raw):
    """Return a sanitized event ID string, or None if the event has no safe ID.

    Accepts only str values that pass the same printability rules as analyze_event.
    Never exposes raw exception details.
    """
    if not isinstance(raw, dict):
        return None
    value = raw.get("id")
    if (not isinstance(value, str) or not value.strip()
            or len(value) > _SAFE_ID_MAX_LEN
            or any(ord(c) < 32 for c in value)):
        return None
    return value


class BatchResult:
    """Holds successes and per-event failures from a batch run."""

    def __init__(self, scored, errors):
        self.scored = scored   # list of enriched event dicts (score, risk added)
        self.errors = errors   # list of {"index": int, "id": str|None, "reason": str}

    def as_dict(self):
        return {
            "scored": self.scored,
            "errors": self.errors,
            "total": len(self.scored) + len(self.errors),
            "success_count": len(self.scored),
            "error_count": len(self.errors),
        }


def analyze_batch(events):
    """Analyze a list of event dicts.  Returns a BatchResult.

    Raises TypeError  if events is not a list.
    Raises ValueError if the list exceeds MAX_BATCH_SIZE.
    Individual InvalidEvent failures are captured per-event, not raised.
    EngineError (binary missing/timeout) propagates to the caller unchanged —
    the entire batch fails closed, consistent with the existing fail-closed policy.
    """
    if not isinstance(events, list):
        raise TypeError("events must be a list.")
    if len(events) > MAX_BATCH_SIZE:
        raise ValueError(
            f"Batch size {len(events)} exceeds maximum of {MAX_BATCH_SIZE}."
        )

    scored, errors = [], []
    for i, raw in enumerate(events):
        try:
            scored.append(analyze_event(raw))
        except InvalidEvent:
            # Sanitize: only include a safe ID and a fixed-vocabulary reason.
            errors.append({
                "index": i,
                "id": _safe_event_id(raw),
                "reason": "Event did not pass schema validation.",
            })
    return BatchResult(scored, errors)
