"""
Explainable score decomposition.

Derives per-attribute contribution breakdowns from the canonical scoring formula.

Canonical formula (read-only — defined authoritatively in native/scorer.cpp):
    score = min(100, severity*6 + min(failed_logins, 10)*2 + suspicious_flag*20)

This module recomputes the formula in Python purely for explanation purposes.
The authoritative score is always the integer returned by the C++ scorer via
analyze_event().  If this module's recomputation disagrees with that score,
explain_score() raises EngineError rather than displaying contradictory values.
"""
from sentinel.orchestrator import EngineError

# Mirror the C++ constants exactly — change only if scorer.cpp changes.
_MAX_SCORE          = 100
_SEVERITY_WEIGHT    = 6
_LOGIN_WEIGHT       = 2
_LOGIN_CAP          = 10
_SUSPICIOUS_WEIGHT  = 20


def explain_score(scored_event):
    """Return an explanation dict for a fully scored event dict.

    Input must already contain 'score' and 'risk' keys (output of analyze_event).

    Raises KeyError    if required fields are absent.
    Raises EngineError if the Python recomputation disagrees with the native score,
                       preventing contradictory information from reaching the UI.
    """
    sev    = scored_event["severity"]
    logins = scored_event["failed_logins"]
    susp   = scored_event["suspicious_process"]
    native_score = scored_event["score"]

    sev_contrib   = sev * _SEVERITY_WEIGHT
    login_contrib = min(logins, _LOGIN_CAP) * _LOGIN_WEIGHT
    susp_contrib  = _SUSPICIOUS_WEIGHT if susp else 0
    raw_total     = sev_contrib + login_contrib + susp_contrib
    recomputed    = min(raw_total, _MAX_SCORE)

    if recomputed != native_score:
        raise EngineError(
            "Score explanation is inconsistent with the native engine result."
        )

    return {
        "score": native_score,
        "risk": scored_event["risk"],
        "contributions": {
            "severity":           sev_contrib,
            "failed_logins":      login_contrib,
            "suspicious_process": susp_contrib,
        },
        "raw_total": raw_total,
        "capped": raw_total > _MAX_SCORE,
        "factors": _build_factors(sev, logins, susp, login_contrib),
    }


def _build_factors(sev, logins, susp, login_contrib):
    """Return human-readable sentences describing non-zero contributors."""
    factors = []
    if sev > 0:
        factors.append(
            f"Severity {sev}/10 contributed {sev * _SEVERITY_WEIGHT} points."
        )
    if login_contrib > 0:
        capped_note = (
            f" ({logins} total, capped at {_LOGIN_CAP})" if logins > _LOGIN_CAP else ""
        )
        factors.append(
            f"{logins} failed login(s){capped_note} contributed {login_contrib} points."
        )
    if susp:
        factors.append(
            f"Suspicious process flag contributed {_SUSPICIOUS_WEIGHT} points."
        )
    if not factors:
        factors.append("No risk indicators detected.")
    return factors
