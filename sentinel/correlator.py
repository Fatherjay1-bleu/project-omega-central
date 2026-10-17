"""
Deterministic correlation rules applied to a set of scored events.

Rules operate only on fields present in the documented event schema:
  id, source, severity, failed_logins, suspicious_process, score, risk.

No timestamps, IP addresses, user identities, or sequence assumptions are used.
Findings describe deterministic indicators, not causal or temporal relationships.
"""
from dataclasses import dataclass, field
from typing import List

_HIGH_RISK_LEVELS         = {"HIGH", "CRITICAL"}
_LOGIN_STORM_THRESHOLD    = 10     # CORR-001: single-event failed_logins >= this
_CLUSTER_MIN_COUNT        = 2      # CORR-002/003: minimum matching events
_ELEVATED_BATCH_FRACTION  = 0.5   # CORR-004: >= 50 % of events HIGH or CRITICAL


@dataclass
class Finding:
    """A single correlation finding.  All text is derived from event schema fields."""
    rule_id:      str
    finding_type: str
    description:  str
    event_ids:    List[str] = field(default_factory=list)

    def as_dict(self):
        return {
            "rule_id":      self.rule_id,
            "finding_type": self.finding_type,
            "description":  self.description,
            "event_ids":    self.event_ids,
        }


def correlate(scored_events):
    """Apply all correlation rules to a list of scored event dicts.

    Returns a list of Finding objects (empty list if no rules fire or input is empty).
    scored_events must be the output of analyze_event / analyze_batch.scored.
    Does not raise; individual rule failures would be surfaced as missing findings.
    """
    if not scored_events:
        return []

    findings = []
    findings.extend(_rule_login_storm(scored_events))
    findings.extend(_rule_process_cluster(scored_events))
    findings.extend(_rule_multi_source_critical(scored_events))
    findings.extend(_rule_elevated_batch_risk(scored_events))
    return findings


# ---------------------------------------------------------------------------
# CORR-001: High-volume failed logins on a single event
# ---------------------------------------------------------------------------

def _rule_login_storm(events):
    findings = []
    for ev in events:
        if ev["failed_logins"] >= _LOGIN_STORM_THRESHOLD:
            findings.append(Finding(
                rule_id="CORR-001",
                finding_type="LOGIN_STORM",
                description=(
                    f"Event {ev['id']} recorded {ev['failed_logins']} failed login(s), "
                    f"meeting the high-volume threshold of {_LOGIN_STORM_THRESHOLD}."
                ),
                event_ids=[ev["id"]],
            ))
    return findings


# ---------------------------------------------------------------------------
# CORR-002: Multiple events with suspicious_process = true
# ---------------------------------------------------------------------------

def _rule_process_cluster(events):
    flagged = [ev for ev in events if ev["suspicious_process"]]
    if len(flagged) >= _CLUSTER_MIN_COUNT:
        return [Finding(
            rule_id="CORR-002",
            finding_type="PROCESS_CLUSTER",
            description=(
                f"{len(flagged)} event(s) reported a suspicious process indicator: "
                f"{', '.join(ev['id'] for ev in flagged)}."
            ),
            event_ids=[ev["id"] for ev in flagged],
        )]
    return []


# ---------------------------------------------------------------------------
# CORR-003: CRITICAL risk observed from multiple distinct sources
# ---------------------------------------------------------------------------

def _rule_multi_source_critical(events):
    critical_events  = [ev for ev in events if ev["risk"] == "CRITICAL"]
    critical_sources = {ev["source"] for ev in critical_events}
    if len(critical_sources) >= _CLUSTER_MIN_COUNT:
        return [Finding(
            rule_id="CORR-003",
            finding_type="MULTI_SOURCE_CRITICAL",
            description=(
                f"CRITICAL risk score observed from {len(critical_sources)} "
                f"distinct source(s): {', '.join(sorted(critical_sources))}."
            ),
            event_ids=[ev["id"] for ev in critical_events],
        )]
    return []


# ---------------------------------------------------------------------------
# CORR-004: High proportion of HIGH/CRITICAL events in the batch
# ---------------------------------------------------------------------------

def _rule_elevated_batch_risk(events):
    high_or_critical = [ev for ev in events if ev["risk"] in _HIGH_RISK_LEVELS]
    fraction = len(high_or_critical) / len(events)
    if fraction >= _ELEVATED_BATCH_FRACTION:
        pct = int(fraction * 100)
        return [Finding(
            rule_id="CORR-004",
            finding_type="ELEVATED_BATCH_RISK",
            description=(
                f"{pct}% of events ({len(high_or_critical)}/{len(events)}) "
                f"are rated HIGH or CRITICAL."
            ),
            event_ids=[ev["id"] for ev in high_or_critical],
        )]
    return []
