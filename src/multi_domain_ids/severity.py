from __future__ import annotations

from collections.abc import Iterable, Mapping


_SEVERITY_REASON = {
    "critical": "Correlated detections span at least three security domains with independent evidence.",
    "high": "Multiple independent detection signals or threat-intelligence corroboration are present.",
    "medium": "A detection signal supports suspicious activity, but independent corroboration is limited.",
    "low": "A model or rule flagged activity without independent corroborating evidence.",
    "informational": "The event was not classified as suspicious.",
}


def assess_severity(
    suspicious: bool,
    evidence: Iterable[Mapping[str, object] | str],
    *,
    threat_matches: Iterable[Mapping[str, object]] = (),
    correlated_domains: Iterable[str] = (),
) -> tuple[str, str]:
    """Assess severity from independent evidence, never from model confidence alone."""
    if not suspicious:
        return "informational", _SEVERITY_REASON["informational"]

    evidence_items = list(evidence)
    distinct_signals = {
        str(item.get("signal") or item.get("source") or item.get("description") or "")
        if isinstance(item, Mapping)
        else str(item)
        for item in evidence_items
    }
    distinct_signals.discard("")
    matches = list(threat_matches)
    domains = {str(domain).strip().lower() for domain in correlated_domains if str(domain).strip()}

    if len(domains) >= 3 and len(distinct_signals) >= 3:
        return "critical", _SEVERITY_REASON["critical"]
    if len(distinct_signals) >= 3 or (len(distinct_signals) >= 1 and matches):
        return "high", _SEVERITY_REASON["high"]
    if distinct_signals:
        return "medium", _SEVERITY_REASON["medium"]
    return "low", _SEVERITY_REASON["low"]


def severity_reason(severity: str) -> str:
    try:
        return _SEVERITY_REASON[severity.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported severity: {severity!r}") from exc
