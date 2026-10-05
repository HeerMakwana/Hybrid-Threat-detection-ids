"""Explainable 100-point risk scoring for streaming IDS events."""


def calculate_risk(
    ml_confidence,
    threat_intel_score,
    attack_severity,
    mitre_score,
    repetition_score,
):
    """Convert normalized signals into an explainable 0-100 risk score."""

    components = {
        "ml": round(_clamp(ml_confidence) * 40),
        "threat_intelligence": round(_clamp(threat_intel_score) * 25),
        "attack_severity": round(_clamp(attack_severity) * 20),
        "mitre": round(_clamp(mitre_score) * 10),
        "repetition": round(_clamp(repetition_score) * 5),
    }
    score = sum(components.values())

    return {
        "score": int(score),
        "severity": classify_risk(score),
        "priority": classify_priority(score),
        "recommended_action": "PENDING_HUMAN_REVIEW",
        "factors": components,
    }


def classify_risk(score):
    """Map the final risk score to an operator-friendly severity."""

    score = _clamp(score, upper=100.0)
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def classify_priority(score):
    """Map risk to an ordered analyst queue without taking network action."""
    score = _clamp(score, upper=100.0)
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def _clamp(value, lower=0.0, upper=1.0):
    try:
        return max(lower, min(upper, float(value)))
    except (TypeError, ValueError):
        return lower