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


def _clamp(value, lower=0.0, upper=1.0):
    try:
        return max(lower, min(upper, float(value)))
    except (TypeError, ValueError):
        return lower