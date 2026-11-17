from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_ATTACK_TEXT = {
    "brute_force": ("Repeated authentication failures", "An account may be exposed to credential guessing."),
    "brute_force_login": ("Repeated authentication failures", "An account may be exposed to credential guessing."),
    "ddos": ("Potential denial-of-service activity", "Service availability may be affected by excessive traffic."),
    "dns_tunneling": ("Potential DNS tunneling", "DNS may be carrying unusual data or command traffic."),
    "port_scan": ("Network service discovery activity", "An actor may be mapping reachable services."),
    "scanning": ("Network service discovery activity", "An actor may be mapping reachable services."),
    "sql_injection": ("Potential SQL injection", "An application or database may be exposed to unauthorized query manipulation."),
    "suspicious_process_execution": ("Suspicious process execution", "A host may be running an unexpected or unsafe command."),
    "threat_intelligence_match": ("Threat-intelligence indicator match", "An observed indicator is associated with threat-intelligence evidence."),
    "multi_stage_incident": ("Correlated multi-domain activity", "Related detections across security domains may indicate a broader incident."),
}

_ACTION_STEPS = {
    "brute_force": "Review failed-login history, source addresses, and affected accounts; enforce approved lockout and MFA policies.",
    "brute_force_login": "Review failed-login history, source addresses, and affected accounts; enforce approved lockout and MFA policies.",
    "ddos": "Compare traffic with service baselines and upstream telemetry; apply approved rate limiting or provider mitigation if impact is confirmed.",
    "dns_tunneling": "Review queried domains, resolver logs, and endpoint processes; block indicators only after validation.",
    "port_scan": "Verify the source and destination scope, then restrict unnecessary exposed services under change control.",
    "scanning": "Verify the source and destination scope, then restrict unnecessary exposed services under change control.",
    "sql_injection": "Preserve the request and application logs; validate parameterized queries, input handling, and exposed application paths.",
    "suspicious_process_execution": "Preserve endpoint telemetry and inspect the process tree, command line, signer, and file provenance.",
    "threat_intelligence_match": "Validate the indicator and its age/reputation with the provider before blocking or isolating assets.",
    "multi_stage_incident": "Review the linked event timeline and affected assets; assign an incident owner and preserve relevant evidence.",
}


def explain_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic, evidence-linked explanation and response checklist."""
    attack = str(alert.get("attack_name", "suspicious_activity")).strip().lower()
    title, impact = _ATTACK_TEXT.get(
        attack,
        ("Suspicious activity detected", "The observed behavior may indicate a security policy violation or threat."),
    )
    evidence = alert.get("evidence", [])
    evidence_summary = [
        _evidence_text(item) for item in evidence
    ] if isinstance(evidence, list) else []
    evidence_summary = [item for item in evidence_summary if item]
    if evidence_summary:
        why = "Detection is supported by: " + "; ".join(evidence_summary) + "."
    else:
        why = "The detector flagged this event, but no additional evidence details were supplied."

    severity_reason = str(alert.get("severity_reason", "Severity reflects corroborating evidence, not confidence alone."))
    confidence = alert.get("confidence_score")
    confidence_note = (
        f"Model confidence is {float(confidence):.3f}; it is a model score and is not necessarily calibrated."
        if isinstance(confidence, (int, float))
        else "No model confidence score was provided."
    )
    mitigation = _ACTION_STEPS.get(
        attack,
        "Validate the event against surrounding telemetry before taking containment action.",
    )
    return {
        "alert_title": title,
        "what_happened": f"{title}.",
        "why_detected": why,
        "potential_impact": impact,
        "confidence_note": confidence_note,
        "severity_reason": severity_reason,
        "evidence_summary": evidence_summary,
        "immediate_action": "Acknowledge the alert, check current service or account impact, and preserve relevant logs.",
        "investigation_steps": [
            "Review the linked event and nearby telemetry for the same asset or identity.",
            "Confirm timestamps, source context, and whether the activity is expected.",
            "Check the listed evidence and threat-intelligence provider status.",
        ],
        "containment_recommendation": mitigation,
        "recovery_guidance": "Restore affected services or credentials only after the cause is understood and controls are verified.",
        "escalation_guidance": "Escalate high or critical alerts, confirmed impact, or unexplained correlated activity to the incident-response owner.",
        "automated_response": "No containment or remediation action was performed automatically.",
    }


def _evidence_text(item: object) -> str:
    if isinstance(item, Mapping):
        return str(item.get("description") or item.get("signal") or "").strip()
    return str(item).strip()
