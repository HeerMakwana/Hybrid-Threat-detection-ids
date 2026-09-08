"""Canonical security event schema emitted by the IDS."""

from datetime import datetime, timezone
from uuid import uuid4


def create_security_event(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    attack_type,
    prediction,
    ml_confidence,
    threshold,
    risk_score,
    severity,
    mitre_tactic=None,
    mitre_technique=None,
    threat_intel=None,
    explanation=None,
    attack_name=None,
    detector_version="1.0",
):
    """Create the normalized JSON event consumed by Wazuh."""

    return {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_intrusion",
        "source": {
            "ip": source_ip,
            "port": source_port,
        },
        "destination": {
            "ip": destination_ip,
            "port": destination_port,
        },
        "network": {
            "protocol": protocol,
        },
        "detection": {
            "prediction": prediction,
            "attack_type": attack_type,
            "attack_name": attack_name,
            "ml_confidence": ml_confidence,
            "threshold": threshold,
        },
        "risk": {
            "score": risk_score,
            "severity": severity,
        },
        "mitre": {
            "tactic": mitre_tactic,
            "technique": mitre_technique,
        },
        "threat_intelligence": threat_intel,
        "explanation": explanation,
        "detector": {
            "name": "Hybrid-Threat-Detection-IDS",
            "version": detector_version,
        },
    }