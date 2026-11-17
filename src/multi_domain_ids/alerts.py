from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import math
import uuid
from typing import Any

from .explanations import explain_alert
from .mitre import map_mitre_attack
from .severity import assess_severity

_OPTIONAL_FIELDS = (
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "hostname",
    "device_id",
    "username",
    "affected_asset",
    "domain",
    "url",
    "hash",
    "file_hash",
    "md5",
    "sha1",
    "sha256",
    "attack_probability",
)


def normalize_alert(
    event: Mapping[str, Any],
    *,
    detection_domain: str,
    detection_source: str,
    event_category: str,
    attack_name: str,
    model_name: str,
    suspicious: bool,
    confidence_score: float | None,
    evidence: Sequence[Mapping[str, Any] | str] = (),
    threat_intelligence: Mapping[str, Any] | None = None,
    correlated_domains: Sequence[str] = (),
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Normalize one event into a stable, JSON-serializable alert record."""
    for field_name, value in (
        ("detection_domain", detection_domain),
        ("detection_source", detection_source),
        ("event_category", event_category),
        ("attack_name", attack_name),
        ("model_name", model_name),
    ):
        if not value or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")

    confidence = _confidence(confidence_score)
    evidence_items = [_normalize_evidence(item) for item in evidence]
    intel = dict(threat_intelligence or {})
    matches = intel.get("ioc_matches", [])
    if not isinstance(matches, list):
        raise ValueError("threat_intelligence.ioc_matches must be a list")
    severity, reason = assess_severity(
        suspicious,
        evidence_items,
        threat_matches=matches,
        correlated_domains=correlated_domains,
    )

    timestamp, timestamp_source = _timestamp(event.get("timestamp"))
    normalized: dict[str, Any] = {
        "event_id": str(event.get("event_id") or uuid.uuid4()),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "detection_domain": detection_domain.strip().lower(),
        "detection_source": detection_source.strip(),
        "event_category": event_category.strip(),
        "attack_name": attack_name.strip().lower(),
        "model_name": model_name.strip(),
        "model_prediction": "suspicious" if suspicious else "benign",
        "confidence_score": confidence,
        "severity": severity,
        "severity_reason": reason,
        "evidence": evidence_items,
        "threat_intelligence": intel,
        "correlation_id": correlation_id,
        "recommended_action": [],
    }
    for field_name in _OPTIONAL_FIELDS:
        value = event.get(field_name)
        if value is not None and value != "":
            if field_name.endswith("_port"):
                port = _valid_port(value, field_name)
                normalized[field_name] = port
            elif field_name == "attack_probability":
                normalized[field_name] = _confidence(value)
            else:
                normalized[field_name] = str(value)
    if event.get("source_event_reference") is not None:
        normalized["source_event_reference"] = str(event["source_event_reference"])

    normalized["mitre_attack"] = map_mitre_attack(attack_name, event)
    normalized["explanation"] = explain_alert(normalized)
    normalized["recommended_action"] = [
        normalized["explanation"]["immediate_action"],
        normalized["explanation"]["containment_recommendation"],
    ]
    return normalized


def _normalize_evidence(item: Mapping[str, Any] | str) -> dict[str, str]:
    if isinstance(item, str):
        description = item.strip()
        signal = description
    elif isinstance(item, Mapping):
        description = str(item.get("description") or item.get("signal") or "").strip()
        signal = str(item.get("signal") or description).strip()
    else:
        raise TypeError("Evidence entries must be strings or mappings")
    if not description:
        raise ValueError("Evidence descriptions must not be empty")
    return {"signal": signal, "description": description}


def _confidence(value: float | None) -> float | None:
    if value is None:
        return None
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise ValueError("confidence_score must be a finite value between 0 and 1")
    return score


def _timestamp(value: object) -> tuple[str, str]:
    if value is None or value == "":
        return datetime.now(timezone.utc).isoformat(), "ingestion_time"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(float(value), timezone.utc)
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid event timestamp: {value!r}") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        raise ValueError("timestamp must be an ISO string, epoch number, or omitted")
    return parsed.astimezone(timezone.utc).isoformat(), "event"


def _valid_port(value: object, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer from 0 to 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer from 0 to 65535") from exc
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field_name} must be an integer from 0 to 65535")
    if not 0 <= port <= 65535:
        raise ValueError(f"{field_name} must be an integer from 0 to 65535")
    return port
