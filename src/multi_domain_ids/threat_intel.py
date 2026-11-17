from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IOCRecord:
    ip: str | None = None
    domain: str | None = None
    source: str = "local"
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)


class ThreatIntelScorer:
    """Small deterministic intelligence scorer for alert normalization."""

    def __init__(self, provider_weights: dict[str, float] | None = None):
        self.provider_weights = provider_weights or {
            "abuseipdb": 0.35,
            "virustotal": 0.30,
            "otx": 0.20,
            "opencti": 0.15,
        }

    def score_ioc(self, record: dict[str, Any]) -> IOCRecord:
        ip = record.get("source_ip") or record.get("destination_ip")
        domain = record.get("domain")
        score = 0.0
        reasons: list[str] = []

        if ip:
            score += 0.25
            reasons.append(f"network indicator: {ip}")
        if domain:
            score += 0.15
            reasons.append(f"domain indicator: {domain}")

        if record.get("protocol") in {"TCP", "UDP"}:
            score += 0.1
            reasons.append("transport protocol present")
        if record.get("suspicious"):
            score += 0.25
            reasons.append("suspicious marker present")
        if record.get("severity") in {"high", "critical"}:
            score += 0.2
            reasons.append("severity escalation")

        score = min(score, 1.0)
        return IOCRecord(ip=ip, domain=domain, source="deterministic", score=score, reasons=reasons)

    def assess_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        ioc = self.score_ioc(alert)
        confidence = min(1.0, round(ioc.score + 0.2 * alert.get("overall_score", 0.0), 3))
        severity = "low"
        if confidence >= 0.85:
            severity = "critical"
        elif confidence >= 0.7:
            severity = "high"
        elif confidence >= 0.45:
            severity = "medium"
        return {
            "ioc": {
                "ip": ioc.ip,
                "domain": ioc.domain,
                "source": ioc.source,
            },
            "threat_confidence": confidence,
            "severity": severity,
            "reasons": ioc.reasons,
        }
