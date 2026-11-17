from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import ipaddress
import json
import threading
from typing import Any

from .alerts import normalize_alert
from .correlation import IncidentCorrelator
from .explanations import explain_alert
from .threat_intelligence import (
    IOCMatcher,
    ThreatIntelligenceService,
    aggregate_reputation,
    assess_threat,
)


class JsonlAlertSink:
    """Append one complete JSON object per line for Wazuh agent collection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, alert: Mapping[str, Any]) -> None:
        line = json.dumps(alert, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line + "\n")
            stream.flush()


class AlertProcessor:
    """Normalize, enrich, explain, correlate, and persist detections."""

    def __init__(
        self,
        sink: JsonlAlertSink,
        *,
        threat_intelligence: ThreatIntelligenceService | None = None,
        correlator: IncidentCorrelator | None = None,
    ):
        self.sink = sink
        self.threat_intelligence = threat_intelligence
        self.correlator = correlator or IncidentCorrelator()

    def process(
        self,
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
        known_iocs: Sequence[Mapping[str, Any] | str] = (),
    ) -> list[dict[str, Any]]:
        provider_results = self._lookup_indicators(event)
        alert_iocs = self._indicator_event(event)
        matches = IOCMatcher().match(alert_iocs, provider_results, known_iocs)
        intel = {
            "status": "enabled" if self.threat_intelligence and self.threat_intelligence.enabled else "disabled_or_unconfigured",
            "provider_results": provider_results,
            "reputation": aggregate_reputation(provider_results),
            "ioc_matches": matches,
            "assessment": assess_threat(
                {
                    "confidence": event.get("attack_probability", confidence_score or 0.0),
                    **alert_iocs,
                },
                provider_results,
                matches,
            ),
            "severity_note": "Threat-intelligence assessment is supplemental; alert severity is evidence-based and independent of model confidence.",
        }
        alert = normalize_alert(
            event,
            detection_domain=detection_domain,
            detection_source=detection_source,
            event_category=event_category,
            attack_name=attack_name,
            model_name=model_name,
            suspicious=suspicious,
            confidence_score=confidence_score,
            evidence=evidence,
            threat_intelligence=intel,
        )
        records = [alert]
        incident = self.correlator.ingest(alert)
        if incident is not None:
            incident["explanation"] = explain_alert(incident)
            records.append(incident)
        for record in records:
            self.sink.write(record)
        return records

    def _lookup_indicators(self, event: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        service = self.threat_intelligence
        if service is None or not service.enabled:
            return {}
        results: dict[str, dict[str, Any]] = {}
        for field in ("source_ip", "destination_ip"):
            indicator = event.get(field)
            if not indicator:
                continue
            try:
                address = ipaddress.ip_address(str(indicator))
            except ValueError:
                results[f"{field}:lookup_policy"] = {
                    "provider": "lookup_policy",
                    "ip": str(indicator),
                    "available": False,
                    "error": "invalid_ip_skipped",
                }
                continue
            if not address.is_global:
                results[f"{field}:lookup_policy"] = {
                    "provider": "lookup_policy",
                    "ip": str(address),
                    "available": False,
                    "error": "non_global_ip_skipped",
                }
                continue
            provider_results = service.lookup(str(address))
            for provider_name, result in provider_results.items():
                results[f"{field}:{provider_name}"] = result
        return results

    @staticmethod
    def _indicator_event(event: Mapping[str, Any]) -> dict[str, Any]:
        fields = (
            "source_ip",
            "destination_ip",
            "domain",
            "url",
            "hash",
            "file_hash",
            "md5",
            "sha1",
            "sha256",
        )
        return {field: event[field] for field in fields if event.get(field) is not None}
