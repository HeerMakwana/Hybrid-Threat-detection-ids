from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from .severity import assess_severity


_ENTITY_FIELDS = ("affected_asset", "device_id", "hostname", "username", "source_ip", "destination_ip")


class IncidentCorrelator:
    """Correlate suspicious events sharing an entity within a bounded time window."""

    def __init__(self, window_seconds: int = 900, max_events: int = 10_000):
        if window_seconds <= 0 or max_events <= 0:
            raise ValueError("window_seconds and max_events must be positive")
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque()
        self._clusters: dict[str, dict[str, dict[str, Any]]] = {}

    def ingest(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        if alert.get("model_prediction") != "suspicious":
            return None
        event_id = str(alert.get("event_id") or "")
        if not event_id:
            raise ValueError("Correlatable alerts must have an event_id")
        if event_id in self._seen:
            return None
        timestamp = _event_time(alert.get("timestamp"))
        keys = _entity_keys(alert)
        if not keys:
            self._remember(event_id)
            return None

        related: dict[str, dict[str, Any]] = {}
        for key in keys:
            retained = []
            for prior in self._by_entity[key]:
                if abs(timestamp - prior["_timestamp"]) <= self.window_seconds:
                    retained.append(prior)
                    if prior.get("event_id") != event_id:
                        related[str(prior["event_id"])] = prior
            self._by_entity[key] = retained

        current = dict(alert)
        current["_timestamp"] = timestamp
        current["correlation_entities"] = sorted(keys)
        for key in keys:
            self._by_entity[key].append(current)
        self._remember(event_id)
        self._bound_history()

        events = [*related.values(), current]
        domains = {str(item.get("detection_domain", "")).lower() for item in events}
        domains.discard("")
        if len(domains) < 2:
            return None

        prior_cluster_ids = sorted({
            str(item["correlation_id"])
            for item in events
            if item.get("correlation_id") in self._clusters
        })
        cluster_id = prior_cluster_ids[0] if prior_cluster_ids else _stable_cluster_id(events)
        cluster: dict[str, dict[str, Any]] = {}
        for prior_id in prior_cluster_ids:
            cluster.update(self._clusters.pop(prior_id, {}))
        cluster.update({str(item["event_id"]): item for item in events})
        for item in cluster.values():
            item["correlation_id"] = cluster_id
        domains = {
            str(item.get("detection_domain", "")).lower()
            for item in cluster.values()
        }
        domains.discard("")
        self._clusters[cluster_id] = cluster

        evidence = [
            item
            for event in cluster.values()
            for item in event.get("evidence", [])
            if isinstance(item, (dict, str))
        ]
        severity, reason = assess_severity(
            True,
            evidence,
            threat_matches=[
                match
                for event in cluster.values()
                for match in event.get("threat_intelligence", {}).get("ioc_matches", [])
            ],
            correlated_domains=domains,
        )
        timeline = [
            {
                "event_id": str(item["event_id"]),
                "timestamp": str(item["timestamp"]),
                "detection_domain": str(item["detection_domain"]),
                "attack_name": str(item["attack_name"]),
            }
            for item in sorted(cluster.values(), key=lambda item: item["_timestamp"])
        ]
        return {
            "incident_id": cluster_id,
            "correlation_id": cluster_id,
            "event_id": _incident_event_id(cluster_id),
            "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
            "detection_domain": "correlation",
            "detection_source": "incident_correlator",
            "event_category": "correlated_incident",
            "attack_name": "multi_stage_incident",
            "model_name": "rule_based_correlation",
            "model_prediction": "suspicious",
            "confidence_score": None,
            "severity": severity,
            "severity_reason": reason,
            "correlated_domains": sorted(domains),
            "related_event_ids": sorted(cluster),
            "timeline": timeline,
            "affected_assets": sorted({
                str(event[field])
                for event in cluster.values()
                for field in ("affected_asset", "device_id", "hostname")
                if event.get(field)
            }),
            "evidence": evidence,
            "recommended_action": [
                "Review the linked event timeline and affected assets.",
                "Preserve relevant logs and escalate according to the incident-response policy.",
            ],
        }

    def _remember(self, event_id: str) -> None:
        self._seen.add(event_id)
        self._seen_order.append(event_id)
        while len(self._seen_order) > self.max_events:
            self._seen.discard(self._seen_order.popleft())

    def _bound_history(self) -> None:
        all_events = {
            str(event["event_id"]): event
            for events in self._by_entity.values()
            for event in events
        }
        if len(all_events) <= self.max_events:
            return
        keep_ids = {
            event_id
            for event_id, _ in sorted(
                all_events.items(),
                key=lambda pair: pair[1]["_timestamp"],
                reverse=True,
            )[: self.max_events]
        }
        for key in list(self._by_entity):
            retained = [event for event in self._by_entity[key] if str(event["event_id"]) in keep_ids]
            if retained:
                self._by_entity[key] = retained
            else:
                del self._by_entity[key]
        for cluster_id in list(self._clusters):
            cluster = {
                event_id: event
                for event_id, event in self._clusters[cluster_id].items()
                if event_id in keep_ids
            }
            if len(cluster) < 2:
                del self._clusters[cluster_id]
            else:
                self._clusters[cluster_id] = cluster


def _entity_keys(event: dict[str, Any]) -> set[str]:
    return {
        f"{field}:{str(event[field]).strip().lower()}"
        for field in _ENTITY_FIELDS
        if event.get(field) is not None and str(event[field]).strip()
    }


def _event_time(value: object) -> float:
    if not isinstance(value, str):
        raise ValueError("Correlatable event timestamps must be normalized ISO strings")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid event timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _stable_cluster_id(events: list[dict[str, Any]]) -> str:
    identities = sorted(str(item["event_id"]) for item in events)
    digest = hashlib.sha256(json.dumps(identities, separators=(",", ":")).encode()).hexdigest()[:24]
    return f"inc-{digest}"


def _incident_event_id(cluster_id: str) -> str:
    digest = hashlib.sha256(cluster_id.encode()).hexdigest()[:24]
    return f"incident-{digest}"
