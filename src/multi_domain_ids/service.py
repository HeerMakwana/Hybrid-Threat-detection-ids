from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pandas as pd

from .alert_pipeline import AlertProcessor
from .domains import NetworkSecurityPipeline
from .sqli_model import SqliModel


class MultiDomainDetectionService:
    """Run real model inference and send normalized detections to the alert pipeline."""

    def __init__(
        self,
        alert_processor: AlertProcessor,
        *,
        network: NetworkSecurityPipeline | None = None,
        sqli: SqliModel | None = None,
    ):
        self.alert_processor = alert_processor
        self.network = network or NetworkSecurityPipeline()
        self.sqli = sqli

    def detect_network(
        self,
        event: Mapping[str, Any],
        features: Mapping[str, Any] | pd.DataFrame,
        *,
        evidence: Sequence[Mapping[str, Any] | str] = (),
    ) -> list[dict[str, Any]]:
        probability = float(self.network.predict_proba(features)[0, 1])
        suspicious = probability >= self.network.threshold
        alert_event = {**event, "attack_probability": probability}
        return self.alert_processor.process(
            alert_event,
            detection_domain="network",
            detection_source="legacy_network_model",
            event_category="network_flow",
            attack_name=str(event.get("attack_name") or "suspicious_network_activity"),
            model_name="hybrid_voting_5ensemble_v3",
            suspicious=suspicious,
            confidence_score=max(probability, 1.0 - probability),
            evidence=evidence,
        )

    def detect_sqli_features(
        self,
        event: Mapping[str, Any],
        features: Mapping[str, Any] | pd.DataFrame,
        *,
        evidence: Sequence[Mapping[str, Any] | str] = (),
    ) -> list[dict[str, Any]]:
        if self.sqli is None:
            raise RuntimeError("An actual-data SQLi model must be supplied before SQLi inference")
        frame = features if isinstance(features, pd.DataFrame) else pd.DataFrame([features])
        probability = float(self.sqli.predict_proba(frame)[0, 1])
        suspicious = self.sqli.predict(frame)[0] == 1
        alert_event = {**event, "attack_probability": probability}
        return self.alert_processor.process(
            alert_event,
            detection_domain="database",
            detection_source="actual_sqli_model",
            event_category="database_query",
            attack_name=str(event.get("attack_name") or "sql_injection"),
            model_name="sqli_random_forest",
            suspicious=bool(suspicious),
            confidence_score=max(probability, 1.0 - probability),
            evidence=evidence,
        )
