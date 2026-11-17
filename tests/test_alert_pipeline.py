from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

import numpy as np
import pytest

from multi_domain_ids.alert_pipeline import AlertProcessor, JsonlAlertSink
from multi_domain_ids.alerts import normalize_alert
from multi_domain_ids.mitre import map_mitre_attack
from multi_domain_ids.service import MultiDomainDetectionService
from tools.validate_wazuh_config import validate as validate_wazuh_config


def _normalize(**kwargs):
    defaults = {
        "event": {"timestamp": "2026-01-02T03:04:05Z", "source_ip": "192.0.2.10"},
        "detection_domain": "network",
        "detection_source": "unit-test",
        "event_category": "network_flow",
        "attack_name": "port_scan",
        "model_name": "test-model",
        "suspicious": True,
        "confidence_score": 0.99,
    }
    defaults.update(kwargs)
    return normalize_alert(**defaults)


def test_normalized_alert_has_contract_timestamp_provenance_and_explanation():
    alert = _normalize(evidence=["20 distinct destination ports observed"])

    assert alert["event_id"]
    assert alert["timestamp"] == "2026-01-02T03:04:05+00:00"
    assert alert["timestamp_source"] == "event"
    assert alert["detection_domain"] == "network"
    assert alert["model_prediction"] == "suspicious"
    assert alert["severity"] == "medium"
    assert alert["mitre_attack"] == []
    assert alert["explanation"]["automated_response"].startswith("No containment")
    assert "confidence_score" in alert
    assert "domain" not in alert


def test_confidence_alone_does_not_inflate_evidence_based_severity():
    alert = _normalize(evidence=[])

    assert alert["confidence_score"] == 0.99
    assert alert["severity"] == "low"


def test_severity_can_use_independent_evidence_and_ioc_match():
    alert = _normalize(
        evidence=[{"signal": "signature", "description": "A scan signature matched"}],
        threat_intelligence={
            "ioc_matches": [
                {"ioc_type": "ip", "value": "192.0.2.10", "source": "otx", "confidence": 0.8}
            ]
        },
    )

    assert alert["severity"] == "high"
    assert "corroboration" in alert["severity_reason"]


def test_optional_fields_are_omitted_and_bad_ports_or_scores_are_rejected():
    alert = _normalize(event={"timestamp": "2026-01-02T03:04:05Z"})
    assert "source_ip" not in alert

    with pytest.raises(ValueError, match="destination_port"):
        _normalize(event={"destination_port": 53.5})
    with pytest.raises(ValueError, match="confidence_score"):
        _normalize(confidence_score=float("nan"))


def test_mitre_mapping_requires_supporting_event_evidence():
    assert map_mitre_attack("port_scan", {}) == []
    assert map_mitre_attack("port_scan", {"distinct_destination_ports": 12})[0]["technique_id"] == "T1046"
    assert map_mitre_attack("sql_injection", {}) == []
    assert map_mitre_attack("sql_injection", {"application_exposed": True})[0]["technique_id"] == "T1190"


def test_processor_writes_jsonl_and_emits_linked_incident(tmp_path):
    output = tmp_path / "alerts.jsonl"
    processor = AlertProcessor(JsonlAlertSink(output))
    first = processor.process(
        {
            "event_id": "network-1",
            "timestamp": "2026-01-02T03:04:05Z",
            "affected_asset": "server-1",
        },
        detection_domain="network",
        detection_source="model",
        event_category="network_flow",
        attack_name="port_scan",
        model_name="network-model",
        suspicious=True,
        confidence_score=0.95,
        evidence=["distinct destinations observed"],
    )
    second = processor.process(
        {
            "event_id": "identity-1",
            "timestamp": "2026-01-02T03:05:05Z",
            "affected_asset": "server-1",
        },
        detection_domain="identity",
        detection_source="rule",
        event_category="authentication",
        attack_name="brute_force_login",
        model_name="identity-rule",
        suspicious=True,
        confidence_score=0.9,
        evidence=["repeated failures observed"],
    )

    assert len(first) == 1
    assert len(second) == 2
    incident = second[1]
    assert set(incident["related_event_ids"]) == {"network-1", "identity-1"}
    assert incident["detection_domain"] == "correlation"
    assert incident["explanation"]["alert_title"]
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 3
    assert all(isinstance(record, dict) for record in records)


def test_detection_service_uses_legacy_model_threshold(tmp_path):
    class Network:
        threshold = 0.21

        def predict_proba(self, features):
            return np.asarray([[0.7, 0.3]])

    processor = AlertProcessor(JsonlAlertSink(tmp_path / "alerts.jsonl"))
    service = MultiDomainDetectionService(processor, network=Network())

    alert = service.detect_network(
        {"source_ip": "192.0.2.10"},
        {"Flow Duration": 12.0},
    )[0]

    assert alert["model_prediction"] == "suspicious"
    assert alert["attack_probability"] == 0.3
    assert alert["confidence_score"] == 0.7


def test_processor_matches_provider_ioc_in_normalized_event(tmp_path):
    class ProviderService:
        enabled = True

        def lookup(self, ip):
            return {
                "otx": {
                    "provider": "otx",
                    "ip": ip,
                    "available": True,
                    "pulse_count": 1,
                    "relevant_indicators": [ip],
                }
            }

    processor = AlertProcessor(
        JsonlAlertSink(tmp_path / "alerts.jsonl"),
        threat_intelligence=ProviderService(),
    )
    alert = processor.process(
        {"source_ip": "8.8.8.8"},
        detection_domain="network",
        detection_source="model",
        event_category="network_flow",
        attack_name="suspicious_network_activity",
        model_name="network-model",
        suspicious=True,
        confidence_score=0.9,
        evidence=["network rule matched"],
    )[0]

    assert alert["threat_intelligence"]["ioc_matches"][0]["source"] == "otx"
    assert alert["severity"] == "high"
    assert alert["threat_intelligence"]["assessment"]["score"] >= 0.0


def test_processor_never_submits_non_global_addresses_to_providers(tmp_path):
    class ProviderService:
        enabled = True

        def __init__(self):
            self.lookups = []

        def lookup(self, ip):
            self.lookups.append(ip)
            return {}

    service = ProviderService()
    processor = AlertProcessor(
        JsonlAlertSink(tmp_path / "alerts.jsonl"),
        threat_intelligence=service,
    )
    alert = processor.process(
        {"source_ip": "10.1.2.3", "destination_ip": "192.168.1.20"},
        detection_domain="network",
        detection_source="test",
        event_category="network_flow",
        attack_name="test",
        model_name="test",
        suspicious=False,
        confidence_score=0.1,
    )

    assert service.lookups == []
    assert alert[0]["threat_intelligence"]["provider_results"][
        "source_ip:lookup_policy"
    ]["error"] == "non_global_ip_skipped"


def test_wazuh_example_xml_files_are_well_formed():
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "wazuh/agent/multi_domain_ids.conf",
        "wazuh/decoders/multi_domain_ids_decoder.xml",
        "wazuh/rules/multi_domain_ids_rules.xml",
    ):
        ET.parse(root / relative)
    validate_wazuh_config()
