import json
import os

import numpy as np
import pandas as pd

from threat_intelligence.assessment import (
    IOCMatcher,
    aggregate_reputation,
    assess_threat,
    classify_severity,
    normalize_ioc,
)
from simulation import run_simulation


def result(provider, ip="192.0.2.1", **values):
    return {"provider": provider, "ip": ip, "available": True, **values}


def test_reputation_aggregation_one_multiple_consensus_and_disagreement():
    one = aggregate_reputation({"abuseipdb": result("abuseipdb", abuse_confidence_score=90)})
    assert one["providers_checked"] == 1 and one["providers_reporting_malicious"] == 1
    many = aggregate_reputation({
        "abuseipdb": result("abuseipdb", abuse_confidence_score=90),
        "virustotal": result("virustotal", malicious_count=2),
        "otx": result("otx", pulse_count=0),
    })
    assert many["consensus"] == "malicious" and many["providers_available"] == 3
    disagreement = aggregate_reputation({
        "abuseipdb": result("abuseipdb", abuse_confidence_score=0),
        "virustotal": result("virustotal", malicious_count=1),
    })
    assert disagreement["providers_reporting_malicious"] == 1


def test_all_unavailable_is_not_malicious():
    results = {"abuseipdb": {"provider": "abuseipdb", "available": False, "error": "timeout"},
               "virustotal": {"provider": "virustotal", "available": False, "error": "http_500"}}
    aggregate = aggregate_reputation(results)
    assert aggregate["providers_available"] == 0
    assert aggregate["providers_reporting_malicious"] == 0
    assert aggregate["overall_reputation"] == 0.0


def test_ioc_normalization_and_exact_matching():
    assert normalize_ioc("2001:0DB8::1", "ip") == "2001:db8::1"
    assert normalize_ioc("Example.COM.", "domain") == "example.com"
    assert normalize_ioc("HTTPS://Example.COM/path?x=1", "url") == "https://example.com/path?x=1"
    assert normalize_ioc("A" * 64, "hash") == ("a" * 64)
    assert normalize_ioc("not an ip", "ip") is None
    alert = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.2", "domain": "Example.COM.",
             "url": "https://example.com/path", "sha256": "A" * 64}
    providers = {
        "abuse": result("abuseipdb", abuse_confidence_score=90),
        "otx": result("otx", ip="198.51.100.2", pulse_count=2,
                       relevant_indicators=["example.com", {"value": "A" * 64, "type": "hash"}]),
    }
    matches = IOCMatcher().match(alert, providers)
    assert {(match["ioc_type"], match["value"]) for match in matches} == {
        ("ip", "192.0.2.1"), ("ip", "198.51.100.2"), ("domain", "example.com"), ("hash", "a" * 64)
    }


def test_url_and_configured_multiple_ioc_matches():
    alert = {"source_ip": "192.0.2.1", "url": "https://example.com/path"}
    matches = IOCMatcher().match(alert, {}, [{"ioc_type": "url", "value": "HTTPS://EXAMPLE.COM/path", "source": "configured", "confidence": 0.9}])
    assert matches[0]["confidence"] == 0.9
    assert IOCMatcher().match({"source_ip": "192.0.2.1"}, {}, [{"value": "192.0.2.1"}, {"value": "192.0.2.1", "source": "feed"}])


def test_threat_confidence_is_bounded_deterministic_and_explained():
    alert = {"confidence": 0.97, "source_ip": "192.0.2.1"}
    providers = {"abuseipdb": result("abuseipdb", abuse_confidence_score=94),
                 "virustotal": result("virustotal", malicious_count=5, suspicious_count=1)}
    matches = IOCMatcher().match(alert, providers)
    first = assess_threat(alert, providers, matches)
    second = assess_threat(alert, providers, matches)
    assert first == second
    assert 0.0 <= first["score"] <= 1.0
    assert first["severity"] == "CRITICAL"
    assert any("ML confidence" in factor for factor in first["factors"])
    assert any("AbuseIPDB" in factor for factor in first["factors"])
    assert any("VirusTotal" in factor for factor in first["factors"])


def test_score_boundaries_and_severity():
    assert classify_severity(0.0) == "LOW"
    assert classify_severity(0.24) == "LOW"
    assert classify_severity(0.25) == "MEDIUM"
    assert classify_severity(0.49) == "MEDIUM"
    assert classify_severity(0.50) == "HIGH"
    assert classify_severity(0.74) == "HIGH"
    assert classify_severity(0.75) == "CRITICAL"
    assert classify_severity(2.0) == "CRITICAL"
    assert classify_severity(-1.0) == "LOW"
    low = assess_threat({"confidence": 0}, {}, [])
    assert low["score"] == 0.0 and low["severity"] == "LOW"


def test_json_serialization_and_failure_handling():
    alert = {"confidence": 0.8, "source_ip": "192.0.2.1", "threat_intelligence": {
        "source_ip": {"abuseipdb": {"available": False, "error": "timeout"}}},
        "ioc_matches": []}
    alert["threat_confidence"] = assess_threat(alert, {"abuseipdb": {"provider": "abuseipdb", "available": False}}, [])
    serialized = json.dumps(alert)
    assert '"severity": "LOW"' not in serialized
    assert "threat_confidence" in json.loads(serialized)


def test_complete_mocked_simulation_enriched_jsonl(tmp_path, monkeypatch):
    class FakeModel:
        def predict(self, values):
            return np.array([1])

        def predict_proba(self, values):
            return np.array([[0.03, 0.97]])

    class FakeScaler:
        def transform(self, values):
            return values

    class FakeService:
        def lookup(self, ip):
            return {
                "abuseipdb": result("abuseipdb", ip=ip, abuse_confidence_score=94),
                "virustotal": {"provider": "virustotal", "ip": ip, "available": False, "error": "timeout"},
                "otx": result("otx", ip=ip, pulse_count=2, relevant_indicators=[ip]),
                "opencti": {"provider": "opencti", "ip": ip, "available": False, "error": "disabled"},
            }

    artifact = {"model": FakeModel(), "scaler": FakeScaler(), "feature_columns": ["Flow Duration"],
                "threshold": 0.21, "model_type": "mock-model"}
    monkeypatch.setattr("simulation.load_model_artifact", lambda path: artifact)
    data_path = tmp_path / "input.csv"
    alert_path = tmp_path / "alerts.jsonl"
    pd.DataFrame([{"Flow Duration": 1, "Source IP": "192.0.2.1", "Destination IP": "198.51.100.2",
                   "Source Port": 12345, "Destination Port": 443, "Protocol": "TCP"}]).to_csv(data_path, index=False)
    run_simulation("unused.joblib", str(data_path), str(alert_path), threat_intel_service=FakeService())
    with open(alert_path, encoding="utf-8") as handle:
        alert = json.loads(handle.readline())
    assert alert["confidence"] == 0.97
    assert alert["source_ip"] == "192.0.2.1" and alert["destination_ip"] == "198.51.100.2"
    assert alert["threat_intelligence"]["source_ip"]["abuseipdb"]["available"] is True
    assert len(alert["ioc_matches"]) == 4
    assert {(match["source"], match["value"]) for match in alert["ioc_matches"]} == {
        ("abuseipdb", "192.0.2.1"), ("abuseipdb", "198.51.100.2"),
        ("otx", "192.0.2.1"), ("otx", "198.51.100.2"),
    }
    assert 0.0 <= alert["threat_confidence"]["score"] <= 1.0
    assert alert["threat_confidence"]["severity"] == "CRITICAL"
    assert alert["threat_confidence"]["factors"]
    assert "api_key" not in json.dumps(alert).lower()