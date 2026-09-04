import json

import pytest

from siem import (
    WazuhForwarder,
    WazuhForwardingError,
)


def sample_alert():
    return {
        "alert_id": "test-alert-001",
        "timestamp": "2026-09-04T12:00:00Z",
        "record_index": 1,
        "predicted_label": "ANOMALY",
        "confidence": 0.98,
        "threshold": 0.21,
        "model_type": "hybrid_voting_5ensemble_v3",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "source_port": 4444,
        "destination_port": 80,
        "protocol": "TCP",
        "ioc_matches": [
            {
                "ioc_type": "ip",
                "value": "192.168.1.100",
                "matched": True,
            }
        ],
        "threat_confidence": {
            "score": 0.91,
            "severity": "CRITICAL",
            "factors": [
                "High ML confidence",
                "IOC match detected",
            ],
        },
    }


def test_build_payload():
    payload = WazuhForwarder.build_payload(
        sample_alert()
    )

    assert payload["integration"] == "hybrid-ids"
    assert payload["event_type"] == "intrusion_detection"
    assert payload["alert_id"] == "test-alert-001"
    assert payload["source_ip"] == "192.168.1.100"
    assert payload["destination_ip"] == "192.168.1.10"
    assert payload["threat_score"] == 0.91
    assert payload["threat_severity"] == "CRITICAL"
    assert payload["ioc_match_count"] == 1


def test_critical_alert_format():
    forwarder = WazuhForwarder(
        "127.0.0.1"
    )

    message = forwarder._format_message(
        sample_alert()
    ).decode("utf-8")

    assert message.startswith(
        "<130>hybrid-ids: "
    )

    json_data = message.split(
        "hybrid-ids: ",
        1
    )[1].strip()

    payload = json.loads(json_data)

    assert payload["threat_severity"] == "CRITICAL"


def test_missing_alert_id():
    forwarder = WazuhForwarder(
        "127.0.0.1"
    )

    alert = sample_alert()
    del alert["alert_id"]

    with pytest.raises(WazuhForwardingError):
        forwarder.send_alert(alert)


def test_invalid_protocol():
    with pytest.raises(ValueError):
        WazuhForwarder(
            "127.0.0.1",
            protocol="http",
        )