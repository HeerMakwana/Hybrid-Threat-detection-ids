import json

import numpy as np
import pandas as pd

from detection.streaming_detector import StreamingDetector
from siem.wazuh_adapter import WazuhJsonlAdapter


def test_streaming_detector_emits_canonical_event(tmp_path, monkeypatch):
    class FakeModel:
        def predict_proba(self, values):
            return np.array([[0.03, 0.97]])

    class FakeScaler:
        def transform(self, values):
            return values

    artifact = {
        "model": FakeModel(),
        "scaler": FakeScaler(),
        "feature_columns": ["Flow Duration"],
        "threshold": 0.21,
        "model_type": "mock-model",
    }

    monkeypatch.setattr(
        "detection.streaming_detector.load_model_artifact",
        lambda path: artifact,
    )

    detector = StreamingDetector("unused.joblib")
    row = pd.Series(
        {
            "Flow Duration": 1,
            "Source IP": "192.168.10.45",
            "Destination IP": "192.168.10.10",
            "Source Port": 53122,
            "Destination Port": 80,
            "Protocol": "TCP",
            "Label": "PortScan",
        }
    )

    result = detector.process_record(row, sequence_number=1)

    assert result.prediction == "ATTACK"
    assert result.security_event["mitre"]["technique"] == "T1046"
    assert result.security_event["risk"]["score"] > 0
    assert result.security_event["workflow"]["status"] == "PENDING_REVIEW"
    assert result.security_event["workflow"]["priority"] in {"P1", "P2", "P3", "P4"}
    assert result.security_event["threat_intelligence"]["sources"]

    output_path = tmp_path / "live_security_events.jsonl"
    writer = WazuhJsonlAdapter(output_path=output_path)
    writer.append(result.security_event)

    with output_path.open(encoding="utf-8") as handle:
        saved = json.loads(handle.readline())

    assert saved["event_type"] == "network_intrusion"
    assert saved["source"]["ip"] == "192.168.10.45"
    assert saved["detector"]["name"] == "Hybrid-Threat-Detection-IDS"