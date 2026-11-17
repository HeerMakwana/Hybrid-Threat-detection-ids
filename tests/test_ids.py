from __future__ import annotations

import numpy as np
import pandas as pd

from multi_domain_ids import MultiDomainIDS
from multi_domain_ids.ensemble import HybridEnsembleModel
from multi_domain_ids.model_loader import load_model_artifact


def test_original_network_model_loads_and_predicts():
    artifact = load_model_artifact("models/final_model.joblib")
    assert artifact["model_type"] == "hybrid_voting_5ensemble_v3"
    assert len(artifact["feature_columns"]) == 17
    assert artifact["threshold"] > 0.0

    model = MultiDomainIDS()
    model.network.load_pretrained_model()
    proba = model.network.predict_proba({
        "Flow Duration": 1.0,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Total Length of Fwd Packets": 100.0,
        "Total Length of Bwd Packets": 80.0,
        "Fwd Packet Length Max": 30.0,
        "Fwd Packet Length Min": 5.0,
        "Fwd Packet Length Mean": 12.0,
        "Fwd Packet Length Std": 4.0,
        "Bwd Packet Length Max": 25.0,
        "Bwd Packet Length Min": 6.0,
        "Bwd Packet Length Mean": 14.0,
        "Bwd Packet Length Std": 3.0,
        "Flow Bytes/s": 10000.0,
        "Flow Packets/s": 200.0,
        "Packet Length Mean": 15.0,
        "Packet Length Std": 2.0,
    })
    assert proba.shape == (1, 2)
    assert 0.0 <= proba[0, 0] <= 1.0
    assert 0.0 <= proba[0, 1] <= 1.0


def test_hybrid_ensemble_synthetic_network_data():
    rng = np.random.default_rng(42)
    X = pd.DataFrame({
        "Flow Duration": rng.normal(0.0, 1.0, 120),
        "Total Fwd Packets": rng.normal(0.0, 1.0, 120),
        "Total Backward Packets": rng.normal(0.0, 1.0, 120),
        "Total Length of Fwd Packets": rng.normal(0.0, 1.0, 120),
        "Total Length of Bwd Packets": rng.normal(0.0, 1.0, 120),
        "Fwd Packet Length Max": rng.normal(0.0, 1.0, 120),
        "Fwd Packet Length Min": rng.normal(0.0, 1.0, 120),
        "Fwd Packet Length Mean": rng.normal(0.0, 1.0, 120),
        "Fwd Packet Length Std": rng.normal(0.0, 1.0, 120),
        "Bwd Packet Length Max": rng.normal(0.0, 1.0, 120),
        "Bwd Packet Length Min": rng.normal(0.0, 1.0, 120),
        "Bwd Packet Length Mean": rng.normal(0.0, 1.0, 120),
        "Bwd Packet Length Std": rng.normal(0.0, 1.0, 120),
        "Flow Bytes/s": rng.normal(0.0, 1.0, 120),
        "Flow Packets/s": rng.normal(0.0, 1.0, 120),
        "Packet Length Mean": rng.normal(0.0, 1.0, 120),
        "Packet Length Std": rng.normal(0.0, 1.0, 120),
    })
    X.iloc[60:] += 3.0
    y = np.array([0] * 60 + [1] * 60)

    model = HybridEnsembleModel(calibrate=False)
    model.fit(X, y)
    proba = model.predict_proba(X)

    assert proba.shape == (120, 2)
    assert proba[:, 1].min() >= 0.0
    assert proba[:, 1].max() <= 1.0
    assert model.predict(X).sum() > 50


def test_sql_pipeline_detects_attacks():
    ids = MultiDomainIDS()
    ids.fit_demo()
    safe = ["SELECT * FROM users WHERE id = 42"]
    malicious = ["SELECT * FROM users WHERE username = 'admin' OR 1=1"]

    safe_prob = ids.database.predict_proba(safe)[0, 1]
    malicious_prob = ids.database.predict_proba(malicious)[0, 1]

    assert safe_prob < malicious_prob
    assert malicious_prob > 0.5


def test_multi_domain_ids_alert_summary():
    ids = MultiDomainIDS()
    ids.fit_demo()
    payload = {
        "network": {
            "Flow Duration": 120.0,
            "Total Fwd Packets": 40,
            "Total Backward Packets": 20,
            "Total Length of Fwd Packets": 5000.0,
            "Total Length of Bwd Packets": 3000.0,
            "Fwd Packet Length Max": 100.0,
            "Fwd Packet Length Min": 20.0,
            "Fwd Packet Length Mean": 80.0,
            "Fwd Packet Length Std": 15.0,
            "Bwd Packet Length Max": 90.0,
            "Bwd Packet Length Min": 25.0,
            "Bwd Packet Length Mean": 60.0,
            "Bwd Packet Length Std": 10.0,
            "Flow Bytes/s": 120000.0,
            "Flow Packets/s": 1000.0,
            "Packet Length Mean": 75.0,
            "Packet Length Std": 20.0,
        },
        "sql": "SELECT * FROM users WHERE username = 'admin' OR 1=1",
        "host": {
            "cpu_usage": 0.9,
            "memory_usage": 0.8,
            "disk_usage": 0.7,
            "network_connections": 200,
            "parent_child_ratio": 2.1,
            "process_entropy": 0.8,
            "privilege_escalation": 1,
            "suspicious_process_count": 8,
        },
        "identity": {
            "failed_logins": 10,
            "successful_logins": 1,
            "new_device_logins": 2,
            "privilege_escalation": 1,
            "user_anomaly_score": 0.9,
            "time_window_lateral_movement": 2,
        },
        "dns": {
            "query_length": 90,
            "label_count": 3,
            "numeric_ratio": 0.8,
            "entropy_score": 0.9,
            "avg_subdomain_depth": 4.0,
            "is_malicious_tld": 1,
            "is_high_entropy": 1,
            "suspicious_dns_pattern": 1,
        },
    }
    summary = ids.predict(payload)
    alert = ids.generate_alert(payload)

    assert "overall_score" in summary
    assert summary["overall_score"] >= 0.0
    assert "severity" in alert
    assert alert["triggered"] is True or alert["severity"] in {"low", "medium", "high", "critical"}
