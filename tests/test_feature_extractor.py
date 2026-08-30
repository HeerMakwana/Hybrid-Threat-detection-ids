import pandas as pd

from feature_extractor import CICIDS_FEATURES, flow_features_from_packet_dict
from simulation import align_cicids_columns


def test_flow_record_preserves_features_and_network_metadata_separately():
    packet = {
        "src": "203.0.113.10",
        "dst": "198.51.100.20",
        "sport": 49152,
        "dport": 443,
        "proto": "TCP",
        "length": 128,
        "ts": 10.0,
    }

    flow = flow_features_from_packet_dict(packet)

    assert set(CICIDS_FEATURES).issubset(flow)
    assert flow["Flow Duration"] == 1e-6
    assert flow["Total Fwd Packets"] == 1
    assert flow["Total Length of Fwd Packets"] == 128.0
    assert {field: flow[field] for field in (
        "source_ip", "destination_ip", "source_port", "destination_port", "protocol"
    )} == {
        "source_ip": "203.0.113.10",
        "destination_ip": "198.51.100.20",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "TCP",
    }


def test_metadata_is_excluded_from_model_feature_vector():
    flow = flow_features_from_packet_dict({
        "src": "203.0.113.10", "dst": "198.51.100.20", "sport": 49152,
        "dport": 443, "proto": "TCP", "length": 128, "ts": 10.0,
    })

    aligned = align_cicids_columns(pd.DataFrame([flow]), CICIDS_FEATURES)

    assert list(aligned.columns) == CICIDS_FEATURES
    assert "source_ip" not in aligned.columns
    assert "destination_ip" not in aligned.columns
    assert "source_port" not in aligned.columns
    assert "destination_port" not in aligned.columns
    assert "protocol" not in aligned.columns