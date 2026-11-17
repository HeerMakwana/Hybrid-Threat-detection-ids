from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd

CICIDS_FEATURES: list[str] = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
]

SQL_FEATURE_COLUMNS: list[str] = [
    "query_length",
    "num_keywords",
    "num_special_chars",
    "num_union_tokens",
    "num_select_tokens",
    "num_comment_tokens",
    "contains_or_1_equals_1",
    "contains_union_select",
    "contains_sql_comment",
    "contains_benchmark",
    "contains_sleep",
    "contains_drop",
    "contains_insert",
    "contains_update",
    "contains_delete",
]

HOST_FEATURE_COLUMNS: list[str] = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "network_connections",
    "parent_child_ratio",
    "process_entropy",
    "privilege_escalation",
    "suspicious_process_count",
]

IDENTITY_FEATURE_COLUMNS: list[str] = [
    "failed_logins",
    "successful_logins",
    "new_device_logins",
    "privilege_escalation",
    "user_anomaly_score",
    "time_window_lateral_movement",
]

DNS_FEATURE_COLUMNS: list[str] = [
    "query_length",
    "label_count",
    "numeric_ratio",
    "entropy_score",
    "avg_subdomain_depth",
    "is_malicious_tld",
    "is_high_entropy",
    "suspicious_dns_pattern",
]


def normalize_label(value: object) -> int:
    label = str(value).strip().lower()
    if label in {"0", "benign", "normal", "safe"}:
        return 0
    if label in {"1", "attack", "malicious", "anomaly", "intrusion", "sqli", "sql_injection"}:
        return 1
    if label in {"true", "yes"}:
        return 1
    if label in {"false", "no"}:
        return 0
    return int(bool(label))


def coerce_numeric_frame(frame: pd.DataFrame, desired_columns: Iterable[str]) -> pd.DataFrame:
    numeric = frame.copy()
    for column in desired_columns:
        if column in numeric.columns:
            numeric[column] = pd.to_numeric(numeric[column], errors="coerce").fillna(0.0)
        else:
            numeric[column] = 0.0
    return numeric


def make_safe_float_array(values: np.ndarray) -> np.ndarray:
    clean = np.asarray(values, dtype=np.float64)
    clean = np.nan_to_num(clean, nan=0.0, posinf=0.0, neginf=0.0)
    return np.clip(clean, -1.0e12, 1.0e12)
