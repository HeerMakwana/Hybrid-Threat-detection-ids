from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .ensemble import HybridEnsembleModel
from .feature_extractor import CICIDS_FEATURES
from .feature_schema import (
    DNS_FEATURE_COLUMNS,
    HOST_FEATURE_COLUMNS,
    IDENTITY_FEATURE_COLUMNS,
    SQL_FEATURE_COLUMNS,
    coerce_numeric_frame,
)
from .model_loader import load_model_artifact


class BaseDomainPipeline:
    def fit(self, X: Any, y: Any) -> "BaseDomainPipeline":
        raise NotImplementedError

    def predict_proba(self, X: Any) -> np.ndarray:
        raise NotImplementedError

    def predict(self, X: Any) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


@dataclass
class NetworkSecurityPipeline(BaseDomainPipeline):
    model: Any = None
    model_path: str = "models/final_model.joblib"
    label_column: str = "label"
    feature_columns: list[str] | None = None
    threshold: float = 0.5
    scaler: Any = None

    def _default_model_path(self) -> str:
        candidates = [
            Path(__file__).resolve().parents[2] / "models" / "final_model.joblib",
            Path.cwd() / "models" / "final_model.joblib",
            os.path.join(os.getcwd(), "models", "final_model.joblib"),
            os.path.join(os.getcwd(), "..", "Hybrid-Threat-detection-ids-main", "models", "final_model.joblib"),
        ]
        for candidate in candidates:
            path = str(candidate)
            if os.path.exists(path):
                return path
        return self.model_path

    def load_pretrained_model(self) -> "NetworkSecurityPipeline":
        resolved = self._default_model_path()
        artifact = load_model_artifact(resolved)
        self.model = artifact["model"]
        self.scaler = artifact.get("scaler")
        self.feature_columns = artifact.get("feature_columns", CICIDS_FEATURES)
        self.threshold = float(artifact.get("threshold", 0.5))
        return self

    def fit(self, X: Any, y: Any) -> "NetworkSecurityPipeline":
        if self.model is None:
            self.load_pretrained_model()
        return self

    def _prepare_frame(self, X: Any) -> pd.DataFrame:
        if isinstance(X, dict):
            frame = pd.DataFrame([X])
        elif isinstance(X, pd.DataFrame):
            frame = X.copy()
        else:
            frame = pd.DataFrame(X)
        if self.feature_columns is None:
            feature_columns = CICIDS_FEATURES
        else:
            feature_columns = self.feature_columns
        numeric = frame.reindex(columns=feature_columns, fill_value=0.0)
        return numeric.fillna(0.0)

    def predict_proba(self, X: Any) -> np.ndarray:
        if self.model is None:
            self.load_pretrained_model()
        frame = self._prepare_frame(X)
        if self.scaler is not None:
            X_scaled = self.scaler.transform(frame.to_numpy(dtype=float))
            return self.model.predict_proba(X_scaled)
        return self.model.predict_proba(frame.to_numpy(dtype=float))


@dataclass
class DatabaseSecurityPipeline(BaseDomainPipeline):
    vectorizer: TfidfVectorizer = field(default_factory=lambda: TfidfVectorizer(ngram_range=(1, 2), min_df=1))
    classifier: LogisticRegression = field(default_factory=lambda: LogisticRegression(max_iter=2000, class_weight="balanced"))

    def _build_features(self, samples: list[str]) -> list[dict[str, float]]:
        features = []
        for sample in samples:
            query = str(sample or "")
            lowered = query.lower()
            features.append({
                "query_length": len(query),
                "num_keywords": sum(token in lowered for token in ["select", "insert", "delete", "update", "union", "drop", "or", "and", "where", "sleep", "benchmark"]),
                "num_special_chars": sum(ch in query for ch in ["=", "'", "--", "/*", "*/", ";", "(", ")", "%", "|", "&"]),
                "num_union_tokens": query.lower().count("union"),
                "num_select_tokens": query.lower().count("select"),
                "num_comment_tokens": query.lower().count("--") + query.lower().count("/*"),
                "contains_or_1_equals_1": int("or 1=1" in lowered or "or 1 = 1" in lowered),
                "contains_union_select": int("union select" in lowered),
                "contains_sql_comment": int("--" in query or "/*" in query),
                "contains_benchmark": int("benchmark(" in lowered or "sleep(" in lowered),
                "contains_sleep": int("sleep(" in lowered),
                "contains_drop": int("drop" in lowered),
                "contains_insert": int("insert" in lowered),
                "contains_update": int("update" in lowered),
                "contains_delete": int("delete" in lowered),
            })
        return features

    def fit(self, X: Any, y: Any) -> "DatabaseSecurityPipeline":
        samples = []
        for value in X:
            if isinstance(value, dict):
                samples.append(str(value.get("query", value.get("sql", ""))))
            else:
                samples.append(str(value))
        labels = np.asarray(y, dtype=int)
        feature_frame = pd.DataFrame(self._build_features(samples))
        feature_frame = feature_frame.reindex(columns=SQL_FEATURE_COLUMNS, fill_value=0.0)
        self.classifier.fit(feature_frame, labels)
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        samples = []
        for value in X:
            if isinstance(value, dict):
                samples.append(str(value.get("query", value.get("sql", ""))))
            else:
                samples.append(str(value))
        feature_frame = pd.DataFrame(self._build_features(samples))
        feature_frame = feature_frame.reindex(columns=SQL_FEATURE_COLUMNS, fill_value=0.0)
        proba = self.classifier.predict_proba(feature_frame)
        return proba


@dataclass
class HostEndpointPipeline(BaseDomainPipeline):
    model: RandomForestClassifier = field(default_factory=lambda: RandomForestClassifier(n_estimators=120, random_state=42, n_jobs=-1, class_weight="balanced"))

    def fit(self, X: Any, y: Any) -> "HostEndpointPipeline":
        frame = pd.DataFrame(X)
        frame = coerce_numeric_frame(frame, HOST_FEATURE_COLUMNS)
        self.model.fit(frame[HOST_FEATURE_COLUMNS], np.asarray(y, dtype=int))
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        frame = pd.DataFrame(X)
        frame = coerce_numeric_frame(frame, HOST_FEATURE_COLUMNS)
        return self.model.predict_proba(frame[HOST_FEATURE_COLUMNS])


@dataclass
class IdentitySecurityPipeline(BaseDomainPipeline):
    model: RandomForestClassifier = field(default_factory=lambda: RandomForestClassifier(n_estimators=140, random_state=42, n_jobs=-1, class_weight="balanced"))

    def fit(self, X: Any, y: Any) -> "IdentitySecurityPipeline":
        frame = pd.DataFrame(X)
        frame = coerce_numeric_frame(frame, IDENTITY_FEATURE_COLUMNS)
        self.model.fit(frame[IDENTITY_FEATURE_COLUMNS], np.asarray(y, dtype=int))
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        frame = pd.DataFrame(X)
        frame = coerce_numeric_frame(frame, IDENTITY_FEATURE_COLUMNS)
        return self.model.predict_proba(frame[IDENTITY_FEATURE_COLUMNS])


@dataclass
class DnsSecurityPipeline(BaseDomainPipeline):
    model: LogisticRegression = field(default_factory=lambda: LogisticRegression(max_iter=2000, class_weight="balanced"))

    def fit(self, X: Any, y: Any) -> "DnsSecurityPipeline":
        frame = pd.DataFrame(X)
        frame = coerce_numeric_frame(frame, DNS_FEATURE_COLUMNS)
        self.model.fit(frame[DNS_FEATURE_COLUMNS], np.asarray(y, dtype=int))
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        frame = pd.DataFrame(X)
        frame = coerce_numeric_frame(frame, DNS_FEATURE_COLUMNS)
        return self.model.predict_proba(frame[DNS_FEATURE_COLUMNS])


@dataclass
class MultiDomainIDS:
    network: NetworkSecurityPipeline = field(default_factory=NetworkSecurityPipeline)
    database: DatabaseSecurityPipeline = field(default_factory=DatabaseSecurityPipeline)
    host: HostEndpointPipeline = field(default_factory=HostEndpointPipeline)
    identity: IdentitySecurityPipeline = field(default_factory=IdentitySecurityPipeline)
    dns: DnsSecurityPipeline = field(default_factory=DnsSecurityPipeline)

    def fit_demo(self) -> "MultiDomainIDS":
        self.network.load_pretrained_model()

        rng = np.random.default_rng(42)

        sql_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT * FROM users WHERE username = 'admin' OR 1=1",
            "SELECT * FROM users WHERE password = 'x' --",
            "SELECT * FROM customers WHERE region = 'us'",
        ] * 45
        sql_labels = np.array([0, 1, 1, 0] * 45, dtype=int)
        self.database.fit(sql_queries, sql_labels)

        host_x = pd.DataFrame({
            "cpu_usage": rng.uniform(0.1, 0.9, 180),
            "memory_usage": rng.uniform(0.15, 0.95, 180),
            "disk_usage": rng.uniform(0.1, 0.8, 180),
            "network_connections": rng.integers(10, 200, 180),
            "parent_child_ratio": rng.uniform(0.1, 2.0, 180),
            "process_entropy": rng.uniform(0.2, 1.0, 180),
            "privilege_escalation": rng.integers(0, 2, 180),
            "suspicious_process_count": rng.integers(0, 8, 180),
        }).astype(float)
        host_y = np.array([0] * 90 + [1] * 90, dtype=int)
        host_x.loc[90:, ["cpu_usage", "memory_usage", "suspicious_process_count", "privilege_escalation"]] += 0.4
        self.host.fit(host_x, host_y)

        identity_x = pd.DataFrame({
            "failed_logins": rng.integers(0, 5, 180),
            "successful_logins": rng.integers(0, 4, 180),
            "new_device_logins": rng.integers(0, 3, 180),
            "privilege_escalation": rng.integers(0, 2, 180),
            "user_anomaly_score": rng.uniform(0.0, 1.0, 180),
            "time_window_lateral_movement": rng.integers(0, 3, 180),
        }).astype(float)
        identity_y = np.array([0] * 90 + [1] * 90, dtype=int)
        identity_x.loc[90:, ["failed_logins", "privilege_escalation", "time_window_lateral_movement", "user_anomaly_score"]] += 1.2
        self.identity.fit(identity_x, identity_y)

        dns_x = pd.DataFrame({
            "query_length": rng.integers(5, 80, 180),
            "label_count": rng.integers(0, 4, 180),
            "numeric_ratio": rng.uniform(0.0, 0.9, 180),
            "entropy_score": rng.uniform(0.2, 1.0, 180),
            "avg_subdomain_depth": rng.uniform(0.0, 4.0, 180),
            "is_malicious_tld": rng.integers(0, 2, 180),
            "is_high_entropy": rng.integers(0, 2, 180),
            "suspicious_dns_pattern": rng.integers(0, 2, 180),
        }).astype(float)
        dns_y = np.array([0] * 90 + [1] * 90, dtype=int)
        dns_x.loc[90:, ["query_length", "label_count", "entropy_score", "is_malicious_tld", "is_high_entropy", "suspicious_dns_pattern"]] += 10
        self.dns.fit(dns_x, dns_y)
        return self

    def predict(self, record: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if "network" in record:
            result["network"] = float(self.network.predict_proba(record["network"])[0, 1])
        if "sql" in record:
            result["sql"] = float(self.database.predict_proba([record["sql"]])[0, 1])
        if "host" in record:
            result["host"] = float(self.host.predict_proba(pd.DataFrame([record["host"]]))[0, 1])
        if "identity" in record:
            result["identity"] = float(self.identity.predict_proba(pd.DataFrame([record["identity"]]))[0, 1])
        if "dns" in record:
            result["dns"] = float(self.dns.predict_proba(pd.DataFrame([record["dns"]]))[0, 1])
        result["overall_score"] = float(np.mean(list(result.values())) if result else 0.0)
        result["overall_flag"] = result["overall_score"] >= 0.5
        return result

    def generate_alert(self, record: dict[str, Any]) -> dict[str, Any]:
        summary = self.predict(record)
        normalized = {key: float(value) for key, value in summary.items() if key in {"network", "sql", "host", "identity", "dns", "overall_score"}}
        severity = "critical" if normalized.get("overall_score", 0.0) >= 0.8 else "high" if normalized.get("overall_score", 0.0) >= 0.6 else "medium" if normalized.get("overall_score", 0.0) >= 0.4 else "low"
        alert = {
            "severity": severity,
            "overall_score": normalized.get("overall_score", 0.0),
            "domain_scores": normalized,
            "triggered": bool(summary.get("overall_flag", False)),
            "payload": record,
        }
        return alert
