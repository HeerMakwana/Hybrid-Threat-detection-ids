from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.preprocessing import RobustScaler

try:
    import lightgbm as lgb
except ImportError:  # pragma: no cover - optional dependency
    lgb = None


DEFAULT_WEIGHTS = np.array([4.0, 3.0, 1.5, 1.0, 0.8], dtype=float)


class ProbabilityCalibrator:
    """Simple wrapper that adapts a fitted estimator to a calibrated predict_proba API."""

    def __init__(self, estimator: Any, calibrator: Any):
        self.estimator = estimator
        self.calibrator = calibrator

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if hasattr(self.calibrator, "predict_proba"):
            return self.calibrator.predict_proba(X)
        base = self.estimator.predict_proba(X)[:, 1]
        if hasattr(self.calibrator, "transform"):
            calibrated = self.calibrator.transform(base)
        else:
            calibrated = self.calibrator.predict_proba(base.reshape(-1, 1))[:, 1]
        return np.column_stack([1.0 - calibrated, calibrated])

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


@dataclass
class HybridEnsembleModel:
    weights: np.ndarray = field(default_factory=lambda: DEFAULT_WEIGHTS.copy())
    calibrate: bool = True
    use_lightgbm: bool = True
    threshold: float = 0.5
    feature_columns: list[str] | None = None
    scaler: RobustScaler | None = None
    base_models_: list[Any] = field(default_factory=list)
    meta_learner_: Any | None = None

    def __post_init__(self):
        self.weights = np.asarray(self.weights, dtype=float)

    def _build_estimators(self) -> list[Any]:
        if lgb is not None and self.use_lightgbm:
            return [
                lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, max_depth=5, subsample=0.9, random_state=42),
                lgb.LGBMClassifier(n_estimators=600, learning_rate=0.03, max_depth=-1, num_leaves=63, subsample=0.9, random_state=43),
                RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1, class_weight="balanced"),
                ExtraTreesClassifier(n_estimators=150, random_state=42, n_jobs=-1, class_weight="balanced"),
                SGDClassifier(loss="log_loss", max_iter=2000, tol=1e-4, class_weight="balanced"),
            ]
        return [
            RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1, class_weight="balanced"),
            ExtraTreesClassifier(n_estimators=150, random_state=42, n_jobs=-1, class_weight="balanced"),
            SGDClassifier(loss="log_loss", max_iter=2000, tol=1e-4, class_weight="balanced"),
            LogisticRegression(max_iter=2000, class_weight="balanced"),
            VotingClassifier(estimators=[
                ("rf", RandomForestClassifier(n_estimators=80, random_state=42, n_jobs=-1)),
                ("et", ExtraTreesClassifier(n_estimators=80, random_state=42, n_jobs=-1)),
            ], voting="soft"),
        ]

    def _prepare_features(self, X: Any) -> np.ndarray:
        if isinstance(X, pd.DataFrame):
            if self.feature_columns is not None:
                X = X.reindex(columns=self.feature_columns, fill_value=0.0)
            return X.to_numpy(dtype=np.float64)
        return np.asarray(X, dtype=np.float64)

    def fit(self, X: Any, y: Any) -> "HybridEnsembleModel":
        X_array = self._prepare_features(X)
        self.feature_columns = list(X.columns) if isinstance(X, pd.DataFrame) else [f"feature_{i}" for i in range(X_array.shape[1])]
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X_array)

        base_models = self._build_estimators()
        calibrated = []
        for estimator in base_models:
            if self.calibrate:
                calibrator = CalibratedClassifierCV(estimator=estimator, method="isotonic", cv=3)
                calibrator.fit(X_scaled, y)
                calibrated.append(ProbabilityCalibrator(estimator, calibrator))
            else:
                estimator.fit(X_scaled, y)
                calibrated.append(estimator)
        self.base_models_ = calibrated

        stack = np.column_stack([model.predict_proba(X_scaled)[:, 1] for model in self.base_models_])
        self.meta_learner_ = LogisticRegression(max_iter=2000)
        self.meta_learner_.fit(stack, y)
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        if self.scaler is None:
            raise ValueError("The ensemble has not been trained yet.")
        X_scaled = self.scaler.transform(self._prepare_features(X))
        stack = np.column_stack([model.predict_proba(X_scaled)[:, 1] for model in self.base_models_])
        if self.meta_learner_ is not None:
            final = self.meta_learner_.predict_proba(stack)[:, 1]
        else:
            weighted = stack @ self.weights / self.weights.sum()
            final = weighted
        return np.column_stack([1.0 - final, final])

    def predict(self, X: Any, threshold: float | None = None) -> np.ndarray:
        threshold = self.threshold if threshold is None else threshold
        proba = self.predict_proba(X)[:, 1]
        return (proba >= threshold).astype(int)

    def save(self, path: str) -> None:
        payload = {
            "model": self,
            "feature_columns": self.feature_columns,
            "weights": self.weights,
            "threshold": self.threshold,
            "model_type": "HybridEnsembleModel",
        }
        joblib.dump(payload, path)

    @classmethod
    def load(cls, path: str) -> "HybridEnsembleModel":
        payload = joblib.load(path)
        if isinstance(payload, cls):
            return payload
        model = payload["model"]
        model.feature_columns = payload.get("feature_columns", model.feature_columns)
        model.threshold = payload.get("threshold", model.threshold)
        return model
