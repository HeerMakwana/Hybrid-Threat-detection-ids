from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from .dataset_loaders import LabeledDataset, SQLI_FEATURE_COLUMNS, load_sqli_csv


@dataclass
class SqliModel:
    estimator: RandomForestClassifier
    feature_columns: tuple[str, ...] = SQLI_FEATURE_COLUMNS
    threshold: float = 0.5

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        missing = [column for column in self.feature_columns if column not in features.columns]
        if missing:
            raise ValueError(f"SQLi input is missing required feature columns: {missing}")
        ordered = features.loc[:, self.feature_columns]
        if ordered.isna().any().any():
            raise ValueError("SQLi features contain missing values")
        return self.estimator.predict_proba(ordered)

    def predict(self, features: pd.DataFrame, threshold: float | None = None) -> np.ndarray:
        threshold = self.threshold if threshold is None else threshold
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        return (self.predict_proba(features)[:, 1] >= threshold).astype("int8")


def train_sqli_dataset(
    path: str | Path,
    *,
    test_size: float = 0.2,
    random_state: int = 42,
    model_out: str | Path | None = None,
    overwrite: bool = False,
) -> tuple[SqliModel, dict[str, Any]]:
    """Train and evaluate SQLi using only loaded source rows and a grouped split."""
    if not 0.1 <= test_size <= 0.5:
        raise ValueError("test_size must be between 0.1 and 0.5")
    artifact = Path(model_out) if model_out is not None else None
    if artifact is not None and artifact.exists():
        if not overwrite:
            raise FileExistsError(
                f"Model artifact already exists; choose another path or explicitly allow "
                f"replacement: {artifact}"
            )
        backup_path = artifact.with_name(f"{artifact.name}.bak")
        if backup_path.exists():
            raise FileExistsError(
                f"Refusing to overwrite the existing model backup: {backup_path}"
            )
    dataset = load_sqli_csv(path)
    split = _grouped_split(dataset, test_size=test_size, random_state=random_state)
    train_idx, test_idx = split["train_indices"], split["test_indices"]
    estimator = RandomForestClassifier(
        n_estimators=250,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1,
    )
    x_train = dataset.features.iloc[train_idx].loc[:, SQLI_FEATURE_COLUMNS]
    y_train = dataset.labels.iloc[train_idx]
    x_test = dataset.features.iloc[test_idx].loc[:, SQLI_FEATURE_COLUMNS]
    y_test = dataset.labels.iloc[test_idx]
    estimator.fit(x_train, y_train)
    model = SqliModel(estimator=estimator)
    probabilities = model.predict_proba(x_test)[:, 1]
    predictions = (probabilities >= 0.5).astype("int8")
    report: dict[str, Any] = {
        "dataset": str(Path(path).resolve()),
        "rows_loaded": int(len(dataset.labels)),
        "rows_excluded_for_conflicting_duplicate_features": split["conflicting_rows"],
        "conflicting_feature_groups": split["conflicting_groups"],
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "feature_count": int(len(SQLI_FEATURE_COLUMNS)),
        "feature_columns": list(SQLI_FEATURE_COLUMNS),
        "class_distribution": {
            "normal": int((dataset.labels == 0).sum()),
            "malicious": int((dataset.labels == 1).sum()),
        },
        "split": {
            "method": "GroupShuffleSplit by exact feature-vector fingerprint",
            "test_size": test_size,
            "random_state": random_state,
        },
        "threshold": 0.5,
        "metrics": {
            "accuracy": float(accuracy_score(y_test, predictions)),
            "precision": float(precision_score(y_test, predictions, zero_division=0)),
            "recall": float(recall_score(y_test, predictions, zero_division=0)),
            "f1": float(f1_score(y_test, predictions, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, probabilities)),
            "average_precision": float(average_precision_score(y_test, probabilities)),
            "confusion_matrix_labels_0_1": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        },
        "artifact_path": None,
    }
    if artifact is not None:
        artifact.parent.mkdir(parents=True, exist_ok=True)
        backup_path = None
        if artifact.exists():
            backup_path = artifact.with_name(f"{artifact.name}.bak")
            shutil.copy2(artifact, backup_path)
        with tempfile.NamedTemporaryFile(
            prefix=f"{artifact.name}.",
            suffix=".tmp",
            dir=artifact.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
        replaced = False
        try:
            joblib.dump(
                {
                    "model": model.estimator,
                    "feature_columns": list(model.feature_columns),
                    "threshold": 0.5,
                    "dataset": str(Path(path).resolve()),
                    "metrics": report["metrics"],
                },
                temporary_path,
            )
            temporary_path.replace(artifact)
            replaced = True
        finally:
            temporary_path.unlink(missing_ok=True)
            if backup_path is not None and not replaced:
                backup_path.unlink(missing_ok=True)
        report["artifact_path"] = str(artifact.resolve())
        report["backup_path"] = str(backup_path.resolve()) if backup_path else None
    return model, report


def load_sqli_model(path: str | Path) -> SqliModel:
    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or "model" not in artifact:
        raise ValueError(f"Invalid SQLi model artifact: {path}")
    columns = tuple(artifact.get("feature_columns", ()))
    if columns != SQLI_FEATURE_COLUMNS:
        raise ValueError("SQLi artifact feature ordering does not match the dataset schema")
    threshold = artifact.get("threshold")
    if not isinstance(threshold, (int, float)) or not 0.0 <= float(threshold) <= 1.0:
        raise ValueError("SQLi artifact has an invalid classification threshold")
    return SqliModel(
        estimator=artifact["model"],
        feature_columns=columns,
        threshold=float(threshold),
    )


def _grouped_split(
    dataset: LabeledDataset,
    *,
    test_size: float,
    random_state: int,
) -> dict[str, Any]:
    fingerprints = _feature_fingerprints(dataset.features)
    group_frame = pd.DataFrame(
        {"fingerprint": fingerprints, "target": dataset.labels.to_numpy()}
    )
    group_labels = group_frame.groupby("fingerprint", sort=False)["target"]
    conflicting = set(group_labels.nunique().loc[lambda values: values > 1].index)
    keep = ~group_frame["fingerprint"].isin(conflicting)
    retained = np.flatnonzero(keep.to_numpy())
    retained_groups = group_frame.loc[keep, "fingerprint"].to_numpy()
    retained_labels = dataset.labels.iloc[retained].to_numpy()
    if len(np.unique(retained_labels)) != 2:
        raise ValueError("SQLi dataset must retain both classes after conflicting groups are excluded")
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_rel, test_rel = next(
        splitter.split(np.zeros(len(retained)), retained_labels, groups=retained_groups)
    )
    train_indices = retained[train_rel]
    test_indices = retained[test_rel]
    if set(fingerprints.iloc[train_indices]) & set(fingerprints.iloc[test_indices]):
        raise RuntimeError("Grouped split unexpectedly put a feature vector in both partitions")
    if len(np.unique(dataset.labels.iloc[test_indices])) != 2:
        raise ValueError("Grouped test split does not contain both classes")
    return {
        "train_indices": train_indices,
        "test_indices": test_indices,
        "conflicting_groups": len(conflicting),
        "conflicting_rows": int((~keep).sum()),
    }


def _feature_fingerprints(features: pd.DataFrame) -> pd.Series:
    fingerprints = []
    for row in features.itertuples(index=False, name=None):
        canonical = json.dumps(
            [None if pd.isna(value) else float(value) for value in row],
            separators=(",", ":"),
            allow_nan=False,
        )
        fingerprints.append(hashlib.sha256(canonical.encode("ascii")).hexdigest())
    return pd.Series(fingerprints, index=features.index, dtype="string")
