from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from multi_domain_ids.dataset_loaders import LabeledDataset, SQLI_FEATURE_COLUMNS
from multi_domain_ids.sqli_model import (
    SqliModel,
    _grouped_split,
    load_sqli_model,
    train_sqli_dataset,
)


def test_grouped_split_excludes_conflicting_feature_vectors_without_leakage():
    features = pd.DataFrame({"feature": [0.0, 1.0, 1.0, 2.0, 3.0, 4.0]})
    labels = pd.Series([0, 0, 1, 1, 0, 1], name="target")
    dataset = LabeledDataset(features, labels, labels.astype("string"))

    split = _grouped_split(dataset, test_size=0.5, random_state=7)

    assert split["conflicting_groups"] == 1
    assert split["conflicting_rows"] == 2
    train_features = set(features.iloc[split["train_indices"]]["feature"])
    test_features = set(features.iloc[split["test_indices"]]["feature"])
    assert train_features.isdisjoint(test_features)
    assert labels.iloc[split["train_indices"]].nunique() == 2
    assert labels.iloc[split["test_indices"]].nunique() == 2


def test_sqli_model_requires_exact_feature_schema_and_valid_threshold():
    model = SqliModel(estimator=RandomForestClassifier(), feature_columns=("a",))

    with pytest.raises(ValueError, match="missing required feature columns"):
        model.predict_proba(pd.DataFrame({"b": [1]}))
    with pytest.raises(ValueError, match="threshold"):
        model.predict(pd.DataFrame({"a": [1]}), threshold=2)


def test_sqli_artifact_loader_checks_feature_order(tmp_path):
    features = pd.DataFrame(np.zeros((2, len(SQLI_FEATURE_COLUMNS))), columns=SQLI_FEATURE_COLUMNS)
    model = RandomForestClassifier(n_estimators=1, random_state=1).fit(features, [0, 1])
    path = tmp_path / "model.joblib"
    joblib.dump(
        {
            "model": model,
            "feature_columns": list(reversed(SQLI_FEATURE_COLUMNS)),
            "threshold": 0.5,
        },
        path,
    )

    with pytest.raises(ValueError, match="feature ordering"):
        load_sqli_model(path)


def test_sqli_training_refuses_to_replace_an_existing_artifact_by_default(tmp_path):
    artifact = tmp_path / "existing.joblib"
    artifact.write_bytes(b"preserve me")

    with pytest.raises(FileExistsError, match="explicitly allow replacement"):
        train_sqli_dataset(tmp_path / "missing.csv", model_out=artifact)

    assert artifact.read_bytes() == b"preserve me"
