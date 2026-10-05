"""Compare compact baseline classifiers on the 2024 flow feature contract."""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from feature_schema import align_feature_frame
from model_loader import load_model_artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rows", type=int, default=100_000)
    parser.add_argument("--output", default="logs/model_comparison_2024.json")
    args = parser.parse_args()

    data = pd.read_csv("data/2024/Data.csv")
    labels = pd.read_csv("data/2024/Label.csv").iloc[:, 0]
    data["__label__"] = (labels.to_numpy() != 0).astype(np.int8)
    if args.max_rows and len(data) > args.max_rows:
        data, _ = train_test_split(
            data, train_size=args.max_rows, random_state=42,
            stratify=data["__label__"],
        )
    y = data.pop("__label__").to_numpy()
    artifact = load_model_artifact("models/final_model.joblib")
    X = align_feature_frame(data, artifact["feature_columns"]).to_numpy(dtype=np.float32)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_test = scaler.transform(X_test).astype(np.float32)

    estimators = {
        "logistic_regression": LogisticRegression(
            class_weight="balanced", max_iter=500, n_jobs=-1,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=200, max_leaf_nodes=31, learning_rate=0.08,
            l2_regularization=0.1, random_state=42,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=100, max_depth=16, min_samples_leaf=5,
            class_weight="balanced_subsample", n_jobs=-1, random_state=42,
        ),
    }
    report = {"rows": len(y), "test_rows": len(y_test), "models": {}}
    for name, estimator in estimators.items():
        estimator.fit(X_train, y_train)
        probabilities = estimator.predict_proba(X_test)[:, 1]
        predictions = (probabilities >= 0.5).astype(np.int8)
        report["models"][name] = {
            "accuracy": accuracy_score(y_test, predictions),
            "precision": precision_score(y_test, predictions, zero_division=0),
            "recall": recall_score(y_test, predictions, zero_division=0),
            "f1": f1_score(y_test, predictions, zero_division=0),
            "roc_auc": roc_auc_score(y_test, probabilities),
        }
    report["production_artifact_reference"] = json.loads(
        Path("models/evaluation_results.json").read_text(encoding="utf-8")
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()