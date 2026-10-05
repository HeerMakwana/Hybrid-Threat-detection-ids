"""Evaluate the saved binary IDS model on the CIC-UNSW-NB15 2024 files."""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from model_loader import load_model_artifact


DATASET = Path("data/2024")
MODEL = Path("models/final_model.joblib")


def main() -> None:
    artifact = load_model_artifact(str(MODEL))
    data = pd.read_csv(DATASET / "Data.csv")
    labels = pd.read_csv(DATASET / "Label.csv").iloc[:, 0].to_numpy()
    if len(data) != len(labels):
        raise ValueError(f"Data/label row mismatch: {len(data)} != {len(labels)}")

    data = data.rename(columns={
        "Total Fwd Packet": "Total Fwd Packets",
        "Total Bwd packets": "Total Backward Packets",
        "Total Length of Fwd Packet": "Total Length of Fwd Packets",
        "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    })
    features = artifact["feature_columns"]
    aligned = pd.DataFrame({
        feature: pd.to_numeric(data[feature], errors="coerce").fillna(0.0)
        if feature in data.columns else 0.0
        for feature in features
    })
    aligned = aligned.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    aligned = aligned.clip(lower=-1e12, upper=1e12)

    probabilities = artifact["model"].predict_proba(
        artifact["scaler"].transform(aligned.to_numpy(dtype=np.float32, copy=False))
    )[:, 1]
    actual = (labels != 0).astype(np.int8)
    threshold = float(artifact.get("threshold", 0.5))
    predicted = (probabilities >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()

    metrics = {
        "rows": len(actual),
        "threshold": threshold,
        "accuracy": accuracy_score(actual, predicted),
        "precision": precision_score(actual, predicted, zero_division=0),
        "recall": recall_score(actual, predicted, zero_division=0),
        "f1": f1_score(actual, predicted, zero_division=0),
        "false_positive_rate": fp / max(1, fp + tn),
        "roc_auc": roc_auc_score(actual, probabilities),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "actual_benign": int((actual == 0).sum()),
        "actual_attack": int((actual == 1).sum()),
        "predicted_benign": int((predicted == 0).sum()),
        "predicted_attack": int((predicted == 1).sum()),
    }
    print(json.dumps(metrics, indent=2))
    print("Per original label:")
    for label in sorted(np.unique(labels)):
        mask = labels == label
        print(
            f"  label {int(label)}: n={int(mask.sum()):,}, "
            f"detected={int(predicted[mask].sum()):,}, "
            f"rate={float(predicted[mask].mean()):.4f}"
        )


if __name__ == "__main__":
    main()