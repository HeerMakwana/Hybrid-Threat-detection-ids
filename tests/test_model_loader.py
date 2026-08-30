import numpy as np

from model_loader import load_model_artifact


def test_existing_model_loads_and_predicts_without_rewriting_artifact():
    artifact = load_model_artifact("models/final_model.joblib")
    assert artifact["model_type"] == "hybrid_voting_5ensemble_v3"
    assert abs(artifact["threshold"] - 0.21) < 1e-8
    assert len(artifact["feature_columns"]) == 17
    assert artifact["model"].__class__.__name__ == "VotingClassifier"
    assert artifact["scaler"].__class__.__name__ == "RobustScaler"
    features = np.zeros((2, len(artifact["feature_columns"])), dtype=np.float32)
    scaled = artifact["scaler"].transform(features)
    probabilities = artifact["model"].predict_proba(scaled)
    predictions = artifact["model"].predict(scaled)
    assert probabilities.shape == (2, 2)
    assert predictions.shape == (2,)
    assert np.isfinite(probabilities).all()