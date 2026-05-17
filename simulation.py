"""Run the trained model on simulation data and generate alerts."""
import argparse
import json
import os
import re
import pandas as pd
import numpy as np
import joblib
from datetime import datetime


FEATURE_ALIASES = {
    "flow duration": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",
    "fwd packet length max": "Fwd Packet Length Max",
    "fwd packet length min": "Fwd Packet Length Min",
    "fwd packet length mean": "Fwd Packet Length Mean",
    "fwd packet length std": "Fwd Packet Length Std",
    "bwd packet length max": "Bwd Packet Length Max",
    "bwd packet length min": "Bwd Packet Length Min",
    "bwd packet length mean": "Bwd Packet Length Mean",
    "bwd packet length std": "Bwd Packet Length Std",
    "flow bytes/s": "Flow Bytes/s",
    "flow bytes per second": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "flow packets per second": "Flow Packets/s",
    "packet length mean": "Packet Length Mean",
    "packet length std": "Packet Length Std",
}


def _normalize(name):
    return re.sub(r"\s+", " ", str(name).strip().lower())


def find_label_column(df):
    """Find the label column in the dataframe."""
    candidates = [c for c in df.columns if _normalize(c) in {"label", "class", "attack", "target"}]
    if candidates:
        return candidates[0]
    return None  # May not exist in simulation data


def align_cicids_columns(df, feature_columns):
    """Align columns to match training features."""
    rename_map = {}
    normalized_lookup = {_normalize(col): col for col in df.columns}
    for alias, canonical in FEATURE_ALIASES.items():
        if alias in normalized_lookup:
            rename_map[normalized_lookup[alias]] = canonical

    df = df.rename(columns=rename_map)

    # Build aligned feature frame with features from training
    aligned = pd.DataFrame(index=df.index)
    for feature in feature_columns:
        if feature in df.columns:
            aligned[feature] = pd.to_numeric(df[feature], errors="coerce").fillna(0.0)
        else:
            aligned[feature] = 0.0
    return aligned


def run_simulation(model_path, data_path, alert_file, threshold=None):
    print(f"Loading model: {model_path}", flush=True)
    artifact = joblib.load(model_path)
    model = artifact["model"]
    scaler = artifact["scaler"]
    feature_columns = artifact["feature_columns"]
    threshold = threshold or artifact.get("threshold", 0.5)
    
    print(f"Model type: {artifact.get('model_type', 'unknown')}", flush=True)
    print(f"Detection threshold: {threshold:.4f}", flush=True)
    
    print(f"Loading simulation data: {data_path}", flush=True)
    df = pd.read_csv(data_path)
    print(f"Loaded {len(df)} records from simulation data", flush=True)
    
    # Preprocess data
    X = align_cicids_columns(df, feature_columns)
    
    # Sanitize numeric values
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X = X.clip(lower=-1e12, upper=1e12)
    
    # Scale features
    X_scaled = scaler.transform(X)
    print(f"Features scaled: shape {X_scaled.shape}", flush=True)
    
    # Make predictions
    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)[:, 1]
    print(f"Predictions complete", flush=True)
    
    # Generate alerts for anomalies (predictions >= threshold)
    alerts = []
    benign_count = 0
    anomaly_count = 0
    
    os.makedirs(os.path.dirname(alert_file) or ".", exist_ok=True)
    
    with open(alert_file, "w", encoding="utf-8") as f:
        for idx, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if pred == 1:  # Anomaly detected
                anomaly_count += 1
                alert = {
                    "alert_id": f"sim-alert-{idx}-{int(datetime.utcnow().timestamp())}",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "record_index": int(idx),
                    "predicted_label": "ANOMALY",
                    "confidence": float(prob),
                    "threshold": float(threshold),
                    "model_type": artifact.get("model_type", "unknown"),
                }
                alerts.append(alert)
                f.write(json.dumps(alert) + "\n")
                print(f"ALERT [{idx}]: Anomaly detected with confidence {prob:.4f}")
            else:
                benign_count += 1
    
    # Print summary
    print("\n" + "="*60)
    print("SIMULATION SUMMARY")
    print("="*60)
    print(f"Total records processed: {len(df)}")
    print(f"Benign records: {benign_count}")
    print(f"Anomalies detected: {anomaly_count}")
    print(f"Detection rate: {anomaly_count / len(df) * 100:.2f}%")
    print(f"Alerts written to: {alert_file}")
    print("="*60 + "\n")
    
    # Save simulation results JSON
    results = {
        "simulation_data_file": data_path,
        "model_file": model_path,
        "model_type": artifact.get("model_type", "unknown"),
        "threshold": float(threshold),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_records": int(len(df)),
        "benign_records": int(benign_count),
        "anomalies_detected": int(anomaly_count),
        "detection_rate": float(anomaly_count / len(df)),
        "alert_file": alert_file,
        "alerts": alerts,
    }
    
    results_file = os.path.join(os.path.dirname(alert_file) or ".", "simulation_results.json")
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved results to: {results_file}")


def main():
    parser = argparse.ArgumentParser(description="Run simulation on model")
    parser.add_argument("--model", default="models/final_model.joblib", help="Path to trained model")
    parser.add_argument("--data", default="data/simulation_data.csv", help="Path to simulation data CSV")
    parser.add_argument("--alert-file", default="logs/simulation_alerts.jsonl", help="Output file for alerts")
    parser.add_argument("--threshold", type=float, default=None, help="Detection threshold (uses model default if not set)")
    args = parser.parse_args()
    
    run_simulation(args.model, args.data, args.alert_file, args.threshold)


if __name__ == "__main__":
    main()
