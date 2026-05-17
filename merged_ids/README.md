# Hybrid ML-Based Intrusion Detection System (IDS)

A high-performance ensemble machine learning model for detecting network intrusions and anomalies. Trained on CICIDS2017 dataset with **98.15% accuracy**, **92.55% precision**, **98.54% recall**, and only **1.95% false positive rate**.

## Features

- **5-Estimator Hybrid Ensemble**: LightGBM (2x) + Random Forest + Extra Trees + Calibrated SGD
- **Stacking Meta-Learner**: LogisticRegression trained on calibrated base estimator probabilities
- **Cost-Sensitive Learning**: Scale-pos-weight for LightGBM to handle class imbalance
- **Probability Calibration**: Isotonic/Platt scaling for reliable prediction confidence
- **Production-Ready**: Optimized threshold tuning, low false alarm rate
- **Scalable**: Handles 2.8M+ training samples with chunked CSV loading and float32 casting

## Performance Metrics

| Metric | Value |
|--------|-------|
| Accuracy | 98.15% |
| Precision | 92.55% |
| Recall (Detection Rate) | 98.54% |
| F1 Score | 95.45% |
| False Positive Rate | 1.95% |
| ROC-AUC | 0.9984 |

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Load and Use the Pre-trained Model

```python
import joblib
import numpy as np

# Load trained model
artifact = joblib.load('models/final_model.joblib')
model = artifact['model']
scaler = artifact['scaler']
feature_columns = artifact['feature_columns']
threshold = artifact['threshold']  # 0.210

# Prepare your feature matrix (shape: n_samples × 17)
X = ...  # Your network traffic features

# Scale features
X_scaled = scaler.transform(X)

# Get predictions
probs = model.predict_proba(X_scaled)[:, 1]
predictions = (probs >= threshold).astype(int)  # 1=Attack, 0=Normal

# With confidence scores
for i, (pred, prob) in enumerate(zip(predictions, probs)):
    if pred == 1:
        print(f"Sample {i}: ATTACK (confidence={prob:.4f})")
    else:
        print(f"Sample {i}: NORMAL (confidence={1-prob:.4f})")
```

### 3. Train on Your Own Data

```bash
python train_model.py \
    --data path/to/your/data.csv \
    --label Label \
    --out models/my_model.joblib \
    --stack \
    --calibrate \
    --scale-pos-weight \
    --recall-weight 0.5 \
    --f1-weight 0.2 \
    --fp-penalty 0.3
```

## Model Files

- **`models/final_model.joblib`** (16.7 MB): Production model artifact
  - 5 base estimators (fitted & calibrated)
  - Stacking meta-learner
  - RobustScaler
  - Optimal decision threshold (0.210)
  
- **`models/evaluation_results.json`**: Full training metrics
- **`SIMULATION_TEST_REPORT.md`**: Test results on 500 samples

## Model Architecture

```
Hybrid 5-Estimator Soft-Voting Ensemble with Stacking
├── lgbm_fast (LightGBM, 400 trees, shallow)
├── lgbm_deep (LightGBM, 600 trees, deep)
├── rf (RandomForest, 150 trees)
├── et (ExtraTreesClassifier, 150 trees)
└── sgd_cal (SGD with Isotonic Calibration)

Weights: [4.0, 3.0, 1.5, 1.0, 0.8]

Pipeline:
1. Feature scaling (RobustScaler)
2. Parallel base estimator predictions
3. Probability calibration (IsotonicRegression)
4. Stacking via LogisticRegression meta-learner
5. Threshold-based final classification (threshold=0.210)
```

## Command-Line Options

```
python train_model.py --help

  --data PATH              Path to CSV training data (required)
  --label COLUMN           Label column name (auto-detected if omitted)
  --max-rows N             Limit rows via stratified sampling (for quick testing)
  --out PATH               Output model path (default: models/final_model.joblib)
  --gpu                    Enable GPU training for LightGBM
  --balance-ratio R        Undersample negatives to achieve ratio (0 < R < 1)
  --recall-weight W        Recall weight for threshold optimization (default 0.5)
  --f1-weight W            F1 weight for threshold optimization (default 0.2)
  --fp-penalty P           FP rate penalty for threshold optimization (default 0.3)
  --stack                  Enable stacking meta-learner
  --calibrate              Enable probability calibration
  --scale-pos-weight       Use LightGBM scale_pos_weight (cost-sensitive)
```

## Test Results

### Simulation Test (500 samples: 96 attacks + 404 benign)

| Attack Type | Detected | Rate | Avg Confidence |
|-------------|----------|------|-----------------|
| DDoS | 20/20 | 100% | 0.964 |
| DoS Hulk | 38/38 | 100% | 0.869 |
| PortScan | 30/30 | 100% | 0.952 |
| FTP-Patator | 2/2 | 100% | 0.918 |
| DoS variants | 6/6 | 100% | 0.858+ |
| **BENIGN** | 8/404 | 2.0% | 0.057 |

**Perfect attack detection (100% recall) with minimal false alarms (1.98% FPR).**

See [SIMULATION_TEST_REPORT.md](SIMULATION_TEST_REPORT.md) for detailed analysis.

## Dataset Format

Your CSV should contain 17+ features matching the CICIDS schema:

**Required Features** (17 minimum):
- Flow Duration
- Total Fwd/Backward Packets
- Packet Length Mean/Std/Min/Max
- Flow Bytes/s, Flow Packets/s
- IAT Mean/Std/Max/Min
- Forward/Backward Packet Statistics
- TCP Flags (SYN, FIN, RST, etc.)

**Label Column**:
- "BENIGN" or "NORMAL" = 0 (normal traffic)
- Any other value = 1 (attack)

See `data/README.md` for details.

## File Structure

```
merged_ids/
├── train_model.py              # Main training pipeline
├── feature_extractor.py        # CICIDS feature definitions
├── simulation.py               # Inference script
├── models/
│   ├── final_model.joblib      # Production model (16.7 MB)
│   └── evaluation_results.json # Training metrics
├── data/
│   ├── combined.csv            # Full training data (2.8M rows)
│   ├── simulation_data.csv     # Test set (500 samples)
│   └── README.md
├── README.md                   # This file
└── SIMULATION_TEST_REPORT.md   # Test results
```

## Performance Notes

- **Training**: ~4 minutes on 2.8M samples (24-core CPU)
- **Inference**: ~5 seconds for 566k samples (batch)
- **Model Size**: 16.7 MB (compressed)
- **RAM**: ~2-3 GB during training

## References

Trained on CICIDS2017 dataset:
- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization."* ICISSP.

## License

MIT License - See LICENSE file for details.

---

**Status**: Production-Ready  
**Version**: 1.0 (Stacking + Calibration + LightGBM)  
**Last Updated**: May 2026
```

Notes:
- The interface will fall back to simulation if live capture fails and fallback is enabled.
- Alerts are JSON lines and can be forwarded to syslog.
