# Model training and evaluation

This report distinguishes existing artifacts and measured dataset holdout
results from work that has not been run in this repository. No existing model
was retrained or replaced during this task.

## Existing artifacts

| Domain | Artifact | Verified contract | Status and caveat |
|---|---|---|---|
| Network | `models/final_model.joblib` | Loads as `hybrid_voting_5ensemble_v3`; 17 ordered CICIDS-derived features; stored threshold approximately `0.21`; scaler and classifier prediction path are covered by tests. | Preserved and loaded. No new held-out evaluation was run because the full CICIDS2017 corpus is unavailable and the local sample has uncertain provenance and only BENIGN/DDoS labels. |
| SQL injection | `models/sqli_model.joblib` | Loads as `RandomForestClassifier`; 26 exact numeric feature columns; stored threshold `0.5`. | Preserved and loaded. The current Python environment has scikit-learn 1.8.0 while this artifact was serialized with 1.9.1; the loader emits `InconsistentVersionWarning`. Loading succeeded, but the warning requires a pinned compatible environment for production use. |

## Existing SQLi holdout results

The recorded evaluation used the actual
`Normal &Malicious SQLi.csv` file (64,172 rows). Five groups of identical
feature vectors with conflicting labels (136 rows total) were excluded. The
remaining data was split using `GroupShuffleSplit` by a SHA-256 fingerprint of
the exact 26-feature vector, so an identical feature vector could not cross
the train/test boundary.

| Metric | Measured value |
|---|---:|
| Train rows | 51,106 |
| Test rows | 12,930 |
| Accuracy | 0.998685 |
| Precision | 0.998031 |
| Recall | 0.999737 |
| F1 | 0.998883 |
| ROC AUC | 0.999984 |
| Average precision | 0.999988 |
| False-positive rate | 0.002817 |
| False-negative rate | 0.000263 |
| Confusion matrix (Normal, Malicious) | `[[5309, 15], [2, 7604]]` |

These are dataset-specific holdout measurements from the existing training
run; they do not establish external generalization. The saved threshold is
`0.5`; the historical report does not show a separately optimized validation
threshold, so it must not be described as validation-selected. Raw SQL text
is not accepted as model input because the source definitions for all 26
engineered values are not verified.

## Network model and data limitations

The network artifact preserves the legacy five-estimator soft-voting model
(LightGBM Fast, LightGBM Deep, Random Forest, Extra Trees, and calibrated
SGD). Its 17-feature ordering and saved threshold are used at inference. The
artifact was not retrained or independently benchmarked in this task.

`train_sample.csv` has 200,000 rows, three missing `Flow Bytes/s` values,
1,913 duplicate rows, only BENIGN/DDoS labels, and unverified official-source
provenance. `simulation_data.csv` has 500 rows and four duplicate rows with
unverified provenance. Neither is used here to claim network model metrics.
The ToN-IoT network files have independent feature schemas and are not passed
to the CICIDS model.

## Other domains and threshold policy

No supervised host, identity, DNS, or IoT artifact was trained in this task.
The auth stream processor is an ingestion/aggregation component, not a trained
identity detector. LANL `flows.txt.gz` and `dns.txt.gz` have no attack labels,
and `redteam.txt.gz` contains event annotations rather than complete labeled
examples. The ToN-IoT archive is incomplete and standard ZIP tools cannot open
it as a normal archive.

No new threshold was selected. In future training, split train/validation/test
by an appropriate grouping key before fitting; select a threshold on the
validation set using a documented objective and report test metrics only once.
Do not fit preprocessing on the test set. Preserve an existing artifact and
its backup before any approved replacement. `train-sqli` now refuses to
overwrite an existing model by default; `--overwrite` explicitly requests
replacement and preserves the prior file as `.bak`.

No additional feature-importance, training-time, inference-time, PR curve, or
per-class metrics are asserted beyond the recorded results above. These
remain evaluation work rather than inferred results.
