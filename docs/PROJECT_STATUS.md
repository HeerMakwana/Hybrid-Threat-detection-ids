# Project Status

## Completed

- Retrained the production ensemble on all 447,915 CIC-UNSW-NB15 2024 flows.
- Calibrated a zero-validation-false-negative threshold with exact probability boundary selection.
- Reduced validation false positives to 2.88% while retaining 100% validation recall.
- Added shared feature alignment for training, replay, and live packet capture.
- Added bounded live flow capture through TShark/PyShark.
- Added baseline model comparison for logistic regression, histogram gradient boosting, and random forest.
- Added explainable risk score, P1-P4 prioritization, MITRE mapping, and Wazuh rules.
- Added Wazuh JSONL ingestion and Ubuntu deployment instructions.
- Added human approval decisions for approve, reject, and escalate workflows.

## Response Safety

The review workflow records a requested action but never executes network blocking.
Wazuh active response should only be enabled after the operator validates alert
volume, allowlists trusted sources, and approves a separate production policy.

Record a review decision for a canonical event with:

```bash
python scripts/review_alert.py input.json output.json \
  --decision approve --reviewer analyst-1 --action COLLECT_EVIDENCE
```

## Current Validation

- Validation rows: `89,583`
- Validation recall: `100.00%`
- Validation false negatives: `0`
- Validation false-positive rate: `2.88%`
- Full automated test suite: `28 passed`

The zero-false-negative result is empirical for the held-out validation set. It
cannot guarantee zero misses on future unseen traffic without alerting all traffic
or continuously retraining with new labeled data.