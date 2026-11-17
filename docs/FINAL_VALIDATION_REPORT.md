# Final validation report

Status date: 2026-11-15. This report separates local code/test verification
from data-scale processing and external deployment verification. No source
datasets or existing model artifacts were overwritten.

## 1. Architecture

The repository contains a legacy CICIDS-feature network model, a dataset-
feature SQLi model, domain pipeline prototypes, a normalized JSONL alert sink,
evidence-based severity and MITRE mapping, an entity/time-window correlator,
optional threat-intelligence providers, and example Wazuh agent/decoder/rule
configuration. A new resumable LANL authentication stream processor writes
compact summaries/checkpoints and keeps the original gzip in Downloads.

## 2. Dataset inventory and mapping

The recursive inventory and actual absolute source paths are in
[`DATASET_INVENTORY.md`](DATASET_INVENTORY.md) and
[`dataset_manifest.json`](../dataset_manifest.json). Direct Downloads files
found: `auth.txt.gz`, `dns.txt.gz`, `flows.txt.gz`, `proc.txt.gz`,
`redteam.txt.gz`, `Normal &Malicious SQLi.csv`, `simulation_data.csv`,
`train_sample.csv`, and `OneDrive_2026-11-13.zip`.

| Domain | Available data | Status |
|---|---|---|
| Network | CICIDS-format sample/simulation, ToN-IoT network members, LANL flows | Full CICIDS2017 not located; LANL flows unlabeled; ToN archive incomplete. |
| SQLi/database | 64,172-row SQLi CSV with 26 engineered numeric columns | Loader and existing artifact use the dataset schema; raw query-only inference is not supported. |
| Host/endpoint | LANL proc and ToN-IoT Linux process/memory/disk members | Positional loader and schema tests; no production host detector. |
| Identity/authentication | 7,626,505,167-byte LANL auth gzip and 749 red-team annotations | Full stream completed: 1,051,430,459 valid rows, zero malformed, and gzip trailer validation succeeded. Red-team association matched 735 annotations to 740 auth rows. |
| DNS | LANL DNS | Positional loader; no labels and no production detector. |
| IoT | Seven device telemetry CSV members in the ToN-IoT archive | Schema-specific loader exists; no trained IoT detector; archive incomplete. |

No Windows Security or Sysmon export was found in the recursive Downloads
inventory. The original source files are referenced in place and remain
untouched.

## 3. Preprocessing and feature engineering

CSV loaders normalize column names, reject unknown labels, and keep target
columns out of model features. CICIDS uses the network artifact's ordered 17
features; SQLi uses its own 26 numeric features; ToN-IoT files keep independent
schemas. LANL loaders parse positional schemas in chunks, normalize blank and
`?` fields to missing, and reject or explicitly log/skip wrong-width rows.

The auth processor counts success/failure, auth type, logon type, orientation,
and missing fields. Its red-team association requires exact source-user,
source-computer, and destination-computer keys plus a default absolute
five-minute time window. Annotation associations are reported separately and
are not inference features or proof that an event is malicious.

## 4. Models and measured metrics

Existing artifacts were preserved:

- Network: `models/final_model.joblib`, `hybrid_voting_5ensemble_v3`, 17
  features, stored threshold approximately `0.21`; loader and inference path
  are tested. No new full-corpus evaluation was run.
- SQLi: `models/sqli_model.joblib`, Random Forest, 26 features, stored
  threshold `0.5`; load and actual-row inference were tested. Recorded grouped
  holdout metrics are accuracy `0.998685`, precision `0.998031`, recall
  `0.999737`, F1 `0.998883`, ROC AUC `0.999984`, average precision
  `0.999988`, with confusion matrix `[[5309, 15], [2, 7604]]`. These metrics
  are specific to the source file and recorded split.

The network threshold is artifact-preserved; the SQLi report does not
establish that `0.5` was validation-optimized. No new threshold was selected.
The SQLi artifact was serialized under scikit-learn 1.9.1; the current
environment is 1.8.0 and emits `InconsistentVersionWarning`. Pin and verify a
compatible runtime before production use. No new host, identity, DNS, or IoT
model was trained.

## 5. Six-domain status

| Domain | Status | Evidence / limitation |
|---|---|---|
| Network intrusion | TESTED | Existing artifact loads and predicts; no full CICIDS corpus or fresh held-out evaluation. |
| SQLi/database | TESTED | Existing artifact loads and predicts on downloaded features; actual-query feature extraction is blocked by unverified feature definitions. |
| Host/endpoint | NOT IMPLEMENTED | LANL proc schema loader is tested; no production process feature model/rules or alert adapter. |
| Identity/authentication | DATA PROCESSING COMPLETE / DETECTOR NOT IMPLEMENTED | Full aggregation completed with 1,051,430,459 rows, 1,038,590,151 Success, 12,840,308 Fail, and zero malformed rows. Gzip EOF/trailer validation succeeded; red-team association matched 735 of 749 annotations. This is not a production identity detector or model. The legacy checkpoint lacked a red-team fingerprint and was linked after source path/row-count/window checks; its prior content fingerprint was unavailable. |
| DNS | NOT IMPLEMENTED | LANL schema loader exists; no production detector or domain alert adapter. |
| IoT | NOT IMPLEMENTED | Schema-specific ToN-IoT CSV loader exists; no model/prediction/alert pipeline; archive completeness prevents corpus acceptance. |

“Implemented” describes the scoped auth processor only, not the overall
six-domain acceptance requirement.

## 6. Threat intelligence, correlation, severity, and ATT&CK

- AbuseIPDB, VirusTotal, OTX, and OpenCTI adapters are implemented. Parsing,
  failure isolation, IOC matching, caching, and environment setup are tested
  with mocks; no live credentials/API verification was performed.
- External lookups are limited to globally routable IP addresses. Invalid or
  non-global values are explicitly marked skipped. Domain/URL/hash live
  adapters, provider-specific rate-limit retries, and URLhaus/ThreatFox are
  not implemented.
- Existing correlation groups suspicious alerts only when they share an
  entity within a bounded time window; unit tests exercise linked alerts.
- Severity remains separate from confidence and uses evidence, TI matches,
  and correlated domains. MITRE mapping requires supporting evidence. These
  components have unit-test coverage.

## 7. JSONL and Wazuh

Normalized JSONL output, alert normalization, and local XML structure checks
are covered by tests. `WazuhSvc` was observed running, but the protected agent
configuration could not be read with current permissions. No TCP connection
on ports 1514/1515 or UDP endpoint owned by the agent process was observed.
Manager ingestion, decoder extraction, custom rule matches, indexing, and
Dashboard visibility are therefore **BLOCKED / NOT VERIFIED END-TO-END**.
See [`WAZUH_DEPLOYMENT_AND_VALIDATION.md`](WAZUH_DEPLOYMENT_AND_VALIDATION.md).

## 8. Tests and evidence

The complete pytest suite passed: **54 passed, 0 failed, 0 skipped** on Python
3.12.10, including checkpoint retry and auth outcome alias coverage. Wazuh
XML/structure validation and manifest JSON validation also passed. The full
auth gzip was read to EOF and trailer validation succeeded. A prior transient
checkpoint replacement error was recovered; its log entry is retained. No
synthetic data or screenshots are represented as real-world evidence. No
Wazuh delivery evidence exists.

## 9. Remaining blockers

- The full CICIDS2017 corpus was not located; local CICIDS-format data has
  limited labels, duplicates/missing values, or uncertain provenance.
- The ToN-IoT archive is split/spanned or incomplete; only 20 previously
  verified processed CSV members are established, with Windows/network
  entries missing.
- Host, identity, DNS, and IoT production detector/model/alert acceptance is
  incomplete.
- SQLi raw-query inference and external provider live checks are unavailable.
- The scikit-learn artifact/runtime version mismatch must be resolved.
- Wazuh manager connection, decoder/rules, and Dashboard path need deployment
  access and end-to-end testing.
