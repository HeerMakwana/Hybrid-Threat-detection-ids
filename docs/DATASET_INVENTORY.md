# Dataset inventory

Inventory updated 2026-11-15 from a recursive scan of
`C:\Users\ISHITA DUBEY\Downloads`. Original files are read in place. No file
was moved, renamed, deleted, extracted, or edited. The authoritative paths,
schema definitions, label counts, ToN-IoT member details, and provenance notes
are in [`dataset_manifest.json`](../dataset_manifest.json).

## Files found directly under Downloads

| File | Size (bytes) | Observed format/schema | Rows and labels | Intended use and status |
|---|---:|---|---|---|
| `auth.txt.gz` | 7,626,505,167 | Headerless gzip CSV, 9 fields: `time`, `source_user_domain`, `destination_user_domain`, `source_computer`, `destination_computer`, `authentication_type`, `logon_type`, `authentication_orientation`, `success_failure` | **1,051,430,459 rows**, zero malformed; outcomes: 1,038,590,151 Success and 12,840,308 Fail. Full gzip stream reached EOF and trailer validation succeeded. | Identity/authentication aggregation complete. The separate red-team join matched 735/749 annotations and associated 740 auth rows within 300 seconds; annotations are not inference features or proof of maliciousness. |
| `dns.txt.gz` | 185,104,948 | Headerless gzip CSV: `time`, `source_computer`, `resolved_computer` | 10,000 sample rows previously checked; no label field. | DNS relationships/anomaly research; not a supervised dataset. |
| `flows.txt.gz` | 1,083,479,100 | Headerless gzip CSV: `time`, `duration`, `source_computer`, `source_port`, `destination_computer`, `destination_port`, `protocol`, `packet_count`, `byte_count` | 10,000 sample rows previously checked; no label field. | LANL network behavior; separate schema from CICIDS features. |
| `proc.txt.gz` | 2,358,611,883 | Headerless gzip CSV: `time`, `user_domain`, `computer`, `process_name`, `start_end` | First two records matched the schema; complete row count not measured. | Host/process telemetry. The schema-specific chunk loader is implemented; no trained detector is claimed. |
| `redteam.txt.gz` | 4,858 | Headerless gzip CSV: `time`, `user_domain`, `source_computer`, `destination_computer` | 749 annotation rows; these are not benign/attack training pairs. | Supporting ground-truth annotations for a time-aware join, not an inference feature. |
| `Normal &Malicious SQLi.csv` | 14,964,657 | CSV with `Query`, `Type Attack`, and 26 numeric engineered features | 64,172 rows: 38,307 Malicious and 25,865 Normal; no missing/non-numeric model features in the prior full inspection. | SQL injection; inference uses the exact 26-feature schema. Raw-query feature generation is not verified. |
| `simulation_data.csv` | 169,136 | CICIDS-format CSV, 79 columns | 500 rows; 404 BENIGN, 96 attack rows; 4 duplicate rows; no missing cells. | Small simulation/sample data with unverified provenance; not used to claim model performance. |
| `train_sample.csv` | 73,682,719 | CICIDS-format CSV, 79 columns; model loader selects the existing model's ordered 17 features | 200,000 rows: 71,973 BENIGN and 128,027 DDoS; 1,913 duplicate rows and 3 missing `Flow Bytes/s` values. | Network sample only, not the full CICIDS2017 corpus; underlying official-source provenance remains unverified. |
| `OneDrive_2026-11-13.zip` | 20,875,224,279 | Split/spanned or incomplete archive; standard .NET ZIP open failed. | Prior member-level audit recorded 20 processed CSV entries with matching size/CRC metadata; this does not establish archive completeness. | Contains the available ToN-IoT subset described below. Do not extract the archive to Downloads or assume missing members are present. |

## LANL schema and annotation notes

The positional schemas match the official LANL format descriptions and the
downloaded sample rows. `?` and blank values are normalized as missing. The
authentication `Success`/`Failure` field describes authentication outcome; it
is not an intrusion label. DNS and flows have no attack label. Red-team
annotations are not converted into fabricated negative examples.

The implemented auth-to-redteam association requires equality of
`source_user_domain`, `source_computer`, and `destination_computer` with the
red-team `user_domain`, `source_computer`, and `destination_computer`, plus an
absolute timestamp difference no greater than the configured window (default
300 seconds). It reports associated rows and unmatched annotations. This is
weak event attribution, not proof that each matching auth event is malicious.
Annotation data is not used as a model input.

`process-auth` streamed the complete gzip file, validated nine-field records,
and completed with **1,051,430,459 rows and zero malformed rows**. Reading to
EOF validated the gzip trailer. The observed authentication outcomes were
1,038,590,151 `Success` and 12,840,308 `Fail` (failure ratio 0.012212). The
300-second exact-key association matched 735 of 749 red-team annotations and
associated 740 auth rows. This is aggregation/weak event attribution, not an
identity detector or proof of maliciousness.

The first attempt encountered a transient Windows permission error replacing
its checkpoint and was resumed successfully. The legacy checkpoint lacked a
red-team fingerprint; it was linked to the configured Downloads red-team file
after verifying its path, 749 rows, and time window, but the prior run's
content fingerprint was unavailable. The error log retains the recovered
checkpoint-write error. Gzip is not seekable for efficient restart, so resume
re-reads and skips records up to the last checkpoint; it does not duplicate
aggregate counts. Only compact summary/checkpoint files are written; the raw
dataset is not decompressed to disk. Parquet output is not enabled because no
Parquet engine is installed.

## ToN-IoT entries inside the archive

The prior member audit recorded size/CRC checks and row/label totals for these
20 entries. Use each source file's own schema; do not concatenate unlike
schemas. Per-file binary labels, attack-type counts, column names, sizes, and
CRC details are in the manifest.

| Archive member | Rows | Schema ID | Domain |
|---|---:|---|---|
| `Network_dataset_1.csv` | 1,000,000 | `ton_network` | Network |
| `Network_dataset_10.csv` | 1,000,000 | `ton_network` | Network |
| `Network_dataset_11.csv` | 1,000,000 | `ton_network` | Network |
| `Network_dataset_12.csv` | 1,000,000 | `ton_network` | Network |
| `Network_dataset_13.csv` | 1,000,000 | `ton_network` | Network |
| `Network_dataset_14.csv` | 1,000,000 | `ton_network` | Network |
| `Network_dataset_15.csv` | 1,000,000 | `ton_network` | Network |
| `IoT_Fridge.csv` | 587,076 | `ton_iot_fridge` | IoT |
| `IoT_Garage_Door.csv` | 591,446 | `ton_iot_garage_door` | IoT |
| `IoT_GPS_Tracker.csv` | 595,686 | `ton_iot_gps` | IoT |
| `IoT_Modbus.csv` | 287,194 | `ton_iot_modbus` | IoT |
| `IoT_Motion_Light.csv` | 452,262 | `ton_iot_motion_light` | IoT |
| `IoT_Thermostat.csv` | 442,228 | `ton_iot_thermostat` | IoT |
| `IoT_Weather.csv` | 650,242 | `ton_iot_weather` | IoT |
| `linux_disk_1.csv` | 1,000,000 | `ton_linux_disk` | Host/Linux |
| `linux_disk_2.csv` | 927,361 | `ton_linux_disk` | Host/Linux |
| `linux_memory1.csv` | 1,000,000 | `ton_linux_memory` | Host/Linux |
| `linux_memory2.csv` | 1,000,000 | `ton_linux_memory` | Host/Linux |
| `Linux_process_1.csv` | 1,000,000 | `ton_linux_process` | Host/Linux |
| `Linux_process_2.csv` | 927,968 | `ton_linux_process` | Host/Linux |

The available archive listing did not include processed Windows telemetry; it
included feature-description files and error-marker entries for missing
network members. The 20 recorded CSV members are a usable but incomplete
subset, not the complete ToN-IoT corpus.

## Configuration and reproducibility

Dataset root defaults to the current user's `Downloads` directory. Override it
with `MULTI_DOMAIN_IDS_DATASET_ROOT`, or set dataset-specific
`MULTI_DOMAIN_IDS_<NAME>_PATH` variables. Generated outputs default to the
repository's ignored `artifacts` directory and can be redirected with
`MULTI_DOMAIN_IDS_OUTPUT_DIR`. See [`.env.example`](../.env.example). The
manifest keeps the actual absolute paths used during this inventory.

Run `python -m multi_domain_ids.cli dataset-inventory` to list dataset-like
files recursively under the configured root without opening or modifying
them.

No datasets were found or assumed in repository `data/` or `datasets/`
directories. The full CICIDS2017 corpus, processed ToN-IoT Windows logs, and
Windows Security/Sysmon exports were not established by this Downloads scan.
