# Beginner deployment guide

This project writes newline-delimited JSON alerts for a Wazuh agent to collect. It does not include a web dashboard, install Wazuh, or perform automatic containment.

## 1. Install the project

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

The legacy network model is stored at `models/final_model.joblib`. Keep that model and all trained model files out of source control.

## 2. Train the SQL injection model on the real dataset

Only the combined SQLi file is currently suitable for direct supervised training. Run:

```powershell
python -m multi_domain_ids.cli train-sqli `
  --dataset "C:\Users\ISHITA DUBEY\Downloads\Normal &Malicious SQLi.csv" `
  --model-out "models\sqli_model_candidate.joblib"
```

The command reports measured holdout metrics and saves a local artifact. The split groups identical feature vectors so they cannot appear in both train and test partitions. Feature vectors with contradictory labels are excluded from both partitions and counted in the report. The resulting model accepts the dataset's 26 numeric feature columns; raw-query extraction is not enabled because the source of several feature definitions could not be verified. Do not feed the model guessed features.
Existing artifact paths are protected by default. Use `--overwrite` only when intentionally replacing an artifact; the old file is preserved as a `.bak` copy.

The CICIDS file located so far is a 200,000-row sample, not the full corpus; it has missing values and its original download provenance is unverified. The ToN-IoT bundle is structurally incomplete despite integrity checks on its 20 processed CSV members. LANL flows/DNS have no labels. The full `auth.txt.gz` is present and has a streaming processor, but it is not treated as processed until a full run completes. `proc.txt.gz` is present and its schema-specific loader is implemented; no production host model is claimed. See [the dataset inventory](DATASET_INVENTORY.md).

## 3. Process the full LANL authentication file

The input remains at its Downloads path. This command streams it in bounded
chunks, validates the nine-field schema, uses red-team records only for
time-bounded association, and writes compact aggregate/checkpoint files to the
ignored project `artifacts` directory:

```powershell
python -m multi_domain_ids.cli process-auth `
  --dataset "C:\Users\ISHITA DUBEY\Downloads\auth.txt.gz" `
  --redteam "C:\Users\ISHITA DUBEY\Downloads\redteam.txt.gz" `
  --output-dir "D:\projects\Multi-Domain-Hybrid-IDS\artifacts" `
  --chunksize 100000
```

The run reads the full compressed stream and may take substantial time. It
does not decompress the source to another file or write one output row per
authentication event. Progress is printed per million processed records.
`artifacts\identity\auth_processing_checkpoint.json` is updated as chunks
complete; rerunning the same command resumes from that checkpoint. Gzip is
not seekable, so restart replays and skips the checkpointed input records.
Review `auth_processing_summary.json` and `auth_processing_errors.jsonl` for
the completion state, counts, elapsed time, malformed rows, and annotation
join results. A complete run also validates the gzip trailer.

Set `MULTI_DOMAIN_IDS_DATASET_ROOT`, individual
`MULTI_DOMAIN_IDS_<NAME>_PATH` overrides, or `MULTI_DOMAIN_IDS_OUTPUT_DIR` to
relocate datasets and generated outputs. See [`.env.example`](../.env.example);
the example file is a template and is not automatically loaded by Python.

## 4. Configure threat-intelligence providers (optional)

Set credentials in the IDS process environment, not in source files or Wazuh XML:

```powershell
$env:THREAT_INTEL_ENABLED = "true"
$env:ABUSEIPDB_API_KEY = "<your key>"
$env:VIRUSTOTAL_API_KEY = "<your key>"
$env:OTX_API_KEY = "<your key>"
$env:OPENCTI_URL = "https://your-opencti.example"
$env:OPENCTI_API_KEY = "<your key>"
$env:OPENCTI_ENABLED = "true"
```

Only configure providers you are authorized to use. The provider integrations have independent failure handling and share a TTL cache. The application does not print API keys. Provider reputation and the legacy threat score are supplemental; the standardized alert severity is based on corroborating evidence, not model confidence alone.

## 5. Run inference and write alerts

Application code can create the JSONL sink, provider service, processor, and inference service:

```python
from multi_domain_ids import AlertProcessor, JsonlAlertSink, MultiDomainDetectionService
from multi_domain_ids.sqli_model import load_sqli_model
from multi_domain_ids.threat_intelligence import build_threat_intelligence_service

processor = AlertProcessor(
    JsonlAlertSink(r"C:\ProgramData\MultiDomainIDS\ids_alerts.jsonl"),
    threat_intelligence=build_threat_intelligence_service(),
)
ids = MultiDomainDetectionService(
    processor,
    sqli=load_sqli_model("models/sqli_model.joblib"),
)
```

Call `detect_network(event, network_features)` with the legacy model's ordered 17 features. Call `detect_sqli_features(event, features)` with the exact 26-column SQLi dataset feature schema. For SQLi, a raw query alone is not enough to reproduce the unverified feature definitions. The host, identity, and DNS demo models are not production detectors; the auth file processor is not an inference model.

The processor appends one JSON object per line. A second JSONL record is emitted when cross-domain correlation finds suspicious events sharing an entity within the configured time window. Wazuh delivery is asynchronous through its agent; successful file writing is not proof of manager ingestion.

## 6. Wazuh deployment for this Windows environment

The intended architecture is one Wazuh all-in-one Linux host (Wazuh server, indexer, and dashboard) plus the Windows Wazuh agent on this development computer. The agent reads the IDS JSONL file locally and forwards events to the manager. The Wazuh Dashboard is the only security interface; this project does not provide another dashboard.

Environment inspection on 2026-11-14 found:

- VirtualBox is installed. It has a registered VM named `Ubuntu`, but it is saved/stopped, runs Ubuntu 24.10, and has a NAT adapter only. This inspection did not resume or modify it, so whether Wazuh is installed inside it is unknown.
- No Wazuh Windows service, process, installation path, configured manager address, or local Wazuh listener was found.
- WSL is not installed and the Docker command is unavailable. No remote manager address was configured in this repository or Windows environment.
- The repository has no separate Wazuh integration script; forwarding is intended to be the `JsonlAlertSink` writing the file watched by the agent.
- Consequently there is no currently reachable manager whose version or decoder/rule behavior can be checked. The stopped Ubuntu VM is not evidence that a Wazuh manager is installed.

Do not install the manager into the existing Ubuntu 24.10 VM based on this guide: Wazuh's current quickstart lists Ubuntu 24.04, not 24.10. Use a new Ubuntu Server 24.04 LTS VM (or an existing supported Linux server) and leave the saved VM untouched. The official quickstart recommendation for a small deployment is 4 vCPU, 8 GiB RAM, and 50 GB storage.

### Install the central Wazuh components

For a local VirtualBox deployment, create an Ubuntu Server 24.04 LTS VM with at least the quickstart resources above. Configure one NAT adapter for package downloads and a second host-only adapter for Windows-to-VM communication. This keeps the manager/dashboard reachable from the Windows host without exposing them to the LAN. Use VirtualBox's Host-only Network settings to create/assign that second adapter. Do not copy an example or guessed IP into the agent configuration.

On the new Linux VM, follow the [official Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) and install the all-in-one stack:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The current official quickstart uses the Wazuh 4.14 installer. Save the generated credentials securely; do not place them in this repository or paste them into alerts. Find the VM's host-only IPv4 address with `ip -br -4 addr` and use the address on the host-only interface. The Windows host must be able to reach it on TCP 1514 (agent events), TCP 1515 (agent enrollment), and TCP 443 (dashboard). If a firewall is enabled, allow only the Windows host's host-only address to those ports.

Record and verify the installed component versions on the Linux VM before using version-specific rules:

```bash
sudo /var/ossec/bin/wazuh-control info
dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard
```

The Wazuh version is currently **unknown** because there is no running, reachable installation to query.

### Install the Windows agent and watch the JSONL file

Use the Wazuh agent release matching the installed manager's release. The following MSI URL is the 4.14.10 Windows agent shown in the current Wazuh Windows-agent instructions; only use it if the manager is on the compatible 4.14 release. Replace the placeholder with the host-only address discovered above:

```powershell
$manager = "<MANAGER_HOST_ONLY_IP>"
$msi = Join-Path $env:TEMP "wazuh-agent-4.14.10-1.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.10-1.msi" -OutFile $msi
msiexec.exe /i $msi /q "WAZUH_MANAGER=$manager"
Start-Service WazuhSvc
```

In `C:\Program Files (x86)\ossec-agent\ossec.conf`, merge the block from `wazuh\agent\multi_domain_ids.conf` inside the existing `<ossec_config>` root. Do not replace the agent's existing configuration. The configured location must be exactly the path passed to `JsonlAlertSink`, and both the Python process and Wazuh agent service must be able to access it. The example path is `C:\ProgramData\MultiDomainIDS\ids_alerts.jsonl`.

Restart the agent after the merge:

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

### Install and validate custom decoders and rules

Copy the project's `wazuh\decoders\multi_domain_ids_decoder.xml` and `wazuh\rules\multi_domain_ids_rules.xml` into the Wazuh manager's custom directories as separate files:

- `/var/ossec/etc/decoders/multi_domain_ids_decoder.xml`
- `/var/ossec/etc/rules/multi_domain_ids_rules.xml`

Do not replace `local_rules.xml`, any built-in decoder, or any default rule file. After copying, run `/var/ossec/bin/wazuh-logtest` on the manager (or **Tools > Ruleset Test** in the Wazuh Dashboard), paste one single-line alert JSON record, and inspect both the decoded fields and matching rule in the output. Only then restart the manager and check its status. The log test is the required check for the installed version; XML parsing alone cannot validate Wazuh syntax or extraction.

Important compatibility issue still to resolve: the IDS record contains arrays of objects, including `evidence` and `mitre_attack`, and nested threat-intelligence data. Wazuh's JSON decoder documentation says arrays of objects are not supported. Scalar top-level fields may still decode, but do not assume that the full evidence/ATT&CK/TI content is searchable. The current custom rules and decoder have not been tested with a Wazuh manager. Before relying on the integration, test the actual JSONL record with `wazuh-logtest`; if those fields are missing, add a Wazuh-safe flattened representation while preserving the original IDS alert, then retest against the installed version.

## 7. Find and interpret IDS alerts in Wazuh

Once an agent is connected and manager processing is verified:

1. Sign in to the **Wazuh Dashboard** at `https://<MANAGER_HOST_ONLY_IP>`. In the navigation, open **Threat Intelligence > Threat Hunting** and set a time range that includes the event. The menu names can differ slightly by Wazuh release.
2. Select an IDS result and open its event details/raw JSON. The `rule` object is generated by Wazuh; decoded IDS fields are dynamic fields from the JSON event. In raw alert JSON, these are normally shown under `data`, while `wazuh-logtest` shows the decoded field names directly. Confirm the exact paths in this manager before saving searches or dashboards.
3. Use the event details to check the Wazuh `rule.id`, `rule.description`, and `rule.level`, then inspect the IDS fields below. The IDS `severity` label (`low`, `medium`, `high`, or `critical`) is not the same scale as Wazuh's numeric `rule.level`. The current rules use levels 3, 10, 12, and 7 for the generic, high, critical, and correlated cases, respectively.

| IDS field | What it means |
| --- | --- |
| `event_id`, `timestamp`, `timestamp_source` | Event identity and event time; `timestamp_source=ingestion_time` means the input had no timestamp. |
| `detection_domain`, `detection_source`, `event_category` | Which detector/domain produced the alert and what kind of event it represents. |
| `attack_name`, `model_name`, `model_prediction` | Detector's attack label, model/rule name, and suspicious/benign result. A suspicious result is an investigation lead, not proof of compromise. |
| `severity`, `severity_reason` | Evidence-based IDS severity and the reason for that level. Confidence alone does not increase severity. |
| `confidence_score` | Model score from 0 to 1, or null when no score exists. It is not necessarily calibrated and is not a probability that compromise occurred. |
| `evidence` | Signal descriptions supporting the detection. The current evidence entries are objects; Wazuh's decoder may not extract this array until a compatible flattened field is provided and verified. |
| `explanation` | Human-readable title, what happened, why detected, potential impact, severity rationale, investigation steps, and response guidance. |
| `recommended_action` | Suggested manual follow-up. No action is automatically executed. |
| `source_ip`, `destination_ip`, ports, protocol, hostname, device/user, URL/hash fields | Optional context copied from the input event. Missing values are intentionally omitted. |
| `threat_intelligence` | Optional provider status, reputation, assessment, and IOC matches; it is supplemental evidence and may be unconfigured. Nested object arrays need the same decoder compatibility check. |
| `mitre_attack` | ATT&CK mapping only when the event supplies supporting evidence. The list contains objects and may not decode in the current JSONL shape. |
| `correlation_id`, `related_event_ids`, `timeline`, `correlated_domains` | For a generated correlated-incident record, links related detections sharing an entity within the correlation window. The timeline is not a separate detection model. |

Interpret the common detections as follows:

- **Network intrusion** (for example `port_scan`): inspect source/destination addresses, ports, protocol, event evidence, and nearby network telemetry. Confirm the observed scope before changing network controls.
- **SQL injection** (`sql_injection`): review the application endpoint, event reference, evidence, and application/database logs. The model requires the verified feature vector; a raw SQL string alone is not sufficient input for the trained model.
- **Brute-force authentication** (`brute_force_login`): review the affected username, source address, failure history, and whether a legitimate user or automation explains the attempts. Identity-domain inference is not represented as a production-trained model in this project.
- **Suspicious process activity** (`suspicious_process_execution`): inspect the host, source event, process-tree/command-line telemetry, signer, and file provenance in the endpoint's source logs. The normalized alert only includes optional fields explicitly listed by the alert contract; do not assume a process name or command line is present unless the raw alert shows it. Host/process inference is not represented as a production-trained model in this project.
- **Correlated incident** (`multi_stage_incident`): use `related_event_ids`, `timeline`, and `correlated_domains` to review the individual detections in order. It means suspicious alerts shared an entity within the configured time window; it does not independently confirm an intrusion.

Search only on field paths that `wazuh-logtest` confirms were extracted. For example, after confirming the actual indexed field name, filter by the attack label (`data.attack_name`) or domain (`data.detection_domain`) in Threat Hunting. Do not treat these sample paths as verified for this manager until they appear in its decoded output and alert JSON.

The manager's JSON alert log is `/var/ossec/logs/alerts/alerts.json`. Confirm an event there and in the Dashboard before calling delivery successful. A Python JSONL write, a successful local XML parse, or a ruleset-test match is not by itself proof of agent-to-manager delivery or dashboard visibility.

## 8. Validate local configuration

```powershell
python tools\validate_wazuh_config.py
python -m pytest
```

The XML validator checks well-formedness and required elements only. It does not validate manager syntax, field extraction, rule matching, indexing, or delivery. Those require a reachable Wazuh deployment and the checks above.
