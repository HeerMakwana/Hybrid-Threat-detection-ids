# Wazuh deployment and validation

Wazuh is the intended and only user-facing security monitoring dashboard.
The IDS writes JSONL alerts to the configured path; the Wazuh agent tails that
file and forwards records to the manager. This repository does not install or
operate a manager.

## Local configuration

- Agent JSONL path: `C:\ProgramData\MultiDomainIDS\ids_alerts.jsonl`
- Agent example: `wazuh/agent/multi_domain_ids.conf`
- Decoder example: `wazuh/decoders/multi_domain_ids_decoder.xml`
- Rules example: `wazuh/rules/multi_domain_ids_rules.xml`
- Local structural validator: `python tools\validate_wazuh_config.py`

Merge the `<localfile>` block into the existing agent configuration; do not
replace the agent's whole `ossec.conf`. Ensure that the actual `JsonlAlertSink`
path matches the monitored location and is readable by the agent service.
Install custom decoders and rules as separate manager files, then use
`wazuh-logtest` against a real generated single-line alert before restarting
services.

## What has and has not been verified

The repository's XML parser checks well-formedness, unique custom rule IDs,
the JSON decoder declaration, and the agent's JSON `localfile` path. Unit
tests run these structural checks. This is not equivalent to Wazuh's own
configuration validation.

No end-to-end Wazuh delivery is claimed. The Windows `WazuhSvc` service was
observed running, but the installed `ossec.conf` could not be read with the
current permissions. No TCP connection on ports 1514/1515 or UDP endpoint
owned by the agent process was observed during the check. Therefore the
configured manager address, agent connection, manager-side decoder
extraction, custom rule match, indexed alert, and Dashboard visibility remain
unverified. `wazuh-logtest` and manager-side validation were not available as
evidence. Arrays of objects and nested threat-intelligence content may not be
searchable with Wazuh's JSON decoder; validate the scalar fields against the
installed Wazuh version.

## End-to-end acceptance procedure

1. Generate a clearly labeled controlled IDS test event and confirm one JSON
   object is appended to the configured JSONL path.
2. Run `wazuh-logtest` on the manager with that exact JSON line; confirm the
   expected scalar fields and custom rule ID.
3. Confirm the Windows agent is connected and that the manager receives the
   event.
4. Confirm the corresponding record appears in the manager alert output and
   the Wazuh Dashboard.
5. Record the Wazuh manager/agent versions and keep the raw test event and
   manager output as evidence without including credentials.

Do not treat XML well-formedness or a successful local JSONL write as proof of
delivery. If no supported manager is reachable, keep the deployment marked
blocked and provide the deployment commands for that environment rather than
claiming a verified integration.
