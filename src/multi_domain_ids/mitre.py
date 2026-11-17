from __future__ import annotations

from collections.abc import Mapping


def map_mitre_attack(
    attack_name: str,
    event: Mapping[str, object],
) -> list[dict[str, str]]:
    """Return ATT&CK techniques only when the event contains supporting evidence."""
    attack = attack_name.strip().lower().replace("-", "_").replace(" ", "_")
    if attack in {"port_scan", "portscan", "scanning"}:
        count = _number(event.get("distinct_destination_ports"))
        if count is not None and count >= 10:
            return [_technique("Discovery", "T1046", "Network Service Discovery")]
    elif attack in {"brute_force", "brute_force_login", "password_attack"}:
        failures = _number(event.get("failed_logins"))
        if failures is not None and failures >= 5:
            return [_technique("Credential Access", "T1110", "Brute Force")]
    elif attack in {"sql_injection", "sqli"}:
        if event.get("application_exposed") is True:
            return [_technique("Initial Access", "T1190", "Exploit Public-Facing Application")]
    elif attack in {"dns_tunneling", "dns_tunnel"}:
        if event.get("dns_tunneling_indicators") is True:
            return [_technique("Command and Control", "T1071.004", "DNS")]
    elif attack in {"ddos", "denial_of_service"}:
        if event.get("traffic_rate_exceeds_baseline") is True:
            return [_technique("Impact", "T1498", "Network Denial of Service")]
    elif attack in {"suspicious_process_execution", "command_execution"}:
        if event.get("interpreted_command_observed") is True:
            return [_technique("Execution", "T1059", "Command and Scripting Interpreter")]
    return []


def _number(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _technique(tactic: str, technique_id: str, name: str) -> dict[str, str]:
    return {
        "framework": "MITRE ATT&CK",
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": name,
    }
