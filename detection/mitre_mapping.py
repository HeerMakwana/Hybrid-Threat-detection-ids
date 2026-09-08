"""Minimal MITRE ATT&CK mapping for common demo attack labels."""

MITRE_MAPPING = {
    "PortScan": {
        "tactic": "Discovery",
        "technique": "T1046",
        "name": "Network Service Scanning",
    },
    "DDoS": {
        "tactic": "Impact",
        "technique": "T1498",
        "name": "Network Denial of Service",
    },
    "DoS": {
        "tactic": "Impact",
        "technique": "T1498",
        "name": "Network Denial of Service",
    },
    "FTP-Patator": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "name": "Brute Force",
    },
    "SSH-Patator": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "name": "Brute Force",
    },
    "Brute Force": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "name": "Brute Force",
    },
}


def map_attack_to_mitre(attack_type):
    """Return a MITRE mapping for an attack label or a benign fallback."""

    if not attack_type:
        return {
            "tactic": None,
            "technique": None,
            "name": None,
        }

    normalized = str(attack_type).strip()
    if normalized.upper() in {"BENIGN", "NORMAL"}:
        return {
            "tactic": None,
            "technique": None,
            "name": None,
        }

    return dict(
        MITRE_MAPPING.get(
            normalized,
            {
                "tactic": "Discovery",
                "technique": "T1046",
                "name": normalized,
            },
        )
    )