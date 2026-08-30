"""VirusTotal v3 IP address provider."""

import os

import requests

from .base import BaseThreatIntelligenceProvider


class VirusTotalProvider(BaseThreatIntelligenceProvider):
    name = "virustotal"
    endpoint = "https://www.virustotal.com/api/v3/ip_addresses/{}"

    def __init__(self, api_key=None, enabled=None, **kwargs):
        key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        super().__init__(key, _enabled("VIRUSTOTAL_ENABLED", enabled, bool(key)), **kwargs)

    def _lookup(self, ip):
        if not self.api_key:
            return self.unavailable(ip, "missing_api_key")
        response = requests.get(self.endpoint.format(ip), headers={"x-apikey": self.api_key}, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        if not isinstance(attributes, dict):
            return self.unavailable(ip, "malformed_response")
        stats = attributes.get("last_analysis_stats", {})
        return {"provider": self.name, "ip": ip, "available": True,
                "malicious_count": stats.get("malicious", 0), "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0), "undetected_count": stats.get("undetected", 0),
                "reputation_score": attributes.get("reputation"), "country": attributes.get("country"),
                "asn": attributes.get("asn"), "as_owner": attributes.get("as_owner"), "network": attributes.get("network")}


def _enabled(name, value, default):
    if value is not None:
        return value
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


VirusTotal = VirusTotalProvider