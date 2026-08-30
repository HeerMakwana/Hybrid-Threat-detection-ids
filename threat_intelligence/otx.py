"""AlienVault OTX IP reputation provider."""

import os

import requests

from .base import BaseThreatIntelligenceProvider


class OTXProvider(BaseThreatIntelligenceProvider):
    name = "otx"
    endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"

    def __init__(self, api_key=None, enabled=None, **kwargs):
        key = api_key or os.getenv("OTX_API_KEY")
        super().__init__(key, _enabled("OTX_ENABLED", enabled, bool(key)), **kwargs)

    def _lookup(self, ip):
        if not self.api_key:
            return self.unavailable(ip, "missing_api_key")
        response = requests.get(self.endpoint.format(ip), headers={"X-OTX-API-KEY": self.api_key}, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return self.unavailable(ip, "malformed_response")
        pulse_info = data.get("pulse_info") or {}
        return {"provider": self.name, "ip": ip, "available": True,
                "pulse_count": pulse_info.get("count", 0), "reputation": data.get("reputation"),
                "related_threats": data.get("related", []), "relevant_indicators": data.get("indicator", []),
                "first_seen": data.get("first_seen"), "last_seen": data.get("last_seen")}


def _enabled(name, value, default):
    if value is not None:
        return value
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


AlienVaultOTXProvider = OTXProvider