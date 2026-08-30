"""AbuseIPDB API v2 provider."""

import os

import requests

from .base import BaseThreatIntelligenceProvider


class AbuseIPDBProvider(BaseThreatIntelligenceProvider):
    name = "abuseipdb"
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key=None, enabled=None, **kwargs):
        key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        super().__init__(key, _enabled("ABUSEIPDB_ENABLED", enabled, bool(key)), **kwargs)

    def _lookup(self, ip):
        if not self.api_key:
            return self.unavailable(ip, "missing_api_key")
        response = requests.get(self.endpoint, headers={"Key": self.api_key, "Accept": "application/json"}, params={"ipAddress": ip}, timeout=self.timeout)
        response.raise_for_status()
        data = response.json().get("data")
        if not isinstance(data, dict):
            return self.unavailable(ip, "malformed_response")
        return {"provider": self.name, "ip": ip, "available": True,
                "abuse_confidence_score": data.get("abuseConfidenceScore"), "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"), "isp": data.get("isp"), "domain": data.get("domain"),
                "usage_type": data.get("usageType"), "last_reported_at": data.get("lastReportedAt")}


def _enabled(name, value, default):
    if value is not None:
        return value
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


AbuseIPDB = AbuseIPDBProvider