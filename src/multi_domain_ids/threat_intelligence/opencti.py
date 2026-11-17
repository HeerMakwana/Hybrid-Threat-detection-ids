"""Configurable OpenCTI GraphQL provider; disabled unless explicitly enabled."""

import os

import requests

from .base import BaseThreatIntelligenceProvider


class OpenCTIProvider(BaseThreatIntelligenceProvider):
    name = "opencti"

    def __init__(self, url=None, api_key=None, enabled=None, **kwargs):
        self.url = (url or os.getenv("OPENCTI_URL", "")).rstrip("/")
        key = api_key or os.getenv("OPENCTI_API_KEY")
        default = bool(self.url and key) and os.getenv("OPENCTI_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
        super().__init__(key, default if enabled is None else enabled, **kwargs)

    def _lookup(self, ip):
        if not self.url or not self.api_key:
            return self.unavailable(ip, "missing_configuration")
        query = {"query": "query($value: String!) { indicators(filters: {key: value, values: [$value]}) { edges { node { id pattern created_at } } } }", "variables": {"value": ip}}
        response = requests.post(self.url + "/graphql", headers={"Authorization": f"Bearer {self.api_key}"}, json=query, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        indicators = data.get("data", {}).get("indicators", {}).get("edges", [])
        if not isinstance(indicators, list):
            return self.unavailable(ip, "malformed_response")
        return {"provider": self.name, "ip": ip, "available": True,
                "indicators": [edge.get("node", {}) for edge in indicators if isinstance(edge, dict)]}


OpenCTI = OpenCTIProvider