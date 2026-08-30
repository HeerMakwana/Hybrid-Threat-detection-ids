"""Common provider contract and failure-isolated orchestration."""

import ipaddress
import os

class BaseThreatIntelligenceProvider:
    name = "provider"

    def __init__(self, api_key=None, enabled=True, timeout=10, cache=None):
        self.api_key = api_key
        self.enabled = bool(enabled)
        self.timeout = timeout
        self.cache = cache

    def lookup(self, ip):
        try:
            ipaddress.ip_address(str(ip))
        except ValueError:
            return self.unavailable(ip, "invalid_ip")
        if not self.enabled:
            return self.unavailable(ip, "disabled")
        cached = self.cache.get(self.name, str(ip)) if self.cache else None
        if cached is not None:
            return cached
        try:
            result = self._lookup(str(ip))
            if self.cache:
                self.cache.set(self.name, str(ip), result)
            return result
        except Exception as exc:
            return self.unavailable(ip, self.error_code(exc))

    def _lookup(self, ip):
        raise NotImplementedError

    @staticmethod
    def error_code(error):
        response = getattr(error, "response", None)
        if response is not None and getattr(response, "status_code", None):
            return f"http_{response.status_code}"
        return error.__class__.__name__.lower()

    def unavailable(self, ip, error=None):
        result = {"provider": self.name, "ip": str(ip) if ip is not None else None, "available": False}
        if error:
            result["error"] = error
        return result


class ThreatIntelligenceService:
    def __init__(self, providers, enabled=True):
        self.providers = list(providers)
        self.enabled = bool(enabled)

    def lookup(self, ip):
        if not self.enabled:
            return {provider.name: provider.unavailable(ip, "disabled") for provider in self.providers}
        results = {}
        for provider in self.providers:
            try:
                results[provider.name] = provider.lookup(ip)
            except Exception as exc:
                results[provider.name] = provider.unavailable(ip, provider.error_code(exc))
        return results

    enrich = lookup

    @classmethod
    def from_environment(cls, providers, cache=None):
        for provider in providers:
            provider.cache = cache
        return cls(providers, enabled=_env_bool("THREAT_INTEL_ENABLED", False))


def _env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}