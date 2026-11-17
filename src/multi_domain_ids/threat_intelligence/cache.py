"""Small in-memory cache shared by all threat intelligence providers."""

import time
import os
from copy import deepcopy


class ThreatIntelligenceCache:
    def __init__(self, ttl_seconds=300, clock=None):
        self.ttl_seconds = max(0, float(ttl_seconds))
        self._clock = clock or time.monotonic
        self._entries = {}

    def get(self, provider, ip):
        key = f"{provider}:{ip}"
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() - entry[0] >= self.ttl_seconds:
            self._entries.pop(key, None)
            return None
        return deepcopy(entry[1])

    def set(self, provider, ip, result):
        self._entries[f"{provider}:{ip}"] = (self._clock(), deepcopy(result))

    def clear(self):
        self._entries.clear()


def cache_from_environment():
    """Create the shared cache using THREAT_INTEL_CACHE_TTL_SECONDS."""
    return ThreatIntelligenceCache(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "300"))