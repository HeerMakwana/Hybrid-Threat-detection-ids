import pytest
import requests

from simulation import extract_network_metadata
from threat_intelligence.abuseipdb import AbuseIPDBProvider
from threat_intelligence.base import BaseThreatIntelligenceProvider, ThreatIntelligenceService
from threat_intelligence.cache import ThreatIntelligenceCache
from threat_intelligence.opencti import OpenCTIProvider
from threat_intelligence.otx import OTXProvider
from threat_intelligence.virustotal import VirusTotalProvider


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.HTTPError(response=self)
            raise error

    def json(self):
        return self.payload


def test_metadata_aliases_and_missing_values():
    import pandas as pd
    row = pd.Series({"Source IP": "192.0.2.1", "Dst Port": 443, "Protocol": "TCP"})
    assert extract_network_metadata(row) == {
        "source_ip": "192.0.2.1", "destination_ip": None, "source_port": None,
        "destination_port": 443, "protocol": "TCP",
    }


def test_invalid_ip_is_unavailable():
    result = AbuseIPDBProvider(api_key="key", enabled=True).lookup("not-an-ip")
    assert result == {"provider": "abuseipdb", "ip": "not-an-ip", "available": False, "error": "invalid_ip"}


def test_abuseipdb_success_and_normalization(monkeypatch):
    calls = []
    monkeypatch.setattr("threat_intelligence.abuseipdb.requests.get", lambda *args, **kwargs: (calls.append(args) or FakeResponse({"data": {
        "abuseConfidenceScore": 94, "totalReports": 12, "countryCode": "US", "isp": "Example ISP",
        "domain": "example.test", "usageType": "Data Center", "lastReportedAt": "2026-01-01T00:00:00Z"}})))
    result = AbuseIPDBProvider(api_key="key", enabled=True).lookup("192.0.2.1")
    assert result["abuse_confidence_score"] == 94
    assert result["available"] is True
    assert calls


@pytest.mark.parametrize("status", [429, 500])
def test_abuseipdb_http_failures(monkeypatch, status):
    monkeypatch.setattr("threat_intelligence.abuseipdb.requests.get", lambda *args, **kwargs: FakeResponse({}, status))
    result = AbuseIPDBProvider(api_key="key", enabled=True).lookup("192.0.2.1")
    assert result["available"] is False
    assert result["error"] == f"http_{status}"


def test_abuseipdb_missing_key_and_timeout(monkeypatch):
    assert AbuseIPDBProvider(enabled=True).lookup("192.0.2.1")["error"] == "missing_api_key"
    def timeout(*args, **kwargs):
        raise requests.Timeout()
    monkeypatch.setattr("threat_intelligence.abuseipdb.requests.get", timeout)
    assert AbuseIPDBProvider(api_key="key", enabled=True).lookup("192.0.2.1")["available"] is False


def test_virustotal_success_and_failure(monkeypatch):
    monkeypatch.setattr("threat_intelligence.virustotal.requests.get", lambda *args, **kwargs: FakeResponse({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 4},
        "reputation": -10, "country": "US", "asn": 64500, "as_owner": "Example", "network": "192.0.2.0/24"}}}))
    result = VirusTotalProvider(api_key="key", enabled=True).lookup("192.0.2.1")
    assert result["malicious_count"] == 2
    monkeypatch.setattr("threat_intelligence.virustotal.requests.get", lambda *args, **kwargs: FakeResponse({}, 503))
    assert VirusTotalProvider(api_key="key", enabled=True).lookup("192.0.2.1")["error"] == "http_503"


def test_otx_success_and_failure(monkeypatch):
    monkeypatch.setattr("threat_intelligence.otx.requests.get", lambda *args, **kwargs: FakeResponse({"pulse_info": {"count": 3}, "reputation": 1, "related": ["botnet"]}))
    assert OTXProvider(api_key="key", enabled=True).lookup("192.0.2.1")["pulse_count"] == 3
    monkeypatch.setattr("threat_intelligence.otx.requests.get", lambda *args, **kwargs: FakeResponse({}, 500))
    assert OTXProvider(api_key="key", enabled=True).lookup("192.0.2.1")["available"] is False


def test_opencti_disabled_and_mocked_success(monkeypatch):
    disabled = OpenCTIProvider(url="http://cti", api_key="key", enabled=False)
    assert disabled.lookup("192.0.2.1")["error"] == "disabled"
    monkeypatch.setattr("threat_intelligence.opencti.requests.post", lambda *args, **kwargs: FakeResponse({"data": {"indicators": {"edges": [{"node": {"id": "indicator-1"}}]}}}))
    result = OpenCTIProvider(url="http://cti", api_key="key", enabled=True).lookup("192.0.2.1")
    assert result["indicators"][0]["id"] == "indicator-1"


def test_cache_hit_and_expiration():
    now = [0]
    cache = ThreatIntelligenceCache(ttl_seconds=10, clock=lambda: now[0])
    provider = AbuseIPDBProvider(api_key=None, enabled=True, cache=cache)
    provider._lookup = lambda ip: {"provider": "abuseipdb", "ip": ip, "available": True, "calls": 1}
    assert provider.lookup("192.0.2.1")["calls"] == 1
    provider._lookup = lambda ip: {"provider": "abuseipdb", "ip": ip, "available": True, "calls": 2}
    assert provider.lookup("192.0.2.1")["calls"] == 1
    now[0] = 11
    assert provider.lookup("192.0.2.1")["calls"] == 2


class FailingProvider(BaseThreatIntelligenceProvider):
    name = "failing"
    def _lookup(self, ip):
        raise RuntimeError("offline")


class WorkingProvider(BaseThreatIntelligenceProvider):
    name = "working"
    def _lookup(self, ip):
        return {"provider": self.name, "ip": ip, "available": True, "value": "ok"}


def test_provider_failure_isolation_and_disabled_service():
    service = ThreatIntelligenceService([FailingProvider(), WorkingProvider()])
    results = service.lookup("192.0.2.1")
    assert results["failing"]["available"] is False
    assert results["working"]["value"] == "ok"
    disabled = ThreatIntelligenceService([WorkingProvider()], enabled=False).lookup("192.0.2.1")
    assert disabled["working"]["error"] == "disabled"