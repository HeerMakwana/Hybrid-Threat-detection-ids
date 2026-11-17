"""Provider-neutral threat intelligence foundations for the IDS."""

from .base import BaseThreatIntelligenceProvider, ThreatIntelligenceService
from .cache import ThreatIntelligenceCache
from .assessment import IOCMatcher, aggregate_reputation, assess_threat, classify_severity, normalize_ioc
from .abuseipdb import AbuseIPDBProvider
from .opencti import OpenCTIProvider
from .otx import OTXProvider
from .virustotal import VirusTotalProvider
from .factory import build_threat_intelligence_service

__all__ = [
    "BaseThreatIntelligenceProvider",
    "ThreatIntelligenceService",
    "ThreatIntelligenceCache",
    "IOCMatcher",
    "aggregate_reputation",
    "assess_threat",
    "classify_severity",
    "normalize_ioc",
    "AbuseIPDBProvider",
    "OpenCTIProvider",
    "OTXProvider",
    "VirusTotalProvider",
    "build_threat_intelligence_service",
]