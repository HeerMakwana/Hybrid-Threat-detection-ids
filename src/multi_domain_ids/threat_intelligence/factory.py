"""Environment-driven construction of the preserved provider integrations."""

import os

from .abuseipdb import AbuseIPDBProvider
from .base import ThreatIntelligenceService
from .cache import cache_from_environment
from .opencti import OpenCTIProvider
from .otx import OTXProvider
from .virustotal import VirusTotalProvider


def build_threat_intelligence_service() -> ThreatIntelligenceService:
    timeout = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "10"))
    providers = [
        AbuseIPDBProvider(timeout=timeout),
        VirusTotalProvider(timeout=timeout),
        OTXProvider(timeout=timeout),
        OpenCTIProvider(timeout=timeout),
    ]
    return ThreatIntelligenceService.from_environment(
        providers,
        cache=cache_from_environment(),
    )
