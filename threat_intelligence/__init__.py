"""Provider-neutral threat intelligence foundations for the IDS."""

from .base import BaseThreatIntelligenceProvider, ThreatIntelligenceService
from .cache import ThreatIntelligenceCache
from .assessment import IOCMatcher, aggregate_reputation, assess_threat, classify_severity, normalize_ioc

__all__ = [
	"BaseThreatIntelligenceProvider", "ThreatIntelligenceService", "ThreatIntelligenceCache",
	"IOCMatcher", "aggregate_reputation", "assess_threat", "classify_severity", "normalize_ioc",
]