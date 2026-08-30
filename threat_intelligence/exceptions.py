"""Exceptions used by threat intelligence providers."""


class ThreatIntelligenceError(Exception):
    """Base exception for provider and normalization failures."""


class ProviderConfigurationError(ThreatIntelligenceError):
    """Raised when a provider is not configured for live lookups."""


class ProviderResponseError(ThreatIntelligenceError):
    """Raised when a provider returns an unusable response."""