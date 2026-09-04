"""SIEM integration for the Hybrid Threat Detection IDS."""

from .wazuh_forwarder import WazuhForwarder, WazuhForwardingError

__all__ = [
    "WazuhForwarder",
    "WazuhForwardingError",
]