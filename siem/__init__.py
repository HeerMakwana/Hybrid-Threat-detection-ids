"""SIEM integration for the Hybrid Threat Detection IDS."""

from .event_schema import create_security_event
from .wazuh_adapter import WazuhJsonlAdapter
from .wazuh_forwarder import WazuhForwarder, WazuhForwardingError

__all__ = [
    "WazuhJsonlAdapter",
    "WazuhForwarder",
    "WazuhForwardingError",
    "create_security_event",
]