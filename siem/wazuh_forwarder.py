"""Wazuh SIEM integration for the Hybrid Threat Detection IDS."""

import json
import os
import socket
from typing import Any, Dict, Optional


class WazuhForwardingError(RuntimeError):
    """Raised when an IDS alert cannot be forwarded to Wazuh."""


class WazuhForwarder:
    """Forward enriched IDS alerts to a Wazuh manager using Syslog."""

    SEVERITY_MAP = {
        "CRITICAL": 2,
        "HIGH": 3,
        "MEDIUM": 4,
        "LOW": 6,
    }

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "tcp",
        timeout: float = 5.0,
    ):
        self.host = host
        self.port = int(port)
        self.protocol = protocol.lower()
        self.timeout = float(timeout)

        if self.protocol not in {"tcp", "udp"}:
            raise ValueError("Protocol must be either 'tcp' or 'udp'.")

    @classmethod
    def from_environment(cls) -> Optional["WazuhForwarder"]:
        """Create a Wazuh forwarder using environment variables."""

        enabled = os.getenv("WAZUH_ENABLED", "false").lower()

        if enabled not in {"true", "1", "yes", "on"}:
            return None

        host = os.getenv("WAZUH_HOST", "").strip()

        if not host:
            raise WazuhForwardingError(
                "WAZUH_ENABLED is enabled but WAZUH_HOST is not configured."
            )

        return cls(
            host=host,
            port=int(os.getenv("WAZUH_PORT", "514")),
            protocol=os.getenv("WAZUH_PROTOCOL", "tcp"),
            timeout=float(os.getenv("WAZUH_TIMEOUT", "5")),
        )

    @classmethod
    def build_payload(cls, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert the existing Hybrid IDS alert into a
        compact SIEM-friendly JSON payload.
        """

        threat = alert.get("threat_confidence", {})

        if not isinstance(threat, dict):
            threat = {}

        ioc_matches = alert.get("ioc_matches", [])

        if not isinstance(ioc_matches, list):
            ioc_matches = []

        return {
            "integration": "hybrid-ids",
            "event_type": "intrusion_detection",

            "alert_id": alert.get("alert_id"),
            "timestamp": alert.get("timestamp"),
            "record_index": alert.get("record_index"),

            "predicted_label": alert.get("predicted_label"),
            "confidence": alert.get("confidence"),
            "threshold": alert.get("threshold"),
            "model_type": alert.get("model_type"),

            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "source_port": alert.get("source_port"),
            "destination_port": alert.get("destination_port"),
            "protocol": alert.get("protocol"),

            "threat_score": threat.get("score"),
            "threat_severity": threat.get("severity"),
            "threat_factors": threat.get("factors", []),

            "ioc_match_count": len(ioc_matches),
        }

    @classmethod
    def _get_priority(cls, severity: str) -> int:
        """Return the Syslog PRI value for an alert severity."""

        severity_value = cls.SEVERITY_MAP.get(
            str(severity).upper(),
            6,
        )

        # Facility 16 = local0
        facility = 16

        return facility * 8 + severity_value

    def _format_message(self, alert: Dict[str, Any]) -> bytes:
        """Convert an IDS alert into a Syslog message."""

        payload = self.build_payload(alert)

        severity = payload.get(
            "threat_severity",
            "LOW",
        )

        priority = self._get_priority(severity)

        json_payload = json.dumps(
            payload,
            separators=(",", ":"),
        )

        message = f"<{priority}>hybrid-ids: {json_payload}\n"

        return message.encode("utf-8")

    def send_alert(self, alert: Dict[str, Any]) -> None:
        """Send one enriched IDS alert to Wazuh."""

        if not isinstance(alert, dict):
            raise WazuhForwardingError(
                "Alert must be a dictionary."
            )

        if not alert.get("alert_id"):
            raise WazuhForwardingError(
                "Alert is missing alert_id."
            )

        message = self._format_message(alert)

        try:
            if self.protocol == "tcp":
                self._send_tcp(message)
            else:
                self._send_udp(message)

        except (OSError, socket.timeout) as exc:
            raise WazuhForwardingError(
                f"Could not send alert to Wazuh "
                f"at {self.host}:{self.port}: {exc}"
            ) from exc

    def _send_tcp(self, message: bytes) -> None:
        """Send the message using TCP Syslog."""

        with socket.create_connection(
            (self.host, self.port),
            timeout=self.timeout,
        ) as connection:
            connection.sendall(message)

    def _send_udp(self, message: bytes) -> None:
        """Send the message using UDP Syslog."""

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as connection:
            connection.settimeout(self.timeout)
            connection.sendto(
                message,
                (self.host, self.port),
            )