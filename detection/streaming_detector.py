"""Streaming detector that replays flow records through the trained IDS model."""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd

from detection.mitre_mapping import map_attack_to_mitre
from detection.risk_scoring import calculate_risk
from model_loader import load_model_artifact
from siem.event_schema import create_security_event
from threat_intelligence.abuseipdb import AbuseIPDBProvider
from threat_intelligence.assessment import IOCMatcher, aggregate_reputation, assess_threat
from threat_intelligence.base import ThreatIntelligenceService
from threat_intelligence.cache import cache_from_environment
from threat_intelligence.opencti import OpenCTIProvider
from threat_intelligence.otx import OTXProvider
from threat_intelligence.virustotal import VirusTotalProvider


DEMO_THREAT_INTEL = {
    "192.168.10.45": {
        "abuseipdb": {
            "provider": "abuseipdb",
            "ip": "192.168.10.45",
            "available": True,
            "abuse_confidence_score": 87,
        },
        "virustotal": {
            "provider": "virustotal",
            "ip": "192.168.10.45",
            "available": True,
            "malicious_count": 4,
            "suspicious_count": 1,
        },
        "otx": {
            "provider": "otx",
            "ip": "192.168.10.45",
            "available": True,
            "pulse_count": 3,
            "relevant_indicators": ["192.168.10.45"],
        },
        "opencti": {
            "provider": "opencti",
            "ip": "192.168.10.45",
            "available": True,
            "indicators": [{"value": "192.168.10.45", "type": "ip"}],
        },
    },
    "192.168.10.46": {
        "abuseipdb": {
            "provider": "abuseipdb",
            "ip": "192.168.10.46",
            "available": True,
            "abuse_confidence_score": 91,
        },
        "virustotal": {
            "provider": "virustotal",
            "ip": "192.168.10.46",
            "available": True,
            "malicious_count": 5,
            "suspicious_count": 0,
        },
        "otx": {
            "provider": "otx",
            "ip": "192.168.10.46",
            "available": True,
            "pulse_count": 4,
            "relevant_indicators": ["192.168.10.46"],
        },
        "opencti": {
            "provider": "opencti",
            "ip": "192.168.10.46",
            "available": True,
            "indicators": [{"value": "192.168.10.46", "type": "ip"}],
        },
    },
    "192.168.10.47": {
        "abuseipdb": {
            "provider": "abuseipdb",
            "ip": "192.168.10.47",
            "available": True,
            "abuse_confidence_score": 83,
        },
        "virustotal": {
            "provider": "virustotal",
            "ip": "192.168.10.47",
            "available": True,
            "malicious_count": 3,
            "suspicious_count": 1,
        },
        "otx": {
            "provider": "otx",
            "ip": "192.168.10.47",
            "available": True,
            "pulse_count": 2,
            "relevant_indicators": ["192.168.10.47"],
        },
        "opencti": {
            "provider": "opencti",
            "ip": "192.168.10.47",
            "available": True,
            "indicators": [{"value": "192.168.10.47", "type": "ip"}],
        },
    },
    "192.168.10.50": {
        "abuseipdb": {
            "provider": "abuseipdb",
            "ip": "192.168.10.50",
            "available": True,
            "abuse_confidence_score": 0,
        },
        "virustotal": {
            "provider": "virustotal",
            "ip": "192.168.10.50",
            "available": True,
            "malicious_count": 0,
            "suspicious_count": 0,
        },
        "otx": {
            "provider": "otx",
            "ip": "192.168.10.50",
            "available": True,
            "pulse_count": 0,
            "relevant_indicators": [],
        },
        "opencti": {
            "provider": "opencti",
            "ip": "192.168.10.50",
            "available": True,
            "indicators": [],
        },
    },
}


ATTACK_SEVERITY = {
    "DDoS": 1.0,
    "DoS": 0.9,
    "PortScan": 0.8,
    "FTP-Patator": 0.85,
    "SSH-Patator": 0.85,
    "Brute Force": 0.85,
}


def _normalize(name):
    return str(name).strip().lower().replace(" ", "_")


def _first_present(record, candidates):
    for candidate in candidates:
        for key in record.index:
            if _normalize(key) == _normalize(candidate):
                value = record[key]
                if pd.isna(value):
                    continue
                return value
    return None


def extract_network_metadata(record):
    """Extract source/destination metadata from a flow record."""

    source_ip = _first_present(record, ("source_ip", "src ip", "src", "source"))
    destination_ip = _first_present(record, ("destination_ip", "dst ip", "dst", "destination"))
    source_port = _first_present(record, ("source_port", "src port", "sport"))
    destination_port = _first_present(record, ("destination_port", "dst port", "dport"))
    protocol = _first_present(record, ("protocol", "proto"))

    def _as_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    return {
        "source_ip": str(source_ip) if source_ip is not None else None,
        "destination_ip": str(destination_ip) if destination_ip is not None else None,
        "source_port": _as_int(source_port),
        "destination_port": _as_int(destination_port),
        "protocol": str(protocol) if protocol is not None else None,
    }


def infer_attack_type(record):
    """Infer an attack type label from the dataset row when available."""

    label = _first_present(record, ("label", "class", "attack", "target"))
    if label is None:
        return None

    text = str(label).strip()
    if not text or text.upper() in {"BENIGN", "NORMAL"}:
        return None

    normalized = text.replace("_", " ").replace("  ", " ").strip()
    aliases = {
        "dos hulk": "DoS",
        "dos goldeneye": "DoS",
        "ddos": "DDoS",
        "portscan": "PortScan",
        "ftp patator": "FTP-Patator",
        "ssh patator": "SSH-Patator",
        "brute force": "Brute Force",
        "web attack brute force": "Brute Force",
    }

    lower = normalized.lower()
    if lower in aliases:
        return aliases[lower]
    if "dos" in lower:
        return "DoS"
    if "ddos" in lower:
        return "DDoS"
    if "portscan" in lower:
        return "PortScan"
    if "patator" in lower:
        return "FTP-Patator" if "ftp" in lower else "SSH-Patator"
    if "brute" in lower:
        return "Brute Force"
    return normalized


def align_cicids_columns(df, feature_columns):
    """Align input columns to the trained CICIDS feature vector."""

    rename_map = {}
    normalized_lookup = {_normalize(col): col for col in df.columns}
    aliases = {
        "flow_duration": "Flow Duration",
        "total_fwd_packets": "Total Fwd Packets",
        "total_backward_packets": "Total Backward Packets",
        "total_length_of_fwd_packets": "Total Length of Fwd Packets",
        "total_length_of_bwd_packets": "Total Length of Bwd Packets",
        "fwd_packet_length_max": "Fwd Packet Length Max",
        "fwd_packet_length_min": "Fwd Packet Length Min",
        "fwd_packet_length_mean": "Fwd Packet Length Mean",
        "fwd_packet_length_std": "Fwd Packet Length Std",
        "bwd_packet_length_max": "Bwd Packet Length Max",
        "bwd_packet_length_min": "Bwd Packet Length Min",
        "bwd_packet_length_mean": "Bwd Packet Length Mean",
        "bwd_packet_length_std": "Bwd Packet Length Std",
        "flow_bytes_s": "Flow Bytes/s",
        "flow_packets_s": "Flow Packets/s",
        "packet_length_mean": "Packet Length Mean",
        "packet_length_std": "Packet Length Std",
    }
    for alias, canonical in aliases.items():
        if alias in normalized_lookup:
            rename_map[normalized_lookup[alias]] = canonical

    df = df.rename(columns=rename_map)

    aligned = pd.DataFrame(index=df.index)
    for feature in feature_columns:
        if feature in df.columns:
            aligned[feature] = pd.to_numeric(df[feature], errors="coerce").fillna(0.0)
        else:
            aligned[feature] = 0.0
    return aligned


def _summarize_threat_intel(provider_results):
    aggregated = aggregate_reputation(provider_results)
    sources = sorted(
        {
            result.get("provider", provider_name)
            for provider_name, result in provider_results.items()
            if result.get("available")
        }
    )
    return {
        "reputation": aggregated["consensus"],
        "confidence": round(aggregated["overall_reputation"], 4),
        "sources": sources,
    }


def _demo_threat_intel_lookup(ip):
    if ip in DEMO_THREAT_INTEL:
        return DEMO_THREAT_INTEL[ip]
    return {
        "abuseipdb": {
            "provider": "abuseipdb",
            "ip": ip,
            "available": True,
            "abuse_confidence_score": 0,
        },
        "virustotal": {
            "provider": "virustotal",
            "ip": ip,
            "available": True,
            "malicious_count": 0,
            "suspicious_count": 0,
        },
        "otx": {
            "provider": "otx",
            "ip": ip,
            "available": True,
            "pulse_count": 0,
            "relevant_indicators": [],
        },
        "opencti": {
            "provider": "opencti",
            "ip": ip,
            "available": True,
            "indicators": [],
        },
    }


def _infer_default_threat_service():
    return ThreatIntelligenceService.from_environment(
        [
            AbuseIPDBProvider(),
            VirusTotalProvider(),
            OTXProvider(),
            OpenCTIProvider(),
        ],
        cache=cache_from_environment(),
    )


def _demo_source_ip(attack_type, sequence_number):
    if attack_type:
        mapped = {
            "PortScan": "192.168.10.45",
            "DDoS": "192.168.10.46",
            "DoS": "192.168.10.46",
            "FTP-Patator": "192.168.10.47",
            "SSH-Patator": "192.168.10.47",
            "Brute Force": "192.168.10.47",
        }.get(str(attack_type), "192.168.10.45")
        return mapped

    return "192.168.10.50" if not sequence_number or sequence_number % 2 else "192.168.10.51"


def _demo_destination_ip():
    return "192.168.10.10"


def _demo_source_port(sequence_number):
    base = 42000
    try:
        offset = int(sequence_number or 0) % 2000
    except (TypeError, ValueError):
        offset = 0
    return base + offset


def _demo_destination_port(attack_type):
    if not attack_type:
        return 443
    if str(attack_type) in {"PortScan", "FTP-Patator", "SSH-Patator", "Brute Force"}:
        return 21
    if str(attack_type) in {"DDoS", "DoS"}:
        return 80
    return 443


@dataclass
class DetectionResult:
    """Prediction, enrichment, and alert data for a single flow."""

    prediction: str
    confidence: float
    threshold: float
    attack_type: Optional[str]
    legacy_alert: Optional[Dict[str, Any]]
    security_event: Optional[Dict[str, Any]]
    threat_intelligence: Optional[Dict[str, Any]]
    risk: Optional[Dict[str, Any]]


class StreamingDetector:
    """Run the trained model incrementally against one flow at a time."""

    def __init__(
        self,
        model_path,
        threshold=None,
        threat_intel_service=None,
    ):
        artifact = load_model_artifact(model_path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.feature_columns = artifact["feature_columns"]
        self.threshold = float(threshold if threshold is not None else artifact.get("threshold", 0.5))
        self.model_type = artifact.get("model_type", "unknown")
        self.threat_intel_service = threat_intel_service or _infer_default_threat_service()
        self._attack_counts = defaultdict(int)

    def process_record(self, record, sequence_number=None):
        """Process one dataset row and return a structured detection result."""

        series = record if isinstance(record, pd.Series) else pd.Series(record)
        aligned = align_cicids_columns(pd.DataFrame([series]), self.feature_columns)
        aligned = aligned.replace([np.inf, -np.inf], np.nan).fillna(0.0).clip(lower=-1e12, upper=1e12)

        scaled = self.scaler.transform(aligned.to_numpy(dtype=float, copy=False))
        probabilities = self.model.predict_proba(scaled)
        confidence = float(probabilities[0][1])
        prediction = "ATTACK" if confidence >= self.threshold else "BENIGN"

        attack_type = infer_attack_type(series)
        metadata = extract_network_metadata(series)
        metadata["source_ip"] = metadata.get("source_ip") or _demo_source_ip(attack_type, sequence_number)
        metadata["destination_ip"] = metadata.get("destination_ip") or _demo_destination_ip()
        metadata["source_port"] = metadata.get("source_port") or _demo_source_port(sequence_number)
        metadata["destination_port"] = metadata.get("destination_port") or _demo_destination_port(attack_type)
        metadata["protocol"] = metadata.get("protocol") or "TCP"

        if prediction != "ATTACK":
            return DetectionResult(
                prediction=prediction,
                confidence=confidence,
                threshold=self.threshold,
                attack_type=attack_type,
                legacy_alert=None,
                security_event=None,
                threat_intelligence=None,
                risk=None,
            )

        source_ip = metadata.get("source_ip")
        destination_ip = metadata.get("destination_ip")
        provider_results = self._lookup_threat_intel(source_ip)
        alert_stub = {
            "confidence": confidence,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        }
        ioc_matches = IOCMatcher().match(alert_stub, provider_results)
        threat_confidence = assess_threat(alert_stub, provider_results, ioc_matches)
        threat_summary = _summarize_threat_intel(provider_results)

        self._attack_counts[source_ip or "unknown"] += 1
        repetition_score = min(1.0, self._attack_counts[source_ip or "unknown"] / 5.0)
        mitre = map_attack_to_mitre(attack_type)
        attack_severity_score = _attack_severity_score(attack_type)
        mitre_score = 0.0 if not mitre.get("technique") else 0.8
        risk = calculate_risk(
            ml_confidence=confidence,
            threat_intel_score=threat_confidence["score"],
            attack_severity=attack_severity_score,
            mitre_score=mitre_score,
            repetition_score=repetition_score,
        )

        explanation = list(threat_confidence["factors"])
        if attack_type:
            explanation.append(f"Attack type inferred from replay data: {attack_type}")
        if mitre.get("technique"):
            explanation.append(f"Mapped to MITRE {mitre['technique']}")
        explanation.append(f"Repeated activity score: {repetition_score:.2f}")

        severity = risk["severity"].upper()
        security_event = create_security_event(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=metadata.get("source_port"),
            destination_port=metadata.get("destination_port"),
            protocol=metadata.get("protocol"),
            attack_type=attack_type,
            prediction=prediction,
            ml_confidence=round(confidence, 4),
            threshold=round(self.threshold, 4),
            risk_score=risk["score"],
            severity=severity,
            mitre_tactic=mitre.get("tactic"),
            mitre_technique=mitre.get("technique"),
            threat_intel=threat_summary,
            explanation=explanation,
            attack_name=mitre.get("name"),
            detector_version=str(self.model_type),
        )
        security_event["risk"]["factors"] = risk["factors"]
        security_event["threat_intelligence"]["details"] = provider_results

        legacy_alert = {
            "alert_id": f"stream-{sequence_number or self._attack_counts[source_ip or 'unknown']}",
            "timestamp": security_event["timestamp"],
            "record_index": sequence_number,
            "predicted_label": prediction,
            "confidence": round(confidence, 4),
            "threshold": round(self.threshold, 4),
            "model_type": self.model_type,
            **metadata,
            "threat_intelligence": provider_results,
            "ioc_matches": ioc_matches,
            "threat_confidence": threat_confidence,
            "mitre": mitre,
            "risk": risk,
        }

        return DetectionResult(
            prediction=prediction,
            confidence=confidence,
            threshold=self.threshold,
            attack_type=attack_type,
            legacy_alert=legacy_alert,
            security_event=security_event,
            threat_intelligence=provider_results,
            risk=risk,
        )

    def _lookup_threat_intel(self, source_ip):
        if source_ip and source_ip in DEMO_THREAT_INTEL:
            return _demo_threat_intel_lookup(source_ip)
        if source_ip:
            results = self.threat_intel_service.lookup(source_ip)
            if any(result.get("available") for result in results.values()):
                return results
        return _demo_threat_intel_lookup(source_ip or "unknown")


def _attack_severity_score(attack_type):
    if not attack_type:
        return 0.5
    return ATTACK_SEVERITY.get(str(attack_type), 0.6)