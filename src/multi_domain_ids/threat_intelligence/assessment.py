"""Deterministic Part 2 threat assessment built on Part 1 provider results."""

import ipaddress
from urllib.parse import urlsplit, urlunsplit


SEVERITY_THRESHOLDS = ((0.75, "CRITICAL"), (0.50, "HIGH"), (0.25, "MEDIUM"), (0.0, "LOW"))


def normalize_ioc(value, ioc_type=None):
    """Return a canonical IOC or None when its type/value is invalid."""
    if value is None:
        return None
    text = str(value).strip()
    kind = (ioc_type or infer_ioc_type(text)).lower()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if kind == "domain":
        domain = text.rstrip(".").lower()
        if not domain or "." not in domain or "/" in domain or " " in domain:
            return None
        return domain
    if kind == "url":
        parts = urlsplit(text)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.rstrip(".").lower()
        netloc = host
        try:
            port = parts.port
        except ValueError:
            return None
        if port:
            netloc += f":{port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    if kind == "hash":
        candidate = text.lower()
        if len(candidate) in {32, 40, 64, 96, 128} and all(char in "0123456789abcdef" for char in candidate):
            return candidate
        return None
    return None


def infer_ioc_type(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return "ip"
    except ValueError:
        pass
    if str(value).lower().startswith(("http://", "https://")):
        return "url"
    if len(str(value).strip()) in {32, 40, 64, 96, 128}:
        return "hash"
    return "domain"


class IOCMatcher:
    """Exact, source-aware matching against alert values and provider evidence."""

    def match(self, alert, provider_results, known_iocs=None):
        alert_values = self._alert_values(alert)
        matches = []
        for provider_key, result in provider_results.items():
            if not result.get("available"):
                continue
            provider = result.get("provider", provider_key)
            evidence = self._provider_values(provider, result)
            for ioc_type, value, confidence in evidence:
                canonical = normalize_ioc(value, ioc_type)
                if canonical is None or canonical not in alert_values.get(ioc_type, set()):
                    continue
                matches.append({"ioc_type": ioc_type, "value": canonical, "matched": True,
                                "source": provider, "confidence": round(_clamp(confidence), 4)})
        for item in known_iocs or []:
            if isinstance(item, str):
                item = {"value": item}
            ioc_type = item.get("ioc_type") or infer_ioc_type(item.get("value"))
            canonical = normalize_ioc(item.get("value"), ioc_type)
            if canonical in alert_values.get(ioc_type, set()):
                matches.append({"ioc_type": ioc_type, "value": canonical, "matched": True,
                                "source": item.get("source", "configured"),
                                "confidence": round(_clamp(item.get("confidence", 1.0)), 4)})
        return _unique_matches(matches)

    @staticmethod
    def _alert_values(alert):
        values = {"ip": set(), "domain": set(), "url": set(), "hash": set()}
        for field in ("source_ip", "destination_ip"):
            normalized = normalize_ioc(alert.get(field), "ip")
            if normalized:
                values["ip"].add(normalized)
        for field in ("domain", "url", "hash", "file_hash", "md5", "sha1", "sha256"):
            kind = "hash" if field in {"hash", "file_hash", "md5", "sha1", "sha256"} else field
            normalized = normalize_ioc(alert.get(field), kind)
            if normalized:
                values[kind].add(normalized)
        return values

    @staticmethod
    def _provider_values(provider, result):
        values = []
        if result.get("ip"):
            signal = _provider_signal(provider, result)
            if signal > 0:
                values.append(("ip", result["ip"], signal))
        for field in ("domain", "url", "hash", "sha256", "sha1", "md5"):
            if result.get(field):
                values.append(("hash" if field != "domain" and field != "url" else field, result[field], _provider_signal(provider, result)))
        for indicator in result.get("relevant_indicators", []) or []:
            if isinstance(indicator, str):
                values.append((infer_ioc_type(indicator), indicator, 0.75))
            elif isinstance(indicator, dict):
                value = indicator.get("indicator") or indicator.get("value")
                if value:
                    values.append((indicator.get("type") or infer_ioc_type(value), value, 0.75))
        for indicator in result.get("indicators", []) or []:
            if isinstance(indicator, dict):
                value = indicator.get("value") or indicator.get("pattern")
                if value:
                    values.append((indicator.get("type") or infer_ioc_type(value), value, 0.8))
        return values


def aggregate_reputation(provider_results):
    available = {}
    checked = set()
    for provider_key, result in provider_results.items():
        provider = result.get("provider", provider_key)
        checked.add(provider)
        if result.get("available"):
            available[provider] = max(available.get(provider, 0.0), _provider_signal(provider, result))
    evidence = available
    reporting = [value for value in evidence.values() if value > 0]
    return {
        "providers_checked": len(checked),
        "providers_available": len(available),
        "providers_reporting_malicious": len(reporting),
        "consensus": "malicious" if reporting and len(reporting) >= max(1, (len(available) + 1) // 2) else "no_malicious_evidence",
        "overall_reputation": round(sum(evidence.values()) / len(evidence), 4) if evidence else 0.0,
    }


def assess_threat(alert, provider_results, ioc_matches=None):
    """Calculate a bounded threat score from documented, deterministic components."""
    reputation = aggregate_reputation(provider_results)
    matches = ioc_matches if ioc_matches is not None else IOCMatcher().match(alert, provider_results)
    ml = _clamp(alert.get("confidence", 0.0))
    ioc_component = _clamp(sum(match.get("confidence", 0.0) for match in matches) / max(1, len(matches))) if matches else 0.0
    consensus_component = reputation["providers_reporting_malicious"] / max(1, reputation["providers_available"])
    score = (0.35 * ml) + (0.30 * reputation["overall_reputation"]) + (0.20 * ioc_component) + (0.15 * consensus_component)
    score = round(_clamp(score), 4)
    factors = _factors(ml, provider_results, matches, reputation)
    return {"score": score, "severity": classify_severity(score), "factors": factors}


def classify_severity(score):
    score = _clamp(score)
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return "LOW"


def _provider_signal(provider, result):
    if provider == "abuseipdb":
        return _clamp((result.get("abuse_confidence_score") or 0) / 100)
    if provider == "virustotal":
        malicious = min(1.0, (result.get("malicious_count") or 0) / 5)
        suspicious = min(1.0, (result.get("suspicious_count") or 0) / 5) * 0.25
        return _clamp(malicious + suspicious)
    if provider == "otx":
        return _clamp((result.get("pulse_count") or 0) / 5)
    if provider == "opencti":
        return 1.0 if result.get("indicators") else 0.0
    return _clamp(result.get("threat_score", 0.0))


def _factors(ml, providers, matches, reputation):
    factors = [f"ML confidence: {ml:.2f}"]
    abuse = _provider_result(providers, "abuseipdb")
    virus_total = _provider_result(providers, "virustotal")
    otx = _provider_result(providers, "otx")
    opencti = _provider_result(providers, "opencti")
    if abuse and abuse.get("abuse_confidence_score"):
        factors.append(f"AbuseIPDB abuse confidence: {abuse['abuse_confidence_score']}%")
    if virus_total and virus_total.get("malicious_count", 0):
        factors.append("VirusTotal reported malicious detections")
    if otx and otx.get("pulse_count", 0):
        factors.append(f"OTX pulses: {otx['pulse_count']}")
    if opencti and opencti.get("indicators"):
        factors.append("OpenCTI returned matching indicators")
    if matches:
        factors.append(f"IOC matched by {len({match['source'] for match in matches})} provider source(s)")
    if reputation["providers_available"] and reputation["providers_reporting_malicious"] == 0:
        factors.append("Available providers returned no malicious evidence")
    return factors


def _provider_result(results, provider_name):
    for key, result in results.items():
        if result.get("provider", key) == provider_name and result.get("available"):
            return result
    return None


def _unique_matches(matches):
    unique = []
    seen = set()
    for match in matches:
        key = (match["ioc_type"], match["value"], match["source"])
        if key not in seen:
            seen.add(key)
            unique.append(match)
    return unique


def _clamp(value):
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0