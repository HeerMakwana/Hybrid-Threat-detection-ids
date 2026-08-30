# Threat Intelligence Part 1

The IDS keeps ML inference and alert creation in `simulation.py`. The `threat_intelligence` package is a separate provider layer for IP enrichment. Part 1 only retrieves and normalizes provider data; it does not perform IOC matching, confidence aggregation, reputation scoring, or severity scoring.

Flow records created by `feature_extractor.py` preserve the packet five-tuple alongside the existing 17 aggregate features. The current CICIDS-derived CSV files do not contain those metadata fields, so historical simulation alerts cannot perform real IP lookups until the simulation input is generated from a genuine IP-bearing flow source. No metadata is fabricated for those files.

## Providers

- AbuseIPDB uses API v2 IP check and returns abuse score, reports, ISP, domain, usage type, and report time.
- VirusTotal uses its v3 IP endpoint and returns analysis counts, reputation, country, ASN, owner, and network.
- AlienVault OTX uses the IP general endpoint and returns pulse count, reputation, related threats, indicators, and dates.
- OpenCTI uses a configurable GraphQL endpoint and is disabled by default. It is mocked in tests; configure `OPENCTI_URL`, `OPENCTI_API_KEY`, and `OPENCTI_ENABLED=true` for a real instance.

All providers return normalized dictionaries with `provider`, `ip`, and `available`. Missing credentials, invalid IPs, HTTP errors, timeouts, malformed responses, and network errors produce an unavailable result. The service isolates each provider, so one failure cannot remove another provider's result or an ML alert.

## Configuration

Copy `.env.example` to `.env` and set values as needed. `.env` is ignored by git. The package reads environment variables; loading `.env` itself is intentionally left to the process runner. `THREAT_INTEL_ENABLED` defaults to false. Provider toggles are independently configurable. `ThreatIntelligenceCache` provides an in-memory provider/IP cache with a configurable TTL when constructed by the caller.

## Testing

`pytest -q` runs mocked tests only. No API keys are printed and no automated test makes a live request. A live smoke test can be added by an operator using the configured providers and a single test IP; live results are not claimed by this repository.

## Part 2 Assessment

`aggregate_reputation()` keeps each normalized provider result intact and reports provider availability, malicious reporters, consensus, and `overall_reputation`. An unavailable provider is excluded from the reputation average; it is never treated as safe or malicious. Consensus is `malicious` when at least half of available providers have a positive normalized signal, otherwise it is `no_malicious_evidence`.

`IOCMatcher` performs exact normalized matching for alert source/destination IPs, domains, URLs, and common hashes. IPs use Python `ipaddress`; domains are lower-cased and stripped of a trailing dot; URLs compare normalized HTTP(S) scheme, host, port, path, and query; hashes are lower-case hexadecimal values of common lengths. Provider evidence remains source-aware, so the same IOC can produce multiple matches from different providers.

Threat confidence is calculated as:

```text
score = clamp(
		0.35 * ML confidence
	+ 0.30 * average provider reputation signal
	+ 0.20 * average IOC match confidence
	+ 0.15 * malicious-provider consensus,
	0.0, 1.0)
```

Signals are normalized as follows: AbuseIPDB abuse confidence divided by 100; VirusTotal `min(1, malicious_count / 5) + 0.25 * min(1, suspicious_count / 5)`; OTX `min(1, pulse_count / 5)`; and OpenCTI 1.0 when indicators exist, otherwise 0.0. Provider averages use available providers only. IOC confidence is averaged only when matches exist, otherwise zero. Consensus is malicious reporters divided by available providers, with zero when no providers are available. The score is rounded to four decimals and clamped to `[0, 1]`. The existing alert `confidence` remains ML confidence.

Severity is deterministic: `0.00-0.24 LOW`, `0.25-0.49 MEDIUM`, `0.50-0.74 HIGH`, and `0.75-1.00 CRITICAL`. Explanation factors are emitted only for actual ML, provider, pulse, IOC, or availability evidence.

An enriched alert retains all Part 1 fields and adds `threat_intelligence` (IP-scoped provider results), `ioc_matches`, and `threat_confidence`:

```json
{
	"confidence": 0.97,
	"threat_intelligence": {"source_ip": {"abuseipdb": {"available": true}}},
	"ioc_matches": [{"ioc_type": "ip", "value": "192.0.2.1", "matched": true, "source": "abuseipdb", "confidence": 0.94}],
	"threat_confidence": {"score": 0.91, "severity": "CRITICAL", "factors": ["ML confidence: 0.97"]}
}
```

The existing Part 1 cache remains the only cache. `run_simulation()` performs one service lookup per unique source/destination IP, allowing provider results to use the existing `provider:ip` TTL cache. All provider failures remain isolated and an ML anomaly alert is still written when every provider is unavailable.

## Model Compatibility

The unchanged model artifact contains the legacy pickle global `_loss.CyHalfBinomialLoss`. The installed equivalent is `sklearn._loss._loss.CyHalfBinomialLoss`; this identity was verified in the tested environments. `model_loader.py` uses a temporary exact `NumpyUnpickler` mapping for that single reference while joblib loads the compressed artifact, then restores the original loader. No fake module, site-package edit, retraining, or artifact rewrite is used. The tested versions are Python 3.12.10 or 3.14.2, scikit-learn 1.9.0, LightGBM 4.7.0, and joblib 1.5.3.