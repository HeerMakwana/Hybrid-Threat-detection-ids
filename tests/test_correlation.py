from __future__ import annotations

from multi_domain_ids.correlation import IncidentCorrelator


def _event(event_id, domain, timestamp, entity):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "detection_domain": domain,
        "attack_name": "suspicious_activity",
        "model_prediction": "suspicious",
        "evidence": [{"signal": event_id, "description": "independent observed signal"}],
        "affected_asset": entity,
    }


def test_correlates_distinct_domains_for_a_shared_entity_in_time_window():
    correlator = IncidentCorrelator(window_seconds=300)
    assert correlator.ingest(_event("one", "network", "2026-01-01T00:00:00+00:00", "host-a")) is None

    incident = correlator.ingest(_event("two", "identity", "2026-01-01T00:04:00+00:00", "host-a"))

    assert incident is not None
    assert incident["related_event_ids"] == ["one", "two"]
    assert incident["correlated_domains"] == ["identity", "network"]
    assert incident["severity"] == "medium"


def test_does_not_correlate_unrelated_or_out_of_window_events():
    correlator = IncidentCorrelator(window_seconds=60)
    correlator.ingest(_event("one", "network", "2026-01-01T00:00:00+00:00", "host-a"))

    unrelated = correlator.ingest(_event("two", "identity", "2026-01-01T00:00:30+00:00", "host-b"))
    outside_window = correlator.ingest(_event("three", "identity", "2026-01-01T00:02:00+00:00", "host-a"))

    assert unrelated is None
    assert outside_window is None


def test_deduplicates_an_event_id():
    correlator = IncidentCorrelator()
    event = _event("same", "network", "2026-01-01T00:00:00+00:00", "host-a")

    assert correlator.ingest(event) is None
    assert correlator.ingest(event) is None
