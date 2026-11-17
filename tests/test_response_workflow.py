import pytest

from detection.response_workflow import review_event


def test_review_requires_human_and_does_not_execute_action():
    event = {"source": {"ip": "203.0.113.10"}, "workflow": {"status": "PENDING_REVIEW"}}

    reviewed = review_event(event, "approve", "analyst-1", "BLOCK_SOURCE")

    assert reviewed["workflow"]["status"] == "APPROVED"
    assert reviewed["workflow"]["approved_by"] == "analyst-1"
    assert reviewed["workflow"]["requested_action"] == "BLOCK_SOURCE"
    assert reviewed["workflow"]["executed"] is False
    assert event["workflow"]["status"] == "PENDING_REVIEW"


def test_allowlist_blocks_destructive_review_action():
    event = {"source": {"ip": "192.0.2.10"}}

    with pytest.raises(ValueError, match="allowlisted"):
        review_event(event, "approve", "analyst-1", "BLOCK_SOURCE", ["192.0.2.10"])