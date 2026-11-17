"""Human-approved response decisions for IDS security events."""

from copy import deepcopy
from datetime import datetime, timezone


DECISIONS = {"APPROVE", "REJECT", "ESCALATE"}
SAFE_ACTIONS = {"NONE", "BLOCK_SOURCE", "ISOLATE_HOST", "COLLECT_EVIDENCE"}


def review_event(event, decision, reviewer, action="NONE", allowlisted_ips=()):
    """Attach an analyst decision without performing a network-side action."""
    decision = str(decision).upper()
    action = str(action).upper()
    reviewer = str(reviewer).strip()
    if decision not in DECISIONS:
        raise ValueError(f"Unsupported decision: {decision}")
    if action not in SAFE_ACTIONS:
        raise ValueError(f"Unsupported response action: {action}")
    if not reviewer:
        raise ValueError("A reviewer identity is required")

    reviewed = deepcopy(event)
    source_ip = reviewed.get("source", {}).get("ip")
    if source_ip in set(allowlisted_ips) and action in {"BLOCK_SOURCE", "ISOLATE_HOST"}:
        raise ValueError("Destructive response is not allowed for an allowlisted source")

    status = {
        "APPROVE": "APPROVED",
        "REJECT": "REJECTED",
        "ESCALATE": "ESCALATED",
    }[decision]
    reviewed.setdefault("workflow", {}).update({
        "status": status,
        "approved_by": reviewer,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "requested_action": action,
        "executed": False,
    })
    return reviewed