"""Record a human review decision for one canonical IDS JSON event."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.response_workflow import review_event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--decision", choices=("approve", "reject", "escalate"), required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--action", default="NONE",
                        choices=("NONE", "BLOCK_SOURCE", "ISOLATE_HOST", "COLLECT_EVIDENCE"))
    parser.add_argument("--allowlist", action="append", default=[])
    args = parser.parse_args()
    event = json.loads(args.input.read_text(encoding="utf-8"))
    reviewed = review_event(event, args.decision, args.reviewer, args.action, args.allowlist)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(reviewed, indent=2), encoding="utf-8")
    print(f"Recorded {reviewed['workflow']['status']} review in {args.output}")


if __name__ == "__main__":
    main()