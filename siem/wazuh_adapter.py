"""Local-file adapter for Wazuh agent ingestion."""

import json
import os
from pathlib import Path


class WazuhJsonlAdapter:
    """Append normalized IDS events to a JSONL file watched by the Wazuh agent."""

    def __init__(self, output_path="logs/live_security_events.jsonl", overwrite=False):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.overwrite = bool(overwrite)

        if self.overwrite:
            self.output_path.write_text("", encoding="utf-8")

    @classmethod
    def from_environment(cls):
        """Create an adapter using the environment override if present."""

        return cls(
            output_path=os.getenv(
                "LIVE_SECURITY_EVENT_FILE",
                "logs/live_security_events.jsonl",
            )
        )

    def append(self, event):
        """Write one canonical event as a single JSON line."""

        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    event,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
            handle.write("\n")