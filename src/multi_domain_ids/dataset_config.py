from __future__ import annotations

import os
from pathlib import Path


_DATASET_FILENAMES = {
    "auth": "auth.txt.gz",
    "cicids_sample": "train_sample.csv",
    "dns": "dns.txt.gz",
    "flows": "flows.txt.gz",
    "proc": "proc.txt.gz",
    "redteam": "redteam.txt.gz",
    "simulation": "simulation_data.csv",
    "sqli": "Normal &Malicious SQLi.csv",
    "ton_iot_archive": "OneDrive_2026-11-13.zip",
}


def dataset_path(name: str, explicit_path: str | Path | None = None) -> Path:
    """Resolve a dataset override, then the configured dataset root."""
    if name not in _DATASET_FILENAMES:
        raise ValueError(f"Unknown dataset name: {name!r}")
    if explicit_path is not None:
        return Path(explicit_path).expanduser().resolve()

    override = os.environ.get(f"MULTI_DOMAIN_IDS_{name.upper()}_PATH")
    if override:
        return Path(override).expanduser().resolve()

    return (dataset_root_path() / _DATASET_FILENAMES[name]).resolve()


def dataset_root_path(explicit_path: str | Path | None = None) -> Path:
    if explicit_path is not None:
        return Path(explicit_path).expanduser().resolve()
    root = os.environ.get("MULTI_DOMAIN_IDS_DATASET_ROOT", "").strip()
    if not root:
        root = str(Path.home() / "Downloads")
    return Path(root).expanduser().resolve()


def output_directory(explicit_path: str | Path | None = None) -> Path:
    """Resolve the output directory without placing generated data in Downloads."""
    if explicit_path is not None:
        return Path(explicit_path).expanduser().resolve()
    configured = os.environ.get("MULTI_DOMAIN_IDS_OUTPUT_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    repository_root = Path(__file__).resolve().parents[2]
    return repository_root / "artifacts"
