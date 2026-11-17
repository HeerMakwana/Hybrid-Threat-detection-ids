from __future__ import annotations

import os
from pathlib import Path


_DATASET_SUFFIXES = {
    ".7z",
    ".arff",
    ".csv",
    ".feather",
    ".gz",
    ".json",
    ".jsonl",
    ".parquet",
    ".tar",
    ".txt",
    ".xlsx",
    ".zip",
}


def discover_dataset_files(root: str | Path) -> list[dict[str, int | str]]:
    """Recursively inventory dataset-like files without opening or modifying them."""
    directory = Path(root).expanduser().resolve()
    if not directory.is_dir():
        raise NotADirectoryError(f"Dataset root is not a directory: {directory}")

    discovered: list[dict[str, int | str]] = []

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current_root, _, filenames in os.walk(directory, onerror=raise_walk_error):
        for filename in filenames:
            path = Path(current_root) / filename
            if path.suffix.lower() not in _DATASET_SUFFIXES:
                continue
            discovered.append(
                {
                    "path": str(path.resolve()),
                    "name": path.name,
                    "size_bytes": path.stat().st_size,
                    "format": _format_name(path),
                }
            )
    return sorted(discovered, key=lambda item: str(item["path"]).casefold())


def _format_name(path: Path) -> str:
    if path.name.lower().endswith(".txt.gz"):
        return "gzip-compressed text"
    if path.name.lower().endswith(".csv.gz"):
        return "gzip-compressed CSV"
    return path.suffix.lower().lstrip(".")
