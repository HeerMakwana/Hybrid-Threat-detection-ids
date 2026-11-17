from __future__ import annotations

from collections import Counter
import csv
import gzip
import json
import os
from pathlib import Path
import time
from typing import Any, Callable

import pandas as pd

from .dataset_loaders import LANL_COLUMN_NAMES, iter_lanl_chunks


ProgressCallback = Callable[[dict[str, Any]], None]
_CHECKPOINT_NAME = "auth_processing_checkpoint.json"
_SUMMARY_NAME = "auth_processing_summary.json"
_ERRORS_NAME = "auth_processing_errors.jsonl"


def process_auth_dataset(
    dataset_path: str | Path,
    output_dir: str | Path,
    *,
    redteam_path: str | Path | None = None,
    annotation_window_seconds: int = 300,
    chunksize: int = 100_000,
    resume: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Stream LANL authentication records into a compact, resumable summary.

    The source is never extracted or modified. A checkpoint stores only
    aggregate counts and the source record offset; resuming a gzip stream
    replays and skips the already-checkpointed records.
    """
    source = Path(dataset_path).expanduser().resolve()
    destination = Path(output_dir).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Authentication dataset does not exist: {source}")
    if chunksize <= 0:
        raise ValueError("chunksize must be greater than zero")
    if annotation_window_seconds < 0:
        raise ValueError("annotation_window_seconds must not be negative")

    source_stat = source.stat()
    fingerprint = {
        "path": str(source),
        "size_bytes": source_stat.st_size,
        "mtime_ns": source_stat.st_mtime_ns,
    }
    destination.mkdir(parents=True, exist_ok=True)
    checkpoint_path = destination / _CHECKPOINT_NAME
    summary_path = destination / _SUMMARY_NAME
    errors_path = destination / _ERRORS_NAME
    redteam_source = (
        Path(redteam_path).expanduser().resolve() if redteam_path is not None else None
    )
    redteam_fingerprint = _file_fingerprint(redteam_source) if redteam_source else None
    redteam_index, redteam_rows = _load_redteam_index(redteam_source)
    if redteam_source and _file_fingerprint(redteam_source) != redteam_fingerprint:
        raise RuntimeError("Red-team annotation source changed while it was being read")

    state = _new_state(
        fingerprint,
        redteam_fingerprint,
        redteam_rows,
        annotation_window_seconds,
    )
    if checkpoint_path.exists():
        if not resume:
            raise FileExistsError(
                f"Checkpoint already exists; choose a different output directory or resume: "
                f"{checkpoint_path}"
            )
        state = _read_checkpoint(
            checkpoint_path,
            fingerprint,
            redteam_fingerprint,
            annotation_window_seconds,
        )
        if state.get("complete"):
            result = _summary_payload(
                state, float(state.get("elapsed_seconds", 0.0)), resumed=True
            )
            result["status"] = "completed"
            result["summary_path"] = str(summary_path)
            _write_json_atomic(summary_path, result)
            return result

    checkpoint_records = int(state["records_seen"])
    was_resumed = checkpoint_records > 0
    matched_annotations = set(state["matched_annotation_ids"])
    started = time.monotonic()

    def report_malformed(record_number: int, actual_fields: int, expected_fields: int) -> None:
        item = {
            "dataset": str(source),
            "record_number": record_number,
            "actual_fields": actual_fields,
            "expected_fields": expected_fields,
            "error": "LANL authentication record has an invalid field count",
        }
        with errors_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(item, separators=(",", ":")) + "\n")

    stage = "read_auth_dataset"
    try:
        chunks = iter_lanl_chunks(
            "auth",
            source,
            chunksize=chunksize,
            malformed_rows="skip",
            malformed_row_handler=report_malformed,
            skip_records=checkpoint_records,
        )
        for frame in chunks:
            state["records_seen"] = int(frame.attrs["source_record_end"])
            state["processed_rows"] += int(len(frame))
            state["malformed_rows"] += int(frame.attrs["malformed_rows"])
            _update_counts(state, frame)
            _update_redteam_matches(
                frame,
                redteam_index,
                matched_annotations,
                annotation_window_seconds,
                state,
            )
            state["matched_annotation_ids"] = sorted(matched_annotations)
            stage = "write_checkpoint"
            _write_json_atomic(checkpoint_path, _checkpoint_payload(state, started))
            if progress_callback is not None:
                stage = "progress_callback"
                progress_callback(_summary_payload(state, _elapsed(state, started), resumed=False))
            stage = "read_auth_dataset"
    except (
        OSError,
        EOFError,
        UnicodeDecodeError,
        csv.Error,
        gzip.BadGzipFile,
        ValueError,
    ) as exc:
        _append_error(
            errors_path,
            {
                "dataset": str(source),
                "record_number": int(state["records_seen"]) + 1,
                "stage": stage,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        _write_json_atomic(checkpoint_path, _checkpoint_payload(state, started))
        raise

    current_stat = source.stat()
    if (
        current_stat.st_size != fingerprint["size_bytes"]
        or current_stat.st_mtime_ns != fingerprint["mtime_ns"]
    ):
        raise RuntimeError("Authentication source changed while it was being processed")
    if redteam_source and _file_fingerprint(redteam_source) != redteam_fingerprint:
        raise RuntimeError("Red-team annotation source changed while auth was processed")

    state["complete"] = True
    state["elapsed_seconds"] = float(state.get("elapsed_seconds", 0.0)) + (
        time.monotonic() - started
    )
    result = _summary_payload(state, state["elapsed_seconds"], resumed=was_resumed)
    result["status"] = "completed"
    result["summary_path"] = str(summary_path)
    _write_json_atomic(checkpoint_path, {**state, "elapsed_seconds": result["elapsed_seconds"]})
    _write_json_atomic(summary_path, result)
    return result


def _new_state(
    fingerprint: dict[str, Any],
    redteam_fingerprint: dict[str, Any] | None,
    redteam_rows: int,
    annotation_window_seconds: int,
) -> dict[str, Any]:
    return {
        "version": 1,
        "source": fingerprint,
        "redteam_source": redteam_fingerprint,
        "schema": list(LANL_COLUMN_NAMES["auth"]),
        "records_seen": 0,
        "processed_rows": 0,
        "malformed_rows": 0,
        "authentication_outcomes": {},
        "authentication_types": {},
        "logon_types": {},
        "authentication_orientations": {},
        "missing_values": {},
        "redteam_rows": redteam_rows,
        "redteam_matched_rows": 0,
        "redteam_associated_auth_rows": 0,
        "matched_annotation_ids": [],
        "annotation_window_seconds": annotation_window_seconds,
        "elapsed_seconds": 0.0,
        "complete": False,
    }


def _read_checkpoint(
    path: Path,
    fingerprint: dict[str, Any],
    redteam_fingerprint: dict[str, Any] | None,
    annotation_window_seconds: int,
) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        state = json.load(stream)
    if not isinstance(state, dict) or state.get("version") != 1:
        raise ValueError(f"Unsupported authentication checkpoint: {path}")
    if state.get("source") != fingerprint:
        raise ValueError(
            "Authentication checkpoint belongs to a different source file; "
            "use a new output directory"
        )
    if state.get("redteam_source") != redteam_fingerprint:
        raise ValueError(
            "Authentication checkpoint belongs to a different red-team source; "
            "use a new output directory"
        )
    if state.get("annotation_window_seconds") != annotation_window_seconds:
        raise ValueError(
            "Authentication checkpoint uses a different annotation time window; "
            "use a new output directory"
        )
    return state


def _update_counts(state: dict[str, Any], frame: pd.DataFrame) -> None:
    if frame.empty:
        return
    count_columns = {
        "authentication_outcomes": "success_failure",
        "authentication_types": "authentication_type",
        "logon_types": "logon_type",
        "authentication_orientations": "authentication_orientation",
    }
    for counter_name, column in count_columns.items():
        counts = frame[column].fillna("<missing>").astype(str).str.strip()
        counts = counts.str.lower().value_counts(dropna=False)
        counter = Counter(state[counter_name])
        counter.update({str(key): int(value) for key, value in counts.items()})
        state[counter_name] = dict(counter)

    for column in LANL_COLUMN_NAMES["auth"]:
        missing_count = int(frame[column].isna().sum())
        if missing_count:
            state["missing_values"][column] = (
                int(state["missing_values"].get(column, 0)) + missing_count
            )


def _load_redteam_index(
    path: Path | None,
) -> tuple[dict[tuple[str, str, str], list[tuple[int, int]]], int]:
    if path is None:
        return {}, 0
    if not path.is_file():
        raise FileNotFoundError(f"Red-team annotation dataset does not exist: {path}")
    index: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
    annotation_id = 0
    for frame in iter_lanl_chunks("redteam", path, chunksize=100_000):
        for row in frame.itertuples(index=False, name=None):
            timestamp, user, source_computer, destination_computer = row
            if pd.isna(timestamp) or pd.isna(user) or pd.isna(source_computer) or pd.isna(
                destination_computer
            ):
                annotation_id += 1
                continue
            key = (str(user), str(source_computer), str(destination_computer))
            index.setdefault(key, []).append((int(timestamp), annotation_id))
            annotation_id += 1
    for annotations in index.values():
        annotations.sort()
    return index, annotation_id


def _file_fingerprint(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Dataset does not exist: {path}")
    stat = path.stat()
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _update_redteam_matches(
    frame: pd.DataFrame,
    index: dict[tuple[str, str, str], list[tuple[int, int]]],
    matched_annotations: set[int],
    window_seconds: int,
    state: dict[str, Any],
) -> None:
    if frame.empty or not index:
        return
    annotation_records = [
        (key[0], key[1], key[2], timestamp, annotation_id)
        for key, annotations in index.items()
        for timestamp, annotation_id in annotations
    ]
    annotations = pd.DataFrame(
        annotation_records,
        columns=[
            "source_user_domain",
            "source_computer",
            "destination_computer",
            "_annotation_time",
            "_annotation_id",
        ],
    )
    events = frame.reset_index(drop=True).copy()
    events["_event_id"] = events.index
    events["_event_time"] = pd.to_numeric(events["time"], errors="coerce")
    events = events.dropna(
        subset=[
            "_event_time",
            "source_user_domain",
            "source_computer",
            "destination_computer",
        ]
    )
    if events.empty:
        return
    matches = events.merge(
        annotations,
        on=["source_user_domain", "source_computer", "destination_computer"],
        how="inner",
        sort=False,
    )
    if matches.empty:
        return
    in_window = (
        matches["_event_time"] - matches["_annotation_time"]
    ).abs().le(window_seconds)
    associated = matches.loc[in_window]
    if associated.empty:
        return
    state["redteam_associated_auth_rows"] += int(associated["_event_id"].nunique())
    matched_annotations.update(associated["_annotation_id"].astype(int).tolist())
    state["redteam_matched_rows"] = len(matched_annotations)


def _checkpoint_payload(state: dict[str, Any], started: float) -> dict[str, Any]:
    payload = dict(state)
    payload["elapsed_seconds"] = float(state.get("elapsed_seconds", 0.0)) + (
        time.monotonic() - started
    )
    return payload


def _elapsed(state: dict[str, Any], started: float) -> float:
    return float(state.get("elapsed_seconds", 0.0)) + (time.monotonic() - started)


def _summary_payload(
    state: dict[str, Any],
    elapsed_seconds: float,
    *,
    resumed: bool,
) -> dict[str, Any]:
    rows = int(state["processed_rows"])
    outcomes = state["authentication_outcomes"]
    failure_count = sum(
        int(outcomes.get(outcome, 0)) for outcome in ("fail", "failed", "failure")
    )
    success_count = int(outcomes.get("success", 0))
    classified_count = failure_count + success_count
    return {
        "status": "already_completed" if state.get("complete") else "processing",
        "dataset_path": state["source"]["path"],
        "dataset_size_bytes": state["source"]["size_bytes"],
        "schema": state["schema"],
        "records_seen": int(state["records_seen"]),
        "processed_rows": rows,
        "malformed_rows": int(state["malformed_rows"]),
        "authentication_outcomes": dict(state["authentication_outcomes"]),
        "authentication_types": dict(state["authentication_types"]),
        "logon_types": dict(state["logon_types"]),
        "authentication_orientations": dict(state["authentication_orientations"]),
        "missing_values": dict(state["missing_values"]),
        "features": {
            "successful_authentication_rows": success_count,
            "failed_authentication_rows": failure_count,
            "failure_ratio": (
                failure_count / classified_count if classified_count else None
            ),
        },
        "redteam_annotation_join": {
            "status": "processed" if state["redteam_source"] else "not_configured",
            "dataset_path": (
                state["redteam_source"]["path"] if state["redteam_source"] else None
            ),
            "annotation_rows": int(state["redteam_rows"]),
            "matched_annotation_rows": int(state["redteam_matched_rows"]),
            "unmatched_annotation_rows": int(
                state["redteam_rows"] - state["redteam_matched_rows"]
            ),
            "associated_authentication_rows": int(state["redteam_associated_auth_rows"]),
            "join_keys": [
                "source_user_domain = redteam.user_domain",
                "source_computer = redteam.source_computer",
                "destination_computer = redteam.destination_computer",
            ],
            "absolute_time_window_seconds": int(state["annotation_window_seconds"]),
            "used_as_inference_feature": False,
        },
        "elapsed_seconds": round(float(elapsed_seconds), 3),
        "rows_per_second": (
            round(rows / elapsed_seconds, 2) if elapsed_seconds > 0 else None
        ),
        "resumed": resumed,
        "complete": bool(state.get("complete")),
    }


def _append_error(path: Path, item: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(item, separators=(",", ":")) + "\n")


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    for attempt in range(5):
        try:
            temporary_path.replace(path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.1 * (2**attempt))
