from __future__ import annotations

import csv
from dataclasses import dataclass
import gzip
from pathlib import Path
from typing import IO, Callable, Iterator
import zipfile
import zlib

import pandas as pd

from .feature_extractor import CICIDS_FEATURES

SQLI_FEATURE_COLUMNS = (
    "query_length",
    "word_count",
    "special_char_count",
    "digit_count",
    "contains_select",
    "contains_union",
    "contains_insert",
    "contains_update",
    "contains_delete",
    "contains_where",
    "contains_and",
    "contains_or",
    "keyword_ratio",
    "contains_double_dash",
    "contains_comment",
    "contains_semicolon",
    "contains_single_quote",
    "contains_double_quote",
    "contains_equals",
    "contains_sleep",
    "max_word_length",
    "min_word_length",
    "uppercase_count",
    "special_char_ratio",
    "Query_Entropy",
    "Query_Digit_Ratio",
)

LANL_COLUMN_NAMES = {
    "auth": (
        "time",
        "source_user_domain",
        "destination_user_domain",
        "source_computer",
        "destination_computer",
        "authentication_type",
        "logon_type",
        "authentication_orientation",
        "success_failure",
    ),
    "dns": ("time", "source_computer", "resolved_computer"),
    "flows": (
        "time",
        "duration",
        "source_computer",
        "source_port",
        "destination_computer",
        "destination_port",
        "protocol",
        "packet_count",
        "byte_count",
    ),
    "redteam": (
        "time",
        "user_domain",
        "source_computer",
        "destination_computer",
    ),
    "proc": ("time", "user_domain", "computer", "process_name", "start_end"),
}

LANL_DOCUMENTED_ONLY_COLUMNS = {
    dataset: LANL_COLUMN_NAMES[dataset] for dataset in ("auth", "proc")
}

LANL_POSITIONAL_FIELD_COUNTS = {
    dataset: len(columns) for dataset, columns in LANL_COLUMN_NAMES.items()
}

CICIDS2017_LABELS = {
    "benign",
    "bot",
    "ddos",
    "dos goldeneye",
    "dos hulk",
    "dos slowhttptest",
    "dos slowloris",
    "ftp-patator",
    "heartbleed",
    "infiltration",
    "portscan",
    "ssh-patator",
    "web attack - brute force",
    "web attack - sql injection",
    "web attack - xss",
}

TON_IOT_ATTACK_TYPES = {
    "backdoor",
    "ddos",
    "dos",
    "injection",
    "mitm",
    "normal",
    "password",
    "ransomware",
    "scanning",
    "xss",
}


@dataclass(frozen=True)
class LabeledDataset:
    features: pd.DataFrame
    labels: pd.Series
    class_names: pd.Series
    raw_input: pd.Series | None = None


def _clean_column_names(frame: pd.DataFrame) -> pd.DataFrame:
    names = [str(column).lstrip("\ufeff").strip() for column in frame.columns]
    if len(names) != len(set(names)):
        raise ValueError("Dataset contains duplicate column names after whitespace normalization")
    frame.columns = names
    return frame


def _binary_labels(
    values: pd.Series,
    *,
    dataset_name: str,
    benign_names: set[str],
    allowed_names: set[str] | None = None,
) -> tuple[pd.Series, pd.Series]:
    names = values.astype("string").str.strip()
    normalized = (
        names.str.lower()
        .str.replace("\u2013", "-", regex=False)
        .str.replace("\u2014", "-", regex=False)
    )
    if names.isna().any() or names.eq("").any():
        raise ValueError(f"{dataset_name} contains empty labels")
    if allowed_names is not None:
        unknown = set(normalized.unique()) - allowed_names
        if unknown:
            raise ValueError(f"{dataset_name} contains unsupported labels: {sorted(unknown)}")
    target = (~normalized.isin(benign_names)).astype("int8")
    target.name = "target"
    names.name = values.name
    return target, names


def _numeric_features(
    frame: pd.DataFrame,
    columns: tuple[str, ...],
    *,
    dataset_name: str,
) -> pd.DataFrame:
    features = frame.loc[:, columns].copy()
    for column in columns:
        numeric = pd.to_numeric(features[column], errors="coerce")
        invalid = features[column].notna() & numeric.isna()
        if invalid.any():
            raise ValueError(
                f"{dataset_name} feature {column!r} contains non-numeric values"
            )
        features[column] = numeric
    return features


def validate_zip_archive(path: str | Path) -> None:
    """Raise when a ZIP is incomplete or any member fails its CRC check."""
    try:
        with zipfile.ZipFile(path) as archive:
            corrupt_member = archive.testzip()
    except (zipfile.BadZipFile, OSError, EOFError, zlib.error) as exc:
        raise ValueError(f"Invalid or incomplete ZIP archive: {exc}") from exc
    if corrupt_member is not None:
        raise ValueError(f"ZIP member failed its CRC check: {corrupt_member}")


def load_cicids2017_csv(path: str | Path) -> LabeledDataset:
    """Load CICIDS flow rows into the legacy model's exact 17-feature order."""
    frame = _clean_column_names(pd.read_csv(path, encoding="utf-8-sig", low_memory=False))
    label_column = next((name for name in frame.columns if name.lower() == "label"), None)
    if label_column is None:
        raise ValueError("CICIDS CSV is missing its Label column")

    missing = [column for column in CICIDS_FEATURES if column not in frame.columns]
    if missing:
        raise ValueError(f"CICIDS CSV is missing required model features: {missing}")

    features = _numeric_features(frame, CICIDS_FEATURES, dataset_name="CICIDS")
    labels, class_names = _binary_labels(
        frame[label_column],
        dataset_name="CICIDS",
        benign_names={"benign"},
        allowed_names=CICIDS2017_LABELS,
    )
    return LabeledDataset(features, labels, class_names)


def load_sqli_csv(path: str | Path) -> LabeledDataset:
    """Load the combined SQLi CSV without mixing query text with flow features."""
    frame = _clean_column_names(pd.read_csv(path, encoding="utf-8-sig", low_memory=False))
    label_column = next((name for name in frame.columns if name.lower() == "type attack"), None)
    if label_column is None:
        raise ValueError("SQLi CSV is missing its Type Attack label column")

    missing = [column for column in SQLI_FEATURE_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"SQLi CSV is missing required feature columns: {missing}")

    query_column = next((name for name in frame.columns if name.lower() == "query"), None)
    features = _numeric_features(frame, SQLI_FEATURE_COLUMNS, dataset_name="SQLi")

    labels, class_names = _binary_labels(
        frame[label_column],
        dataset_name="SQLi",
        benign_names={"normal"},
        allowed_names={"normal", "malicious"},
    )
    raw_input = frame[query_column].astype("string") if query_column else None
    return LabeledDataset(features, labels, class_names, raw_input)


def _convert_ton_features(features: pd.DataFrame) -> pd.DataFrame:
    converted = features.copy()
    for column in converted.columns:
        values = converted[column].astype("string").str.strip()
        values = values.mask(values.eq(""), pd.NA)
        numeric = pd.to_numeric(values, errors="coerce")
        if (numeric.notna() | values.isna()).all():
            converted[column] = numeric
        else:
            converted[column] = values
    return converted


def iter_ton_iot_csv(
    path: str | Path | IO[bytes] | IO[str],
    *,
    chunksize: int = 100_000,
) -> Iterator[LabeledDataset]:
    """Stream one ToN-IoT CSV; each source file keeps its own feature schema."""
    if chunksize <= 0:
        raise ValueError("chunksize must be greater than zero")

    reader = pd.read_csv(
        path,
        encoding="utf-8-sig",
        dtype="string",
        chunksize=chunksize,
        on_bad_lines="error",
    )
    for raw_chunk in reader:
        chunk = _clean_column_names(raw_chunk)
        label_column = next((name for name in chunk.columns if name.lower() == "label"), None)
        if label_column is None:
            raise ValueError(f"ToN-IoT CSV {path!s} is missing its label column")
        class_column = next((name for name in chunk.columns if name.lower() == "type"), None)

        numeric_labels = pd.to_numeric(chunk[label_column].str.strip(), errors="coerce")
        if numeric_labels.isna().any() or not set(numeric_labels.unique()).issubset({0, 1}):
            raise ValueError(f"ToN-IoT CSV {path!s} must have binary 0/1 labels")

        excluded = [label_column]
        if class_column is not None:
            excluded.append(class_column)
            class_names = chunk[class_column].astype("string").str.strip()
            normalized_types = (
                class_names.str.lower()
                .str.replace("\u2013", "-", regex=False)
                .str.replace("\u2014", "-", regex=False)
            )
            if (
                normalized_types.isna().any()
                or normalized_types.eq("").any()
                or not set(normalized_types.unique()).issubset(TON_IOT_ATTACK_TYPES)
            ):
                raise ValueError(f"ToN-IoT CSV {path!s} contains unsupported type values")
            type_is_normal = normalized_types.eq("normal")
            if not (numeric_labels.eq(0) == type_is_normal).all():
                raise ValueError(
                    f"ToN-IoT CSV {path!s} has inconsistent label and type columns"
                )
        features = _convert_ton_features(chunk.drop(columns=excluded))
        labels = numeric_labels.astype("int8")
        labels.name = "target"
        class_names = (
            class_names
            if class_column is not None
            else chunk[label_column].astype("string").str.strip()
        )
        class_names.name = class_column or label_column
        yield LabeledDataset(features, labels, class_names)


def iter_lanl_chunks(
    dataset: str,
    path: str | Path,
    *,
    chunksize: int = 100_000,
    malformed_rows: str = "raise",
    malformed_row_handler: Callable[[int, int, int], None] | None = None,
    skip_records: int = 0,
) -> Iterator[pd.DataFrame]:
    """Read headerless LANL records with documented names and strict row widths.

    Names follow the official LANL format descriptions. Authentication and
    process schemas are validated against the locally downloaded files;
    documented missing-value placeholders are normalized, and no binary
    labels are fabricated.
    """
    if chunksize <= 0:
        raise ValueError("chunksize must be greater than zero")
    if malformed_rows not in {"raise", "skip"}:
        raise ValueError("malformed_rows must be either 'raise' or 'skip'")
    if skip_records < 0:
        raise ValueError("skip_records must not be negative")
    if dataset not in LANL_POSITIONAL_FIELD_COUNTS:
        raise ValueError(
            f"No verified positional schema for LANL {dataset!r}"
        )

    columns = LANL_COLUMN_NAMES[dataset]
    source = Path(path)
    opener = gzip.open if source.suffix.lower() == ".gz" else open
    with opener(source, "rt", encoding="utf-8", newline="") as stream:
        rows: list[list[str]] = []
        record_number = 0
        chunk_start_record = skip_records + 1
        chunk_malformed = 0
        for row in csv.reader(stream, strict=True):
            record_number += 1
            if record_number <= skip_records:
                continue
            if len(row) != len(columns):
                if malformed_rows == "raise":
                    raise ValueError(
                        f"LANL {dataset} row {record_number} has {len(row)} fields; "
                        f"expected {len(columns)}"
                    )
                chunk_malformed += 1
                if malformed_row_handler is not None:
                    malformed_row_handler(record_number, len(row), len(columns))
                continue
            rows.append([value.strip() for value in row])
            if len(rows) == chunksize:
                frame = _lanl_frame(rows, columns)
                frame.attrs["source_record_start"] = chunk_start_record
                frame.attrs["source_record_end"] = record_number
                frame.attrs["malformed_rows"] = chunk_malformed
                yield frame
                rows = []
                chunk_malformed = 0
                chunk_start_record = record_number + 1
        if rows or chunk_malformed:
            frame = _lanl_frame(rows, columns)
            frame.attrs["source_record_start"] = chunk_start_record
            frame.attrs["source_record_end"] = record_number
            frame.attrs["malformed_rows"] = chunk_malformed
            yield frame


def _lanl_frame(rows: list[list[str]], columns: tuple[str, ...]) -> pd.DataFrame:
    frame = pd.DataFrame(rows, columns=columns, dtype="string")
    for column in columns:
        frame[column] = frame[column].mask(frame[column].isin(["", "?"]), pd.NA)
    return frame
