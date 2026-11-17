from __future__ import annotations

import gzip
import io
import zipfile

import pandas as pd
import pytest

from multi_domain_ids.dataset_loaders import (
    LANL_COLUMN_NAMES,
    LANL_DOCUMENTED_ONLY_COLUMNS,
    LANL_POSITIONAL_FIELD_COUNTS,
    SQLI_FEATURE_COLUMNS,
    iter_lanl_chunks,
    iter_ton_iot_csv,
    load_cicids2017_csv,
    load_sqli_csv,
    validate_zip_archive,
)
from multi_domain_ids.feature_extractor import CICIDS_FEATURES


def test_cicids_loader_preserves_legacy_model_feature_order(tmp_path):
    source = tmp_path / "cicids_sample.csv"
    frame = pd.DataFrame(
        {
            f" {column} ": [index + 1, index + 2]
            for index, column in enumerate(CICIDS_FEATURES)
        }
    )
    frame[" Label "] = ["BENIGN", "DDoS"]
    frame.to_csv(source, index=False)

    dataset = load_cicids2017_csv(source)

    assert list(dataset.features.columns) == CICIDS_FEATURES
    assert dataset.labels.tolist() == [0, 1]
    assert dataset.class_names.tolist() == ["BENIGN", "DDoS"]
    assert "Label" not in dataset.features.columns


def test_sqli_loader_uses_dataset_schema_and_keeps_query_separate(tmp_path):
    source = tmp_path / "sqli.csv"
    frame = pd.DataFrame(
        {
            "Query": ["SELECT 'a,b' FROM t", "plain input"],
            "Type Attack": ["Malicious", "Normal"],
            **{column: [1, 0] for column in SQLI_FEATURE_COLUMNS},
        }
    )
    frame.to_csv(source, index=False)

    dataset = load_sqli_csv(source)

    assert list(dataset.features.columns) == list(SQLI_FEATURE_COLUMNS)
    assert dataset.labels.tolist() == [1, 0]
    assert dataset.class_names.tolist() == ["Malicious", "Normal"]
    assert dataset.raw_input.tolist() == ["SELECT 'a,b' FROM t", "plain input"]
    assert "Query" not in dataset.features.columns
    assert "Type Attack" not in dataset.features.columns


def test_ton_iot_loader_preserves_independent_file_schemas(tmp_path):
    network_path = tmp_path / "network.csv"
    iot_path = tmp_path / "iot.csv"
    pd.DataFrame(
        {
            "ts": ["1", "2"],
            "src_ip": ["192.0.2.1", "192.0.2.2"],
            "label": ["0", "1"],
            "type": ["normal", "scanning"],
        }
    ).to_csv(network_path, index=False)
    pd.DataFrame(
        {
            "date": ["01-Jan-19", "01-Jan-19"],
            "temperature": ["20.5", "22.0"],
            "label": ["0", "1"],
            "type": ["normal", "ddos"],
        }
    ).to_csv(iot_path, index=False)

    network = next(iter_ton_iot_csv(network_path, chunksize=2))
    iot = next(iter_ton_iot_csv(iot_path, chunksize=2))

    assert list(network.features.columns) == ["ts", "src_ip"]
    assert list(iot.features.columns) == ["date", "temperature"]
    assert network.labels.tolist() == [0, 1]
    assert iot.features["temperature"].tolist() == [20.5, 22.0]
    assert network.class_names.tolist() == ["normal", "scanning"]
    assert "label" not in network.features.columns
    assert "type" not in network.features.columns


def test_ton_iot_loader_accepts_a_streamed_csv_member():
    source = io.BytesIO(
        b"date,time,temperature,label,type\n"
        b"01-Jan-19,12:00,20.5,0,normal\n"
        b"01-Jan-19,12:01,22.0,1,ddos\n"
    )

    dataset = next(iter_ton_iot_csv(source, chunksize=1))

    assert list(dataset.features.columns) == ["date", "time", "temperature"]
    assert dataset.labels.tolist() == [0]
    assert dataset.features["temperature"].tolist() == [20.5]


@pytest.mark.parametrize(
    ("dataset_name", "row"),
    [
        ("dns", "2,C4653,C5030\n"),
        ("flows", "1,0,C1065,389,C3799,N10451,6,10,5323\n"),
        ("redteam", "150885,U620@DOM1,C17693,C1003\n"),
    ],
)
def test_lanl_positional_widths_match_observed_files(tmp_path, dataset_name, row):
    source = tmp_path / f"{dataset_name}.txt.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        stream.write(row)

    chunk = next(iter_lanl_chunks(dataset_name, source))

    assert chunk.shape == (1, LANL_POSITIONAL_FIELD_COUNTS[dataset_name])
    assert chunk.columns.tolist() == list(LANL_COLUMN_NAMES[dataset_name])
    assert chunk.iloc[0, 0] == row.split(",", 1)[0]


def test_lanl_loader_uses_observed_positional_fields_without_labeling(tmp_path):
    source = tmp_path / "dns.txt.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        stream.write("2,C4653,C5030\n6,C1191,C419\n")

    chunks = list(iter_lanl_chunks("dns", source, chunksize=1))

    assert LANL_POSITIONAL_FIELD_COUNTS["dns"] == 3
    assert len(chunks) == 2
    assert chunks[0].columns.tolist() == ["time", "source_computer", "resolved_computer"]
    assert chunks[1].iloc[0].tolist() == ["6", "C1191", "C419"]


def test_lanl_auth_and_proc_schemas_are_documented_and_supported():
    assert len(LANL_DOCUMENTED_ONLY_COLUMNS["auth"]) == 9
    assert len(LANL_DOCUMENTED_ONLY_COLUMNS["proc"]) == 5
    assert LANL_POSITIONAL_FIELD_COUNTS["auth"] == 9
    assert LANL_POSITIONAL_FIELD_COUNTS["proc"] == 5


@pytest.mark.parametrize(
    ("dataset_name", "row"),
    [
        ("auth", "1,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n"),
        ("proc", "1,U1@DOM1,C1,P1,Start\n"),
    ],
)
def test_lanl_auth_and_proc_rows_use_verified_local_schemas(tmp_path, dataset_name, row):
    source = tmp_path / f"{dataset_name}.txt.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        stream.write(row)

    frame = next(iter_lanl_chunks(dataset_name, source))

    assert frame.columns.tolist() == list(LANL_COLUMN_NAMES[dataset_name])
    assert frame.shape[1] == LANL_POSITIONAL_FIELD_COUNTS[dataset_name]


def test_lanl_can_skip_and_report_malformed_records(tmp_path):
    source = tmp_path / "auth_malformed.txt.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        stream.write("1,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n")
        stream.write("2,malformed,row\n")
        stream.write("3,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Failure\n")
    malformed = []

    chunks = list(
        iter_lanl_chunks(
            "auth",
            source,
            chunksize=1,
            malformed_rows="skip",
            malformed_row_handler=lambda *entry: malformed.append(entry),
        )
    )

    assert [len(chunk) for chunk in chunks] == [1, 1]
    assert chunks[-1].attrs["source_record_end"] == 3
    assert sum(chunk.attrs["malformed_rows"] for chunk in chunks) == 1
    assert malformed == [(2, 3, 9)]


def test_lanl_rejects_rows_with_missing_or_extra_fields(tmp_path):
    source = tmp_path / "malformed_dns.txt.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        stream.write("2,C4653,C5030\n3,C1191\n")

    chunks = iter_lanl_chunks("dns", source, chunksize=1)
    next(chunks)
    with pytest.raises(ValueError, match="row 2 has 2 fields; expected 3"):
        next(chunks)


def test_lanl_documented_question_mark_placeholders_become_missing(tmp_path):
    source = tmp_path / "dns_missing_value.txt.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        stream.write("2,?,C5030\n")

    chunk = next(iter_lanl_chunks("dns", source))

    assert pd.isna(chunk.loc[0, "source_computer"])


def test_cicids_rejects_unknown_labels_and_missing_required_features(tmp_path):
    source = tmp_path / "cicids_invalid.csv"
    frame = pd.DataFrame({column: [1] for column in CICIDS_FEATURES})
    frame["Label"] = ["ransomware"]
    frame.to_csv(source, index=False)
    with pytest.raises(ValueError, match="unsupported labels"):
        load_cicids2017_csv(source)

    frame = frame.drop(columns=[CICIDS_FEATURES[0]])
    frame["Label"] = ["BENIGN"]
    frame.to_csv(source, index=False)
    with pytest.raises(ValueError, match="missing required model features"):
        load_cicids2017_csv(source)


def test_cicids_preserves_missing_numeric_values_instead_of_imputing_zero(tmp_path):
    source = tmp_path / "cicids_missing.csv"
    frame = pd.DataFrame({column: [1] for column in CICIDS_FEATURES})
    frame.loc[0, "Flow Bytes/s"] = float("nan")
    frame["Label"] = ["BENIGN"]
    frame.to_csv(source, index=False)

    dataset = load_cicids2017_csv(source)

    assert pd.isna(dataset.features.loc[0, "Flow Bytes/s"])


def test_cicids_rejects_non_numeric_feature_values(tmp_path):
    source = tmp_path / "cicids_non_numeric.csv"
    frame = pd.DataFrame(
        {
            column: ["not-a-number" if index == 0 else "1"]
            for index, column in enumerate(CICIDS_FEATURES)
        }
    )
    frame["Label"] = ["BENIGN"]
    frame.to_csv(source, index=False)

    with pytest.raises(ValueError, match="contains non-numeric values"):
        load_cicids2017_csv(source)


def test_sqli_rejects_unknown_labels_and_missing_required_columns(tmp_path):
    source = tmp_path / "sqli_invalid.csv"
    frame = pd.DataFrame({column: [1] for column in SQLI_FEATURE_COLUMNS})
    frame["Type Attack"] = ["Attack"]
    frame.to_csv(source, index=False)
    with pytest.raises(ValueError, match="unsupported labels"):
        load_sqli_csv(source)

    frame = frame.drop(columns=[SQLI_FEATURE_COLUMNS[0]])
    frame["Type Attack"] = ["Normal"]
    frame.to_csv(source, index=False)
    with pytest.raises(ValueError, match="missing required feature columns"):
        load_sqli_csv(source)


def test_ton_iot_rejects_missing_label_invalid_labels_and_label_type_mismatch(tmp_path):
    source = tmp_path / "ton_invalid.csv"
    pd.DataFrame({"value": [1], "type": ["normal"]}).to_csv(source, index=False)
    with pytest.raises(ValueError, match="missing its label column"):
        next(iter_ton_iot_csv(source))

    pd.DataFrame({"value": [1], "label": [2], "type": ["normal"]}).to_csv(
        source, index=False
    )
    with pytest.raises(ValueError, match="binary 0/1"):
        next(iter_ton_iot_csv(source))

    pd.DataFrame({"value": [1], "label": [1], "type": ["normal"]}).to_csv(
        source, index=False
    )
    with pytest.raises(ValueError, match="inconsistent label and type"):
        next(iter_ton_iot_csv(source))

    pd.DataFrame({"value": [1], "label": [1], "type": ["unfamiliar"]}).to_csv(
        source, index=False
    )
    with pytest.raises(ValueError, match="unsupported type values"):
        next(iter_ton_iot_csv(source))


def test_cicids_rejects_malformed_csv_rows(tmp_path):
    source = tmp_path / "cicids_malformed.csv"
    frame = pd.DataFrame({column: [1] for column in CICIDS_FEATURES})
    frame["Label"] = ["BENIGN"]
    frame.to_csv(source, index=False)
    with source.open("a", encoding="utf-8") as stream:
        stream.write(",".join(["extra"] * (len(CICIDS_FEATURES) + 2)) + "\n")

    with pytest.raises(pd.errors.ParserError):
        load_cicids2017_csv(source)


def test_zip_validator_accepts_complete_archive_and_rejects_truncation(tmp_path):
    source = tmp_path / "complete.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("data.csv", "value\n1\n")

    validate_zip_archive(source)

    truncated = tmp_path / "truncated.zip"
    truncated.write_bytes(source.read_bytes()[:-10])
    with pytest.raises(ValueError, match="Invalid or incomplete ZIP archive"):
        validate_zip_archive(truncated)


def test_zip_validator_rejects_corrupt_member_crc(tmp_path):
    source = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("data.csv", "value\n1\n")

    contents = bytearray(source.read_bytes())
    payload_offset = contents.index(b"value\n1\n")
    contents[payload_offset] ^= 1
    source.write_bytes(contents)

    with pytest.raises(ValueError, match="failed its CRC check"):
        validate_zip_archive(source)
