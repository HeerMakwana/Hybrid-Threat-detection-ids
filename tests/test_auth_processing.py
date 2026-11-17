from __future__ import annotations

import gzip
import json

import pytest

from multi_domain_ids.auth_processing import process_auth_dataset


def _write_auth(path, rows):
    with gzip.open(path, "wt", encoding="utf-8", newline="") as stream:
        stream.writelines(rows)


def test_auth_processor_counts_records_and_joins_redteam_with_time_window(tmp_path):
    auth_path = tmp_path / "auth.txt.gz"
    redteam_path = tmp_path / "redteam.txt.gz"
    _write_auth(
        auth_path,
        [
            "100,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Failure\n",
            "200,U3@DOM1,U4@DOM1,C3,C4,NTLM,Network,LogOn,Success\n",
            "300,U5@DOM1,U6@DOM1,C5,C6,NTLM,Network,LogOn,Fail\n",
        ],
    )
    _write_auth(redteam_path, ["101,U1@DOM1,C1,C2\n"])

    report = process_auth_dataset(
        auth_path,
        tmp_path / "output",
        redteam_path=redteam_path,
        annotation_window_seconds=5,
        chunksize=1,
    )

    assert report["status"] == "completed"
    assert report["processed_rows"] == 3
    assert report["features"]["failed_authentication_rows"] == 2
    assert report["features"]["successful_authentication_rows"] == 1
    assert report["features"]["failure_ratio"] == pytest.approx(2 / 3)
    assert report["redteam_annotation_join"]["matched_annotation_rows"] == 1
    assert report["redteam_annotation_join"]["associated_authentication_rows"] == 1
    assert report["redteam_annotation_join"]["dataset_path"] == str(
        redteam_path.resolve()
    )
    assert report["redteam_annotation_join"]["used_as_inference_feature"] is False

    summary_path = tmp_path / "output" / "auth_processing_summary.json"
    summary_path.write_text(
        json.dumps({"status": "completed", "features": {"failed_authentication_rows": 0}}),
        encoding="utf-8",
    )
    refreshed_report = process_auth_dataset(
        auth_path,
        tmp_path / "output",
        redteam_path=redteam_path,
        annotation_window_seconds=5,
        chunksize=1,
    )

    assert refreshed_report["features"]["failed_authentication_rows"] == 2


def test_auth_processor_logs_and_skips_malformed_rows(tmp_path):
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth(
        auth_path,
        [
            "1,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n",
            "2,bad,row\n",
        ],
    )

    report = process_auth_dataset(auth_path, tmp_path / "output", chunksize=1)
    error_path = tmp_path / "output" / "auth_processing_errors.jsonl"

    assert report["records_seen"] == 2
    assert report["processed_rows"] == 1
    assert report["malformed_rows"] == 1
    assert json.loads(error_path.read_text(encoding="utf-8"))["record_number"] == 2


def test_auth_processor_resumes_from_last_checkpoint_without_duplicate_counts(tmp_path):
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth(
        auth_path,
        [
            "1,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Failure\n",
            "2,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n",
            "3,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n",
        ],
    )
    output = tmp_path / "output"
    callback_calls = 0

    def interrupt_after_first_chunk(_report):
        nonlocal callback_calls
        callback_calls += 1
        if callback_calls == 1:
            raise RuntimeError("controlled interruption")

    with pytest.raises(RuntimeError, match="controlled interruption"):
        process_auth_dataset(
            auth_path,
            output,
            chunksize=1,
            progress_callback=interrupt_after_first_chunk,
        )

    report = process_auth_dataset(auth_path, output, chunksize=1)

    assert report["resumed"] is True
    assert report["records_seen"] == 3
    assert report["processed_rows"] == 3
    assert report["authentication_outcomes"] == {"failure": 1, "success": 2}


def test_atomic_checkpoint_retries_transient_windows_replace_lock(tmp_path, monkeypatch):
    from pathlib import Path

    from multi_domain_ids.auth_processing import _write_json_atomic

    original_replace = Path.replace
    attempts = []

    def replace_once_locked(source, destination):
        attempts.append(None)
        if len(attempts) == 1:
            raise PermissionError("temporary Windows file lock")
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", replace_once_locked)
    checkpoint = tmp_path / "checkpoint.json"

    _write_json_atomic(checkpoint, {"records_seen": 12})

    assert len(attempts) == 2
    assert json.loads(checkpoint.read_text(encoding="utf-8")) == {
        "records_seen": 12
    }
