from __future__ import annotations

from multi_domain_ids.dataset_config import dataset_path, dataset_root_path
from multi_domain_ids.dataset_inventory import discover_dataset_files


def test_dataset_inventory_discovers_supported_files_recursively(tmp_path):
    root = tmp_path / "Downloads"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "train.csv").write_text("a\n1\n", encoding="utf-8")
    (nested / "auth.txt.gz").write_bytes(b"compressed")
    (nested / "notes.py").write_text("not data", encoding="utf-8")

    files = discover_dataset_files(root)

    assert [item["name"] for item in files] == ["auth.txt.gz", "train.csv"]
    assert files[0]["format"] == "gzip-compressed text"
    assert files[0]["size_bytes"] == len(b"compressed")


def test_dataset_paths_support_root_and_per_dataset_overrides(tmp_path, monkeypatch):
    root = tmp_path / "source-data"
    override = tmp_path / "custom-auth.gz"
    monkeypatch.setenv("MULTI_DOMAIN_IDS_DATASET_ROOT", str(root))
    monkeypatch.setenv("MULTI_DOMAIN_IDS_AUTH_PATH", str(override))

    assert dataset_root_path() == root.resolve()
    assert dataset_path("dns") == (root / "dns.txt.gz").resolve()
    assert dataset_path("auth") == override.resolve()
    assert dataset_path("auth", root / "explicit.gz") == (root / "explicit.gz").resolve()
