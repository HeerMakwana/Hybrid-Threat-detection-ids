from __future__ import annotations

import argparse
import json
from pathlib import Path

from .auth_processing import process_auth_dataset
from .dataset_config import dataset_path, dataset_root_path, output_directory
from .dataset_inventory import discover_dataset_files
from .domains import MultiDomainIDS
from .sqli_model import train_sqli_dataset
from .threat_intel import ThreatIntelScorer


def _demo_record() -> dict:
    return {
        "network": {
            "Flow Duration": 120.0,
            "Total Fwd Packets": 32,
            "Total Backward Packets": 28,
            "Total Length of Fwd Packets": 5000.0,
            "Total Length of Bwd Packets": 6000.0,
            "Fwd Packet Length Max": 100.0,
            "Fwd Packet Length Min": 40.0,
            "Fwd Packet Length Mean": 75.0,
            "Fwd Packet Length Std": 15.0,
            "Bwd Packet Length Max": 90.0,
            "Bwd Packet Length Min": 30.0,
            "Bwd Packet Length Mean": 65.0,
            "Bwd Packet Length Std": 12.0,
            "Flow Bytes/s": 120000.0,
            "Flow Packets/s": 1500.0,
            "Packet Length Mean": 80.0,
            "Packet Length Std": 18.0,
        },
        "sql": "SELECT * FROM users WHERE username='admin' OR 1=1",
        "host": {
            "cpu_usage": 0.91,
            "memory_usage": 0.87,
            "disk_usage": 0.72,
            "network_connections": 190,
            "parent_child_ratio": 2.2,
            "process_entropy": 0.92,
            "privilege_escalation": 1,
            "suspicious_process_count": 9,
        },
        "identity": {
            "failed_logins": 12,
            "successful_logins": 1,
            "new_device_logins": 3,
            "privilege_escalation": 1,
            "user_anomaly_score": 0.93,
            "time_window_lateral_movement": 2,
        },
        "dns": {
            "query_length": 92,
            "label_count": 4,
            "numeric_ratio": 0.7,
            "entropy_score": 0.95,
            "avg_subdomain_depth": 4.4,
            "is_malicious_tld": 1,
            "is_high_entropy": 1,
            "suspicious_dns_pattern": 1,
        },
        "source_ip": "203.0.113.10",
        "destination_ip": "198.51.100.54",
        "protocol": "TCP",
        "severity": "high",
        "suspicious": True,
    }


def train_demo() -> MultiDomainIDS:
    ids = MultiDomainIDS()
    ids.fit_demo()
    return ids


def evaluate_demo() -> dict:
    ids = train_demo()
    alert = ids.generate_alert(_demo_record())
    scorer = ThreatIntelScorer()
    enriched = scorer.assess_alert(alert)
    payload = {
        "alert": alert,
        "intel": enriched,
    }
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Domain Hybrid IDS CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("train-demo", help="Train a demo model across the five domains")
    subparsers.add_parser("evaluate-demo", help="Run a synthetic alert evaluation")
    inventory_parser = subparsers.add_parser(
        "dataset-inventory",
        help="Recursively list dataset-like files under a configurable root",
    )
    inventory_parser.add_argument("--root", help="Dataset root; defaults to Downloads")
    train_sqli_parser = subparsers.add_parser(
        "train-sqli",
        help="Train and evaluate the SQLi model from the actual combined SQLi CSV",
    )
    train_sqli_parser.add_argument(
        "--dataset",
        help="Path to the SQLi CSV (defaults to MULTI_DOMAIN_IDS_SQLI_PATH or dataset root)",
    )
    train_sqli_parser.add_argument(
        "--model-out",
        default="models/sqli_model.joblib",
        help="Output path for the locally ignored model artifact",
    )
    train_sqli_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Back up and replace an existing model artifact",
    )
    process_auth_parser = subparsers.add_parser(
        "process-auth",
        help="Stream LANL authentication records into a resumable aggregate report",
    )
    process_auth_parser.add_argument(
        "--dataset",
        help="Path to auth.txt.gz (defaults to MULTI_DOMAIN_IDS_AUTH_PATH or dataset root)",
    )
    process_auth_parser.add_argument(
        "--redteam",
        help="Path to redteam.txt.gz (defaults to MULTI_DOMAIN_IDS_REDTEAM_PATH or dataset root)",
    )
    process_auth_parser.add_argument(
        "--output-dir",
        help="Output directory (defaults to MULTI_DOMAIN_IDS_OUTPUT_DIR or ./artifacts)",
    )
    process_auth_parser.add_argument("--chunksize", type=int, default=100_000)
    process_auth_parser.add_argument("--annotation-window-seconds", type=int, default=300)
    process_auth_parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Refuse to resume from an existing checkpoint",
    )

    args = parser.parse_args()

    if args.command == "train-demo":
        ids = train_demo()
        print(json.dumps(ids.predict(_demo_record()), indent=2))
    elif args.command == "evaluate-demo":
        result = evaluate_demo()
        print(json.dumps(result, indent=2))
    elif args.command == "dataset-inventory":
        print(
            json.dumps(
                {
                    "root": str(dataset_root_path(args.root)),
                    "files": discover_dataset_files(dataset_root_path(args.root)),
                },
                indent=2,
            )
        )
    elif args.command == "train-sqli":
        _, report = train_sqli_dataset(
            dataset_path("sqli", args.dataset),
            model_out=Path(args.model_out),
            overwrite=args.overwrite,
        )
        print(json.dumps(report, indent=2))
    elif args.command == "process-auth":
        auth_path = dataset_path("auth", args.dataset)
        redteam_path = dataset_path("redteam", args.redteam)
        report = process_auth_dataset(
            auth_path,
            output_directory(args.output_dir) / "identity",
            redteam_path=redteam_path,
            chunksize=args.chunksize,
            annotation_window_seconds=args.annotation_window_seconds,
            resume=not args.no_resume,
            progress_callback=_auth_progress(),
        )
        print(json.dumps(report, indent=2))


def _auth_progress():
    last_reported_rows = 0

    def report_progress(report: dict) -> None:
        nonlocal last_reported_rows
        processed_rows = int(report["processed_rows"])
        if processed_rows - last_reported_rows >= 1_000_000:
            print(
                json.dumps(
                    {
                        "status": "processing",
                        "records_seen": report["records_seen"],
                        "processed_rows": processed_rows,
                        "elapsed_seconds": report["elapsed_seconds"],
                        "rows_per_second": report["rows_per_second"],
                    }
                ),
                flush=True,
            )
            last_reported_rows = processed_rows

    return report_progress


if __name__ == "__main__":
    main()
