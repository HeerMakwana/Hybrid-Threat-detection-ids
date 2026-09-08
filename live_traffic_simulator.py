"""Replay labeled flow data as a live IDS stream and emit Wazuh-ready JSONL events."""

import argparse
import os
from itertools import cycle
import time

import pandas as pd

from detection.streaming_detector import StreamingDetector, infer_attack_type
from siem.wazuh_adapter import WazuhJsonlAdapter


SCENARIO_FILTERS = {
    "mixed": None,
    "portscan": ["portscan"],
    "ddos": ["ddos"],
    "bruteforce": ["ftp-patator", "ssh-patator", "brute force", "web attack brute force"],
    "dos": ["dos"],
    "attackburst": "__ATTACKS_ONLY__",
}


def _normalize_label(value):
    return str(value).strip().lower()


def _repeat_frame(frame, limit):
    if limit is None or len(frame) >= limit:
        return frame.head(limit) if limit is not None else frame

    rows = []
    source_rows = list(frame.itertuples(index=False, name=None))
    for row in cycle(source_rows):
        rows.append(row)
        if len(rows) >= limit:
            break

    return pd.DataFrame(rows, columns=frame.columns)


def load_demo_rows(data_path, scenario="mixed", limit=None):
    frame = pd.read_csv(data_path)
    if scenario not in SCENARIO_FILTERS:
        raise ValueError(f"Unknown scenario: {scenario}")

    label_column = next((column for column in frame.columns if _normalize_label(column) in {"label", "class", "attack", "target"}), None)
    if label_column and SCENARIO_FILTERS[scenario] == "__ATTACKS_ONLY__":
        filtered = frame[~frame[label_column].astype(str).str.upper().isin({"BENIGN", "NORMAL"})]
        if filtered.empty:
            filtered = frame
        filtered = filtered.reset_index(drop=True)
        return _repeat_frame(filtered, limit)

    if label_column and SCENARIO_FILTERS[scenario]:
        labels = SCENARIO_FILTERS[scenario]
        filtered = frame[frame[label_column].astype(str).str.lower().apply(lambda value: any(label in value for label in labels))]
        if filtered.empty:
            filtered = frame
    else:
        filtered = frame

    if limit is not None:
        filtered = filtered.head(limit)
    filtered = filtered.reset_index(drop=True)
    return _repeat_frame(filtered, limit)


def print_banner(scenario, source_path, total_rows, delay):
    print("+------------------------------------------+")
    print("|       LIVE TRAFFIC SIMULATOR             |")
    print("+------------------------------------------+")
    print(f"| Scenario: {scenario:<30}|")
    print(f"| Source: {os.path.basename(source_path):<32}|")
    print(f"| Flows: {total_rows:<34}|")
    print(f"| Delay: {delay:<35}|")
    print("+------------------------------------------+")


def run_live_simulation(
    model_path,
    data_path,
    output_path,
    scenario="mixed",
    delay=0.5,
    limit=None,
    threshold=None,
    alerts_only=False,
    overwrite=False,
    target_alerts=None,
):
    detector = StreamingDetector(model_path=model_path, threshold=threshold)
    writer = WazuhJsonlAdapter(output_path=output_path, overwrite=overwrite)
    rows = load_demo_rows(data_path, scenario=scenario, limit=limit)

    print_banner(scenario, data_path, len(rows), delay)
    print(f"[INFO] Writing Wazuh events to: {writer.output_path}")
    print(f"[INFO] Detector threshold: {detector.threshold:.4f}")

    alerts_written = 0
    row_items = list(rows.iterrows())
    if not row_items:
        print("[WARN] No rows available for replay.")
        return

    max_iterations = target_alerts * 10 if target_alerts is not None else len(row_items)
    row_iterator = cycle(row_items) if target_alerts is not None else iter(row_items)

    for index, (_, row) in enumerate(row_iterator, start=1):
        result = detector.process_record(row, sequence_number=index)
        attack_type = infer_attack_type(row)
        source_ip = result.legacy_alert.get("source_ip") if result.legacy_alert else None
        destination_ip = result.legacy_alert.get("destination_ip") if result.legacy_alert else None
        print(f"[{time.strftime('%H:%M:%S')}] FLOW #{index:03d}")
        print(f"  Source: {source_ip or 'unknown'}")
        print(f"  Destination: {destination_ip or 'unknown'}")
        print(f"  Prediction: {result.prediction}")
        print(f"  Confidence: {result.confidence:.4f}")

        if result.security_event is not None:
            writer.append(result.security_event)
            alerts_written += 1
            print(f"  Attack: {attack_type or 'Unknown'}")
            print(f"  Risk: {result.risk['score']}/100 ({result.risk['severity'].upper()})")
            print(f"  MITRE: {result.security_event['mitre']['technique'] or 'N/A'}")
            print(f"  Wazuh: event appended to {writer.output_path}")
        elif not alerts_only:
            print("  Status: benign")

        if target_alerts is not None and alerts_written >= target_alerts:
            break

        if target_alerts is not None and index >= max_iterations and alerts_written < target_alerts:
            print(f"[WARN] Stopped after {index} replayed rows with only {alerts_written} alerts written.")
            break

        if delay > 0:
            time.sleep(delay)

    print(f"[INFO] Alerts written: {alerts_written}")


def main():
    parser = argparse.ArgumentParser(description="Replay labeled flow data as a live stream for Wazuh ingestion")
    parser.add_argument("--model", default="models/final_model.joblib", help="Path to the trained model artifact")
    parser.add_argument("--data", default="data/simulation_data.csv", help="Path to the labeled flow CSV")
    parser.add_argument("--output", default="logs/live_security_events.jsonl", help="Wazuh-monitored JSONL output file")
    parser.add_argument("--scenario", default="mixed", choices=sorted(SCENARIO_FILTERS), help="Replay scenario")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between flows in seconds")
    parser.add_argument("--limit", type=int, default=None, help="Optional row limit for the replay")
    parser.add_argument("--threshold", type=float, default=None, help="Override the model operating threshold")
    parser.add_argument("--alerts-only", action="store_true", help="Only print and write alert events")
    parser.add_argument("--overwrite", action="store_true", help="Truncate the output file before writing")
    parser.add_argument("--target-alerts", type=int, default=None, help="Stop after writing this many alerts")
    args = parser.parse_args()

    run_live_simulation(
        model_path=args.model,
        data_path=args.data,
        output_path=args.output,
        scenario=args.scenario,
        delay=args.delay,
        limit=args.limit,
        threshold=args.threshold,
        alerts_only=args.alerts_only,
        overwrite=args.overwrite,
        target_alerts=args.target_alerts,
    )


if __name__ == "__main__":
    main()