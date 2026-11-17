"""Capture packets, build bounded flow windows, and emit IDS/Wazuh events."""

import argparse
import pandas as pd
import pyshark

from feature_extractor import PacketWindow, pkt_to_minimal_features
from detection.streaming_detector import StreamingDetector
from siem.wazuh_adapter import WazuhJsonlAdapter


def run_capture(model_path, interface, output_path, bpf_filter=None, flow_timeout=5.0):
    detector = StreamingDetector(model_path=model_path)
    writer = WazuhJsonlAdapter(output_path=output_path)
    window = PacketWindow(timeout=flow_timeout)
    sequence = 0
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    print(f"Capturing on {interface}; flow timeout={flow_timeout:.1f}s")
    try:
        for packet in capture.sniff_continuously():
            packet_data = pkt_to_minimal_features(packet)
            packet_data["length"] = packet_data.pop("pkt_len")
            key = window.add_packet(packet_data)
            for expired_key, flow in window.expire(packet_data["ts"]):
                if flow is None:
                    continue
                flow.update({
                    "source_ip": expired_key[0],
                    "destination_ip": expired_key[1],
                    "source_port": expired_key[2],
                    "destination_port": expired_key[3],
                    "protocol": expired_key[4],
                })
                sequence += 1
                result = detector.process_record(pd.Series(flow), sequence_number=sequence)
                if result.security_event is not None:
                    writer.append(result.security_event)
                    print(
                        f"ALERT flow={sequence} risk={result.risk['score']} "
                        f"severity={result.risk['severity']}"
                    )
            if key is None:
                continue
    except KeyboardInterrupt:
        print("Stopping capture and flushing buffered flows...")
    finally:
        for flushed_key, flow in window.flush():
            if flow is None:
                continue
            flow.update({
                "source_ip": flushed_key[0],
                "destination_ip": flushed_key[1],
                "source_port": flushed_key[2],
                "destination_port": flushed_key[3],
                "protocol": flushed_key[4],
            })
            sequence += 1
            result = detector.process_record(pd.Series(flow), sequence_number=sequence)
            if result.security_event is not None:
                writer.append(result.security_event)
        capture.close()


def main():
    parser = argparse.ArgumentParser(description="Run Hybrid IDS on live packets")
    parser.add_argument("--interface", required=True, help="Capture interface, e.g. eth0")
    parser.add_argument("--model", default="models/final_model.joblib")
    parser.add_argument("--output", default="logs/live_security_events.jsonl")
    parser.add_argument("--bpf-filter", default=None, help="Optional libpcap filter")
    parser.add_argument("--flow-timeout", type=float, default=5.0)
    args = parser.parse_args()
    run_capture(args.model, args.interface, args.output, args.bpf_filter, args.flow_timeout)


if __name__ == "__main__":
    main()