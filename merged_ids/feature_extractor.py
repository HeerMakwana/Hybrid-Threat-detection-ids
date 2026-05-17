import time


CICIDS_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
]


class PacketWindow:
    """Simple windowed aggregator keyed by 5-tuple to build flow-like features."""

    def __init__(self, timeout=5.0):
        self.flows = {}
        self.timeout = timeout

    def add_packet(self, pkt):
        # pkt expected to be a dict with keys: src, dst, sport, dport, proto, length, ts
        key = (pkt.get("src"), pkt.get("dst"), pkt.get("sport"), pkt.get("dport"), pkt.get("proto"))
        now = pkt.get("ts", time.time())
        if key not in self.flows:
            # initialize fwd/bwd stats and remember initial src to label directions
            self.flows[key] = {
                "init_src": pkt.get("src"),
                "fwd_pkts": 0,
                "bwd_pkts": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "fwd_lengths": [],
                "bwd_lengths": [],
                "start": now,
                "end": now,
                "total_pkts": 0,
            }
        f = self.flows[key]
        f["total_pkts"] += 1
        l = pkt.get("length", 0)
        # determine direction relative to init_src
        if pkt.get("src") == f.get("init_src"):
            f["fwd_pkts"] += 1
            f["fwd_bytes"] += l
            f["fwd_lengths"].append(l)
        else:
            f["bwd_pkts"] += 1
            f["bwd_bytes"] += l
            f["bwd_lengths"].append(l)
        f["end"] = now
        return key

    def extract_flow_features(self, key):
        f = self.flows.get(key)
        if not f:
            return None
        duration = max(1e-6, f["end"] - f["start"]) if f.get("end") else 1e-6
        total_bytes = f.get("fwd_bytes", 0) + f.get("bwd_bytes", 0)
        total_pkts = f.get("total_pkts", 0)

        def stats(lst):
            if not lst:
                return {"max": 0, "min": 0, "mean": 0.0, "std": 0.0}
            import statistics
            return {
                "max": max(lst),
                "min": min(lst),
                "mean": statistics.mean(lst),
                "std": statistics.pstdev(lst) if len(lst) > 1 else 0.0,
            }

        fwd_s = stats(f.get("fwd_lengths", []))
        bwd_s = stats(f.get("bwd_lengths", []))

        pkt_mean = 0.0
        pkt_std = 0.0
        if total_pkts > 0:
            combined = f.get("fwd_lengths", []) + f.get("bwd_lengths", [])
            pkt_mean = float(sum(combined) / len(combined)) if combined else 0.0
            if len(combined) > 1:
                import statistics
                pkt_std = statistics.pstdev(combined)

        features = {
            "Flow Duration": float(duration),
            "Total Fwd Packets": int(f.get("fwd_pkts", 0)),
            "Total Backward Packets": int(f.get("bwd_pkts", 0)),
            "Total Length of Fwd Packets": float(f.get("fwd_bytes", 0)),
            "Total Length of Bwd Packets": float(f.get("bwd_bytes", 0)),
            "Fwd Packet Length Max": float(fwd_s["max"]),
            "Fwd Packet Length Min": float(fwd_s["min"]),
            "Fwd Packet Length Mean": float(fwd_s["mean"]),
            "Fwd Packet Length Std": float(fwd_s["std"]),
            "Bwd Packet Length Max": float(bwd_s["max"]),
            "Bwd Packet Length Min": float(bwd_s["min"]),
            "Bwd Packet Length Mean": float(bwd_s["mean"]),
            "Bwd Packet Length Std": float(bwd_s["std"]),
            "Flow Bytes/s": float(total_bytes / duration),
            "Flow Packets/s": float(total_pkts / duration),
            "Packet Length Mean": float(pkt_mean),
            "Packet Length Std": float(pkt_std),
        }
        return features


def flow_features_from_packet_dict(pkt):
    window = PacketWindow(timeout=5.0)
    key = window.add_packet(pkt)
    return window.extract_flow_features(key) or {}


def pkt_to_minimal_features(pkt, prev_ts=None):
    """Convert a pyshark/packet-like object (or dict) into a minimal feature dict.
    This is intentionally small and robust for live capture. The training pipeline will
    select a subset of features and save feature names; detector will map them where possible.
    """
    # pkt may be a dict already
    if isinstance(pkt, dict):
        data = pkt
    else:
        # assume pyshark packet-like
        data = {}
        try:
            data["length"] = int(pkt.length)
        except Exception:
            data["length"] = 0
        try:
            data["proto"] = pkt.highest_layer
        except Exception:
            data["proto"] = "UNK"
        try:
            data["src"] = pkt.ip.src
            data["dst"] = pkt.ip.dst
        except Exception:
            data["src"] = pkt.get("ip.src", "")
            data["dst"] = pkt.get("ip.dst", "")
        try:
            data["sport"] = int(pkt[pkt.transport_layer].srcport)
            data["dport"] = int(pkt[pkt.transport_layer].dstport)
        except Exception:
            data["sport"] = 0
            data["dport"] = 0
        try:
            data["ts"] = float(pkt.sniff_timestamp)
        except Exception:
            data["ts"] = time.time()

    # minimal features
    f = {
        "pkt_len": float(data.get("length", 0)),
        "proto": data.get("proto", "UNK"),
        "src": data.get("src", ""),
        "dst": data.get("dst", ""),
        "sport": int(data.get("sport", 0) or 0),
        "dport": int(data.get("dport", 0) or 0),
        "ts": float(data.get("ts", time.time())),
    }
    if prev_ts is None:
        f["iat"] = 0.0
    else:
        f["iat"] = max(0.0, f["ts"] - prev_ts)
    return f
