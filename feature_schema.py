"""Shared feature alignment for training, replay, and live flow inference."""

import re

import numpy as np
import pandas as pd

from feature_extractor import CICIDS_FEATURES


FEATURE_ALIASES = {
    "flow duration": "Flow Duration",
    "total fwd packet": "Total Fwd Packets",
    "total fwd packets": "Total Fwd Packets",
    "total backward packet": "Total Backward Packets",
    "total backward packets": "Total Backward Packets",
    "total bwd packets": "Total Backward Packets",
    "total length of fwd packet": "Total Length of Fwd Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "total length of bwd packet": "Total Length of Bwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",
    "fwd packet length max": "Fwd Packet Length Max",
    "fwd packet length min": "Fwd Packet Length Min",
    "fwd packet length mean": "Fwd Packet Length Mean",
    "fwd packet length std": "Fwd Packet Length Std",
    "bwd packet length max": "Bwd Packet Length Max",
    "bwd packet length min": "Bwd Packet Length Min",
    "bwd packet length mean": "Bwd Packet Length Mean",
    "bwd packet length std": "Bwd Packet Length Std",
    "flow bytes/s": "Flow Bytes/s",
    "flow bytes per second": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "flow packets per second": "Flow Packets/s",
    "packet length mean": "Packet Length Mean",
    "packet length std": "Packet Length Std",
}


def normalize_column(name):
    return re.sub(r"\s+", " ", str(name).strip().lower())


def align_feature_frame(frame, feature_columns=None):
    """Return a finite numeric frame in the exact trained feature order."""
    feature_columns = feature_columns or CICIDS_FEATURES
    normalized = {normalize_column(column): column for column in frame.columns}
    rename_map = {
        normalized[alias]: canonical
        for alias, canonical in FEATURE_ALIASES.items()
        if alias in normalized
    }
    renamed = frame.rename(columns=rename_map)
    aligned = pd.DataFrame(index=renamed.index)
    for feature in feature_columns:
        if feature in renamed.columns:
            aligned[feature] = pd.to_numeric(renamed[feature], errors="coerce")
        else:
            aligned[feature] = np.float32(0.0)
    return aligned.replace([np.inf, -np.inf], np.nan).fillna(0.0).clip(-1e12, 1e12)