

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import os
import re
import time
import warnings
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    psutil = None
    HAS_PSUTIL = False
from sklearn.isotonic import IsotonicRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.linear_model import SGDClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, LabelEncoder

from feature_extractor import CICIDS_FEATURES


class ProbabilityCalibrator:
    """Wrap an estimator and a fitted calibrator to provide a
    `predict_proba` interface returning calibrated probabilities.
    """
    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        p = self.estimator.predict_proba(X)[:, 1]
        if hasattr(self.calibrator, "transform"):
            p2 = self.calibrator.transform(p)
        else:
            p2 = self.calibrator.predict_proba(p.reshape(-1, 1))[:, 1]
        return np.vstack([1 - p2, p2]).T

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

# ── Optional fast libraries ──────────────────────────────────────────────────
try:
    import lightgbm as lgb
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False

try:
    import pyarrow  # noqa: F401 -- checked for pandas engine selection
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

N_CORES = max(1, multiprocessing.cpu_count())

# ── Constants ────────────────────────────────────────────────────────────────
BENIGN_LABELS: frozenset[str] = frozenset({"benign", "normal", "0"})

FEATURE_ALIASES: dict[str, str] = {
    "flow duration": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
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


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(name: str) -> str:
    return re.sub(r"\s+", " ", str(name).strip().lower())


def _ram_gb() -> float:
    if HAS_PSUTIL:
        return psutil.virtual_memory().available / 1e9
    # Fallback when psutil is not installed (use conservative 0.0)
    return 0.0


def _elapsed(t0: float) -> str:
    s = time.time() - t0
    return f"{s / 60:.1f} min" if s >= 60 else f"{s:.1f}s"


def _log_mem(stage: str) -> None:
    log.info("[mem] %-30s  %.1f GB free", stage, _ram_gb())


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def _cast_numeric_f32(df: pd.DataFrame) -> pd.DataFrame:
    """Downcast all float64 columns to float32.  Halves RAM immediately."""
    f64_cols = df.select_dtypes(include="float64").columns
    if len(f64_cols):
        df[f64_cols] = df[f64_cols].astype(np.float32)
    return df


def load_data(path: str, chunksize: int = 300_000) -> pd.DataFrame:
    """Load CSV with the fastest available engine.

    - pyarrow engine when installed: 3-5x faster, lower peak RAM.
    - Chunked C-engine reads for large files without pyarrow to avoid OOM.
    - Casts all numeric columns to float32 immediately after loading.
    """
    file_mb = os.path.getsize(path) / 1e6
    log.info("CSV on disk: %.0f MB  |  free RAM: %.1f GB", file_mb, _ram_gb())

    read_kwargs: dict[str, Any] = {"low_memory": False}
    if HAS_PYARROW:
        read_kwargs["engine"] = "pyarrow"
        log.info("Using pyarrow CSV engine")
    else:
        log.info("pyarrow not found -- using C engine  (pip install pyarrow to speed up loading)")

    if file_mb < 500 or HAS_PYARROW:
        df = pd.read_csv(path, **read_kwargs)
    else:
        log.info("Reading in chunks of %d rows ...", chunksize)
        chunks: list[pd.DataFrame] = []
        for i, chunk in enumerate(pd.read_csv(path, chunksize=chunksize, **read_kwargs)):
            chunks.append(_cast_numeric_f32(chunk))
            if (i + 1) % 5 == 0:
                log.info("  ... %d rows loaded, %.1f GB free", (i + 1) * chunksize, _ram_gb())
        df = pd.concat(chunks, ignore_index=True)

    df = _cast_numeric_f32(df)
    log.info("Rows loaded: %d  |  free RAM after: %.1f GB", len(df), _ram_gb())
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Sampling
# ─────────────────────────────────────────────────────────────────────────────

def stratified_sample(df: pd.DataFrame, label_col: str, max_rows: int | None) -> pd.DataFrame:
    """Downsample while preserving per-class proportions exactly."""
    if max_rows is None or len(df) <= max_rows:
        return df
    frac = max_rows / len(df)
    log.info("Stratified sampling %d -> %d rows (frac=%.3f)", len(df), max_rows, frac)
    parts = []
    for _, g in df.groupby(label_col):
        parts.append(g.sample(frac=frac, random_state=42))
    return pd.concat(parts, ignore_index=True)


# ─────────────────────────────────────────────────────────────────────────────
# Column alignment & preprocessing
# ─────────────────────────────────────────────────────────────────────────────

def find_label_column(df: pd.DataFrame) -> str:
    candidates = [c for c in df.columns if _normalize(c) in {"label", "class", "attack", "target"}]
    if candidates:
        return candidates[0]
    raise ValueError("Cannot find label column. Expected one of: Label, Class, Attack, Target.")


def align_cicids_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename aliases to canonical names; build the fixed CICIDS feature frame."""
    norm_lookup = {_normalize(c): c for c in df.columns}
    rename_map = {
        norm_lookup[alias]: canonical
        for alias, canonical in FEATURE_ALIASES.items()
        if alias in norm_lookup
    }
    df = df.rename(columns=rename_map)

    aligned = pd.DataFrame(index=df.index, dtype=np.float32)
    for feature in CICIDS_FEATURES:
        if feature in df.columns:
            aligned[feature] = (
                pd.to_numeric(df[feature], errors="coerce")
                .fillna(0.0)
                .astype(np.float32)
            )
        else:
            aligned[feature] = np.float32(0.0)
    return aligned


def encode_labels_vectorised(series: pd.Series) -> np.ndarray:
    """Vectorised label binarisation.

    ~40x faster than row-wise .apply(lambda) on 2.8M rows because it avoids
    the Python interpreter overhead per element.
    """
    normalised = series.astype(str).str.strip().str.lower()
    return (~normalised.isin(BENIGN_LABELS)).astype(np.int8).values


def sanitize(arr: np.ndarray) -> np.ndarray:
    """Replace +-inf / NaN in-place; clip to float32-safe range."""
    np.nan_to_num(arr, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.clip(arr, -1e9, 1e9, out=arr)
    return arr


def preprocess(df: pd.DataFrame, label_col: str) -> tuple[pd.DataFrame, np.ndarray]:
    y = encode_labels_vectorised(df[label_col])
    X = align_cicids_columns(df)
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# Threshold search -- fully vectorised, no Python loop over metrics
# ─────────────────────────────────────────────────────────────────────────────

def find_best_threshold(
    probs: np.ndarray,
    y_true: np.ndarray,
    n_steps: int = 81,
    recall_weight: float = 0.75,
    f1_weight: float = 0.20,
    fp_penalty: float = 0.05,
) -> tuple[float, dict[float, dict]]:
    """Vectorised threshold sweep using sort + cumsum.

    O(n log n) total cost instead of O(n x steps) from the old loop.
    Score = recall_weight x recall + f1_weight x F1 - fp_penalty x FP_rate
    """
    thresholds = np.linspace(0.10, 0.90, n_steps, dtype=np.float32)

    # Sort predictions descending; keep labels in the same order
    sort_idx = np.argsort(-probs)
    probs_sorted = probs[sort_idx]
    y_sorted = y_true[sort_idx].astype(np.int32)

    total_pos = int(y_true.sum())
    total_neg = len(y_true) - total_pos
    cum_tp = np.cumsum(y_sorted)   # cum_tp[k] = TP if we predict top k+1 as positive

    results: dict[float, dict] = {}
    best_thresh = 0.5
    best_score = -np.inf

    for t in thresholds:
        n_pred_pos = int((probs_sorted >= t).sum())
        if n_pred_pos == 0:
            tp, fp = 0, 0
        else:
            tp = int(cum_tp[n_pred_pos - 1])
            fp = n_pred_pos - tp

        recall = tp / max(1, total_pos)
        prec   = tp / max(1, tp + fp)
        f1     = 2 * prec * recall / max(1e-9, prec + recall)
        fp_r   = fp / max(1, total_neg)
        score  = recall_weight * recall + f1_weight * f1 - fp_penalty * fp_r

        key = round(float(t), 4)
        results[key] = {
            "recall":    round(recall, 4),
            "precision": round(prec,   4),
            "f1":        round(f1,     4),
            "fp_rate":   round(fp_r,   4),
            "score":     round(score,  4),
        }
        if score > best_score:
            best_score = score
            best_thresh = float(t)

    return best_thresh, results


# ─────────────────────────────────────────────────────────────────────────────
# Estimator definitions
# ─────────────────────────────────────────────────────────────────────────────

def _make_lgbm(
    n_estimators: int,
    max_depth: int,
    learning_rate: float,
    num_leaves: int,
    use_gpu: bool,
    seed: int,
    scale_pos_weight: float | None = None,
) -> "lgb.LGBMClassifier":
    params: dict[str, Any] = dict(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        num_leaves=num_leaves,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.05,
        reg_lambda=0.1,
        class_weight="balanced",
        n_jobs=N_CORES,
        random_state=seed,
        verbose=-1,
    )
    if scale_pos_weight is not None:
        params["scale_pos_weight"] = float(scale_pos_weight)
    if use_gpu:
        params.update(device="gpu", gpu_use_dp=False)
    return lgb.LGBMClassifier(**params)


def _make_hgbm(
    n_iter: int,
    max_depth: int,
    lr: float,
    min_samples_leaf: int,
    l2: float,
    seed: int,
) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        learning_rate=lr,
        max_iter=n_iter,
        max_depth=max_depth,
        max_bins=255,
        min_samples_leaf=min_samples_leaf,
        l2_regularization=l2,
        early_stopping=True,
        validation_fraction=0.05,
        n_iter_no_change=25,
        random_state=seed,
    )


def build_estimators(use_gpu: bool) -> list[tuple[str, Any]]:
    """Return (name, unfitted estimator) pairs.

    Uses LightGBM boosters when available (5-10x faster).
    Falls back to sklearn HistGBM transparently.
    """
    if HAS_LGBM:
        log.info("LightGBM available -- using LGBM boosters%s", " [GPU]" if use_gpu else "")
        booster_1 = ("lgbm_fast", _make_lgbm(
            n_estimators=400, max_depth=8,  learning_rate=0.08,
            num_leaves=63,  use_gpu=use_gpu, seed=42,
        ))
        booster_2 = ("lgbm_deep", _make_lgbm(
            n_estimators=600, max_depth=12, learning_rate=0.04,
            num_leaves=127, use_gpu=use_gpu, seed=7,
        ))
    else:
        log.info("LightGBM not installed -- using HistGBM  (pip install lightgbm for ~5x speedup)")
        booster_1 = ("hgbm_fast", _make_hgbm(
            n_iter=300, max_depth=8,  lr=0.08, min_samples_leaf=20, l2=0.05, seed=42,
        ))
        booster_2 = ("hgbm_deep", _make_hgbm(
            n_iter=400, max_depth=12, lr=0.04, min_samples_leaf=10, l2=0.02, seed=7,
        ))

    rf = ("rf", RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=20,
        min_samples_leaf=10,
        max_features="sqrt",
        class_weight="balanced_subsample",
        n_jobs=N_CORES,
        random_state=42,
    ))
    et = ("et", ExtraTreesClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=20,
        min_samples_leaf=10,
        max_features="log2",
        class_weight="balanced_subsample",
        n_jobs=N_CORES,
        random_state=42,
    ))

    # CalibratedClassifierCV wraps SGD so its probabilities are reliable for
    # soft voting.  Raw log_loss SGD probs are systematically miscalibrated
    # under class imbalance.
    sgd_base = SGDClassifier(
        loss="log_loss",
        alpha=1e-5,
        max_iter=2000,
        tol=1e-4,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )
    sgd = ("sgd_cal", CalibratedClassifierCV(sgd_base, method="isotonic", cv=3))

    return [booster_1, booster_2, rf, et, sgd]


def feature_engineer_df(df: pd.DataFrame) -> pd.DataFrame:
    """Add lightweight engineered features to improve separability.

    These are cheap, vectorised transforms derived from CICIDS flow fields.
    """
    df = df.copy()
    # safe log of flow duration
    if "Flow Duration" in df.columns:
        df["log_flow_duration"] = np.log1p(df["Flow Duration"].astype(np.float32).clip(lower=0))
    else:
        df["log_flow_duration"] = 0.0

    # ratio of forward/backward packets
    if "Total Fwd Packets" in df.columns:
        fwd = df["Total Fwd Packets"].astype(np.float32)
    else:
        fwd = pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)
    if "Total Backward Packets" in df.columns:
        bwd = df["Total Backward Packets"].astype(np.float32)
    else:
        bwd = pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)
    df["fwd_bwd_ratio"] = (fwd + 1.0) / (bwd + 1.0)

    # bytes per packet (flow-level)
    if "Flow Bytes/s" in df.columns:
        flow_bytes = df["Flow Bytes/s"].astype(np.float32)
    else:
        flow_bytes = pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)
    if "Flow Packets/s" in df.columns:
        flow_pkts = df["Flow Packets/s"].astype(np.float32)
    else:
        flow_pkts = pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)
    df["bytes_per_packet"] = np.where(flow_pkts > 0, flow_bytes / flow_pkts, 0.0).astype(np.float32)

    # packet length mean normalised
    if "Packet Length Mean" in df.columns:
        pkt_mean = df["Packet Length Mean"].astype(np.float32)
        df["pkt_len_mean_norm"] = pkt_mean / (pkt_mean.abs().median() + 1e-6)
    else:
        df["pkt_len_mean_norm"] = 0.0

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Parallel fitting with per-estimator checkpoints
# ─────────────────────────────────────────────────────────────────────────────

def _fit_one(
    name: str,
    estimator: Any,
    X_train: np.ndarray,
    y_train: np.ndarray,
    checkpoint_dir: Path,
) -> tuple[str, Any]:
    """Fit a single estimator; checkpoint immediately after so crashes are recoverable."""
    ck_path = checkpoint_dir / f"ckpt_{name}.joblib"
    if ck_path.exists():
        log.info("[%s] Resuming from checkpoint", name)
        return name, joblib.load(ck_path)

    t0 = time.time()
    log.info("[%s] Training ...", name)
    estimator.fit(X_train, y_train)
    log.info("[%s] Done in %s", name, _elapsed(t0))
    joblib.dump(estimator, ck_path, compress=1)
    log.info("[%s] Checkpoint -> %s", name, ck_path.name)
    return name, estimator


def fit_parallel(
    estimators: list[tuple[str, Any]],
    X_train: np.ndarray,
    y_train: np.ndarray,
    checkpoint_dir: Path,
) -> list[tuple[str, Any]]:
    """Fit all estimators, overlapping where the GIL allows.

    LightGBM, HistGBM, RF, and ET all release the GIL during their inner
    loops, so the threading backend achieves genuine concurrency.
    We cap parallel jobs at 3 to avoid over-subscribing the CPU when each
    estimator also uses n_jobs=-1 internally.
    """
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    if N_CORES <= 1:
        log.info("Single CPU -- fitting sequentially")
        return [_fit_one(n, e, X_train, y_train, checkpoint_dir) for n, e in estimators]

    n_parallel = min(3, len(estimators), N_CORES)
    log.info("Fitting %d estimators, %d at a time (threading backend) ...",
             len(estimators), n_parallel)
    results = joblib.Parallel(n_jobs=n_parallel, backend="threading", verbose=0)(
        joblib.delayed(_fit_one)(name, est, X_train, y_train, checkpoint_dir)
        for name, est in estimators
    )
    return list(results)


def _fit_one_prefit(
    name: str,
    estimator: Any,
    X_train: np.ndarray,
    y_train: np.ndarray,
    checkpoint_dir: Path,
) -> tuple[str, Any]:
    # Wrapper kept for API symmetry; uses same _fit_one
    return _fit_one(name, estimator, X_train, y_train, checkpoint_dir)


def assemble_voting_classifier(
    fitted: list[tuple[str, Any]],
    weights: list[float],
) -> VotingClassifier:
    """Wrap already-trained estimators in a VotingClassifier without re-fitting.

    We bypass sklearn's fit() by directly setting the internal attributes that
    predict_proba() reads.
    """
    vc = VotingClassifier(
        estimators=fitted,
        voting="soft",
        weights=weights,
        n_jobs=1,
    )
    vc.estimators_ = [est for _, est in fitted]
    # Use a real LabelEncoder instance so the object is pickleable.
    le = LabelEncoder()
    le.classes_ = np.array([0, 1])
    vc.le_ = le
    vc.classes_ = np.array([0, 1])
    return vc


# ─────────────────────────────────────────────────────────────────────────────
# Main training routine
# ─────────────────────────────────────────────────────────────────────────────

# Weights: [booster_fast, booster_deep, RF, ET, SGD_cal]
# Increased boosting weights to prioritise hist/lightgbm models for recall.
ENSEMBLE_WEIGHTS = [4.0, 3.0, 1.5, 1.0, 0.8]


def train(args: argparse.Namespace) -> None:
    t_total = time.time()
    out_dir = Path(args.out).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = out_dir / "checkpoints"
    use_gpu = getattr(args, "gpu", False)

    log.info("=" * 60)
    log.info("IDS Training Pipeline  cores=%d  lgbm=%s  pyarrow=%s  gpu=%s",
             N_CORES, HAS_LGBM, HAS_PYARROW, use_gpu)
    log.info("=" * 60)

    # ── 1. Load ───────────────────────────────────────────────────────────────
    t = time.time()
    df = load_data(args.data)
    log.info("Load: %s", _elapsed(t))

    # Normalise column names early: remove stray leading/trailing whitespace
    df.columns = df.columns.astype(str).str.strip()

    # ── 2. Find label column ──────────────────────────────────────────────────
    label_col = args.label or find_label_column(df)
    log.info("Label column: '%s'", label_col)

    # ── 3. Optional stratified downsample ─────────────────────────────────────
    if getattr(args, "max_rows", None):
        df = stratified_sample(df, label_col, args.max_rows)

    # ── 4. Preprocess: vectorised encode + CICIDS alignment ───────────────────
    _log_mem("before preprocess")
    t = time.time()
    # Add engineered features before building the CICIDS feature frame so
    # derived columns are available for alignment.
    df = feature_engineer_df(df)
    X, y = preprocess(df, label_col)
    del df                          # free original dataframe immediately
    pos_pct = 100.0 * float(y.mean())
    log.info("Preprocess: %s  |  attack %.2f%%  benign %.2f%%",
             _elapsed(t), pos_pct, 100 - pos_pct)
    _log_mem("after preprocess")

    # ── 5. Train/val split (BEFORE scaling -- no data leakage) ───────────────
    X_train_df, X_val_df, y_train, y_val = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y,
    )
    del X
    log.info("Split -- train: %d  val: %d", len(X_train_df), len(X_val_df))

    # Optional: undersample the majority class in the training set to increase
    # attack prevalence and improve recall on imbalanced datasets. Use
    # --balance-ratio to set desired positive fraction (e.g. 0.5 = 50% positives).
    if getattr(args, "balance_ratio", None) is not None:
        desired = float(args.balance_ratio)
        if not (0.0 < desired < 1.0):
            log.warning("--balance-ratio must be between 0 and 1; ignoring")
        else:
            # y_train is a numpy array parallel to X_train_df
            pos_idx = np.where(y_train == 1)[0]
            neg_idx = np.where(y_train == 0)[0]
            n_pos = len(pos_idx)
            n_neg_needed = int(n_pos * (1.0 - desired) / max(1e-9, desired))
            if n_neg_needed < len(neg_idx):
                rng = np.random.RandomState(42)
                keep_neg = rng.choice(neg_idx, size=n_neg_needed, replace=False)
                keep_idx = np.concatenate([pos_idx, keep_neg])
                X_train_df = X_train_df.iloc[keep_idx].reset_index(drop=True)
                y_train = y_train[keep_idx]
                log.info("Balanced train set: positives=%d negatives=%d", n_pos, n_neg_needed)
            else:
                log.info("Requested balance_ratio not achievable (not enough negatives); skipping")

    # ── 6. Sanitize (in-place, no extra allocation) ───────────────────────────
    X_train_np = sanitize(X_train_df.values.astype(np.float32))
    X_val_np   = sanitize(X_val_df.values.astype(np.float32))
    feature_columns = X_train_df.columns.tolist()
    del X_train_df, X_val_df

    # ── 7. Scale -- RobustScaler handles IDS outliers better than Standard ────
    t = time.time()
    scaler = RobustScaler()
    X_train_sc = scaler.fit_transform(X_train_np).astype(np.float32)
    X_val_sc   = scaler.transform(X_val_np).astype(np.float32)
    del X_train_np, X_val_np
    log.info("RobustScaler fit+transform: %s", _elapsed(t))
    _log_mem("after scaling")

    # ── 8. Build estimators ───────────────────────────────────────────────────
    # If requested, compute scale_pos_weight for LightGBM boosters from
    # the training fit split (negatives/positives ratio).
    scale_pos_weight = None
    if getattr(args, "scale_pos_weight", False) and len(y_train) > 0:
        pos = int(y_train.sum())
        neg = int(len(y_train) - pos)
        if pos > 0:
            scale_pos_weight = neg / max(1, pos)
            log.info("Using scale_pos_weight=%.3f for LightGBM", scale_pos_weight)

    # Re-build estimators with scale_pos_weight injected into LGBM constructors
    estimators = []
    for name, est in build_estimators(use_gpu=use_gpu):
        if HAS_LGBM and name.startswith("lgbm_") and scale_pos_weight is not None:
            # recreate with scale_pos_weight
            if name == "lgbm_fast":
                estimators.append((name, _make_lgbm(400, 8, 0.08, 63, use_gpu, 42, scale_pos_weight)))
            else:
                estimators.append((name, _make_lgbm(600, 12, 0.04, 127, use_gpu, 7, scale_pos_weight)))
        else:
            estimators.append((name, est))
    estimator_names = [n for n, _ in estimators]
    log.info("Estimators: %s", " | ".join(estimator_names))

    # ── 9. Parallel fit with checkpointing ───────────────────────────────────
    t = time.time()
    # If stacking or calibration is requested we need a train-fit / calib split.
    do_stack = getattr(args, "stack", False)
    do_calib = getattr(args, "calibrate", False)

    if do_stack or do_calib:
        # split training into fit / calib (80/20)
        from sklearn.model_selection import train_test_split as _split
        X_fit, X_calib, y_fit, y_calib = _split(
            X_train_sc, y_train, test_size=0.20, random_state=42, stratify=y_train
        )
        # fit base estimators on X_fit
        fitted = fit_parallel(estimators, X_fit, y_fit, checkpoint_dir)

        # optionally calibrate each estimator on X_calib
        if do_calib:
            calibrated = []
            for name, est in fitted:
                try:
                    probs_cal = est.predict_proba(X_calib)[:, 1]
                    iso = IsotonicRegression(out_of_bounds="clip")
                    iso.fit(probs_cal, y_calib)
                    calibrated.append((name, ProbabilityCalibrator(est, iso)))
                except Exception:
                    # fallback to Platt scaling via a logistic regressor on probs
                    probs_cal = est.predict_proba(X_calib)[:, 1].reshape(-1, 1)
                    platt = LogisticRegression(max_iter=2000)
                    platt.fit(probs_cal, y_calib)
                    calibrated.append((name, ProbabilityCalibrator(est, platt)))
            fitted = calibrated

        # If stacking requested, train meta-learner on calibrated/fitted estimators' probs on X_calib
        if do_stack:
            # Build meta train matrix
            meta_X = np.column_stack([est.predict_proba(X_calib)[:, 1] for _, est in fitted])
            meta_y = y_calib
            # simple logistic with small grid search for C
            meta = LogisticRegression(class_weight="balanced", max_iter=2000, solver="lbfgs")
            gs = GridSearchCV(meta, {"C": [0.01, 0.1, 1.0, 10.0]}, cv=3, scoring="f1", n_jobs=1)
            gs.fit(meta_X, meta_y)
            meta = gs.best_estimator_
            log.info("Meta-learner trained (best C=%.4f)", gs.best_params_["C"])
            # assemble final model wrapper as a tuple (fitted_base_list, meta)
            model = (fitted, meta)
        else:
            # no stacking: assemble voting classifier from fitted estimators
            model = assemble_voting_classifier(fitted, ENSEMBLE_WEIGHTS)

    else:
        # standard path: fit each estimator on full X_train_sc
        fitted = fit_parallel(estimators, X_train_sc, y_train, checkpoint_dir)
        model = assemble_voting_classifier(fitted, ENSEMBLE_WEIGHTS)
    log.info("All estimators trained: %s", _elapsed(t))
    _log_mem("after training")

    # ── 10. Assemble ensemble ─────────────────────────────────────────────────
    model = assemble_voting_classifier(fitted, ENSEMBLE_WEIGHTS)

    # ── 11. Validation probabilities ──────────────────────────────────────────
    t = time.time()
    # Obtain validation probabilities depending on model type
    if isinstance(model, tuple):
        # stacking: model = (fitted_list, meta)
        fitted_list, meta = model
        val_meta_X = np.column_stack([est.predict_proba(X_val_sc)[:, 1] for _, est in fitted_list])
        probs = meta.predict_proba(val_meta_X)[:, 1]
    else:
        probs = model.predict_proba(X_val_sc)[:, 1]
    log.info("Val inference: %s", _elapsed(t))

    # ── 12. Vectorised threshold search ───────────────────────────────────────
    t = time.time()
    best_thresh, thresh_table = find_best_threshold(
        probs,
        y_val,
        recall_weight=getattr(args, "recall_weight", 0.75),
        f1_weight=getattr(args, "f1_weight", 0.20),
        fp_penalty=getattr(args, "fp_penalty", 0.05),
    )
    log.info("Threshold search: %s", _elapsed(t))
    best = thresh_table[round(best_thresh, 4)]
    log.info("Best threshold: %.3f  recall=%.4f  precision=%.4f  fp_rate=%.4f",
             best_thresh, best["recall"], best["precision"], best["fp_rate"])

    # ── 13. Final metrics ─────────────────────────────────────────────────────
    val_preds = (probs >= best_thresh).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_val, val_preds).ravel()
    fp_rate = fp / max(1, fp + tn)
    roc_auc = float(roc_auc_score(y_val, probs)) if len(np.unique(y_val)) > 1 else None

    metrics: dict[str, Any] = {
        "model_architecture":       "5-estimator hybrid soft-voting ensemble",
        "estimators":               estimator_names,
        "boosting_backend":         "lightgbm" if HAS_LGBM else "sklearn_histgbm",
        "gpu_training":             use_gpu and HAS_LGBM,
        "voting_method":            "soft",
        "weights":                  ENSEMBLE_WEIGHTS,
        "rows_total":               int(len(y_train) + len(y_val)),
        "train_rows":               int(len(y_train)),
        "validation_rows":          int(len(y_val)),
        "class_balance_attack_pct": round(pos_pct, 2),
        "accuracy":                 float(accuracy_score(y_val, val_preds)),
        "precision":                float(precision_score(y_val, val_preds, zero_division=0)),
        "recall":                   float(recall_score(y_val, val_preds, zero_division=0)),
        "f1_score":                 float(f1_score(y_val, val_preds, zero_division=0)),
        "false_positive_rate":      float(fp_rate),
        "roc_auc":                  roc_auc,
        "threshold":                float(best_thresh),
        "threshold_optimisation":   "recall*0.60 + F1*0.30 - FP_rate*0.10",
        "confusion_matrix":         {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "anomalies_in_validation":  int(y_val.sum()),
        "anomalies_detected":       int(tp),
        "false_alarms":             int(fp),
        "training_time_seconds":    round(time.time() - t_total, 1),
    }

    # ── 14. Save model artifact ───────────────────────────────────────────────
    artifact: dict[str, Any] = {
        "model":            model,
        "scaler":           scaler,
        "feature_columns":  feature_columns,
        "threshold":        float(best_thresh),
        "label_column":     label_col,
        "model_type":       "hybrid_voting_5ensemble_v3",
        "estimators":       estimator_names,
        "weights":          ENSEMBLE_WEIGHTS,
        "boosting_backend": "lightgbm" if HAS_LGBM else "sklearn_histgbm",
    }
    joblib.dump(artifact, args.out, compress=3)
    log.info("Model saved -> %s", args.out)

    metrics_path = out_dir / "evaluation_results.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    log.info("Metrics saved -> %s", metrics_path)

    # ── 15. Summary ───────────────────────────────────────────────────────────
    W = 70
    sep = "=" * W
    print(f"\n{sep}")
    print("HYBRID IDS ENSEMBLE -- EVALUATION SUMMARY")
    print(sep)
    backend_label = ("LightGBM" if HAS_LGBM else "sklearn HistGBM") + (" [GPU]" if use_gpu and HAS_LGBM else "")
    print(f"  Backend    : {backend_label}")
    print(f"  Estimators : {' | '.join(estimator_names)}")
    print(f"  Weights    : {ENSEMBLE_WEIGHTS}")
    print(f"  Train rows : {metrics['train_rows']:>10,}   Val rows: {metrics['validation_rows']:,}")
    print(f"  Attack %   : {metrics['class_balance_attack_pct']:.2f}%")
    print(f"{'-' * W}")
    print(f"  Accuracy             {metrics['accuracy']:.4f}")
    print(f"  Precision            {metrics['precision']:.4f}")
    print(f"  Recall (detection)   {metrics['recall']:.4f}  <- most important for IDS")
    print(f"  F1 Score             {metrics['f1_score']:.4f}")
    print(f"  False Positive Rate  {metrics['false_positive_rate']:.4f}")
    if roc_auc is not None:
        print(f"  ROC AUC              {roc_auc:.4f}")
    print(f"  Threshold            {metrics['threshold']:.3f}")
    print(f"{'-' * W}")
    print(f"  Anomalies in val : {metrics['anomalies_in_validation']:,}")
    print(f"  Detected         : {metrics['anomalies_detected']:,}")
    print(f"  False alarms     : {metrics['false_alarms']:,}")
    print(f"  Total time       : {metrics['training_time_seconds']:.0f}s")
    print(f"{sep}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a hybrid IDS ensemble model.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--data",     required=True,
                        help="Path to labeled CSV dataset")
    parser.add_argument("--label",    default=None,
                        help="Label column name (auto-detected if omitted)")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Cap rows via stratified sampling (e.g. 500000 for a quick run)")
    parser.add_argument("--out",      default="models/final_model.joblib",
                        help="Output path for the joblib model artifact")
    parser.add_argument("--gpu",      action="store_true",
                        help="Enable GPU training for LightGBM boosters (requires LightGBM + CUDA)")
    parser.add_argument(
        "--balance-ratio", type=float, default=None,
        help="Undersample training negatives to achieve this positive fraction (0<r<1)",
    )
    parser.add_argument(
        "--recall-weight", type=float, default=0.75,
        help="Recall weight for threshold optimisation (default 0.75)",
    )
    parser.add_argument(
        "--f1-weight", type=float, default=0.20,
        help="F1 weight for threshold optimisation (default 0.20)",
    )
    parser.add_argument(
        "--fp-penalty", type=float, default=0.05,
        help="FP penalty for threshold optimisation (default 0.05)",
    )
    parser.add_argument("--stack", action="store_true", help="Train stacking meta-learner on out-of-fold predictions")
    parser.add_argument("--calibrate", action="store_true", help="Calibrate tree boosters on held-out calibration set")
    parser.add_argument("--scale-pos-weight", action="store_true", help="Use scale_pos_weight for LightGBM instead of undersampling")
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()