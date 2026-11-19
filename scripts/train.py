"""Train the GradientBoosting Pipeline and calibrate the suppression threshold.

Data: the canonical UNSW-NB15 file ``data/unsw-nb15.csv`` when present
(real columns dur, sbytes, dbytes, rate, sttl, ct_srv_src, label), otherwise
the synthetic UNSW-NB15-style generator. Threshold calibration is done on
INCIDENT-level pooled probabilities by the caller (see benchmark.py); this
module calibrates on whatever probabilities it is given and reports
honestly whether the target was met.

Usage: python scripts/train.py
Get UNSW-NB15 from UNSW Canberra (https://research.unsw.edu.au/projects/
unsw-nb15-dataset) or Kaggle ("UNSW-NB15") and save the testing set as
``data/unsw-nb15.csv``. Do NOT commit the dataset. No download is performed
by this script.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from api.config import settings
from api.scoring import FEATURE_NAMES, generate_synthetic_flows, inject_missing, train_model

UNSW_PATH = Path("data/unsw-nb15.csv")
# Real UNSW-NB15 columns used as model features, in FEATURE_NAMES order.
UNSW_COLUMNS = ["dur", "sbytes", "dbytes", "rate", "sttl", "ct_srv_src"]


def load_unsw() -> tuple[np.ndarray, np.ndarray] | None:
    """Load UNSW-NB15 if the file exists; return None otherwise (synthetic fallback).

    Raises ValueError (fails loudly) when the file exists but a required
    column is missing — never silently zero-fills or clips a column.
    """
    if not UNSW_PATH.exists():
        return None
    df = pd.read_csv(UNSW_PATH)
    missing = [c for c in UNSW_COLUMNS + ["label"] if c not in df.columns]
    if missing:
        raise ValueError(
            f"{UNSW_PATH} is missing required columns {missing}; "
            "expected real UNSW-NB15 columns dur, sbytes, dbytes, rate, sttl, "
            "ct_srv_src, label. Fix the file instead of training on bad data."
        )
    # Flow columns only: UNSW-NB15 has no severity column, and severity
    # is not a model feature (it enters only through the priority formula).
    X = df[UNSW_COLUMNS].astype(float).to_numpy()
    y = (df["label"].astype(str).str.lower().isin(["1", "attack", "malicious"])).astype(int).to_numpy()
    # Same missing-flow injection as the synthetic generator, so the model
    # learns how to score alerts that arrive without flow data.
    return inject_missing(X, seed=7), y


def calibrate_threshold(
    model, X_val: np.ndarray, y_val: np.ndarray, target: float
) -> tuple[float, float, bool]:
    """Calibrate the suppression threshold on validation probabilities.

    Scans the unique validation probabilities ROC-style (highest first,
    up to 1.0) and picks the HIGHEST threshold whose malicious recall is
    still >= ``target`` — the highest threshold suppresses the most while
    keeping the false-negative budget. Returns (threshold, recall,
    target_met). If no threshold meets the target (e.g. no malicious rows
    in the validation set), returns the lowest observed probability, the
    best recall found, and ``target_met=False`` — the caller must report
    "target not met", never silently claim the target.
    """
    y_val = np.asarray(y_val)
    if int((y_val == 1).sum()) == 0:
        return 0.0, 0.0, False
    probs = model.predict_proba(X_val)[:, 1]
    candidates = sorted(set(float(p) for p in probs) | {1.0}, reverse=True)
    best_recall = 0.0
    for t in candidates:
        recall = float(((probs >= t) & (y_val == 1)).sum() / max(int((y_val == 1).sum()), 1))
        best_recall = max(best_recall, recall)
        if recall >= target:
            return float(t), recall, True
    return float(min(candidates)), best_recall, False


def calibrate_incident_threshold(
    scores: list[float], labels: list[int], target: float
) -> tuple[float, float, bool]:
    """Same rule as ``calibrate_threshold`` but on incident-level scores.

    ``scores`` are pooled incident ML probabilities, ``labels`` 1/0 for
    malicious/benign incidents. Returns (threshold, recall, target_met).
    """
    scores_arr = np.asarray(scores, dtype=float)
    labels_arr = np.asarray(labels, dtype=int)
    if int((labels_arr == 1).sum()) == 0:
        return 0.0, 0.0, False
    candidates = sorted(set(float(s) for s in scores_arr) | {1.0}, reverse=True)
    best_recall = 0.0
    for t in candidates:
        recall = float(((scores_arr >= t) & (labels_arr == 1)).sum() / int((labels_arr == 1).sum()))
        best_recall = max(best_recall, recall)
        if recall >= target:
            return float(t), recall, True
    return float(min(candidates)), best_recall, False


def main() -> dict:
    loaded = load_unsw()
    source = "unsw-nb15.csv" if loaded else "synthetic (UNSW-NB15-style)"
    X, y = loaded if loaded else generate_synthetic_flows()
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = train_model(X_train, y_train)
    threshold, recall, met = calibrate_threshold(model, X_val, y_val, settings.recall_target)
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, settings.model_path)
    with open(settings.threshold_path, "w") as f:
        json.dump({"threshold": threshold, "recall_target": settings.recall_target,
                   "validation_recall": recall, "target_met": met,
                   "features": FEATURE_NAMES, "source": source}, f, indent=2)
    status = "target met" if met else "TARGET NOT MET"
    print(f"Source: {source} | train={len(y_train)} val={len(y_val)} | "
          f"threshold={threshold:.4f} validation_recall={recall:.4f} "
          f"(target {settings.recall_target}) — {status}")
    return {"threshold": threshold, "validation_recall": recall, "target_met": met, "source": source}


if __name__ == "__main__":
    main()
