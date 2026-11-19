"""Retrain using analyst feedback: feedback-labelled incidents add weighted
synthetic samples in the current feature order (dur, sbytes, dbytes, rate,
sttl, ct_srv_src — flow columns only, no severity), then train.py's
calibration runs again.
Usage: python scripts/retrain.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import os

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

from api.config import settings
from api.database import SessionLocal
from api.models import Feedback
from api.scoring import FEATURE_NAMES, generate_synthetic_flows, train_model
from scripts.train import calibrate_threshold, load_unsw


def main() -> dict:
    db = SessionLocal()
    feedback = db.query(Feedback).all()
    tp = sum(1 for f in feedback if f.label == "true_positive")
    fp = sum(1 for f in feedback if f.label == "false_positive")
    db.close()
    loaded = load_unsw()
    X, y = loaded if loaded else generate_synthetic_flows()
    # Feedback weighting: each true-positive label adds 20 malicious samples,
    # each false-positive adds 20 benign samples (small, explicit, auditable).
    rng = np.random.default_rng(7)
    extra_X, extra_y = [], []
    for _ in range(tp * 20):
        extra_X.append([rng.uniform(0.1, 30.0), rng.uniform(500, 80000), rng.uniform(200, 60000),
                        rng.uniform(5, 800), float(np.clip(rng.normal(62, 12), 0, 255)),
                        float(rng.integers(1, 25))])
        extra_y.append(1)
    for _ in range(fp * 20):
        extra_X.append([rng.uniform(0.0, 5.0), rng.uniform(40, 8000), rng.uniform(40, 5000),
                        rng.uniform(0.1, 120), float(np.clip(rng.normal(254, 4), 0, 255)),
                        float(rng.integers(1, 4))])
        extra_y.append(0)
    if extra_X:
        X = np.vstack([X, np.array(extra_X)])
        y = np.concatenate([y, np.array(extra_y)])
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = train_model(X_train, y_train)
    threshold, recall, met = calibrate_threshold(model, X_val, y_val, settings.recall_target)
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, settings.model_path)
    with open(settings.threshold_path, "w") as f:
        json.dump({"threshold": threshold, "recall_target": settings.recall_target,
                   "validation_recall": recall, "target_met": met,
                   "features": FEATURE_NAMES, "feedback_tp": tp, "feedback_fp": fp}, f, indent=2)
    status = "target met" if met else "TARGET NOT MET"
    print(f"Retrained on {len(y)} samples ({tp} TP / {fp} FP feedback): "
          f"threshold={threshold:.4f} validation_recall={recall:.4f} — {status}")
    return {"threshold": threshold, "validation_recall": recall, "target_met": met, "tp": tp, "fp": fp}


if __name__ == "__main__":
    main()
