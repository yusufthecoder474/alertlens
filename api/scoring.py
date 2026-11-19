"""Incident scoring: weighted severity + asset criticality + ML probability.

priority = 0.4 * mean severity + 0.3 * asset criticality + 0.3 * ML probability

Model features (``FEATURE_NAMES``) are real UNSW-NB15 flow columns plus the
alert's severity weight — **no IP-derived features**: source/destination IPs
are identifiers in alerts, never model inputs. Flow fields come from
``alert["raw"]`` when a SIEM provides them; a missing flow field is
``NaN`` and is median-imputed inside the saved sklearn Pipeline
(``SimpleImputer(strategy="median")`` + ``StandardScaler`` +
``GradientBoostingClassifier``). Missing values are never zero-filled and
never clipped to 1: the imputer's medians come from the training data.

Incident ML pooling is **noisy-OR**, not the mean:
``pooled = 1 - prod(1 - p_i)``. One strongly malicious alert must surface
an incident even when it sits among many benign alerts; the mean let benign
alerts dilute an attack to invisibility (see tests/test_scoring.py).
"""
import json
import math
import os

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from api.config import settings
from api.mitre import SEVERITY_WEIGHT, asset_criticality

# Real UNSW-NB15 columns (dur, sbytes, dbytes, rate, sttl, ct_srv_src)
# plus the alert severity weight. No IP octets, no hour, nothing derived
# from an IP address.
FEATURE_NAMES = ["dur", "sbytes", "dbytes", "rate", "sttl", "ct_srv_src", "severity_num"]
_model_cache: dict = {}


def build_pipeline() -> Pipeline:
    """Median imputation + scaling + GradientBoosting, as one saved object."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(random_state=42)),
    ])


def extract_features(alert: dict) -> list[float]:
    """Build the model features from one alert dict.

    Flow columns are read from ``alert["raw"]``; a missing column is
    ``float("nan")`` (median-imputed by the Pipeline), never a silent 0.
    ``severity_num`` always comes from the alert's severity.
    """
    raw = alert.get("raw") or {}

    def _flow(name: str) -> float:
        v = raw.get(name)
        if v is None:
            return float("nan")
        try:
            return float(v)
        except (TypeError, ValueError):
            return float("nan")

    return [_flow(name) for name in FEATURE_NAMES[:-1]] + [
        SEVERITY_WEIGHT.get(str(alert.get("severity", "low")).lower(), 0.25),
    ]


def generate_synthetic_flows(n: int = 2000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Synthetic UNSW-NB15-style flow data (labelled, reproducible).

    Ranges follow the real UNSW-NB15 columns (dur in seconds, sbytes/dbytes
    in bytes, rate in packets/sec, sttl 0-255, ct_srv_src count, severity
    weight 0.25-1.0). The two classes deliberately **overlap** — malicious
    flows skew longer, larger and lower-TTL, benign flows the other way, but
    neither class is separable — so a calibrated threshold is meaningful
    instead of sitting at the 0.95 edge of a trivially separable set.
    Used when the real UNSW-NB15 file is absent (see scripts/train.py).
    """
    rng = np.random.default_rng(seed)
    half = n // 2

    def _flows(malicious: bool) -> np.ndarray:
        if malicious:
            dur = rng.uniform(0.1, 30.0, half)
            sbytes = rng.uniform(500, 80000, half)
            dbytes = rng.uniform(200, 60000, half)
            rate = rng.uniform(5, 800, half)
            sttl = np.clip(rng.normal(62, 12, half), 0, 255)
            ct = rng.integers(1, 25, half).astype(float)
            sev = rng.uniform(0.5, 1.0, half)
        else:
            dur = rng.uniform(0.0, 5.0, half)
            sbytes = rng.uniform(40, 8000, half)
            dbytes = rng.uniform(40, 5000, half)
            rate = rng.uniform(0.1, 120, half)
            sttl = np.clip(rng.normal(254, 4, half), 0, 255)
            ct = rng.integers(1, 4, half).astype(float)
            sev = rng.uniform(0.25, 0.75, half)
        return np.column_stack([dur, sbytes, dbytes, rate, sttl, ct, sev])

    X = np.vstack([_flows(False), _flows(True)])
    y = np.array([0] * half + [1] * half)
    idx = rng.permutation(n)
    X, y = X[idx], y[idx]
    return inject_missing(X, seed=seed), y


def inject_missing(X: np.ndarray, frac: float = 0.25, seed: int = 7) -> np.ndarray:
    """Blank out all flow columns of ``frac`` of rows (NaN, not zero).

    Alerts posted without flow data arrive as all-NaN flow features and are
    median-imputed by the Pipeline. If the model never saw such rows in
    training, that imputed point is out-of-distribution and the tree routes
    it arbitrarily (in practice: always malicious). Injecting the same
    missingness into training — with the label kept — teaches the model
    that a no-flow alert is judged on its severity alone.
    """
    X = X.astype(float).copy()
    rng = np.random.default_rng(seed)
    mask = rng.random(len(X)) < frac
    X[mask, :6] = np.nan
    return X


def train_model(X: np.ndarray, y: np.ndarray) -> Pipeline:
    """Train the Pipeline (imputer + scaler + GradientBoosting) on flows."""
    model = build_pipeline()
    model.fit(X, y)
    return model


def load_model() -> tuple[Pipeline, float]:
    """Load the saved Pipeline + threshold, or train in memory as a fallback.

    Returns (model, threshold). Threshold defaults to 0.5 when no
    threshold file exists. A stale model file trained on the old
    7-feature layout (with IP octets) is detected by its feature count
    and ignored, so an old ``models/model.pkl`` can never silently score
    with the wrong features.
    """
    if "model" in _model_cache:
        return _model_cache["model"], _model_cache["threshold"]
    threshold = 0.5
    if os.path.exists(settings.threshold_path):
        with open(settings.threshold_path) as f:
            threshold = float(json.load(f).get("threshold", 0.5))
    model = None
    if os.path.exists(settings.model_path):
        try:
            candidate = joblib.load(settings.model_path)
            n_features = getattr(candidate, "n_features_in_", None)
            if n_features == len(FEATURE_NAMES):
                model = candidate
        except Exception:
            model = None
    if model is None:
        X, y = generate_synthetic_flows()
        model = train_model(X, y)
    _model_cache["model"] = model
    _model_cache["threshold"] = threshold
    return model, threshold


def clear_model_cache() -> None:
    """Drop the cached model/threshold (used by tests after retraining)."""
    _model_cache.clear()


def ml_probability(alert: dict) -> float:
    """ML probability that one alert is malicious (0-1)."""
    model, _ = load_model()
    features = np.array([extract_features(alert)], dtype=float)
    return float(model.predict_proba(features)[0][1])


def noisy_or(probs: list[float]) -> float:
    """Noisy-OR pooling: 1 - prod(1 - p_i). One strong alert surfaces."""
    if not probs:
        return 0.0
    pooled = 1.0 - math.prod(1.0 - min(max(p, 0.0), 1.0) for p in probs)
    return round(float(pooled), 4)


def score_incident(alerts: list[dict]) -> tuple[float, float]:
    """Return (priority_score, noisy-OR pooled ML probability) for a group."""
    if not alerts:
        return 0.0, 0.0
    sev = sum(SEVERITY_WEIGHT.get(str(a.get("severity", "low")).lower(), 0.25) for a in alerts) / len(alerts)
    crit = max(asset_criticality(a.get("host")) for a in alerts)
    ml_prob = noisy_or([ml_probability(a) for a in alerts])
    priority = round(0.4 * sev + 0.3 * crit + 0.3 * ml_prob, 4)
    return priority, ml_prob
