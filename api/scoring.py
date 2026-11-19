"""Incident scoring: weighted severity + asset criticality + ML probability.

priority = 0.4 * mean severity + 0.3 * asset criticality + 0.3 * ML probability

Model features (``FEATURE_NAMES``) are real UNSW-NB15 flow columns only —
**no IP-derived features and no severity**: UNSW-NB15 has no severity
column, and severity enters the score only through the priority formula
above, never through the model. Source/destination IPs are identifiers
in alerts, never model inputs. Flow fields come from ``alert["raw"]``
when a SIEM provides them; a missing flow field is ``NaN`` and is
median-imputed inside the saved sklearn Pipeline
(``SimpleImputer(strategy="median")`` + ``StandardScaler`` +
``GradientBoostingClassifier``). Missing values are never zero-filled and
never clipped to 1: the imputer's medians come from the training data.

**No evidence, no suppression:** an alert with no flow evidence at all
(all six flow fields missing) gets ``ml_probability=None`` — it is never
scored by the model and never suppresses an incident. An incident whose
alerts all lack flow evidence has ``ml_probability=None`` and is never
suppressed; its priority is 0.4 * mean severity + 0.3 * asset criticality
(the ML term is omitted, not zeroed).

Incident ML pooling is **noisy-OR**, not the mean:
``pooled = 1 - prod(1 - p_i)`` over alerts *with* flow evidence. One
strongly malicious alert must surface an incident even when it sits
among many benign alerts; the mean let benign alerts dilute an attack
to invisibility (see tests/test_scoring.py).
"""
import json
import math
import os

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from api.config import settings
from api.mitre import SEVERITY_WEIGHT, asset_criticality

# Real UNSW-NB15 columns only. No IP octets, no hour, nothing derived
# from an IP address, and no severity — severity enters only through the
# priority formula in score_incident(), never through the model.
FEATURE_NAMES = ["dur", "sbytes", "dbytes", "rate", "sttl", "ct_srv_src"]
_model_cache: dict = {}

# Deterministic synthetic fallback (see load_model): fixed seed and
# fixed train/validation split, so every portable (model.pkl-free)
# build trains and calibrates the same model and threshold.
FALLBACK_SEED = 42
FALLBACK_FLOWS = 2000
FALLBACK_VAL_FRACTION = 0.2


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

    return [_flow(name) for name in FEATURE_NAMES]


def has_flow_evidence(alert: dict) -> bool:
    """True when at least one flow feature is observed (not NaN).

    An alert with an empty ``raw`` (or all flow fields missing) has no
    flow evidence: the model must not score it (see ml_probability).
    """
    return any(not math.isnan(v) for v in extract_features(alert))


def generate_synthetic_flows(n: int = 2000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Synthetic UNSW-NB15-style flow data (labelled, reproducible).

    Ranges follow the real UNSW-NB15 columns (dur in seconds, sbytes/dbytes
    in bytes, rate in packets/sec, sttl 0-255, ct_srv_src count). The
    classes **overlap realistically**, in two ways:

    1. Overlapping ranges: sttl is N(90, 45) malicious vs N(200, 60) benign
       and rate is 1-800 vs 0.1-400, so neither feature separates the
       classes on its own (the old sttl of N(62, 12) vs N(254, 4) did).
    2. Cross-drawn rows: ~15% of malicious rows use benign-like flow
       columns ("stealthy attacks") and ~10% of benign rows use
       malicious-like flow columns ("scanners/backups"). Severity is not
       a column here at all, so severity alone cannot solve the task.

    Used when the real UNSW-NB15 file is absent (see scripts/train.py).
    Because the generator and the model share these distributions, any
    evaluation on this data is an **upper bound** on real-world performance
    (see README Limitations).
    """
    rng = np.random.default_rng(seed)
    half = n // 2

    def _flows(malicious: bool, count: int) -> np.ndarray:
        if malicious:
            dur = rng.uniform(0.05, 30.0, count)
            sbytes = rng.uniform(100, 80000, count)
            dbytes = rng.uniform(100, 60000, count)
            rate = rng.uniform(1, 800, count)
            sttl = np.clip(rng.normal(90, 45, count), 0, 255)
            ct = rng.integers(1, 25, count).astype(float)
        else:
            dur = rng.uniform(0.0, 15.0, count)
            sbytes = rng.uniform(40, 30000, count)
            dbytes = rng.uniform(40, 20000, count)
            rate = rng.uniform(0.1, 400, count)
            sttl = np.clip(rng.normal(200, 60, count), 0, 255)
            ct = rng.integers(1, 12, count).astype(float)
        return np.column_stack([dur, sbytes, dbytes, rate, sttl, ct])

    X_mal = _flows(True, half)
    X_ben = _flows(False, half)
    # Stealthy attacks (15%) and scanner/backup-like benign traffic (10%).
    stealth = rng.random(half) < 0.15
    if stealth.any():
        X_mal[stealth] = _flows(False, int(stealth.sum()))
    noisy = rng.random(half) < 0.10
    if noisy.any():
        X_ben[noisy] = _flows(True, int(noisy.sum()))

    X = np.vstack([X_ben, X_mal])
    y = np.array([0] * half + [1] * half)
    idx = rng.permutation(n)
    X, y = X[idx], y[idx]
    return inject_missing(X, seed=seed), y


def inject_missing(X: np.ndarray, frac: float = 0.25, seed: int = 7) -> np.ndarray:
    """Blank a random proper subset of flow columns in ``frac`` of rows.

    Alerts posted with partial flow data arrive with some NaN features and
    are median-imputed by the Pipeline. If the model never saw such rows
    in training, the imputed point is out-of-distribution and the tree
    routes it arbitrarily. Injecting the same partial missingness into
    training — with the label kept — teaches the model to handle it.
    Only a *proper* subset is blanked (1 to n-1 columns): a row that is
    entirely blank has no flow evidence at all, is never scored — see
    ml_probability — and must not be modelled as a median-imputed point.
    """
    X = X.astype(float).copy()
    rng = np.random.default_rng(seed)
    n_cols = X.shape[1]
    for i in range(len(X)):
        if rng.random() < frac:
            k = int(rng.integers(1, n_cols))  # 1..n-1 columns blanked
            cols = rng.choice(n_cols, size=k, replace=False)
            X[i, cols] = np.nan
    return X


def train_model(X: np.ndarray, y: np.ndarray) -> Pipeline:
    """Train the Pipeline (imputer + scaler + GradientBoosting) on flows."""
    model = build_pipeline()
    model.fit(X, y)
    return model


def _calibrate_flow_threshold(model, X_val: np.ndarray, y_val: np.ndarray,
                              target: float) -> tuple[float, float, bool]:
    """Highest threshold whose malicious recall on val is >= ``target``.

    Same rule as ``scripts/train.py::calibrate_threshold`` (kept here
    because that module imports this one, so it cannot be imported back):
    scan the unique validation probabilities highest-first and pick the
    highest threshold still meeting the target. Returns
    (threshold, recall, target_met); if no threshold meets the target,
    returns the lowest observed probability, the best recall found, and
    ``target_met=False`` — the caller must report "target not met".
    """
    y_val = np.asarray(y_val)
    if int((y_val == 1).sum()) == 0:
        return 0.0, 0.0, False
    probs = model.predict_proba(X_val)[:, 1]
    candidates = sorted(set(float(p) for p in probs) | {1.0}, reverse=True)
    best_recall = 0.0
    for t in candidates:
        recall = float(((probs >= t) & (y_val == 1)).sum()
                       / max(int((y_val == 1).sum()), 1))
        best_recall = max(best_recall, recall)
        if recall >= target:
            return float(t), recall, True
    return float(min(candidates)), best_recall, False


def load_model() -> tuple[Pipeline, float]:
    """Load the saved Pipeline + its paired threshold, or train a
    synthetic fallback with its own calibrated threshold.

    Saved-model path: ``models/model.pkl`` and ``models/threshold.json``
    are a pair written together by ``scripts/train.py``; the threshold
    file is read ONLY when a valid saved model was actually loaded.

    Fallback path (no valid ``models/model.pkl`` — e.g. the portable zip,
    which ships no trained model): train on a deterministic synthetic
    train split and calibrate the threshold on the matching synthetic
    validation split (``generate_synthetic_flows(2000, seed=42)``,
    80/20 stratified split, ``random_state=42``). The fallback NEVER
    reads ``models/threshold.json`` — that file belongs to the
    UNSW-trained model, and reusing it would pair a synthetic-trained
    model with a threshold calibrated on different data — and never
    writes it either. A threshold is never reused across models or
    data sources. A stale model file trained on an old feature layout
    (e.g. the 7-feature one that included severity_num) is detected by
    its feature count and ignored, so an old ``models/model.pkl`` can
    never silently score with the wrong features.
    """
    if "model" in _model_cache:
        return _model_cache["model"], _model_cache["threshold"]
    model = None
    if os.path.exists(settings.model_path):
        try:
            candidate = joblib.load(settings.model_path)
            n_features = getattr(candidate, "n_features_in_", None)
            if n_features == len(FEATURE_NAMES):
                model = candidate
        except Exception:
            model = None
    if model is not None:
        threshold = 0.5
        if os.path.exists(settings.threshold_path):
            with open(settings.threshold_path) as f:
                threshold = float(json.load(f).get("threshold", 0.5))
    else:
        X, y = generate_synthetic_flows(FALLBACK_FLOWS, seed=FALLBACK_SEED)
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=FALLBACK_VAL_FRACTION,
            random_state=FALLBACK_SEED, stratify=y)
        model = train_model(X_train, y_train)
        threshold, _, _ = _calibrate_flow_threshold(
            model, X_val, y_val, settings.recall_target)
    _model_cache["model"] = model
    _model_cache["threshold"] = threshold
    return model, threshold


def clear_model_cache() -> None:
    """Drop the cached model/threshold (used by tests after retraining)."""
    _model_cache.clear()


def ml_probability(alert: dict) -> float | None:
    """ML probability that one alert is malicious (0-1), or None.

    Returns None when the alert has no flow evidence at all (all six
    flow fields missing): the model has nothing to score, so it must
    not invent a probability — callers treat None as "no evidence"
    (never suppressed, see score_incident and suppression_decision).
    """
    if not has_flow_evidence(alert):
        return None
    model, _ = load_model()
    features = np.array([extract_features(alert)], dtype=float)
    return float(model.predict_proba(features)[0][1])


def noisy_or(probs: list[float]) -> float:
    """Noisy-OR pooling: 1 - prod(1 - p_i). One strong alert surfaces."""
    if not probs:
        return 0.0
    pooled = 1.0 - math.prod(1.0 - min(max(p, 0.0), 1.0) for p in probs)
    return round(float(pooled), 4)


def score_incident(alerts: list[dict]) -> tuple[float, float | None]:
    """Return (priority_score, noisy-OR pooled ML probability) for a group.

    The pooled probability is over alerts *with* flow evidence only.
    When no alert in the group has flow evidence, the pooled probability
    is None and the priority is 0.4 * mean severity + 0.3 * asset
    criticality (the ML term is omitted, not zeroed) — severity is the
    only place it enters the score. An empty group is (0.0, None).
    """
    if not alerts:
        return 0.0, None
    sev = sum(SEVERITY_WEIGHT.get(str(a.get("severity", "low")).lower(), 0.25) for a in alerts) / len(alerts)
    crit = max(asset_criticality(a.get("host")) for a in alerts)
    probs = [p for p in (ml_probability(a) for a in alerts) if p is not None]
    if not probs:
        return round(0.4 * sev + 0.3 * crit, 4), None
    ml_prob = noisy_or(probs)
    priority = round(0.4 * sev + 0.3 * crit + 0.3 * ml_prob, 4)
    return priority, ml_prob
