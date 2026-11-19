"""Scoring / ML / explainability tests."""
from datetime import datetime


import numpy as np
import pytest

from api.explain import explain_factors
from api.mitre import asset_criticality, mitre_for_rule
from api.scoring import (
    FEATURE_NAMES, extract_features, generate_synthetic_flows, load_model,
    ml_probability, noisy_or, score_incident,
)
from scripts.train import calibrate_incident_threshold, calibrate_threshold

T = datetime(2026, 11, 19, 9, 0, 0)


def _a(rule="Suspicious PowerShell", sev="high", host="web-01", src="10.0.0.7"):
    return {"timestamp": T, "rule_name": rule, "severity": sev, "host": host,
            "src_ip": src, "dst_ip": "10.0.0.20", "raw": {}}


def test_extract_features_has_six_flow_values_and_no_severity_or_ip():
    # Flow columns only: UNSW-NB15 has no severity, and severity enters
    # only through the priority formula, never through the model.
    assert FEATURE_NAMES == ["dur", "sbytes", "dbytes", "rate", "sttl", "ct_srv_src"]
    assert not any("octet" in f or "ip" in f or "sev" in f for f in FEATURE_NAMES)
    feats = extract_features(_a())
    assert len(feats) == 6
    # No flow data in raw -> all NaN (no evidence), never a silent 0.
    assert all(np.isnan(v) for v in feats)


def test_ml_probability_in_range():
    flow = {"dur": 10.0, "sbytes": 40000, "dbytes": 20000, "rate": 300,
            "sttl": 62, "ct_srv_src": 12}
    assert 0.0 <= ml_probability(_a() | {"raw": flow}) <= 1.0


def test_ml_probability_none_without_flow_evidence():
    """No flow evidence -> None, never an invented probability."""
    assert ml_probability(_a()) is None  # raw == {}
    assert ml_probability(_a() | {"raw": {"dur": None, "sbytes": None}}) is None


def test_ml_probability_differs_for_different_flow_values(monkeypatch):
    """The model actually reads the flows: malicious-like vs benign-like
    flows must score differently (same rule, same severity, same host).

    Uses a synthetic-trained model on purpose: the shipped UNSW-trained
    model ranks these hand-picked flows the other way round (in real
    UNSW-NB15 traffic small fast flows are often probes, so "small" is
    not "benign" there) — direction is a property of the training data,
    not of whether the model reads its inputs.
    """
    import api.scoring as scoring
    X, y = generate_synthetic_flows(500, seed=3)
    model = scoring.train_model(X, y)
    monkeypatch.setattr(scoring, "load_model", lambda: (model, 0.5))
    scoring.clear_model_cache()
    mal = {"dur": 10.0, "sbytes": 40000, "dbytes": 20000, "rate": 300,
           "sttl": 62, "ct_srv_src": 12}
    ben = {"dur": 0.5, "sbytes": 500, "dbytes": 300, "rate": 10,
           "sttl": 254, "ct_srv_src": 1}
    p_mal = ml_probability(_a() | {"raw": mal})
    p_ben = ml_probability(_a() | {"raw": ben})
    assert p_mal is not None and p_ben is not None
    assert p_mal > p_ben
    scoring.clear_model_cache()


def test_score_incident_no_evidence_returns_none_and_never_suppresses():
    """All alerts without flow data: ml_probability None, priority from
    severity + asset criticality only (ML term omitted, not zeroed)."""
    priority, prob = score_incident([_a(sev="critical", host="dc-01")])
    assert prob is None
    assert priority == pytest.approx(0.4 * 1.0 + 0.3 * 1.0)


def test_critical_host_scores_higher_than_workstation():
    crit, _ = score_incident([_a(host="dc-01", sev="critical")])
    low, _ = score_incident([_a(host="workstation-01", sev="low")])
    assert crit > low


def test_score_incident_empty_is_zero():
    assert score_incident([]) == (0.0, None)


def test_score_incident_returns_bounded_values():
    flow = {"dur": 10.0, "sbytes": 40000, "dbytes": 20000, "rate": 300,
            "sttl": 62, "ct_srv_src": 12}
    priority, prob = score_incident([_a() | {"raw": flow},
                                     _a(rule="Mimikatz Credential Dump", sev="critical") | {"raw": flow}])
    assert 0.0 <= priority <= 1.0 and 0.0 <= prob <= 1.0


def test_generate_synthetic_flows_shape_and_balance():
    X, y = generate_synthetic_flows(200)
    assert X.shape == (200, 6) and y.shape == (200,)
    assert int(y.sum()) == 100


def test_calibration_meets_recall_target():
    X, y = generate_synthetic_flows(1000)
    model, _ = load_model()
    threshold, recall, met = calibrate_threshold(model, X, y, 0.95)
    assert met and recall >= 0.95 and 0.0 <= threshold <= 1.0


def test_calibration_threshold_above_095_is_reachable():
    """When malicious scores sit at 0.99 and benign at 0.5, the highest
    threshold meeting a 0.95 recall target is 0.99, not a grid value."""
    class _M:
        def predict_proba(self, X):
            return np.array([[1 - p, p] for p in X[:, 0]])
    X = np.array([[0.99]] * 20 + [[0.5]] * 20)
    y = np.array([1] * 20 + [0] * 20)
    threshold, recall, met = calibrate_threshold(_M(), X, y, 0.95)
    assert met and threshold == pytest.approx(0.99) and recall == pytest.approx(1.0)


def test_calibration_target_unattainable_reports_not_met():
    """No malicious rows in validation: recall is undefined, so the target
    cannot be met — the function must say so, not silently claim success."""
    class _M:
        def predict_proba(self, X):
            return np.array([[0.9, 0.1]] * len(X))
    X = np.array([[0.1]] * 10)
    y = np.array([0] * 10)
    threshold, recall, met = calibrate_threshold(_M(), X, y, 0.95)
    assert met is False and recall == 0.0


def test_calibration_incident_level_highest_threshold():
    scores = [0.99, 0.98, 0.97, 0.96, 0.20, 0.10]
    labels = [1, 1, 1, 1, 0, 0]
    threshold, recall, met = calibrate_incident_threshold(scores, labels, 0.95)
    assert met and threshold == pytest.approx(0.96) and recall == pytest.approx(1.0)


def test_noisy_or_beats_mean_dilution():
    """One high-probability alert among five benign ones must still surface:
    noisy-OR ~0.99 where the mean would be ~0.21."""
    probs = [0.99, 0.05, 0.05, 0.05, 0.05, 0.05]
    assert noisy_or(probs) == pytest.approx(0.99, abs=0.01)
    assert sum(probs) / len(probs) < 0.25
    assert noisy_or([]) == 0.0
    assert noisy_or([0.0, 0.0]) == 0.0


def test_score_incident_uses_noisy_or_not_mean(monkeypatch):
    """A dilution incident (1 malicious-flow alert + 5 benign-flow alerts)
    keeps a pooled probability near the malicious alert's, not the mean.

    Uses a synthetic-trained model (see test_ml_probability_differs...):
    the shipped UNSW-trained model ranks these hand-picked flows
    differently, which is a property of the training data, not of pooling.
    """
    import api.scoring as scoring
    X, y = generate_synthetic_flows(500, seed=3)
    model = scoring.train_model(X, y)
    monkeypatch.setattr(scoring, "load_model", lambda: (model, 0.5))
    scoring.clear_model_cache()
    from datetime import datetime
    T = datetime(2026, 11, 19, 9, 0, 0)
    mal = {"dur": 10.0, "sbytes": 40000, "dbytes": 20000, "rate": 300, "sttl": 62, "ct_srv_src": 12}
    ben = {"dur": 0.5, "sbytes": 500, "dbytes": 300, "rate": 10, "sttl": 254, "ct_srv_src": 1}
    alerts = [{"timestamp": T, "rule_name": "Mimikatz Credential Dump", "severity": "critical",
               "host": "db-01", "src_ip": "10.0.0.7", "dst_ip": "10.0.0.30", "raw": mal}]
    alerts += [{"timestamp": T, "rule_name": "Suspicious Registry Change", "severity": "low",
                "host": "db-01", "src_ip": "10.0.0.7", "dst_ip": "10.0.0.30", "raw": ben} for _ in range(5)]
    _, pooled = score_incident(alerts)
    assert pooled >= 0.9


def test_mitre_map_has_12_rules():
    from api.mitre import RULE_TO_MITRE
    assert len(RULE_TO_MITRE) == 12
    assert mitre_for_rule("Mimikatz Credential Dump") == "T1003.001"
    assert mitre_for_rule("Unknown Rule") is None


def test_asset_criticality_known_and_unknown():
    assert asset_criticality("dc-01") == 1.0
    assert asset_criticality("no-such-host") == 0.5
    assert asset_criticality(None) == 0.5


def test_explain_factors_mentions_mitre_and_duplicates():
    factors = explain_factors([_a()], ml_probability=0.9, duplicate_count=3)
    text = " ".join(factors)
    assert "T1059.001" in text and "3 duplicate" in text
    assert len(factors) <= 5


def test_explain_factors_no_evidence_says_so():
    factors = explain_factors([_a()], ml_probability=None, duplicate_count=0)
    text = " ".join(factors)
    assert "No flow evidence" in text


def test_fallback_ignores_unsw_threshold_json(monkeypatch, tmp_path):
    """Regression: with no saved model, load_model must NOT reuse the
    threshold from models/threshold.json (which belongs to the
    UNSW-trained model). It trains a synthetic model and calibrates its
    own threshold on the deterministic synthetic train/val split.

    A decoy threshold.json is planted with a value the fallback must
    never return; the returned threshold must equal a freshly calibrated
    synthetic threshold instead.
    """
    import json

    import api.scoring as scoring
    from api.config import settings
    from sklearn.model_selection import train_test_split

    decoy = tmp_path / "threshold.json"
    decoy.write_text(json.dumps({"threshold": 0.123456, "source": "unsw-nb15.csv"}))
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "no-such-model.pkl"))
    monkeypatch.setenv("THRESHOLD_PATH", str(decoy))
    scoring.clear_model_cache()
    try:
        _, threshold = load_model()
        X, y = generate_synthetic_flows(2000, seed=42)
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
        expected_model = scoring.train_model(X_train, y_train)
        expected, _, _ = calibrate_threshold(
            expected_model, X_val, y_val, settings.recall_target)
        assert threshold == pytest.approx(expected)
        assert threshold != pytest.approx(0.123456)
        # Deterministic: a second load after clearing the cache gives
        # the same self-calibrated threshold.
        scoring.clear_model_cache()
        _, threshold2 = load_model()
        assert threshold2 == pytest.approx(threshold)
    finally:
        scoring.clear_model_cache()


def test_fallback_works_without_any_threshold_file(monkeypatch, tmp_path):
    """Regression: with neither model.pkl nor threshold.json present,
    the fallback still loads and returns a usable calibrated threshold."""
    import api.scoring as scoring

    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "no-such-model.pkl"))
    monkeypatch.setenv("THRESHOLD_PATH", str(tmp_path / "no-such-threshold.json"))
    scoring.clear_model_cache()
    try:
        model, threshold = load_model()
        assert model is not None
        assert 0.0 < threshold <= 1.0
    finally:
        scoring.clear_model_cache()


def test_saved_model_uses_its_paired_threshold(monkeypatch, tmp_path):
    """Saved-model path: a valid model.pkl loads together with the
    threshold from its paired threshold.json, unchanged."""
    import json

    import joblib

    import api.scoring as scoring

    X, y = generate_synthetic_flows(500, seed=3)
    model = scoring.train_model(X, y)
    pkl = tmp_path / "model.pkl"
    joblib.dump(model, pkl)
    thr = tmp_path / "threshold.json"
    thr.write_text(json.dumps({"threshold": 0.4242}))
    monkeypatch.setenv("MODEL_PATH", str(pkl))
    monkeypatch.setenv("THRESHOLD_PATH", str(thr))
    scoring.clear_model_cache()
    try:
        _, threshold = load_model()
        assert threshold == pytest.approx(0.4242)
    finally:
        scoring.clear_model_cache()
