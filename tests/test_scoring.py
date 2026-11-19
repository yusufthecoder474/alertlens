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


def test_extract_features_has_seven_values_and_no_ip_features():
    assert FEATURE_NAMES == ["dur", "sbytes", "dbytes", "rate", "sttl", "ct_srv_src", "severity_num"]
    assert not any("octet" in f or "ip" in f for f in FEATURE_NAMES)
    feats = extract_features(_a())
    assert len(feats) == 7
    # No flow data in raw -> NaN (median-imputed by the Pipeline), never a silent 0.
    assert all(np.isnan(v) for v in feats[:6])
    assert feats[6] == 0.75  # severity_num for "high"


def test_ml_probability_in_range():
    assert 0.0 <= ml_probability(_a()) <= 1.0


def test_critical_host_scores_higher_than_workstation():
    crit, _ = score_incident([_a(host="dc-01", sev="critical")])
    low, _ = score_incident([_a(host="workstation-01", sev="low")])
    assert crit > low


def test_score_incident_empty_is_zero():
    assert score_incident([]) == (0.0, 0.0)


def test_score_incident_returns_bounded_values():
    priority, prob = score_incident([_a(), _a(rule="Mimikatz Credential Dump", sev="critical")])
    assert 0.0 <= priority <= 1.0 and 0.0 <= prob <= 1.0


def test_generate_synthetic_flows_shape_and_balance():
    X, y = generate_synthetic_flows(200)
    assert X.shape == (200, 7) and y.shape == (200,)
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


def test_score_incident_uses_noisy_or_not_mean(client=None):
    """A dilution incident (1 malicious-flow alert + 5 benign-flow alerts)
    keeps a pooled probability near the malicious alert's, not the mean."""
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
