"""Suppression / reopen API tests: hidden-by-default, reopen, status clears,
metrics consistency, headline 'target not met', noisy-OR dilution at API level."""
from datetime import datetime, timedelta

from tests.conftest import HEADERS

T0 = datetime(2026, 11, 19, 9, 0, 0)
BENIGN_FLOW = {"dur": 0.5, "sbytes": 500, "dbytes": 300, "rate": 10,
               "sttl": 254, "ct_srv_src": 1}
MALICIOUS_FLOW = {"dur": 10.0, "sbytes": 40000, "dbytes": 20000, "rate": 300,
                  "sttl": 62, "ct_srv_src": 12}


def _alert(aid, ts, rule="Suspicious Registry Change", sev="low", host="workstation-01",
           raw=None, malicious=False):
    return {"id": aid, "timestamp": ts.isoformat() if isinstance(ts, datetime) else ts,
            "source": "siem-demo", "rule_name": rule, "severity": sev,
            "src_ip": "10.0.0.7", "dst_ip": "10.0.0.20", "host": host,
            "raw": raw if raw is not None else BENIGN_FLOW, "is_malicious": malicious}


def _post(client, alerts):
    return client.post("/alerts", json={"alerts": alerts}, headers=HEADERS)


def _incidents(client, suppressed=False):
    q = "/incidents?include_suppressed=true" if suppressed else "/incidents"
    return client.get(q, headers=HEADERS).json()


def test_benign_low_probability_incident_is_suppressed_and_hidden_by_default(client):
    r = _post(client, [_alert("b1", T0, malicious=False)])
    assert r.status_code == 200
    assert _incidents(client) == []
    hidden = _incidents(client, suppressed=True)
    assert len(hidden) == 1
    inc = hidden[0]
    assert inc["suppressed"] is True
    assert inc["suppression_reason"] and "below calibrated threshold" in inc["suppression_reason"]


def test_reopen_returns_suppressed_incident_to_the_queue(client):
    _post(client, [_alert("b1", T0, malicious=False)])
    inc_id = _incidents(client, suppressed=True)[0]["id"]
    r = client.post(f"/incidents/{inc_id}/reopen", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "new"
    assert r.json()["suppressed"] is False
    assert r.json()["suppression_reason"] is None
    shown = _incidents(client)
    assert len(shown) == 1 and shown[0]["id"] == inc_id


def test_reopen_404(client):
    assert client.post("/incidents/9999/reopen", headers=HEADERS).status_code == 404


def test_patch_status_on_suppressed_incident_clears_suppression(client):
    _post(client, [_alert("b1", T0, malicious=False)])
    inc_id = _incidents(client, suppressed=True)[0]["id"]
    r = client.patch(f"/incidents/{inc_id}/status", json={"status": "investigating"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "investigating"
    assert r.json()["suppressed"] is False
    assert r.json()["suppression_reason"] is None
    assert len(_incidents(client)) == 1


def test_metrics_mixed_set_counts_and_after_triage_reduction(client):
    _post(client, [_alert("m1", T0, rule="Mimikatz Credential Dump", sev="critical",
                          host="db-01", raw=MALICIOUS_FLOW, malicious=True)])
    _post(client, [_alert("b1", T0 + timedelta(minutes=5), malicious=False)])
    m = client.get("/metrics", headers=HEADERS).json()
    assert m["total_alerts"] == 2 and m["total_incidents"] == 2
    assert m["surfaced_incidents"] == 1 and m["suppressed_incidents"] == 1
    assert m["recall_at_threshold"] == 1.0 and m["recall_target_met"] is True
    # after-triage reduction == (raw - surfaced) / raw, reported only because
    # the recall target was met.
    assert m["after_triage_reduction_pct"] == round(100.0 * (1 - 1 / 2), 2)
    assert m["headline_reduction_label"] == f"{m['after_triage_reduction_pct']}%"


def test_metrics_headline_is_target_not_met_when_malicious_incident_suppressed(client):
    # Labelled malicious, but benign flows + low severity -> below threshold.
    _post(client, [_alert("m1", T0, malicious=True)])
    m = client.get("/metrics", headers=HEADERS).json()
    assert m["recall_at_threshold"] == 0.0
    assert m["recall_target_met"] is False
    assert m["after_triage_reduction_pct"] is None
    assert m["headline_reduction_pct"] is None
    assert m["headline_reduction_label"] == "target not met"


def test_noisy_or_dilution_incident_surfaces_via_api(client):
    """1 malicious-flow alert + 5 benign-flow alerts in one incident: the
    noisy-OR pooled probability stays near the malicious alert's, so the
    incident surfaces instead of being diluted into suppression."""
    alerts = [_alert("d0", T0, rule="Mimikatz Credential Dump", sev="critical",
                     host="db-01", raw=MALICIOUS_FLOW, malicious=True)]
    # Benign alerts 6 minutes apart: outside the 300s dedup window, so all
    # five stay distinct (same rule/host would otherwise dedup to one).
    alerts += [_alert(f"d{i}", T0 + timedelta(minutes=i * 6), host="db-01",
                      raw=BENIGN_FLOW, malicious=False) for i in range(1, 6)]
    r = _post(client, alerts)
    assert r.status_code == 200
    shown = _incidents(client)
    assert len(shown) == 1
    assert shown[0]["suppressed"] is False
    assert shown[0]["alert_count"] == 6
    assert shown[0]["ml_probability"] >= 0.9
