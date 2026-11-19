"""API tests: auth, ingest, workflow, metrics, rate limiting, validation."""
from datetime import datetime, timedelta


from tests.conftest import HEADERS

T0 = "2026-11-19T09:00:00"


def _alert(aid="a1", ts=T0, rule="Suspicious PowerShell", sev="high",
           src="10.0.0.7", dst="10.0.0.20", host="workstation-01"):
    return {"id": aid, "timestamp": ts, "source": "siem-demo", "rule_name": rule,
            "severity": sev, "src_ip": src, "dst_ip": dst, "host": host, "raw": {}}


def _post(client, alerts):
    return client.post("/alerts", json={"alerts": alerts}, headers=HEADERS)


def test_health_needs_no_auth(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_alerts_rejects_missing_api_key(client):
    assert client.post("/alerts", json={"alerts": [_alert()]}).status_code == 401


def test_alerts_rejects_wrong_api_key(client):
    r = client.post("/alerts", json={"alerts": [_alert()]}, headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_incidents_rejects_missing_api_key(client):
    assert client.get("/incidents").status_code == 401


def test_metrics_rejects_missing_api_key(client):
    assert client.get("/metrics").status_code == 401


def test_ingest_creates_incident(client):
    r = _post(client, [_alert()])
    assert r.status_code == 200
    assert r.json()["inserted"] == 1
    incs = client.get("/incidents", headers=HEADERS).json()
    assert len(incs) == 1 and incs[0]["alert_count"] == 1
    assert incs[0]["mitre_tags"] == ["T1059.001"]
    assert incs[0]["factors"] and incs[0]["summary"]


def test_ingest_is_idempotent_on_alert_id(client):
    _post(client, [_alert()])
    r = _post(client, [_alert()])
    assert r.json() == {"inserted": 0, "skipped": 1, "duplicates": 0,
                        "incidents_created_or_updated": 0, "incident_ids": []}
    assert client.get("/metrics", headers=HEADERS).json()["total_alerts"] == 1


def test_duplicates_linked_never_deleted(client):
    alerts = [_alert(aid=f"a{i}", ts=(datetime.fromisoformat(T0) + timedelta(seconds=i * 10)).isoformat())
              for i in range(5)]
    r = _post(client, alerts)
    assert r.json()["duplicates"] == 4
    m = client.get("/metrics", headers=HEADERS).json()
    assert m["total_alerts"] == 5 and m["duplicate_alerts"] == 4
    incs = client.get("/incidents", headers=HEADERS).json()
    assert incs[0]["duplicate_count"] == 4


def test_attack_chain_becomes_one_incident(client):
    alerts = [
        _alert("c1", "2026-11-19T09:10:00", "Port Scan Detected", "high", "203.0.113.5", "10.0.0.20", "web-01"),
        _alert("c2", "2026-11-19T09:17:00", "Suspicious PowerShell", "high", "203.0.113.5", "10.0.0.20", "web-01"),
        _alert("c3", "2026-11-19T09:24:00", "Data Exfiltration Large Upload", "high",
            "203.0.113.5", "10.0.0.20", "web-01"),
    ]
    _post(client, alerts)
    incs = client.get("/incidents", headers=HEADERS).json()
    assert len(incs) == 1 and incs[0]["alert_count"] == 3
    assert set(incs[0]["mitre_tags"]) == {"T1046", "T1059.001", "T1041"}


def test_incident_detail_has_timeline(client):
    _post(client, [_alert()])
    inc_id = client.get("/incidents", headers=HEADERS).json()[0]["id"]
    detail = client.get(f"/incidents/{inc_id}", headers=HEADERS).json()
    assert len(detail["alerts"]) == 1 and detail["alerts"][0]["rule_name"] == "Suspicious PowerShell"


def test_incident_detail_404(client):
    assert client.get("/incidents/9999", headers=HEADERS).status_code == 404


def test_status_workflow_and_invalid_status(client):
    _post(client, [_alert()])
    inc_id = client.get("/incidents", headers=HEADERS).json()[0]["id"]
    r = client.patch(f"/incidents/{inc_id}/status", json={"status": "investigating"}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["status"] == "investigating"
    assert client.patch(f"/incidents/{inc_id}/status", json={"status": "bogus"}, headers=HEADERS).status_code == 422


def test_status_404(client):
    assert client.patch("/incidents/9999/status", json={"status": "resolved"}, headers=HEADERS).status_code == 404


def test_feedback_stored_and_invalid_label_rejected(client):
    _post(client, [_alert()])
    inc_id = client.get("/incidents", headers=HEADERS).json()[0]["id"]
    r = client.post(f"/incidents/{inc_id}/feedback", json={"label": "false_positive", "note": "test"}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["label"] == "false_positive"
    assert client.post(f"/incidents/{inc_id}/feedback", json={"label": "maybe"}, headers=HEADERS).status_code == 422
    m = client.get("/metrics", headers=HEADERS).json()
    assert m["false_positive_rate"] == 1.0


def test_feedback_404(client):
    assert client.post("/incidents/9999/feedback", json={"label": "true_positive"}, headers=HEADERS).status_code == 404


def test_metrics_on_seeded_shape(client):
    _post(client, [_alert("a1"), _alert("a2", ts="2026-11-19T09:01:00", host="db-01")])
    m = client.get("/metrics", headers=HEADERS).json()
    assert m["total_alerts"] == 2 and m["total_incidents"] == 2
    assert m["alert_reduction_pct"] == 0.0 and m["threshold"] > 0


def test_validation_rejects_bad_severity(client):
    assert _post(client, [_alert(sev="urgent")]).status_code == 422


def test_validation_rejects_empty_batch(client):
    assert _post(client, []).status_code == 422


def test_validation_rejects_missing_rule(client):
    bad = _alert()
    del bad["rule_name"]
    assert _post(client, [bad]).status_code == 422


def test_incident_filter_by_status(client):
    _post(client, [_alert()])
    inc_id = client.get("/incidents", headers=HEADERS).json()[0]["id"]
    client.patch(f"/incidents/{inc_id}/status", json={"status": "resolved"}, headers=HEADERS)
    assert len(client.get("/incidents?status=resolved", headers=HEADERS).json()) == 1
    assert client.get("/incidents?status=new", headers=HEADERS).json() == []


def test_rate_limit_returns_429(monkeypatch, client):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    assert _post(client, [_alert("r1")]).status_code == 200
    assert _post(client, [_alert("r2")]).status_code == 200
    assert _post(client, [_alert("r3")]).status_code == 429
