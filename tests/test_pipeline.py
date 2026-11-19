"""Pipeline attach path + summary fallback tests."""
from datetime import datetime

import httpx

from api.summary import llm_summary, next_action, template_summary
from tests.conftest import HEADERS
from tests.test_api import _alert, _post


def test_second_batch_attaches_to_open_incident(client):
    _post(client, [_alert("a1", "2026-11-19T09:00:00")])
    _post(client, [_alert("a2", "2026-11-19T09:10:00")])
    incs = client.get("/incidents", headers=HEADERS).json()
    assert len(incs) == 1 and incs[0]["alert_count"] == 2


def test_resolved_incident_not_reused(client):
    _post(client, [_alert("a1", "2026-11-19T09:00:00")])
    inc_id = client.get("/incidents", headers=HEADERS).json()[0]["id"]
    client.patch(f"/incidents/{inc_id}/status", json={"status": "resolved"}, headers=HEADERS)
    _post(client, [_alert("a2", "2026-11-19T09:10:00")])
    assert len(client.get("/incidents", headers=HEADERS).json()) == 2


def test_template_summary_is_deterministic():
    inc = {"host": "web-01", "src_ip": "1.2.3.4", "mitre_tags": ["T1046"],
           "priority_score": 0.8, "ml_probability": 0.9,
           "first_seen": datetime(2026, 11, 19, 9, 0), "last_seen": datetime(2026, 11, 19, 9, 10)}
    alerts = [{"rule_name": "Port Scan Detected"}]
    s1 = template_summary(inc, alerts)
    assert template_summary(inc, alerts) == s1
    assert "web-01" in s1 and "T1046" in s1 and "isolate" in s1


def test_llm_summary_falls_back_to_template_without_key():
    inc = {"host": "web-01", "src_ip": "1.2.3.4", "mitre_tags": [], "priority_score": 0.2,
           "ml_probability": 0.1, "first_seen": "2026-11-19", "last_seen": "2026-11-19"}
    text, source = llm_summary(inc, [{"rule_name": "Port Scan Detected"}])
    assert source == "template" and "web-01" in text


def _llm_inc():
    return {"host": "web-01", "src_ip": "1.2.3.4", "mitre_tags": [], "priority_score": 0.2,
            "ml_probability": 0.1, "first_seen": "2026-11-19", "last_seen": "2026-11-19"}


def test_llm_summary_falls_back_to_template_on_timeout(monkeypatch):
    """LLM enabled + key set, but the request times out: template, not an error."""
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

    def _raise(*args, **kwargs):
        raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr("api.summary.httpx.post", _raise)
    text, source = llm_summary(_llm_inc(), [{"rule_name": "Port Scan Detected"}])
    assert source == "template" and "web-01" in text


def test_llm_summary_falls_back_to_template_on_http_error(monkeypatch):
    """LLM enabled + key set, but the request fails (e.g. 500): template."""
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

    def _raise(*args, **kwargs):
        raise httpx.HTTPError("server error")

    monkeypatch.setattr("api.summary.httpx.post", _raise)
    text, source = llm_summary(_llm_inc(), [{"rule_name": "Port Scan Detected"}])
    assert source == "template" and "web-01" in text


def test_next_action_branches():
    assert "isolate" in next_action(0.8, 0.9)
    assert "triage" in next_action(0.5, 0.3)
    assert "monitor" in next_action(0.1, 0.1)
