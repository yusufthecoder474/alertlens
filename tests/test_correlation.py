"""Correlation unit tests."""
from datetime import datetime, timedelta

from api.correlation import correlate, correlation_key

T0 = datetime(2026, 11, 19, 9, 0, 0)


def _a(ts, host="web-01", src="10.0.0.7", rule="Port Scan Detected"):
    return {"timestamp": ts, "host": host, "src_ip": src, "rule_name": rule}


def test_same_host_groups_into_one_incident():
    groups = correlate([_a(T0), _a(T0 + timedelta(minutes=10)), _a(T0 + timedelta(minutes=20))], 3600)
    assert len(groups) == 1 and len(groups[0]) == 3


def test_gap_over_window_splits_incident():
    groups = correlate([_a(T0), _a(T0 + timedelta(seconds=3601))], 3600)
    assert len(groups) == 2


def test_gap_exactly_at_window_stays_together():
    groups = correlate([_a(T0), _a(T0 + timedelta(seconds=3600))], 3600)
    assert len(groups) == 1


def test_different_hosts_split():
    groups = correlate([_a(T0, host="web-01"), _a(T0, host="db-01")], 3600)
    assert len(groups) == 2


def test_host_missing_falls_back_to_src_ip():
    assert correlation_key({"host": None, "src_ip": "1.2.3.4"}) == "1.2.3.4"
    assert correlation_key({"host": "", "src_ip": "1.2.3.4"}) == "1.2.3.4"


def test_empty_input_no_groups():
    assert correlate([], 3600) == []


def test_unsorted_input_is_sorted_before_grouping():
    groups = correlate([_a(T0 + timedelta(minutes=5)), _a(T0)], 3600)
    assert len(groups) == 1 and groups[0][0]["timestamp"] == T0


def test_three_attack_chain_groups_as_one():
    alerts = [_a(T0 + timedelta(minutes=i * 7), rule=r) for i, r in
              enumerate(["Port Scan Detected", "Suspicious PowerShell", "Data Exfiltration Large Upload"])]
    groups = correlate(alerts, 3600)
    assert len(groups) == 1 and len(groups[0]) == 3
