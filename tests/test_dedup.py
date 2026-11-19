"""Dedup unit tests, including window-boundary edge cases."""
from datetime import datetime, timedelta

from api.dedup import dedup_batch, fingerprint, is_duplicate_of

T0 = datetime(2026, 11, 19, 9, 0, 0)


def _alert(ts, rule="Suspicious PowerShell", src="10.0.0.7", dst="10.0.0.20", host="workstation-01", aid="a1"):
    return {"id": aid, "timestamp": ts, "rule_name": rule, "src_ip": src, "dst_ip": dst, "host": host}


def test_fingerprint_stable_for_same_fields():
    a = fingerprint("R", "1.1.1.1", "2.2.2.2", "h1")
    assert a == fingerprint("R", "1.1.1.1", "2.2.2.2", "h1")


def test_fingerprint_differs_when_rule_changes():
    assert fingerprint("R1", "1.1.1.1", "2.2.2.2", "h1") != fingerprint("R2", "1.1.1.1", "2.2.2.2", "h1")


def test_fingerprint_differs_when_src_ip_changes():
    assert fingerprint("R", "1.1.1.1", "2.2.2.2", "h1") != fingerprint("R", "1.1.1.2", "2.2.2.2", "h1")


def test_fingerprint_differs_when_host_changes():
    assert fingerprint("R", "1.1.1.1", "2.2.2.2", "h1") != fingerprint("R", "1.1.1.1", "2.2.2.2", "h2")


def test_fingerprint_handles_none_fields():
    assert fingerprint("R", None, None, None) == fingerprint("R", None, None, None)


def test_exactly_at_window_is_duplicate():
    assert is_duplicate_of(T0, T0 + timedelta(seconds=300), 300) is True


def test_one_second_past_window_is_not_duplicate():
    assert is_duplicate_of(T0, T0 + timedelta(seconds=301), 300) is False


def test_candidate_before_first_is_not_duplicate():
    assert is_duplicate_of(T0, T0 - timedelta(seconds=10), 300) is False


def test_same_second_is_duplicate():
    assert is_duplicate_of(T0, T0, 300) is True


def test_dedup_batch_keeps_first_and_links_rest():
    alerts = [_alert(T0 + timedelta(seconds=i * 10), aid=f"a{i}") for i in range(5)]
    kept, dups = dedup_batch(alerts, 300)
    assert len(kept) == 1 and len(dups) == 4
    assert all(d["duplicate_of"] == "a0" for d in dups)
    assert all(d["is_duplicate"] for d in dups)


def test_dedup_batch_new_window_after_expiry_keeps_again():
    alerts = [_alert(T0, aid="a0"), _alert(T0 + timedelta(seconds=301), aid="a1"),
              _alert(T0 + timedelta(seconds=302), aid="a2")]
    kept, dups = dedup_batch(alerts, 300)
    assert len(kept) == 2 and len(dups) == 1


def test_dedup_batch_different_hosts_not_duplicates():
    alerts = [_alert(T0, host="h1", aid="a0"), _alert(T0, host="h2", aid="a1")]
    kept, dups = dedup_batch(alerts, 300)
    assert len(kept) == 2 and not dups


def test_dedup_batch_empty_input():
    assert dedup_batch([], 300) == ([], [])


def test_dedup_batch_unsorted_input_sorted_by_time():
    alerts = [_alert(T0 + timedelta(seconds=60), aid="a1"), _alert(T0, aid="a0")]
    kept, dups = dedup_batch(alerts, 300)
    assert kept[0]["id"] == "a0" and dups[0]["duplicate_of"] == "a0"
