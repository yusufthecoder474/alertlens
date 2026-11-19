"""Correlation: group deduped (kept) alerts into incidents.

Key = (host or src_ip). Alerts for the same key join one incident while the
gap since that key's last alert stays within the correlation window; a gap
over the window starts a new incident for that key. Grouping is per key, so
alerts for other hosts interleaved in time never split an incident.
"""
from datetime import datetime

from api.config import settings


def correlation_key(alert: dict) -> str:
    """Group key for an alert: host first, falling back to source IP."""
    return alert.get("host") or alert.get("src_ip") or "unknown"


def correlate(alerts: list[dict], window_seconds: int | None = None) -> list[list[dict]]:
    """Group time-sorted alerts into incidents, one running group per key."""
    window = settings.correlation_window_seconds if window_seconds is None else window_seconds
    open_groups: dict[str, list[dict]] = {}
    last_seen: dict[str, datetime] = {}
    finished: list[list[dict]] = []
    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        key = correlation_key(alert)
        gap = (alert["timestamp"] - last_seen[key]).total_seconds() if key in last_seen else 0
        if key in open_groups and gap > window:
            finished.append(open_groups.pop(key))
        open_groups.setdefault(key, []).append(alert)
        last_seen[key] = alert["timestamp"]
    finished.extend(open_groups.values())
    return finished
