"""Deduplication: fingerprint + time window. Duplicates are linked, never deleted."""
import hashlib
from datetime import datetime

from api.config import settings


def fingerprint(rule_name: str, src_ip: str | None, dst_ip: str | None, host: str | None) -> str:
    """Stable hash of the fields that define 'the same alert firing again'."""
    key = "|".join([rule_name or "", src_ip or "", dst_ip or "", host or ""])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def is_duplicate_of(first_seen: datetime, candidate: datetime, window_seconds: int | None = None) -> bool:
    """True if ``candidate`` falls within the dedup window after ``first_seen``.

    Boundary: exactly ``window_seconds`` apart counts as a duplicate
    (``<=``), one second later does not. ``candidate`` before ``first_seen``
    is never a duplicate.
    """
    window = settings.dedup_window_seconds if window_seconds is None else window_seconds
    delta = (candidate - first_seen).total_seconds()
    return 0 <= delta <= window


def dedup_batch(alerts: list[dict], window_seconds: int | None = None) -> tuple[list[dict], list[dict]]:
    """Split a time-sorted batch into kept alerts and duplicates (pure function).

    ``alerts`` are dicts with keys rule_name/src_ip/dst_ip/host/timestamp.
    The first alert per fingerprint is kept; later ones inside the window are
    duplicates and carry ``duplicate_of`` = the kept alert's id.
    """
    window = settings.dedup_window_seconds if window_seconds is None else window_seconds
    first_seen: dict[str, dict] = {}
    kept, duplicates = [], []
    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        fp = fingerprint(alert.get("rule_name"), alert.get("src_ip"), alert.get("dst_ip"), alert.get("host"))
        alert = dict(alert)
        alert["fingerprint"] = fp
        first = first_seen.get(fp)
        if first is not None and is_duplicate_of(first["timestamp"], alert["timestamp"], window):
            alert["is_duplicate"] = True
            alert["duplicate_of"] = first.get("id")
            duplicates.append(alert)
        else:
            alert["is_duplicate"] = False
            alert["duplicate_of"] = None
            first_seen[fp] = alert
            kept.append(alert)
    return kept, duplicates
