"""Postgres-backed concurrency test: two simultaneous ingests of the same
batch must not create duplicate Alert rows.

Skipped unless DATABASE_URL starts with "postgresql" (CI sets the Postgres
17 service URL; locally on SQLite this test is skipped — see RESULTS.md).
"""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest

from api.database import SessionLocal
from api.models import Alert
from api.pipeline import ingest_alerts

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL", "").startswith("postgresql"),
    reason="Postgres-backed concurrency test; skipped on SQLite",
)

T0 = datetime(2026, 11, 19, 9, 0, 0)


def _batch(n: int = 10) -> list[dict]:
    return [{
        "id": f"c{i}", "timestamp": T0 + timedelta(seconds=i * 10),
        "source": "siem-demo", "rule_name": "Suspicious PowerShell",
        "severity": "high", "src_ip": "10.0.0.7", "dst_ip": "10.0.0.20",
        "host": "workstation-01", "raw": {}, "is_malicious": True,
    } for i in range(n)]


def _run_once(alerts: list[dict]) -> dict:
    db = SessionLocal()
    try:
        return ingest_alerts(db, alerts)
    finally:
        db.close()


def test_two_concurrent_ingests_of_same_batch_create_no_duplicates(db):
    alerts = _batch(10)
    with ThreadPoolExecutor(max_workers=2) as ex:
        results = list(ex.map(_run_once, [alerts, alerts]))
    assert len(results) == 2
    assert all(isinstance(r, dict) and "inserted" in r for r in results)
    assert db.query(Alert).count() == 10
