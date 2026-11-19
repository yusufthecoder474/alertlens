"""Seed the database directly from data/sample_alerts.csv via the pipeline.
Usage: DATABASE_URL=... python scripts/seed.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import json
from datetime import datetime

from api.database import Base, SessionLocal, engine
from api.pipeline import ingest_alerts


def _parse_raw(value) -> dict:
    """Parse the ``raw`` JSON column when present; empty -> {}."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}

Base.metadata.create_all(bind=engine)


def main(path: str = "data/sample_alerts.csv") -> dict:
    with open(path) as f:
        rows = list(csv.DictReader(f))
    alerts = [{
        "id": r["id"], "timestamp": datetime.fromisoformat(r["timestamp"]), "source": r["source"],
        "rule_name": r["rule_name"], "severity": r["severity"],
        "src_ip": r.get("src_ip") or None, "dst_ip": r.get("dst_ip") or None,
        "host": r.get("host") or None, "raw": _parse_raw(r.get("raw")),
        "is_malicious": r.get("is_malicious") == "1",
    } for r in rows]
    db = SessionLocal()
    result = ingest_alerts(db, alerts)
    db.close()
    print(f"Seeded {len(alerts)} alerts: {result}")
    return result


if __name__ == "__main__":
    main()
