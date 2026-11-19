"""Load a CSV of alerts into a running API (POST /alerts in batches of 200).
Usage: API_KEY=... python scripts/load_csv.py data/sample_alerts.csv
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import json
import os
import sys

import httpx

API_URL = os.environ.get("API_URL", "http://localhost:8000")
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise SystemExit("API_KEY is required in the environment to load alerts "
                     "(the same key the API was started with). "
                     "Run: API_KEY=<your key> python scripts/load_csv.py <file>")


def _parse_raw(value) -> dict:
    """Parse the ``raw`` JSON column when present; empty -> {}."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}


def main(path: str) -> None:
    with open(path) as f:
        rows = list(csv.DictReader(f))
    alerts = [{
        "id": r["id"], "timestamp": r["timestamp"], "source": r["source"],
        "rule_name": r["rule_name"], "severity": r["severity"],
        "src_ip": r.get("src_ip") or None, "dst_ip": r.get("dst_ip") or None,
        "host": r.get("host") or None, "raw": _parse_raw(r.get("raw")),
        "is_malicious": r.get("is_malicious") == "1",
    } for r in rows]
    total = {"inserted": 0, "skipped": 0, "duplicates": 0}
    for i in range(0, len(alerts), 200):
        resp = httpx.post(f"{API_URL}/alerts", headers={"X-API-Key": API_KEY}, trust_env=False,
                          json={"alerts": alerts[i:i + 200]}, timeout=30.0)
        resp.raise_for_status()
        for k in total:
            total[k] += resp.json().get(k, 0)
    print(f"Loaded {len(alerts)} alerts from {path}: {json.dumps(total)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/sample_alerts.csv")
