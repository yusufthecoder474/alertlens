"""Build an alert stream from the real UNSW-NB15 dataset (if present).

NOTE on IPs: the UNSW-NB15 training set as distributed here has NO
srcip/dstip columns, so src_ip/dst_ip below are deterministic placeholder
addresses derived from the row id (10.x.y.z, hash of the id). They are
identifiers only — never model features — and are NOT the real addresses.
Hosts are derived from the same hash.

Reads ``data/unsw-nb15.csv`` and writes ``data/unsw_alerts.csv``: one alert
per dataset row, timestamps spread over hours, host assigned
deterministically from a hash of the placeholder IP into a small host pool,
``raw`` = JSON of the row's dur/sbytes/dbytes/rate/sttl/ct_srv_src, and
``is_malicious`` from the row's label.

attack_cat -> rule_name mapping (documented here because UNSW categories do
not match AlertLens rules one-to-one; the mapping is a judgement call, not a
ground truth):

    Exploits        -> "Exploit Attempt"          (not in the 12-rule MITRE map)
    Reconnaissance  -> "Port Scan Detected"
    DoS             -> "Denial of Service"        (not in the 12-rule MITRE map)
    Generic         -> "Malware Signature Match"
    Fuzzers         -> "Suspicious Traffic Burst" (not in the 12-rule MITRE map)
    Analysis        -> "Suspicious Registry Change"
    Backdoor        -> "Backdoor Activity"        (not in the 12-rule MITRE map)
    Shellcode       -> "Suspicious PowerShell"
    Worms           -> "Malware Signature Match"
    Normal          -> "Failed Login Burst"       (benign noise; label 0)

Rules marked "not in the 12-rule MITRE map" get no MITRE technique tag at
ingest time — that is honest behaviour, not a bug. Severity is derived from
the attack category: Exploits/Backdoor/Shellcode/Worms -> critical,
Reconnaissance/DoS/Generic -> high, Fuzzers/Analysis -> medium,
Normal -> low.

Where to get UNSW-NB15: UNSW Canberra,
https://research.unsw.edu.au/projects/unsw-nb15-dataset, or Kaggle
("UNSW-NB15"). Save the testing set as the canonical file
``data/unsw-nb15.csv`` (do NOT commit the dataset). This script never
downloads data: if the file is absent it prints a clear NOT RUN message and
exits 0.

Usage: python scripts/make_alerts_from_unsw.py [--seed 42]
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

UNSW_PATH = Path("data/unsw-nb15.csv")
OUT_PATH = Path("data/unsw_alerts.csv")
BASE = datetime(2026, 11, 19, 9, 0, 0)
HOST_POOL = ["workstation-01", "workstation-02", "workstation-03",
             "web-01", "web-02", "db-01", "dc-01"]

# attack_cat -> (rule_name, severity). See module docstring for the mapping.
CATEGORY_MAP = {
    "Exploits": ("Exploit Attempt", "critical"),
    "Reconnaissance": ("Port Scan Detected", "high"),
    "DoS": ("Denial of Service", "high"),
    "Generic": ("Malware Signature Match", "high"),
    "Fuzzers": ("Suspicious Traffic Burst", "medium"),
    "Analysis": ("Suspicious Registry Change", "medium"),
    "Backdoor": ("Backdoor Activity", "critical"),
    "Shellcode": ("Suspicious PowerShell", "critical"),
    "Worms": ("Malware Signature Match", "critical"),
    "Normal": ("Failed Login Burst", "low"),
}
FLOW_COLS = ["dur", "sbytes", "dbytes", "rate", "sttl", "ct_srv_src"]


def _pseudo_ip(row_id: str, which: int) -> str:
    """Deterministic placeholder IP from a row id (see module docstring).

    The distributed UNSW-NB15 training set has no srcip/dstip columns, so
    alerts get a stable 10.x.y.z address hashed from the row id instead.
    """
    digest = hashlib.sha256(f"{row_id}:{which}".encode()).hexdigest()
    return f"10.{int(digest[0:2], 16)}.{int(digest[2:4], 16)}.{int(digest[4:6], 16)}"


def host_for(srcip: str) -> str:
    """Deterministic host from srcip hash (same IP always maps to same host)."""
    digest = hashlib.sha256(str(srcip).encode()).hexdigest()
    return HOST_POOL[int(digest, 16) % len(HOST_POOL)]


def main(seed: int = 42) -> int:
    if not UNSW_PATH.exists():
        print(f"NOT RUN: {UNSW_PATH} not found. Get UNSW-NB15 from UNSW Canberra "
              "(https://research.unsw.edu.au/projects/unsw-nb15-dataset) or Kaggle "
              '("UNSW-NB15") and save the testing set as data/unsw-nb15.csv. '
              "No data was downloaded.")
        return 0
    df = pd.read_csv(UNSW_PATH, encoding="utf-8-sig")  # BOM on first column
    missing = [c for c in FLOW_COLS + ["label"] if c not in df.columns]
    if missing:
        raise ValueError(f"{UNSW_PATH} is missing required columns {missing}")
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    rows = []
    for i, r in df.iterrows():
        cat = str(r.get("attack_cat", "Normal"))
        rule, sev = CATEGORY_MAP.get(cat, ("Suspicious Traffic Burst", "medium"))
        raw = {c: (None if pd.isna(r[c]) else float(r[c])) for c in FLOW_COLS}
        src_ip = _pseudo_ip(str(r["id"]), 0)
        dst_ip = _pseudo_ip(str(r["id"]), 1)
        rows.append({
            "id": f"unsw-{i:06d}",
            "timestamp": (BASE + timedelta(seconds=int(i) * 10)).isoformat(),
            "source": "unsw-nb15",
            "rule_name": rule,
            "severity": sev,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "host": host_for(src_ip),
            "is_malicious": int(str(r["label"]).lower() in ("1", "attack", "malicious")),
            "raw": json.dumps(raw),
        })
    with open(OUT_PATH, "w", newline="") as f:
        import csv
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} alerts to {OUT_PATH} "
          f"({sum(r['is_malicious'] for r in rows)} malicious) from {UNSW_PATH}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    sys.exit(main(args.seed))
