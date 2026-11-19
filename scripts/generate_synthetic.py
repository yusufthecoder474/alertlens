"""Generate the seeded alert dataset: duplicate storms + 3 attack chains + noise.

Deterministic (seed 42). Writes data/sample_alerts.csv with an is_malicious
label column used by benchmark.py only; the label is never sent to the API
as a feature. Every alert also carries a ``raw`` column: a JSON object of
UNSW-NB15-style flow features (dur, sbytes, dbytes, rate, sttl, ct_srv_src)
drawn from the same distributions as ``api.scoring.generate_synthetic_flows``
— malicious-like flows for malicious alerts, benign-like for benign — with
the classes deliberately overlapping. ``severity_num`` is derived from the
alert severity at scoring time and is never stored in ``raw``.

Also writes data/synthetic_flows.csv (UNSW-NB15-style flows, header =
``api.scoring.FEATURE_NAMES`` + ``label``) and data/scenarios.csv (see
``generate_scenarios``).

Usage: python scripts/generate_synthetic.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import json
import random
from datetime import datetime, timedelta

from api.scoring import FEATURE_NAMES, generate_synthetic_flows

RULES = [
    ("Suspicious PowerShell", "high"), ("Mimikatz Credential Dump", "critical"),
    ("Unusual Outbound Traffic", "medium"), ("Failed Login Burst", "medium"),
    ("Port Scan Detected", "high"), ("Malware Signature Match", "critical"),
    ("Lateral Movement SMB", "high"), ("DNS Tunnelling Suspected", "medium"),
    ("Ransomware File Encryption", "critical"), ("Privilege Escalation Attempt", "high"),
    ("Suspicious Registry Change", "low"), ("Data Exfiltration Large Upload", "high"),
]
BENIGN = [("Failed Login Burst", "medium"), ("Suspicious Registry Change", "low"),
          ("Unusual Outbound Traffic", "medium"), ("Port Scan Detected", "high")]
BASE = datetime(2026, 11, 19, 9, 0, 0)


def flow_dict(rng: random.Random, malicious: bool) -> dict:
    """One UNSW-NB15-style flow dict, same ranges as generate_synthetic_flows.

    Malicious: dur 0.1-30, sbytes 500-80000, dbytes 200-60000, rate 5-800,
    sttl ~N(62,12), ct_srv_src 1-25. Benign: dur 0-5, sbytes 40-8000,
    dbytes 40-5000, rate 0.1-120, sttl ~N(254,4), ct_srv_src 1-4.
    """
    if malicious:
        return {
            "dur": round(rng.uniform(0.1, 30.0), 3),
            "sbytes": int(rng.uniform(500, 80000)),
            "dbytes": int(rng.uniform(200, 60000)),
            "rate": round(rng.uniform(5, 800), 3),
            "sttl": int(max(0, min(255, rng.gauss(62, 12)))),
            "ct_srv_src": rng.randint(1, 25),
        }
    return {
        "dur": round(rng.uniform(0.0, 5.0), 3),
        "sbytes": int(rng.uniform(40, 8000)),
        "dbytes": int(rng.uniform(40, 5000)),
        "rate": round(rng.uniform(0.1, 120), 3),
        "sttl": int(max(0, min(255, rng.gauss(254, 4)))),
        "ct_srv_src": rng.randint(1, 4),
    }


def _alert_dict(aid, ts, rule, sev, src, dst, host, malicious, raw):
    return {"id": aid, "timestamp": ts.isoformat(), "source": "siem-demo",
            "rule_name": rule, "severity": sev, "src_ip": src, "dst_ip": dst,
            "host": host, "is_malicious": int(malicious),
            "raw": json.dumps(raw)}


def generate_scenarios(n: int = 300, seed: int = 42) -> list[dict]:
    """Generate ``n`` labelled incident scenarios for incident-level evaluation.

    Each scenario is {"scenario_id", "host", "is_malicious", "kind",
    "alerts": [...]} where each alert is an ingest-shaped dict with a
    ``raw`` flow dict. Kinds (counts for n=300):

    - clear_attack (110, malicious): recon -> execution -> exfiltration chains.
    - benign_noise (100, benign): scattered low/medium alerts, benign flows.
    - admin_powershell_storm (30, benign, HARD): many high-severity
      Suspicious PowerShell alerts with benign flows — severity alone would
      flag these; only the flow features say benign.
    - backup_burst (30, benign, HARD): large sbytes/dbytes (scheduled backup)
      with benign TTL/rates — volume alone looks like exfiltration.
    - low_severity_first_stage (20, malicious, HARD): low-severity rules
      (registry change / failed logins) with malicious flows — severity
      alone would miss these; only the flow features say malicious.
    - multi_host_chain (10, malicious, HARD): one attack spanning 2-3 hosts.
      Correlation splits these per host, so evaluation must group a
      scenario's alerts by host — each host's alerts are one incident with
      the scenario's label.

    Deterministic per seed. >=100 scenarios are malicious for n=300.
    """
    rng = random.Random(seed)
    kinds = (
        ["clear_attack"] * 110 + ["benign_noise"] * 100
        + ["admin_powershell_storm"] * 30 + ["backup_burst"] * 30
        + ["low_severity_first_stage"] * 20 + ["multi_host_chain"] * 10
    )
    # Scale the mix to n (default 300 keeps the exact counts above).
    if n != 300:
        kinds = (kinds * ((n // len(kinds)) + 1))[:n]
    rng.shuffle(kinds)
    hosts = ["workstation-01", "workstation-02", "workstation-03", "web-01",
             "web-02", "db-01", "dc-01"]
    scenarios: list[dict] = []
    for i, kind in enumerate(kinds):
        sid = f"scenario-{seed}-{i:04d}"
        t0 = BASE + timedelta(minutes=rng.randint(0, 600))
        alerts: list[dict] = []
        counter = [0]

        def add(rule, sev, src, dst, host, ts, malicious, raw):
            counter[0] += 1
            alerts.append(_alert_dict(f"{sid}-a{counter[0]:02d}", ts, rule, sev,
                                      src, dst, host, malicious, raw))

        if kind == "clear_attack":
            host = rng.choice(hosts)
            chain = [("Port Scan Detected", "high"), ("Suspicious PowerShell", "high"),
                     ("Data Exfiltration Large Upload", "high")]
            for j, (rule, sev) in enumerate(chain[:rng.randint(2, 3)]):
                add(rule, sev, "203.0.113.5", "10.0.0.20", host,
                    t0 + timedelta(minutes=j * 7), True, flow_dict(rng, True))
            malicious = True
        elif kind == "benign_noise":
            host = rng.choice(hosts)
            for j in range(rng.randint(1, 3)):
                rule, sev = rng.choice(BENIGN)
                add(rule, sev, f"10.0.0.{rng.randint(11, 19)}", "10.0.0.20", host,
                    t0 + timedelta(minutes=j * 3), False, flow_dict(rng, False))
            malicious = False
        elif kind == "admin_powershell_storm":
            host = rng.choice(hosts)
            for j in range(rng.randint(4, 8)):
                add("Suspicious PowerShell", "high", "10.0.0.7", "10.0.0.20", host,
                    t0 + timedelta(seconds=j * 20), False, flow_dict(rng, False))
            malicious = False
        elif kind == "backup_burst":
            host = rng.choice(hosts)
            for j in range(rng.randint(2, 4)):
                raw = flow_dict(rng, False)
                # Scheduled backup: huge byte counts, but benign TTL and rate.
                raw["sbytes"] = int(rng.uniform(50000, 90000))
                raw["dbytes"] = int(rng.uniform(40000, 80000))
                raw["dur"] = round(rng.uniform(10, 30), 3)
                add("Unusual Outbound Traffic", "high", "10.0.0.7", "10.0.0.20", host,
                    t0 + timedelta(minutes=j * 5), False, raw)
            malicious = False
        elif kind == "low_severity_first_stage":
            host = rng.choice(hosts)
            for j, (rule, sev) in enumerate(
                    [("Suspicious Registry Change", "low"), ("Failed Login Burst", "low"),
                     ("Port Scan Detected", "low")][:rng.randint(2, 3)]):
                add(rule, sev, "203.0.113.5", "10.0.0.20", host,
                    t0 + timedelta(minutes=j * 6), True, flow_dict(rng, True))
            malicious = True
        else:  # multi_host_chain
            chain_hosts = rng.sample(hosts, rng.randint(2, 3))
            chain = [("Port Scan Detected", "high"), ("Suspicious PowerShell", "high"),
                     ("Lateral Movement SMB", "high"), ("Data Exfiltration Large Upload", "high")]
            for j, host in enumerate(chain_hosts):
                rule, sev = chain[j % len(chain)]
                add(rule, sev, "203.0.113.5", "10.0.0.20", host,
                    t0 + timedelta(minutes=j * 8), True, flow_dict(rng, True))
            host = chain_hosts[0]
            malicious = True
        scenarios.append({"scenario_id": sid, "host": host, "is_malicious": malicious,
                          "kind": kind, "alerts": alerts})
    # In-memory scenario alerts carry ``raw`` as a dict (the CSV writer
    # stringifies it); only the on-disk rows store it as a JSON string.
    for sc in scenarios:
        for a in sc["alerts"]:
            a["raw"] = json.loads(a["raw"])
    return scenarios


def main() -> None:
    rng = random.Random(42)
    rows: list[dict] = []
    n = [0]

    def add(rule, sev, src, dst, host, ts, malicious):
        n[0] += 1
        rows.append(_alert_dict(f"alert-{n[0]:04d}", ts, rule, sev, src, dst,
                                host, malicious, flow_dict(rng, malicious)))

    # Duplicate storm: same fingerprint fires 40x in 4 minutes (dedup target).
    for i in range(40):
        add("Suspicious PowerShell", "high", "10.0.0.7", "10.0.0.20", "workstation-01",
            BASE + timedelta(seconds=i * 6), True)
    # Duplicate storm 2: benign registry noise, 25x.
    for i in range(25):
        add("Suspicious Registry Change", "low", "10.0.0.9", "10.0.0.20", "workstation-02",
            BASE + timedelta(seconds=i * 8), False)
    # Attack chain 1 (host web-01): recon -> PowerShell -> exfiltration.
    chain1 = [("Port Scan Detected", "high"), ("Suspicious PowerShell", "high"),
              ("Data Exfiltration Large Upload", "high")]
    for i, (rule, sev) in enumerate(chain1):
        add(rule, sev, "203.0.113.5", "10.0.0.20", "web-01", BASE + timedelta(minutes=10 + i * 7), True)
    # Attack chain 2 (host db-01): credential dump -> lateral movement.
    for i, (rule, sev) in enumerate([("Mimikatz Credential Dump", "critical"),
                                     ("Lateral Movement SMB", "high")]):
        add(rule, sev, "10.0.0.7", "10.0.0.30", "db-01", BASE + timedelta(minutes=30 + i * 5), True)
    # Attack chain 3 (host dc-01): privilege escalation -> ransomware.
    for i, (rule, sev) in enumerate([("Privilege Escalation Attempt", "high"),
                                     ("Ransomware File Encryption", "critical")]):
        add(rule, sev, "10.0.0.7", "10.0.0.10", "dc-01", BASE + timedelta(minutes=50 + i * 6), True)
    # Benign noise: 80 scattered alerts across hosts.
    hosts = ["workstation-01", "workstation-02", "workstation-03", "web-02"]
    for i in range(80):
        rule, sev = rng.choice(BENIGN)
        add(rule, sev, f"10.0.0.{rng.randint(11, 19)}", "10.0.0.20",
            rng.choice(hosts), BASE + timedelta(minutes=rng.randint(0, 300)), False)

    with open("data/sample_alerts.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    X, y = generate_synthetic_flows()
    with open("data/synthetic_flows.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(FEATURE_NAMES + ["label"])
        for xi, yi in zip(X, y):
            w.writerow([f"{v:.4f}" for v in xi] + [int(yi)])
    scenarios = generate_scenarios(300, 42)
    with open("data/scenarios.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario_id", "kind", "is_malicious", "id", "timestamp", "source",
                    "rule_name", "severity", "src_ip", "dst_ip", "host", "raw"])
        for sc in scenarios:
            for a in sc["alerts"]:
                w.writerow([sc["scenario_id"], sc["kind"], int(sc["is_malicious"]),
                            a["id"], a["timestamp"], a["source"], a["rule_name"],
                            a["severity"], a["src_ip"], a["dst_ip"], a["host"],
                            json.dumps(a["raw"])])
    n_sc_alerts = sum(len(s["alerts"]) for s in scenarios)
    print(f"Wrote {len(rows)} alerts to data/sample_alerts.csv "
          f"({sum(r['is_malicious'] for r in rows)} malicious) and {len(y)} flows to data/synthetic_flows.csv; "
          f"{len(scenarios)} scenarios ({sum(s['is_malicious'] for s in scenarios)} malicious, "
          f"{n_sc_alerts} alerts) to data/scenarios.csv")


if __name__ == "__main__":
    main()
