"""Benchmark AlertLens; prints real measured numbers (nothing invented).

Part A — demo pipeline: data/sample_alerts.csv through the real ingest
pipeline (throwaway SQLite DB), reporting raw alerts, incidents, surfaced
vs suppressed incidents, duplicates, both reductions, the headline label,
recall/precision, threshold, median dwell and dedup latency.

Part B — 5-seed incident-level evaluation (synthetic scenario set): for
each seed 0-4, generate_scenarios(300, seed) is split 60/20/20 stratified
by is_malicious (train/val/test); a flow model is trained on
generate_synthetic_flows(2000, seed) (flow-level training — the scenario
train split is held out unused, val calibrates, test evaluates); each
val/test incident is scored by pooling its alerts' ML probabilities, the
threshold is calibrated on VAL incidents with calibrate_incident_threshold
(target 0.95), and TEST incidents give recall, precision and after-triage
reduction. Per-seed and mean +/- std are reported, plus a 95% Wilson
interval for the pooled test recall (pooled TP / pooled malicious).

Baselines, calibrated on the same val incidents to the same 0.95 recall
target and evaluated on the same test incidents:
  (i)   severity-only: max severity weight in the incident,
  (ii)  alert-level mean: MEAN alert ML probability (the old pooling),
  (iii) AlertLens: noisy-OR pooled ML probability.

All Part B numbers are labelled "synthetic scenario set". If any method
fails the recall target on test, that is reported, not hidden.

Part C — UNSW-NB15-derived flow-level evaluation (only when
``data/unsw-nb15.csv`` exists): the single file is split 60/20/20
stratified by label with fixed seed 42; a GradientBoosting Pipeline is
trained on train, the threshold is calibrated on val (target 0.95) and
reported on TEST flows only (recall with 95% Wilson interval, precision,
and the fraction of test flows suppressed at the threshold as "reduction").
Part C is flow-level, not incident-level, and is reported separately from
the synthetic Parts A/B — never merged into them. The alert stream built by
``scripts/make_alerts_from_unsw.py`` is also produced (row count reported).
Citation: Moustafa and Slay (2015), "UNSW-NB15: a comprehensive data set
for network intrusion detection systems", MilCIS 2015.

Usage: python benchmark.py
"""
import json
import math
import os
import sys
import tempfile
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(suffix=".db")

import csv  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from api.database import Base, SessionLocal, engine  # noqa: E402
from api.metrics import compute_metrics  # noqa: E402
from api.mitre import SEVERITY_WEIGHT  # noqa: E402
from api.models import Incident  # noqa: E402
from api.pipeline import ingest_alerts  # noqa: E402
from api.scoring import (  # noqa: E402
    extract_features, generate_synthetic_flows, load_model, noisy_or, train_model,
)
from scripts.generate_synthetic import generate_scenarios  # noqa: E402
from scripts.train import calibrate_incident_threshold  # noqa: E402

TARGET = 0.95
SEEDS = [0, 1, 2, 3, 4]


def _parse_raw(value) -> dict:
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}


def _load_csv_alerts(path: str) -> list[dict]:
    with open(path) as f:
        rows = list(csv.DictReader(f))
    return [{
        "id": r["id"], "timestamp": datetime.fromisoformat(r["timestamp"]), "source": r["source"],
        "rule_name": r["rule_name"], "severity": r["severity"],
        "src_ip": r.get("src_ip") or None, "dst_ip": r.get("dst_ip") or None,
        "host": r.get("host") or None, "raw": _parse_raw(r.get("raw")),
        "is_malicious": r.get("is_malicious") == "1",
    } for r in rows]


def part_a() -> dict:
    """Demo pipeline on data/sample_alerts.csv through the real ingest."""
    Base.metadata.create_all(bind=engine)
    alerts = _load_csv_alerts("data/sample_alerts.csv")
    db = SessionLocal()
    try:
        start = time.perf_counter()
        result = ingest_alerts(db, alerts)
        elapsed = time.perf_counter() - start
        metrics = compute_metrics(db)
        _, threshold = load_model()
        incidents = db.query(Incident).all()
        labelled = [i for i in incidents if i.is_malicious is not None]
        malicious = [i for i in labelled if i.is_malicious]
        surfaced_mal = [i for i in malicious if not i.suppressed]
        surfaced = [i for i in incidents if not i.suppressed]
        recall = len(surfaced_mal) / len(malicious) if malicious else 0.0
        precision = len(surfaced_mal) / len(surfaced) if surfaced else 0.0
    finally:
        # Always release the session, even if ingest or scoring fails.
        db.close()
    out = {
        "raw_alerts": len(alerts),
        "incidents": len(incidents),
        "surfaced_incidents": metrics["surfaced_incidents"],
        "suppressed_incidents": metrics["suppressed_incidents"],
        "duplicates_suppressed": result["duplicates"],
        "dedup_correlation_reduction_pct": metrics["dedup_correlation_reduction_pct"],
        "after_triage_reduction_pct": metrics["after_triage_reduction_pct"],
        "headline_reduction_label": metrics["headline_reduction_label"],
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "threshold": threshold,
        "median_dwell_seconds": metrics["median_dwell_seconds"],
        "dedup_latency_ms_per_alert": round(1000 * elapsed / len(alerts), 3),
        "total_ingest_seconds": round(elapsed, 3),
    }
    print("Part A — demo pipeline (data/sample_alerts.csv, real ingest, temp SQLite)")
    for k, v in out.items():
        print(f"  {k}: {v}")
    return out


def _incidents_from_scenarios(scenarios: list[dict]) -> list[dict]:
    """One incident per (scenario, host): multi-host chains split per host,
    each host's alerts one incident with the scenario's label."""
    incidents = []
    for sc in scenarios:
        by_host: dict[str, list[dict]] = {}
        for a in sc["alerts"]:
            by_host.setdefault(a.get("host") or "unknown", []).append(a)
        for host, alerts in by_host.items():
            incidents.append({"scenario_id": sc["scenario_id"], "host": host,
                              "is_malicious": sc["is_malicious"], "kind": sc["kind"],
                              "alerts": alerts})
    return incidents


def _score_incident(model, alerts: list[dict], method: str) -> float:
    probs = []
    for a in alerts:
        feats = np.array([extract_features(a)], dtype=float)
        probs.append(float(model.predict_proba(feats)[0][1]))
    if method == "alertlens":
        return noisy_or(probs)
    if method == "mean":
        return float(np.mean(probs)) if probs else 0.0
    if method == "severity":
        return max(SEVERITY_WEIGHT.get(str(a.get("severity", "low")).lower(), 0.25)
                   for a in alerts)
    raise ValueError(f"unknown method {method}")


def _evaluate(scores: list[float], labels: list[int], n_alerts: int,
              threshold: float) -> dict:
    surfaced = [s >= threshold for s in scores]
    tp = sum(1 for s, y in zip(surfaced, labels) if s and y == 1)
    fp = sum(1 for s, y in zip(surfaced, labels) if s and y == 0)
    n_mal = sum(1 for y in labels if y == 1)
    recall = tp / n_mal if n_mal else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    reduction = 100.0 * (1 - sum(surfaced) / n_alerts) if n_alerts else 0.0
    return {"recall": round(recall, 4), "precision": round(precision, 4),
            "reduction": round(reduction, 2), "tp": tp, "n_malicious": n_mal,
            "surfaced": int(sum(surfaced)), "n_incidents": len(labels)}


def _wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def part_b() -> dict:
    """5-seed incident-level evaluation + baselines (synthetic scenario set)."""
    methods = ["alertlens", "mean", "severity"]
    per_seed: dict[str, list[dict]] = {m: [] for m in methods}
    per_seed_alertlens_detail: list[dict] = []
    pooled_tp = pooled_mal = 0
    for seed in SEEDS:
        scenarios = generate_scenarios(300, seed)
        incidents = _incidents_from_scenarios(scenarios)
        labels_all = [int(i["is_malicious"]) for i in incidents]
        idx = list(range(len(incidents)))
        train_idx, rest_idx = train_test_split(
            idx, test_size=0.4, random_state=seed, stratify=labels_all)
        rest_labels = [labels_all[i] for i in rest_idx]
        val_idx, test_idx = train_test_split(
            rest_idx, test_size=0.5, random_state=seed, stratify=rest_labels)
        # Flow-level training (the scenario train split is held out unused;
        # val calibrates the threshold, test evaluates).
        X, y = generate_synthetic_flows(2000, seed)
        model = train_model(X, y)
        val = [incidents[i] for i in val_idx]
        test = [incidents[i] for i in test_idx]
        n_test_alerts = sum(len(i["alerts"]) for i in test)
        val_labels = [int(i["is_malicious"]) for i in val]
        test_labels = [int(i["is_malicious"]) for i in test]
        for method in methods:
            val_scores = [_score_incident(model, i["alerts"], method) for i in val]
            threshold, val_recall, val_met = calibrate_incident_threshold(
                val_scores, val_labels, TARGET)
            test_scores = [_score_incident(model, i["alerts"], method) for i in test]
            ev = _evaluate(test_scores, test_labels, n_test_alerts, threshold)
            ev["threshold"] = round(threshold, 4)
            ev["val_recall"] = round(val_recall, 4)
            ev["val_target_met"] = bool(val_met)
            ev["test_target_met"] = bool(ev["recall"] >= TARGET)
            ev["seed"] = seed
            per_seed[method].append(ev)
            if method == "alertlens":
                pooled_tp += ev["tp"]
                pooled_mal += ev["n_malicious"]
                per_seed_alertlens_detail.append({
                    "seed": seed, "n_test_incidents": ev["n_incidents"],
                    "n_test_malicious": ev["n_malicious"],
                    "n_test_alerts": n_test_alerts, "threshold": ev["threshold"],
                    "val_recall": ev["val_recall"], "val_target_met": ev["val_target_met"],
                    "test_recall": ev["recall"], "test_precision": ev["precision"],
                    "test_reduction": ev["reduction"],
                    "test_target_met": ev["test_target_met"],
                })
    lo, hi = _wilson_interval(pooled_tp, pooled_mal)
    pooled_recall = round(pooled_tp / pooled_mal, 4) if pooled_mal else 0.0

    def _mean_std(key: str, rows: list[dict]) -> tuple[float, float]:
        vals = np.array([r[key] for r in rows], dtype=float)
        return round(float(vals.mean()), 4), round(float(vals.std(ddof=1)), 4)

    print("\nPart B — 5-seed incident-level evaluation (synthetic scenario set)")
    print("  Seeds 0-4; 300 scenarios/seed, stratified 60/20/20 train/val/test;")
    print("  flow model trained on generate_synthetic_flows(2000, seed);")
    print("  threshold calibrated on VAL incidents (target 0.95), evaluated on TEST incidents.")
    print("  AlertLens per-seed (test):")
    for d in per_seed_alertlens_detail:
        print(f"    seed {d['seed']}: test_incidents={d['n_test_incidents']} "
              f"test_malicious={d['n_test_malicious']} test_alerts={d['n_test_alerts']} "
              f"threshold={d['threshold']} val_recall={d['val_recall']} "
              f"val_target_met={d['val_target_met']} test_recall={d['test_recall']} "
              f"test_precision={d['test_precision']} test_reduction={d['test_reduction']}% "
              f"test_target_met={d['test_target_met']}")
    summary = {}
    for method in methods:
        rows = per_seed[method]
        r_mean, r_std = _mean_std("recall", rows)
        p_mean, p_std = _mean_std("precision", rows)
        d_mean, d_std = _mean_std("reduction", rows)
        summary[method] = {"recall_mean": r_mean, "recall_std": r_std,
                           "precision_mean": p_mean, "precision_std": p_std,
                           "reduction_mean": d_mean, "reduction_std": d_std,
                           "test_target_met_all_seeds": all(r["test_target_met"] for r in rows)}
    print("  Baseline table (mean +/- std over 5 seeds, TEST incidents, synthetic scenario set):")
    print("    method      recall          precision       after-triage reduction  recall target met (all seeds)")
    for method, label in [("alertlens", "AlertLens (noisy-OR)"),
                          ("mean", "mean pooling"),
                          ("severity", "severity-only")]:
        s = summary[method]
        print(f"    {label:<20} {s['recall_mean']:.4f} +/- {s['recall_std']:.4f}  "
              f"{s['precision_mean']:.4f} +/- {s['precision_std']:.4f}  "
              f"{s['reduction_mean']:.2f}% +/- {s['reduction_std']:.2f}%  "
              f"{s['test_target_met_all_seeds']}")
    print(f"  Pooled test recall (AlertLens): {pooled_tp}/{pooled_mal} = {pooled_recall} "
          f"(95% Wilson interval [{lo}, {hi}])")
    for method in methods:
        rows = per_seed[method]
        if not all(r["test_target_met"] for r in rows):
            failed = [r["seed"] for r in rows if not r["test_target_met"]]
            print(f"  NOTE: {method} FAILED the 0.95 recall target on test "
                  f"in seeds {failed} — reported, not hidden.")
    return {"per_seed": per_seed_alertlens_detail, "summary": summary,
            "pooled_recall": pooled_recall, "pooled_tp": pooled_tp,
            "pooled_malicious": pooled_mal, "wilson_95": [lo, hi]}


UNSW_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "data", "unsw-nb15.csv")


def part_c() -> dict | None:
    """UNSW-NB15-derived flow-level evaluation on TEST flows only.

    Returns None (and prints NOT RUN) when data/unsw-nb15.csv is absent.
    Stratified 60/20/20 train/val/test split, fixed seed 42; threshold
    calibrated on val, reported on test only. Reduction here is the
    fraction of TEST flows suppressed (below threshold) — a flow-level
    figure, labelled as such, not an incident-level reduction.
    """
    from scripts.train import calibrate_threshold, load_unsw

    if not os.path.exists(UNSW_PATH):
        print("\nPart C — UNSW-NB15-derived evaluation: NOT RUN "
              "(data/unsw-nb15.csv not found; no data downloaded).")
        return None
    X, y = load_unsw()
    X_train, X_rest, y_train, y_rest = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(
        X_rest, y_rest, test_size=0.5, random_state=42, stratify=y_rest)
    model = train_model(X_train, y_train)
    threshold, val_recall, val_met = calibrate_threshold(model, X_val, y_val, TARGET)
    probs = model.predict_proba(X_test)[:, 1]
    surfaced = probs >= threshold
    tp = int(((surfaced) & (y_test == 1)).sum())
    fp = int(((surfaced) & (y_test == 0)).sum())
    n_mal = int((y_test == 1).sum())
    recall = tp / n_mal if n_mal else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    reduction = float(100.0 * (1 - surfaced.mean()))
    lo, hi = _wilson_interval(tp, n_mal)
    from scripts.make_alerts_from_unsw import main as _make_alerts
    _make_alerts(seed=42)
    print("\nPart C — UNSW-NB15-derived evaluation (TEST flows only, seed 42)")
    print(f"  rows: {len(y)} (train={len(y_train)} val={len(y_val)} test={len(y_test)})")
    print(f"  threshold={threshold:.4f} val_recall={val_recall:.4f} val_target_met={val_met}")
    print(f"  test_recall={recall:.4f} (95% Wilson interval [{lo}, {hi}]) "
          f"test_precision={precision:.4f} test_reduction={reduction:.2f}%")
    print(f"  test_target_met={bool(recall >= TARGET)} "
          f"(pooled TP {tp}/{n_mal} malicious test flows)")
    if recall < TARGET:
        print("  NOTE: Part C FAILED the 0.95 recall target on test — reported, not hidden.")
    return {"n_rows": int(len(y)), "n_train": int(len(y_train)),
            "n_val": int(len(y_val)), "n_test": int(len(y_test)),
            "threshold": round(float(threshold), 4),
            "val_recall": round(float(val_recall), 4),
            "val_target_met": bool(val_met),
            "test_recall": round(float(recall), 4),
            "test_precision": round(float(precision), 4),
            "test_reduction": round(reduction, 2),
            "test_target_met": bool(recall >= TARGET),
            "tp": tp, "n_malicious_test": n_mal, "wilson_95": [lo, hi]}


def main() -> dict:
    print("AlertLens benchmark — all numbers measured in this run")
    try:
        a = part_a()
        b = part_b()
        c = part_c()
    finally:
        # Always dispose the engine pool, even if a part fails mid-run,
        # so no SQLite connection is left open after the benchmark exits.
        engine.dispose()
    if c is None:
        print("\nData-source labels: Part A uses the seeded demo set (synthetic); "
              "Part B uses the synthetic scenario set. No UNSW-NB15 data was used.")
    else:
        print("\nData-source labels: Part A uses the seeded demo set (synthetic); "
              "Part B uses the synthetic scenario set; Part C is UNSW-NB15-derived "
              "(flow-level, test only) and is reported separately.")
    return {"part_a": a, "part_b": b, "part_c": c}


if __name__ == "__main__":
    main()
