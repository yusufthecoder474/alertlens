# AlertLens — SOC Alert Triage and Deduplication Dashboard

**Assumptions (one line):** Seeded/demo data is synthetic and labelled, the ML model trains on synthetic UNSW-NB15-style flows when the real dataset file is absent, and the LLM summary is off by default.

AlertLens ingests noisy security alerts, deduplicates and correlates them into **incidents**, prioritizes **incidents** (not single alerts) under an explicit false-negative budget, and hands the analyst a short evidence package: who / what / when / where / why / next action.

## Problem

SOC analysts drown in alerts. Most of the noise is the same detection firing again and again, or several detections that are really one attack seen from different angles. Triaging alert-by-alert wastes the scarcest resource — analyst attention — and the alerts that matter get buried. AlertLens attacks the volume at the incident level: suppress exact repeats, group what belongs together, score the group, and show the evidence needed to decide in one screen.

## Related Work

Only the sources below are cited. Industry sources are labelled non-peer-reviewed; no other papers or statistics are claimed.

- **Devo, "The Evolution Toward an Alertless SOC" (2025, industry, non-peer-reviewed).** Wakefield Research survey of 200 US SOC professionals (28 Jan–10 Feb 2025, released 16 Apr 2025): 83% of analysts are overwhelmed by alert volume, false positives and missing context; 85% spend significant time collecting and linking evidence. (The brief's claim that under one third use AI for automated triage was **not independently verified** and is stated here only as a brief claim, not as a Devo figure.)
- **François Labrèche (Sophos), "A Needle in a Haystack: Identifying an Infostealer Attack Through Trillions of Events in a Large-scale Modern SOC", NorthSec 2026, Montreal, May 2026 (industry research, non-peer-reviewed; Sophos blog version).** Multi-stage pipeline: detectors, dedup + correlation, suppression, then supervised ML prioritization. After dedup/correlation, 9.5% of alerts remained. The idea of prioritizing *grouped incidents* rather than individual alerts is this project's gap framing, not a quoted Sophos claim.
- **Koumourou et al. (2025, peer-reviewed conference paper).** S. Koumourou, A. Peratikou, E. Stavrou, S. Theodoulou, S. Stavrou, "Reducing SOC Analysts Alert Fatigue via Real-Time CTI Correlation and Deduplication", in *International Conference on Critical Information Infrastructures Security (CRITIS 2025)*, Springer LNCS, Oct 2025, pp. 20–35, DOI: 10.1007/978-3-032-19540-1_2.

**Gaps AlertLens addresses:** (1) incident-level prioritization, (2) an explicit false-negative budget (recall target) with auditable suppression — nothing is ever deleted, duplicates are linked and counted, (3) a decision-ready evidence package per incident.

## Architecture

```mermaid
flowchart LR
    SIEM[SIEM / CSV loader] -->|POST /alerts JSON batch| API[FastAPI + SQLAlchemy]
    API --> DEDUP[Dedup: fingerprint + 300s window]
    DEDUP --> CORR[Correlation: host/src_ip + 1h window]
    CORR --> SCORE[Scoring: severity + asset criticality + ML prob]
    SCORE --> DB[(PostgreSQL / SQLite)]
    DB --> UI[React dashboard: Dashboard, Queue, Detail]
    UI -->|status + true/false positive| API
    FB[Analyst feedback] --> RETRAIN[scripts/retrain.py]
    RETRAIN --> SCORE
```

## Design decisions

- **Incidents, not alerts.** Scoring and the queue operate on incidents; an alert storm becomes one row.
- **Nothing is ever deleted.** Duplicates stay in the database with `is_duplicate=true` and `duplicate_of_id`, so suppression is auditable and reversible.
- **Recall budget before reduction.** The suppression threshold is calibrated on a validation split as the *highest* threshold whose malicious recall still meets `RECALL_TARGET` (default 95%). Alert reduction is reported *after* that constraint, never the other way round.
- **Small, hand-made MITRE map (12 rules).** Auditable by an analyst; a generated map nobody can review would be worse.
- **Deterministic summary by default.** The template summary always works. The LLM path needs `LLM_ENABLED=true` plus a key, and any failure or timeout falls back to the template (recorded as `summary_source`).
- **SQLite for local dev/tests, PostgreSQL in Docker/CI.** Same SQLAlchemy models; tests run without Docker.
- **Simple code over clever code.** Small modules, type hints and docstrings on public functions, pure functions (`dedup_batch`, `correlate`) that are easy to unit-test.

## Pinned versions and support status (checked 2026-11-19)

| Component | Pinned | Support status |
|---|---|---|
| Python | 3.11 | Security-only until 31 Oct 2027 — still supported; plan the upgrade before then |
| PostgreSQL | 17 (`postgres:17`) | Supported until 8 Nov 2029 |
| Node | 24 LTS | Supported until 30 Apr 2028 (Node 22 ends 30 Apr 2027, so it was not used) |
| React | 19 | Current major |
| Vite | 7 | Needs Node 20.19+/22.12+; Node 24 fits |

Local verification in this workspace ran on Python 3.12.3 and Node 24.22.1 (the pinned versions are what Docker/CI use).

## Quickstart

```bash
cp .env.example .env          # set a real API_KEY
make install                  # venv + pip install; frontend npm install
python scripts/generate_synthetic.py   # writes data/sample_alerts.csv (152 alerts, now with a raw flow column), data/synthetic_flows.csv, data/scenarios.csv (300 scenarios)
make train                    # trains model, calibrates threshold (default recall target 0.95)
make run                      # API on http://localhost:8000
# in another shell:
API_URL=http://localhost:8000 API_KEY=<your key> python scripts/load_csv.py data/sample_alerts.csv
cd frontend && npm run dev    # UI on http://localhost:5173
```

Docker (all three services):

```bash
docker compose up --build
# API http://localhost:8000, UI http://localhost:5173
```

UNSW-NB15 (optional, real data): get it from UNSW Canberra (https://research.unsw.edu.au/projects/unsw-nb15-dataset) or Kaggle ("UNSW-NB15"), save the testing set as `data/unsw-nb15.csv` (do not commit it), then `python scripts/make_alerts_from_unsw.py` writes `data/unsw_alerts.csv` and `python scripts/train.py` trains on it. Without the file, training and evaluation use the synthetic fallback and say so; nothing is ever downloaded.

## API

All endpoints except `GET /health` require header `X-API-Key: <API_KEY>`. Rate limit: 60 requests/minute per key (429 beyond it; `RATE_LIMIT_PER_MINUTE` overrides).

| Method | Path | Description |
|---|---|---|
| GET | /health | Liveness, no auth |
| POST | /alerts | Ingest a JSON batch (max 1000); idempotent on alert `id` |
| GET | /incidents?status=&sort=&include_suppressed= | List incidents, filter by status, sort by `priority` or `recent`; suppressed incidents hidden by default, shown with `include_suppressed=true` |
| GET | /incidents/{id} | Evidence package + alert timeline |
| PATCH | /incidents/{id}/status | `new` / `in_triage` / `investigating` / `resolved`; clears suppression (an analyst who moves an incident has looked at it) |
| POST | /incidents/{id}/reopen | Reopen a suppressed incident: status back to `new`, suppression cleared, visible in the queue again |
| POST | /incidents/{id}/feedback | `true_positive` / `false_positive` (+ optional note) |
| GET | /metrics | Dedup/correlation reduction %, after-triage reduction %, headline label, surfaced vs suppressed counts, recall at threshold |

## Metrics definitions

Two reductions are reported separately — conflating them was an old bug:

- **Dedup / correlation reduction %** = `100 * (1 - incidents / alerts)`: what dedup + correlation alone remove from the queue. (Kept as `alert_reduction_pct` too, for compatibility.)
- **After-triage reduction %** = `100 * (1 - surfaced incidents / alerts)`: what the analyst actually has to look at after the recall-budgeted suppression step.
- **Headline reduction** = the after-triage reduction, published **only when `recall_at_threshold >= recall_target`** (default 0.95). When recall is below target the headline is the string `"target not met"` and `headline_reduction_pct` / `after_triage_reduction_pct` are null — the dashboard shows "target not met" instead of a number. Reduction is never reported ahead of the false-negative budget.
- **Suppression ratio** = duplicates / total alerts.
- **Surfaced / suppressed incidents** = incidents with the suppression flag off / on. Suppression hides an incident from the default queue (`GET /incidents`); it never deletes anything. Reopen (`POST /incidents/{id}/reopen`) or a status change clears it.
- **Median dwell** = median (incident last_seen − first_seen) in seconds.
- **False-positive rate** = false-positive feedback / all feedback (null until feedback exists).
- **Reopen rate** = incidents back in triage/investigating / resolved incidents (null until a resolution exists).
- **Recall at threshold** = malicious incidents with ML probability ≥ threshold / all labelled malicious incidents. It is measured on the suppression decision itself (the `suppressed` flag), not on a re-computed probability.

## Evaluation

All numbers below are measured by `python benchmark.py` (see `RESULTS.md` for the verbatim output). Every evaluation number is labelled with its data source; nothing is presented as production performance.

- **Incident-level, not alert-level.** Scoring, threshold calibration and recall are all measured on incidents: an incident is one scenario's alerts on one host (multi-host chains split per host, one incident per host, each carrying the scenario's label).
- **Part A — demo pipeline (synthetic seeded set).** `data/sample_alerts.csv` (152 alerts) through the real ingest pipeline: 7 incidents, 64 duplicates, 95.39% after-triage reduction, recall 1.0, precision 0.5714.
- **Part B — 5-seed scenario evaluation (synthetic scenario set).** For each seed 0–4, `generate_scenarios(300, seed)` produces 300 labelled scenarios (140 malicious) including hard cases — benign admin PowerShell storms, scheduled-backup bursts, low-severity first-stage attacks, multi-host chains — split 60/20/20 stratified by `is_malicious` (train/val/test). A flow model trains on `generate_synthetic_flows(2000, seed)` (flow-level training); each val/test incident is scored by noisy-OR pooling its alerts' ML probabilities; the threshold is calibrated on VAL incidents with `calibrate_incident_threshold` (target 0.95) and evaluated on TEST incidents. AlertLens: mean test recall **0.9935 ± 0.0144**, precision **1.0000 ± 0.0000**, after-triage reduction **79.54% ± 2.09%**; pooled test recall 155/156 = **0.9936** with a 95% Wilson interval of **[0.9646, 0.9989]**. The recall target was met on test in all 5 seeds.
- **Data-source labels.** Part A uses the seeded demo set (synthetic); Part B uses the synthetic scenario set. UNSW-NB15-derived evaluation is NOT RUN — no dataset file was present. To run it, save the UNSW-NB15 testing set as `data/unsw-nb15.csv` (UNSW Canberra, https://research.unsw.edu.au/projects/unsw-nb15-dataset, or Kaggle "UNSW-NB15"), run `scripts/make_alerts_from_unsw.py`, then `scripts/train.py` and `benchmark.py`.

## Baselines

Same val calibration (0.95 recall target) and same test incidents as Part B above; all numbers are means ± std over 5 seeds on TEST incidents (synthetic scenario set):

| Method | Recall | Precision | After-triage reduction | Recall target met (all seeds) |
|---|---|---|---|---|
| AlertLens (noisy-OR pooled ML prob) | 0.9935 ± 0.0144 | 1.0000 ± 0.0000 | 79.54% ± 2.09% | Yes |
| Mean pooling (mean alert ML prob) | 0.9290 ± 0.0735 | 1.0000 ± 0.0000 | 80.80% ± 3.02% | **No — failed in seeds 2, 3, 4** |
| Severity-only (max severity weight) | 1.0000 ± 0.0000 | 0.4937 ± 0.0035 | 58.30% ± 3.93% | Yes |

AlertLens wins on recall (target met every seed) and precision. Mean pooling — the old pooling — fails the recall target because averaging lets benign alerts dilute an attack to invisibility; its slightly higher reduction (80.80% vs 79.54%) comes from suppressing attacks it should have surfaced. Severity-only meets recall but at precision 0.4937: it surfaces roughly half the benign incidents too, and reduces the queue far less.

## Results

Run `python benchmark.py` and paste the output here (and into `RESULTS.md`). No numbers are claimed in this table until that run is pasted.

| Metric | Value |
|---|---|
| Alerts in (Part A, demo set) | 152 |
| Incidents out | 7 (all surfaced, 0 suppressed) |
| Duplicates suppressed | 64 |
| Dedup / correlation reduction % | 95.39 |
| After-triage reduction % (headline) | 95.39 |
| Recall / precision (Part A) | 1.0 / 0.5714 |
| Dedup latency | 2.138 ms/alert (varies run to run) |
| Incident-level recall, 5 seeds (Part B, synthetic scenario set) | 0.9935 ± 0.0144 |
| Incident-level precision, 5 seeds | 1.0000 ± 0.0000 |
| Incident-level after-triage reduction, 5 seeds | 79.54% ± 2.09% |
| Pooled test recall + 95% Wilson interval | 0.9936, [0.9646, 0.9989] |

## Limitations

- The seeded dataset and the fallback training data are **synthetic**; the model is highly separable on them, so the calibrated thresholds sit near the edge (0.998+ on scenario validation) and seeded precision is modest (0.5714 on the demo set). Real UNSW-NB15 data (`data/unsw-nb15.csv`, loaded by `scripts/train.py` when present; alerts built by `scripts/make_alerts_from_unsw.py`) would give a meaningful calibration.
- Flow fields (`dur`, `sbytes`, `dbytes`, `rate`, `sttl`, `ct_srv_src`) come from the alert's `raw` payload when the SIEM provides them. A missing flow field is `NaN`, median-imputed inside the saved sklearn Pipeline — never zero-filled, never clipped. Alerts that arrive with no flow data at all are judged on their severity alone; the model is trained with 25% of rows missing all flow columns (label kept) so that imputed point is in-distribution. No IP-derived features are used anywhere: source/destination IPs are identifiers, never model inputs.
- The MITRE map covers 12 rules only; unmapped rules get no technique tag.
- Correlation is by host/src_ip within a 1-hour window — a slow, multi-day attack chain spanning hosts will split, and a multi-host chain splits into one incident per host (each carrying the chain's label in evaluation).
- No authentication beyond the API key; this is a single-team demo, not a multi-tenant product.
- The LLM summary path has **not been run** (no key supplied); it is code only, never presented as a live result.

## Security notes (OWASP Top 10 mapping)

- **Broken Access Control (A01):** every endpoint except `/health` requires the `X-API-Key` header; missing/wrong key → 401.
- **Injection (A03):** all database access goes through SQLAlchemy ORM / parameterized queries; no string-built SQL anywhere.
- **Security Misconfiguration (A05):** secrets live only in `.env` (never committed; `.env.example` is a template), debug/reload off in Docker, CORS restricted to the local dev UI origin.
- **Vulnerable Components (A06):** pinned dependencies in `requirements.txt` / `package.json`; CI runs lint + tests on every push.
- **Identification/Auth Failures (A07):** single shared API key is a deliberate demo simplification — documented as a limitation, not production auth. The key is fail-fast: when `ENV != "dev"` and no real `API_KEY` is set, the process refuses to start instead of running with a placeholder. Key comparison uses `hmac.compare_digest` (constant time). The frontend never hard-codes a key: it reads `VITE_API_KEY` and sends an empty key otherwise.
- **Software/Data Integrity (A08):** no deserialization of untrusted data; model files are loaded only from the local `models/` directory.
- **Logging/Monitoring (A09):** ingest counts and metrics are exposed via `/metrics`; failures return structured 4xx errors (401/404/422/429) instead of stack traces.
- **SSRF (A10):** the only outbound call is the optional LLM request to `api.openai.com`, behind the `LLM_ENABLED` flag with a 5-second timeout and a template fallback.

## How to demo (5 steps)

See `DEMO.md` for the full script. In short: (1) show the seeded CSV and its two duplicate storms + three attack chains, (2) load it and watch 152 alerts collapse to 7 incidents in the Dashboard, (3) open the top incident and read its evidence package aloud, (4) mark one incident false positive and show the metrics move, (5) run `python benchmark.py` live and read the numbers — including the 5-seed baseline table, where mean pooling fails the recall target in 3 of 5 seeds.

## AWS deploy note (docs only, not deployed)

EC2 free tier (t2.micro/t3.micro) + RDS PostgreSQL free tier: run the API container on EC2 with `DATABASE_URL` pointing at RDS, put the built frontend (`npm run build`) behind the same host or S3 + CloudFront, keep the API key in EC2 environment variables (never in the image), and open only ports 80/443 in the security group. No deployment has been performed; this is a plan, not a claim.

## Non-goals

User accounts, multi-tenancy, Kafka/streaming, Kubernetes, mobile, real SIEM connectors, custom deep learning, websockets.
