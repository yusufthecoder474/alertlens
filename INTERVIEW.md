# AlertLens — 15 interview questions with short answers

1. **What is a SOC alert?**
   A single detection event from a security tool (SIEM/EDR/firewall): one rule fired, at one time, about one host or IP. Alerts are noisy by design — a detector fires every time its condition matches.

2. **What is a SIEM?**
   Security Information and Event Management: it collects logs/events from many sources, normalises them, runs detection rules, and stores alerts for analysts. AlertLens consumes SIEM-style alerts; it is not a SIEM itself.

3. **What is EDR?**
   Endpoint Detection and Response: an agent on a host that watches processes, files and network activity and can isolate the host. EDR detections are a common alert source for a SIEM.

4. **What is a false positive?**
   An alert (or incident) that looks malicious but is benign — e.g. an admin running PowerShell. False positives waste triage time and train analysts to ignore alerts.

5. **What is a false negative, and why is it worse?**
   A real attack that produces no alert, or one that gets suppressed. A false positive costs minutes; a false negative can cost a breach. That asymmetry is why AlertLens budgets recall explicitly.

6. **What is the difference between dedup and correlation?**
   Dedup removes *repeats of the same detection* (same fingerprint inside a time window). Correlation groups *different detections* that belong to one attack (same host/src_ip within a window). Dedup shrinks volume; correlation builds the story.

7. **Why dedup by fingerprint instead of exact matching?**
   The fingerprint hashes the fields that define "the same thing firing again" (rule, src/dst IP, host) and ignores timestamps and IDs, so re-fires of the same detection match even though each alert row is technically distinct.

8. **Why is the dedup window configurable, and what happens at the boundary?**
   Different rules re-fire at different rates; a fixed window would over- or under-suppress. The boundary is tested: exactly at the window counts as a duplicate, one second past it does not.

9. **Why score incidents instead of individual alerts?**
   One attack produces many alerts of varying severity; scoring alerts ranks the loudest detector, not the most dangerous attack. Scoring the incident pools severity, asset criticality and ML probability across the whole chain, and the queue stays short enough to work through. The ML pooling is noisy-OR — `1 - prod(1 - p_i)` — not the mean: one strongly malicious alert must surface an incident even among many benign alerts, where the mean would dilute it. On the easy synthetic set that mattered (mean pooling failed the 0.95 recall target in 3 of 5 seeds); on the harder overlapping-flow set it stopped mattering — mean pooling ties noisy-OR on recall (0.9419 each) and beats it on precision (0.7256 vs 0.6451), failing in seeds 0 and 3 while noisy-OR fails in seeds 2 and 3 — so I report the pooling choice as no advantage for noisy-OR here, not a win.

10. **Why set a recall target instead of just maximising alert reduction?**
    Reduction is easy to maximise — suppress everything and reduction is 100%, but so is the miss rate. The recall target (default 95% of malicious incidents must still surface) is a false-negative budget: reduction is only reported *after* that constraint is met. The headline number follows the same rule: if recall at the threshold is below target, the dashboard shows the string "target not met" instead of a percentage, and `after_triage_reduction_pct` is null. A reduction number that hides a missed attack is worse than no number.

11. **How is the suppression threshold calibrated?**
    On a held-out validation split, scan thresholds ROC-style: take the unique validation probabilities (plus 1.0), sort them highest first, and pick the highest one whose malicious recall still meets the target. Highest, because it suppresses the most while keeping the budget. The scan is over unique probabilities, not a fixed grid, so the answer can be an exact observed value (e.g. 0.99) rather than a grid artefact. Calibration is incident-level — on pooled noisy-OR incident scores, not alert scores — because suppression acts on incidents. If no threshold meets the target (e.g. no malicious rows in validation), the function returns `target_met=False` and the best recall found; the caller must report "target not met", never silently claim the target.

12. **Why is nothing ever deleted, and how does suppression/reopen work?**
    Suppression must be auditable: an analyst (or an auditor) can reopen a duplicate, see why it was suppressed, and re-triage it. Deleting would also destroy the evidence needed to measure false negatives later. A suppressed incident stays in the database with `suppressed=true` and a `suppression_reason` string naming the numbers ("ML probability 0.01 below calibrated threshold 0.50…"); it is hidden from the default queue (`GET /incidents`) and shown only with `include_suppressed=true`. `POST /incidents/{id}/reopen` puts it back to status `new` with suppression cleared, and any `PATCH /incidents/{id}/status` also clears suppression — an analyst who moves an incident has looked at it. Status (`new`/`in_triage`/`investigating`/`resolved`) and the suppressed flag are independent.

13. **How does analyst feedback improve the system?**
    True/false-positive markings are stored per incident and the retrain script adds weighted training samples from them, then re-calibrates the threshold. Feedback is the only labelled data that reflects *this* environment's benign behaviour.

14. **What does the evidence package contain, and why?**
    Who (host/IP), what (alerts + duplicates suppressed), when (first/last seen), where (asset criticality), why (top factors in plain English + MITRE tags), and a next action. Devo's survey found analysts spend most of their time assembling exactly this — so the product assembles it for them.

15. **What are the main trade-offs / limitations?**
    The seeded and scenario data are synthetic, and the Part B generator and model share distributions, so Part B is an upper bound; the 0.95 recall target is not met on the harder synthetic set (seeds 2 and 3) or on UNSW-NB15 test flows (0.9486 — target not met). Demo-set precision is 0.5. The MITRE map covers only 12 rules; correlation by host within one hour misses slow multi-host chains, which split into one incident per host; and a shared API key is demo-grade auth, not production auth. Each is stated in the README rather than hidden. Evaluation is incident-level on a 5-seed synthetic scenario set (300 scenarios/seed, stratified 60/20/20, threshold calibrated on validation incidents, tested on held-out test incidents): AlertLens recall 0.9419 ± 0.0699, precision 0.6451, reduction 70.02% ± 5.68%, pooled recall 0.9423 with a 95% Wilson interval of [0.894, 0.9694]. Baselines on the same split: mean pooling 0.9419 ± 0.0803 (precision 0.7256), failing in seeds 0 and 3; severity-only meets recall at precision 0.4937. The model uses no IP-derived features — only real UNSW-NB15 flow columns (severity is not a feature; it enters only through the priority formula) — and a missing flow field is NaN median-imputed by the Pipeline, never zero-filled; alerts with no flow evidence at all are never scored by the model (ml_probability is None) and never suppressed, and the evidence package says "no flow evidence". Part C (UNSW-NB15-derived, flow-level, test only, 35,069 test flows): recall 0.9486, precision 0.9334, reduction 30.83% (Moustafa and Slay 2015).
