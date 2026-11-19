"""Dashboard metrics, computed from stored alerts/incidents/feedback.

Two reductions are reported separately — conflating them was the old bug:
- ``dedup_correlation_reduction_pct`` = 100 * (1 - incidents / raw alerts):
  what dedup + correlation alone remove from the queue.
- ``after_triage_reduction_pct`` = 100 * (1 - surfaced incidents / raw alerts):
  what the analyst actually has to look at after the recall-budgeted
  suppression step. This is the headline number, and it is only published
  when ``recall_at_threshold >= recall_target``; otherwise the headline is
  the string "target not met" (``headline_reduction_pct`` is None).

Recall is measured on the *suppression decision itself* (suppressed flag),
not on a re-computed probability, so the metric describes what triage did.
"""
import statistics

from sqlalchemy.orm import Session

from api.config import settings
from api.models import Alert, Feedback, Incident
from api.scoring import load_model


def compute_metrics(db: Session) -> dict:
    """Return the metrics dict served by GET /metrics."""
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()
    surfaced = db.query(Incident).filter(Incident.suppressed.is_(False)).count()
    suppressed = total_incidents - surfaced
    duplicate_alerts = db.query(Alert).filter(Alert.is_duplicate.is_(True)).count()
    dedup_corr = round(100.0 * (1 - total_incidents / total_alerts), 2) if total_alerts and total_incidents else 0.0
    suppression = round(duplicate_alerts / total_alerts, 4) if total_alerts else 0.0
    dwells = [
        (i.last_seen - i.first_seen).total_seconds()
        for i in db.query(Incident).all() if i.last_seen and i.first_seen
    ]
    median_dwell = round(statistics.median(dwells), 1) if dwells else 0.0
    feedback = db.query(Feedback).all()
    fp_rate = None
    if feedback:
        fp_rate = round(sum(1 for f in feedback if f.label == "false_positive") / len(feedback), 4)
    resolved = db.query(Incident).filter(Incident.status == "resolved").count()
    reopen_rate = None
    if resolved:
        reopened = db.query(Incident).filter(Incident.status.in_(["in_triage", "investigating"])).count()
        reopen_rate = round(reopened / resolved, 4)
    _, threshold = load_model()
    labelled = db.query(Incident).filter(Incident.is_malicious.isnot(None)).all()
    recall = None
    if labelled:
        malicious = [i for i in labelled if i.is_malicious]
        if malicious:
            surfaced_mal = [i for i in malicious if not i.suppressed]
            recall = round(len(surfaced_mal) / len(malicious), 4)
    target = settings.recall_target
    target_met = bool(recall is not None and recall >= target)
    after_triage = (
        round(100.0 * (1 - surfaced / total_alerts), 2)
        if total_alerts and target_met else None
    )
    return {
        "total_alerts": total_alerts, "raw_alerts": total_alerts,
        "total_incidents": total_incidents, "incidents": total_incidents,
        "surfaced_incidents": surfaced, "suppressed_incidents": suppressed,
        "duplicate_alerts": duplicate_alerts,
        "alert_reduction_pct": dedup_corr,
        "dedup_correlation_reduction_pct": dedup_corr,
        "after_triage_reduction_pct": after_triage,
        "headline_reduction_pct": after_triage,
        "headline_reduction_label": f"{after_triage}%" if after_triage is not None else "target not met",
        "recall_target": target, "recall_target_met": target_met,
        "suppression_ratio": suppression, "median_dwell_seconds": median_dwell,
        "false_positive_rate": fp_rate, "reopen_rate": reopen_rate,
        "recall_at_threshold": recall, "threshold": threshold,
    }
