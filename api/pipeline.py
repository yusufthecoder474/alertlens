"""Ingest pipeline: normalize -> dedup (vs DB + batch) -> correlate -> score.

Idempotent: re-posting an alert with an existing id returns it as skipped.
Duplicates are stored with is_duplicate=True and linked to the first alert.
"""
import json
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api import dedup as dedup_mod
from api.config import settings
from api.correlation import correlate, correlation_key
from api.explain import explain_factors
from api.mitre import SEVERITY_WEIGHT, mitre_for_rule
from api.models import Alert, Incident
from api.scoring import load_model, score_incident
from api.summary import llm_summary


def _alert_to_dict(alert: Alert) -> dict:
    raw = json.loads(alert.raw) if alert.raw else {}
    return {
        "id": alert.id, "timestamp": alert.timestamp, "source": alert.source,
        "rule_name": alert.rule_name, "severity": alert.severity,
        "src_ip": alert.src_ip, "dst_ip": alert.dst_ip, "host": alert.host,
        "raw": raw, "is_malicious": alert.is_malicious,
    }


def suppression_decision(ml_probability: float) -> tuple[bool, str | None]:
    """Apply the false-negative budget: below threshold -> suppressed.

    Returns (suppressed, reason). The reason names the numbers so an
    analyst can see exactly why this incident left the queue.
    """
    _, threshold = load_model()
    if ml_probability >= threshold:
        return False, None
    return True, (
        f"ML probability {ml_probability:.2f} below calibrated threshold "
        f"{threshold:.2f} (recall target {settings.recall_target:.2f}); "
        "incident suppressed from the queue, not deleted — reopen to triage it."
    )


def _find_open_incident(db: Session, key: str, ts: datetime) -> Incident | None:
    """Find a non-resolved incident with the same host/src_ip within the window."""
    since = ts - timedelta(seconds=settings.correlation_window_seconds)
    candidates = (
        db.query(Incident).filter(Incident.status != "resolved", Incident.last_seen >= since)
        .order_by(Incident.last_seen.desc()).all()
    )
    for inc in candidates:
        inc_key = inc.host or inc.src_ip or "unknown"
        if inc_key == key:
            return inc
    return None


def ingest_alerts(db: Session, alerts: list[dict], _attempt: int = 0) -> dict:
    """Ingest normalized alert dicts; return counts + created incident ids.

    Each dict needs id/timestamp/source/rule_name/severity and may carry
    src_ip/dst_ip/host/raw/is_malicious.

    Concurrency: if another request inserts the same alert ids between our
    existence check and our flush/commit, the unique alert-id primary key
    raises IntegrityError. The whole transaction is rolled back and retried;
    on retry the already-inserted alerts are seen and skipped, so no
    duplicate rows are created and no work is half-applied.
    """
    try:
        return _ingest_once(db, alerts)
    except IntegrityError:
        db.rollback()
        if _attempt >= 3:
            raise
        return ingest_alerts(db, alerts, _attempt + 1)


def _ingest_once(db: Session, alerts: list[dict]) -> dict:
    """One ingest attempt inside a single transaction (see ingest_alerts)."""
    inserted = skipped = duplicates = 0
    kept_dicts: list[dict] = []
    for raw_alert in alerts:
        if db.query(Alert).filter(Alert.id == raw_alert["id"]).first():
            skipped += 1
            continue
        fp = dedup_mod.fingerprint(raw_alert.get("rule_name"), raw_alert.get("src_ip"),
                                   raw_alert.get("dst_ip"), raw_alert.get("host"))
        window_start = raw_alert["timestamp"] - timedelta(seconds=settings.dedup_window_seconds)
        prior = (
            db.query(Alert).filter(Alert.fingerprint == fp, Alert.timestamp >= window_start,
                                   Alert.timestamp <= raw_alert["timestamp"], Alert.is_duplicate.is_(False))
            .order_by(Alert.timestamp.asc()).first()
        )
        is_dup = prior is not None
        alert = Alert(
            id=raw_alert["id"], timestamp=raw_alert["timestamp"], source=raw_alert["source"],
            rule_name=raw_alert["rule_name"], severity=str(raw_alert["severity"]).lower(),
            src_ip=raw_alert.get("src_ip"), dst_ip=raw_alert.get("dst_ip"), host=raw_alert.get("host"),
            raw=json.dumps(raw_alert.get("raw") or {}), fingerprint=fp,
            is_duplicate=is_dup, duplicate_of_id=prior.id if prior else None,
            is_malicious=raw_alert.get("is_malicious"),
        )
        db.add(alert)
        if is_dup:
            duplicates += 1
        else:
            inserted += 1
            kept_dicts.append(_alert_to_dict(alert))
    db.flush()

    # Dedup inside the batch itself (same fingerprint twice in one request).
    kept_dicts, batch_dups = dedup_mod.dedup_batch(kept_dicts)
    for dup in batch_dups:
        row = db.query(Alert).filter(Alert.id == dup["id"]).first()
        if row:
            row.is_duplicate = True
            row.duplicate_of_id = dup.get("duplicate_of")
            duplicates += 1
            inserted -= 1
    db.flush()

    # Correlate kept alerts into incidents (new or attached to an open one).
    incident_ids: list[int] = []
    for group in correlate(kept_dicts):
        key = correlation_key(group[0])
        existing = _find_open_incident(db, key, group[0]["timestamp"])
        if existing:
            _attach_to_incident(db, existing, group)
            incident_ids.append(existing.id)
        else:
            incident_ids.append(_create_incident(db, group).id)
    db.commit()
    return {"inserted": inserted, "skipped": skipped, "duplicates": duplicates,
            "incidents_created_or_updated": len(incident_ids), "incident_ids": incident_ids}


def _incident_fields(group: list[dict]) -> dict:
    """Shared fields for a new incident or an updated one."""
    priority, ml_prob = score_incident(group)
    mitre = sorted({mitre_for_rule(a["rule_name"]) for a in group if mitre_for_rule(a["rule_name"])})
    top_sev = max((a.get("severity", "low") for a in group),
                  key=lambda s: SEVERITY_WEIGHT.get(str(s).lower(), 0.25))
    return {
        "priority_score": priority, "ml_probability": ml_prob, "mitre_tags": mitre,
        "severity": str(top_sev).lower(),
        "first_seen": min(a["timestamp"] for a in group),
        "last_seen": max(a["timestamp"] for a in group),
        "is_malicious": any(a.get("is_malicious") for a in group),
    }


def _create_incident(db: Session, group: list[dict]) -> Incident:
    fields = _incident_fields(group)
    host = group[0].get("host")
    src_ip = group[0].get("src_ip")
    dup_count = db.query(Alert).filter(
        Alert.duplicate_of_id.in_([a["id"] for a in group])).count()
    suppressed, reason = suppression_decision(fields["ml_probability"])
    incident = Incident(
        title=f"{group[0]['rule_name']} on {host or src_ip or 'unknown'}",
        host=host, src_ip=src_ip, status="new", alert_count=len(group),
        duplicate_count=dup_count, suppressed=suppressed, suppression_reason=reason,
        **fields,
    )
    incident.factors = json.dumps(explain_factors(group, fields["ml_probability"], dup_count))
    incident.mitre_tags = json.dumps(fields["mitre_tags"])
    db.add(incident)
    db.flush()
    for a in group:
        db.query(Alert).filter(Alert.id == a["id"]).update({"incident_id": incident.id})
    inc_dict = {"host": host, "src_ip": src_ip, "mitre_tags": fields["mitre_tags"],
                "priority_score": fields["priority_score"], "ml_probability": fields["ml_probability"],
                "first_seen": fields["first_seen"], "last_seen": fields["last_seen"]}
    summary, source = llm_summary(inc_dict, group)
    incident.summary, incident.summary_source = summary, source
    db.flush()
    return incident


def _attach_to_incident(db: Session, incident: Incident, group: list[dict]) -> None:
    """Add a new group of alerts to an existing open incident and rescore it."""
    for a in group:
        db.query(Alert).filter(Alert.id == a["id"]).update({"incident_id": incident.id})
    db.flush()
    rows = db.query(Alert).filter(Alert.incident_id == incident.id, Alert.is_duplicate.is_(False)).all()
    all_alerts = [_alert_to_dict(r) for r in rows]
    fields = _incident_fields(all_alerts)
    dup_count = db.query(Alert).filter(Alert.incident_id == incident.id, Alert.is_duplicate.is_(True)).count()
    incident.priority_score = fields["priority_score"]
    incident.ml_probability = fields["ml_probability"]
    incident.mitre_tags = json.dumps(fields["mitre_tags"])
    incident.severity = fields["severity"]
    incident.last_seen = fields["last_seen"]
    incident.alert_count = len(all_alerts)
    incident.duplicate_count = dup_count
    incident.is_malicious = fields["is_malicious"]
    suppressed, reason = suppression_decision(fields["ml_probability"])
    incident.suppressed = suppressed
    incident.suppression_reason = reason
    incident.factors = json.dumps(explain_factors(all_alerts, fields["ml_probability"], dup_count))
    inc_dict = {"host": incident.host, "src_ip": incident.src_ip, "mitre_tags": fields["mitre_tags"],
                "priority_score": fields["priority_score"], "ml_probability": fields["ml_probability"],
                "first_seen": fields["first_seen"], "last_seen": fields["last_seen"]}
    summary, source = llm_summary(inc_dict, all_alerts)
    incident.summary, incident.summary_source = summary, source
    db.flush()