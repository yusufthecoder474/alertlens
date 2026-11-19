"""FastAPI app: ingest, incidents, analyst workflow, metrics, health."""
import json
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from api.database import Base, engine, get_db
from api.metrics import compute_metrics
from api.models import Alert, Feedback, Incident
from api.pipeline import ingest_alerts
from api.schemas import AlertBatch, FeedbackIn, IncidentOut, MetricsOut, StatusUpdate
from api.security import api_key_auth, check_rate_limit

Base.metadata.create_all(bind=engine)
app = FastAPI(title="AlertLens", version="1.0.0",
              description="SOC alert triage and deduplication dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])


def _incident_out(inc: Incident) -> IncidentOut:
    return IncidentOut(
        id=inc.id, title=inc.title, host=inc.host, src_ip=inc.src_ip, status=inc.status,
        priority_score=inc.priority_score, ml_probability=inc.ml_probability,
        severity=inc.severity, mitre_tags=json.loads(inc.mitre_tags or "[]"),
        factors=json.loads(inc.factors or "[]"), summary=inc.summary or "",
        summary_source=inc.summary_source, analyst_label=inc.analyst_label,
        first_seen=inc.first_seen, last_seen=inc.last_seen,
        alert_count=inc.alert_count, duplicate_count=inc.duplicate_count,
        is_malicious=inc.is_malicious,
        suppressed=bool(inc.suppressed), suppression_reason=inc.suppression_reason,
    )


@app.get("/health")
def health() -> dict:
    """Unauthenticated liveness check."""
    return {"status": "ok"}


@app.post("/alerts", dependencies=[Depends(api_key_auth)])
def post_alerts(batch: AlertBatch, db: Session = Depends(get_db), key: str = Depends(api_key_auth)) -> dict:
    """Ingest a batch of alerts (idempotent on alert id)."""
    check_rate_limit(key)
    alerts = [a.model_dump() for a in batch.alerts]
    return ingest_alerts(db, alerts)


@app.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(status: str | None = Query(default=None),
                   sort: str = Query(default="priority"),
                   include_suppressed: bool = Query(default=False),
                   db: Session = Depends(get_db)) -> list[IncidentOut]:
    """List incidents, optionally filtered by status, sorted by priority or recency.

    Suppressed incidents (below the calibrated threshold) are hidden by
    default; pass ``include_suppressed=true`` to see them. They are never
    deleted and can be reopened.
    """
    q = db.query(Incident)
    if not include_suppressed:
        q = q.filter(Incident.suppressed.is_(False))
    if status:
        q = q.filter(Incident.status == status)
    q = q.order_by(Incident.priority_score.desc()) if sort == "priority" else q.order_by(Incident.last_seen.desc())
    return [_incident_out(i) for i in q.all()]


@app.get("/incidents/{incident_id}", dependencies=[Depends(api_key_auth)])
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> dict:
    """Incident detail: evidence package + alert timeline."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).order_by(Alert.timestamp.asc()).all()
    timeline = [{
        "id": a.id, "timestamp": a.timestamp.isoformat(), "rule_name": a.rule_name,
        "severity": a.severity, "src_ip": a.src_ip, "dst_ip": a.dst_ip, "host": a.host,
        "is_duplicate": a.is_duplicate, "duplicate_of_id": a.duplicate_of_id,
    } for a in alerts]
    return {"incident": _incident_out(inc), "alerts": timeline}


@app.patch("/incidents/{incident_id}/status", dependencies=[Depends(api_key_auth)])
def update_status(incident_id: int, body: StatusUpdate, db: Session = Depends(get_db)) -> IncidentOut:
    """Move an incident through new -> in_triage -> investigating -> resolved."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = body.status
    # An analyst who moves an incident has looked at it: the suppression
    # decision is lifted so the incident stays visible in the queue.
    inc.suppressed = False
    inc.suppression_reason = None
    db.commit()
    db.refresh(inc)
    return _incident_out(inc)


@app.post("/incidents/{incident_id}/reopen", dependencies=[Depends(api_key_auth)])
def reopen_incident(incident_id: int, db: Session = Depends(get_db)) -> IncidentOut:
    """Reopen a suppressed incident: back to ``new`` and visible in the queue."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = "new"
    inc.suppressed = False
    inc.suppression_reason = None
    db.commit()
    db.refresh(inc)
    return _incident_out(inc)


@app.post("/incidents/{incident_id}/feedback", dependencies=[Depends(api_key_auth)])
def post_feedback(incident_id: int, body: FeedbackIn, db: Session = Depends(get_db)) -> dict:
    """Analyst marks an incident true/false positive; stored for retraining."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.add(Feedback(incident_id=incident_id, label=body.label, note=body.note, created_at=datetime.now(timezone.utc)))
    inc.analyst_label = body.label
    db.commit()
    return {"incident_id": incident_id, "label": body.label}


@app.get("/metrics", response_model=MetricsOut, dependencies=[Depends(api_key_auth)])
def get_metrics(db: Session = Depends(get_db)) -> MetricsOut:
    """Dashboard metrics (see api/metrics.py for definitions)."""
    return MetricsOut(**compute_metrics(db))
