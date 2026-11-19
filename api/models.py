"""SQLAlchemy models. Nothing is ever deleted: duplicates are linked, not removed."""
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text

from api.database import Base


class Alert(Base):
    """One normalized alert. ``is_duplicate`` alerts stay in the table."""

    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String, nullable=False)
    rule_name = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    host = Column(String, nullable=True, index=True)
    raw = Column(Text, nullable=False, default="{}")
    fingerprint = Column(String, nullable=False, index=True)
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(String, ForeignKey("alerts.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    is_malicious = Column(Boolean, nullable=True)  # label, only on seeded data


class Incident(Base):
    """A correlated group of alerts on one host / source IP."""

    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    host = Column(String, nullable=True)
    src_ip = Column(String, nullable=True)
    status = Column(String, default="new")  # new/in_triage/investigating/resolved
    priority_score = Column(Float, default=0.0)
    # NULL when the incident has no flow evidence (the model did not
    # score it). NOT default 0.0: SQLAlchemy fires a column default when
    # the value is None on INSERT, which would silently turn "no evidence"
    # into a 0.0 probability.
    ml_probability = Column(Float, nullable=True, default=None)
    severity = Column(String, default="low")
    mitre_tags = Column(Text, default="[]")  # JSON list of technique ids
    factors = Column(Text, default="[]")  # JSON list of plain-English factors
    summary = Column(Text, default="")
    summary_source = Column(String, default="template")  # template | llm
    analyst_label = Column(String, nullable=True)  # true_positive / false_positive
    # Suppression is a triage decision, NOT an analyst status. An incident is
    # suppressed when its pooled ML probability is below the calibrated
    # threshold; it is never deleted and an analyst can reopen it (which
    # clears both fields). ``status`` keeps the analyst workflow
    # new/in_triage/investigating/resolved independently of this flag.
    suppressed = Column(Boolean, default=False)
    suppression_reason = Column(String, nullable=True)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    alert_count = Column(Integer, default=0)
    duplicate_count = Column(Integer, default=0)
    is_malicious = Column(Boolean, nullable=True)


class Feedback(Base):
    """Analyst feedback on an incident; the retrain script consumes this."""

    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    label = Column(String, nullable=False)  # true_positive / false_positive
    note = Column(String, default="")
    created_at = Column(DateTime, nullable=False)
