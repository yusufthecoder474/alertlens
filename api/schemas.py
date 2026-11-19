"""Pydantic request/response schemas (validation boundary for all input)."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class AlertIn(BaseModel):
    """One alert as posted by a SIEM / CSV loader."""

    id: str = Field(..., min_length=1, max_length=128)
    timestamp: datetime
    source: str = Field(..., min_length=1, max_length=64)
    rule_name: str = Field(..., min_length=1, max_length=128)
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    host: Optional[str] = None
    raw: dict[str, Any] = {}
    is_malicious: Optional[bool] = None

    @field_validator("severity")
    @classmethod
    def _severity_allowed(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v.lower()


class AlertBatch(BaseModel):
    """A batch of alerts; capped so one request cannot flood the DB."""

    alerts: list[AlertIn] = Field(..., min_length=1, max_length=1000)


class StatusUpdate(BaseModel):
    """Analyst status change for an incident."""

    status: str

    @field_validator("status")
    @classmethod
    def _status_allowed(cls, v: str) -> str:
        allowed = {"new", "in_triage", "investigating", "resolved"}
        if v.lower() not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return v.lower()


class FeedbackIn(BaseModel):
    """Analyst true/false-positive marking."""

    label: str
    note: str = ""

    @field_validator("label")
    @classmethod
    def _label_allowed(cls, v: str) -> str:
        allowed = {"true_positive", "false_positive"}
        if v.lower() not in allowed:
            raise ValueError(f"label must be one of {sorted(allowed)}")
        return v.lower()


class IncidentOut(BaseModel):
    """Incident as returned by the API."""

    id: int
    title: str
    host: Optional[str] = None
    src_ip: Optional[str] = None
    status: str
    priority_score: float
    # None when no alert in the incident has flow evidence (the model did
    # not score it); such incidents are never suppressed.
    ml_probability: Optional[float] = None
    severity: str
    mitre_tags: list[str] = []
    factors: list[str] = []
    summary: str = ""
    summary_source: str = "template"
    analyst_label: Optional[str] = None
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    duplicate_count: int
    is_malicious: Optional[bool] = None


class MetricsOut(BaseModel):
    """Dashboard metrics (see api/metrics.py for exact definitions)."""

    total_alerts: int
    raw_alerts: int
    total_incidents: int
    incidents: int
    surfaced_incidents: int
    suppressed_incidents: int
    duplicate_alerts: int
    alert_reduction_pct: float  # == dedup_correlation_reduction_pct (kept for compat)
    dedup_correlation_reduction_pct: float
    after_triage_reduction_pct: Optional[float] = None  # None when recall target not met
    headline_reduction_pct: Optional[float] = None
    headline_reduction_label: str = "target not met"
    recall_target: float
    recall_target_met: bool
    suppression_ratio: float
    median_dwell_seconds: float
    false_positive_rate: Optional[float] = None
    reopen_rate: Optional[float] = None
    recall_at_threshold: Optional[float] = None
    threshold: float
