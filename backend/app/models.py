from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class NormalizedEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    asset: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    status: str | None = None
    message: str | None = None
    raw_log: str

class DetectionRule(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str
    tactic: str
    technique: str
    confidence: float = Field(ge=0, le=1)
    event_type: str | None = None
    status: str | None = None
    keywords: list[str] = []
    threshold: int = 1
    window_minutes: int = 5
    group_by: list[str] = []

class Alert(BaseModel):
    alert_id: str
    rule_id: str
    title: str
    severity: str
    tactic: str
    technique: str
    confidence: float
    timestamp: datetime
    asset: str | None = None
    user: str | None = None
    src_ip: str | None = None
    evidence: list[str] = []
    recommended_action: str

class Incident(BaseModel):
    incident_id: str
    priority: str
    status: str = "open"
    owner: str = "unassigned"
    related_alert_ids: list[str]
    evidence_summary: str
    timeline: list[dict[str, Any]]
    recommended_response_actions: list[str]

class Anomaly(BaseModel):
    anomaly_id: str
    timestamp: datetime
    entity: str
    anomaly_score: float = Field(ge=0, le=1)
    reason: str
    contributing_features: dict[str, Any]
    recommended_analyst_action: str
    related_event_ids: list[str] = []
