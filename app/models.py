from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.mitre_execution_ta0002 import is_allowed_ta0002_technique


class TrapSession(BaseModel):
    trap: str
    target_domain: Literal["IT", "OT"]
    started_at: datetime
    last_activity: datetime
    metadata: Dict[str, str] = Field(default_factory=dict)


class PredictionIn(BaseModel):
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Prediction timestamp in ISO-8601 format.",
    )
    tactic_id: Literal["TA0002"] = Field(
        ..., description="MITRE ATT&CK tactic ID. For this phase only TA0002."
    )
    technique_id: str = Field(
        ..., description="MITRE ATT&CK technique ID (e.g. T1059 or T1059.003)."
    )
    matrix: Literal["enterprise", "ics"] = Field(
        ..., description="Source matrix from Narcis model output."
    )
    target_domain: Literal["IT", "OT"] = Field(
        ..., description="Destination domain for trap activation."
    )
    confidence: float = Field(..., ge=0.0, le=1.0)
    ttl_seconds: int = Field(default=120, ge=10, le=3600)
    attack_phase: Optional[str] = Field(default="execution")
    attacker_command: Optional[str] = Field(
        default=None,
        description="Optional command intercepted from the attacker to route to Ollama.",
    )
    end_of_attack: bool = Field(
        default=False,
        description="Set true to trigger final SOC report generation from observatory JSON logs.",
    )

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not is_allowed_ta0002_technique(normalized):
            raise ValueError(
                "Invalid TA0002 technique ID. "
                "Use only real Execution technique IDs (e.g. T1059, T1204.002)."
            )
        return normalized


class PredictionAccepted(BaseModel):
    event_id: str
    accepted_at: datetime
    reaction: Dict[str, object]
    queue_status: str


class AttackerCommandIn(BaseModel):
    command: str = Field(..., min_length=1, max_length=4000)
    source_ip: Optional[str] = Field(
        default=None,
        description="Optional source IP override for simulation and session separation.",
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Optional user-agent override for simulation and session separation.",
    )


class SocReportRequest(BaseModel):
    attack_label: str = Field(default="Echo-Net simulated incident")
    model: Optional[str] = Field(default=None)


class ScenarioRunRequest(BaseModel):
    source_ip: str = Field(default="10.20.30.40")
    user_agent: str = Field(default="scenario-runner/1.0")
    commands: list[str] = Field(
        default_factory=lambda: [
            "whoami",
            "ip route",
            "show me current network routes",
        ]
    )
    trigger_ot: bool = Field(default=True)
    generate_report: bool = Field(default=True)
    attack_label: str = Field(default="Echo-Net scenario-runner incident")
