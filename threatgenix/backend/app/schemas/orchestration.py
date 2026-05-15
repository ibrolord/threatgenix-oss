"""Schemas for durable orchestration jobs."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


OrchestrationJobKind = Literal[
    "evidence_rebuild",
    "validation_run",
    "security_audit",
    "environment_audit",
    "custom",
]
OrchestrationTaskKind = Literal[
    "agent_reasoning",
    "tool_execution",
    "evidence_projection",
    "human_review",
]
OrchestrationStatus = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "cancelled",
    "blocked",
]
ALLOWED_ORCHESTRATION_TOOLS = frozenset(
    {
        "nuclei",
        "semgrep",
        "osv-scanner",
        "trivy",
        "checkov",
        "trufflehog",
        "prowler",
        "external-report",
        "pentest-report",
        "evidence",
        "evidence-rebuild",
        "security-review",
        "environment-audit",
    }
)


class OrchestrationTaskCreate(BaseModel):
    task_kind: OrchestrationTaskKind = "tool_execution"
    agent_name: str | None = Field(default=None, max_length=120)
    tool_name: str | None = Field(default=None, max_length=120)
    input_payload: dict = Field(default_factory=dict)
    max_attempts: int = Field(default=1, ge=1, le=5)

    @model_validator(mode="after")
    def validate_tool_execution_tool_name(self) -> "OrchestrationTaskCreate":
        if self.tool_name is not None:
            self.tool_name = self.tool_name.strip() or None
        if self.task_kind != "tool_execution":
            return self
        if not self.tool_name:
            raise ValueError("tool_name is required for tool_execution tasks")
        if self.tool_name not in ALLOWED_ORCHESTRATION_TOOLS:
            raise ValueError(f"unsupported orchestration tool: {self.tool_name}")
        return self


class OrchestrationJobCreate(BaseModel):
    job_kind: OrchestrationJobKind
    objective: str = Field(min_length=5, max_length=2000)
    requested_tools: list[str] = Field(default_factory=list, max_length=20)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=120)
    inputs: dict = Field(default_factory=dict)
    policy: dict = Field(default_factory=dict)
    tasks: list[OrchestrationTaskCreate] = Field(default_factory=list, max_length=50)

    @field_validator("requested_tools")
    @classmethod
    def validate_requested_tools(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for tool_name in value:
            trimmed = tool_name.strip()
            if not trimmed:
                raise ValueError("requested tool names must not be blank")
            if len(trimmed) > 120:
                raise ValueError("requested tool names must be 120 characters or fewer")
            if trimmed not in ALLOWED_ORCHESTRATION_TOOLS:
                raise ValueError(f"unsupported orchestration tool: {trimmed}")
            normalized.append(trimmed)
        return normalized


class OrchestrationTaskResponse(BaseModel):
    id: UUID
    job_id: UUID
    threat_model_id: UUID
    task_kind: str
    agent_name: str | None = None
    tool_name: str | None = None
    status: str
    input_payload: dict = Field(default_factory=dict)
    output_payload: dict = Field(default_factory=dict)
    error_message: str | None = None
    attempt_count: int
    max_attempts: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class OrchestrationEventResponse(BaseModel):
    id: UUID
    job_id: UUID
    task_id: UUID | None = None
    threat_model_id: UUID
    event_type: str
    level: str
    message: str
    payload: dict = Field(default_factory=dict)
    created_at: datetime


class OrchestrationJobResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    owner_id: UUID
    job_kind: str
    status: str
    objective: str
    requested_tools: list[str] = Field(default_factory=list)
    idempotency_key: str | None = None
    inputs: dict = Field(default_factory=dict)
    policy: dict = Field(default_factory=dict)
    result_summary: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    tasks: list[OrchestrationTaskResponse] = Field(default_factory=list)
    events: list[OrchestrationEventResponse] = Field(default_factory=list)
