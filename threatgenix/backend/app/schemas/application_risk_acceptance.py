"""Schemas for application review risk acceptance lifecycle."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

RiskAcceptanceScopeType = Literal["rule", "finding", "route", "app"]
RiskAcceptanceStatus = Literal["active", "expired", "revoked"]


class ApplicationRiskAcceptanceCreate(BaseModel):
    finding_stable_id: str | None = Field(default=None, max_length=255)
    scope_type: RiskAcceptanceScopeType
    scope_value: str = Field(min_length=1, max_length=500)
    justification: str = Field(min_length=10, max_length=4000)
    compensating_control: str | None = Field(default=None, max_length=4000)
    expires_at: datetime

    @field_validator("scope_value", "finding_stable_id", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: object) -> str | None:
        if value is None:
            return None
        candidate = str(value).strip()
        return candidate or None


class ApplicationRiskAcceptanceRevoke(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


class ApplicationRiskAcceptanceExpireResponse(BaseModel):
    expired_count: int = Field(ge=0)


class ApplicationRiskAcceptanceResponse(BaseModel):
    id: UUID
    tenant_key: str
    app_name: str
    review_id: UUID
    finding_stable_id: str | None = None
    scope_type: RiskAcceptanceScopeType
    scope_value: str
    justification: str
    compensating_control: str | None = None
    approver_id: UUID
    approved_at: datetime
    expires_at: datetime
    status: RiskAcceptanceStatus
    revoked_at: datetime | None = None
    revoked_by_id: UUID | None = None
    revoked_reason: str | None = None
    audit_events: list[dict] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}
