"""Schemas for managed scanner enqueueing from application reviews."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.application_review import ReviewTool
from app.schemas.scan import ScanJobResponse


class EnqueueReviewScannersRequest(BaseModel):
    bundle_id: UUID
    tools: list[ReviewTool] | None = Field(default=None, max_length=20)
    external_active_authorized: bool = False
    external_targets: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("tools")
    @classmethod
    def deduplicate_tools(cls, value: list[ReviewTool] | None) -> list[ReviewTool] | None:
        if value is None:
            return None
        return list(dict.fromkeys(value))

    @field_validator("external_targets")
    @classmethod
    def normalize_external_targets(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        return list(dict.fromkeys(normalized))


class EnqueueReviewScannersResponse(BaseModel):
    review_id: UUID
    bundle_id: UUID
    jobs: list[ScanJobResponse]
