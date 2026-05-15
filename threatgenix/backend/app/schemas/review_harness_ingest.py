"""Schemas for review-scoped managed scanner harness ingestion."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.tool_harness import ToolHarnessOutput


class IngestHarnessOutputRequest(BaseModel):
    bundle_id: UUID
    output: ToolHarnessOutput


class IngestHarnessOutputResponse(BaseModel):
    review_id: UUID
    bundle_id: UUID
    scan_job_id: UUID
    status: str
    finding_count: int = Field(ge=0)
    finding_keys: list[str] = Field(default_factory=list)
