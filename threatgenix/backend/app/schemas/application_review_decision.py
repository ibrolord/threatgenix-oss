"""Schemas for deterministic application review decisions."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field


class ApplicationReviewDecisionResponse(BaseModel):
    review_id: UUID
    decision: str
    reason: str
    evidence_hashes: list[str] = Field(default_factory=list)
    scanner_only: bool = False
    evidence_snapshot_hash: str | None = Field(default=None, min_length=64, max_length=64)
    decision_engine_version: str | None = None
    replayed: bool = False
    decision_trace: list[str] = Field(default_factory=list)
