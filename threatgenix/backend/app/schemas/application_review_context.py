"""Schemas for review security context retrieval."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ApplicationReviewContextEntryResponse(BaseModel):
    id: UUID
    review_id: UUID
    source_type: str
    source_object_id: UUID | None
    item_type: str
    title: str
    body: str
    keywords: list[str]
    facets: dict = Field(default_factory=dict)
    retrieval_text: str = ""
    source_refs: list[dict]
    content_hash: str
    status: str
    stale_reason: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RebuildReviewContextIndexResponse(BaseModel):
    review_id: UUID
    entry_count: int = Field(ge=0)


class ReviewContextSearchResponse(BaseModel):
    review_id: UUID
    query: str
    mode: str = "keyword"
    fallback_reason: str | None = None
    results: list[ApplicationReviewContextEntryResponse]
