"""Schemas for the durable web review artifact."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.application_review import ApplicationReviewResponse
from app.schemas.application_review_context import ApplicationReviewContextEntryResponse


class ApplicationReviewEvidenceChainStep(BaseModel):
    step_type: str
    label: str
    source_ref: dict | None = None
    content_hash: str | None = None


class ApplicationReviewEvidenceChain(BaseModel):
    chain_id: str
    title: str
    item_type: str
    status: str
    stale_reason: str | None = None
    content_hash: str
    source_refs: list[dict] = Field(default_factory=list)
    steps: list[ApplicationReviewEvidenceChainStep] = Field(default_factory=list)


class ApplicationReviewGraphNode(BaseModel):
    id: str
    label: str
    node_type: str
    evidence_hashes: list[str] = Field(default_factory=list)
    status: str | None = None


class ApplicationReviewGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    evidence_hashes: list[str] = Field(default_factory=list)


class ApplicationReviewGraphSlice(BaseModel):
    nodes: list[ApplicationReviewGraphNode] = Field(default_factory=list)
    edges: list[ApplicationReviewGraphEdge] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)


class ApplicationReviewArtifactFixPlanStep(BaseModel):
    title: str
    action: str
    verification: str
    cited_content_hashes: list[str] = Field(default_factory=list)
    source_refs: list[dict] = Field(default_factory=list)


class ApplicationReviewRerunHistoryEntry(BaseModel):
    review_id: UUID
    parent_review_id: UUID | None = None
    status: str
    decision: str | None = None
    commit_sha: str | None = None
    evidence_snapshot_hash: str | None = None
    updated_at: datetime


class ApplicationReviewArtifactResponse(BaseModel):
    review: ApplicationReviewResponse
    web_url: str
    decision_record: dict | None = None
    raw_evidence: list[ApplicationReviewContextEntryResponse] = Field(default_factory=list)
    raw_evidence_count: int = Field(ge=0)
    has_stale_evidence: bool = False
    missing_evidence: list[str] = Field(default_factory=list)
    source_ref_count: int = Field(ge=0)
    evidence_chains: list[ApplicationReviewEvidenceChain] = Field(default_factory=list)
    graph_slice: ApplicationReviewGraphSlice = Field(default_factory=ApplicationReviewGraphSlice)
    fix_plan: list[ApplicationReviewArtifactFixPlanStep] = Field(default_factory=list)
    accepted_risks: list[ApplicationReviewContextEntryResponse] = Field(default_factory=list)
    rerun_history: list[ApplicationReviewRerunHistoryEntry] = Field(default_factory=list)
    redacted: bool = True
