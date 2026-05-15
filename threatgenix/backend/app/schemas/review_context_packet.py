"""Schemas for grounded AI context packets and output validation."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


CONTEXT_PACKET_VERSION = "threatgenix_context_packet_v1"


class ReviewContextPacketEntry(BaseModel):
    entry_id: UUID
    item_type: str
    title: str
    untrusted_text: str
    source_refs: list[dict]
    content_hash: str


class ReviewContextPacket(BaseModel):
    version: str = CONTEXT_PACKET_VERSION
    review_id: UUID
    app_name: str
    commit_sha: str | None = None
    deterministic_decision: str | None = None
    policy: dict = Field(default_factory=dict)
    evidence_snapshot_hash: str
    entries: list[ReviewContextPacketEntry] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class GroundedFixPlanStep(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    remediation: str = Field(min_length=1, max_length=2000)
    cited_content_hashes: list[str] = Field(default_factory=list, min_length=1)


class GroundedAIReviewOutput(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    proposed_decision: Literal["pass", "block", "fix", "verify", "gather_evidence"] | None = None
    cited_content_hashes: list[str] = Field(default_factory=list, min_length=1)
    fix_plan: list[GroundedFixPlanStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def fix_steps_must_be_cited(self) -> "GroundedAIReviewOutput":
        for step in self.fix_plan:
            if not step.cited_content_hashes:
                raise ValueError("Every fix-plan step must cite evidence.")
        return self


class GroundedAIValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


class GroundedAIExplanationResponse(BaseModel):
    review_id: UUID
    packet: ReviewContextPacket
    output: GroundedAIReviewOutput | None = None
    validation: GroundedAIValidationResult
    explanation_status: Literal["ready", "missing_evidence", "invalid"] = "ready"
    prompt_contract: list[str] = Field(default_factory=list)
