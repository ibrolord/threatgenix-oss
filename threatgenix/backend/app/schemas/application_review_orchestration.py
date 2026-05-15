"""Schemas for deterministic invoke-anywhere review orchestration."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.application_review import ApplicationReviewCreate, ApplicationReviewResponse, ReviewTool
from app.schemas.application_review_bundle import (
    ApplicationReviewBundleCreate,
    ApplicationReviewBundleResponse,
)
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.schemas.scan import ScanJobResponse
from app.schemas.threat_model import ThreatModelCreate

RunStatus = Literal["completed", "failed"]
StepStatus = Literal["pass", "fail", "skip"]


class ReviewOrchestrationStep(BaseModel):
    name: str
    status: StepStatus
    detail: str


class ApplicationReviewOrchestrationRequest(BaseModel):
    threat_model: ThreatModelCreate | None = None
    review: ApplicationReviewCreate
    bundle: ApplicationReviewBundleCreate | None = None
    scanner_tools: list[ReviewTool] | None = Field(default=None, max_length=20)
    external_active_authorized: bool = False
    external_targets: list[str] = Field(default_factory=list, max_length=20)
    rebuild_context: bool = True
    evaluate_decision: bool = True

    @model_validator(mode="after")
    def validate_orchestration_shape(self) -> "ApplicationReviewOrchestrationRequest":
        if self.threat_model is not None and self.review.threat_model_id is not None:
            raise ValueError("Use either threat_model or review.threat_model_id, not both.")
        if self.scanner_tools and self.bundle is None:
            raise ValueError("scanner_tools requires bundle.")
        if self.scanner_tools and not (self.threat_model or self.review.threat_model_id):
            raise ValueError(
                "scanner_tools requires threat_model or review.threat_model_id because scanner jobs are linked to a threat model."
            )
        return self


class ApplicationReviewOrchestrationResponse(BaseModel):
    status: RunStatus
    steps: list[ReviewOrchestrationStep] = Field(default_factory=list)
    failure_reason: str | None = None
    threat_model_id: UUID | None = None
    review: ApplicationReviewResponse | None = None
    bundle: ApplicationReviewBundleResponse | None = None
    scanner_jobs: list[ScanJobResponse] = Field(default_factory=list)
    indexed_entry_count: int | None = None
    decision: ApplicationReviewDecisionResponse | None = None
    web_url: str | None = None
