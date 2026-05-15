"""Schemas for invoke-anywhere application security reviews."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

ReviewInvocationSurface = Literal["cli", "mcp", "api", "pr", "web"]
ReviewInputKind = Literal["diff", "snapshot", "metadata"]
REVIEW_LIFECYCLE_STATUSES = (
    "created",
    "intake_required",
    "bundle_required",
    "bundle_received",
    "scanning",
    "extracting_context",
    "indexing",
    "building_graph",
    "deciding",
    "explaining",
    "completed",
    "blocked_by_policy",
    "blocked_by_permission",
    "failed_retryable",
    "failed_terminal",
    "cancelled",
)

ReviewStatus = Literal[
    "created",
    "intake_required",
    "bundle_required",
    "bundle_received",
    "scanning",
    "extracting_context",
    "indexing",
    "building_graph",
    "deciding",
    "explaining",
    "completed",
    "blocked_by_policy",
    "blocked_by_permission",
    "failed_retryable",
    "failed_terminal",
    "cancelled",
]
ReviewDecision = Literal["pass", "block", "fix", "verify", "gather_evidence"]
ReviewTool = Literal[
    "semgrep",
    "osv-scanner",
    "trivy",
    "checkov",
    "trufflehog",
    "nuclei",
    "ai-red-team",
    "evidence",
    "security-review",
]


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint_scope(scope: dict) -> str:
    return hashlib.sha256(canonical_json(scope).encode("utf-8")).hexdigest()


class ApplicationReviewCreate(BaseModel):
    app_name: str = Field(min_length=1, max_length=255)
    threat_model_id: UUID | None = None
    parent_review_id: UUID | None = None
    invocation_surface: ReviewInvocationSurface = "api"
    input_kind: ReviewInputKind = "metadata"
    commit_sha: str | None = Field(default=None, max_length=80)
    bundle_hash: str | None = Field(default=None, max_length=80)
    scope: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)
    policy: dict = Field(default_factory=dict)
    requested_tools: list[ReviewTool] = Field(default_factory=list, max_length=20)
    intake_version: str = "threatgenix_appsec_v1"
    intake_answers: dict[str, object] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=120)

    @field_validator("app_name")
    @classmethod
    def validate_app_name(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("app_name must not be blank")
        return candidate

    @field_validator("commit_sha", "bundle_hash", "idempotency_key")
    @classmethod
    def normalize_optional_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None

    @field_validator("requested_tools")
    @classmethod
    def deduplicate_tools(cls, value: list[ReviewTool]) -> list[ReviewTool]:
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def require_review_input_anchor(self) -> "ApplicationReviewCreate":
        if self.input_kind in {"diff", "snapshot"} and not (
            self.commit_sha or self.bundle_hash or self.scope
        ):
            raise ValueError("diff and snapshot reviews require commit_sha, bundle_hash, or scope")
        return self


class ApplicationReviewResponse(BaseModel):
    id: UUID
    tenant_key: str
    owner_id: UUID
    organization_id: UUID | None = None
    threat_model_id: UUID | None = None
    parent_review_id: UUID | None = None
    review_lineage_id: UUID
    app_name: str
    invocation_surface: str
    input_kind: str
    status: ReviewStatus
    decision: ReviewDecision | None = None
    commit_sha: str | None = None
    bundle_hash: str | None = None
    scope_fingerprint: str
    idempotency_key: str
    requested_tools: list[str] = Field(default_factory=list)
    scope: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)
    policy: dict = Field(default_factory=dict)
    result_summary: str | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
