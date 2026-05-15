"""Schemas for GitHub PR review integration."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.application_review import ReviewTool

GitHubRepositoryLinkStatus = Literal["active", "suspended", "uninstalled"]
GitHubWebhookStatus = Literal["accepted", "ignored", "rejected"]


class GitHubRepositoryLinkCreate(BaseModel):
    installation_id: str = Field(min_length=1, max_length=80)
    repository_id: str = Field(min_length=1, max_length=80)
    repository_full_name: str = Field(min_length=3, max_length=255)
    private: bool = True
    threat_model_id: UUID | None = None
    requested_tools: list[ReviewTool] = Field(default_factory=lambda: ["semgrep"], max_length=20)

    @field_validator("installation_id", "repository_id", mode="before")
    @classmethod
    def stringify_provider_id(cls, value: object) -> str:
        return str(value).strip()

    @field_validator("repository_full_name")
    @classmethod
    def normalize_repository_full_name(cls, value: str) -> str:
        candidate = value.strip()
        if "/" not in candidate:
            raise ValueError("repository_full_name must be owner/repo.")
        return candidate


class GitHubRepositoryLinkResponse(BaseModel):
    id: UUID
    tenant_key: str
    owner_id: UUID
    organization_id: UUID | None = None
    threat_model_id: UUID | None = None
    installation_id: str
    repository_id: str
    repository_full_name: str
    private: bool
    requested_tools: list[ReviewTool] = Field(default_factory=list)
    status: GitHubRepositoryLinkStatus
    created_at: datetime | None = None
    updated_at: datetime | None = None


class GitHubWebhookResponse(BaseModel):
    status: GitHubWebhookStatus
    event: str
    action: str | None = None
    delivery_id: str
    repository_full_name: str | None = None
    pull_request_number: int | None = None
    review_id: UUID | None = None
    review_lineage_id: UUID | None = None
    web_url: str | None = None
    check_name: str = "ThreatGenix Security Review"
    comment_body: str | None = None
    ignored_reason: str | None = None
