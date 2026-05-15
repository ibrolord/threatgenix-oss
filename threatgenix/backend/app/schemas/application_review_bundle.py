"""Schemas for manifest-only review bundles."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

BundleKind = Literal["diff", "snapshot", "metadata", "existing_evidence"]
BundleSource = Literal["cli", "github", "api"]
BundleFileKind = Literal[
    "source",
    "test",
    "dependency_lock",
    "iac",
    "config",
    "doc",
    "other",
]
BundleStatus = Literal["ready", "superseded", "deleted"]


class ApplicationReviewBundleManifestItem(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    file_kind: BundleFileKind = "other"
    sha256: str = Field(min_length=64, max_length=64)
    byte_size: int = Field(ge=0)
    source: BundleSource = "api"

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str) -> str:
        candidate = value.strip().lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("sha256 must be a 64-character hex digest")
        return candidate


class ApplicationReviewBundleCreate(BaseModel):
    bundle_kind: BundleKind
    source: BundleSource = "api"
    manifest: list[ApplicationReviewBundleManifestItem] = Field(min_length=1, max_length=5000)
    redaction_report: dict = Field(default_factory=dict)
    retention_expires_at: datetime | None = None
    legal_hold: bool = False


class ApplicationReviewBundleResponse(BaseModel):
    id: UUID
    tenant_key: str
    review_id: UUID
    owner_id: UUID
    organization_id: UUID | None = None
    bundle_kind: BundleKind
    source: BundleSource
    status: BundleStatus
    manifest: list[dict]
    redaction_report: dict = Field(default_factory=dict)
    integrity: dict = Field(default_factory=dict)
    storage_backend: str = "database_manifest"
    encryption_status: str = "metadata_only"
    content_hash: str
    byte_size: int
    file_count: int
    retention_expires_at: datetime | None = None
    legal_hold: bool = False
    created_at: datetime
    updated_at: datetime
