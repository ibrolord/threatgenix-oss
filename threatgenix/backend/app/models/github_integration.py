"""GitHub App repository links for PR-triggered reviews."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class GitHubRepositoryLink(Base):
    __tablename__ = "github_repository_links"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active','suspended','uninstalled')",
            name="ck_github_repository_links_status",
        ),
        UniqueConstraint(
            "installation_id",
            "repository_id",
            name="uq_github_repository_links_installation_repo",
        ),
        Index("ix_github_repository_links_tenant", "tenant_key"),
        Index("ix_github_repository_links_owner", "owner_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    threat_model_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="SET NULL"), nullable=True
    )
    installation_id: Mapped[str] = mapped_column(String(80), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(80), nullable=False)
    repository_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    private: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requested_tools: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class GitHubReviewDispatch(Base):
    __tablename__ = "github_review_dispatches"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','dispatching','dispatched','retryable_failed','terminal_failed')",
            name="ck_github_review_dispatches_status",
        ),
        CheckConstraint(
            "status_state IS NULL OR status_state IN ('success','failure','pending','error')",
            name="ck_github_review_dispatches_status_state",
        ),
        UniqueConstraint(
            "tenant_key",
            "review_id",
            "repository_id",
            "pull_request_number",
            "head_sha",
            "status_context",
            name="uq_github_review_dispatches_review_sha_context",
        ),
        Index("ix_github_review_dispatches_status", "status", "queued_at"),
        Index("ix_github_review_dispatches_review", "review_id"),
        Index("ix_github_review_dispatches_tenant", "tenant_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("application_security_reviews.id", ondelete="CASCADE"), nullable=False
    )
    installation_id: Mapped[str] = mapped_column(String(80), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(80), nullable=False)
    repository_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(80), nullable=False)
    status_context: Mapped[str] = mapped_column(String(120), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False)
    review_decision: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    comment_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status_state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    target_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    dispatched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
