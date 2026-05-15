"""Manifest-only bundles attached to application security reviews."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ApplicationReviewBundle(Base):
    __tablename__ = "application_review_bundles"
    __table_args__ = (
        CheckConstraint(
            "bundle_kind IN ('diff','snapshot','metadata','existing_evidence')",
            name="ck_application_review_bundles_kind",
        ),
        CheckConstraint(
            "source IN ('cli','github','api')",
            name="ck_application_review_bundles_source",
        ),
        CheckConstraint(
            "status IN ('ready','superseded','deleted')",
            name="ck_application_review_bundles_status",
        ),
        Index("ix_application_review_bundles_tenant_review", "tenant_key", "review_id"),
        Index(
            "ix_application_review_bundles_one_ready",
            "tenant_key",
            "review_id",
            unique=True,
            postgresql_where=text("status = 'ready'"),
        ),
        Index(
            "ix_application_review_bundles_content_hash",
            "tenant_key",
            "review_id",
            "content_hash",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("application_security_reviews.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    bundle_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ready", nullable=False)
    manifest: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    redaction_report: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    integrity: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    storage_backend: Mapped[str] = mapped_column(String(40), default="database_manifest", nullable=False)
    encryption_status: Mapped[str] = mapped_column(String(40), default="metadata_only", nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False)
    retention_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    review = relationship("ApplicationSecurityReview", back_populates="bundles")
    owner = relationship("User", lazy="selectin")
    organization = relationship("Organization", lazy="selectin")
