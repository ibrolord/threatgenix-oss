"""Application security review objects for invoke-anywhere reviews."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.schemas.application_review import REVIEW_LIFECYCLE_STATUSES


REVIEW_STATUS_SQL = ",".join(f"'{status}'" for status in REVIEW_LIFECYCLE_STATUSES)


class ApplicationSecurityReview(Base):
    __tablename__ = "application_security_reviews"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({REVIEW_STATUS_SQL})",
            name="ck_application_security_reviews_status",
        ),
        CheckConstraint(
            "decision IS NULL OR decision IN ('pass','block','fix','verify','gather_evidence')",
            name="ck_application_security_reviews_decision",
        ),
        CheckConstraint(
            "invocation_surface IN ('cli','mcp','api','pr','web')",
            name="ck_application_security_reviews_invocation_surface",
        ),
        CheckConstraint(
            "input_kind IN ('diff','snapshot','metadata')",
            name="ck_application_security_reviews_input_kind",
        ),
        Index("ix_application_security_reviews_tenant_created", "tenant_key", "created_at"),
        Index("ix_application_security_reviews_threat_model_created", "threat_model_id", "created_at"),
        Index("ix_application_security_reviews_lineage", "review_lineage_id", "created_at"),
        Index(
            "ix_application_security_reviews_idempotency",
            "tenant_key",
            "idempotency_key",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    threat_model_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="SET NULL"), nullable=True, index=True
    )
    parent_review_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("application_security_reviews.id", ondelete="SET NULL"),
        nullable=True,
    )
    review_lineage_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    app_name: Mapped[str] = mapped_column(String(255), nullable=False)
    invocation_surface: Mapped[str] = mapped_column(String(40), nullable=False)
    input_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False)
    decision: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    commit_sha: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    bundle_hash: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    scope_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    requested_tools: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    scope: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    context: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    policy: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    owner = relationship("User", lazy="selectin")
    organization = relationship("Organization", lazy="selectin")
    threat_model = relationship("ThreatModel", lazy="selectin")
    parent_review = relationship(
        "ApplicationSecurityReview",
        remote_side=[id],
        lazy="selectin",
    )
    bundles = relationship(
        "ApplicationReviewBundle",
        back_populates="review",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
