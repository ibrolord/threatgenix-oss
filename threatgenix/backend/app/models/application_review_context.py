"""Tenant-scoped retrieval index for application security reviews."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ApplicationReviewContextEntry(Base):
    __tablename__ = "application_review_context_entries"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('review','bundle','scan_finding','policy','manual',"
            "'document','code_summary','evidence_item','evidence_entity',"
            "'evidence_relationship','evidence_finding','threat','decision',"
            "'organization','code_context')",
            name="ck_application_review_context_entries_source_type",
        ),
        CheckConstraint(
            "item_type IN ('app_profile','org_profile','review_scope','bundle_file',"
            "'scanner_finding','policy','control','accepted_risk','note','doc',"
            "'code_summary','evidence_item','evidence_entity','evidence_relationship',"
            "'evidence_finding','prior_review_decision','code_context')",
            name="ck_application_review_context_entries_item_type",
        ),
        CheckConstraint(
            "status IN ('active','stale','deleted')",
            name="ck_application_review_context_entries_status",
        ),
        Index(
            "ix_application_review_context_tenant_review",
            "tenant_key",
            "review_id",
            "status",
        ),
        Index(
            "ix_application_review_context_source_object",
            "source_type",
            "source_object_id",
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
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_object_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    item_type: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    keywords: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    facets: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    retrieval_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source_refs: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    stale_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
