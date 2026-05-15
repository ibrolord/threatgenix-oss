"""Risk acceptance lifecycle for application security reviews."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ApplicationRiskAcceptance(Base):
    __tablename__ = "application_risk_acceptances"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('rule','finding','route','app')",
            name="ck_application_risk_acceptances_scope_type",
        ),
        CheckConstraint(
            "status IN ('active','expired','revoked')",
            name="ck_application_risk_acceptances_status",
        ),
        Index("ix_application_risk_acceptances_tenant_review", "tenant_key", "review_id"),
        Index("ix_application_risk_acceptances_scope", "tenant_key", "scope_type", "scope_value"),
        Index("ix_application_risk_acceptances_expiry", "status", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    app_name: Mapped[str] = mapped_column(String(255), nullable=False)
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("application_security_reviews.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_stable_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    scope_value: Mapped[str] = mapped_column(String(500), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_control: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approver_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    audit_events: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
