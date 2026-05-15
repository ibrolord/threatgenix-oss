"""Threat audit trail model (F-15: Threat History / Audit)."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ThreatAuditLog(Base):
    __tablename__ = "threat_audit_logs"
    __table_args__ = (
        Index("ix_threat_audit_logs_threat_created", "threat_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(30), nullable=False)  # "created", "triaged", "status_changed"
    old_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # null for "created"
    new_status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", lazy="joined")
