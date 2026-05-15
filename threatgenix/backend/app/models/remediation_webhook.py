from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RemediationWebhookNonce(Base):
    __tablename__ = "remediation_webhook_nonces"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scope: Mapped[str] = mapped_column(String(length=120), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(length=64), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(length=40), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "scope",
            "nonce_hash",
            name="uq_remediation_webhook_nonces_scope_nonce_hash",
        ),
        Index("ix_remediation_webhook_nonces_expires_at", "expires_at"),
    )
