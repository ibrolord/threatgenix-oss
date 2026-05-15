import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# Default TTL for uploaded documents (24 hours)
DOCUMENT_TTL_HOURS = 24


def _default_expires_at() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=DOCUMENT_TTL_HOURS)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    page_count: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_text: Mapped[Optional[str]] = mapped_column(Text)
    parsed_components: Mapped[Optional[dict]] = mapped_column(JSONB)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    parsed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), default=_default_expires_at,
        comment="When raw_text will be purged. NULL = no expiry (sanitized/demo docs).",
    )
    purged: Mapped[bool] = mapped_column(Boolean, default=False, comment="True after raw_text has been purged at expiry.")

    threat_model = relationship("ThreatModel", back_populates="documents")
