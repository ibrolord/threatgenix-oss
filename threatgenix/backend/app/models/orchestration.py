"""Durable orchestration primitives for agent and tool work."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class OrchestrationJob(Base):
    __tablename__ = "orchestration_jobs"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_orchestration_jobs_id_model",
        ),
        CheckConstraint(
            "job_kind IN ('evidence_rebuild','validation_run','security_audit','environment_audit','custom')",
            name="ck_orchestration_jobs_kind",
        ),
        CheckConstraint(
            "status IN ('pending','running','completed','failed','cancelled','blocked')",
            name="ck_orchestration_jobs_status",
        ),
        Index("ix_orchestration_jobs_threat_model_status", "threat_model_id", "status"),
        Index("ix_orchestration_jobs_owner_created", "owner_id", "created_at"),
        Index(
            "ix_orchestration_jobs_idempotency",
            "threat_model_id",
            "owner_id",
            "idempotency_key",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    job_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    requested_tools: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    inputs: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    policy: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    tasks = relationship(
        "OrchestrationTask",
        back_populates="job",
        cascade="all, delete-orphan",
    )
    events = relationship(
        "OrchestrationEvent",
        back_populates="job",
        cascade="all, delete-orphan",
    )


class OrchestrationTask(Base):
    __tablename__ = "orchestration_tasks"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_orchestration_tasks_id_model",
        ),
        CheckConstraint(
            "task_kind IN ('agent_reasoning','tool_execution','evidence_projection','human_review')",
            name="ck_orchestration_tasks_kind",
        ),
        CheckConstraint(
            "status IN ('pending','running','completed','failed','cancelled','blocked')",
            name="ck_orchestration_tasks_status",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts >= 1 AND attempt_count <= max_attempts",
            name="ck_orchestration_tasks_attempt_bounds",
        ),
        Index("ix_orchestration_tasks_job_status", "job_id", "status"),
        Index(
            "ix_orchestration_tasks_threat_model_status", "threat_model_id", "status"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("orchestration_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    task_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    agent_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    tool_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    input_payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    output_payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    job = relationship("OrchestrationJob", back_populates="tasks")
    events = relationship(
        "OrchestrationEvent",
        back_populates="task",
        cascade="all, delete-orphan",
    )


class OrchestrationEvent(Base):
    __tablename__ = "orchestration_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('created','queued','started','tool_called','evidence_added','completed','failed','cancelled','blocked','note')",
            name="ck_orchestration_events_type",
        ),
        CheckConstraint(
            "level IN ('debug','info','warning','error')",
            name="ck_orchestration_events_level",
        ),
        Index("ix_orchestration_events_job_created", "job_id", "created_at"),
        Index(
            "ix_orchestration_events_threat_model_created",
            "threat_model_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("orchestration_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    task_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("orchestration_tasks.id", ondelete="SET NULL"),
        nullable=True,
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    job = relationship("OrchestrationJob", back_populates="events")
    task = relationship("OrchestrationTask", back_populates="events")
