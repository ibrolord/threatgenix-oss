"""Threat-scoped agent orchestration runs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


AGENT_TYPE_SQL = "'threat_validation','code_fix','iac_fix','configuration_fix'"


class ThreatValidationRun(Base):
    __tablename__ = "threat_validation_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('created','running','completed','failed','blocked')",
            name="ck_threat_validation_runs_status",
        ),
        CheckConstraint(
            "conclusion IS NULL OR conclusion IN "
            "('confirmed','not_supported','needs_human_review','more_evidence_required','failed')",
            name="ck_threat_validation_runs_conclusion",
        ),
        CheckConstraint(
            f"agent_type IN ({AGENT_TYPE_SQL})",
            name="ck_threat_validation_runs_agent_type",
        ),
        Index("ix_threat_validation_runs_threat_created", "threat_id", "created_at"),
        Index("ix_threat_validation_runs_tenant_created", "tenant_key", "created_at"),
        Index("ix_threat_validation_runs_review", "application_review_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False
    )
    application_review_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("application_security_reviews.id", ondelete="SET NULL"), nullable=True
    )
    orchestration_job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orchestration_jobs.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False)
    conclusion: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    requested_tools: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    domain_agent_plan: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    domain_agent_results: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    exploitability: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_type: Mapped[str] = mapped_column(String(40), default="threat_validation", nullable=False)
    agent_version: Mapped[str] = mapped_column(String(80), nullable=False)
    input_schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    output_schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(80), nullable=False)
    tool_harness_versions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    model_provider: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(160), nullable=True)
    prompt_version: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    model_output_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    deterministic_fallback_used: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    threat = relationship("Threat", lazy="selectin")
    application_review = relationship("ApplicationSecurityReview", lazy="selectin")
    orchestration_job = relationship("OrchestrationJob", lazy="selectin")


class ThreatRemediationRun(Base):
    __tablename__ = "threat_remediation_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('drafting','awaiting_confirmation','handoff_created','failed','cancelled')",
            name="ck_threat_remediation_runs_status",
        ),
        CheckConstraint(
            "agent_type IN ('code_fix','iac_fix','configuration_fix')",
            name="ck_threat_remediation_runs_agent_type",
        ),
        Index("ix_threat_remediation_runs_validation_created", "validation_run_id", "created_at"),
        Index("ix_threat_remediation_runs_threat_created", "threat_id", "created_at"),
        Index("ix_threat_remediation_runs_tenant_created", "tenant_key", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_key: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    validation_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_validation_runs.id", ondelete="CASCADE"), nullable=False
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False
    )
    application_review_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("application_security_reviews.id", ondelete="SET NULL"), nullable=True
    )
    orchestration_job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orchestration_jobs.id", ondelete="SET NULL"), nullable=True
    )
    agent_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="drafting", nullable=False)
    fix_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    patch_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ticket_draft: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    pr_draft: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    external_ticket_id: Mapped[Optional[str]] = mapped_column(String(240), nullable=True)
    external_ticket_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_pr_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    handoff_delivery_status: Mapped[str] = mapped_column(String(32), default="recorded", nullable=False)
    handoff_provider: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    handoff_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    handoff_idempotency_key: Mapped[Optional[str]] = mapped_column(String(240), nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_version: Mapped[str] = mapped_column(String(80), nullable=False)
    input_schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    output_schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(80), nullable=False)
    tool_harness_versions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    model_provider: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(160), nullable=True)
    prompt_version: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    model_output_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    deterministic_fallback_used: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    validation_run = relationship("ThreatValidationRun", lazy="selectin")
    threat = relationship("Threat", lazy="selectin")
    orchestration_job = relationship("OrchestrationJob", lazy="selectin")
