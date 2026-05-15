import uuid
from datetime import date, datetime
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Threat(Base):
    __tablename__ = "threats"
    __table_args__ = (
        CheckConstraint(
            "stride_category IN ('Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege')",
            name="ck_threats_stride_category",
        ),
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_threats_severity",
        ),
        CheckConstraint(
            "source IN ('Rules', 'AI', 'AI+Rules', 'Manual')",
            name="ck_threats_source",
        ),
        CheckConstraint(
            "status IN ('Open', 'In Progress', 'Mitigated', 'Accepted', 'Dismissed')",
            name="ck_threats_status",
        ),
        CheckConstraint(
            "control_effectiveness IN ('none', 'partial', 'substantial', 'full')",
            name="ck_threats_control_effectiveness",
        ),
        CheckConstraint(
            "residual_risk_level IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')",
            name="ck_threats_residual_risk_level",
        ),
        CheckConstraint(
            "qualification_score IS NULL OR (qualification_score >= 0 AND qualification_score <= 100)",
            name="ck_threats_qualification_score_range",
        ),
        CheckConstraint(
            "auto_score IS NULL OR (auto_score >= 0 AND auto_score <= 100)",
            name="ck_threats_auto_score_range",
        ),
        CheckConstraint(
            "analyst_score IS NULL OR (analyst_score >= 0 AND analyst_score <= 100)",
            name="ck_threats_analyst_score_range",
        ),
        CheckConstraint(
            "ai_likelihood_score IS NULL OR (ai_likelihood_score >= 0 AND ai_likelihood_score <= 100)",
            name="ck_threats_ai_likelihood_score_range",
        ),
        CheckConstraint(
            "false_positive_reason IS NULL OR false_positive_reason IN ("
            "'compensating_control', 'not_applicable', 'duplicate', "
            "'architecture_mismatch', 'accepted_risk', 'other')",
            name="ck_threats_false_positive_reason",
        ),
        Index("ix_threats_threat_model_id", "threat_model_id"),
        Index("ix_threats_model_status", "threat_model_id", "status"),
        Index("ix_threats_model_display_id", "threat_model_id", "display_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False)
    display_id: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    stride_category: Mapped[str] = mapped_column(String(30), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="Open")
    dismiss_reason: Mapped[Optional[str]] = mapped_column(Text)
    threat_subtype: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(50))
    ai_enhanced: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_managed: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    original_rule_threat_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("threats.id"))
    affected_node_ids: Mapped[list] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    affected_edge_ids: Mapped[list] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    relevance_rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitigation_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitigation_owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    mitigation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    control_effectiveness: Mapped[str] = mapped_column(
        String(20), nullable=False, default="none", server_default="none"
    )
    residual_risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    qualification_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    qualification_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Qualification workflow fields (v2)
    auto_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    analyst_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    analyst_score_rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_likelihood_assessment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_likelihood_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ai_likelihood_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cluster_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_clusters.id", ondelete="SET NULL"), nullable=True
    )
    false_positive_reason: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    qualification_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    citations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]", default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    threat_model = relationship("ThreatModel", back_populates="threats")
    scan_results = relationship("ScanThreatResult", back_populates="threat", cascade="all, delete-orphan")
    cluster = relationship("ThreatCluster", back_populates="threats", foreign_keys=[cluster_id])


class ThreatCluster(Base):
    __tablename__ = "threat_clusters"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False
    )
    cluster_label: Mapped[str] = mapped_column(String(200), nullable=False)
    cluster_reason: Mapped[str] = mapped_column(String(50), nullable=False)
    representative_threat_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )
    threat_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    threats = relationship("Threat", back_populates="cluster", foreign_keys="Threat.cluster_id")
