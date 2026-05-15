import uuid
from datetime import date, datetime

from typing import Optional

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ThreatModel(Base):
    __tablename__ = "threat_models"
    __table_args__ = (
        CheckConstraint(
            "data_classification IN ('Public', 'Internal', 'Confidential', 'Restricted')",
            name="ck_threat_models_data_classification",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    system_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    data_classification: Mapped[str] = mapped_column(String(50), nullable=False)
    regulatory_scope: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(String(50)), nullable=True, default=list,
        comment="Selected regulatory frameworks: OSFI B-13, PCI DSS, PIPEDA, FINTRAC, NIST, ISO 27001",
    )
    deployment_model: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True,
        comment="Deployment model: on-prem, cloud, hybrid",
    )
    repository_evidence: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Optional parsed repository/codebase evidence attached to this threat model.",
    )
    cloud_scan_evidence: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Optional parsed Prowler/ScoutSuite evidence attached to this threat model.",
    )
    iac_evidence: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Optional parsed Terraform / CloudFormation / Kubernetes IaC evidence attached to this threat model.",
    )
    environment_context_summary: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None,
        comment="Combined machine-extracted environment evidence summary injected into analysis prompts.",
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=True,
        index=True,
        comment="Tenant workspace that owns this threat model. Backfilled from the owner for pre-SaaS rows.",
    )
    last_analyzed_threats: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Snapshot of GeneratedThreat dicts from last /analyze run for diff",
    )
    last_analyze_requested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None,
        comment="Cross-worker throttle marker for the /analyze endpoint.",
    )
    report_logo_base64: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None,
        comment="Base64-encoded logo image for PDF report header.",
    )
    report_watermark_text: Mapped[Optional[str]] = mapped_column(
        String(200), nullable=True, default=None,
        comment="Watermark text for PDF report (e.g. CONFIDENTIAL, DRAFT).",
    )
    report_template: Mapped[str] = mapped_column(
        String(50), nullable=False, default="default", server_default="default",
        comment="Selected report template identifier (built-in or custom).",
    )
    report_templates: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Custom structured report templates defined for this threat model.",
    )
    arch_diagrams: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="List of {name, image_base64} architectural diagrams embedded in PDF report.",
    )
    dfd_views: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="List of linked DFD view configs and per-view layout snapshots.",
    )
    dfd_component_templates: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Custom DFD component templates/stencils defined for this threat model.",
    )
    dfd_property_options: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Custom dropdown aliases for DFD node metadata fields defined per threat model.",
    )
    assumptions: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Structured assumption register tied to DFD nodes, edges, and trust boundaries.",
    )
    model_snapshots: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Named point-in-time snapshots of the DFD + threats used for review and diff.",
    )
    review_records: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Review workflow state, comments, assignees, and sign-off history for saved snapshots.",
    )
    review_state: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Lightweight persisted workbench review state keyed to computed source objects.",
    )
    control_library: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Reusable mitigation / control entries mapped to threats for this model.",
    )
    collaborators: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Threat-model collaborator roster with per-model role assignments.",
    )
    assignments: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Shared analyst action items linked to reviews, threats, and DFD anchors.",
    )
    notifications: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Per-model activity feed for reviews, assignments, and governance events.",
    )
    # Analyst attestation and review scheduling fields (migration 045)
    analyst_name: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, default=None,
        comment="Name of the analyst who produced this threat model.",
    )
    analyst_attestation: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None,
        comment="Analyst sign-off statement affirming accuracy and completeness of the threat model.",
    )
    next_review_date: Mapped[Optional[date]] = mapped_column(
        Date, nullable=True, default=None,
        comment="Scheduled date for the next formal review of this threat model.",
    )
    out_of_scope_statement: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None,
        comment="Explicit statement of what is excluded from this threat model's scope.",
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    owner = relationship("User", lazy="selectin")
    organization = relationship("Organization", lazy="selectin")
    documents = relationship("Document", back_populates="threat_model", cascade="all, delete-orphan")
    nodes = relationship("DFDNode", back_populates="threat_model", cascade="all, delete-orphan")
    edges = relationship("DFDEdge", back_populates="threat_model", cascade="all, delete-orphan")
    trust_boundaries = relationship("TrustBoundary", back_populates="threat_model", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="threat_model", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", cascade="all, delete-orphan")
    validation_schedules = relationship("ValidationSchedule", back_populates="threat_model", cascade="all, delete-orphan")
    validation_case_states = relationship("ValidationCaseState", back_populates="threat_model", cascade="all, delete-orphan")
