"""Canonical evidence graph models.

These tables are a projection layer over existing ThreatGenix sources such as
DFDs, documents, environment evidence, scan jobs, and threats. Native product
tables remain the source of truth; this layer makes provenance, freshness, and
relationships queryable.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


CONFIDENCE_LABELS = (
    "'validated','strongly_indicated','contextual','theoretical','unknown','suppressed'"
)
FRESHNESS_STATUSES = "'fresh','aging','stale','expired','unknown'"


class EvidenceSource(Base):
    __tablename__ = "evidence_sources"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_evidence_sources_id_model",
        ),
        UniqueConstraint(
            "threat_model_id",
            "stable_key",
            name="uq_evidence_sources_model_stable_key",
        ),
        CheckConstraint(
            "source_type IN ("
            "'threat_model','dfd','document','repository','cloud_scan','iac',"
            "'scan','threat_register','coverage','review','manual'"
            ")",
            name="ck_evidence_sources_type",
        ),
        CheckConstraint(
            "ingestion_mode IN ('projection','upload','import','execution','manual','seed')",
            name="ck_evidence_sources_ingestion_mode",
        ),
        CheckConstraint(
            "trust_level IN ('verified','indicated','modeled','inferred','untrusted')",
            name="ck_evidence_sources_trust_level",
        ),
        CheckConstraint(
            "status IN ('active','stale','expired','deleted','error')",
            name="ck_evidence_sources_status",
        ),
        Index(
            "ix_evidence_sources_threat_model_type", "threat_model_id", "source_type"
        ),
        Index("ix_evidence_sources_threat_model_status", "threat_model_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    stable_key: Mapped[str] = mapped_column(String(500), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_name: Mapped[str] = mapped_column(String(300), nullable=False)
    provider: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    transport: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    uri: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_fingerprint_sha256: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    ingestion_mode: Mapped[str] = mapped_column(
        String(30), default="projection", nullable=False
    )
    trust_level: Mapped[str] = mapped_column(
        String(30), default="modeled", nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    collected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    parser_version: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    source_metadata: Mapped[dict] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    items = relationship(
        "EvidenceItem", back_populates="source", cascade="all, delete-orphan"
    )


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_evidence_items_id_model",
        ),
        UniqueConstraint(
            "threat_model_id",
            "stable_key",
            name="uq_evidence_items_model_stable_key",
        ),
        CheckConstraint(
            f"confidence_label IN ({CONFIDENCE_LABELS})",
            name="ck_evidence_items_confidence_label",
        ),
        CheckConstraint(
            f"freshness_status IN ({FRESHNESS_STATUSES})",
            name="ck_evidence_items_freshness_status",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_evidence_items_confidence_score",
        ),
        Index("ix_evidence_items_source_id", "source_id"),
        Index("ix_evidence_items_threat_model_type", "threat_model_id", "item_type"),
        Index(
            "ix_evidence_items_threat_model_freshness",
            "threat_model_id",
            "freshness_status",
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
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    stable_key: Mapped[str] = mapped_column(String(600), nullable=False)
    item_type: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_ref: Mapped[Optional[str]] = mapped_column(String(600), nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    content_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    confidence_label: Mapped[str] = mapped_column(
        String(30), default="contextual", nullable=False
    )
    freshness_status: Mapped[str] = mapped_column(
        String(20), default="unknown", nullable=False
    )
    observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    effective_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    source = relationship("EvidenceSource", back_populates="items")


class EvidenceEntity(Base):
    __tablename__ = "evidence_entities"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_evidence_entities_id_model",
        ),
        UniqueConstraint(
            "threat_model_id",
            "canonical_key",
            name="uq_evidence_entities_model_canonical_key",
        ),
        CheckConstraint(
            "status IN ('active','tombstoned')",
            name="ck_evidence_entities_status",
        ),
        Index(
            "ix_evidence_entities_threat_model_type", "threat_model_id", "entity_type"
        ),
        Index(
            "ix_evidence_entities_source_object",
            "source_object_type",
            "source_object_id",
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
    entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(700), nullable=False)
    display_name: Mapped[str] = mapped_column(String(500), nullable=False)
    source_object_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    source_object_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EvidenceObservation(Base):
    __tablename__ = "evidence_observations"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_evidence_observations_id_model",
        ),
        CheckConstraint(
            f"confidence_label IN ({CONFIDENCE_LABELS})",
            name="ck_evidence_observations_confidence_label",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_evidence_observations_confidence_score",
        ),
        Index("ix_evidence_observations_item_id", "evidence_item_id"),
        Index("ix_evidence_observations_subject", "subject_entity_id"),
        Index(
            "ix_evidence_observations_threat_model_predicate",
            "threat_model_id",
            "predicate",
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
    evidence_item_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    predicate: Mapped[str] = mapped_column(String(120), nullable=False)
    object_entity_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    value_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    value_json: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    confidence_label: Mapped[str] = mapped_column(
        String(30), default="contextual", nullable=False
    )
    observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class EvidenceRelationship(Base):
    __tablename__ = "evidence_relationships"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_evidence_relationships_id_model",
        ),
        UniqueConstraint(
            "threat_model_id",
            "stable_key",
            name="uq_evidence_relationships_model_stable_key",
        ),
        CheckConstraint(
            f"confidence_label IN ({CONFIDENCE_LABELS})",
            name="ck_evidence_relationships_confidence_label",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_evidence_relationships_confidence_score",
        ),
        Index("ix_evidence_relationships_from", "from_entity_id"),
        Index("ix_evidence_relationships_to", "to_entity_id"),
        Index(
            "ix_evidence_relationships_threat_model_type",
            "threat_model_id",
            "relationship_type",
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
    stable_key: Mapped[str] = mapped_column(String(800), nullable=False)
    from_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    to_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_item_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    confidence_label: Mapped[str] = mapped_column(
        String(30), default="contextual", nullable=False
    )
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class EvidenceFinding(Base):
    __tablename__ = "evidence_findings"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "threat_model_id",
            name="uq_evidence_findings_id_model",
        ),
        UniqueConstraint(
            "threat_model_id",
            "finding_key",
            name="uq_evidence_findings_model_finding_key",
        ),
        CheckConstraint(
            "severity IN ('Critical','High','Medium','Low','Info','Unknown')",
            name="ck_evidence_findings_severity",
        ),
        CheckConstraint(
            "status IN ('open','in_progress','mitigated','accepted','dismissed','refuted','informational')",
            name="ck_evidence_findings_status",
        ),
        CheckConstraint(
            f"confidence_label IN ({CONFIDENCE_LABELS})",
            name="ck_evidence_findings_confidence_label",
        ),
        CheckConstraint(
            f"freshness_status IN ({FRESHNESS_STATUSES})",
            name="ck_evidence_findings_freshness_status",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_evidence_findings_confidence_score",
        ),
        Index("ix_evidence_findings_source_id", "source_id"),
        Index(
            "ix_evidence_findings_threat_model_kind", "threat_model_id", "finding_kind"
        ),
        Index("ix_evidence_findings_threat_model_status", "threat_model_id", "status"),
        Index(
            "ix_evidence_findings_source_object",
            "source_object_type",
            "source_object_id",
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
    finding_key: Mapped[str] = mapped_column(String(700), nullable=False)
    finding_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="Unknown", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    source_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_sources.id", ondelete="SET NULL"),
        nullable=True,
    )
    primary_evidence_item_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    confidence_label: Mapped[str] = mapped_column(
        String(30), default="contextual", nullable=False
    )
    freshness_status: Mapped[str] = mapped_column(
        String(20), default="unknown", nullable=False
    )
    source_system: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_object_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    source_object_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finding_metadata: Mapped[dict] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EvidenceFindingLink(Base):
    __tablename__ = "evidence_finding_links"
    __table_args__ = (
        CheckConstraint(
            "link_type IN ('supports','refutes','affects','observed_on','derived_from','needs_evidence')",
            name="ck_evidence_finding_links_type",
        ),
        CheckConstraint(
            f"confidence_label IN ({CONFIDENCE_LABELS})",
            name="ck_evidence_finding_links_confidence_label",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_evidence_finding_links_confidence_score",
        ),
        Index("ix_evidence_finding_links_finding_id", "finding_id"),
        Index("ix_evidence_finding_links_evidence_item_id", "evidence_item_id"),
        Index("ix_evidence_finding_links_entity_id", "entity_id"),
        Index("ix_evidence_finding_links_threat_model", "threat_model_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_item_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True,
    )
    observation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_observations.id", ondelete="SET NULL"),
        nullable=True,
    )
    entity_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    link_type: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    confidence_label: Mapped[str] = mapped_column(
        String(30), default="contextual", nullable=False
    )
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
