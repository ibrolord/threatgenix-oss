"""Threat intelligence database models.

Stores structured data from 6 sources:
- MITRE ATT&CK (techniques, tactics, groups)
- CAPEC (attack patterns)
- CWE (software weaknesses)
- CRI Profile (financial sector → ATT&CK mappings)
- CISA KEV (known exploited vulnerabilities)
- CCCS advisories (Canadian cyber threat context)

Two table categories:
1. Lookup tables (deterministic): CRI mappings, KEV entries
2. RAG tables (semantic search): ATT&CK, CAPEC, CWE, CCCS → embedded in pgvector
"""

from datetime import datetime
from typing import Optional

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


# ─── ATT&CK Techniques (RAG source) ─────────────────────────────────


class AttackTechnique(Base):
    """MITRE ATT&CK Enterprise technique or sub-technique."""

    __tablename__ = "attack_techniques"
    __table_args__ = (
        UniqueConstraint("technique_id"),
        Index("ix_attack_techniques_tactic", "tactic"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., "T1657"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    tactic: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., "impact"
    is_subtechnique: Mapped[bool] = mapped_column(default=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String(20))  # Parent technique ID
    platforms: Mapped[Optional[list]] = mapped_column(ARRAY(String(50)), default=list)
    mitigations: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)  # {mitigation_id: name}
    url: Mapped[Optional[str]] = mapped_column(String(500))
    stix_id: Mapped[Optional[str]] = mapped_column(String(100))  # STIX 2.1 object ID
    version: Mapped[str] = mapped_column(String(20), default="0")  # ATT&CK version
    embedding: Mapped[Optional[list]] = mapped_column(Vector(1024))  # Titan Embeddings v2
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── CAPEC Attack Patterns (RAG source) ─────────────────────────────


class AttackPattern(Base):
    """CAPEC attack pattern."""

    __tablename__ = "attack_patterns"
    __table_args__ = (
        UniqueConstraint("capec_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capec_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., "CAPEC-151"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    likelihood: Mapped[Optional[str]] = mapped_column(String(20))  # High, Medium, Low
    severity: Mapped[Optional[str]] = mapped_column(String(20))
    prerequisites: Mapped[Optional[str]] = mapped_column(Text)
    related_cwe_ids: Mapped[Optional[list]] = mapped_column(ARRAY(String(20)), default=list)
    related_attack_ids: Mapped[Optional[list]] = mapped_column(ARRAY(String(20)), default=list)
    embedding: Mapped[Optional[list]] = mapped_column(Vector(1024))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── CWE Weaknesses (RAG source) ────────────────────────────────────


class WeaknessEntry(Base):
    """CWE software weakness."""

    __tablename__ = "weakness_entries"
    __table_args__ = (
        UniqueConstraint("cwe_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cwe_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., "CWE-287"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    extended_description: Mapped[Optional[str]] = mapped_column(Text)
    consequences: Mapped[Optional[str]] = mapped_column(Text)
    mitigations: Mapped[Optional[str]] = mapped_column(Text)
    related_capec_ids: Mapped[Optional[list]] = mapped_column(ARRAY(String(20)), default=list)
    is_top_25: Mapped[bool] = mapped_column(default=False)  # CWE Top 25 2025
    embedding: Mapped[Optional[list]] = mapped_column(Vector(1024))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── CRI Profile Mappings (deterministic lookup) ────────────────────


class CRIMapping(Base):
    """CRI Profile v2.1 Diagnostic Statement → ATT&CK technique mapping.

    Deterministic lookup: given an ATT&CK technique, return CRI controls.
    """

    __tablename__ = "cri_mappings"
    __table_args__ = (
        UniqueConstraint("cri_control_id", "attack_technique_id"),
        Index("ix_cri_mappings_attack_id", "attack_technique_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cri_control_id: Mapped[str] = mapped_column(String(30), nullable=False)  # e.g., "RA.02.01"
    cri_control_name: Mapped[str] = mapped_column(String(500), nullable=False)
    cri_function: Mapped[Optional[str]] = mapped_column(String(50))  # e.g., "Identify", "Protect"
    attack_technique_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., "T1657"
    mapping_type: Mapped[Optional[str]] = mapped_column(String(30))  # "mitigates", "detects"
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── CISA KEV (deterministic lookup) ────────────────────────────────


class KEVEntry(Base):
    """CISA Known Exploited Vulnerability catalog entry."""

    __tablename__ = "kev_entries"
    __table_args__ = (
        UniqueConstraint("cve_id"),
        Index("ix_kev_entries_vendor_product", "vendor_project", "product"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False)  # e.g., "CVE-2024-12345"
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_name: Mapped[str] = mapped_column(String(500), nullable=False)
    date_added: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    short_description: Mapped[Optional[str]] = mapped_column(Text)
    required_action: Mapped[Optional[str]] = mapped_column(Text)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    known_ransomware_use: Mapped[Optional[str]] = mapped_column(String(20))  # "Known", "Unknown"
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── CCCS Advisories (RAG source) ───────────────────────────────────


class CCSCAdvisory(Base):
    """Canadian Centre for Cyber Security advisory."""

    __tablename__ = "cccs_advisories"
    __table_args__ = (
        UniqueConstraint("advisory_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    advisory_id: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., "AV25-123"
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    url: Mapped[Optional[str]] = mapped_column(String(500))
    referenced_cves: Mapped[Optional[list]] = mapped_column(ARRAY(String(30)), default=list)
    referenced_attack_ids: Mapped[Optional[list]] = mapped_column(ARRAY(String(20)), default=list)
    severity: Mapped[Optional[str]] = mapped_column(String(20))
    affected_products: Mapped[Optional[list]] = mapped_column(ARRAY(String(255)), default=list)
    embedding: Mapped[Optional[list]] = mapped_column(Vector(1024))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── Threat Intel Sync Metadata ─────────────────────────────────────


class ThreatIntelSync(Base):
    """Tracks last sync time and status for each threat intel source."""

    __tablename__ = "threat_intel_syncs"
    __table_args__ = (
        UniqueConstraint("source_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_name: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., "attack", "capec"
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[Optional[str]] = mapped_column(String(50))  # e.g., ATT&CK "v18.1"
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, syncing, complete, error
    error_message: Mapped[Optional[str]] = mapped_column(Text)
