"""Schemas for the canonical evidence graph projection."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


EvidenceConfidenceLabel = Literal[
    "validated",
    "strongly_indicated",
    "contextual",
    "theoretical",
    "unknown",
    "suppressed",
]
EvidenceFreshnessStatus = Literal["fresh", "aging", "stale", "expired", "unknown"]


class EvidenceSourceResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    owner_id: UUID | None = None
    stable_key: str
    source_type: str
    source_name: str
    provider: str | None = None
    transport: str | None = None
    reference: str | None = None
    uri: str | None = None
    source_fingerprint_sha256: str | None = None
    ingestion_mode: str
    trust_level: str
    status: str
    imported_at: datetime
    collected_at: datetime | None = None
    last_synced_at: datetime | None = None
    expires_at: datetime | None = None
    parser_version: str | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EvidenceItemResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    source_id: UUID
    stable_key: str
    item_type: str
    title: str
    summary: str | None = None
    raw_ref: str | None = None
    raw_payload: dict = Field(default_factory=dict)
    content_sha256: str | None = None
    confidence_score: float
    confidence_label: EvidenceConfidenceLabel
    freshness_status: EvidenceFreshnessStatus
    observed_at: datetime | None = None
    effective_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class EvidenceEntityResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    entity_type: str
    canonical_key: str
    display_name: str
    source_object_type: str | None = None
    source_object_id: str | None = None
    properties: dict = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    status: str
    created_at: datetime
    updated_at: datetime


class EvidenceRelationshipResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    stable_key: str
    from_entity_id: UUID
    to_entity_id: UUID
    relationship_type: str
    evidence_item_id: UUID | None = None
    confidence_score: float
    confidence_label: EvidenceConfidenceLabel
    rationale: str | None = None
    properties: dict = Field(default_factory=dict)
    created_at: datetime


class EvidenceObservationResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    evidence_item_id: UUID
    subject_entity_id: UUID
    predicate: str
    object_entity_id: UUID | None = None
    value_text: str | None = None
    value_json: dict = Field(default_factory=dict)
    severity: str | None = None
    confidence_score: float
    confidence_label: EvidenceConfidenceLabel
    observed_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime


class EvidenceFindingResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    finding_key: str
    finding_kind: str
    title: str
    description: str
    severity: str
    status: str
    source_id: UUID | None = None
    primary_evidence_item_id: UUID | None = None
    confidence_score: float
    confidence_label: EvidenceConfidenceLabel
    freshness_status: EvidenceFreshnessStatus
    source_system: str | None = None
    source_object_type: str | None = None
    source_object_id: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EvidenceFindingLinkResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    finding_id: UUID
    evidence_item_id: UUID | None = None
    observation_id: UUID | None = None
    entity_id: UUID | None = None
    link_type: str
    confidence_score: float
    confidence_label: EvidenceConfidenceLabel
    rationale: str | None = None
    created_at: datetime


class EvidenceCountBucket(BaseModel):
    key: str
    count: int


class EvidenceCoverageGap(BaseModel):
    gap_type: str
    severity: Literal["blocking", "warning", "info"]
    title: str
    detail: str
    remediation: str


class EvidenceStatusResponse(BaseModel):
    threat_model_id: UUID
    projection_status: Literal["not_built", "current", "stale", "error"]
    generated_at: datetime
    source_count: int
    item_count: int
    entity_count: int
    relationship_count: int
    observation_count: int
    finding_count: int
    sources_by_type: list[EvidenceCountBucket] = Field(default_factory=list)
    items_by_type: list[EvidenceCountBucket] = Field(default_factory=list)
    entities_by_type: list[EvidenceCountBucket] = Field(default_factory=list)
    findings_by_kind: list[EvidenceCountBucket] = Field(default_factory=list)
    freshness: list[EvidenceCountBucket] = Field(default_factory=list)
    coverage_gaps: list[EvidenceCoverageGap] = Field(default_factory=list)


class EvidenceCoverageResponse(BaseModel):
    status: EvidenceStatusResponse
    relationship_types: list[EvidenceCountBucket] = Field(default_factory=list)
    finding_link_types: list[EvidenceCountBucket] = Field(default_factory=list)
    unlinked_finding_count: int = 0
    validated_finding_count: int = 0
    contextual_finding_count: int = 0
    stale_or_expired_item_count: int = 0


class EvidenceGraphResponse(BaseModel):
    status: EvidenceStatusResponse
    sources: list[EvidenceSourceResponse] = Field(default_factory=list)
    items: list[EvidenceItemResponse] = Field(default_factory=list)
    entities: list[EvidenceEntityResponse] = Field(default_factory=list)
    relationships: list[EvidenceRelationshipResponse] = Field(default_factory=list)
    observations: list[EvidenceObservationResponse] = Field(default_factory=list)
    findings: list[EvidenceFindingResponse] = Field(default_factory=list)
    links: list[EvidenceFindingLinkResponse] = Field(default_factory=list)


class EvidenceEntityNeighborhoodResponse(BaseModel):
    root_entity: EvidenceEntityResponse
    depth: int
    entities: list[EvidenceEntityResponse] = Field(default_factory=list)
    relationships: list[EvidenceRelationshipResponse] = Field(default_factory=list)
    findings: list[EvidenceFindingResponse] = Field(default_factory=list)
    links: list[EvidenceFindingLinkResponse] = Field(default_factory=list)


class EvidenceChainResponse(BaseModel):
    finding: EvidenceFindingResponse
    source: EvidenceSourceResponse | None = None
    primary_item: EvidenceItemResponse | None = None
    evidence_items: list[EvidenceItemResponse] = Field(default_factory=list)
    observations: list[EvidenceObservationResponse] = Field(default_factory=list)
    entities: list[EvidenceEntityResponse] = Field(default_factory=list)
    links: list[EvidenceFindingLinkResponse] = Field(default_factory=list)
