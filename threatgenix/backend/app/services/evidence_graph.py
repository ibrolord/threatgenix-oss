"""Query helpers for the canonical evidence graph."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dfd import DFDEdge, DFDNode
from app.models.document import Document
from app.models.evidence import (
    EvidenceEntity,
    EvidenceFinding,
    EvidenceFindingLink,
    EvidenceItem,
    EvidenceObservation,
    EvidenceRelationship,
    EvidenceSource,
)
from app.models.scan import ScanJob, ScanThreatResult
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.schemas.evidence import (
    EvidenceConfidenceLabel,
    EvidenceCoverageResponse,
    EvidenceCountBucket,
    EvidenceCoverageGap,
    EvidenceChainResponse,
    EvidenceEntityNeighborhoodResponse,
    EvidenceEntityResponse,
    EvidenceFreshnessStatus,
    EvidenceFindingLinkResponse,
    EvidenceFindingResponse,
    EvidenceGraphResponse,
    EvidenceItemResponse,
    EvidenceObservationResponse,
    EvidenceRelationshipResponse,
    EvidenceSourceResponse,
    EvidenceStatusResponse,
)
from app.services.evidence_freshness import utc_now


def stable_hash(payload: object) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def confidence_label(score: float) -> EvidenceConfidenceLabel:
    if score >= 80:
        return "validated"
    if score >= 60:
        return "strongly_indicated"
    if score >= 35:
        return "contextual"
    if score > 0:
        return "theoretical"
    return "unknown"


def _coerce_confidence_label(value: str) -> EvidenceConfidenceLabel:
    if value == "validated":
        return "validated"
    if value == "strongly_indicated":
        return "strongly_indicated"
    if value == "contextual":
        return "contextual"
    if value == "theoretical":
        return "theoretical"
    if value == "suppressed":
        return "suppressed"
    return "unknown"


def _coerce_freshness_status(value: str) -> EvidenceFreshnessStatus:
    if value == "fresh":
        return "fresh"
    if value == "aging":
        return "aging"
    if value == "stale":
        return "stale"
    if value == "expired":
        return "expired"
    return "unknown"


def native_key(table_name: str, native_id: object) -> str:
    return f"native:{table_name}:{native_id}"


def json_key(prefix: str, *parts: object) -> str:
    cleaned = [
        str(part).strip().replace(" ", "_") for part in parts if part is not None
    ]
    return ":".join([prefix, *cleaned])


def _bucket_response(rows: Iterable[Any]) -> list[EvidenceCountBucket]:
    return [
        EvidenceCountBucket(key=str(row[0] or "unknown"), count=int(row[1] or 0))
        for row in rows
    ]


async def delete_evidence_graph(db: AsyncSession, threat_model_id: UUID) -> None:
    """Delete the projected graph for one threat model.

    Native source tables are not modified.
    """
    for model in (
        EvidenceFindingLink,
        EvidenceRelationship,
        EvidenceObservation,
        EvidenceFinding,
        EvidenceEntity,
        EvidenceItem,
        EvidenceSource,
    ):
        await db.execute(delete(model).where(model.threat_model_id == threat_model_id))


def serialize_source(source: EvidenceSource) -> EvidenceSourceResponse:
    return EvidenceSourceResponse(
        id=source.id,
        threat_model_id=source.threat_model_id,
        owner_id=source.owner_id,
        stable_key=source.stable_key,
        source_type=source.source_type,
        source_name=source.source_name,
        provider=source.provider,
        transport=source.transport,
        reference=source.reference,
        uri=source.uri,
        source_fingerprint_sha256=source.source_fingerprint_sha256,
        ingestion_mode=source.ingestion_mode,
        trust_level=source.trust_level,
        status=source.status,
        imported_at=source.imported_at,
        collected_at=source.collected_at,
        last_synced_at=source.last_synced_at,
        expires_at=source.expires_at,
        parser_version=source.parser_version,
        metadata=source.source_metadata or {},
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


def serialize_item(item: EvidenceItem) -> EvidenceItemResponse:
    return EvidenceItemResponse(
        id=item.id,
        threat_model_id=item.threat_model_id,
        source_id=item.source_id,
        stable_key=item.stable_key,
        item_type=item.item_type,
        title=item.title,
        summary=item.summary,
        raw_ref=item.raw_ref,
        raw_payload=item.raw_payload or {},
        content_sha256=item.content_sha256,
        confidence_score=item.confidence_score,
        confidence_label=_coerce_confidence_label(item.confidence_label),
        freshness_status=_coerce_freshness_status(item.freshness_status),
        observed_at=item.observed_at,
        effective_at=item.effective_at,
        expires_at=item.expires_at,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def serialize_entity(entity: EvidenceEntity) -> EvidenceEntityResponse:
    return EvidenceEntityResponse(
        id=entity.id,
        threat_model_id=entity.threat_model_id,
        entity_type=entity.entity_type,
        canonical_key=entity.canonical_key,
        display_name=entity.display_name,
        source_object_type=entity.source_object_type,
        source_object_id=entity.source_object_id,
        properties=entity.properties or {},
        first_seen_at=entity.first_seen_at,
        last_seen_at=entity.last_seen_at,
        status=entity.status,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


def serialize_relationship(
    relationship: EvidenceRelationship,
) -> EvidenceRelationshipResponse:
    return EvidenceRelationshipResponse(
        id=relationship.id,
        threat_model_id=relationship.threat_model_id,
        stable_key=relationship.stable_key,
        from_entity_id=relationship.from_entity_id,
        to_entity_id=relationship.to_entity_id,
        relationship_type=relationship.relationship_type,
        evidence_item_id=relationship.evidence_item_id,
        confidence_score=relationship.confidence_score,
        confidence_label=_coerce_confidence_label(relationship.confidence_label),
        rationale=relationship.rationale,
        properties=relationship.properties or {},
        created_at=relationship.created_at,
    )


def serialize_observation(
    observation: EvidenceObservation,
) -> EvidenceObservationResponse:
    return EvidenceObservationResponse(
        id=observation.id,
        threat_model_id=observation.threat_model_id,
        evidence_item_id=observation.evidence_item_id,
        subject_entity_id=observation.subject_entity_id,
        predicate=observation.predicate,
        object_entity_id=observation.object_entity_id,
        value_text=observation.value_text,
        value_json=observation.value_json or {},
        severity=observation.severity,
        confidence_score=observation.confidence_score,
        confidence_label=_coerce_confidence_label(observation.confidence_label),
        observed_at=observation.observed_at,
        expires_at=observation.expires_at,
        created_at=observation.created_at,
    )


def serialize_finding(finding: EvidenceFinding) -> EvidenceFindingResponse:
    return EvidenceFindingResponse(
        id=finding.id,
        threat_model_id=finding.threat_model_id,
        finding_key=finding.finding_key,
        finding_kind=finding.finding_kind,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        source_id=finding.source_id,
        primary_evidence_item_id=finding.primary_evidence_item_id,
        confidence_score=finding.confidence_score,
        confidence_label=_coerce_confidence_label(finding.confidence_label),
        freshness_status=_coerce_freshness_status(finding.freshness_status),
        source_system=finding.source_system,
        source_object_type=finding.source_object_type,
        source_object_id=finding.source_object_id,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        resolved_at=finding.resolved_at,
        metadata=finding.finding_metadata or {},
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


def serialize_link(link: EvidenceFindingLink) -> EvidenceFindingLinkResponse:
    return EvidenceFindingLinkResponse(
        id=link.id,
        threat_model_id=link.threat_model_id,
        finding_id=link.finding_id,
        evidence_item_id=link.evidence_item_id,
        observation_id=link.observation_id,
        entity_id=link.entity_id,
        link_type=link.link_type,
        confidence_score=link.confidence_score,
        confidence_label=_coerce_confidence_label(link.confidence_label),
        rationale=link.rationale,
        created_at=link.created_at,
    )


async def _count_rows(db: AsyncSession, model, threat_model_id: UUID) -> int:
    result = await db.execute(
        select(func.count(model.id)).where(model.threat_model_id == threat_model_id)
    )
    return int(result.scalar_one() or 0)


async def _group_counts(
    db: AsyncSession,
    model,
    column,
    threat_model_id: UUID,
) -> list[EvidenceCountBucket]:
    result = await db.execute(
        select(column, func.count(model.id))
        .where(model.threat_model_id == threat_model_id)
        .group_by(column)
        .order_by(column.asc())
    )
    return _bucket_response(result.all())


async def build_coverage_gaps(
    db: AsyncSession,
    threat_model: ThreatModel,
) -> list[EvidenceCoverageGap]:
    gaps: list[EvidenceCoverageGap] = []
    threat_model_id = threat_model.id

    node_count = await _count_rows(db, DFDNode, threat_model_id)
    edge_count = await _count_rows(db, DFDEdge, threat_model_id)
    document_count = await _count_rows(db, Document, threat_model_id)
    threat_count = await _count_rows(db, Threat, threat_model_id)

    completed_scan_result = await db.execute(
        select(func.count(ScanJob.id)).where(
            ScanJob.threat_model_id == threat_model_id,
            ScanJob.status == "completed",
        )
    )
    completed_scan_count = int(completed_scan_result.scalar_one() or 0)

    scan_result = await db.execute(
        select(func.count(ScanThreatResult.id))
        .join(Threat, Threat.id == ScanThreatResult.threat_id)
        .where(Threat.threat_model_id == threat_model_id)
    )
    scan_result_count = int(scan_result.scalar_one() or 0)

    if node_count == 0:
        gaps.append(
            EvidenceCoverageGap(
                gap_type="missing_dfd",
                severity="blocking",
                title="No DFD entities are modeled",
                detail="The evidence graph cannot connect findings to assets until the model has DFD nodes.",
                remediation="Generate or draw a DFD before treating review findings as asset-backed.",
            )
        )
    elif edge_count == 0:
        gaps.append(
            EvidenceCoverageGap(
                gap_type="missing_data_flows",
                severity="warning",
                title="No data flows are modeled",
                detail="Assets exist, but ThreatGenix cannot reason about boundary crossings or data paths.",
                remediation="Add DFD edges for the important request, event, and data flows.",
            )
        )

    if document_count == 0:
        gaps.append(
            EvidenceCoverageGap(
                gap_type="missing_architecture_document",
                severity="info",
                title="No architecture document is attached",
                detail="The model currently lacks document-derived architecture evidence.",
                remediation="Upload an architecture document or attach a TMAC import as a source.",
            )
        )

    if not any(
        [
            getattr(threat_model, "repository_evidence", None),
            getattr(threat_model, "cloud_scan_evidence", None),
            getattr(threat_model, "iac_evidence", None),
        ]
    ):
        gaps.append(
            EvidenceCoverageGap(
                gap_type="missing_environment_evidence",
                severity="warning",
                title="No repo, cloud, or IaC evidence is connected",
                detail="The graph only has modeled data and cannot compare it with implementation or environment evidence.",
                remediation="Attach repository, cloud scan, or IaC evidence from the Environment Evidence panel.",
            )
        )

    if completed_scan_count == 0:
        gaps.append(
            EvidenceCoverageGap(
                gap_type="missing_validation_runs",
                severity="warning",
                title="No completed validation run exists",
                detail="No tool output has validated or refuted modeled threats yet.",
                remediation="Run an authorized validation tool or ingest a supported external scan report.",
            )
        )

    if threat_count > 0 and scan_result_count == 0:
        gaps.append(
            EvidenceCoverageGap(
                gap_type="unvalidated_threats",
                severity="info",
                title="Threats are not linked to validation results",
                detail="Threats exist, but no scan-to-threat validation mapping is present.",
                remediation="Run semantic scan mapping after validation evidence is available.",
            )
        )

    return gaps


async def build_evidence_status(
    db: AsyncSession,
    threat_model: ThreatModel,
) -> EvidenceStatusResponse:
    threat_model_id = threat_model.id
    source_count = await _count_rows(db, EvidenceSource, threat_model_id)
    status = "not_built"
    if source_count > 0:
        error_result = await db.execute(
            select(func.count(EvidenceSource.id)).where(
                EvidenceSource.threat_model_id == threat_model_id,
                EvidenceSource.status == "error",
            )
        )
        stale_result = await db.execute(
            select(func.count(EvidenceItem.id)).where(
                EvidenceItem.threat_model_id == threat_model_id,
                EvidenceItem.freshness_status.in_(("stale", "expired")),
            )
        )
        stale_source_result = await db.execute(
            select(func.count(EvidenceSource.id)).where(
                EvidenceSource.threat_model_id == threat_model_id,
                EvidenceSource.status.in_(("stale", "expired")),
            )
        )
        stale_sync_count = 0
        threat_model_updated_at = getattr(threat_model, "updated_at", None)
        if threat_model_updated_at is not None:
            stale_sync_result = await db.execute(
                select(func.count(EvidenceSource.id)).where(
                    EvidenceSource.threat_model_id == threat_model_id,
                    or_(
                        EvidenceSource.last_synced_at.is_(None),
                        EvidenceSource.last_synced_at < threat_model_updated_at,
                    ),
                )
            )
            stale_sync_count = int(stale_sync_result.scalar_one() or 0)

        if int(error_result.scalar_one() or 0) > 0:
            status = "error"
        elif (
            int(stale_result.scalar_one() or 0) > 0
            or int(stale_source_result.scalar_one() or 0) > 0
            or stale_sync_count > 0
        ):
            status = "stale"
        else:
            status = "current"

    return EvidenceStatusResponse(
        threat_model_id=threat_model_id,
        projection_status=status,
        generated_at=utc_now(),
        source_count=source_count,
        item_count=await _count_rows(db, EvidenceItem, threat_model_id),
        entity_count=await _count_rows(db, EvidenceEntity, threat_model_id),
        relationship_count=await _count_rows(db, EvidenceRelationship, threat_model_id),
        observation_count=await _count_rows(db, EvidenceObservation, threat_model_id),
        finding_count=await _count_rows(db, EvidenceFinding, threat_model_id),
        sources_by_type=await _group_counts(
            db, EvidenceSource, EvidenceSource.source_type, threat_model_id
        ),
        items_by_type=await _group_counts(
            db, EvidenceItem, EvidenceItem.item_type, threat_model_id
        ),
        entities_by_type=await _group_counts(
            db, EvidenceEntity, EvidenceEntity.entity_type, threat_model_id
        ),
        findings_by_kind=await _group_counts(
            db, EvidenceFinding, EvidenceFinding.finding_kind, threat_model_id
        ),
        freshness=await _group_counts(
            db, EvidenceItem, EvidenceItem.freshness_status, threat_model_id
        ),
        coverage_gaps=await build_coverage_gaps(db, threat_model),
    )


async def list_evidence_graph(
    db: AsyncSession,
    threat_model: ThreatModel,
    *,
    limit: int = 500,
) -> EvidenceGraphResponse:
    threat_model_id = threat_model.id
    status = await build_evidence_status(db, threat_model)

    async def _list(model, order_column):
        result = await db.execute(
            select(model)
            .where(model.threat_model_id == threat_model_id)
            .order_by(order_column.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    return EvidenceGraphResponse(
        status=status,
        sources=[
            serialize_source(item)
            for item in await _list(EvidenceSource, EvidenceSource.source_type)
        ],
        items=[
            serialize_item(item)
            for item in await _list(EvidenceItem, EvidenceItem.item_type)
        ],
        entities=[
            serialize_entity(item)
            for item in await _list(EvidenceEntity, EvidenceEntity.entity_type)
        ],
        relationships=[
            serialize_relationship(item)
            for item in await _list(
                EvidenceRelationship, EvidenceRelationship.relationship_type
            )
        ],
        observations=[
            serialize_observation(item)
            for item in await _list(EvidenceObservation, EvidenceObservation.predicate)
        ],
        findings=[
            serialize_finding(item)
            for item in await _list(EvidenceFinding, EvidenceFinding.finding_kind)
        ],
        links=[
            serialize_link(item)
            for item in await _list(EvidenceFindingLink, EvidenceFindingLink.link_type)
        ],
    )


async def list_evidence_entities(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    entity_type: str | None = None,
    limit: int = 500,
) -> list[EvidenceEntityResponse]:
    stmt = select(EvidenceEntity).where(
        EvidenceEntity.threat_model_id == threat_model_id
    )
    if entity_type:
        stmt = stmt.where(EvidenceEntity.entity_type == entity_type)
    result = await db.execute(
        stmt.order_by(EvidenceEntity.entity_type.asc()).limit(limit)
    )
    return [serialize_entity(item) for item in result.scalars().all()]


async def list_evidence_findings(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    finding_kind: str | None = None,
    limit: int = 500,
) -> list[EvidenceFindingResponse]:
    stmt = select(EvidenceFinding).where(
        EvidenceFinding.threat_model_id == threat_model_id
    )
    if finding_kind:
        stmt = stmt.where(EvidenceFinding.finding_kind == finding_kind)
    result = await db.execute(
        stmt.order_by(EvidenceFinding.severity.desc()).limit(limit)
    )
    return [serialize_finding(item) for item in result.scalars().all()]


async def build_evidence_coverage(
    db: AsyncSession,
    threat_model: ThreatModel,
) -> EvidenceCoverageResponse:
    threat_model_id = threat_model.id

    async def _count(stmt) -> int:
        result = await db.execute(stmt)
        return int(result.scalar_one() or 0)

    unlinked_finding_count = await _count(
        select(func.count(EvidenceFinding.id))
        .outerjoin(
            EvidenceFindingLink,
            EvidenceFindingLink.finding_id == EvidenceFinding.id,
        )
        .where(
            EvidenceFinding.threat_model_id == threat_model_id,
            EvidenceFindingLink.id.is_(None),
        )
    )
    validated_finding_count = await _count(
        select(func.count(EvidenceFinding.id)).where(
            EvidenceFinding.threat_model_id == threat_model_id,
            EvidenceFinding.confidence_label == "validated",
        )
    )
    contextual_finding_count = await _count(
        select(func.count(EvidenceFinding.id)).where(
            EvidenceFinding.threat_model_id == threat_model_id,
            EvidenceFinding.confidence_label.in_(["contextual", "theoretical"]),
        )
    )
    stale_or_expired_item_count = await _count(
        select(func.count(EvidenceItem.id)).where(
            EvidenceItem.threat_model_id == threat_model_id,
            EvidenceItem.freshness_status.in_(["stale", "expired"]),
        )
    )

    return EvidenceCoverageResponse(
        status=await build_evidence_status(db, threat_model),
        relationship_types=await _group_counts(
            db,
            EvidenceRelationship,
            EvidenceRelationship.relationship_type,
            threat_model_id,
        ),
        finding_link_types=await _group_counts(
            db,
            EvidenceFindingLink,
            EvidenceFindingLink.link_type,
            threat_model_id,
        ),
        unlinked_finding_count=unlinked_finding_count,
        validated_finding_count=validated_finding_count,
        contextual_finding_count=contextual_finding_count,
        stale_or_expired_item_count=stale_or_expired_item_count,
    )


async def get_entity_neighborhood(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    entity_id: UUID | None = None,
    canonical_key: str | None = None,
    depth: int = 1,
    limit: int = 200,
) -> EvidenceEntityNeighborhoodResponse | None:
    stmt = select(EvidenceEntity).where(
        EvidenceEntity.threat_model_id == threat_model_id
    )
    if entity_id is not None:
        stmt = stmt.where(EvidenceEntity.id == entity_id)
    elif canonical_key:
        stmt = stmt.where(EvidenceEntity.canonical_key == canonical_key)
    else:
        return None
    result = await db.execute(stmt.limit(1))
    root = result.scalar_one_or_none()
    if root is None:
        return None

    entity_ids: set[UUID] = {root.id}
    frontier: set[UUID] = {root.id}
    relationships_by_id: dict[UUID, EvidenceRelationship] = {}

    for _ in range(max(depth, 0)):
        if not frontier or len(relationships_by_id) >= limit:
            break
        result = await db.execute(
            select(EvidenceRelationship)
            .where(
                EvidenceRelationship.threat_model_id == threat_model_id,
                or_(
                    EvidenceRelationship.from_entity_id.in_(frontier),
                    EvidenceRelationship.to_entity_id.in_(frontier),
                ),
            )
            .limit(limit)
        )
        next_frontier: set[UUID] = set()
        for relationship in result.scalars().all():
            relationships_by_id.setdefault(relationship.id, relationship)
            for next_id in (
                relationship.from_entity_id,
                relationship.to_entity_id,
            ):
                if next_id not in entity_ids:
                    next_frontier.add(next_id)
        entity_ids.update(next_frontier)
        frontier = next_frontier

    entities_result = await db.execute(
        select(EvidenceEntity)
        .where(
            EvidenceEntity.threat_model_id == threat_model_id,
            EvidenceEntity.id.in_(entity_ids),
        )
        .limit(limit)
    )
    entities = list(entities_result.scalars().all())

    links_result = await db.execute(
        select(EvidenceFindingLink)
        .where(
            EvidenceFindingLink.threat_model_id == threat_model_id,
            EvidenceFindingLink.entity_id.in_(entity_ids),
        )
        .limit(limit)
    )
    links = list(links_result.scalars().all())
    finding_ids = {link.finding_id for link in links}
    findings: list[EvidenceFinding] = []
    if finding_ids:
        findings_result = await db.execute(
            select(EvidenceFinding)
            .where(
                EvidenceFinding.threat_model_id == threat_model_id,
                EvidenceFinding.id.in_(finding_ids),
            )
            .limit(limit)
        )
        findings = list(findings_result.scalars().all())

    return EvidenceEntityNeighborhoodResponse(
        root_entity=serialize_entity(root),
        depth=depth,
        entities=[serialize_entity(entity) for entity in entities],
        relationships=[
            serialize_relationship(relationship)
            for relationship in relationships_by_id.values()
        ],
        findings=[serialize_finding(finding) for finding in findings],
        links=[serialize_link(link) for link in links],
    )


async def get_evidence_chain(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    finding_key: str | None = None,
    source_object_type: str | None = None,
    source_object_id: str | None = None,
    limit: int = 200,
) -> EvidenceChainResponse | None:
    stmt = select(EvidenceFinding).where(
        EvidenceFinding.threat_model_id == threat_model_id
    )
    if finding_key:
        stmt = stmt.where(EvidenceFinding.finding_key == finding_key)
    elif source_object_type and source_object_id:
        stmt = stmt.where(
            EvidenceFinding.source_object_type == source_object_type,
            EvidenceFinding.source_object_id == source_object_id,
        )
    else:
        return None

    result = await db.execute(stmt.order_by(EvidenceFinding.created_at.desc()).limit(1))
    finding = result.scalar_one_or_none()
    if finding is None:
        return None

    source = None
    if finding.source_id is not None:
        source_result = await db.execute(
            select(EvidenceSource)
            .where(
                EvidenceSource.id == finding.source_id,
                EvidenceSource.threat_model_id == threat_model_id,
            )
            .limit(1)
        )
        source = source_result.scalar_one_or_none()

    links_result = await db.execute(
        select(EvidenceFindingLink)
        .where(
            EvidenceFindingLink.finding_id == finding.id,
            EvidenceFindingLink.threat_model_id == threat_model_id,
        )
        .limit(limit)
    )
    links = list(links_result.scalars().all())
    item_ids = {
        item_id for item_id in [finding.primary_evidence_item_id] if item_id is not None
    }
    item_ids.update(link.evidence_item_id for link in links if link.evidence_item_id)
    entity_ids = {link.entity_id for link in links if link.entity_id}

    items: list[EvidenceItem] = []
    if item_ids:
        items_result = await db.execute(
            select(EvidenceItem)
            .where(
                EvidenceItem.id.in_(item_ids),
                EvidenceItem.threat_model_id == threat_model_id,
            )
            .order_by(EvidenceItem.created_at.asc())
            .limit(limit)
        )
        items = list(items_result.scalars().all())

    observation_stmt = select(EvidenceObservation).where(
        EvidenceObservation.threat_model_id == threat_model_id
    )
    observation_filters = []
    if item_ids:
        observation_filters.append(EvidenceObservation.evidence_item_id.in_(item_ids))
    if entity_ids:
        observation_filters.append(
            EvidenceObservation.subject_entity_id.in_(entity_ids)
        )
    observations: list[EvidenceObservation] = []
    if observation_filters:
        observations_result = await db.execute(
            observation_stmt.where(or_(*observation_filters)).limit(limit)
        )
        observations = list(observations_result.scalars().all())
        entity_ids.update(observation.subject_entity_id for observation in observations)
        entity_ids.update(
            observation.object_entity_id
            for observation in observations
            if observation.object_entity_id
        )

    entities: list[EvidenceEntity] = []
    if entity_ids:
        entities_result = await db.execute(
            select(EvidenceEntity)
            .where(
                EvidenceEntity.id.in_(entity_ids),
                EvidenceEntity.threat_model_id == threat_model_id,
            )
            .order_by(EvidenceEntity.entity_type.asc())
            .limit(limit)
        )
        entities = list(entities_result.scalars().all())

    primary_item = next(
        (item for item in items if item.id == finding.primary_evidence_item_id),
        None,
    )
    return EvidenceChainResponse(
        finding=serialize_finding(finding),
        source=serialize_source(source) if source else None,
        primary_item=serialize_item(primary_item) if primary_item else None,
        evidence_items=[serialize_item(item) for item in items],
        observations=[
            serialize_observation(observation) for observation in observations
        ],
        entities=[serialize_entity(entity) for entity in entities],
        links=[serialize_link(link) for link in links],
    )
