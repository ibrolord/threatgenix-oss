"""Projection from native ThreatGenix records into the evidence graph."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
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
from app.models.scan import (
    ScanExecutionArtifact,
    ScanFinding,
    ScanJob,
    ScanThreatResult,
)
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.services.evidence_freshness import derive_freshness_status, utc_now
from app.services.evidence_graph import (
    build_evidence_status,
    confidence_label,
    delete_evidence_graph,
    json_key,
    native_key,
    stable_hash,
)


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _severity_from_scan(severity: str | None) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "unknown": "Unknown",
    }
    return mapping.get((severity or "").casefold(), "Unknown")


def _parse_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _status_from_threat(status: str | None) -> str:
    mapping = {
        "Open": "open",
        "In Progress": "in_progress",
        "Mitigated": "mitigated",
        "Accepted": "accepted",
        "Dismissed": "dismissed",
    }
    return mapping.get(status or "", "open")


def _threat_confidence(threat: Threat) -> float:
    if threat.source == "Rules":
        return 55.0
    if threat.source == "AI+Rules":
        return 50.0
    if threat.source == "Manual":
        return 45.0
    return 25.0


class EvidenceProjectionBuilder:
    def __init__(self, db: AsyncSession, threat_model: ThreatModel) -> None:
        self.db = db
        self.threat_model = threat_model
        self.threat_model_id = threat_model.id
        self.now = utc_now()
        self.sources: dict[str, EvidenceSource] = {}
        self.items: dict[str, EvidenceItem] = {}
        self.entities: dict[str, EvidenceEntity] = {}
        self.findings: dict[str, EvidenceFinding] = {}

    def add_source(
        self,
        *,
        stable_key: str,
        source_type: str,
        source_name: str,
        trust_level: str,
        ingestion_mode: str = "projection",
        provider: str | None = None,
        transport: str | None = None,
        reference: str | None = None,
        uri: str | None = None,
        collected_at: object | None = None,
        expires_at: object | None = None,
        parser_version: str | None = None,
        metadata: dict | None = None,
        payload: object | None = None,
    ) -> EvidenceSource:
        source = EvidenceSource(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            owner_id=getattr(self.threat_model, "owner_id", None),
            stable_key=stable_key,
            source_type=source_type,
            source_name=source_name,
            provider=provider,
            transport=transport,
            reference=reference,
            uri=uri,
            source_fingerprint_sha256=stable_hash(payload)
            if payload is not None
            else None,
            ingestion_mode=ingestion_mode,
            trust_level=trust_level,
            status="active",
            collected_at=_parse_datetime(collected_at),
            last_synced_at=self.now,
            expires_at=_parse_datetime(expires_at),
            parser_version=parser_version,
            source_metadata=metadata or {},
        )
        self.sources[stable_key] = source
        self.db.add(source)
        return source

    def add_entity(
        self,
        *,
        entity_type: str,
        canonical_key: str,
        display_name: str,
        source_object_type: str | None = None,
        source_object_id: str | None = None,
        properties: dict | None = None,
    ) -> EvidenceEntity:
        existing = self.entities.get(canonical_key)
        if existing is not None:
            return existing
        entity = EvidenceEntity(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            entity_type=entity_type,
            canonical_key=canonical_key,
            display_name=display_name,
            source_object_type=source_object_type,
            source_object_id=source_object_id,
            properties=properties or {},
            last_seen_at=self.now,
            status="active",
        )
        self.entities[canonical_key] = entity
        self.db.add(entity)
        return entity

    def add_item(
        self,
        *,
        source: EvidenceSource,
        stable_key: str,
        item_type: str,
        title: str,
        summary: str | None = None,
        raw_ref: str | None = None,
        raw_payload: dict | None = None,
        confidence_score: float = 50.0,
        observed_at: object | None = None,
        expires_at: object | None = None,
    ) -> EvidenceItem:
        payload = raw_payload or {}
        normalized_observed_at = _parse_datetime(observed_at)
        normalized_expires_at = _parse_datetime(expires_at)
        item = EvidenceItem(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            source=source,
            stable_key=stable_key,
            item_type=item_type,
            title=title,
            summary=summary,
            raw_ref=raw_ref,
            raw_payload=payload,
            content_sha256=stable_hash(payload) if payload else None,
            confidence_score=confidence_score,
            confidence_label=confidence_label(confidence_score),
            freshness_status=derive_freshness_status(
                observed_at=normalized_observed_at,
                collected_at=source.collected_at,
                expires_at=normalized_expires_at or source.expires_at,
                now=self.now,
            ),
            observed_at=normalized_observed_at,
            expires_at=normalized_expires_at,
        )
        self.items[stable_key] = item
        self.db.add(item)
        return item

    def add_relationship(
        self,
        *,
        from_key: str,
        to_key: str,
        relationship_type: str,
        evidence_item: EvidenceItem | None = None,
        confidence_score: float = 50.0,
        rationale: str | None = None,
        properties: dict | None = None,
    ) -> EvidenceRelationship | None:
        from_entity = self.entities.get(from_key)
        to_entity = self.entities.get(to_key)
        if from_entity is None or to_entity is None:
            return None
        stable_key = json_key(
            "rel",
            relationship_type,
            from_key,
            to_key,
            evidence_item.stable_key if evidence_item else None,
        )
        relationship = EvidenceRelationship(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            stable_key=stable_key,
            from_entity_id=from_entity.id,
            to_entity_id=to_entity.id,
            relationship_type=relationship_type,
            evidence_item_id=evidence_item.id if evidence_item else None,
            confidence_score=confidence_score,
            confidence_label=confidence_label(confidence_score),
            rationale=rationale,
            properties=properties or {},
        )
        self.db.add(relationship)
        return relationship

    def add_observation(
        self,
        *,
        evidence_item: EvidenceItem,
        subject_key: str,
        predicate: str,
        value_text: str | None = None,
        value_json: dict | None = None,
        object_key: str | None = None,
        severity: str | None = None,
        confidence_score: float = 50.0,
        observed_at: object | None = None,
    ) -> EvidenceObservation | None:
        subject = self.entities.get(subject_key)
        if subject is None:
            return None
        object_entity = self.entities.get(object_key) if object_key else None
        observation = EvidenceObservation(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            evidence_item_id=evidence_item.id,
            subject_entity_id=subject.id,
            predicate=predicate,
            object_entity_id=object_entity.id if object_entity else None,
            value_text=value_text,
            value_json=value_json or {},
            severity=severity,
            confidence_score=confidence_score,
            confidence_label=confidence_label(confidence_score),
            observed_at=_parse_datetime(observed_at),
        )
        self.db.add(observation)
        return observation

    def add_finding(
        self,
        *,
        finding_key: str,
        finding_kind: str,
        title: str,
        description: str,
        severity: str,
        status: str,
        source: EvidenceSource | None = None,
        primary_item: EvidenceItem | None = None,
        confidence_score: float = 50.0,
        source_system: str | None = None,
        source_object_type: str | None = None,
        source_object_id: str | None = None,
        metadata: dict | None = None,
    ) -> EvidenceFinding:
        finding = EvidenceFinding(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            finding_key=finding_key,
            finding_kind=finding_kind,
            title=title,
            description=description,
            severity=severity,
            status=status,
            source_id=source.id if source else None,
            primary_evidence_item_id=primary_item.id if primary_item else None,
            confidence_score=confidence_score,
            confidence_label=confidence_label(confidence_score),
            freshness_status=primary_item.freshness_status
            if primary_item
            else "unknown",
            source_system=source_system,
            source_object_type=source_object_type,
            source_object_id=source_object_id,
            last_seen_at=self.now,
            finding_metadata=metadata or {},
        )
        self.findings[finding_key] = finding
        self.db.add(finding)
        return finding

    def add_finding_link(
        self,
        *,
        finding: EvidenceFinding,
        link_type: str,
        evidence_item: EvidenceItem | None = None,
        entity_key: str | None = None,
        confidence_score: float = 50.0,
        rationale: str | None = None,
    ) -> EvidenceFindingLink:
        entity = self.entities.get(entity_key) if entity_key else None
        link = EvidenceFindingLink(
            id=uuid4(),
            threat_model_id=self.threat_model_id,
            finding_id=finding.id,
            evidence_item_id=evidence_item.id if evidence_item else None,
            entity_id=entity.id if entity else None,
            link_type=link_type,
            confidence_score=confidence_score,
            confidence_label=confidence_label(confidence_score),
            rationale=rationale,
        )
        self.db.add(link)
        return link


async def _load_projection_inputs(
    db: AsyncSession, threat_model_id: UUID
) -> dict[str, list[Any]]:
    async def _all(model):
        result = await db.execute(
            select(model).where(model.threat_model_id == threat_model_id)
        )
        return list(result.scalars().all())

    scan_jobs = await _all(ScanJob)
    scan_ids = [scan.id for scan in scan_jobs]
    scan_findings: list[ScanFinding] = []
    artifacts: list[ScanExecutionArtifact] = []
    scan_results: list[ScanThreatResult] = []
    if scan_ids:
        result = await db.execute(
            select(ScanFinding).where(ScanFinding.scan_job_id.in_(scan_ids))
        )
        scan_findings = list(result.scalars().all())
        result = await db.execute(
            select(ScanExecutionArtifact).where(
                ScanExecutionArtifact.scan_job_id.in_(scan_ids)
            )
        )
        artifacts = list(result.scalars().all())
        result = await db.execute(
            select(ScanThreatResult).where(ScanThreatResult.scan_job_id.in_(scan_ids))
        )
        scan_results = list(result.scalars().all())

    return {
        "nodes": await _all(DFDNode),
        "edges": await _all(DFDEdge),
        "boundaries": await _all(TrustBoundary),
        "documents": await _all(Document),
        "threats": await _all(Threat),
        "scan_jobs": scan_jobs,
        "scan_findings": scan_findings,
        "scan_artifacts": artifacts,
        "scan_results": scan_results,
    }


async def rebuild_evidence_graph(db: AsyncSession, threat_model: ThreatModel):
    """Rebuild evidence graph v1 from native records for one threat model."""
    await delete_evidence_graph(db, threat_model.id)
    builder = EvidenceProjectionBuilder(db, threat_model)
    inputs = await _load_projection_inputs(db, threat_model.id)

    model_source = builder.add_source(
        stable_key=native_key("threat_models", threat_model.id),
        source_type="threat_model",
        source_name=threat_model.system_name,
        trust_level="modeled",
        payload={
            "system_name": threat_model.system_name,
            "classification": threat_model.data_classification,
            "updated_at": threat_model.updated_at,
        },
    )
    model_item = builder.add_item(
        source=model_source,
        stable_key=json_key("item", "threat_model", threat_model.id),
        item_type="threat_model_metadata",
        title=threat_model.system_name,
        summary=threat_model.description,
        raw_payload={
            "classification": threat_model.data_classification,
            "regulatory_scope": threat_model.regulatory_scope or [],
            "deployment_model": threat_model.deployment_model,
        },
        confidence_score=55.0,
        observed_at=threat_model.updated_at,
    )
    model_entity_key = native_key("threat_models", threat_model.id)
    builder.add_entity(
        entity_type="threat_model",
        canonical_key=model_entity_key,
        display_name=threat_model.system_name,
        source_object_type="threat_model",
        source_object_id=str(threat_model.id),
        properties={
            "data_classification": threat_model.data_classification,
            "regulatory_scope": threat_model.regulatory_scope or [],
        },
    )

    dfd_source = None
    if inputs["nodes"] or inputs["edges"] or inputs["boundaries"]:
        dfd_source = builder.add_source(
            stable_key=json_key("source", "dfd", threat_model.id),
            source_type="dfd",
            source_name="Current DFD",
            trust_level="modeled",
            payload={
                "nodes": [str(node.id) for node in inputs["nodes"]],
                "edges": [str(edge.id) for edge in inputs["edges"]],
                "boundaries": [str(boundary.id) for boundary in inputs["boundaries"]],
            },
        )
        dfd_item = builder.add_item(
            source=dfd_source,
            stable_key=json_key("item", "dfd", threat_model.id),
            item_type="dfd_snapshot",
            title="Current DFD snapshot",
            summary=(
                f"{len(inputs['nodes'])} nodes, {len(inputs['edges'])} flows, "
                f"{len(inputs['boundaries'])} trust boundaries"
            ),
            confidence_score=55.0,
        )
    else:
        dfd_item = None

    await db.flush()

    for boundary in inputs["boundaries"]:
        boundary_key = native_key("trust_boundaries", boundary.id)
        builder.add_entity(
            entity_type="trust_boundary",
            canonical_key=boundary_key,
            display_name=boundary.name,
            source_object_type="trust_boundary",
            source_object_id=str(boundary.id),
            properties={
                "boundary_type": boundary.boundary_type,
                "node_ids": [str(node_id) for node_id in boundary.node_ids or []],
            },
        )
        builder.add_relationship(
            from_key=model_entity_key,
            to_key=boundary_key,
            relationship_type="contains_boundary",
            evidence_item=dfd_item,
            confidence_score=55.0,
        )

    for node in inputs["nodes"]:
        node_key = native_key("dfd_nodes", node.id)
        builder.add_entity(
            entity_type="dfd_node",
            canonical_key=node_key,
            display_name=node.name,
            source_object_type="dfd_node",
            source_object_id=str(node.id),
            properties={
                "node_type": node.node_type,
                "scan_target_url": node.scan_target_url,
                "confidence": node.confidence,
                "properties": node.properties or {},
                "security_controls": node.security_controls or [],
            },
        )
        builder.add_relationship(
            from_key=model_entity_key,
            to_key=node_key,
            relationship_type="contains_node",
            evidence_item=dfd_item,
            confidence_score=55.0,
        )
        if node.trust_boundary_id:
            builder.add_relationship(
                from_key=node_key,
                to_key=native_key("trust_boundaries", node.trust_boundary_id),
                relationship_type="in_boundary",
                evidence_item=dfd_item,
                confidence_score=55.0,
            )

    for edge in inputs["edges"]:
        edge_key = native_key("dfd_edges", edge.id)
        builder.add_entity(
            entity_type="dfd_edge",
            canonical_key=edge_key,
            display_name=edge.label or "Data flow",
            source_object_type="dfd_edge",
            source_object_id=str(edge.id),
            properties={
                "source_node_id": str(edge.source_node_id),
                "target_node_id": str(edge.target_node_id),
                "tls_version": edge.tls_version,
                "is_response": edge.is_response,
                "data_objects": edge.data_objects or [],
                "properties": edge.properties or {},
            },
        )
        builder.add_relationship(
            from_key=native_key("dfd_nodes", edge.source_node_id),
            to_key=native_key("dfd_nodes", edge.target_node_id),
            relationship_type="flows_to",
            evidence_item=dfd_item,
            confidence_score=55.0,
            properties={"edge_id": str(edge.id), "label": edge.label},
        )
        builder.add_relationship(
            from_key=model_entity_key,
            to_key=edge_key,
            relationship_type="contains_flow",
            evidence_item=dfd_item,
            confidence_score=55.0,
        )

    await db.flush()

    if dfd_item is not None:
        for node in inputs["nodes"]:
            builder.add_observation(
                evidence_item=dfd_item,
                subject_key=native_key("dfd_nodes", node.id),
                predicate="modeled_as_dfd_node",
                value_json={"node_type": node.node_type, "confidence": node.confidence},
                confidence_score=55.0,
            )

    for document in inputs["documents"]:
        document_payload = {
            "filename": document.filename,
            "page_count": document.page_count,
            "parsed_components": document.parsed_components,
            "purged": document.purged,
        }
        source = builder.add_source(
            stable_key=native_key("documents", document.id),
            source_type="document",
            source_name=document.filename,
            trust_level="indicated",
            ingestion_mode="upload",
            collected_at=document.uploaded_at,
            expires_at=document.expires_at,
            payload=document_payload,
        )
        item = builder.add_item(
            source=source,
            stable_key=json_key("item", "document", document.id),
            item_type="architecture_document",
            title=document.filename,
            summary=f"{document.page_count} page architecture document",
            raw_payload=document_payload,
            confidence_score=60.0,
            observed_at=document.parsed_at or document.uploaded_at,
            expires_at=document.expires_at,
        )
        document_key = native_key("documents", document.id)
        builder.add_entity(
            entity_type="document",
            canonical_key=document_key,
            display_name=document.filename,
            source_object_type="document",
            source_object_id=str(document.id),
            properties=document_payload,
        )
        await db.flush()
        builder.add_relationship(
            from_key=model_entity_key,
            to_key=document_key,
            relationship_type="has_document",
            evidence_item=item,
            confidence_score=60.0,
        )

    await _project_environment_evidence(builder)
    await db.flush()
    await _project_threats(builder, inputs["threats"], model_item)
    await db.flush()
    await _project_scans(builder, inputs)
    await db.flush()
    return await build_evidence_status(db, threat_model)


async def _project_environment_evidence(builder: EvidenceProjectionBuilder) -> None:
    threat_model = builder.threat_model
    model_key = native_key("threat_models", threat_model.id)

    repository_evidence = _as_dict(getattr(threat_model, "repository_evidence", None))
    if repository_evidence:
        connection = _as_dict(repository_evidence.get("connection"))
        source = builder.add_source(
            stable_key=json_key("source", "repository", threat_model.id),
            source_type="repository",
            source_name=repository_evidence.get("filename") or "Repository evidence",
            provider=connection.get("provider"),
            transport=connection.get("transport"),
            reference=repository_evidence.get("reference")
            or connection.get("reference"),
            trust_level="indicated",
            ingestion_mode="import" if connection else "upload",
            collected_at=repository_evidence.get("parsed_at"),
            parser_version="environment-evidence-v1",
            payload=repository_evidence,
        )
        item = builder.add_item(
            source=source,
            stable_key=json_key("item", "repository", threat_model.id),
            item_type="repository_evidence",
            title="Repository evidence",
            summary=(
                f"{repository_evidence.get('file_count', 0)} files, "
                f"{len(_as_list(repository_evidence.get('code_surfaces')))} code surfaces"
            ),
            raw_payload=repository_evidence,
            confidence_score=50.0,
            observed_at=repository_evidence.get("parsed_at"),
        )
        repo_key = json_key(
            "repo", threat_model.id, repository_evidence.get("reference") or "uploaded"
        )
        builder.add_entity(
            entity_type="repository",
            canonical_key=repo_key,
            display_name=repository_evidence.get("reference") or "Repository evidence",
            source_object_type="repository_evidence",
            properties={
                "languages": repository_evidence.get("languages") or [],
                "frameworks": repository_evidence.get("frameworks") or [],
            },
        )
        await builder.db.flush()
        builder.add_relationship(
            from_key=model_key,
            to_key=repo_key,
            relationship_type="has_repository_evidence",
            evidence_item=item,
            confidence_score=50.0,
        )
        for surface in _as_list(repository_evidence.get("code_surfaces")):
            if not isinstance(surface, dict):
                continue
            surface_id = surface.get("id") or surface.get("name")
            if not surface_id:
                continue
            surface_key = json_key("code_surface", threat_model.id, surface_id)
            builder.add_entity(
                entity_type="code_surface",
                canonical_key=surface_key,
                display_name=surface.get("name") or str(surface_id),
                source_object_type="code_surface",
                source_object_id=str(surface_id),
                properties=surface,
            )
            await builder.db.flush()
            builder.add_relationship(
                from_key=repo_key,
                to_key=surface_key,
                relationship_type="contains_code_surface",
                evidence_item=item,
                confidence_score=50.0,
                rationale="Heuristic repository parser identified this code surface.",
            )

        for risk in _as_list(repository_evidence.get("code_risk_signals")):
            if not isinstance(risk, dict):
                continue
            risk_id = risk.get("id") or stable_hash(risk)[:12]
            finding = builder.add_finding(
                finding_key=json_key("finding", "code_risk", threat_model.id, risk_id),
                finding_kind="code_risk_signal",
                title=str(risk.get("risk_type") or "Code risk signal")
                .replace("_", " ")
                .title(),
                description=str(
                    risk.get("evidence")
                    or "Repository parser identified a contextual code risk signal."
                ),
                severity=str(risk.get("severity") or "Unknown"),
                status="open",
                source=source,
                primary_item=item,
                confidence_score=45.0,
                source_system="repository_evidence",
                source_object_type="code_risk_signal",
                source_object_id=str(risk_id),
                metadata=risk,
            )
            await builder.db.flush()
            surface_id = risk.get("surface_id")
            if surface_id:
                builder.add_finding_link(
                    finding=finding,
                    link_type="supports",
                    evidence_item=item,
                    entity_key=json_key("code_surface", threat_model.id, surface_id),
                    confidence_score=45.0,
                    rationale="Contextual repository signal only; requires validation before promotion.",
                )

    cloud_scan_evidence = _as_dict(getattr(threat_model, "cloud_scan_evidence", None))
    if cloud_scan_evidence:
        source = builder.add_source(
            stable_key=json_key("source", "cloud_scan", threat_model.id),
            source_type="cloud_scan",
            source_name=cloud_scan_evidence.get("filename") or "Cloud scan evidence",
            provider=cloud_scan_evidence.get("provider"),
            trust_level="indicated",
            ingestion_mode="upload",
            collected_at=cloud_scan_evidence.get("parsed_at"),
            parser_version="environment-evidence-v1",
            payload=cloud_scan_evidence,
        )
        item = builder.add_item(
            source=source,
            stable_key=json_key("item", "cloud_scan", threat_model.id),
            item_type="cloud_scan_evidence",
            title="Cloud scan evidence",
            summary=f"{cloud_scan_evidence.get('finding_count', 0)} parsed cloud finding(s)",
            raw_payload=cloud_scan_evidence,
            confidence_score=60.0,
            observed_at=cloud_scan_evidence.get("parsed_at"),
        )
        for idx, cloud_finding in enumerate(
            _as_list(cloud_scan_evidence.get("high_signal_findings"))
        ):
            if not isinstance(cloud_finding, dict):
                continue
            key = cloud_finding.get("resource") or cloud_finding.get("detail") or idx
            finding = builder.add_finding(
                finding_key=json_key("finding", "cloud", threat_model.id, key),
                finding_kind="cloud_scan_finding",
                title=str(cloud_finding.get("category") or "Cloud finding")
                .replace("_", " ")
                .title(),
                description=str(cloud_finding.get("detail") or "Cloud scan finding"),
                severity=_severity_from_scan(cloud_finding.get("severity")),
                status="open",
                source=source,
                primary_item=item,
                confidence_score=60.0,
                source_system=str(cloud_scan_evidence.get("provider") or "cloud_scan"),
                source_object_type="cloud_finding",
                source_object_id=str(key),
                metadata=cloud_finding,
            )
            await builder.db.flush()
            builder.add_finding_link(
                finding=finding,
                link_type="supports",
                evidence_item=item,
                confidence_score=60.0,
                rationale="Imported cloud scan evidence indicates this condition.",
            )

    iac_evidence = _as_dict(getattr(threat_model, "iac_evidence", None))
    if iac_evidence:
        source = builder.add_source(
            stable_key=json_key("source", "iac", threat_model.id),
            source_type="iac",
            source_name=iac_evidence.get("filename") or "IaC evidence",
            reference=iac_evidence.get("reference"),
            trust_level="indicated",
            ingestion_mode="upload",
            collected_at=iac_evidence.get("parsed_at"),
            parser_version="environment-evidence-v1",
            payload=iac_evidence,
        )
        item = builder.add_item(
            source=source,
            stable_key=json_key("item", "iac", threat_model.id),
            item_type="iac_evidence",
            title="Infrastructure-as-code evidence",
            summary=f"{iac_evidence.get('resource_count', 0)} IaC resource(s)",
            raw_payload=iac_evidence,
            confidence_score=55.0,
            observed_at=iac_evidence.get("parsed_at"),
        )
        for resource_name in _as_list(iac_evidence.get("resource_names"))[:200]:
            resource_key = json_key("iac_resource", threat_model.id, resource_name)
            builder.add_entity(
                entity_type="iac_resource",
                canonical_key=resource_key,
                display_name=str(resource_name),
                source_object_type="iac_resource",
                source_object_id=str(resource_name),
                properties={"resource_types": iac_evidence.get("resource_types") or []},
            )
            await builder.db.flush()
            builder.add_relationship(
                from_key=model_key,
                to_key=resource_key,
                relationship_type="has_iac_resource",
                evidence_item=item,
                confidence_score=55.0,
            )


async def _project_threats(
    builder: EvidenceProjectionBuilder,
    threats: list[Threat],
    model_item: EvidenceItem,
) -> None:
    source = builder.add_source(
        stable_key=json_key("source", "threat_register", builder.threat_model_id),
        source_type="threat_register",
        source_name="Threat register",
        trust_level="modeled",
        payload=[str(threat.id) for threat in threats],
    )
    await builder.db.flush()

    for threat in threats:
        score = _threat_confidence(threat)
        item = builder.add_item(
            source=source,
            stable_key=json_key("item", "threat", threat.id),
            item_type="modeled_threat",
            title=threat.display_id,
            summary=threat.description,
            raw_payload={
                "stride_category": threat.stride_category,
                "severity": threat.severity,
                "status": threat.status,
                "source": threat.source,
                "affected_node_ids": [
                    str(node_id) for node_id in threat.affected_node_ids or []
                ],
                "affected_edge_ids": [
                    str(edge_id) for edge_id in threat.affected_edge_ids or []
                ],
            },
            confidence_score=score,
            observed_at=threat.updated_at,
        )
        threat_key = native_key("threats", threat.id)
        builder.add_entity(
            entity_type="threat",
            canonical_key=threat_key,
            display_name=threat.display_id,
            source_object_type="threat",
            source_object_id=str(threat.id),
            properties={
                "description": threat.description,
                "stride_category": threat.stride_category,
                "severity": threat.severity,
                "status": threat.status,
                "source": threat.source,
                "rule_id": threat.rule_id,
            },
        )
        await builder.db.flush()
        builder.add_relationship(
            from_key=native_key("threat_models", builder.threat_model_id),
            to_key=threat_key,
            relationship_type="has_threat",
            evidence_item=item or model_item,
            confidence_score=score,
        )
        finding = builder.add_finding(
            finding_key=json_key("finding", "threat", threat.id),
            finding_kind="modeled_threat",
            title=f"{threat.display_id}: {threat.stride_category}",
            description=threat.description,
            severity=threat.severity,
            status=_status_from_threat(threat.status),
            source=source,
            primary_item=item,
            confidence_score=score,
            source_system=threat.source,
            source_object_type="threat",
            source_object_id=str(threat.id),
            metadata={
                "rule_id": threat.rule_id,
                "threat_subtype": threat.threat_subtype,
                "relevance_rationale": threat.relevance_rationale,
            },
        )
        await builder.db.flush()
        builder.add_finding_link(
            finding=finding,
            link_type="derived_from",
            evidence_item=item,
            entity_key=threat_key,
            confidence_score=score,
        )
        for node_id in threat.affected_node_ids or []:
            builder.add_relationship(
                from_key=threat_key,
                to_key=native_key("dfd_nodes", node_id),
                relationship_type="affects_node",
                evidence_item=item,
                confidence_score=score,
            )
            builder.add_finding_link(
                finding=finding,
                link_type="affects",
                evidence_item=item,
                entity_key=native_key("dfd_nodes", node_id),
                confidence_score=score,
            )
        for edge_id in threat.affected_edge_ids or []:
            builder.add_relationship(
                from_key=threat_key,
                to_key=native_key("dfd_edges", edge_id),
                relationship_type="affects_edge",
                evidence_item=item,
                confidence_score=score,
            )


async def _project_scans(
    builder: EvidenceProjectionBuilder, inputs: dict[str, list[Any]]
) -> None:
    findings_by_job: dict[UUID, list[ScanFinding]] = {}
    for finding in inputs["scan_findings"]:
        findings_by_job.setdefault(finding.scan_job_id, []).append(finding)
    artifacts_by_job: dict[UUID, list[ScanExecutionArtifact]] = {}
    for artifact in inputs["scan_artifacts"]:
        artifacts_by_job.setdefault(artifact.scan_job_id, []).append(artifact)

    for scan_job in inputs["scan_jobs"]:
        source = builder.add_source(
            stable_key=native_key("scan_jobs", scan_job.id),
            source_type="scan",
            source_name=f"{scan_job.tool_name} scan",
            provider=scan_job.tool_name,
            trust_level="verified" if scan_job.status == "completed" else "indicated",
            ingestion_mode="execution"
            if scan_job.tool_name not in {"external-report", "pentest-report"}
            else "import",
            collected_at=scan_job.completed_at or scan_job.created_at,
            payload={
                "status": scan_job.status,
                "tool_name": scan_job.tool_name,
                "target_type": scan_job.target_type,
                "targets": scan_job.targets or {},
                "finding_count": scan_job.finding_count,
            },
        )
        score = 80.0 if scan_job.status == "completed" else 45.0
        item = builder.add_item(
            source=source,
            stable_key=json_key("item", "scan_job", scan_job.id),
            item_type="scan_job",
            title=f"{scan_job.tool_name} scan",
            summary=f"{scan_job.status} scan with {scan_job.finding_count} finding(s)",
            raw_payload={
                "scan_type": scan_job.scan_type,
                "scope": scan_job.scope,
                "target_type": scan_job.target_type,
                "targets": scan_job.targets or {},
                "error_message": scan_job.error_message,
            },
            confidence_score=score,
            observed_at=scan_job.completed_at
            or scan_job.started_at
            or scan_job.created_at,
        )
        scan_key = native_key("scan_jobs", scan_job.id)
        builder.add_entity(
            entity_type="scan_job",
            canonical_key=scan_key,
            display_name=f"{scan_job.tool_name} scan",
            source_object_type="scan_job",
            source_object_id=str(scan_job.id),
            properties={
                "status": scan_job.status,
                "tool_name": scan_job.tool_name,
                "target_type": scan_job.target_type,
                "targets": scan_job.targets or {},
            },
        )
        await builder.db.flush()
        builder.add_relationship(
            from_key=native_key("threat_models", builder.threat_model_id),
            to_key=scan_key,
            relationship_type="has_scan_job",
            evidence_item=item,
            confidence_score=score,
        )
        for node_id, target in (scan_job.targets or {}).items():
            target_key = json_key(
                "scan_target", builder.threat_model_id, node_id, target
            )
            builder.add_entity(
                entity_type="scan_target",
                canonical_key=target_key,
                display_name=str(target),
                source_object_type="scan_target",
                source_object_id=str(node_id),
                properties={"target": target, "target_type": scan_job.target_type},
            )
            await builder.db.flush()
            builder.add_relationship(
                from_key=scan_key,
                to_key=target_key,
                relationship_type="scanned_target",
                evidence_item=item,
                confidence_score=score,
            )

        for artifact in artifacts_by_job.get(scan_job.id, []):
            builder.add_item(
                source=source,
                stable_key=json_key("item", "scan_artifact", artifact.id),
                item_type="scan_execution_artifact",
                title=f"{artifact.tool_name} {artifact.status} artifact",
                summary=artifact.policy_decision,
                raw_payload={
                    "source": artifact.source,
                    "status": artifact.status,
                    "target": artifact.target,
                    "resolved_target": artifact.resolved_target,
                    "deterministic": artifact.deterministic,
                    "sandboxed": artifact.sandboxed,
                    "sandbox_mode": artifact.sandbox_mode,
                    "output_sha256": artifact.output_sha256,
                    "duration_ms": artifact.duration_ms,
                },
                confidence_score=score,
                observed_at=artifact.completed_at or artifact.created_at,
            )

        for scan_finding in findings_by_job.get(scan_job.id, []):
            finding_score = 80.0 if scan_job.status == "completed" else 50.0
            scan_item = builder.add_item(
                source=source,
                stable_key=json_key("item", "scan_finding", scan_finding.id),
                item_type="scan_finding",
                title=scan_finding.template_name,
                summary=scan_finding.extracted_results,
                raw_ref=scan_finding.matched_at,
                raw_payload=scan_finding.raw_output or {},
                confidence_score=finding_score,
                observed_at=scan_finding.created_at,
            )
            await builder.db.flush()
            finding = builder.add_finding(
                finding_key=json_key("finding", "scan", scan_finding.id),
                finding_kind="scan_finding",
                title=scan_finding.template_name,
                description=scan_finding.extracted_results
                or scan_finding.template_name,
                severity=_severity_from_scan(scan_finding.severity),
                status="open",
                source=source,
                primary_item=scan_item,
                confidence_score=finding_score,
                source_system=scan_job.tool_name,
                source_object_type="scan_finding",
                source_object_id=str(scan_finding.id),
                metadata={
                    "template_id": scan_finding.template_id,
                    "matched_at": scan_finding.matched_at,
                    "cve_ids": scan_finding.cve_ids or [],
                    "tags": scan_finding.tags or [],
                    "cvss_score": scan_finding.cvss_score,
                    "deterministic": scan_finding.deterministic,
                },
            )
            await builder.db.flush()
            builder.add_finding_link(
                finding=finding,
                link_type="supports",
                evidence_item=scan_item,
                entity_key=scan_key,
                confidence_score=finding_score,
                rationale="Scanner output reported this finding.",
            )

    threat_by_id = {threat.id: threat for threat in inputs["threats"]}
    scan_job_by_id = {scan.id: scan for scan in inputs["scan_jobs"]}
    for scan_result in inputs["scan_results"]:
        threat = threat_by_id.get(scan_result.threat_id)
        scan_job = scan_job_by_id.get(scan_result.scan_job_id)
        if threat is None or scan_job is None:
            continue
        relationship_type = "validates_threat"
        if scan_result.scan_status in {"mitigated", "not_found"}:
            relationship_type = "refutes_threat"
        elif scan_result.scan_status == "unverifiable":
            relationship_type = "needs_evidence"
        builder.add_relationship(
            from_key=native_key("scan_jobs", scan_result.scan_job_id),
            to_key=native_key("threats", scan_result.threat_id),
            relationship_type=relationship_type,
            confidence_score=75.0,
            rationale=f"Scan mapping status: {scan_result.scan_status}",
            properties={
                "cve_ids": scan_result.cve_ids or [],
                "evidence": scan_result.evidence or [],
            },
        )
        threat_finding = builder.findings.get(
            json_key("finding", "threat", scan_result.threat_id)
        )
        if threat_finding is None:
            continue
        link_type = "supports"
        if scan_result.scan_status in {"mitigated", "not_found"}:
            link_type = "refutes"
        elif scan_result.scan_status == "unverifiable":
            link_type = "needs_evidence"
        builder.add_finding_link(
            finding=threat_finding,
            link_type=link_type,
            evidence_item=builder.items.get(
                json_key("item", "scan_job", scan_result.scan_job_id)
            ),
            entity_key=native_key("scan_jobs", scan_result.scan_job_id),
            confidence_score=85.0 if scan_result.scan_status == "confirmed" else 70.0,
            rationale=f"Scan mapping status: {scan_result.scan_status}",
        )
