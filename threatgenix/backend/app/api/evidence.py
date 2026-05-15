"""Evidence graph read/projection endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.evidence import (
    EvidenceChainResponse,
    EvidenceCoverageResponse,
    EvidenceEntityResponse,
    EvidenceEntityNeighborhoodResponse,
    EvidenceFindingResponse,
    EvidenceGraphResponse,
    EvidenceStatusResponse,
)
from app.services.auth import get_current_user
from app.services.evidence_graph import (
    build_evidence_coverage,
    build_evidence_status,
    get_entity_neighborhood,
    get_evidence_chain,
    list_evidence_entities,
    list_evidence_findings,
    list_evidence_graph,
)
from app.services.evidence_projection import rebuild_evidence_graph
from app.services.model_collaboration import require_model_permission
from app.services.threat_model import get_threat_model

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/evidence",
    tags=["evidence"],
)


async def _load_permitted_threat_model(
    db: AsyncSession,
    threat_model_id: UUID,
    current_user: User,
    permission: str = "read",
):
    threat_model = await get_threat_model(db, threat_model_id)
    return require_model_permission(threat_model, current_user, permission)  # type: ignore[arg-type]


@router.get("/status", response_model=EvidenceStatusResponse)
async def get_evidence_status(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceStatusResponse:
    threat_model = await _load_permitted_threat_model(db, threat_model_id, current_user)
    return await build_evidence_status(db, threat_model)


@router.get("", response_model=EvidenceGraphResponse)
async def get_evidence_graph(
    threat_model_id: UUID,
    limit: int = Query(default=500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceGraphResponse:
    threat_model = await _load_permitted_threat_model(db, threat_model_id, current_user)
    return await list_evidence_graph(db, threat_model, limit=limit)


@router.get("/coverage", response_model=EvidenceCoverageResponse)
async def get_evidence_coverage(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceCoverageResponse:
    threat_model = await _load_permitted_threat_model(db, threat_model_id, current_user)
    return await build_evidence_coverage(db, threat_model)


@router.get("/neighborhood", response_model=EvidenceEntityNeighborhoodResponse)
async def get_evidence_neighborhood(
    threat_model_id: UUID,
    entity_id: UUID | None = Query(default=None),
    canonical_key: str | None = Query(default=None, max_length=700),
    depth: int = Query(default=1, ge=0, le=3),
    limit: int = Query(default=200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceEntityNeighborhoodResponse:
    await _load_permitted_threat_model(db, threat_model_id, current_user)
    if entity_id is None and not canonical_key:
        raise HTTPException(
            status_code=400,
            detail="Provide either entity_id or canonical_key.",
        )
    neighborhood = await get_entity_neighborhood(
        db,
        threat_model_id,
        entity_id=entity_id,
        canonical_key=canonical_key,
        depth=depth,
        limit=limit,
    )
    if neighborhood is None:
        raise HTTPException(status_code=404, detail="Evidence entity not found.")
    return neighborhood


@router.get("/evidence-chain", response_model=EvidenceChainResponse)
async def get_evidence_chain_for_finding(
    threat_model_id: UUID,
    finding_key: str | None = Query(default=None, max_length=700),
    source_object_type: str | None = Query(default=None, max_length=100),
    source_object_id: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceChainResponse:
    await _load_permitted_threat_model(db, threat_model_id, current_user)
    if not finding_key and not (source_object_type and source_object_id):
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide finding_key or both source_object_type and source_object_id."
            ),
        )
    chain = await get_evidence_chain(
        db,
        threat_model_id,
        finding_key=finding_key,
        source_object_type=source_object_type,
        source_object_id=source_object_id,
        limit=limit,
    )
    if chain is None:
        raise HTTPException(status_code=404, detail="Evidence finding not found.")
    return chain


@router.get("/entities", response_model=list[EvidenceEntityResponse])
async def get_evidence_entities(
    threat_model_id: UUID,
    entity_type: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[EvidenceEntityResponse]:
    await _load_permitted_threat_model(db, threat_model_id, current_user)
    return await list_evidence_entities(
        db,
        threat_model_id,
        entity_type=entity_type,
        limit=limit,
    )


@router.get("/findings", response_model=list[EvidenceFindingResponse])
async def get_evidence_findings(
    threat_model_id: UUID,
    finding_kind: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[EvidenceFindingResponse]:
    await _load_permitted_threat_model(db, threat_model_id, current_user)
    return await list_evidence_findings(
        db,
        threat_model_id,
        finding_kind=finding_kind,
        limit=limit,
    )


@router.post("/rebuild", response_model=EvidenceStatusResponse)
async def rebuild_evidence_projection(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceStatusResponse:
    threat_model = await _load_permitted_threat_model(
        db,
        threat_model_id,
        current_user,
        permission="write",
    )
    status = await rebuild_evidence_graph(db, threat_model)
    await db.commit()
    return status
