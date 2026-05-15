"""Threat-model orchestration endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.orchestration import OrchestrationJobCreate, OrchestrationJobResponse
from app.services.auth import get_current_user
from app.services.model_collaboration import require_model_permission
from app.services.orchestration import (
    OrchestrationIdempotencyConflict,
    create_orchestration_job,
    ensure_idempotent_request_matches,
    get_orchestration_job,
    get_orchestration_job_by_idempotency_key,
    list_orchestration_jobs,
    serialize_orchestration_job,
)
from app.services.orchestration_worker import run_orchestration_job
from app.services.threat_model import get_threat_model

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/orchestration",
    tags=["orchestration"],
)


async def _load_permitted_threat_model(
    db: AsyncSession,
    threat_model_id: UUID,
    current_user: User,
    permission: str = "read",
):
    threat_model = await get_threat_model(db, threat_model_id)
    return require_model_permission(threat_model, current_user, permission)  # type: ignore[arg-type]


@router.get("/jobs", response_model=list[OrchestrationJobResponse])
async def list_jobs(
    threat_model_id: UUID,
    limit: int = Query(default=100, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[OrchestrationJobResponse]:
    await _load_permitted_threat_model(db, threat_model_id, current_user)
    jobs = await list_orchestration_jobs(db, threat_model_id, limit=limit)
    return [serialize_orchestration_job(job) for job in jobs]


@router.post("/jobs", response_model=OrchestrationJobResponse)
async def create_job(
    threat_model_id: UUID,
    request: OrchestrationJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrchestrationJobResponse:
    threat_model = await _load_permitted_threat_model(
        db,
        threat_model_id,
        current_user,
        permission="write",
    )
    try:
        job = await create_orchestration_job(
            db,
            threat_model,
            owner_id=current_user.id,
            request=request,
        )
        await db.commit()
    except OrchestrationIdempotencyConflict as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except IntegrityError:
        await db.rollback()
        if not request.idempotency_key:
            raise
        job = await get_orchestration_job_by_idempotency_key(
            db,
            threat_model_id,
            owner_id=current_user.id,
            idempotency_key=request.idempotency_key,
        )
        if job is None:
            raise
        try:
            ensure_idempotent_request_matches(job, request)
        except OrchestrationIdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    reloaded = await get_orchestration_job(db, threat_model_id, job.id)
    return serialize_orchestration_job(reloaded or job)


@router.get("/jobs/{job_id}", response_model=OrchestrationJobResponse)
async def get_job(
    threat_model_id: UUID,
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrchestrationJobResponse:
    await _load_permitted_threat_model(db, threat_model_id, current_user)
    job = await get_orchestration_job(db, threat_model_id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Orchestration job not found.")
    return serialize_orchestration_job(job)


@router.post("/jobs/{job_id}/run", response_model=OrchestrationJobResponse)
async def run_job(
    threat_model_id: UUID,
    job_id: UUID,
    max_tasks: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrchestrationJobResponse:
    await _load_permitted_threat_model(
        db,
        threat_model_id,
        current_user,
        permission="write",
    )
    job = await get_orchestration_job(db, threat_model_id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Orchestration job not found.")
    if job.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the job owner can run this orchestration job.")
    reloaded = await run_orchestration_job(
        db,
        threat_model_id=threat_model_id,
        job_id=job_id,
        max_tasks=max_tasks,
    )
    if reloaded is None:
        raise HTTPException(status_code=404, detail="Orchestration job not found.")
    return serialize_orchestration_job(reloaded)
