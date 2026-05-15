"""Threat-scoped model-agnostic agent orchestration endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import Threat
from app.models.user import User
from app.schemas.threat_agent_orchestration import (
    AgentToolCapabilityResponse,
    ThreatScanPlanApproveRequest,
    ThreatScanPlanCreate,
    ThreatScanPlanRejectRequest,
    ThreatRemediationEvidenceRequest,
    ThreatRemediationHandoffConfirmRequest,
    ThreatRemediationRunCreate,
    ThreatRemediationRunResponse,
    ThreatValidationRunCreate,
    ThreatValidationRunResponse,
)
from app.services.application_review import tenant_key_for_user
from app.services.auth import get_current_user
from app.services.model_collaboration import require_model_permission
from app.services.threat_agent_orchestration import (
    ThreatAgentOrchestrationError,
    attach_remediation_evidence,
    approve_threat_scan_plan,
    confirm_remediation_handoff,
    create_threat_scan_plan,
    create_threat_remediation_run,
    create_threat_validation_run,
    get_remediation_run,
    get_validation_run,
    list_agent_tool_capabilities,
    list_validation_runs,
    reject_threat_scan_plan,
    refresh_validation_run_from_controlled_scans,
    rerun_threat_validation,
    scan_job_ids_from_domain_results,
    serialize_remediation_run,
    serialize_validation_run,
)
from app.services.threat_model import get_threat_model
from app.services.scan_worker import run_scan_job
from app.services.validation_runtime import inline_validation_execution_enabled

router = APIRouter(prefix="/api", tags=["threat-agent-orchestration"])


@router.get(
    "/agent-tools/catalog",
    response_model=list[AgentToolCapabilityResponse],
)
async def get_agent_tool_catalog(
    current_user: User = Depends(get_current_user),
) -> list[AgentToolCapabilityResponse]:
    del current_user
    return list_agent_tool_capabilities()


@router.post(
    "/threat-models/{threat_model_id}/threats/{threat_id}/scan-plans",
    response_model=ThreatValidationRunResponse,
)
async def propose_threat_scan_plan(
    threat_model_id: UUID,
    threat_id: UUID,
    body: ThreatScanPlanCreate = ThreatScanPlanCreate(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    threat = await _get_threat_for_review(db, current_user, threat_model_id, threat_id)
    try:
        run = await create_threat_scan_plan(
            db,
            current_user=current_user,
            threat=threat,
            application_review_id=body.application_review_id,
            requested_tools=body.requested_tools,
            domain_agents=body.domain_agents,
            domain_agent_tools=body.domain_agent_tools,
            domain_agent_tool_mode=body.domain_agent_tool_mode,
            domain_agent_instructions=body.domain_agent_instructions,
            excluded_tools=body.excluded_tools,
            required_tools=body.required_tools,
            question=body.question,
        )
    except ThreatAgentOrchestrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = await serialize_validation_run(db, run)
    await db.commit()
    return response


@router.post(
    "/scan-plans/{scan_plan_id}/approve",
    response_model=ThreatValidationRunResponse,
)
async def approve_scan_plan(
    scan_plan_id: UUID,
    body: ThreatScanPlanApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    run = await _get_validation_or_404(db, current_user, scan_plan_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    try:
        updated = await approve_threat_scan_plan(
            db,
            current_user=current_user,
            run=run,
            body=body,
        )
    except ThreatAgentOrchestrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = await serialize_validation_run(db, updated)
    await db.commit()
    return response


@router.get(
    "/scan-plans/{scan_plan_id}",
    response_model=ThreatValidationRunResponse,
)
async def get_scan_plan(
    scan_plan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    run = await _get_validation_or_404(db, current_user, scan_plan_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    refreshed = await refresh_validation_run_from_controlled_scans(db, run)
    response = await serialize_validation_run(db, refreshed)
    await db.commit()
    return response


@router.post(
    "/scan-plans/{scan_plan_id}/reject",
    response_model=ThreatValidationRunResponse,
)
async def reject_scan_plan(
    scan_plan_id: UUID,
    body: ThreatScanPlanRejectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    run = await _get_validation_or_404(db, current_user, scan_plan_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    try:
        updated = await reject_threat_scan_plan(
            db,
            current_user=current_user,
            run=run,
            body=body,
        )
    except ThreatAgentOrchestrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = await serialize_validation_run(db, updated)
    await db.commit()
    return response


@router.post(
    "/threat-models/{threat_model_id}/threats/{threat_id}/validation-runs",
    response_model=ThreatValidationRunResponse,
)
async def start_threat_validation_run(
    threat_model_id: UUID,
    threat_id: UUID,
    background_tasks: BackgroundTasks,
    body: ThreatValidationRunCreate = ThreatValidationRunCreate(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    threat = await _get_threat_for_review(db, current_user, threat_model_id, threat_id)
    try:
        run = await create_threat_validation_run(
            db,
            current_user=current_user,
            threat=threat,
            application_review_id=body.application_review_id,
            requested_tools=body.requested_tools,
            domain_agents=body.domain_agents,
            domain_agent_tools=body.domain_agent_tools,
            domain_agent_tool_mode=body.domain_agent_tool_mode,
            domain_agent_instructions=body.domain_agent_instructions,
            domain_agent_targets=body.domain_agent_targets,
            excluded_tools=body.excluded_tools,
            required_tools=body.required_tools,
            question=body.question,
        )
    except ThreatAgentOrchestrationError as exc:
        status_code = 429 if "rate limit" in str(exc).casefold() else 422
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    response = await serialize_validation_run(db, run)
    await db.commit()
    _queue_inline_controlled_runner_scans(
        background_tasks,
        getattr(run, "domain_agent_results", None) or [],
    )
    return response


@router.get(
    "/threat-models/{threat_model_id}/threats/{threat_id}/validation-runs",
    response_model=list[ThreatValidationRunResponse],
)
async def list_threat_validation_runs(
    threat_model_id: UUID,
    threat_id: UUID,
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatValidationRunResponse]:
    await _get_threat_for_review(db, current_user, threat_model_id, threat_id)
    runs = await list_validation_runs(
        db,
        tenant_key=tenant_key_for_user(current_user),
        threat_id=threat_id,
        limit=limit,
    )
    refreshed = [await refresh_validation_run_from_controlled_scans(db, run) for run in runs]
    response = [await serialize_validation_run(db, run) for run in refreshed]
    await db.commit()
    return response


@router.get(
    "/threat-validations/{run_id}",
    response_model=ThreatValidationRunResponse,
)
async def get_threat_validation_run(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    run = await _get_validation_or_404(db, current_user, run_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    refreshed = await refresh_validation_run_from_controlled_scans(db, run)
    response = await serialize_validation_run(db, refreshed)
    await db.commit()
    return response


@router.post(
    "/threat-validations/{run_id}/rerun",
    response_model=ThreatValidationRunResponse,
)
async def rerun_threat_validation_run(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatValidationRunResponse:
    run = await _get_validation_or_404(db, current_user, run_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    try:
        new_run = await rerun_threat_validation(db, current_user=current_user, run=run)
    except ThreatAgentOrchestrationError as exc:
        status_code = 429 if "rate limit" in str(exc).casefold() else 422
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    response = await serialize_validation_run(db, new_run)
    await db.commit()
    return response


@router.post(
    "/threat-validations/{run_id}/remediation-runs",
    response_model=ThreatRemediationRunResponse,
)
async def start_threat_remediation_run(
    run_id: UUID,
    body: ThreatRemediationRunCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatRemediationRunResponse:
    validation_run = await _get_validation_or_404(db, current_user, run_id)
    await _require_run_review_access(db, current_user, validation_run.threat_model_id)
    try:
        run = await create_threat_remediation_run(
            db,
            current_user=current_user,
            validation_run=validation_run,
            agent_type=body.agent_type,
        )
    except ThreatAgentOrchestrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = await serialize_remediation_run(db, run)
    await db.commit()
    return response


@router.post(
    "/threat-remediations/{run_id}/confirm-handoff",
    response_model=ThreatRemediationRunResponse,
)
async def confirm_threat_remediation_handoff(
    run_id: UUID,
    body: ThreatRemediationHandoffConfirmRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatRemediationRunResponse:
    run = await _get_remediation_or_404(db, current_user, run_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    try:
        updated = await confirm_remediation_handoff(
            db,
            current_user=current_user,
            run=run,
            body=body,
        )
    except ThreatAgentOrchestrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = await serialize_remediation_run(db, updated)
    await db.commit()
    return response


@router.post(
    "/threat-remediations/{run_id}/evidence",
    response_model=ThreatRemediationRunResponse,
)
async def attach_threat_remediation_evidence(
    run_id: UUID,
    body: ThreatRemediationEvidenceRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatRemediationRunResponse:
    run = await _get_remediation_or_404(db, current_user, run_id)
    await _require_run_review_access(db, current_user, run.threat_model_id)
    updated = await attach_remediation_evidence(
        db,
        current_user=current_user,
        run=run,
        body=body,
    )
    response = await serialize_remediation_run(db, updated)
    await db.commit()
    return response


async def _get_threat_for_review(
    db: AsyncSession,
    current_user: User,
    threat_model_id: UUID,
    threat_id: UUID,
) -> Threat:
    threat_model = require_model_permission(
        await get_threat_model(db, threat_model_id),
        current_user,
        "review",
    )
    result = await db.execute(
        select(Threat).where(
            Threat.threat_model_id == threat_model.id,
            Threat.id == threat_id,
        )
    )
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found.")
    return threat


def _queue_inline_controlled_runner_scans(
    background_tasks: BackgroundTasks | None,
    domain_agent_results: list[dict],
) -> None:
    if background_tasks is None or not inline_validation_execution_enabled():
        return
    for scan_job_id in scan_job_ids_from_domain_results(domain_agent_results):
        background_tasks.add_task(run_scan_job, scan_job_id)


async def _require_run_review_access(
    db: AsyncSession,
    current_user: User,
    threat_model_id: UUID,
) -> None:
    require_model_permission(await get_threat_model(db, threat_model_id), current_user, "review")


async def _get_validation_or_404(
    db: AsyncSession,
    current_user: User,
    run_id: UUID,
):
    run = await get_validation_run(
        db,
        tenant_key=tenant_key_for_user(current_user),
        run_id=run_id,
    )
    if run is None:
        raise HTTPException(status_code=404, detail="Threat validation run not found.")
    return run


async def _get_remediation_or_404(
    db: AsyncSession,
    current_user: User,
    run_id: UUID,
):
    run = await get_remediation_run(
        db,
        tenant_key=tenant_key_for_user(current_user),
        run_id=run_id,
    )
    if run is None:
        raise HTTPException(status_code=404, detail="Threat remediation run not found.")
    return run
