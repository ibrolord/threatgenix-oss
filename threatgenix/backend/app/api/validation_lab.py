"""Validation Lab API for schedules, safety posture, and run-now workflows."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.dfd import DFDNode
from app.models.scan import (
    ScanAuthorization,
    ScanJob,
    ScanTargetAuthorization,
    ValidationSchedule,
)
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.scan import AUTHORIZATION_TEXT, ScanJobResponse
from app.schemas.validation_lab import (
    ProductSecurityValidationCaseResponse,
    ValidationCaseStateUpdateRequest,
    ValidationEvidenceBindingRequest,
    ValidationEvidenceBindingResponse,
    ValidationLabSummaryResponse,
    ValidationScheduleCreateRequest,
    ValidationScheduleResponse,
    ValidationScheduleRunRequest,
    ValidationScheduleUpdateRequest,
    ValidationTargetAuthorizationChallengeRequest,
    ValidationTargetAuthorizationChallengeResponse,
    ValidationTargetAuthorizationResponse,
    ValidationTargetAuthorizationVerifyRequest,
    ValidationTargetBundleResponse,
)
from app.services.auth import get_current_user
from app.services.model_collaboration import require_model_permission
from app.services.scan_worker import run_scan_job
from app.services.scan_target_authorization import (
    ScanTargetAuthorizationError,
    build_target_authorization_challenge,
    verify_http_target_authorization,
)
from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target
from app.services.validation_execution_policy import (
    TARGET_AI_SYSTEM,
    TARGET_IAC_DIRECTORY,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    default_validation_execution_policy_registry,
)
from app.services.validation_lab import (
    bind_validation_evidence_to_node,
    build_validation_lab_summary,
    create_try_sandbox_scan,
    next_run_at_for_cadence,
    update_product_security_case_state,
    validation_schedule_response,
    validation_target_bundle_response,
)
from app.services.validation_runtime import (
    RUNTIME_MANAGED,
    inline_validation_execution_enabled,
    validation_runtime_mode,
    validation_run_submission_blocked_reason,
    validation_run_submission_enabled,
)
from app.services.validation_sandbox import (
    ValidationSandboxTargetError,
    validate_validation_target_access,
    validate_validation_target_reference,
)
from app.services.validation_tools import default_validation_tool_registry
from app.services.validation_target_bundles import (
    ValidationTargetBundleError,
    create_validation_target_bundle,
    is_validation_target_bundle_ref,
    list_validation_target_bundles,
    validate_target_bundle_ref_for_model,
)

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/validation-lab",
    tags=["validation-lab"],
)

_PATH_TARGET_TYPES = {
    TARGET_REPOSITORY_PATH,
    TARGET_LOCKFILE,
    TARGET_IAC_DIRECTORY,
    TARGET_AI_SYSTEM,
}


def _client_ip_from_request(request: Request) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:45]
    if request.client:
        return request.client.host
    return None


async def _get_threat_model(
    threat_model_id: UUID,
    db: AsyncSession,
    current_user: User,
    permission: str,
) -> ThreatModel:
    result = await db.execute(
        select(ThreatModel).where(ThreatModel.id == threat_model_id)
    )
    tm = result.scalar_one_or_none()
    return require_model_permission(tm, current_user, permission)  # type: ignore[arg-type]


async def _get_schedule(
    db: AsyncSession,
    threat_model_id: UUID,
    schedule_id: UUID,
) -> ValidationSchedule:
    result = await db.execute(
        select(ValidationSchedule).where(
            ValidationSchedule.id == schedule_id,
            ValidationSchedule.threat_model_id == threat_model_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if schedule is None:
        raise HTTPException(status_code=404, detail="Validation schedule not found")
    return schedule


async def _validate_target_node(
    db: AsyncSession,
    threat_model_id: UUID,
    target_node_id: UUID | None,
) -> None:
    if target_node_id is None:
        return
    result = await db.execute(
        select(DFDNode).where(
            DFDNode.id == target_node_id,
            DFDNode.threat_model_id == threat_model_id,
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=422,
            detail="target_node_id does not belong to this threat model",
        )


def _validate_tool_target(tool_name: str, target_type: str, target: str) -> None:
    try:
        default_validation_tool_registry().get(tool_name)
        policy = default_validation_execution_policy_registry().get(tool_name)
    except KeyError:
        raise HTTPException(
            status_code=422, detail=f"Unsupported validation tool: {tool_name}"
        )
    decision = policy.evaluate_parse_only(target_type, target)
    if not decision.allowed:
        raise HTTPException(status_code=422, detail=decision.reason)
    if is_validation_target_bundle_ref(target):
        if target_type not in _PATH_TARGET_TYPES:
            raise HTTPException(
                status_code=422,
                detail="Hosted validation target bundles only support path-based target types.",
            )
        return
    if target_type == "url":
        try:
            validate_live_url_target(target)
        except LiveTargetSafetyError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    else:
        try:
            if validation_runtime_mode() == RUNTIME_MANAGED:
                validate_validation_target_reference(target, target_type)
            else:
                validate_validation_target_access(target, target_type)
        except ValidationSandboxTargetError as exc:
            raise HTTPException(status_code=422, detail=str(exc))


async def _validate_hosted_target_ref(
    db: AsyncSession,
    threat_model_id: UUID,
    current_user: User,
    target: str,
) -> None:
    if not is_validation_target_bundle_ref(target):
        return
    try:
        await validate_target_bundle_ref_for_model(
            db,
            threat_model_id=threat_model_id,
            owner_id=current_user.id,
            target_ref=target,
        )
    except ValidationTargetBundleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _require_authorization_acknowledged(value: bool | None) -> None:
    if value is not True:
        raise HTTPException(
            status_code=400,
            detail="Authorization acknowledgment required before saving or executing validation targets.",
        )


def _require_validation_run_submission() -> None:
    if not validation_run_submission_enabled():
        raise HTTPException(
            status_code=403, detail=validation_run_submission_blocked_reason()
        )


def _queue_or_run_scan(background_tasks: BackgroundTasks, scan_job: ScanJob) -> None:
    if inline_validation_execution_enabled():
        background_tasks.add_task(run_scan_job, scan_job.id)


@router.get("", response_model=ValidationLabSummaryResponse)
async def get_validation_lab(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationLabSummaryResponse:
    await _get_threat_model(threat_model_id, db, current_user, "read")
    return await build_validation_lab_summary(db, threat_model_id)


@router.get(
    "/target-authorizations",
    response_model=list[ValidationTargetAuthorizationResponse],
)
async def list_target_authorizations(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ValidationTargetAuthorizationResponse]:
    await _get_threat_model(threat_model_id, db, current_user, "read")
    result = await db.execute(
        select(ScanTargetAuthorization)
        .where(
            ScanTargetAuthorization.threat_model_id == threat_model_id,
            ScanTargetAuthorization.owner_id == current_user.id,
        )
        .order_by(ScanTargetAuthorization.created_at.desc())
        .limit(50)
    )
    return [
        ValidationTargetAuthorizationResponse.model_validate(item)
        for item in result.scalars().all()
    ]


@router.post(
    "/target-authorizations/challenge",
    response_model=ValidationTargetAuthorizationChallengeResponse,
)
async def create_target_authorization_challenge(
    threat_model_id: UUID,
    body: ValidationTargetAuthorizationChallengeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationTargetAuthorizationChallengeResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    try:
        challenge = build_target_authorization_challenge(
            owner_id=current_user.id,
            threat_model_id=threat_model_id,
            target_url=body.target_url,
        )
    except (LiveTargetSafetyError, ScanTargetAuthorizationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ValidationTargetAuthorizationChallengeResponse(
        target_url=challenge.target_url,
        hostname=challenge.hostname,
        normalized_host=challenge.normalized_host,
        proof_method="http_file",
        proof_url=challenge.proof_url,
        proof_token=challenge.proof_token,
        expires_at=challenge.expires_at,
    )


@router.post(
    "/target-authorizations/verify",
    response_model=ValidationTargetAuthorizationResponse,
    status_code=201,
)
async def verify_target_authorization(
    threat_model_id: UUID,
    body: ValidationTargetAuthorizationVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationTargetAuthorizationResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    try:
        authorization = await verify_http_target_authorization(
            db,
            owner_id=current_user.id,
            threat_model_id=threat_model_id,
            target_url=body.target_url,
            proof_token=body.proof_token,
            proof_url=body.proof_url,
        )
    except (LiveTargetSafetyError, ScanTargetAuthorizationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ValidationTargetAuthorizationResponse.model_validate(authorization)


@router.get("/target-bundles", response_model=list[ValidationTargetBundleResponse])
async def get_validation_target_bundles(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ValidationTargetBundleResponse]:
    await _get_threat_model(threat_model_id, db, current_user, "read")
    bundles = await list_validation_target_bundles(db, threat_model_id)
    return [validation_target_bundle_response(bundle) for bundle in bundles]


@router.post(
    "/target-bundles", response_model=ValidationTargetBundleResponse, status_code=201
)
async def upload_validation_target_bundle(
    threat_model_id: UUID,
    file: UploadFile = File(...),
    name: str | None = Form(None),
    authorization_acknowledged: bool = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationTargetBundleResponse:
    threat_model = await _get_threat_model(threat_model_id, db, current_user, "write")
    _require_validation_run_submission()
    _require_authorization_acknowledged(authorization_acknowledged)
    try:
        content = await file.read()
        bundle = await create_validation_target_bundle(
            db,
            threat_model=threat_model,
            current_user=current_user,
            filename=file.filename or "validation-target",
            content_type=file.content_type,
            content=content,
            name=name,
        )
    except ValidationTargetBundleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return validation_target_bundle_response(bundle)


@router.post("/try-sandbox", response_model=ScanJobResponse, status_code=201)
async def run_try_sandbox(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJobResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    scan_job = await create_try_sandbox_scan(db, threat_model_id, current_user)
    return ScanJobResponse.model_validate(scan_job)


@router.patch("/cases/{case_key}", response_model=ProductSecurityValidationCaseResponse)
async def update_validation_case_state(
    threat_model_id: UUID,
    case_key: str,
    body: ValidationCaseStateUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProductSecurityValidationCaseResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    updated_case = await update_product_security_case_state(
        db,
        threat_model_id,
        case_key,
        body,
        current_user,
    )
    if updated_case is None:
        raise HTTPException(
            status_code=404,
            detail="Validation case not found in the current evidence runbook",
        )
    return updated_case


@router.post(
    "/evidence/{finding_id}/bind", response_model=ValidationEvidenceBindingResponse
)
async def bind_validation_evidence(
    threat_model_id: UUID,
    finding_id: UUID,
    body: ValidationEvidenceBindingRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationEvidenceBindingResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    try:
        response = await bind_validation_evidence_to_node(
            db,
            threat_model_id,
            finding_id,
            body.target_node_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if response is None:
        raise HTTPException(
            status_code=404, detail="Validation evidence finding not found"
        )
    return response


@router.post("/schedules", response_model=ValidationScheduleResponse, status_code=201)
async def create_validation_schedule(
    threat_model_id: UUID,
    body: ValidationScheduleCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationScheduleResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    _require_validation_run_submission()
    _require_authorization_acknowledged(body.authorization_acknowledged)
    _validate_tool_target(body.tool_name, body.target_type, body.target)
    await _validate_hosted_target_ref(db, threat_model_id, current_user, body.target)
    await _validate_target_node(db, threat_model_id, body.target_node_id)

    now = datetime.now(timezone.utc)
    schedule = ValidationSchedule(
        threat_model_id=threat_model_id,
        owner_id=current_user.id,
        target_node_id=body.target_node_id,
        name=body.name,
        tool_name=body.tool_name,
        target_type=body.target_type,
        target=body.target,
        scope=body.scope.value,
        cadence=body.cadence,
        enabled=body.enabled,
        authorization_required=True,
        authorization_acknowledged_at=now,
        next_run_at=next_run_at_for_cadence(body.cadence, from_time=now)
        if body.enabled
        else None,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return validation_schedule_response(schedule)


@router.patch("/schedules/{schedule_id}", response_model=ValidationScheduleResponse)
async def update_validation_schedule(
    threat_model_id: UUID,
    schedule_id: UUID,
    body: ValidationScheduleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationScheduleResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    _require_validation_run_submission()
    schedule = await _get_schedule(db, threat_model_id, schedule_id)

    sensitive_update = (
        any(
            value is not None
            for value in [body.tool_name, body.target_type, body.target, body.enabled]
        )
        or body.clear_target_node_id
        or body.target_node_id is not None
    )
    if sensitive_update:
        _require_authorization_acknowledged(body.authorization_acknowledged)
        schedule.authorization_acknowledged_at = datetime.now(timezone.utc)

    # Only revalidate tool/target if those fields are actually changing.
    # Name-only or cadence-only patches must not fail due to policy drift on
    # the stored (already-validated) target.
    if (
        body.tool_name is not None
        or body.target_type is not None
        or body.target is not None
    ):
        next_tool_name = body.tool_name or schedule.tool_name
        next_target_type = body.target_type or schedule.target_type
        next_target = body.target or schedule.target
        _validate_tool_target(next_tool_name, next_target_type, next_target)
        await _validate_hosted_target_ref(
            db, threat_model_id, current_user, next_target
        )

    if body.target_node_id is not None:
        await _validate_target_node(db, threat_model_id, body.target_node_id)
        schedule.target_node_id = body.target_node_id
    elif body.clear_target_node_id:
        schedule.target_node_id = None

    if body.name is not None:
        schedule.name = body.name
    if body.tool_name is not None:
        schedule.tool_name = body.tool_name
    if body.target_type is not None:
        schedule.target_type = body.target_type
    if body.target is not None:
        schedule.target = body.target
    if body.scope is not None:
        schedule.scope = body.scope.value
    if body.cadence is not None:
        schedule.cadence = body.cadence
    if body.enabled is not None:
        schedule.enabled = body.enabled

    now = datetime.now(timezone.utc)
    schedule.next_run_at = (
        next_run_at_for_cadence(schedule.cadence, from_time=now)
        if schedule.enabled
        else None
    )
    await db.commit()
    await db.refresh(schedule)
    return validation_schedule_response(schedule)


@router.delete("/schedules/{schedule_id}", status_code=204, response_model=None)
async def delete_validation_schedule(
    threat_model_id: UUID,
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    schedule = await _get_schedule(db, threat_model_id, schedule_id)
    await db.delete(schedule)
    await db.commit()


@router.post(
    "/schedules/{schedule_id}/run", response_model=ScanJobResponse, status_code=201
)
async def run_validation_schedule(
    threat_model_id: UUID,
    schedule_id: UUID,
    body: ValidationScheduleRunRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJobResponse:
    await _get_threat_model(threat_model_id, db, current_user, "write")
    _require_validation_run_submission()
    _require_authorization_acknowledged(body.authorization_acknowledged)
    schedule = await _get_schedule(db, threat_model_id, schedule_id)
    schedule_state = validation_schedule_response(schedule)
    if not schedule_state.runnable:
        raise HTTPException(
            status_code=400,
            detail=schedule_state.blocked_reason
            or "Validation schedule is not runnable.",
        )

    targets = (
        {str(schedule.target_node_id): schedule.target}
        if schedule.target_node_id is not None
        else {"direct": schedule.target}
    )
    scan_job = ScanJob(
        threat_model_id=threat_model_id,
        owner_id=current_user.id,
        status="pending",
        scan_type="unauthenticated",
        scope=schedule.scope,
        tool_name=schedule.tool_name,
        target_type=schedule.target_type,
        targets=targets,
        nuclei_templates=[],
        finding_count=0,
        credential_id=None,
    )
    db.add(scan_job)
    await db.flush()
    db.add(
        ScanAuthorization(
            scan_job_id=scan_job.id,
            user_id=current_user.id,
            acknowledged_text=AUTHORIZATION_TEXT,
            ip_address=_client_ip_from_request(request),
            targets_snapshot=targets,
        )
    )
    now = datetime.now(timezone.utc)
    schedule.last_run_at = now
    schedule.next_run_at = (
        next_run_at_for_cadence(schedule.cadence, from_time=now)
        if schedule.enabled
        else None
    )
    await db.commit()
    await db.refresh(scan_job)
    _queue_or_run_scan(background_tasks, scan_job)
    return ScanJobResponse.model_validate(scan_job)
