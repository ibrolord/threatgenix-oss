"""Scan API — create, query, and cancel vulnerability scan jobs."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.dfd import DFDNode
from app.models.scan import (
    ScanAuthorization,
    ScanCredential,
    ScanExecutionArtifact,
    ScanJob,
    ScanThreatResult,
)
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.scan import (
    AUTHORIZATION_TEXT,
    EvidenceIngestRequest,
    ScanCreateRequest,
    ScanCorrelationSummaryResponse,
    ScanJobDetailResponse,
    ScanJobResponse,
    ScanThreatResultResponse,
    ThreatScanCorrelationResponse,
    ValidationArtifactBundleImportResponse,
    ValidationArtifactBundleResponse,
    ValidationRunRequest,
    ValidationRunbookResponse,
)
from app.services.auth import get_current_user
from app.services.model_collaboration import require_model_permission
from app.services.scan_mapper import run_semantic_mapping
from app.services.scan_worker import run_scan_job
from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target
from app.services.validation_runbook import build_validation_runbook
from app.services.validation_binding import infer_validation_targets_for_findings
from app.services.validation_execution_policy import (
    TARGET_AI_SYSTEM,
    TARGET_IAC_DIRECTORY,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    TARGET_URL,
    default_evidence_ingest_policy_registry,
    default_validation_execution_policy_registry,
)
from app.services.validation_runtime import (
    inline_validation_execution_enabled,
    validation_run_submission_blocked_reason,
    validation_run_submission_enabled,
)
from app.services.validation_tools import (
    EVIDENCE_IMPORT_TOOL_NAMES,
    default_evidence_import_tool_registry,
    default_validation_tool_registry,
    sanitize_validation_target_for_storage,
)
from app.services.validation_artifact_bundles import (
    build_single_validation_artifact_input,
    import_validation_artifact_bundle,
    parse_validation_artifact_bundle_upload,
    validation_artifact_bundle_size_limit,
)
from app.services.validation_target_bundles import (
    ValidationTargetBundleError,
    is_validation_target_bundle_ref,
    validate_target_bundle_ref_for_model,
)

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/scans",
    tags=["scans"],
)
logger = logging.getLogger("threatgenix.scans")
INGESTED_TARGET_KEY = (
    "ingested"  # Fallback key when parse-only evidence is not tied to a DFD node.
)
DIRECT_TARGET_KEY = "direct"
_HOSTED_TARGET_TYPES = {
    TARGET_REPOSITORY_PATH,
    TARGET_LOCKFILE,
    TARGET_IAC_DIRECTORY,
    TARGET_AI_SYSTEM,
}


def _scan_target_matches(matched_at: str, scan_target: str) -> bool:
    """Return whether a Nuclei matched-at URL belongs to a configured target."""
    matched = matched_at.strip().casefold()
    target = scan_target.strip().rstrip("/").casefold()
    if not matched or not target:
        return False
    return (
        matched == target
        or matched.startswith(f"{target}/")
        or matched.startswith(f"{target}?")
        or matched.startswith(f"{target}#")
    )


def _get_validation_tool_or_422(tool_name: str):
    try:
        return default_validation_tool_registry().get(tool_name)
    except KeyError:
        raise HTTPException(
            status_code=422, detail=f"Unsupported validation tool: {tool_name}"
        )


def _get_evidence_import_tool_or_422(tool_name: str):
    try:
        return default_evidence_import_tool_registry().get(tool_name)
    except KeyError:
        raise HTTPException(
            status_code=422, detail=f"Unsupported evidence source: {tool_name}"
        )


def _get_validation_policy_or_422(tool_name: str):
    try:
        return default_validation_execution_policy_registry().get(tool_name)
    except KeyError:
        raise HTTPException(
            status_code=422, detail=f"Unsupported validation tool: {tool_name}"
        )


def _get_evidence_ingest_policy_or_422(tool_name: str):
    try:
        return default_evidence_ingest_policy_registry().get(tool_name)
    except KeyError:
        raise HTTPException(
            status_code=422, detail=f"Unsupported evidence source: {tool_name}"
        )


def _raw_output_size(raw_output: str) -> int:
    return len(raw_output.encode("utf-8"))


def _client_ip_from_request(request: Request) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:45]
    if request.client:
        return request.client.host
    return None


def _validate_live_url_target_or_422(target: str) -> None:
    try:
        validate_live_url_target(target)
    except LiveTargetSafetyError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


def _require_validation_run_submission() -> None:
    if not validation_run_submission_enabled():
        raise HTTPException(
            status_code=403, detail=validation_run_submission_blocked_reason()
        )


def _queue_or_run_scan(background_tasks: BackgroundTasks, scan_job: ScanJob) -> None:
    if inline_validation_execution_enabled():
        background_tasks.add_task(run_scan_job, scan_job.id)


async def _get_threat_model_for_owner(
    threat_model_id: UUID,
    db: AsyncSession,
    current_user: User,
    permission: str = "write",
) -> ThreatModel:
    """Load a ThreatModel and verify ownership; raises 404/403 on failure."""
    result = await db.execute(
        select(ThreatModel).where(ThreatModel.id == threat_model_id)
    )
    tm = result.scalar_one_or_none()
    return require_model_permission(tm, current_user, permission)  # type: ignore[arg-type]


async def _get_scan_job(
    scan_id: UUID,
    threat_model_id: UUID,
    db: AsyncSession,
) -> ScanJob:
    """Load a ScanJob by id + threat_model_id; raises 404 if missing."""
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.threat_model_id == threat_model_id,
        )
    )
    scan_job = result.scalar_one_or_none()
    if scan_job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return scan_job


async def _get_latest_completed_scan(
    threat_model_id: UUID,
    db: AsyncSession,
) -> ScanJob:
    result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.threat_model_id == threat_model_id,
            ScanJob.status == "completed",
        )
        .order_by(ScanJob.completed_at.desc().nullslast(), ScanJob.created_at.desc())
    )
    scan_job = result.scalars().first()
    if scan_job is None:
        raise HTTPException(status_code=404, detail="No completed scan found")
    return scan_job


async def _build_scan_correlation_entries(
    db: AsyncSession,
    scan_job: ScanJob,
) -> list[ThreatScanCorrelationResponse]:
    node_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == scan_job.threat_model_id)
    )
    nodes = list(node_result.scalars().all())
    nodes_by_id = {str(node.id): node for node in nodes}
    target_index: dict[str, list[DFDNode]] = {}
    for node_id, target_url in (scan_job.targets or {}).items():
        node = nodes_by_id.get(str(node_id))
        normalized_target = str(target_url or "").strip()
        if node is None or not normalized_target:
            continue
        target_index.setdefault(normalized_target, []).append(node)

    for node in nodes:
        candidates = {
            (node.scan_target_url or "").strip(),
            node.name.strip(),
        }
        for candidate in candidates:
            if not candidate:
                continue
            target_index.setdefault(candidate, []).append(node)

    result = await db.execute(
        select(ScanThreatResult, Threat)
        .join(Threat, Threat.id == ScanThreatResult.threat_id)
        .where(ScanThreatResult.scan_job_id == scan_job.id)
        .order_by(Threat.severity.desc(), Threat.display_id.asc())
    )
    entries: list[ThreatScanCorrelationResponse] = []
    for threat_result, threat in result.all():
        evidence = threat_result.evidence or []
        matched_targets = sorted(
            {
                str(item.get("matched_at", ""))
                for item in evidence
                if item.get("matched_at")
            }
        )
        templates = sorted(
            {
                str(item.get("template_name", ""))
                for item in evidence
                if item.get("template_name")
            }
        )
        validation_tools = sorted(
            {
                str(item.get("tool_name", "")).strip()
                for item in evidence
                if item.get("tool_name")
            }
        )
        deterministic_evidence_count = sum(
            1 for item in evidence if item.get("deterministic") is True
        )
        matched_nodes: list[DFDNode] = []
        seen_node_ids: set[UUID] = set()
        finding_titles = sorted(
            {
                f"{str(item.get('template_name', '')).strip()} @ {str(item.get('matched_at', '')).strip()}".strip(
                    " @"
                )
                for item in evidence
                if item.get("template_name") or item.get("matched_at")
            }
        )
        for target in matched_targets:
            for configured_target, target_nodes in target_index.items():
                if not _scan_target_matches(target, configured_target):
                    continue
                for node in target_nodes:
                    if node.id in seen_node_ids:
                        continue
                    seen_node_ids.add(node.id)
                    matched_nodes.append(node)
        entries.append(
            ThreatScanCorrelationResponse(
                scan_job_id=scan_job.id,
                scan_completed_at=scan_job.completed_at,
                threat_id=threat.id,
                threat_display_id=threat.display_id,
                threat_description=threat.description,
                severity=threat.severity,
                stride_category=threat.stride_category,
                scan_status=threat_result.scan_status,
                evidence_count=len(evidence),
                cve_ids=threat_result.cve_ids or [],
                matched_targets=matched_targets[:10],
                templates=templates[:10],
                matched_node_ids=[node.id for node in matched_nodes[:10]],
                matched_node_labels=[node.name for node in matched_nodes[:10]],
                finding_titles=finding_titles[:10],
                validation_tools=validation_tools[:10],
                deterministic_evidence_count=deterministic_evidence_count,
                evidence=evidence[:10],
            )
        )
    return entries


# ---------------------------------------------------------------------------
# POST /api/threat-models/{threat_model_id}/scans
# ---------------------------------------------------------------------------


@router.post("", response_model=ScanJobResponse, status_code=201)
async def create_scan(
    threat_model_id: UUID,
    body: ScanCreateRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJobResponse:
    """Create and queue a new vulnerability scan job for a threat model.

    Requires the caller to set ``authorization_acknowledged=true`` to confirm
    they have permission to scan all listed targets.
    """
    # 1. Ownership check
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="write"
    )
    _require_validation_run_submission()

    # 2. Authorization gate
    if not body.authorization_acknowledged:
        raise HTTPException(
            status_code=400,
            detail=(
                "Authorization acknowledgment required. You must confirm "
                "authorization to scan all targets."
            ),
        )

    # 3. Collect targets from DFD nodes
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    nodes = nodes_result.scalars().all()
    node_ids: set[str] = {str(n.id) for n in nodes}

    targets: dict[str, str] = {}
    for node in nodes:
        if node.scan_target_url:
            targets[str(node.id)] = node.scan_target_url

    # 4. Validate and merge caller overrides (caller wins for existing nodes)
    for override_node_id, override_url in body.target_overrides.items():
        if override_node_id not in node_ids:
            raise HTTPException(
                status_code=422,
                detail=f"target_overrides contains unknown node_id: {override_node_id}",
            )
        if not override_url or not override_url.strip():
            raise HTTPException(
                status_code=422,
                detail=f"target_overrides value for node {override_node_id} must not be blank",
            )
        targets[override_node_id] = override_url.strip()

    # Strip any blank URLs that may have come from DFD nodes (defensive)
    targets = {k: v for k, v in targets.items() if v and v.strip()}

    if not targets:
        raise HTTPException(
            status_code=400,
            detail=(
                "No scan targets configured. Add scan_target_url to DFD nodes first."
            ),
        )

    if body.target_type != TARGET_URL:
        raise HTTPException(
            status_code=422,
            detail="Live DFD scans currently support target_type=url only.",
        )

    for target in targets.values():
        _validate_live_url_target_or_422(target)

    _get_validation_tool_or_422(body.tool_name)
    policy = _get_validation_policy_or_422(body.tool_name)
    for target in targets.values():
        decision = policy.evaluate(body.target_type, target)
        if not decision.allowed:
            raise HTTPException(status_code=400, detail=decision.reason)

    # 5. Capture client IP server-side (not from request body to prevent forgery)
    client_ip = _client_ip_from_request(request)

    # 5b. Validate credential ownership (authenticated scans only)
    if body.credential_id is not None:
        cred_result = await db.execute(
            select(ScanCredential).where(
                ScanCredential.id == body.credential_id,
                ScanCredential.owner_id == current_user.id,
                ScanCredential.threat_model_id == threat_model_id,
            )
        )
        if cred_result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=404,
                detail="Credential not found or does not belong to this threat model",
            )

    # 6. Persist ScanJob
    scan_job = ScanJob(
        threat_model_id=threat_model_id,
        owner_id=current_user.id,
        status="pending",
        scan_type=body.scan_type.value,
        scope=body.scope.value,
        tool_name=body.tool_name,
        target_type=body.target_type,
        targets=targets,
        nuclei_templates=[],
        finding_count=0,
        credential_id=body.credential_id,
    )
    db.add(scan_job)
    await db.flush()  # populate scan_job.id before creating authorization

    # 7. Persist ScanAuthorization
    authorization = ScanAuthorization(
        scan_job_id=scan_job.id,
        user_id=current_user.id,
        acknowledged_text=AUTHORIZATION_TEXT,
        ip_address=client_ip,
        targets_snapshot=targets,
    )
    db.add(authorization)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=404,
            detail="Credential not found or does not belong to this threat model",
        )
    await db.refresh(scan_job)

    logger.info(
        "scan_created job_id=%s threat_model_id=%s user_id=%s targets=%d",
        scan_job.id,
        threat_model_id,
        current_user.id,
        len(targets),
    )

    _queue_or_run_scan(background_tasks, scan_job)

    return ScanJobResponse.model_validate(scan_job)


# ---------------------------------------------------------------------------
# GET /api/threat-models/{threat_model_id}/scans
# ---------------------------------------------------------------------------


@router.get("", response_model=list[ScanJobResponse])
async def list_scans(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanJobResponse]:
    """List all scan jobs for a threat model, ordered newest first."""
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )

    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.threat_model_id == threat_model_id)
        .order_by(ScanJob.created_at.desc())
    )
    jobs = result.scalars().all()
    return [ScanJobResponse.model_validate(j) for j in jobs]


@router.post("/validation-run", response_model=ScanJobResponse, status_code=201)
async def create_validation_run(
    threat_model_id: UUID,
    body: ValidationRunRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJobResponse:
    """Create a live validation run for one explicit target."""
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="write"
    )
    _require_validation_run_submission()

    if not body.authorization_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Authorization acknowledgment required before executing a validation tool.",
        )

    _get_validation_tool_or_422(body.tool_name)
    policy = _get_validation_policy_or_422(body.tool_name)
    target = body.target.strip()
    target_type = body.target_type.strip()
    if is_validation_target_bundle_ref(target):
        if target_type not in _HOSTED_TARGET_TYPES:
            raise HTTPException(
                status_code=422,
                detail="Hosted validation target bundles only support path-based target types.",
            )
        try:
            await validate_target_bundle_ref_for_model(
                db,
                threat_model_id=threat_model_id,
                owner_id=current_user.id,
                target_ref=target,
            )
        except ValidationTargetBundleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif target_type == TARGET_URL:
        _validate_live_url_target_or_422(target)
    decision = policy.evaluate(target_type, target)
    if not decision.allowed:
        raise HTTPException(status_code=400, detail=decision.reason)

    targets: dict[str, str]
    if body.target_node_id is not None:
        node_result = await db.execute(
            select(DFDNode).where(
                DFDNode.id == body.target_node_id,
                DFDNode.threat_model_id == threat_model_id,
            )
        )
        node = node_result.scalar_one_or_none()
        if node is None:
            raise HTTPException(
                status_code=422,
                detail="target_node_id does not belong to this threat model",
            )
        targets = {str(node.id): target}
    else:
        targets = {DIRECT_TARGET_KEY: target}

    scan_job = ScanJob(
        threat_model_id=threat_model_id,
        owner_id=current_user.id,
        status="pending",
        scan_type="unauthenticated",
        scope=body.scope.value,
        tool_name=body.tool_name,
        target_type=target_type,
        targets=targets,
        nuclei_templates=[],
        finding_count=0,
        credential_id=None,
    )
    db.add(scan_job)
    await db.flush()

    authorization = ScanAuthorization(
        scan_job_id=scan_job.id,
        user_id=current_user.id,
        acknowledged_text=AUTHORIZATION_TEXT,
        ip_address=_client_ip_from_request(request),
        targets_snapshot=targets,
    )
    db.add(authorization)
    await db.commit()
    await db.refresh(scan_job)

    _queue_or_run_scan(background_tasks, scan_job)
    logger.info(
        "validation_run_created job_id=%s threat_model_id=%s user_id=%s tool=%s target_type=%s",
        scan_job.id,
        threat_model_id,
        current_user.id,
        body.tool_name,
        target_type,
    )
    return ScanJobResponse.model_validate(scan_job)


@router.post("/ingest-evidence", response_model=ScanJobDetailResponse, status_code=201)
async def ingest_scan_evidence(
    threat_model_id: UUID,
    body: EvidenceIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJobDetailResponse:
    """Parse pre-captured tool output and map it to threats.

    This endpoint never executes scanner binaries. It accepts JSON output
    produced elsewhere, normalizes it through the selected adapter, persists
    compatible ScanFinding rows, and runs the existing semantic mapper.
    """
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="write"
    )

    adapter = _get_evidence_import_tool_or_422(body.tool_name)
    policy = _get_evidence_ingest_policy_or_422(body.tool_name)
    target = body.target.strip()
    target_type = body.target_type.strip()

    decision = policy.evaluate_parse_only(target_type, target)
    if not decision.allowed:
        raise HTTPException(status_code=422, detail=decision.reason)

    if _raw_output_size(body.raw_output) > policy.max_output_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"{body.tool_name} evidence exceeds max_output_bytes="
                f"{policy.max_output_bytes}"
            ),
        )

    parsed_findings = adapter.parse_output(target, body.raw_output)
    targets: dict[str, str] = {}
    if body.target_node_id is not None:
        node_result = await db.execute(
            select(DFDNode).where(
                DFDNode.id == body.target_node_id,
                DFDNode.threat_model_id == threat_model_id,
            )
        )
        node = node_result.scalar_one_or_none()
        if node is None:
            raise HTTPException(
                status_code=422,
                detail="target_node_id does not belong to this threat model",
            )
        targets[str(node.id)] = target
        if body.tool_name in EVIDENCE_IMPORT_TOOL_NAMES:
            parsed_findings = [
                replace(evidence, matched_url=target) for evidence in parsed_findings
            ]
    elif target_type == TARGET_URL:
        node_result = await db.execute(
            select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
        )
        for node in node_result.scalars().all():
            configured_target = (node.scan_target_url or "").strip()
            if configured_target and (
                _scan_target_matches(target, configured_target)
                or _scan_target_matches(configured_target, target)
            ):
                targets[str(node.id)] = configured_target

    if not targets:
        node_result = await db.execute(
            select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
        )
        targets = infer_validation_targets_for_findings(
            node_result.scalars().all(),
            parsed_findings,
            target_type=target_type,
        )

    if not targets:
        targets = {INGESTED_TARGET_KEY: target}

    now = datetime.now(timezone.utc)
    scan_job = ScanJob(
        threat_model_id=threat_model_id,
        owner_id=current_user.id,
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name=body.tool_name,
        target_type=target_type,
        targets=targets,
        nuclei_templates=[],
        started_at=now,
        completed_at=now,
        finding_count=len(parsed_findings),
    )
    db.add(scan_job)
    await db.flush()

    for evidence in parsed_findings:
        db.add(
            evidence.to_scan_finding(
                scan_job.id,
                target_type=target_type,
                evidence_origin="import",
                synthetic=False,
            )
        )
    db.add(
        ScanExecutionArtifact(
            scan_job_id=scan_job.id,
            source="ingest",
            tool_name=body.tool_name,
            target_type=target_type,
            target=sanitize_validation_target_for_storage(target, target_type)
            or target,
            resolved_target=sanitize_validation_target_for_storage(target, target_type),
            status="completed",
            deterministic=adapter.deterministic,
            sandboxed=False,
            sandbox_mode=None,
            container_image=None,
            resource_limits={},
            policy_decision=decision.reason,
            command=[],
            command_redacted=True,
            returncode=0,
            timed_out=False,
            output_limit_exceeded=False,
            stdout_bytes=_raw_output_size(body.raw_output),
            output_sha256=hashlib.sha256(body.raw_output.encode("utf-8")).hexdigest(),
            stderr_summary=None,
            network_mode=policy.network_mode,
            max_runtime_seconds=None,
            max_output_bytes=policy.max_output_bytes,
            started_at=now,
            completed_at=now,
            duration_ms=0,
        )
    )

    await db.flush()
    await run_semantic_mapping(db, scan_job.id)
    await db.commit()

    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.id == scan_job.id)
        .options(
            selectinload(ScanJob.findings),
            selectinload(ScanJob.threat_results),
            selectinload(ScanJob.execution_artifacts),
        )
    )
    created_job = result.scalar_one()
    return ScanJobDetailResponse.model_validate(created_job)


@router.post(
    "/artifact-bundles",
    response_model=ValidationArtifactBundleImportResponse,
    status_code=201,
)
async def upload_validation_artifact_bundle(
    threat_model_id: UUID,
    file: UploadFile = File(...),
    tool_name: str | None = Form(None),
    target_type: str | None = Form(None),
    target: str | None = Form(None),
    target_node_id: UUID | None = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationArtifactBundleImportResponse:
    """Upload pre-captured validation evidence as a tenant-scoped artifact.

    If tool metadata is supplied, the upload is treated as a single scanner
    output file. Without tool metadata, the upload must be a JSON/zip/tar
    bundle containing a validation manifest.
    """
    threat_model = await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="write"
    )
    content = await file.read(validation_artifact_bundle_size_limit() + 1)
    if len(content) > validation_artifact_bundle_size_limit():
        raise HTTPException(
            status_code=413,
            detail=(
                "Validation artifact bundle is too large. "
                f"Limit is {validation_artifact_bundle_size_limit()} bytes."
            ),
        )
    filename = file.filename or "validation-artifact"
    if tool_name or target_type or target:
        if not (tool_name and target_type and target):
            raise HTTPException(
                status_code=422,
                detail="tool_name, target_type, and target are required for single-file evidence uploads.",
            )
        inputs = [
            build_single_validation_artifact_input(
                tool_name=tool_name,
                target_type=target_type,
                target=target,
                target_node_id=target_node_id,
                raw_output=content,
                filename=filename,
            )
        ]
        manifest = {
            "items": [
                {
                    "tool_name": tool_name,
                    "target_type": target_type,
                    "target": sanitize_validation_target_for_storage(
                        target, target_type
                    )
                    or target,
                    "target_node_id": str(target_node_id) if target_node_id else None,
                    "path": filename,
                }
            ]
        }
    else:
        inputs, manifest = parse_validation_artifact_bundle_upload(content, filename)

    bundle, created_scans = await import_validation_artifact_bundle(
        db,
        threat_model=threat_model,
        current_user=current_user,
        filename=filename,
        content_type=file.content_type,
        content=content,
        inputs=inputs,
        manifest=manifest,
    )
    return ValidationArtifactBundleImportResponse(
        bundle=ValidationArtifactBundleResponse.model_validate(bundle),
        created_scans=created_scans,
    )


@router.get("/artifact-bundles", response_model=list[ValidationArtifactBundleResponse])
async def list_validation_artifact_bundles(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ValidationArtifactBundleResponse]:
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )
    from app.models.scan import ValidationArtifactBundle

    result = await db.execute(
        select(ValidationArtifactBundle)
        .where(ValidationArtifactBundle.threat_model_id == threat_model_id)
        .options(selectinload(ValidationArtifactBundle.items))
        .order_by(ValidationArtifactBundle.created_at.desc())
        .limit(25)
    )
    return [
        ValidationArtifactBundleResponse.model_validate(bundle)
        for bundle in result.scalars().all()
    ]


@router.get("/latest/runbook", response_model=ValidationRunbookResponse | None)
async def get_latest_validation_runbook(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationRunbookResponse | None:
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )
    try:
        latest_scan = await _get_latest_completed_scan(threat_model_id, db)
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise
    runbook = await build_validation_runbook(db, latest_scan.id)
    if runbook is None:
        return None
    return runbook


# ---------------------------------------------------------------------------
# GET /api/threat-models/{threat_model_id}/scans/{scan_id}
# ---------------------------------------------------------------------------


@router.get("/{scan_id}", response_model=ScanJobDetailResponse)
async def get_scan(
    threat_model_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJobDetailResponse:
    """Return a scan job with its findings and threat results."""
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )

    result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.id == scan_id,
            ScanJob.threat_model_id == threat_model_id,
        )
        .options(
            selectinload(ScanJob.findings),
            selectinload(ScanJob.threat_results),
            selectinload(ScanJob.execution_artifacts),
        )
    )
    scan_job = result.scalar_one_or_none()
    if scan_job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return ScanJobDetailResponse.model_validate(scan_job)


@router.get("/{scan_id}/runbook", response_model=ValidationRunbookResponse)
async def get_validation_runbook(
    threat_model_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationRunbookResponse:
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )
    scan_job = await _get_scan_job(scan_id, threat_model_id, db)
    runbook = await build_validation_runbook(db, scan_job.id)
    if runbook is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return runbook


# ---------------------------------------------------------------------------
# DELETE /api/threat-models/{threat_model_id}/scans/{scan_id}
# ---------------------------------------------------------------------------


@router.delete("/{scan_id}", status_code=204, response_model=None)
async def cancel_scan(
    threat_model_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cancel a pending or running scan job."""
    from datetime import datetime, timezone

    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="write"
    )

    scan_job = await _get_scan_job(scan_id, threat_model_id, db)

    if scan_job.status in ("pending", "running"):
        scan_job.status = "cancelled"
        scan_job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.info("scan_cancelled job_id=%s user_id=%s", scan_id, current_user.id)


# ---------------------------------------------------------------------------
# GET /api/threat-models/{threat_model_id}/scans/{scan_id}/threat-results
# ---------------------------------------------------------------------------


@router.get("/{scan_id}/threat-results", response_model=list[ScanThreatResultResponse])
async def list_threat_results(
    threat_model_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanThreatResultResponse]:
    """Return the per-threat scan results for a scan job (any status)."""
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )

    # Verify scan job belongs to this threat model
    await _get_scan_job(scan_id, threat_model_id, db)

    result = await db.execute(
        select(ScanThreatResult)
        .where(ScanThreatResult.scan_job_id == scan_id)
        .order_by(ScanThreatResult.created_at.asc())
    )
    threat_results = result.scalars().all()
    return [ScanThreatResultResponse.model_validate(tr) for tr in threat_results]


@router.get("/latest/threat-correlation", response_model=ScanCorrelationSummaryResponse)
async def get_latest_scan_correlation(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanCorrelationSummaryResponse:
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )
    latest_scan = await _get_latest_completed_scan(threat_model_id, db)
    entries = await _build_scan_correlation_entries(db, latest_scan)
    return ScanCorrelationSummaryResponse(
        scan_job_id=latest_scan.id,
        scan_completed_at=latest_scan.completed_at,
        total_correlations=len(entries),
        confirmed_count=sum(1 for entry in entries if entry.scan_status == "confirmed"),
        mitigated_count=sum(1 for entry in entries if entry.scan_status == "mitigated"),
        not_found_count=sum(1 for entry in entries if entry.scan_status == "not_found"),
        unverifiable_count=sum(
            1 for entry in entries if entry.scan_status == "unverifiable"
        ),
        entries=entries,
    )


@router.get(
    "/latest/threat-correlation/{threat_id}",
    response_model=ThreatScanCorrelationResponse,
)
async def get_latest_threat_correlation(
    threat_model_id: UUID,
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatScanCorrelationResponse:
    await _get_threat_model_for_owner(
        threat_model_id, db, current_user, permission="read"
    )
    latest_scan = await _get_latest_completed_scan(threat_model_id, db)
    entries = await _build_scan_correlation_entries(db, latest_scan)
    for entry in entries:
        if entry.threat_id == threat_id:
            return entry
    raise HTTPException(
        status_code=404, detail="No scan correlation found for this threat"
    )
