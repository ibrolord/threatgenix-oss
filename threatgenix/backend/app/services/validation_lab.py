"""Validation lab orchestration helpers."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dfd import DFDNode
from app.models.scan import (
    ScanExecutionArtifact,
    ScanFinding,
    ScanJob,
    ScanThreatResult,
    ValidationCaseEvent,
    ValidationCaseState,
    ValidationSchedule,
)
from app.models.user import User
from app.schemas.scan import ScanJobResponse
from app.schemas.validation_lab import (
    ProductSecurityValidationCaseResponse,
    ValidationCaseEventResponse,
    ValidationCaseStateUpdateRequest,
    ValidationCaseCheckResponse,
    ValidationDemoScenarioResponse,
    ValidationEvidenceBindingResponse,
    ValidationEvidenceLedgerEntryResponse,
    ValidationGapResponse,
    ValidationLabPostureResponse,
    ValidationLabSummaryResponse,
    ValidationRecommendedRunResponse,
    ValidationSafetyControlResponse,
    ValidationScheduleResponse,
    ValidationSetupLaneResponse,
    ValidationTargetBundleResponse,
    ValidationToolSetupProfileResponse,
)
from app.services.agentic_tool_bench import build_agentic_tool_bench
from app.services.scan_mapper import run_semantic_mapping
from app.services.validation_binding import binding_target_for_scan_finding
from app.services.validation_execution_policy import (
    NETWORK_NONE,
    TARGET_AI_SYSTEM,
    TARGET_IAC_DIRECTORY,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    TARGET_URL,
    build_validation_tool_inventory,
    default_validation_execution_policy_registry,
    managed_process_network_policy_blocked,
    validation_tool_runtime_availability,
)
from app.services.validation_runbook import build_validation_runbook
from app.services.validation_runtime import (
    RUNTIME_MANAGED,
    validation_runtime_mode,
    validation_run_submission_blocked_reason,
    validation_run_submission_enabled,
    validation_runtime_state,
)
from app.services.validation_runner_observability import get_runner_queue_status
from app.services.validation_sandbox import (
    ValidationSandboxTargetError,
    configured_validation_allowed_roots,
    validate_validation_target_access,
    validate_validation_target_reference,
    validation_container_runtime,
    validation_isolated_runner_ready_for,
    validation_process_sandbox_network_allowed,
    validation_sandbox_mode,
)
from app.services.validation_tools import (
    default_validation_tool_registry,
    sanitize_validation_target_for_storage,
)
from app.services.validation_target_bundles import (
    is_validation_target_bundle_ref,
    list_validation_target_bundles,
    target_ref_for_bundle,
)
from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target

_PATH_TARGET_TYPES = {
    TARGET_REPOSITORY_PATH,
    TARGET_LOCKFILE,
    TARGET_IAC_DIRECTORY,
    TARGET_AI_SYSTEM,
}
_GLOBAL_TARGET_KEYS = {"direct", "ingested", "try_sandbox"}


def next_run_at_for_cadence(
    cadence: str, *, from_time: datetime | None = None
) -> datetime | None:
    now = from_time or datetime.now(timezone.utc)
    if cadence == "daily":
        return now + timedelta(days=1)
    if cadence == "weekly":
        return now + timedelta(days=7)
    if cadence == "monthly":
        return now + timedelta(days=30)
    return None


async def build_validation_lab_summary(
    db: AsyncSession,
    threat_model_id: UUID,
) -> ValidationLabSummaryResponse:
    schedules = await list_validation_schedules(db, threat_model_id)
    target_bundles = await list_validation_target_bundles(db, threat_model_id)
    recent_scan_rows = await _recent_scans(db, threat_model_id)
    recent_scans = [ScanJobResponse.model_validate(s) for s in recent_scan_rows]
    latest_runbook = None
    latest_completed = next(
        (scan for scan in recent_scans if scan.status == "completed"), None
    )
    if latest_completed is not None:
        latest_runbook = await build_validation_runbook(db, latest_completed.id)

    inventory = build_validation_tool_inventory()
    ready_tool_count = sum(
        1 for item in inventory if item.active and item.readiness_status == "ready"
    )
    evidence_ledger = await _evidence_ledger(db, recent_scan_rows)
    posture = ValidationLabPostureResponse(
        schedule_count=len(schedules),
        enabled_schedule_count=sum(1 for schedule in schedules if schedule.enabled),
        recent_scan_count=len(recent_scans),
        ready_tool_count=ready_tool_count,
        deterministic_tool_count=sum(1 for item in inventory if item.deterministic),
        ai_assisted_tool_count=sum(1 for item in inventory if not item.deterministic),
        validated_threat_count=latest_runbook.coverage.validated_threat_count
        if latest_runbook
        else 0,
        indicated_threat_count=latest_runbook.coverage.indicated_threat_count
        if latest_runbook
        else 0,
        untested_threat_count=latest_runbook.coverage.untested_threat_count
        if latest_runbook
        else 0,
        validated_risk_score=latest_runbook.coverage.validated_risk_score
        if latest_runbook
        else 0,
        indicated_risk_score=latest_runbook.coverage.indicated_risk_score
        if latest_runbook
        else 0,
        ai_assisted_risk_score=latest_runbook.coverage.ai_assisted_risk_score
        if latest_runbook
        else 0,
    )

    runtime = validation_runtime_state()
    runner_status = await get_runner_queue_status(db, threat_model_id=threat_model_id)
    product_security_cases = await apply_product_security_case_state(
        db,
        threat_model_id,
        build_product_security_cases(latest_runbook),
    )
    recommended_next_runs = _recommended_next_runs(
        inventory,
        latest_runbook is not None,
        run_submission_enabled=runtime.run_submission_enabled,
    )
    agentic_tool_bench = build_agentic_tool_bench(
        inventory=inventory,
        product_security_cases=product_security_cases,
        evidence_ledger=evidence_ledger,
        schedules=schedules,
        run_submission_enabled=runtime.run_submission_enabled,
        recommended_next_runs=recommended_next_runs,
    )
    return ValidationLabSummaryResponse(
        threat_model_id=threat_model_id,
        runtime=asdict(runtime),
        runner_status=asdict(runner_status),
        posture=posture,
        tools=[asdict(item) for item in inventory],
        red_team_tools=[],
        setup_lanes=_setup_lanes(
            run_submission_enabled=runtime.run_submission_enabled,
            managed_runner_enabled=runtime.managed_runner_enabled,
        ),
        tool_setup_profiles=_tool_setup_profiles(inventory),
        target_bundles=[
            validation_target_bundle_response(bundle) for bundle in target_bundles
        ],
        schedules=schedules,
        recent_scans=recent_scans,
        latest_runbook=latest_runbook,
        product_security_cases=product_security_cases,
        evidence_ledger=evidence_ledger,
        gaps=_validation_gaps(
            posture_ready_tool_count=ready_tool_count,
            schedules=schedules,
            latest_runbook=latest_runbook,
            scheduler_enabled=_scheduler_enabled(),
            run_submission_enabled=runtime.run_submission_enabled,
        ),
        demo_scenario=_demo_scenario(),
        safety_controls=_safety_controls(),
        recommended_next_runs=recommended_next_runs,
        agentic_tool_bench=agentic_tool_bench,
    )


async def list_validation_schedules(
    db: AsyncSession,
    threat_model_id: UUID,
) -> list[ValidationScheduleResponse]:
    result = await db.execute(
        select(ValidationSchedule)
        .where(ValidationSchedule.threat_model_id == threat_model_id)
        .order_by(ValidationSchedule.created_at.desc())
    )
    schedules = list(result.scalars().all())
    return [validation_schedule_response(schedule) for schedule in schedules]


async def due_validation_schedules(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 25,
) -> list[ValidationSchedule]:
    """Return enabled schedules due for a cron/CI runner to enqueue."""
    cutoff = now or datetime.now(timezone.utc)
    result = await db.execute(
        select(ValidationSchedule)
        .where(
            ValidationSchedule.enabled.is_(True),
            ValidationSchedule.next_run_at.is_not(None),
            ValidationSchedule.next_run_at <= cutoff,
        )
        .order_by(ValidationSchedule.next_run_at.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


def validation_schedule_response(
    schedule: ValidationSchedule,
) -> ValidationScheduleResponse:
    runnable, blocked_reason = _schedule_runnable(schedule)
    return ValidationScheduleResponse(
        id=schedule.id,
        threat_model_id=schedule.threat_model_id,
        name=schedule.name,
        tool_name=schedule.tool_name,
        target_type=schedule.target_type,
        target=schedule.target,
        target_node_id=schedule.target_node_id,
        scope=schedule.scope,
        cadence=schedule.cadence,
        enabled=schedule.enabled,
        authorization_required=schedule.authorization_required,
        authorization_acknowledged_at=schedule.authorization_acknowledged_at,
        last_run_at=schedule.last_run_at,
        next_run_at=schedule.next_run_at,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
        runnable=runnable,
        blocked_reason=blocked_reason,
    )


def validation_target_bundle_response(bundle) -> ValidationTargetBundleResponse:
    return ValidationTargetBundleResponse(
        id=bundle.id,
        threat_model_id=bundle.threat_model_id,
        owner_id=bundle.owner_id,
        organization_id=bundle.organization_id,
        name=bundle.name,
        filename=bundle.filename,
        content_type=bundle.content_type,
        byte_size=bundle.byte_size,
        sha256=bundle.sha256,
        status=bundle.status,
        storage_backend=bundle.storage_backend,
        manifest=bundle.manifest or {},
        target_ref=target_ref_for_bundle(bundle.id),
        retention_expires_at=bundle.retention_expires_at,
        created_at=bundle.created_at,
        updated_at=bundle.updated_at,
    )


async def _recent_scans(db: AsyncSession, threat_model_id: UUID) -> list[ScanJob]:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.threat_model_id == threat_model_id)
        .order_by(ScanJob.created_at.desc())
        .limit(8)
    )
    return list(result.scalars().all())


async def _evidence_ledger(
    db: AsyncSession,
    scans: list[ScanJob],
) -> list[ValidationEvidenceLedgerEntryResponse]:
    entries: list[ValidationEvidenceLedgerEntryResponse] = []
    for scan in scans:
        runbook = (
            await build_validation_runbook(db, scan.id)
            if scan.status == "completed"
            else None
        )
        artifacts_result = await db.execute(
            select(ScanExecutionArtifact)
            .where(ScanExecutionArtifact.scan_job_id == scan.id)
            .order_by(ScanExecutionArtifact.created_at.desc())
        )
        artifacts = list(artifacts_result.scalars().all())
        coverage = runbook.coverage if runbook else None
        entries.append(
            ValidationEvidenceLedgerEntryResponse(
                scan_id=scan.id,
                tool_name=scan.tool_name,
                target_type=scan.target_type,
                status=scan.status,
                target_binding=coverage.target_binding
                if coverage
                else _target_binding(scan.targets or {}),
                finding_count=scan.finding_count,
                mapped_threat_count=coverage.mapped_threat_count if coverage else 0,
                validated_threat_count=coverage.validated_threat_count
                if coverage
                else 0,
                indicated_threat_count=coverage.indicated_threat_count
                if coverage
                else 0,
                unbound_finding_count=coverage.unbound_finding_count if coverage else 0,
                artifact_count=len(artifacts),
                deterministic_finding_count=coverage.deterministic_finding_count
                if coverage
                else 0,
                assisted_finding_count=coverage.assisted_finding_count
                if coverage
                else 0,
                output_sha256=next(
                    (
                        artifact.output_sha256
                        for artifact in artifacts
                        if artifact.output_sha256
                    ),
                    None,
                ),
                error_message=scan.error_message,
                completed_at=scan.completed_at,
                created_at=scan.created_at,
            )
        )
    return entries


def build_product_security_cases(
    latest_runbook,
) -> list[ProductSecurityValidationCaseResponse]:
    """Build Product Security investigation cases from the current runbook.

    This is intentionally derived, not persisted. It gives the product a case
    workflow surface while keeping analyst state/audit persistence for a later
    workflow slice.
    """
    if latest_runbook is None:
        return []

    cases: list[ProductSecurityValidationCaseResponse] = []
    for threat in latest_runbook.mapped_threats:
        status = _case_status_for_threat(threat)
        proof_level = _proof_level_for_threat(threat)
        confidence_score = _case_confidence_score(
            status=status,
            proof_class=threat.proof_class,
            evidence_quality=threat.evidence_quality,
            evidence_count=threat.evidence_count,
            risk_score=threat.risk_score,
        )
        cases.append(
            ProductSecurityValidationCaseResponse(
                case_id=str(threat.threat_id),
                case_type="threat",
                title=f"{threat.threat_display_id} · {threat.stride_category}",
                hypothesis=threat.threat_description,
                severity=threat.severity,
                stride_category=threat.stride_category,
                status=status,
                confidence_label=_confidence_label(confidence_score),
                confidence_score=confidence_score,
                proof_level=proof_level,
                proof_class=threat.proof_class,
                evidence_quality=threat.evidence_quality,
                evidence_count=threat.evidence_count,
                evidence_sources=threat.validation_tools,
                risk_score=threat.risk_score,
                product_questions=_product_security_questions(threat.stride_category),
                recommended_checks=_recommended_checks_for_case(
                    threat.stride_category, status, threat.validation_tools
                ),
                next_action=threat.next_action,
                remediation_action=_remediation_action_for_status(
                    status, threat.validation_tools
                ),
            )
        )

    for finding in latest_runbook.unbound_findings:
        confidence_score = _case_confidence_score(
            status="needs_binding",
            proof_class=finding.proof_class,
            evidence_quality=finding.evidence_quality,
            evidence_count=1,
            risk_score=finding.risk_score,
        )
        cases.append(
            ProductSecurityValidationCaseResponse(
                case_id=str(finding.finding_id),
                case_type="unbound_finding",
                title=f"Unbound · {finding.title}",
                hypothesis=finding.explanation,
                severity=finding.severity,
                stride_category=None,
                status="needs_binding",
                confidence_label=_confidence_label(confidence_score),
                confidence_score=confidence_score,
                proof_level="observed",
                proof_class=finding.proof_class,
                evidence_quality=finding.evidence_quality,
                evidence_count=1,
                evidence_sources=[finding.tool_name] if finding.tool_name else [],
                risk_score=finding.risk_score,
                product_questions=[
                    "Which modeled component owns this evidence?",
                    "Does the matched path, package, endpoint, or resource appear in the DFD metadata?",
                ],
                recommended_checks=[],
                next_action=finding.next_action,
                remediation_action="Bind this evidence to an affected DFD node before using it to validate a semantic threat.",
            )
        )

    status_rank = {
        "validated": 0,
        "relevant": 1,
        "needs_binding": 2,
        "needs_evidence": 3,
    }
    return sorted(
        cases,
        key=lambda case: (
            status_rank.get(case.status, 9),
            -case.risk_score,
            case.title,
        ),
    )


async def apply_product_security_case_state(
    db: AsyncSession,
    threat_model_id: UUID,
    cases: list[ProductSecurityValidationCaseResponse],
) -> list[ProductSecurityValidationCaseResponse]:
    if not cases:
        return cases
    case_keys = [case.case_id for case in cases]
    result = await db.execute(
        select(ValidationCaseState).where(
            ValidationCaseState.threat_model_id == threat_model_id,
            ValidationCaseState.case_key.in_(case_keys),
        )
    )
    states = result.scalars().all()
    if not states:
        return cases

    state_ids = [state.id for state in states]
    events_result = await db.execute(
        select(ValidationCaseEvent)
        .where(ValidationCaseEvent.case_state_id.in_(state_ids))
        .order_by(ValidationCaseEvent.created_at.desc())
    )
    events_by_state_id: dict[UUID, list[ValidationCaseEvent]] = defaultdict(list)
    for event in events_result.scalars().all():
        events_by_state_id[event.case_state_id].append(event)

    return merge_product_security_case_state(cases, states, events_by_state_id)


def merge_product_security_case_state(
    cases: list[ProductSecurityValidationCaseResponse],
    states: list[ValidationCaseState],
    events_by_state_id: dict[UUID, list[ValidationCaseEvent]] | None = None,
) -> list[ProductSecurityValidationCaseResponse]:
    states_by_key = {state.case_key: state for state in states}
    events_by_state_id = events_by_state_id or {}
    merged: list[ProductSecurityValidationCaseResponse] = []
    for case in cases:
        state = states_by_key.get(case.case_id)
        if state is None:
            merged.append(case)
            continue
        case.workflow_status = state.workflow_status
        case.workflow_priority = state.workflow_priority
        case.owner_label = state.owner_label
        case.due_date = state.due_date
        case.analyst_note = state.analyst_note
        case.last_decision = state.last_decision
        case.workflow_updated_at = state.updated_at
        case.audit_events = [
            ValidationCaseEventResponse(
                id=event.id,
                action=event.action,
                changes=event.changes or {},
                note=event.note,
                actor_id=event.actor_id,
                created_at=event.created_at,
            )
            for event in events_by_state_id.get(state.id, [])[:10]
        ]
        merged.append(case)
    return merged


async def update_product_security_case_state(
    db: AsyncSession,
    threat_model_id: UUID,
    case_key: str,
    body: ValidationCaseStateUpdateRequest,
    current_user: User,
) -> ProductSecurityValidationCaseResponse | None:
    latest_runbook = await _latest_runbook(db, threat_model_id)
    cases = build_product_security_cases(latest_runbook)
    current_case = next((case for case in cases if case.case_id == case_key), None)
    if current_case is None:
        return None

    result = await db.execute(
        select(ValidationCaseState).where(
            ValidationCaseState.threat_model_id == threat_model_id,
            ValidationCaseState.case_key == case_key,
        )
    )
    state = result.scalar_one_or_none()
    action = "updated"
    if state is None:
        action = "created"
        state = ValidationCaseState(
            threat_model_id=threat_model_id,
            case_key=case_key,
            case_type=current_case.case_type,
            workflow_status="open",
            created_by_id=current_user.id,
        )
        db.add(state)
        await db.flush()

    changes: dict[str, dict[str, object | None]] = {}

    def assign(field: str, value: object | None) -> None:
        old_value = getattr(state, field)
        if old_value == value:
            return
        changes[field] = {
            "from": _jsonable_change_value(old_value),
            "to": _jsonable_change_value(value),
        }
        setattr(state, field, value)

    if body.workflow_status is not None:
        assign("workflow_status", body.workflow_status)
    if body.workflow_priority is not None:
        assign("workflow_priority", body.workflow_priority)
    elif body.clear_priority:
        assign("workflow_priority", None)
    if body.owner_label is not None:
        assign("owner_label", body.owner_label)
    elif body.clear_owner:
        assign("owner_label", None)
    if body.due_date is not None:
        assign("due_date", body.due_date)
    elif body.clear_due_date:
        assign("due_date", None)
    if body.analyst_note is not None:
        assign("analyst_note", body.analyst_note)
    if body.last_decision is not None:
        assign("last_decision", body.last_decision)

    state.case_type = current_case.case_type
    state.updated_by_id = current_user.id
    state.updated_at = datetime.now(timezone.utc)
    if action == "created" or changes:
        db.add(
            ValidationCaseEvent(
                case_state_id=state.id,
                threat_model_id=threat_model_id,
                actor_id=current_user.id,
                action=action,
                changes=changes,
                note=body.last_decision or body.analyst_note,
            )
        )
    await db.commit()
    await db.refresh(state)

    return merge_product_security_case_state(
        [current_case],
        [state],
        {state.id: await _validation_case_events(db, state.id)},
    )[0]


async def bind_validation_evidence_to_node(
    db: AsyncSession,
    threat_model_id: UUID,
    finding_id: UUID,
    target_node_id: UUID,
) -> ValidationEvidenceBindingResponse | None:
    """Bind an existing validation finding to a DFD node and remap the scan."""
    row_result = await db.execute(
        select(ScanFinding, ScanJob)
        .join(ScanJob, ScanJob.id == ScanFinding.scan_job_id)
        .where(
            ScanFinding.id == finding_id,
            ScanJob.threat_model_id == threat_model_id,
        )
    )
    row = row_result.one_or_none()
    if row is None:
        return None
    finding, scan_job = row

    node_result = await db.execute(
        select(DFDNode).where(
            DFDNode.id == target_node_id,
            DFDNode.threat_model_id == threat_model_id,
        )
    )
    node = node_result.scalar_one_or_none()
    if node is None:
        raise ValueError("target_node_id does not belong to this threat model")
    if scan_job.status != "completed":
        raise ValueError("Only completed validation scans can be rebound")

    existing_targets = scan_job.targets or {}
    binding_target = binding_target_for_scan_finding(
        finding,
        target_type=scan_job.target_type,
        fallback_target=_fallback_target(existing_targets),
    )
    next_targets = {
        str(key): value
        for key, value in existing_targets.items()
        if not _is_global_target_key(str(key))
    }
    next_targets[str(node.id)] = binding_target
    scan_job.targets = next_targets

    await db.execute(
        delete(ScanThreatResult).where(ScanThreatResult.scan_job_id == scan_job.id)
    )
    await db.flush()
    await run_semantic_mapping(db, scan_job.id)
    await db.commit()

    runbook = await build_validation_runbook(db, scan_job.id)
    coverage = runbook.coverage if runbook else None
    return ValidationEvidenceBindingResponse(
        finding_id=finding.id,
        scan_id=scan_job.id,
        threat_model_id=scan_job.threat_model_id,
        target_node_id=node.id,
        target_node_name=node.name,
        binding_target=binding_target,
        target_binding=coverage.target_binding
        if coverage
        else _target_binding(next_targets),
        mapped_threat_count=coverage.mapped_threat_count if coverage else 0,
        unbound_finding_count=coverage.unbound_finding_count if coverage else 0,
        message=f"Evidence bound to {node.name} and semantic mapping refreshed.",
    )


def _jsonable_change_value(value: object | None) -> object | None:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


async def _latest_runbook(db: AsyncSession, threat_model_id: UUID):
    recent_scan_rows = await _recent_scans(db, threat_model_id)
    latest_completed = next(
        (scan for scan in recent_scan_rows if scan.status == "completed"), None
    )
    if latest_completed is None:
        return None
    return await build_validation_runbook(db, latest_completed.id)


async def _validation_case_events(
    db: AsyncSession, state_id: UUID
) -> list[ValidationCaseEvent]:
    result = await db.execute(
        select(ValidationCaseEvent)
        .where(ValidationCaseEvent.case_state_id == state_id)
        .order_by(ValidationCaseEvent.created_at.desc())
    )
    return list(result.scalars().all())


def _target_binding(targets: dict) -> str:
    if not targets:
        return "none"
    keys = {str(key) for key in targets}
    has_global = any(_is_global_target_key(key) for key in keys)
    has_node = any(not _is_global_target_key(key) for key in keys)
    if has_global and has_node:
        return "mixed"
    if has_node:
        return "node_bound"
    return "global"


def _is_global_target_key(key: str) -> bool:
    return key in _GLOBAL_TARGET_KEYS or key.startswith(
        ("direct:", "ingested:", "try_sandbox:")
    )


def _fallback_target(targets: dict) -> str | None:
    for key, value in targets.items():
        if _is_global_target_key(str(key)) and value:
            return str(value)
    for value in targets.values():
        if value:
            return str(value)
    return None


def _case_status_for_threat(threat) -> str:
    if threat.confidence_label == "validated":
        manual_sources = {"external-report", "pentest-report"}
        if threat.proof_class == "deterministic" or manual_sources.intersection(
            threat.validation_tools
        ):
            return "validated"
        return "relevant"
    if threat.confidence_label == "indicated":
        return "relevant"
    return "needs_evidence"


def _proof_level_for_threat(threat) -> str:
    manual_sources = {"external-report", "pentest-report"}
    if threat.confidence_label == "validated" and manual_sources.intersection(
        threat.validation_tools
    ):
        return "human_attested"
    if threat.confidence_label == "validated" and threat.proof_class == "deterministic":
        return "validated"
    if threat.confidence_label == "validated" and threat.evidence_count:
        return "relevant"
    if threat.confidence_label == "indicated":
        return "relevant"
    if threat.evidence_count:
        return "observed"
    return "none"


def _case_confidence_score(
    *,
    status: str,
    proof_class: str,
    evidence_quality: str,
    evidence_count: int,
    risk_score: int,
) -> int:
    base_by_status = {
        "validated": 78,
        "relevant": 55,
        "needs_binding": 38,
        "needs_evidence": 18,
    }
    quality_bonus = {"strong": 10, "moderate": 5, "weak": 0}.get(evidence_quality, 0)
    proof_bonus = {"deterministic": 6, "ai_assisted": 2, "policy": 1, "runtime": 1}.get(
        proof_class, 0
    )
    evidence_bonus = min(8, max(0, evidence_count - 1) * 2)
    risk_bonus = 4 if risk_score >= 80 else 2 if risk_score >= 55 else 0
    score = (
        base_by_status.get(status, 20)
        + quality_bonus
        + proof_bonus
        + evidence_bonus
        + risk_bonus
    )
    return max(0, min(100, score))


def _confidence_label(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _product_security_questions(stride_category: str | None) -> list[str]:
    defaults = [
        "What user, tenant, or trust boundary can be affected?",
        "What concrete evidence proves this is reachable in the product?",
    ]
    if stride_category == "Spoofing":
        return [
            "Can a caller assume another identity, role, or tenant context?",
            "Which authentication or token-verification control should block this?",
        ]
    if stride_category == "Tampering":
        return [
            "Can untrusted input modify protected state, authorization decisions, or persisted records?",
            "Which validation, signing, or integrity control should reject the change?",
        ]
    if stride_category == "Repudiation":
        return [
            "Would the product retain enough audit evidence to prove who performed the action?",
            "Which event, actor, and object identifiers are missing from the audit path?",
        ]
    if stride_category == "Information Disclosure":
        return [
            "What sensitive data, secret, or tenant-owned object can be exposed?",
            "Which access-control, encryption, or data-minimization control should prevent disclosure?",
        ]
    if stride_category == "Denial of Service":
        return [
            "Can an attacker exhaust a shared resource or degrade a critical user journey?",
            "Which rate limit, quota, timeout, or circuit breaker should contain the blast radius?",
        ]
    if stride_category == "Elevation of Privilege":
        return [
            "Can a lower-privileged actor reach admin, cloud, or workload capabilities?",
            "Which authorization, network, or least-privilege control should prevent escalation?",
        ]
    return defaults


def _recommended_checks_for_case(
    stride_category: str | None,
    status: str,
    evidence_sources: list[str] | None = None,
) -> list[ValidationCaseCheckResponse]:
    if status == "validated":
        source = next((item for item in evidence_sources or [] if item), "semgrep")
        target_type_by_tool = {
            "nuclei": TARGET_URL,
            "semgrep": TARGET_REPOSITORY_PATH,
            "trivy": TARGET_IAC_DIRECTORY,
            "osv-scanner": TARGET_LOCKFILE,
            "checkov": TARGET_IAC_DIRECTORY,
            "ai-red-team": TARGET_AI_SYSTEM,
            "external-report": TARGET_URL,
            "pentest-report": TARGET_URL,
        }
        return [
            ValidationCaseCheckResponse(
                tool_name=source,
                target_type=target_type_by_tool.get(source, TARGET_REPOSITORY_PATH),
                priority="P2",
                reason="Retest the fix with the evidence-producing tool before closing the case.",
            )
        ]

    checks_by_stride: dict[str, list[tuple[str, str, str, str]]] = {
        "Spoofing": [
            (
                "semgrep",
                TARGET_REPOSITORY_PATH,
                "P1",
                "Check authentication and token-verification code paths.",
            ),
            (
                "nuclei",
                TARGET_URL,
                "P2",
                "Run safe HTTP/template checks against the exposed endpoint.",
            ),
        ],
        "Tampering": [
            (
                "semgrep",
                TARGET_REPOSITORY_PATH,
                "P1",
                "Check input validation and integrity-sensitive code paths.",
            ),
            (
                "trivy",
                TARGET_IAC_DIRECTORY,
                "P2",
                "Check infrastructure and filesystem misconfigurations that could enable tampering.",
            ),
            (
                "osv-scanner",
                TARGET_LOCKFILE,
                "P2",
                "Confirm dependency advisories behind the semantic risk.",
            ),
        ],
        "Repudiation": [
            (
                "semgrep",
                TARGET_REPOSITORY_PATH,
                "P1",
                "Inspect source paths for missing audit events or actor attribution.",
            ),
        ],
        "Information Disclosure": [
            (
                "checkov",
                TARGET_IAC_DIRECTORY,
                "P1",
                "Check cloud or IaC exposure that can leak data.",
            ),
            (
                "trivy",
                TARGET_IAC_DIRECTORY,
                "P2",
                "Check IaC and filesystem configuration findings that can expose data.",
            ),
            (
                "nuclei",
                TARGET_URL,
                "P2",
                "Check safe HTTP exposure and header evidence.",
            ),
        ],
        "Denial of Service": [
            (
                "osv-scanner",
                TARGET_LOCKFILE,
                "P1",
                "Confirm dependency advisories with denial-of-service impact.",
            ),
            (
                "trivy",
                TARGET_IAC_DIRECTORY,
                "P2",
                "Check configuration findings that amplify resource exhaustion.",
            ),
        ],
        "Elevation of Privilege": [
            (
                "checkov",
                TARGET_IAC_DIRECTORY,
                "P1",
                "Check cloud and network policy paths that create escalation.",
            ),
            (
                "trivy",
                TARGET_IAC_DIRECTORY,
                "P2",
                "Check IaC and filesystem configuration escalation findings.",
            ),
            (
                "nuclei",
                TARGET_URL,
                "P2",
                "Check exposed endpoint misconfiguration evidence.",
            ),
        ],
    }
    return [
        ValidationCaseCheckResponse(
            tool_name=tool_name,
            target_type=target_type,
            priority=priority,  # type: ignore[arg-type]
            reason=reason,
        )
        for tool_name, target_type, priority, reason in checks_by_stride.get(
            stride_category or "", []
        )
    ][:3]


def _remediation_action_for_status(status: str, evidence_sources: list[str]) -> str:
    if status == "validated":
        source_text = (
            ", ".join(evidence_sources) if evidence_sources else "validation evidence"
        )
        return f"Open a fix ticket, attach {source_text}, assign an owner, and schedule a retest before closure."
    if status == "relevant":
        return "Review the evidence, confirm exploitability or compensating controls, then promote to validated or refuted."
    if status == "needs_binding":
        return "Attach this evidence to a DFD node or mark it not applicable so it does not inflate semantic risk."
    return "Run or import the recommended checks against the affected component before making a remediation decision."


def _schedule_runnable(schedule: ValidationSchedule) -> tuple[bool, str | None]:
    if not validation_run_submission_enabled():
        return False, validation_run_submission_blocked_reason()
    try:
        tool = default_validation_tool_registry().get(schedule.tool_name)
        policy = default_validation_execution_policy_registry().get(schedule.tool_name)
    except KeyError:
        return False, "Unsupported validation tool."
    decision = policy.evaluate(schedule.target_type, schedule.target)
    if not decision.allowed:
        return False, decision.reason
    isolated_network_ready = validation_isolated_runner_ready_for(
        policy.tool_name,
        policy.network_mode,
    )
    if managed_process_network_policy_blocked(
        policy.network_mode,
        tool_name=policy.tool_name,
    ):
        return (
            False,
            f"{policy.network_mode} network policy requires an isolated network runner.",
        )
    hosted_target = is_validation_target_bundle_ref(schedule.target)
    if (
        schedule.target_type in _PATH_TARGET_TYPES
        and not configured_validation_allowed_roots()
    ):
        return False, "Local validation allowed roots are not configured."
    if schedule.target_type == TARGET_URL:
        try:
            validate_live_url_target(schedule.target)
        except LiveTargetSafetyError as exc:
            return False, str(exc)
    elif not hosted_target:
        try:
            if validation_runtime_mode() == RUNTIME_MANAGED:
                validate_validation_target_reference(
                    schedule.target, schedule.target_type
                )
            else:
                validate_validation_target_access(schedule.target, schedule.target_type)
        except ValidationSandboxTargetError as exc:
            return False, str(exc)
    runtime_availability = validation_tool_runtime_availability(tool)
    if not runtime_availability.available:
        return False, runtime_availability.detail
    if managed_process_network_policy_blocked(
        policy.network_mode,
        tool_name=policy.tool_name,
    ) or (
        policy.runs_in_sandbox_required
        and validation_sandbox_mode() != "container"
        and policy.network_mode != NETWORK_NONE
        and not validation_process_sandbox_network_allowed(policy.network_mode)
        and not isolated_network_ready
    ):
        return (
            False,
            f"{policy.network_mode} network policy requires an isolated network runner.",
        )
    return True, None


def _safety_controls() -> list[ValidationSafetyControlResponse]:
    allowed_roots = configured_validation_allowed_roots()
    scheduler_enabled = _scheduler_enabled()
    runtime = validation_runtime_state()
    sandbox_mode = validation_sandbox_mode()
    container_runtime = validation_container_runtime()
    container_enabled = sandbox_mode == "container" and bool(container_runtime)
    sandbox_detail = (
        "Sandbox-required tools run in Docker/Podman with readonly mounts, tmpfs, artifact volume, no-new-privileges, dropped capabilities, resource limits, and per-tool network policy."
        if container_enabled
        else "Sandbox-required tools run without a shell, with path allowlists, bounded runtime, capped output, sanitized env, and command redaction. Set THREATGENIX_VALIDATION_SANDBOX_MODE=container for Docker/Podman isolation."
    )
    return [
        ValidationSafetyControlResponse(
            name="SaaS execution boundary",
            status="configured" if runtime.live_execution_enabled else "enforced",
            detail=runtime.detail,
        ),
        ValidationSafetyControlResponse(
            name="Authorization gate",
            status="enforced",
            detail="Every live run requires an explicit per-run authorization acknowledgement.",
        ),
        ValidationSafetyControlResponse(
            name="Sandbox boundary",
            status="enforced" if container_enabled else "configured",
            detail=sandbox_detail,
        ),
        ValidationSafetyControlResponse(
            name="Local path allowlist",
            status="configured" if allowed_roots else "missing",
            detail=(
                f"{len(allowed_roots)} local root(s) configured."
                if allowed_roots
                else "Set THREATGENIX_VALIDATION_ALLOWED_PATHS before running repository, lockfile, or IaC tools."
            ),
        ),
        ValidationSafetyControlResponse(
            name="Scheduled runner",
            status="configured" if scheduler_enabled else "planned",
            detail=(
                "Due validation schedules can be enqueued by the operational scheduler."
                if scheduler_enabled
                else "Run python -m app.cli.run_validation_schedules from cron or CI after enabling the scheduler."
            ),
        ),
    ]


def _setup_lanes(
    *,
    run_submission_enabled: bool,
    managed_runner_enabled: bool,
) -> list[ValidationSetupLaneResponse]:
    return [
        ValidationSetupLaneResponse(
            name="Hosted SaaS",
            status="available" if run_submission_enabled else "active",
            summary="Use Try Sandbox and imported evidence. Live runs are queued to the managed runner when it is enabled.",
            controls=[
                "Curated demo evidence",
                "Pre-captured scanner output import",
                "Semantic mapping without target access",
                "No scanner execution in the API process",
            ],
        ),
        ValidationSetupLaneResponse(
            name="Self-hosted runner",
            status="available" if run_submission_enabled else "blocked",
            summary="Operator-owned deployment that can execute approved tools against explicitly authorized targets.",
            controls=[
                "THREATGENIX_VALIDATION_RUNTIME_MODE=self_hosted",
                "Tool CLIs or pinned container images",
                "THREATGENIX_VALIDATION_ALLOWED_PATHS for repo/IaC tools",
                "Per-run authorization acknowledgement",
            ],
        ),
        ValidationSetupLaneResponse(
            name="Managed isolated runner",
            status="active" if managed_runner_enabled else "planned",
            summary="SaaS worker pool for live validation without giving the API server offensive execution rights.",
            controls=[
                "Dedicated validation worker process",
                "Tenant-scoped network egress policy",
                "Artifact volume, quotas, audit log, and kill switch",
                "Short-lived tenant-scoped scan inputs",
            ],
        ),
    ]


def _tool_setup_profiles(inventory: list) -> list[ValidationToolSetupProfileResponse]:
    return [
        ValidationToolSetupProfileResponse(
            tool_name=tool.name,
            label=_tool_label(tool.name),
            setup_mode=_tool_setup_mode(tool),
            runner_profile=_runner_profile(tool),
            prerequisites=_tool_prerequisites(tool),
            configuration=_tool_configuration(tool),
            safety_gates=_tool_safety_gates(tool),
        )
        for tool in inventory
    ]


def _tool_label(tool_name: str) -> str:
    if tool_name == "osv-scanner":
        return "OSV Scanner"
    return " ".join(part.capitalize() for part in tool_name.split("-"))


def _tool_setup_mode(tool) -> str:
    if not validation_run_submission_enabled():
        return "Hosted import-only"
    if not tool.execution_enabled:
        return "Policy disabled"
    if tool.readiness_status == "ready":
        return "Runnable"
    return "Needs setup"


def _runner_profile(tool) -> str:
    if tool.runtime_strategy == "container_image":
        return "Container-hosted tool with bounded runtime, output, artifact capture, and network policy"
    if not tool.runs_in_sandbox_required:
        return "Direct runner with target-only network access"
    if tool.sandbox_mode == "container":
        return "Container sandbox with bounded runtime, output, and artifact capture"
    return (
        "Process sandbox with no shell, sanitized env, bounded runtime, and output cap"
    )


def _tool_prerequisites(tool) -> list[str]:
    prerequisites = ["Explicit authorization for the target scope"]
    if tool.runtime_strategy == "container_image":
        prerequisites.append("Docker or Podman available to the validation runner")
    elif tool.install_hint and not tool.available:
        prerequisites.append(tool.install_hint)
    elif not tool.available:
        prerequisites.append(f"{tool.name} CLI must be installed on the runner PATH")
    if tool.container_image:
        prerequisites.append(f"Approved runner image: {tool.container_image}")
        if not tool.container_image_present and tool.container_pull_policy == "never":
            prerequisites.append(
                "Pre-pull the approved image or allow controlled image pulls"
            )
    if tool.local_allowlist_required:
        prerequisites.append(
            "Configure THREATGENIX_VALIDATION_ALLOWED_PATHS for local path targets"
        )
    return prerequisites[:5]


def _tool_configuration(tool) -> list[str]:
    configuration = [
        f"Runner: {tool.runtime_strategy.replace('_', ' ')}",
        f"Targets: {', '.join(str(target).replace('_', ' ') for target in tool.supported_targets)}",
        f"Network: {tool.network_mode.replace('_', ' ')}",
        f"Runtime cap: {tool.max_runtime_seconds}s",
        f"Output cap: {tool.max_output_bytes:,} bytes",
    ]
    if tool.runtime_strategy == "container_image":
        configuration.append(f"Container pull policy: {tool.container_pull_policy}")
    if tool.enablement_env:
        configuration.append(f"Enable with {tool.enablement_env}=true")
    return configuration[:6]


def _tool_safety_gates(tool) -> list[str]:
    gates = [
        tool.safety_boundary,
        "Capture artifacts and map evidence to semantic threats",
    ]
    if tool.blocker_reasons:
        gates.append(tool.blocker_reasons[0])
    if tool.setup_actions:
        gates.append(tool.setup_actions[0])
    return gates[:4]


def _scheduler_enabled() -> bool:
    return os.getenv(
        "THREATGENIX_VALIDATION_SCHEDULER_ENABLED", ""
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _validation_gaps(
    *,
    posture_ready_tool_count: int,
    schedules: list[ValidationScheduleResponse],
    latest_runbook,
    scheduler_enabled: bool,
    run_submission_enabled: bool,
) -> list[ValidationGapResponse]:
    gaps: list[ValidationGapResponse] = []
    if not run_submission_enabled:
        gaps.append(
            ValidationGapResponse(
                title="Live runner is not enabled",
                severity="high",
                detail="Tenant-triggered tools cannot run from the API server. Enable the managed runner before accepting live SaaS scanner jobs.",
                next_action="Set THREATGENIX_VALIDATION_RUNTIME_MODE=managed, THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED=true, and run worker_main.py in a dedicated worker process.",
            )
        )
    if posture_ready_tool_count == 0 and run_submission_enabled:
        gaps.append(
            ValidationGapResponse(
                title="No tools are runnable in this environment",
                severity="critical",
                detail="The lab can import captured evidence, but live validation is blocked until at least one approved CLI is installed and enabled.",
                next_action="Install Nuclei or Semgrep first, then configure any required policy env flags and path allowlists.",
            )
        )
    if run_submission_enabled and validation_sandbox_mode() != "container":
        gaps.append(
            ValidationGapResponse(
                title="Container sandbox is not enabled",
                severity="high",
                detail="Sandbox-required tools are protected by the process boundary, but not isolated in Docker/Podman namespaces with readonly mounts and resource limits.",
                next_action="Set THREATGENIX_VALIDATION_SANDBOX_MODE=container after pulling or building approved validation runner images.",
            )
        )
    elif run_submission_enabled and validation_container_runtime() is None:
        gaps.append(
            ValidationGapResponse(
                title="Container sandbox runtime is unavailable",
                severity="critical",
                detail="Container sandbox mode is requested, but Docker/Podman is not available to the backend process.",
                next_action="Start Docker or set THREATGENIX_VALIDATION_CONTAINER_RUNTIME to an available runtime.",
            )
        )
    if run_submission_enabled and not configured_validation_allowed_roots():
        gaps.append(
            ValidationGapResponse(
                title="Repository and IaC scans have no allowed roots",
                severity="high",
                detail="Path-based tools cannot run safely until local filesystem scope is explicit.",
                next_action="Set THREATGENIX_VALIDATION_ALLOWED_PATHS to the exact repo, lockfile, or IaC roots approved for validation.",
            )
        )
    if latest_runbook is None:
        gaps.append(
            ValidationGapResponse(
                title="No completed validation runbook",
                severity="high",
                detail="ThreatGenix cannot quantify validated, indicated, or untested semantic risk without at least one completed run or imported evidence package.",
                next_action="Import the safe Semgrep sample or run a first authorized Nuclei/Semgrep target.",
            )
        )
    else:
        if latest_runbook.coverage.unbound_finding_count:
            gaps.append(
                ValidationGapResponse(
                    title="Evidence exists without DFD binding",
                    severity="medium",
                    detail=f"{latest_runbook.coverage.unbound_finding_count} finding(s) were retained but not tied to affected DFD nodes.",
                    next_action="Add source path, package, cloud resource, or endpoint metadata to DFD nodes, then re-import or rerun evidence.",
                )
            )
        if latest_runbook.coverage.untested_threat_count:
            gaps.append(
                ValidationGapResponse(
                    title="Semantic threats still need validation",
                    severity="medium",
                    detail=f"{latest_runbook.coverage.untested_threat_count} active threat(s) have no validation evidence yet.",
                    next_action="Prioritize P1 recommendations and bind findings to the highest-risk DFD nodes.",
                )
            )
    if run_submission_enabled and not schedules:
        gaps.append(
            ValidationGapResponse(
                title="No saved validation targets",
                severity="medium",
                detail="Repeatable validation requires saved targets, not one-off pasted output.",
                next_action="Save a manual target first; enable cadence only after the target is runnable.",
            )
        )
    elif (
        run_submission_enabled
        and any(schedule.enabled for schedule in schedules)
        and not scheduler_enabled
    ):
        gaps.append(
            ValidationGapResponse(
                title="Schedules are configured but no runner is enabled",
                severity="low",
                detail="Enabled schedules will not enqueue automatically until the operational runner is wired to cron or CI.",
                next_action="Set THREATGENIX_VALIDATION_SCHEDULER_ENABLED=true and run python -m app.cli.run_validation_schedules from cron or CI.",
            )
        )
    return gaps[:6]


def _demo_scenario() -> ValidationDemoScenarioResponse:
    raw_output = {
        "results": [
            {
                "check_id": "threatgenix.jwt-algorithm-confusion",
                "path": "app/auth.py",
                "start": {"line": 42},
                "extra": {
                    "message": "JWT verifier accepts untrusted algorithm configuration",
                    "severity": "ERROR",
                    "metadata": {
                        "technology": ["python", "jwt"],
                        "category": "security",
                        "cwe": ["CWE-347"],
                    },
                },
            }
        ]
    }
    return ValidationDemoScenarioResponse(
        title="Try Sandbox: Semgrep JWT fixture",
        summary="A deterministic source-code finding that ThreatGenix can map without executing any scanner or touching tenant infrastructure.",
        tool_name="semgrep",
        target_type=TARGET_REPOSITORY_PATH,
        target="/try-sandbox/semgrep/jwt-service",
        raw_output=json.dumps(raw_output, indent=2, sort_keys=True),
        expected_signal="Should create source-code evidence for spoofing/authentication threats; binding strength depends on DFD node metadata.",
    )


async def create_try_sandbox_scan(
    db: AsyncSession,
    threat_model_id: UUID,
    owner: User,
) -> ScanJob:
    """Persist a curated validation demo without executing scanner binaries."""
    scenario = _demo_scenario()
    adapter = default_validation_tool_registry().get(scenario.tool_name)
    policy = default_validation_execution_policy_registry().get(scenario.tool_name)
    parsed_findings = adapter.parse_output(scenario.target, scenario.raw_output)
    now = datetime.now(timezone.utc)
    targets = {"try_sandbox": scenario.target}
    scan_job = ScanJob(
        threat_model_id=threat_model_id,
        owner_id=owner.id,
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name=scenario.tool_name,
        target_type=scenario.target_type,
        targets=targets,
        nuclei_templates=[],
        started_at=now,
        completed_at=now,
        finding_count=len(parsed_findings),
        credential_id=None,
    )
    db.add(scan_job)
    await db.flush()
    for evidence in parsed_findings:
        db.add(
            evidence.to_scan_finding(
                scan_job.id,
                target_type=scenario.target_type,
                evidence_origin="try_sandbox",
                synthetic=True,
            )
        )
    db.add(
        ScanExecutionArtifact(
            scan_job_id=scan_job.id,
            source="ingest",
            tool_name=scenario.tool_name,
            target_type=scenario.target_type,
            target=sanitize_validation_target_for_storage(
                scenario.target,
                scenario.target_type,
            )
            or scenario.target,
            resolved_target=None,
            status="completed",
            deterministic=adapter.deterministic,
            sandboxed=False,
            sandbox_mode="try_sandbox",
            container_image=None,
            resource_limits={},
            policy_decision="curated try-sandbox evidence; no scanner executed",
            command=[],
            command_redacted=True,
            returncode=0,
            timed_out=False,
            output_limit_exceeded=False,
            stdout_bytes=len(scenario.raw_output.encode("utf-8")),
            output_sha256=hashlib.sha256(
                scenario.raw_output.encode("utf-8")
            ).hexdigest(),
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
    await db.refresh(scan_job)
    return scan_job


def _recommended_next_runs(
    inventory: list,
    has_runbook: bool,
    *,
    run_submission_enabled: bool,
) -> list[ValidationRecommendedRunResponse]:
    tools = {item.name: item for item in inventory}
    recommendations = [
        (
            "ai-red-team",
            TARGET_AI_SYSTEM,
            "P1",
            "Validate AI-system exploitability from executed prompt-injection, data-leakage, RAG, and agent-tool test evidence.",
        ),
        (
            "semgrep",
            TARGET_REPOSITORY_PATH,
            "P1",
            "Validate semantic code flaws and auth/data-flow assumptions against source evidence.",
        ),
        (
            "osv-scanner",
            TARGET_LOCKFILE,
            "P2",
            "Validate dependency CVEs against lockfile or repository evidence.",
        ),
        (
            "trivy",
            TARGET_IAC_DIRECTORY,
            "P2",
            "Validate filesystem and IaC misconfiguration posture.",
        ),
        (
            "checkov",
            TARGET_IAC_DIRECTORY,
            "P2",
            "Validate cloud/IaC misconfiguration assumptions.",
        ),
    ]
    if not has_runbook:
        recommendations.insert(
            0,
            (
                "nuclei",
                TARGET_URL,
                "P1",
                "Establish baseline HTTP validation evidence for DFD URL targets.",
            ),
        )

    result: list[ValidationRecommendedRunResponse] = []
    for tool_name, target_type, priority, reason in recommendations:
        item = tools.get(tool_name)
        blocked = None
        if not run_submission_enabled:
            blocked = "Live validation runner is not enabled; use Try Sandbox or import captured evidence."
        elif item is None:
            blocked = "Tool is not registered."
        elif not item.execution_enabled:
            blocked = (
                "Execution is policy-disabled; use parse-only import if supported."
            )
        elif not item.available:
            blocked = "CLI is not installed on this runner."
        elif (
            target_type in _PATH_TARGET_TYPES
            and not configured_validation_allowed_roots()
        ):
            blocked = "Local path allowlist is not configured."
        result.append(
            ValidationRecommendedRunResponse(
                tool_name=tool_name,
                target_type=target_type,
                priority=priority,  # type: ignore[arg-type]
                reason=reason,
                blocked_reason=blocked,
            )
        )
    return result[:8]
