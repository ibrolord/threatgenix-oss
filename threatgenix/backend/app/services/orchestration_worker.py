"""Execution worker for durable orchestration jobs."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import async_session
from app.models.dfd import DFDNode
from app.models.orchestration import OrchestrationEvent, OrchestrationJob, OrchestrationTask
from app.models.scan import ScanAuthorization, ScanJob
from app.models.threat_model import ThreatModel
from app.schemas.scan import AUTHORIZATION_TEXT
from app.services.evidence_projection import rebuild_evidence_graph
from app.services.llm_client import get_llm_client_for_user_async
from app.services.scan_worker import _execute_scan
from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target
from app.services.validation_execution_policy import (
    TARGET_URL,
    default_validation_execution_policy_registry,
    managed_process_network_policy_blocked,
)
from app.services.validation_runtime import (
    validation_worker_execution_blocked_reason,
    validation_worker_execution_enabled,
)
from app.services.validation_sandbox import (
    ValidationSandboxTargetError,
    validate_validation_target_access,
)
from app.services.validation_tools import default_validation_tool_registry

VALIDATION_TOOL_NAMES = frozenset(
    {"nuclei", "semgrep", "osv-scanner", "trivy", "checkov", "trufflehog"}
)
TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled", "blocked"})
ORCHESTRATION_TASK_STALE_AFTER_SECONDS = 15 * 60
logger = logging.getLogger("threatgenix.orchestration_worker")


class OrchestrationTaskBlocked(RuntimeError):
    """Raised when a task is intentionally blocked by policy or missing input."""


class OrchestrationTaskFailed(RuntimeError):
    """Raised when a task ran but failed."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _event(
    *,
    job_id: UUID,
    threat_model_id: UUID,
    task_id: UUID | None,
    event_type: str,
    message: str,
    level: str = "info",
    payload: dict[str, Any] | None = None,
) -> OrchestrationEvent:
    return OrchestrationEvent(
        id=uuid4(),
        job_id=job_id,
        task_id=task_id,
        threat_model_id=threat_model_id,
        event_type=event_type,
        level=level,
        message=message,
        payload=payload or {},
    )


def _scope(value: object) -> str:
    raw = str(value or "external").strip().lower()
    return raw if raw in {"external", "internal", "full"} else "external"


def _scan_type(value: object) -> str:
    raw = str(value or "unauthenticated").strip().lower()
    return raw if raw in {"unauthenticated", "authenticated"} else "unauthenticated"


def _optional_uuid(value: object) -> UUID | None:
    return _optional_uuid_field(value, "credential_id")


def _optional_uuid_field(value: object, field_name: str) -> UUID | None:
    if value is None or value == "":
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except ValueError as exc:
        raise OrchestrationTaskBlocked(f"{field_name} must be a valid UUID.") from exc


async def claim_next_orchestration_task(
    db: AsyncSession,
    *,
    threat_model_id: UUID | None = None,
    job_id: UUID | None = None,
) -> OrchestrationTask | None:
    """Claim one pending task using row locks where supported by the database."""

    statement = (
        select(OrchestrationTask, OrchestrationJob)
        .join(OrchestrationJob, OrchestrationJob.id == OrchestrationTask.job_id)
        .where(
            OrchestrationTask.status == "pending",
            OrchestrationTask.attempt_count < OrchestrationTask.max_attempts,
            OrchestrationJob.status.in_(("pending", "running")),
        )
        .order_by(OrchestrationTask.created_at.asc(), OrchestrationTask.id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if threat_model_id is not None:
        statement = statement.where(OrchestrationTask.threat_model_id == threat_model_id)
    if job_id is not None:
        statement = statement.where(OrchestrationTask.job_id == job_id)

    result = await db.execute(statement)
    row = result.first()
    if row is None:
        return None

    task, job = row
    task.status = "running"
    task.started_at = task.started_at or _now()
    task.completed_at = None
    task.error_message = None
    task.attempt_count += 1
    if job.status == "pending":
        job.status = "running"
        job.started_at = job.started_at or _now()

    db.add(
        _event(
            job_id=job.id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="started",
            message="Orchestration task claimed by worker.",
            payload={
                "task_kind": task.task_kind,
                "tool_name": task.tool_name,
                "agent_name": task.agent_name,
                "attempt_count": task.attempt_count,
                "max_attempts": task.max_attempts,
            },
        )
    )
    await db.flush()
    return task


async def run_orchestration_job(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    job_id: UUID,
    max_tasks: int = 10,
) -> OrchestrationJob | None:
    """Run up to ``max_tasks`` pending tasks for one orchestration job."""

    await recover_stale_orchestration_tasks(
        db,
        threat_model_id=threat_model_id,
        job_id=job_id,
    )
    await db.commit()

    ran = 0
    while ran < max_tasks:
        task = await claim_next_orchestration_task(
            db,
            threat_model_id=threat_model_id,
            job_id=job_id,
        )
        if task is None:
            break
        await db.commit()
        await execute_claimed_task(db, task.id)
        ran += 1

    await update_orchestration_job_status(db, job_id)
    await db.commit()
    return await load_orchestration_job(db, threat_model_id, job_id)


async def run_one_pending_orchestration_task() -> UUID | None:
    """Claim and execute one pending orchestration task from the shared worker queue."""

    async with async_session() as db:
        stale_count = await recover_stale_orchestration_tasks(db)
        if stale_count:
            logger.warning("orchestration_worker_recovered_stale_tasks count=%d", stale_count)
        await db.commit()

        task = await claim_next_orchestration_task(db)
        if task is None:
            await db.rollback()
            return None

        task_id = task.id
        job_id = task.job_id
        await db.commit()

    logger.info("orchestration_worker_claimed_task task=%s job=%s", task_id, job_id)
    async with async_session() as db:
        await execute_claimed_task(db, task_id)
    return task_id


async def execute_claimed_task(db: AsyncSession, task_id: UUID) -> OrchestrationTask | None:
    result = await db.execute(
        select(OrchestrationTask)
        .options(selectinload(OrchestrationTask.job))
        .where(OrchestrationTask.id == task_id)
        .limit(1)
    )
    task = result.scalar_one_or_none()
    if task is None or task.status != "running":
        return task

    try:
        try:
            output = await _execute_task_handler(db, task)
        except OrchestrationTaskBlocked as exc:
            await _mark_task_blocked(db, task, str(exc))
        except OrchestrationTaskFailed as exc:
            await _mark_task_failed_or_retry(db, task, str(exc))
        except Exception:
            logger.exception("orchestration_task_error task_id=%s job_id=%s", task.id, task.job_id)
            await _mark_task_failed_or_retry(
                db,
                task,
                "Unexpected orchestration task error; check server logs.",
            )
        else:
            await _mark_task_completed(db, task, output)

        await update_orchestration_job_status(db, task.job_id)
        await db.commit()
    except Exception:
        logger.exception(
            "orchestration_task_finalize_error task_id=%s job_id=%s",
            task.id,
            task.job_id,
        )
        await db.rollback()
        await _mark_running_task_after_finalize_error(db, task_id)
    return task


async def recover_stale_orchestration_tasks(
    db: AsyncSession,
    *,
    threat_model_id: UUID | None = None,
    job_id: UUID | None = None,
    stale_after_seconds: int = ORCHESTRATION_TASK_STALE_AFTER_SECONDS,
) -> int:
    """Fail or requeue running tasks that outlived the worker heartbeat window."""

    cutoff = _now() - timedelta(seconds=stale_after_seconds)
    statement = (
        select(OrchestrationTask)
        .options(selectinload(OrchestrationTask.job))
        .join(OrchestrationJob, OrchestrationJob.id == OrchestrationTask.job_id)
        .where(
            OrchestrationTask.status == "running",
            OrchestrationTask.started_at.is_not(None),
            OrchestrationTask.started_at <= cutoff,
            OrchestrationJob.status == "running",
        )
        .order_by(OrchestrationTask.started_at.asc(), OrchestrationTask.id.asc())
        .with_for_update(skip_locked=True)
    )
    if threat_model_id is not None:
        statement = statement.where(OrchestrationTask.threat_model_id == threat_model_id)
    if job_id is not None:
        statement = statement.where(OrchestrationTask.job_id == job_id)

    result = await db.execute(statement)
    stale_tasks = list(result.scalars().all())
    for task in stale_tasks:
        _mark_stale_running_task(
            db,
            task,
            stale_after_seconds=stale_after_seconds,
        )
    await db.flush()

    for stale_job_id in {task.job_id for task in stale_tasks}:
        await update_orchestration_job_status(db, stale_job_id)

    return len(stale_tasks)


async def _mark_running_task_after_finalize_error(
    db: AsyncSession,
    task_id: UUID,
) -> None:
    result = await db.execute(
        select(OrchestrationTask)
        .options(selectinload(OrchestrationTask.job))
        .where(OrchestrationTask.id == task_id)
        .limit(1)
    )
    task = result.scalar_one_or_none()
    if task is None or task.status != "running":
        return
    await _mark_task_failed_or_retry(
        db,
        task,
        "Worker failed while finalizing orchestration task state.",
    )
    await update_orchestration_job_status(db, task.job_id)
    await db.commit()


async def load_orchestration_job(
    db: AsyncSession,
    threat_model_id: UUID,
    job_id: UUID,
) -> OrchestrationJob | None:
    result = await db.execute(
        select(OrchestrationJob)
        .options(
            selectinload(OrchestrationJob.tasks),
            selectinload(OrchestrationJob.events),
        )
        .where(
            OrchestrationJob.id == job_id,
            OrchestrationJob.threat_model_id == threat_model_id,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def update_orchestration_job_status(db: AsyncSession, job_id: UUID) -> None:
    result = await db.execute(
        select(OrchestrationJob)
        .options(selectinload(OrchestrationJob.tasks))
        .where(OrchestrationJob.id == job_id)
        .limit(1)
    )
    job = result.scalar_one_or_none()
    if job is None:
        return
    tasks = list(job.tasks)
    if not tasks:
        return
    statuses = {task.status for task in tasks}
    if statuses <= {"completed"}:
        job.status = "completed"
        job.completed_at = job.completed_at or _now()
        job.result_summary = "All orchestration tasks completed."
        job.error_message = None
        return
    if statuses & {"failed", "blocked", "cancelled"} and statuses <= TERMINAL_TASK_STATUSES:
        job.completed_at = job.completed_at or _now()
        blocked = sum(1 for task in tasks if task.status == "blocked")
        failed = sum(1 for task in tasks if task.status == "failed")
        cancelled = sum(1 for task in tasks if task.status == "cancelled")
        if failed:
            job.status = "failed"
            job.error_message = (
                f"Orchestration finished with {failed} failed task(s), "
                f"{blocked} blocked task(s), and {cancelled} cancelled task(s)."
            )
        elif blocked:
            job.status = "blocked"
            job.error_message = (
                f"Orchestration blocked with {blocked} blocked task(s) and "
                f"{cancelled} cancelled task(s)."
            )
        else:
            job.status = "cancelled"
            job.error_message = (
                f"Orchestration cancelled with {cancelled} cancelled task(s)."
            )
        return
    if job.status == "pending":
        job.status = "running"
        job.started_at = job.started_at or _now()


async def _execute_task_handler(
    db: AsyncSession,
    task: OrchestrationTask,
) -> dict[str, Any]:
    if task.task_kind == "tool_execution":
        return await _execute_tool_task(db, task)
    if task.task_kind == "evidence_projection":
        return await _execute_evidence_rebuild(db, task)
    if task.task_kind == "agent_reasoning":
        return await _execute_agent_reasoning(db, task)
    if task.task_kind == "human_review":
        raise OrchestrationTaskBlocked("Human review is required before this task can continue.")
    raise OrchestrationTaskBlocked(f"Unsupported orchestration task kind: {task.task_kind}")


async def _execute_tool_task(
    db: AsyncSession,
    task: OrchestrationTask,
) -> dict[str, Any]:
    tool_name = task.tool_name or ""
    if tool_name in {"evidence", "evidence-rebuild"}:
        return await _execute_evidence_rebuild(db, task)
    if tool_name in VALIDATION_TOOL_NAMES:
        return await _execute_validation_tool_task(db, task)
    if tool_name in {"security-review", "environment-audit", "prowler"}:
        raise OrchestrationTaskBlocked(
            f"{tool_name} orchestration handler is not connected yet."
        )
    raise OrchestrationTaskBlocked(f"Unsupported orchestration tool: {tool_name or '(none)'}")


async def _execute_evidence_rebuild(
    db: AsyncSession,
    task: OrchestrationTask,
) -> dict[str, Any]:
    threat_model = await _load_task_threat_model(db, task)
    status = await rebuild_evidence_graph(db, threat_model)
    db.add(
        _event(
            job_id=task.job_id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="evidence_added",
            message="Evidence graph projection rebuilt.",
            payload=status.model_dump(mode="json"),
        )
    )
    return {"evidence_status": status.model_dump(mode="json")}


async def _execute_validation_tool_task(
    db: AsyncSession,
    task: OrchestrationTask,
) -> dict[str, Any]:
    job = task.job
    payload = task.input_payload or {}
    policy_payload = job.policy or {}
    tool_name = task.tool_name or ""
    target = str(payload.get("target") or "").strip()
    target_type = str(payload.get("target_type") or "").strip()
    if not target_type:
        raise OrchestrationTaskBlocked("target_type is required for validation tool execution.")
    if not target:
        raise OrchestrationTaskBlocked("target is required for validation tool execution.")

    authorized = bool(
        payload.get("authorization_acknowledged")
        or policy_payload.get("authorization_acknowledged")
    )
    if not authorized:
        raise OrchestrationTaskBlocked(
            "authorization_acknowledged=true is required before executing validation tools."
        )
    if not validation_worker_execution_enabled():
        raise OrchestrationTaskBlocked(validation_worker_execution_blocked_reason())

    try:
        default_validation_tool_registry().get(tool_name)
        validation_policy = default_validation_execution_policy_registry().get(tool_name)
    except KeyError as exc:
        raise OrchestrationTaskBlocked(f"Unsupported validation tool: {tool_name}") from exc

    decision = validation_policy.evaluate(target_type, target)
    if not decision.allowed:
        raise OrchestrationTaskBlocked(decision.reason)
    if managed_process_network_policy_blocked(
        validation_policy.network_mode,
        tool_name=validation_policy.tool_name,
    ):
        raise OrchestrationTaskBlocked(
            f"{validation_policy.network_mode} network policy requires an isolated network runner."
        )

    if target_type == TARGET_URL:
        try:
            validate_live_url_target(target)
        except LiveTargetSafetyError as exc:
            raise OrchestrationTaskBlocked(str(exc)) from exc
    else:
        try:
            validate_validation_target_access(target, target_type)
        except ValidationSandboxTargetError as exc:
            raise OrchestrationTaskBlocked(str(exc)) from exc

    target_node_id = _optional_uuid_field(payload.get("target_node_id"), "target_node_id")
    if target_node_id is not None:
        node_result = await db.execute(
            select(DFDNode).where(
                DFDNode.id == target_node_id,
                DFDNode.threat_model_id == task.threat_model_id,
            )
        )
        if node_result.scalar_one_or_none() is None:
            raise OrchestrationTaskBlocked(
                "target_node_id does not belong to this threat model."
            )
    target_key = str(target_node_id) if target_node_id else "direct"
    targets = {target_key: target}
    scan_job = ScanJob(
        threat_model_id=task.threat_model_id,
        owner_id=job.owner_id,
        status="pending",
        scan_type=_scan_type(payload.get("scan_type")),
        scope=_scope(payload.get("scope")),
        tool_name=tool_name,
        target_type=target_type,
        targets=targets,
        nuclei_templates=[],
        finding_count=0,
        credential_id=_optional_uuid(payload.get("credential_id")),
    )
    db.add(scan_job)
    await db.flush()
    db.add(
        ScanAuthorization(
            scan_job_id=scan_job.id,
            user_id=job.owner_id,
            acknowledged_text=AUTHORIZATION_TEXT,
            ip_address="orchestration-worker",
            targets_snapshot=targets,
        )
    )
    db.add(
        _event(
            job_id=task.job_id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="tool_called",
            message=f"Validation tool queued: {tool_name}.",
            payload={
                "scan_job_id": str(scan_job.id),
                "tool_name": tool_name,
                "target_type": target_type,
                "scope": scan_job.scope,
            },
        )
    )
    await db.commit()

    await _execute_scan(db, scan_job.id)
    await db.refresh(scan_job)
    output = {
        "scan_job_id": str(scan_job.id),
        "scan_status": scan_job.status,
        "finding_count": scan_job.finding_count,
        "error_message": scan_job.error_message,
    }
    if scan_job.status != "completed":
        raise OrchestrationTaskFailed(
            scan_job.error_message or f"{tool_name} validation run did not complete."
        )
    return output


async def _execute_agent_reasoning(
    db: AsyncSession,
    task: OrchestrationTask,
) -> dict[str, Any]:
    payload = task.input_payload or {}
    prompt = str(payload.get("prompt") or "").strip()
    if not prompt:
        raise OrchestrationTaskBlocked("prompt is required for agent_reasoning tasks.")

    context = await build_orchestration_context(db, task)
    client = await get_llm_client_for_user_async(task.job.owner_id, db)
    tool = {
        "name": "record_agent_reasoning",
        "description": "Record an evidence-grounded orchestration reasoning result.",
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "findings": {"type": "array", "items": {"type": "string"}},
                    "assumptions": {"type": "array", "items": {"type": "string"}},
                    "next_actions": {"type": "array", "items": {"type": "string"}},
                    "citations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["summary", "findings", "assumptions", "next_actions", "citations"],
            }
        },
    }
    result = client.call_with_tools(
        system_message=(
            "You are an evidence-grounded security orchestration agent. Use only the "
            "provided orchestration context. If evidence is missing, say what is missing. "
            "Do not invent facts, scan results, vulnerabilities, tenants, or tool output."
        ),
        user_message=f"Task prompt:\n{prompt}\n\nGrounding context:\n{context}",
        tools=[tool],
        max_tokens=1600,
        prompt_version="orchestration_agent_reasoning_v1",
    )
    if not result:
        raise OrchestrationTaskFailed("Agent reasoning returned no structured output.")
    return {"agent_reasoning": result}


async def build_orchestration_context(
    db: AsyncSession,
    task: OrchestrationTask,
) -> dict[str, Any]:
    result = await db.execute(
        select(OrchestrationJob)
        .options(
            selectinload(OrchestrationJob.tasks),
            selectinload(OrchestrationJob.events),
        )
        .where(OrchestrationJob.id == task.job_id)
        .limit(1)
    )
    job = result.scalar_one()
    prior_tasks = [
        {
            "task_id": str(item.id),
            "task_kind": item.task_kind,
            "tool_name": item.tool_name,
            "agent_name": item.agent_name,
            "status": item.status,
            "output_payload": item.output_payload or {},
            "error_message": item.error_message,
        }
        for item in sorted(job.tasks, key=lambda item: item.created_at)
        if item.id != task.id and item.status in TERMINAL_TASK_STATUSES
    ]
    recent_events = [
        {
            "event_type": event.event_type,
            "level": event.level,
            "message": event.message,
            "payload": event.payload or {},
            "created_at": event.created_at.isoformat() if event.created_at else None,
        }
        for event in sorted(job.events, key=lambda item: item.created_at)[-25:]
    ]
    return {
        "job_id": str(job.id),
        "job_kind": job.job_kind,
        "objective": job.objective,
        "inputs": job.inputs or {},
        "policy": job.policy or {},
        "prior_task_outputs": prior_tasks,
        "recent_events": recent_events,
    }


async def _load_task_threat_model(db: AsyncSession, task: OrchestrationTask) -> ThreatModel:
    result = await db.execute(
        select(ThreatModel)
        .where(ThreatModel.id == task.threat_model_id)
        .limit(1)
    )
    threat_model = result.scalar_one_or_none()
    if threat_model is None:
        raise OrchestrationTaskBlocked("Threat model no longer exists.")
    return threat_model


async def _mark_task_completed(
    db: AsyncSession,
    task: OrchestrationTask,
    output: dict[str, Any],
) -> None:
    task.status = "completed"
    task.output_payload = output
    task.error_message = None
    task.completed_at = _now()
    db.add(
        _event(
            job_id=task.job_id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="completed",
            message="Orchestration task completed.",
            payload={"output_keys": sorted(output.keys())},
        )
    )


async def _mark_task_blocked(db: AsyncSession, task: OrchestrationTask, reason: str) -> None:
    task.status = "blocked"
    task.error_message = reason
    task.completed_at = _now()
    db.add(
        _event(
            job_id=task.job_id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="blocked",
            level="warning",
            message="Orchestration task blocked.",
            payload={"reason": reason},
        )
    )


def _mark_stale_running_task(
    db: AsyncSession,
    task: OrchestrationTask,
    *,
    stale_after_seconds: int,
) -> None:
    reason = (
        "Orchestration task exceeded the running timeout "
        f"({stale_after_seconds} seconds)."
    )
    task.error_message = reason
    if task.attempt_count < task.max_attempts:
        task.status = "pending"
        task.started_at = None
        task.completed_at = None
        level = "warning"
        message = "Orchestration task timed out; retry pending."
        recovery_action = "retry"
    else:
        task.status = "failed"
        task.completed_at = _now()
        level = "error"
        message = "Orchestration task timed out."
        recovery_action = "failed"
    db.add(
        _event(
            job_id=task.job_id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="failed",
            level=level,
            message=message,
            payload={
                "reason": reason,
                "attempt_count": task.attempt_count,
                "max_attempts": task.max_attempts,
                "recovery_action": recovery_action,
                "stale_after_seconds": stale_after_seconds,
            },
        )
    )


async def _mark_task_failed_or_retry(
    db: AsyncSession,
    task: OrchestrationTask,
    reason: str,
) -> None:
    task.error_message = reason
    if task.attempt_count < task.max_attempts:
        task.status = "pending"
        task.completed_at = None
        message = "Orchestration task failed; retry pending."
    else:
        task.status = "failed"
        task.completed_at = _now()
        message = "Orchestration task failed."
    db.add(
        _event(
            job_id=task.job_id,
            task_id=task.id,
            threat_model_id=task.threat_model_id,
            event_type="failed",
            level="error",
            message=message,
            payload={
                "reason": reason,
                "attempt_count": task.attempt_count,
                "max_attempts": task.max_attempts,
            },
        )
    )
