"""Services for durable orchestration jobs and tasks."""

from __future__ import annotations

import json
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.orchestration import (
    OrchestrationEvent,
    OrchestrationJob,
    OrchestrationTask,
)
from app.models.threat_model import ThreatModel
from app.schemas.orchestration import (
    OrchestrationEventResponse,
    OrchestrationJobCreate,
    OrchestrationJobResponse,
    OrchestrationTaskCreate,
    OrchestrationTaskResponse,
)


class OrchestrationIdempotencyConflict(ValueError):
    """Raised when an idempotency key is reused for a different request body."""


def serialize_orchestration_task(
    task: OrchestrationTask,
) -> OrchestrationTaskResponse:
    return OrchestrationTaskResponse(
        id=task.id,
        job_id=task.job_id,
        threat_model_id=task.threat_model_id,
        task_kind=task.task_kind,
        agent_name=task.agent_name,
        tool_name=task.tool_name,
        status=task.status,
        input_payload=task.input_payload or {},
        output_payload=task.output_payload or {},
        error_message=task.error_message,
        attempt_count=task.attempt_count,
        max_attempts=task.max_attempts,
        started_at=task.started_at,
        completed_at=task.completed_at,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


def serialize_orchestration_event(
    event: OrchestrationEvent,
) -> OrchestrationEventResponse:
    return OrchestrationEventResponse(
        id=event.id,
        job_id=event.job_id,
        task_id=event.task_id,
        threat_model_id=event.threat_model_id,
        event_type=event.event_type,
        level=event.level,
        message=event.message,
        payload=event.payload or {},
        created_at=event.created_at,
    )


def serialize_orchestration_job(
    job: OrchestrationJob,
) -> OrchestrationJobResponse:
    return OrchestrationJobResponse(
        id=job.id,
        threat_model_id=job.threat_model_id,
        owner_id=job.owner_id,
        job_kind=job.job_kind,
        status=job.status,
        objective=job.objective,
        requested_tools=job.requested_tools or [],
        idempotency_key=job.idempotency_key,
        inputs=job.inputs or {},
        policy=job.policy or {},
        result_summary=job.result_summary,
        error_message=job.error_message,
        started_at=job.started_at,
        completed_at=job.completed_at,
        created_at=job.created_at,
        updated_at=job.updated_at,
        tasks=[
            serialize_orchestration_task(task)
            for task in sorted(job.tasks, key=lambda item: item.created_at)
        ],
        events=[
            serialize_orchestration_event(event)
            for event in sorted(job.events, key=lambda item: item.created_at)
        ],
    )


def _task_from_request(
    *,
    job: OrchestrationJob,
    threat_model_id: UUID,
    task: OrchestrationTaskCreate,
) -> OrchestrationTask:
    return OrchestrationTask(
        id=uuid4(),
        job_id=job.id,
        threat_model_id=threat_model_id,
        task_kind=task.task_kind,
        agent_name=task.agent_name,
        tool_name=task.tool_name,
        input_payload=task.input_payload,
        max_attempts=task.max_attempts,
    )


def _materialized_task_specs(
    tasks: list[OrchestrationTaskCreate],
    requested_tools: list[str],
) -> list[OrchestrationTaskCreate]:
    task_specs = list(tasks)
    task_tool_names = {task.tool_name for task in task_specs if task.tool_name}
    for tool_name in requested_tools:
        if tool_name in task_tool_names:
            continue
        task_specs.append(
            OrchestrationTaskCreate(
                task_kind="tool_execution",
                tool_name=tool_name,
                input_payload={"source": "requested_tools"},
            )
        )
        task_tool_names.add(tool_name)
    return task_specs


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _task_fingerprint_items(
    tasks: list[OrchestrationTaskCreate],
) -> list[dict[str, object]]:
    items = [
        {
            "task_kind": task.task_kind,
            "agent_name": task.agent_name,
            "tool_name": task.tool_name,
            "input_payload": task.input_payload,
            "max_attempts": task.max_attempts,
        }
        for task in tasks
    ]
    return sorted(items, key=_canonical_json)


def _job_task_fingerprint_items(job: OrchestrationJob) -> list[dict[str, object]]:
    items = [
        {
            "task_kind": task.task_kind,
            "agent_name": task.agent_name,
            "tool_name": task.tool_name,
            "input_payload": task.input_payload or {},
            "max_attempts": task.max_attempts,
        }
        for task in job.tasks
    ]
    return sorted(items, key=_canonical_json)


def _request_fingerprint_payload(request: OrchestrationJobCreate) -> dict[str, object]:
    requested_tools = list(dict.fromkeys(request.requested_tools))
    return {
        "job_kind": request.job_kind,
        "objective": request.objective,
        "requested_tools": requested_tools,
        "inputs": request.inputs,
        "policy": request.policy,
        "tasks": _task_fingerprint_items(
            _materialized_task_specs(list(request.tasks), requested_tools)
        ),
    }


def _job_fingerprint_payload(job: OrchestrationJob) -> dict[str, object]:
    return {
        "job_kind": job.job_kind,
        "objective": job.objective,
        "requested_tools": job.requested_tools or [],
        "inputs": job.inputs or {},
        "policy": job.policy or {},
        "tasks": _job_task_fingerprint_items(job),
    }


def ensure_idempotent_request_matches(
    existing: OrchestrationJob,
    request: OrchestrationJobCreate,
) -> None:
    if _canonical_json(_job_fingerprint_payload(existing)) != _canonical_json(
        _request_fingerprint_payload(request)
    ):
        raise OrchestrationIdempotencyConflict(
            "Idempotency key was already used for a different orchestration request."
        )


async def get_orchestration_job_by_idempotency_key(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    owner_id: UUID,
    idempotency_key: str,
) -> OrchestrationJob | None:
    result = await db.execute(
        select(OrchestrationJob)
        .options(
            selectinload(OrchestrationJob.tasks),
            selectinload(OrchestrationJob.events),
        )
        .where(
            OrchestrationJob.threat_model_id == threat_model_id,
            OrchestrationJob.owner_id == owner_id,
            OrchestrationJob.idempotency_key == idempotency_key,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def create_orchestration_job(
    db: AsyncSession,
    threat_model: ThreatModel,
    *,
    owner_id: UUID,
    request: OrchestrationJobCreate,
) -> OrchestrationJob:
    if request.idempotency_key:
        existing = await get_orchestration_job_by_idempotency_key(
            db,
            threat_model.id,
            owner_id=owner_id,
            idempotency_key=request.idempotency_key,
        )
        if existing is not None:
            ensure_idempotent_request_matches(existing, request)
            return existing

    requested_tools = list(dict.fromkeys(request.requested_tools))
    job = OrchestrationJob(
        id=uuid4(),
        threat_model_id=threat_model.id,
        owner_id=owner_id,
        job_kind=request.job_kind,
        objective=request.objective,
        requested_tools=requested_tools,
        idempotency_key=request.idempotency_key,
        inputs=request.inputs,
        policy=request.policy,
    )
    db.add(job)
    await db.flush()

    task_specs = _materialized_task_specs(list(request.tasks), requested_tools)

    for task_spec in task_specs:
        db.add(
            _task_from_request(
                job=job,
                threat_model_id=threat_model.id,
                task=task_spec,
            )
        )

    db.add(
        OrchestrationEvent(
            id=uuid4(),
            job_id=job.id,
            threat_model_id=threat_model.id,
            event_type="created",
            level="info",
            message="Orchestration job created.",
            payload={
                "job_kind": request.job_kind,
                "requested_tools": requested_tools,
                "idempotency_key": request.idempotency_key,
            },
        )
    )
    await db.flush()
    return job


async def list_orchestration_jobs(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    limit: int = 100,
) -> list[OrchestrationJob]:
    result = await db.execute(
        select(OrchestrationJob)
        .options(
            selectinload(OrchestrationJob.tasks),
            selectinload(OrchestrationJob.events),
        )
        .where(OrchestrationJob.threat_model_id == threat_model_id)
        .order_by(OrchestrationJob.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_orchestration_job(
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
