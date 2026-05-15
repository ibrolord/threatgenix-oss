"""Managed validation runner heartbeat and queue visibility."""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanJob, ValidationWorkerHeartbeat
from app.services.validation_runtime import (
    managed_validation_runner_enabled,
    validation_runtime_mode,
)
from app.services.validation_sandbox import validation_sandbox_mode

_STARTED_AT = datetime.now(timezone.utc)
_DEFAULT_HEARTBEAT_FRESH_SECONDS = int(
    os.getenv("VALIDATION_WORKER_HEARTBEAT_FRESH_SECONDS", "45")
)
_DEFAULT_LEASE_SECONDS = int(os.getenv("VALIDATION_WORKER_LEASE_SECONDS", "90"))
_DEFAULT_MAX_ATTEMPTS = int(os.getenv("VALIDATION_WORKER_MAX_ATTEMPTS", "3"))


@dataclass(frozen=True)
class RunnerQueueStatus:
    pending_count: int
    running_count: int
    failed_count: int
    oldest_pending_age_seconds: int | None
    oldest_running_age_seconds: int | None
    stale_running_count: int
    active_worker_count: int
    last_heartbeat_at: datetime | None
    status: str
    detail: str


def validation_runner_id() -> str:
    configured = os.getenv("VALIDATION_WORKER_RUNNER_ID")
    if configured:
        return configured[:200]
    fly_machine = os.getenv("FLY_MACHINE_ID")
    if fly_machine:
        return f"fly:{fly_machine}"[:200]
    return f"{socket.gethostname()}:{os.getpid()}"[:200]


def validation_worker_version() -> str | None:
    version = os.getenv("FLY_IMAGE_REF") or os.getenv("SOURCE_VERSION")
    if not version:
        return None
    return version[:50]


def validation_worker_lease_seconds() -> int:
    return max(15, _DEFAULT_LEASE_SECONDS)


def validation_worker_max_attempts() -> int:
    return max(1, _DEFAULT_MAX_ATTEMPTS)


def heartbeat_fresh_seconds() -> int:
    return max(15, _DEFAULT_HEARTBEAT_FRESH_SECONDS)


async def record_worker_heartbeat(
    db: AsyncSession,
    *,
    runner_id: str | None = None,
    status: str = "idle",
    current_scan_job_id: UUID | None = None,
    detail: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    runner = runner_id or validation_runner_id()
    result = await db.execute(
        select(ValidationWorkerHeartbeat).where(
            ValidationWorkerHeartbeat.runner_id == runner
        )
    )
    heartbeat = result.scalar_one_or_none()
    if heartbeat is None:
        heartbeat = ValidationWorkerHeartbeat(
            runner_id=runner,
            hostname=socket.gethostname(),
            process_id=os.getpid(),
            fly_machine_id=os.getenv("FLY_MACHINE_ID"),
            started_at=_STARTED_AT,
            last_seen_at=now,
            status=status,
            current_scan_job_id=current_scan_job_id,
            sandbox_mode=validation_sandbox_mode(),
            runtime_mode=validation_runtime_mode(),
            version=validation_worker_version(),
            detail=detail,
        )
        db.add(heartbeat)
        return
    heartbeat.hostname = socket.gethostname()
    heartbeat.process_id = os.getpid()
    heartbeat.fly_machine_id = os.getenv("FLY_MACHINE_ID")
    heartbeat.started_at = _STARTED_AT
    heartbeat.last_seen_at = now
    heartbeat.status = status
    heartbeat.current_scan_job_id = current_scan_job_id
    heartbeat.sandbox_mode = validation_sandbox_mode()
    heartbeat.runtime_mode = validation_runtime_mode()
    heartbeat.version = validation_worker_version()
    heartbeat.detail = detail


async def get_runner_queue_status(
    db: AsyncSession,
    *,
    threat_model_id: UUID | None = None,
) -> RunnerQueueStatus:
    now = datetime.now(timezone.utc)
    fresh_cutoff = now - timedelta(seconds=heartbeat_fresh_seconds())
    stale_cutoff = now - timedelta(seconds=validation_worker_lease_seconds())

    pending_query = select(func.count(ScanJob.id)).where(ScanJob.status == "pending")
    running_query = select(func.count(ScanJob.id)).where(ScanJob.status == "running")
    failed_query = select(func.count(ScanJob.id)).where(ScanJob.status == "failed")
    oldest_pending_query = select(func.min(ScanJob.created_at)).where(ScanJob.status == "pending")
    oldest_running_query = select(func.min(ScanJob.started_at)).where(ScanJob.status == "running")
    stale_running_query = select(func.count(ScanJob.id)).where(
        ScanJob.status == "running",
        (
            (ScanJob.lease_expires_at.is_not(None) & (ScanJob.lease_expires_at < now))
            | (
                ScanJob.lease_expires_at.is_(None)
                & (ScanJob.started_at < stale_cutoff)
            )
        ),
    )
    if threat_model_id is not None:
        pending_query = pending_query.where(ScanJob.threat_model_id == threat_model_id)
        running_query = running_query.where(ScanJob.threat_model_id == threat_model_id)
        failed_query = failed_query.where(ScanJob.threat_model_id == threat_model_id)
        oldest_pending_query = oldest_pending_query.where(ScanJob.threat_model_id == threat_model_id)
        oldest_running_query = oldest_running_query.where(ScanJob.threat_model_id == threat_model_id)
        stale_running_query = stale_running_query.where(ScanJob.threat_model_id == threat_model_id)

    pending_count = int((await db.execute(pending_query)).scalar_one() or 0)
    running_count = int((await db.execute(running_query)).scalar_one() or 0)
    failed_count = int((await db.execute(failed_query)).scalar_one() or 0)
    oldest_pending = (await db.execute(oldest_pending_query)).scalar_one_or_none()
    oldest_running = (await db.execute(oldest_running_query)).scalar_one_or_none()
    stale_running_count = int((await db.execute(stale_running_query)).scalar_one() or 0)

    active_workers = int(
        (
            await db.execute(
                select(func.count(ValidationWorkerHeartbeat.runner_id)).where(
                    ValidationWorkerHeartbeat.last_seen_at >= fresh_cutoff
                )
            )
        ).scalar_one()
        or 0
    )
    last_heartbeat = (
        await db.execute(select(func.max(ValidationWorkerHeartbeat.last_seen_at)))
    ).scalar_one_or_none()

    if not managed_validation_runner_enabled() and active_workers == 0:
        status = "ready"
        detail = "Managed validation runner is not required in this runtime."
    elif active_workers == 0:
        status = "degraded"
        detail = "No fresh managed validation worker heartbeat has been observed."
    elif stale_running_count:
        status = "degraded"
        detail = "One or more running validation jobs have stale worker heartbeats."
    elif pending_count:
        status = "queued"
        detail = "Validation jobs are waiting for the managed runner."
    elif running_count:
        status = "running"
        detail = "The managed runner is processing validation jobs."
    else:
        status = "ready"
        detail = "Managed validation runner is connected and idle."

    return RunnerQueueStatus(
        pending_count=pending_count,
        running_count=running_count,
        failed_count=failed_count,
        oldest_pending_age_seconds=_age_seconds(now, oldest_pending),
        oldest_running_age_seconds=_age_seconds(now, oldest_running),
        stale_running_count=stale_running_count,
        active_worker_count=active_workers,
        last_heartbeat_at=last_heartbeat,
        status=status,
        detail=detail,
    )


def _age_seconds(now: datetime, value: datetime | None) -> int | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0, int((now - value).total_seconds()))
