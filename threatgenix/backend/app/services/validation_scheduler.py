"""Scheduled validation run enqueueing."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanAuthorization, ScanJob, ValidationSchedule
from app.schemas.scan import AUTHORIZATION_TEXT
from app.services.validation_lab import (
    due_validation_schedules,
    next_run_at_for_cadence,
    validation_schedule_response,
)
from app.services.validation_runtime import validation_run_submission_enabled


async def enqueue_due_validation_runs(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 25,
) -> list[ScanJob]:
    """Create pending ScanJob rows for due validation schedules.

    This function does not execute scanners. A cron/worker can call it, commit
    the pending jobs, then let the existing scan worker process those jobs.
    """
    current_time = now or datetime.now(timezone.utc)
    if not validation_run_submission_enabled():
        return []
    schedules = await due_validation_schedules(db, now=current_time, limit=limit)
    jobs: list[ScanJob] = []
    schedule_updates = False
    for schedule in schedules:
        job = _scan_job_for_schedule(schedule)
        if job is None:
            schedule.next_run_at = next_run_at_for_cadence(schedule.cadence, from_time=current_time)
            schedule_updates = True
            continue

        db.add(job)
        await db.flush()
        db.add(
            ScanAuthorization(
                scan_job_id=job.id,
                user_id=schedule.owner_id,
                acknowledged_text=AUTHORIZATION_TEXT,
                ip_address="scheduled-validation-worker",
                targets_snapshot=job.targets,
            )
        )
        schedule.last_run_at = current_time
        schedule.next_run_at = (
            next_run_at_for_cadence(schedule.cadence, from_time=current_time)
            if schedule.enabled
            else None
        )
        schedule_updates = True
        jobs.append(job)

    if jobs or schedule_updates:
        await db.commit()
        for job in jobs:
            await db.refresh(job)
    return jobs


def _scan_job_for_schedule(schedule: ValidationSchedule) -> ScanJob | None:
    schedule_state = validation_schedule_response(schedule)
    if not schedule_state.runnable:
        return None
    if schedule.authorization_acknowledged_at is None:
        return None
    targets = (
        {str(schedule.target_node_id): schedule.target}
        if schedule.target_node_id is not None
        else {"direct": schedule.target}
    )
    return ScanJob(
        threat_model_id=schedule.threat_model_id,
        owner_id=schedule.owner_id,
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
