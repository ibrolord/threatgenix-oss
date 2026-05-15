"""Enqueue due validation schedules.

Run with:
    python -m app.cli.run_validation_schedules

Set THREATGENIX_VALIDATION_SCHEDULER_RUN_INLINE=true to execute queued jobs
in the same process after enqueueing. Production should normally run queued
jobs through the existing worker path instead.
"""

from __future__ import annotations

import asyncio

from app.database import async_session
from app.services.scan_worker import run_scan_job
from app.services.validation_env import validation_env_flag
from app.services.validation_scheduler import enqueue_due_validation_runs


def _env_flag(name: str) -> bool:
    return validation_env_flag(name)


async def main() -> None:
    async with async_session() as db:
        jobs = await enqueue_due_validation_runs(db)
    if _env_flag("THREATGENIX_VALIDATION_SCHEDULER_RUN_INLINE"):
        for job in jobs:
            await run_scan_job(job.id)
    print(f"queued {len(jobs)} validation run(s)")


if __name__ == "__main__":
    asyncio.run(main())
