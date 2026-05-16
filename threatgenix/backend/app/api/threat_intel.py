"""Threat intelligence API endpoints.

Provides sync triggers and status monitoring for all 6 intel sources.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.services.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/threat-intel",
    tags=["threat-intel"],
)


def _require_threat_intel_admin(current_user: User) -> None:
    if getattr(current_user, "role", None) != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required to access threat intelligence operations.",
        )


@router.get("/status")
async def get_intel_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get sync status for all threat intelligence sources."""
    from app.services.threat_intel.sync import get_sync_status

    _require_threat_intel_admin(current_user)
    statuses = await get_sync_status(db)
    sanitized_statuses = [
        {
            key: value
            for key, value in status.items()
            if key not in {"error", "error_message", "traceback"}
        }
        | {"has_error": bool(status.get("error") or status.get("error_message"))}
        for status in statuses
    ]
    return {
        "sources": sanitized_statuses,
        "total_sources": 6,
        "synced": sum(1 for s in statuses if s["status"] == "complete"),
    }


@router.post("/sync/all")
async def sync_all_sources(
    background_tasks: BackgroundTasks,
    with_embeddings: bool = Query(
        True, description="Generate embeddings using the configured embedding provider"
    ),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger full sync of all threat intelligence sources.

    This is the initial seed operation. Runs in background.
    Use GET /api/threat-intel/status to monitor progress.
    """
    _require_threat_intel_admin(current_user)
    background_tasks.add_task(_run_sync_all, with_embeddings)

    return {
        "status": "started",
        "message": "Full threat intelligence sync started. Check /api/threat-intel/status for progress.",
    }


@router.post("/sync/daily")
async def sync_daily_sources(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger daily sync (KEV + CCCS only). Runs in background."""
    _require_threat_intel_admin(current_user)
    background_tasks.add_task(_run_sync_daily)
    return {
        "status": "started",
        "message": "Daily sync started. Check /api/threat-intel/status for progress.",
    }


@router.post("/sync/quarterly")
async def sync_quarterly_sources(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger quarterly sync (ATT&CK + CAPEC + CWE). Runs in background."""
    _require_threat_intel_admin(current_user)
    background_tasks.add_task(_run_sync_quarterly)
    return {
        "status": "started",
        "message": "Quarterly sync started. Check /api/threat-intel/status for progress.",
    }


async def _run_sync_all(with_embeddings: bool = True) -> None:
    """Background task: run full sync with its own DB session."""
    from app.database import async_session
    from app.services.threat_intel.sync import sync_all

    async with async_session() as db:
        try:
            results = await sync_all(db, with_embeddings=with_embeddings)
            logger.info("Background sync_all complete: %s", results)
        except Exception as exc:
            logger.error("Background sync_all failed: %s", exc)


async def _run_sync_daily() -> None:
    """Background task: run daily sync with its own DB session."""
    from app.database import async_session
    from app.services.threat_intel.sync import sync_daily

    async with async_session() as db:
        try:
            results = await sync_daily(db)
            logger.info("Background sync_daily complete: %s", results)
        except Exception as exc:
            logger.error("Background sync_daily failed: %s", exc)


async def _run_sync_quarterly() -> None:
    """Background task: run quarterly sync with its own DB session."""
    from app.database import async_session
    from app.services.threat_intel.sync import sync_quarterly

    async with async_session() as db:
        try:
            results = await sync_quarterly(db)
            logger.info("Background sync_quarterly complete: %s", results)
        except Exception as exc:
            logger.error("Background sync_quarterly failed: %s", exc)
