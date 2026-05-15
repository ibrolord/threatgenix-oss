"""Orchestrate threat intelligence sync across all sources.

Provides a single entry point to sync all feeds, plus individual source
sync functions for daily/quarterly cadence.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import ThreatIntelSync

logger = logging.getLogger(__name__)


async def sync_all(db: AsyncSession, with_embeddings: bool = True) -> dict[str, int]:
    """Run full sync of all threat intelligence sources.

    This is the initial seed operation. Takes ~10-30 minutes depending
    on embedding generation speed.

    Args:
        db: Async database session.
        with_embeddings: Whether to generate embeddings (requires Bedrock).

    Returns:
        Dict mapping source name to number of records ingested.
    """
    from app.services.threat_intel.ingest_attack import ingest_attack
    from app.services.threat_intel.ingest_capec import ingest_capec
    from app.services.threat_intel.ingest_cccs import ingest_cccs
    from app.services.threat_intel.ingest_cri import ingest_cri
    from app.services.threat_intel.ingest_cwe import ingest_cwe
    from app.services.threat_intel.ingest_kev import ingest_kev

    results: dict[str, int] = {}

    # Order matters: CRI depends on ATT&CK IDs being present for context
    sources = [
        ("attack", lambda: ingest_attack(db, with_embeddings=with_embeddings)),
        ("capec", lambda: ingest_capec(db, with_embeddings=with_embeddings)),
        ("cwe", lambda: ingest_cwe(db, with_embeddings=with_embeddings)),
        ("cri", lambda: ingest_cri(db)),
        ("kev", lambda: ingest_kev(db)),
        ("cccs", lambda: ingest_cccs(db, with_embeddings=with_embeddings)),
    ]

    for name, ingest_fn in sources:
        try:
            logger.info("Syncing %s...", name)
            count = await ingest_fn()
            results[name] = count
            logger.info("Synced %s: %d records", name, count)
        except Exception as exc:
            logger.error("Failed to sync %s: %s", name, exc)
            results[name] = -1

    return results


async def sync_daily(db: AsyncSession) -> dict[str, int]:
    """Daily sync: KEV + CCCS only (fast, <1 minute)."""
    from app.services.threat_intel.ingest_cccs import ingest_cccs
    from app.services.threat_intel.ingest_kev import ingest_kev

    results: dict[str, int] = {}

    for name, ingest_fn in [
        ("kev", lambda: ingest_kev(db)),
        ("cccs", lambda: ingest_cccs(db, with_embeddings=True)),
    ]:
        try:
            count = await ingest_fn()
            results[name] = count
        except Exception as exc:
            logger.error("Daily sync failed for %s: %s", name, exc)
            results[name] = -1

    return results


async def sync_quarterly(db: AsyncSession) -> dict[str, int]:
    """Quarterly sync: ATT&CK + CAPEC + CWE (slow, ~10-30 minutes)."""
    from app.services.threat_intel.ingest_attack import ingest_attack
    from app.services.threat_intel.ingest_capec import ingest_capec
    from app.services.threat_intel.ingest_cwe import ingest_cwe

    results: dict[str, int] = {}

    for name, ingest_fn in [
        ("attack", lambda: ingest_attack(db, with_embeddings=True)),
        ("capec", lambda: ingest_capec(db, with_embeddings=True)),
        ("cwe", lambda: ingest_cwe(db, with_embeddings=True)),
    ]:
        try:
            count = await ingest_fn()
            results[name] = count
        except Exception as exc:
            logger.error("Quarterly sync failed for %s: %s", name, exc)
            results[name] = -1

    return results


async def get_sync_status(db: AsyncSession) -> list[dict]:
    """Get sync status for all threat intel sources."""
    result = await db.execute(select(ThreatIntelSync))
    syncs = result.scalars().all()

    return [
        {
            "source": s.source_name,
            "status": s.status,
            "last_sync": s.last_sync_at.isoformat() if s.last_sync_at else None,
            "record_count": s.record_count,
            "version": s.version,
            "error": s.error_message,
        }
        for s in syncs
    ]
