"""Ingest CISA Known Exploited Vulnerabilities (KEV) catalog.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Format: JSON
Update frequency: Multiple times per week (daily sync recommended)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import KEVEntry

logger = logging.getLogger(__name__)

KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _parse_date(date_str: str | None) -> datetime | None:
    """Parse CISA KEV date format (YYYY-MM-DD)."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def ingest_kev(db: AsyncSession) -> int:
    """Download and ingest CISA KEV catalog.

    This is a deterministic lookup table — no embeddings needed.

    Args:
        db: Async database session.

    Returns:
        Number of KEV entries ingested.
    """
    from app.services.threat_intel.ingest_attack import _get_or_create_sync

    sync_record = await _get_or_create_sync(db, "kev")
    sync_record.status = "syncing"
    await db.commit()

    try:
        logger.info("Downloading CISA KEV catalog...")
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(KEV_JSON_URL)
            resp.raise_for_status()

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        logger.info("Parsed %d KEV entries", len(vulnerabilities))

        count = 0
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            existing = await db.execute(
                select(KEVEntry).where(KEVEntry.cve_id == cve_id)
            )
            row = existing.scalars().first()

            entry_data = {
                "cve_id": cve_id,
                "vendor_project": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "vulnerability_name": vuln.get("vulnerabilityName", ""),
                "date_added": _parse_date(vuln.get("dateAdded")),
                "short_description": vuln.get("shortDescription"),
                "required_action": vuln.get("requiredAction"),
                "due_date": _parse_date(vuln.get("dueDate")),
                "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
            }

            if row:
                for key, value in entry_data.items():
                    setattr(row, key, value)
            else:
                db.add(KEVEntry(**entry_data))
            count += 1

        await db.commit()

        sync_record.status = "complete"
        sync_record.last_sync_at = datetime.now(timezone.utc)
        sync_record.record_count = count
        sync_record.error_message = None
        await db.commit()

        logger.info("KEV ingestion complete: %d entries", count)
        return count

    except Exception as exc:
        sync_record.status = "error"
        sync_record.error_message = str(exc)[:500]
        await db.commit()
        logger.error("KEV ingestion failed: %s", exc)
        raise
