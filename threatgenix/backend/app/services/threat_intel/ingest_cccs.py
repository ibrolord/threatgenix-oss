"""Ingest Canadian Centre for Cyber Security (CCCS) advisories via RSS.

Source: https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en
Format: RSS/Atom
Update frequency: Daily sync recommended
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import CCSCAdvisory
from app.services.threat_intel.embeddings import (
    build_embedding_text_advisory,
    generate_embeddings_batch,
)

logger = logging.getLogger(__name__)

CCCS_RSS_URL = (
    "https://www.cyber.gc.ca/api/cccs/atom/v1/get"
    "?feed=alerts_advisories&lang=en"
)

# Regex to extract CVE IDs from advisory text
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

# Regex to extract ATT&CK technique IDs
ATTACK_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


def _extract_advisory_id(link: str, title: str) -> str:
    """Extract advisory ID from the URL or generate from title."""
    # CCCS URLs often contain the advisory ID like AV25-123
    match = re.search(r"(AV\d{2}-\d+|AL\d{2}-\d+)", link)
    if match:
        return match.group(1)
    # Fallback: hash of link
    import hashlib
    return f"CCCS-{hashlib.sha256(link.encode()).hexdigest()[:12]}"


def _parse_date_safe(date_str: str | None) -> datetime | None:
    """Parse various date formats from RSS feeds."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        pass
    # Try ISO format
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


async def ingest_cccs(db: AsyncSession, with_embeddings: bool = True) -> int:
    """Download and ingest CCCS advisories from RSS feed.

    Args:
        db: Async database session.
        with_embeddings: Whether to generate embeddings.

    Returns:
        Number of advisories ingested.
    """
    from app.services.threat_intel.ingest_attack import _get_or_create_sync

    sync_record = await _get_or_create_sync(db, "cccs")
    sync_record.status = "syncing"
    await db.commit()

    try:
        logger.info("Downloading CCCS RSS feed...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(CCCS_RSS_URL)
            resp.raise_for_status()

        feed = feedparser.parse(resp.text)
        entries = feed.get("entries", [])
        logger.info("Parsed %d CCCS advisories from RSS", len(entries))

        advisories_data: list[dict] = []
        for entry in entries:
            title = entry.get("title", "")
            link = entry.get("link", "")
            summary = entry.get("summary", entry.get("description", ""))

            advisory_id = _extract_advisory_id(link, title)
            published = _parse_date_safe(entry.get("published"))
            updated = _parse_date_safe(entry.get("updated"))

            # Extract referenced CVEs and ATT&CK IDs from summary
            full_text = f"{title} {summary}"
            referenced_cves = list(set(CVE_PATTERN.findall(full_text)))
            referenced_attacks = list(set(ATTACK_PATTERN.findall(full_text)))

            advisories_data.append({
                "advisory_id": advisory_id,
                "title": title[:500],
                "summary": summary[:5000] if summary else None,
                "published_date": published,
                "updated_date": updated,
                "url": link[:500] if link else None,
                "referenced_cves": referenced_cves,
                "referenced_attack_ids": referenced_attacks,
            })

        # Generate embeddings
        embeddings: list[list[float]] | None = None
        if with_embeddings and advisories_data:
            logger.info("Generating embeddings for %d advisories...", len(advisories_data))
            texts = [
                build_embedding_text_advisory(
                    a["advisory_id"], a["title"], a["summary"] or ""
                )
                for a in advisories_data
            ]
            embeddings = generate_embeddings_batch(texts)

        # Upsert
        count = 0
        for i, data in enumerate(advisories_data):
            existing = await db.execute(
                select(CCSCAdvisory).where(
                    CCSCAdvisory.advisory_id == data["advisory_id"]
                )
            )
            row = existing.scalars().first()
            embedding = embeddings[i] if embeddings else None

            if row:
                row.title = data["title"]
                row.summary = data["summary"]
                row.published_date = data["published_date"]
                row.updated_date = data["updated_date"]
                row.url = data["url"]
                row.referenced_cves = data["referenced_cves"]
                row.referenced_attack_ids = data["referenced_attack_ids"]
                if embedding:
                    row.embedding = embedding
            else:
                db.add(CCSCAdvisory(**data, embedding=embedding))
            count += 1

        await db.commit()

        sync_record.status = "complete"
        sync_record.last_sync_at = datetime.now(timezone.utc)
        sync_record.record_count = count
        sync_record.error_message = None
        await db.commit()

        logger.info("CCCS ingestion complete: %d advisories", count)
        return count

    except Exception as exc:
        sync_record.status = "error"
        sync_record.error_message = str(exc)[:500]
        await db.commit()
        logger.error("CCCS ingestion failed: %s", exc)
        raise
