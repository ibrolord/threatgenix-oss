"""F-03: Ephemeral document handling — purge expired raw text.

Documents uploaded by users contain sensitive bank architecture data.
After 24 hours the raw_text is purged (set to NULL), but the parsed
components (DFD nodes/edges extracted from the text) are retained so
the threat model remains functional.

This is a data-minimization measure: we keep only what's needed for
the threat model to work, not the original source material.
"""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import update

from app.database import async_session
from app.models.document import Document

logger = logging.getLogger("threatgenix.doc_cleanup")


async def purge_expired_documents(now: datetime | None = None) -> int:
    """Purge raw_text from documents past their expires_at.

    Returns the number of documents purged.
    """
    now = now or datetime.now(timezone.utc)

    async with async_session() as session:
        # Find expired, unpurged documents
        stmt = (
            update(Document)
            .where(
                Document.expires_at <= now,
                Document.purged == False,  # noqa: E712
                Document.expires_at.isnot(None),
            )
            .values(raw_text=None, purged=True)
            .returning(Document.id)
        )
        result = await session.execute(stmt)
        purged_ids = result.scalars().all()
        await session.commit()

    count = len(purged_ids)
    if count > 0:
        logger.info("doc_cleanup purged=%d documents", count)
    return count


async def cleanup_loop(interval_seconds: int = 3600) -> None:
    """Run purge_expired_documents on a recurring interval.

    Default: every hour. Runs forever (call as a background task).
    """
    logger.info("doc_cleanup_loop started interval=%ds", interval_seconds)
    while True:
        try:
            await purge_expired_documents()
        except Exception as exc:
            logger.warning("doc_cleanup_loop error: %s", exc)
        await asyncio.sleep(interval_seconds)
