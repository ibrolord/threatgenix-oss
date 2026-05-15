"""Service layer for resolving scan credentials.

Encapsulates DB lookup + ownership enforcement so callers (e.g. scan_worker)
work with a plain decrypted secret without knowing storage/crypto details.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanCredential


def credential_is_active(
    credential: ScanCredential,
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether a credential is still within its optional retention window."""
    expires_at = getattr(credential, "expires_at", None)
    if expires_at is None:
        return True
    current = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at > current


async def get_credential_for_job(
    db: AsyncSession,
    credential_id: UUID,
    owner_id: UUID,
    threat_model_id: UUID,
) -> ScanCredential | None:
    """Return the ScanCredential matching all three ownership dimensions, or None.

    Never raises — returns None on mismatch so callers can produce a clear error.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(ScanCredential).where(
            ScanCredential.id == credential_id,
            ScanCredential.owner_id == owner_id,
            ScanCredential.threat_model_id == threat_model_id,
            or_(ScanCredential.expires_at.is_(None), ScanCredential.expires_at > now),
        )
    )
    credential = result.scalar_one_or_none()
    if credential is None or not credential_is_active(credential, now=now):
        return None
    return credential


async def purge_expired_credentials(
    db: AsyncSession,
    *,
    now: datetime | None = None,
) -> int:
    """Delete credentials past expires_at and return the number removed."""
    current = now or datetime.now(timezone.utc)
    result = await db.execute(
        delete(ScanCredential).where(
            ScanCredential.expires_at.is_not(None),
            ScanCredential.expires_at <= current,
        )
    )
    return int(result.rowcount or 0)
