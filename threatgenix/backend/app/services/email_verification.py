"""Email verification service: code generation, storage, and validation."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.email_verification import EmailVerification
from app.models.user import User


def _hash_code(code: str) -> str:
    """HMAC-SHA256 digest of a verification code.

    The code is intentionally short for human entry, so use SECRET_KEY as a
    server-side pepper to keep leaked hashes from being trivially brute-forced.
    """
    return hmac.new(
        settings.secret_key.encode(),
        code.strip().upper().encode(),
        hashlib.sha256,
    ).hexdigest()


async def create_verification_code(db: AsyncSession, user_id) -> str:
    """Generate a 6-char alphanumeric code, store its hash, and return the plaintext code."""
    code = secrets.token_hex(3).upper()[:6]  # 6 hex chars, uppercase
    await db.execute(
        sa_update(EmailVerification)
        .where(
            EmailVerification.user_id == user_id,
            EmailVerification.used == False,  # noqa: E712
        )
        .values(used=True)
    )
    record = EmailVerification(
        user_id=user_id,
        code_hash=_hash_code(code),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(record)
    await db.flush()
    return code


async def verify_email_code(db: AsyncSession, email: str, code: str) -> bool:
    """Validate a verification code for the given email. Returns True on success."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is None:
        return False

    code_hash = _hash_code(code)
    result = await db.execute(
        select(EmailVerification).where(
            EmailVerification.user_id == user.id,
            EmailVerification.code_hash == code_hash,
            EmailVerification.used == False,  # noqa: E712
            EmailVerification.expires_at > datetime.now(timezone.utc),
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        return False

    record.used = True
    user.email_verified = True
    await db.flush()
    return True
