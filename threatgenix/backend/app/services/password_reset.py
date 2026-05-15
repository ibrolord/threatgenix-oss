"""Password reset service: token generation, validation, and password update."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.password_reset import PasswordResetToken
from app.models.user import User
from app.services.auth import hash_password


def _hash_token(token: str) -> str:
    """HMAC-SHA256 digest of a reset token."""
    return hmac.new(
        settings.secret_key.encode(),
        token.strip().encode(),
        hashlib.sha256,
    ).hexdigest()


async def create_reset_token(db: AsyncSession, email: str) -> str | None:
    """Generate a reset token for the user with the given email.

    Returns the plaintext token (to be sent via email in production),
    or None if no user with that email exists.
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is None or not getattr(user, "is_active", True):
        return None

    token = secrets.token_urlsafe(32)
    await db.execute(
        sa_update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used == False,  # noqa: E712
        )
        .values(used=True)
    )
    record = PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(record)
    await db.flush()
    return token


async def reset_password(db: AsyncSession, token: str, new_password: str) -> bool:
    """Validate a reset token and update the user's password.

    Returns True on success, False if the token is invalid/expired/used.
    """
    token_hash = _hash_token(token)
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used == False,  # noqa: E712
            PasswordResetToken.expires_at > datetime.now(timezone.utc),
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        return False

    # Update password
    user_result = await db.execute(select(User).where(User.id == record.user_id))
    user = user_result.scalar_one_or_none()
    if user is None:
        return False

    user.hashed_password = hash_password(new_password)
    record.used = True
    await db.flush()
    return True
