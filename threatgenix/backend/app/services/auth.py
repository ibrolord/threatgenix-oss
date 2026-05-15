"""Authentication service: JWT tokens, password hashing, current_user dependency."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import get_db
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(user_id: UUID) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": str(user_id), "exp": expire, "jti": str(uuid4())}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


# ---------------------------------------------------------------------------
# Token revocation (in-memory; sufficient for pilot with single instance)
# ---------------------------------------------------------------------------
_revoked_jtis: set[str] = set()


def revoke_token(jti: str) -> None:
    """Mark a JTI as revoked so the token can no longer authenticate."""
    _revoked_jtis.add(jti)


def is_token_revoked(jti: str) -> bool:
    return jti in _revoked_jtis


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        jti = payload.get("jti")
        if jti and is_token_revoked(jti):
            raise credentials_exception
        user_uuid = UUID(user_id)
    except (JWTError, ValueError):
        raise credentials_exception

    result = await db.execute(
        select(User)
        .where(User.id == user_uuid)
        .options(selectinload(User.organization))
    )
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    if settings.auth_require_email_verification and not getattr(user, "email_verified", False):
        raise credentials_exception
    organization = getattr(user, "organization", None)
    if (
        settings.app_env in {"production", "staging"}
        and getattr(user, "organization_id", None) is None
    ):
        raise credentials_exception
    if organization is not None and not getattr(organization, "is_active", True):
        raise credentials_exception
    return user
