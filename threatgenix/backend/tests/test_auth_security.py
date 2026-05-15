"""Tests for auth security hardening: rate limiting and token revocation."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import Result

from app.config import settings
from app.database import get_db
from app.main import app
from app.models.user import User
from app.services.auth import (
    _revoked_jtis,
    ALGORITHM,
    get_current_user,
    hash_password,
)

BASE_URL = "http://test"


def _make_fake_user(hashed_pw: str | None = None) -> MagicMock:
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = "pilot@example.test"
    user.full_name = "Priya Sharma"
    user.role = "admin"
    user.is_active = True
    user.hashed_password = hashed_pw or hash_password("Secure123!")
    user.organization_id = None
    user.organization = None
    user.report_template_library = None
    return user


@pytest.fixture(autouse=True)
def _clean_revoked_jtis():
    """Ensure auth security tests are isolated from suite-level overrides."""
    _revoked_jtis.clear()
    app.dependency_overrides.pop(get_current_user, None)
    yield
    _revoked_jtis.clear()
    app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_rate_limit():
    """POST /api/auth/login should return 429 after exceeding 10 req/min."""
    db = AsyncMock()
    # Make every login return the fake user (credentials are wrong, so we get 401,
    # but the rate limiter fires regardless of auth outcome).
    mock_result = MagicMock(spec=Result)
    mock_result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_result)

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            statuses = []
            for _ in range(12):
                resp = await client.post(
                    "/api/auth/login",
                    json={"email": "x@test.com", "password": "wrong"},
                )
                statuses.append(resp.status_code)

            # First 10 should be 401 (wrong creds), 11th+ should be 429
            assert 429 in statuses, f"Expected 429 in responses, got: {statuses}"
            # First request should NOT be 429
            assert statuses[0] != 429
    finally:
        app.dependency_overrides.pop(get_db, None)
        # Reset rate limiter state so other tests aren't affected
        from app.limiter import limiter
        limiter.reset()


# ---------------------------------------------------------------------------
# Logout / token revocation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_invalidates_token():
    """Login, logout, then /me with same token should return 401."""
    fake_user = _make_fake_user(hash_password("Secure123!"))

    db = AsyncMock()
    mock_result = MagicMock(spec=Result)
    mock_result.scalar_one_or_none.return_value = fake_user
    db.execute = AsyncMock(return_value=mock_result)

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            # 1. Login
            login_resp = await client.post(
                "/api/auth/login",
                json={"email": "pilot@example.test", "password": "Secure123!"},
            )
            assert login_resp.status_code == 200, login_resp.text
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # 2. Verify /me works
            me_resp = await client.get("/api/auth/me", headers=headers)
            assert me_resp.status_code == 200

            # 3. Logout
            logout_resp = await client.post("/api/auth/logout", headers=headers)
            assert logout_resp.status_code == 204

            # 4. /me with same token should fail
            me_resp2 = await client.get("/api/auth/me", headers=headers)
            assert me_resp2.status_code == 401
    finally:
        app.dependency_overrides.pop(get_db, None)
        from app.limiter import limiter
        limiter.reset()


@pytest.mark.asyncio
async def test_logout_requires_auth():
    """POST /logout without a token should return 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.post("/api/auth/logout")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_current_user_rejects_malformed_subject_as_unauthorized():
    """A signed token with a non-UUID subject should fail closed."""
    token = jwt.encode(
        {"sub": "not-a-uuid", "jti": str(uuid.uuid4())},
        settings.secret_key,
        algorithm=ALGORITHM,
    )

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token=token, db=AsyncMock())

    assert exc_info.value.status_code == 401
