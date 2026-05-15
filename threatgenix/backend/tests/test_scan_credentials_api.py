"""Tests for the scan credentials CRUD API (Phase S2).

Uses the mock DB + ASGITransport pattern consistent with the rest of the test suite.
Crypto correctness is covered in test_credential_crypto.py.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user

BASE_URL = "http://test"
FAKE_USER_ID = uuid.uuid4()
FAKE_TM_ID = uuid.uuid4()
FAKE_CRED_ID = uuid.uuid4()


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeUser:
    id = FAKE_USER_ID
    email = "creds@test.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


class FakeThreatModel:
    id = FAKE_TM_ID
    owner_id = FAKE_USER_ID
    system_name = "Test TM"


class FakeCredential:
    id = FAKE_CRED_ID
    threat_model_id = FAKE_TM_ID
    owner_id = FAKE_USER_ID
    name = "Prod Bearer"
    credential_type = "bearer_token"
    header_name = None
    encrypted_secret = "encrypted-placeholder"
    expires_at = None
    created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# DB mock helpers
# ---------------------------------------------------------------------------

def _make_scalar_result(value):
    m = MagicMock()
    m.scalar_one_or_none.return_value = value
    return m


def _make_scalars_result(values):
    inner = MagicMock()
    inner.all.return_value = list(values)
    m = MagicMock()
    m.scalars.return_value = inner
    return m


async def _override_get_current_user():
    return FakeUser()


# ---------------------------------------------------------------------------
# Tests: response schema — secret never exposed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_credentials_never_exposes_secret():
    """List response must not include the encrypted_secret field."""
    cred = FakeCredential()
    fake_db = AsyncMock()
    fake_db.execute.return_value = _make_scalars_result([cred])

    async def _db():
        yield fake_db

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    # Patch the ownership check so it doesn't hit DB
    import app.api.scan_credentials as creds_api
    orig = creds_api._get_threat_model_for_owner

    async def _mock_owner(*a, **kw):
        return FakeThreatModel()

    creds_api._get_threat_model_for_owner = _mock_owner

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            resp = await client.get(
                f"/api/threat-models/{FAKE_TM_ID}/scan-credentials",
                headers={"Authorization": "Bearer fake-token"},
            )
        assert resp.status_code == 200
        body = resp.text
        assert "encrypted_secret" not in body
        assert "encrypted-placeholder" not in body
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "Prod Bearer"
        assert "secret" not in data[0]
    finally:
        creds_api._get_threat_model_for_owner = orig
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_create_credential_response_never_exposes_secret():
    """Create response must not include the plaintext or encrypted secret."""
    from app.services.credential_crypto import encrypt_secret

    created_cred = FakeCredential()
    created_cred.encrypted_secret = encrypt_secret("my-actual-token")

    fake_db = AsyncMock()
    fake_db.execute.return_value = _make_scalar_result(FakeThreatModel())
    fake_db.add = MagicMock()

    async def _db():
        yield fake_db

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    import app.api.scan_credentials as creds_api
    orig = creds_api._get_threat_model_for_owner

    async def _mock_owner(*a, **kw):
        return FakeThreatModel()

    creds_api._get_threat_model_for_owner = _mock_owner

    # Patch db.refresh to populate the returned cred
    async def _refresh(obj):
        obj.id = FAKE_CRED_ID
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    fake_db.refresh = _refresh

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            resp = await client.post(
                f"/api/threat-models/{FAKE_TM_ID}/scan-credentials",
                json={"name": "Tok", "credential_type": "bearer_token", "secret": "my-actual-token"},
                headers={"Authorization": "Bearer fake-token"},
            )
        assert resp.status_code == 201
        body = resp.text
        assert "my-actual-token" not in body
        assert "encrypted_secret" not in body
        assert "secret" not in resp.json()
    finally:
        creds_api._get_threat_model_for_owner = orig
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_create_short_lived_credential_preserves_expiry_without_secret():
    """Short-lived credential metadata is returned, but plaintext/encrypted secrets are not."""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    fake_db = AsyncMock()
    fake_db.execute.return_value = _make_scalar_result(FakeThreatModel())
    fake_db.add = MagicMock()

    async def _db():
        yield fake_db

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    import app.api.scan_credentials as creds_api
    orig = creds_api._get_threat_model_for_owner

    async def _mock_owner(*a, **kw):
        return FakeThreatModel()

    creds_api._get_threat_model_for_owner = _mock_owner

    async def _refresh(obj):
        obj.id = FAKE_CRED_ID
        obj.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        obj.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    fake_db.refresh = _refresh

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            resp = await client.post(
                f"/api/threat-models/{FAKE_TM_ID}/scan-credentials",
                json={
                    "name": "Ephemeral Tok",
                    "credential_type": "bearer_token",
                    "secret": "temporary-token",
                    "expires_at": expires_at.isoformat(),
                },
                headers={"Authorization": "Bearer fake-token"},
            )
        assert resp.status_code == 201
        body = resp.text
        assert "temporary-token" not in body
        assert "encrypted_secret" not in body
        data = resp.json()
        assert data["expires_at"] is not None
        assert "secret" not in data
    finally:
        creds_api._get_threat_model_for_owner = orig
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


def test_create_credential_rejects_expired_retention_deadline():
    from pydantic import ValidationError

    from app.schemas.scan_credential import ScanCredentialCreate

    with pytest.raises(ValidationError, match="expires_at must be in the future"):
        ScanCredentialCreate(
            name="Expired",
            credential_type="bearer_token",
            secret="already-expired",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )


@pytest.mark.asyncio
async def test_unauthenticated_returns_401():
    """No auth header → 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
        resp = await client.get(f"/api/threat-models/{FAKE_TM_ID}/scan-credentials")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_key_header_requires_header_name_returns_422():
    """api_key_header type without header_name → 422."""
    fake_db = AsyncMock()

    async def _db():
        yield fake_db

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    import app.api.scan_credentials as creds_api
    orig = creds_api._get_threat_model_for_owner

    async def _mock_owner(*a, **kw):
        return FakeThreatModel()

    creds_api._get_threat_model_for_owner = _mock_owner

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            resp = await client.post(
                f"/api/threat-models/{FAKE_TM_ID}/scan-credentials",
                json={"name": "Key", "credential_type": "api_key_header", "secret": "x"},
                headers={"Authorization": "Bearer fake-token"},
            )
        assert resp.status_code == 422
    finally:
        creds_api._get_threat_model_for_owner = orig
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_delete_nonexistent_credential_returns_404():
    """DELETE on missing credential_id → 404."""
    fake_db = AsyncMock()
    fake_db.execute.return_value = _make_scalar_result(None)  # cred not found

    async def _db():
        yield fake_db

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    import app.api.scan_credentials as creds_api
    orig = creds_api._get_threat_model_for_owner

    async def _mock_owner(*a, **kw):
        return FakeThreatModel()

    creds_api._get_threat_model_for_owner = _mock_owner

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            resp = await client.delete(
                f"/api/threat-models/{FAKE_TM_ID}/scan-credentials/{uuid.uuid4()}",
                headers={"Authorization": "Bearer fake-token"},
            )
        assert resp.status_code == 404
    finally:
        creds_api._get_threat_model_for_owner = orig
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)
