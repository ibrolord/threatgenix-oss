"""Tests for scan credential broker ownership and retention gates."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.scan_credential_service import (
    credential_is_active,
    get_credential_for_job,
    purge_expired_credentials,
)


def _scalar_result(value):
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    return result


def test_credential_is_active_without_expiry():
    assert credential_is_active(SimpleNamespace(expires_at=None)) is True


def test_credential_is_active_rejects_expired_short_lived_credential():
    now = datetime(2026, 4, 29, tzinfo=timezone.utc)
    cred = SimpleNamespace(expires_at=now - timedelta(seconds=1))

    assert credential_is_active(cred, now=now) is False


def test_credential_is_active_accepts_future_short_lived_credential():
    now = datetime(2026, 4, 29, tzinfo=timezone.utc)
    cred = SimpleNamespace(expires_at=now + timedelta(minutes=5))

    assert credential_is_active(cred, now=now) is True


@pytest.mark.asyncio
async def test_credential_broker_returns_none_for_expired_credential():
    now = datetime.now(timezone.utc)
    expired_cred = SimpleNamespace(expires_at=now - timedelta(seconds=1))
    db = MagicMock()
    db.execute = AsyncMock(return_value=_scalar_result(expired_cred))

    credential = await get_credential_for_job(
        db,
        credential_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
    )

    assert credential is None


@pytest.mark.asyncio
async def test_credential_broker_returns_active_credential():
    active_cred = SimpleNamespace(expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    db = MagicMock()
    db.execute = AsyncMock(return_value=_scalar_result(active_cred))

    credential = await get_credential_for_job(
        db,
        credential_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
    )

    assert credential is active_cred


@pytest.mark.asyncio
async def test_purge_expired_credentials_reports_deleted_count():
    result = SimpleNamespace(rowcount=2)
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    deleted = await purge_expired_credentials(db, now=datetime.now(timezone.utc))

    assert deleted == 2
    db.execute.assert_awaited_once()
