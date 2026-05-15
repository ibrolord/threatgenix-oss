"""Tests for threat catalog and manual threat creation endpoints."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.threat_catalog import _require_owner
from app.database import get_db
from app.main import app
from app.services.auth import get_current_user

BASE_URL = "http://test"


class FakeUser:
    id = uuid.uuid4()
    email = "catalog@example.com"
    full_name = "Catalog User"
    role = "admin"
    is_active = True


async def override_get_current_user():
    return FakeUser()


async def override_require_owner(threat_model_id: uuid.UUID):
    return FakeUser()


async def override_get_db():
    yield AsyncMock()


app.dependency_overrides[get_current_user] = override_get_current_user
app.dependency_overrides[_require_owner] = override_require_owner
app.dependency_overrides[get_db] = override_get_db


def _manual_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/manual"


def _mock_db_for_manual(existing_threats: list[object] | None = None):
    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = existing_threats or []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.add = MagicMock()
    mock_db.refresh = AsyncMock()
    return mock_db


@pytest.mark.asyncio
async def test_create_manual_custom_threat_succeeds():
    tm_id = uuid.uuid4()
    mock_db = _mock_db_for_manual()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            _manual_url(tm_id),
            json={
                "threat_subtype": "Treasury approval bypass",
                "description": "A privileged operator could bypass treasury approval controls.",
                "severity": "High",
                "stride_category": "Elevation of Privilege",
                "affected_node_ids": [],
            },
        )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "Manual"
    assert body["threat_subtype"] == "Treasury approval bypass"
    assert body["severity"] == "High"
    assert body["stride_category"] == "Elevation of Privilege"


@pytest.mark.asyncio
async def test_create_manual_custom_threat_rejects_invalid_node_ids():
    tm_id = uuid.uuid4()
    mock_db = _mock_db_for_manual()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            _manual_url(tm_id),
            json={
                "threat_subtype": "Invalid node test",
                "description": "Node IDs should be validated.",
                "severity": "Medium",
                "stride_category": "Tampering",
                "affected_node_ids": ["not-a-uuid"],
            },
        )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 400
    assert "affected_node_ids" in response.json()["detail"]
