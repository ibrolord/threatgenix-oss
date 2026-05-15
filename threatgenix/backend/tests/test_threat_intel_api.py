from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.auth import get_current_user


BASE_URL = "http://test"


def _user(role: str) -> SimpleNamespace:
    return SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001",
        email=f"{role}@example.com",
        full_name=f"{role.title()} User",
        role=role,
        is_active=True,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/threat-intel/sync/all",
        "/api/threat-intel/sync/daily",
        "/api/threat-intel/sync/quarterly",
    ],
)
async def test_threat_intel_sync_requires_admin_role(path: str):
    async def override_user():
        return _user("analyst")

    app.dependency_overrides[get_current_user] = override_user
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(path)
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Admin role required to access threat intelligence operations."
    )


@pytest.mark.asyncio
async def test_threat_intel_status_requires_admin_role():
    async def override_user():
        return _user("analyst")

    app.dependency_overrides[get_current_user] = override_user
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get("/api/threat-intel/status")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_threat_intel_daily_sync_admin_enqueues_background_job():
    async def override_user():
        return _user("admin")

    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.threat_intel._run_sync_daily", new_callable=AsyncMock
        ) as run_sync:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post("/api/threat-intel/sync/daily")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["status"] == "started"
    run_sync.assert_awaited_once()


@pytest.mark.asyncio
async def test_threat_intel_status_sanitizes_admin_error_details():
    async def override_user():
        return _user("admin")

    app.dependency_overrides[get_current_user] = override_user
    statuses = [
        {
            "source": "MITRE ATT&CK",
            "status": "error",
            "error": "secret stack trace",
            "record_count": 0,
        }
    ]
    try:
        with patch(
            "app.services.threat_intel.sync.get_sync_status",
            new_callable=AsyncMock,
            return_value=statuses,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get("/api/threat-intel/status")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    source = response.json()["sources"][0]
    assert source["has_error"] is True
    assert "error" not in source
