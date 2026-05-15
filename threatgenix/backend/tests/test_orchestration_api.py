from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.orchestration import OrchestrationJobResponse
from app.services.auth import get_current_user

BASE_URL = "http://test"


def _job_response(
    *,
    job_id: uuid.UUID,
    threat_model_id: uuid.UUID,
    owner_id: uuid.UUID,
) -> OrchestrationJobResponse:
    now = datetime(2026, 4, 29, tzinfo=timezone.utc)
    return OrchestrationJobResponse(
        id=job_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        job_kind="evidence_rebuild",
        status="pending",
        objective="Rebuild evidence graph projection for release readiness.",
        requested_tools=["evidence"],
        inputs={"source": "qa"},
        policy={"max_runtime_seconds": 60},
        result_summary=None,
        error_message=None,
        started_at=None,
        completed_at=None,
        created_at=now,
        updated_at=now,
        tasks=[],
        events=[],
    )


@pytest.mark.asyncio
async def test_create_orchestration_job_requires_write_and_commits():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    job_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    threat_model = SimpleNamespace(id=threat_model_id, owner_id=owner_id, owner=user)
    job = SimpleNamespace(id=job_id)
    response_model = _job_response(
        job_id=job_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
    )
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.orchestration.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.orchestration.create_orchestration_job",
                new_callable=AsyncMock,
                return_value=job,
            ) as create_job,
            patch(
                "app.api.orchestration.get_orchestration_job",
                new_callable=AsyncMock,
                return_value=job,
            ),
            patch(
                "app.api.orchestration.serialize_orchestration_job",
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-models/{threat_model_id}/orchestration/jobs",
                    json={
                        "job_kind": "evidence_rebuild",
                        "objective": "Rebuild evidence graph projection for release readiness.",
                        "requested_tools": ["evidence"],
                        "inputs": {"source": "qa"},
                        "policy": {"max_runtime_seconds": 60},
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["id"] == str(job_id)
    create_job.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_orchestration_job_returns_404_for_missing_job():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    job_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    threat_model = SimpleNamespace(id=threat_model_id, owner_id=owner_id, owner=user)

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.orchestration.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.orchestration.get_orchestration_job",
                new_callable=AsyncMock,
                return_value=None,
            ) as get_job,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/threat-models/{threat_model_id}/orchestration/jobs/{job_id}"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 404
    assert response.json()["detail"] == "Orchestration job not found."
    get_job.assert_awaited_once()
