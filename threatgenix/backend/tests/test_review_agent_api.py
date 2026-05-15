from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.database import get_db
from app.main import app
from app.schemas.application_review import ApplicationReviewResponse
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.schemas.application_review_orchestration import (
    ApplicationReviewOrchestrationResponse,
    ReviewOrchestrationStep,
)
from app.services.agent_access_limits import reset_agent_access_limits
from app.services.auth import get_current_user

BASE_URL = "http://test"


@pytest.fixture(autouse=True)
def _reset_agent_access_limits():
    reset_agent_access_limits()
    yield
    reset_agent_access_limits()


def _review_response(review_id: uuid.UUID, owner_id: uuid.UUID) -> ApplicationReviewResponse:
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return ApplicationReviewResponse(
        id=review_id,
        tenant_key=f"user:{owner_id}",
        owner_id=owner_id,
        organization_id=None,
        threat_model_id=None,
        parent_review_id=None,
        review_lineage_id=review_id,
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="completed",
        decision="verify",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy={},
        result_summary="Needs supporting context.",
        error_message=None,
        created_at=now,
        updated_at=now,
    )


def _context_entry(review_id: uuid.UUID):
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return SimpleNamespace(
        id=uuid.uuid4(),
        review_id=review_id,
        source_type="scan_finding",
        source_object_id=uuid.uuid4(),
        item_type="scanner_finding",
        title="Sensitive export route is missing authorization",
        body="severity=high missing authorization",
        keywords=["severity=high", "authorization"],
        source_refs=[{"type": "path", "path": "apps/api/users.py:42"}],
        content_hash="d" * 64,
        status="active",
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_agent_status_returns_review_and_web_url():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch("app.api.review_agent.get_application_review", new_callable=AsyncMock, return_value=object()),
            patch(
                "app.api.review_agent.serialize_application_review",
                return_value=_review_response(review_id, owner_id),
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(f"/api/agent/reviews/{review_id}/status")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["review"]["id"] == str(review_id)
    assert body["web_url"] == f"{BASE_URL}/reviews/{review_id}"
    assert body["api_status_url"] == f"{BASE_URL}/api/agent/reviews/{review_id}/status"
    assert body["terminal_commands"][0]["label"] == "Check review status"
    assert "$THREATGENIX_TOKEN" in body["terminal_commands"][0]["command"]
    assert body["agent_tools"][0]["name"] == "threatgenix.review.status"
    assert body["access"]["rate_limit"]["tenant_remaining"] >= 0
    assert body["access"]["quotas"]["scan_minutes"]["remaining"] >= 0


@pytest.mark.asyncio
async def test_agent_status_uses_forwarded_public_host_for_links():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch("app.api.review_agent.get_application_review", new_callable=AsyncMock, return_value=object()),
            patch(
                "app.api.review_agent.serialize_application_review",
                return_value=_review_response(review_id, owner_id),
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://threatgenix-api.fly.dev") as client:
                response = await client.get(
                    f"/api/agent/reviews/{review_id}/status",
                    headers={
                        "x-forwarded-host": "threatgenix.vercel.app",
                        "x-forwarded-proto": "https",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    public_base_url = "https://threatgenix.vercel.app"
    assert body["web_url"] == f"{public_base_url}/reviews/{review_id}"
    assert body["api_status_url"] == f"{public_base_url}/api/agent/reviews/{review_id}/status"
    assert f'"{public_base_url}/api/agent/reviews/{review_id}/status"' in body["terminal_commands"][0]["command"]
    assert f'"{public_base_url}/api/agent/reviews/{review_id}/rerun"' in body["terminal_commands"][1]["command"]
    tool_names = {tool["name"] for tool in body["agent_tools"]}
    assert tool_names == {
        "threatgenix.review.status",
        "threatgenix.review.findings",
        "threatgenix.review.rerun",
        "threatgenix.review.open",
        "threatgenix.review.orchestrate",
    }
    assert all("threatgenix-api.fly.dev" not in tool["endpoint"] for tool in body["agent_tools"])


@pytest.mark.asyncio
async def test_agent_orchestration_returns_stable_contract_and_public_url():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()
    service_response = ApplicationReviewOrchestrationResponse(
        status="completed",
        steps=[ReviewOrchestrationStep(name="review", status="pass", detail="created")],
        review=_review_response(review_id, owner_id),
        web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
    )

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.review_agent.orchestrate_application_review",
            new_callable=AsyncMock,
            return_value=service_response,
        ) as orchestrate:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://threatgenix-api.fly.dev") as client:
                response = await client.post(
                    "/api/agent/reviews/orchestrations",
                    headers={
                        "x-forwarded-host": "threatgenix.vercel.app",
                        "x-forwarded-proto": "https",
                    },
                    json={
                        "review": {
                            "app_name": "ExampleApp",
                            "input_kind": "diff",
                            "commit_sha": "abc123",
                            "requested_tools": ["semgrep"],
                            "intake_answers": {
                                "business_purpose": "Exports user data.",
                                "data_classification": "restricted",
                                "sensitive_data_types": ["pii"],
                                "changed_security_surface": ["authz"],
                                "scanner_permissions": ["static_code"],
                                "upload_permission": True,
                                "out_of_scope": ["production data"],
                            },
                        }
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["contract_version"] == "threatgenix.agent.v1"
    assert body["orchestration"]["status"] == "completed"
    assert body["orchestration"]["web_url"] == f"https://threatgenix.vercel.app/reviews/{review_id}"
    assert body["agent_tools"][0]["name"] == "threatgenix.review.status"
    assert "input_schema" in body["agent_tools"][0]
    assert "output_schema" in body["agent_tools"][0]
    assert "rate_limit" in body["agent_tools"][0]
    assert "quota_cost" in body["agent_tools"][0]
    assert body["access"]["quotas"]["ai_tokens"]["used"] == 1000
    assert all("threatgenix-api.fly.dev" not in tool["endpoint"] for tool in body["agent_tools"])
    assert orchestrate.await_args.kwargs["public_web_base_url"] == "https://threatgenix.vercel.app"


@pytest.mark.asyncio
async def test_agent_findings_and_evidence_chain_are_context_scoped():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    finding = _context_entry(review_id)

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.review_agent.search_review_context_index",
            new_callable=AsyncMock,
            return_value=[finding],
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                findings_response = await client.get(f"/api/agent/reviews/{review_id}/findings")
                chain_response = await client.get(
                    f"/api/agent/reviews/{review_id}/findings/{finding.id}/evidence-chain"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert findings_response.status_code == 200
    assert findings_response.json()["findings"][0]["id"] == str(finding.id)
    assert chain_response.status_code == 200
    assert chain_response.json()["source_refs"][0]["path"] == "apps/api/users.py:42"


@pytest.mark.asyncio
async def test_agent_rerun_rebuilds_context_evaluates_decision_and_commits():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()
    decision = ApplicationReviewDecisionResponse(
        review_id=review_id,
        decision="verify",
        reason="Scanner-only evidence needs supporting context.",
        evidence_hashes=["d" * 64],
        scanner_only=True,
    )

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.review_agent.rebuild_review_context_index",
                new_callable=AsyncMock,
                return_value=[object(), object()],
            ),
            patch(
                "app.api.review_agent.evaluate_application_review_decision",
                new_callable=AsyncMock,
                return_value=decision,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(f"/api/agent/reviews/{review_id}/rerun")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["indexed_entry_count"] == 2
    assert response.json()["decision"]["decision"] == "verify"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_agent_rate_limit_returns_retry_after_metadata(monkeypatch):
    monkeypatch.setattr(settings, "agent_token_rate_limit", 1)
    monkeypatch.setattr(settings, "agent_tenant_rate_limit", 100)
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch("app.api.review_agent.get_application_review", new_callable=AsyncMock, return_value=object()) as get_review,
            patch(
                "app.api.review_agent.serialize_application_review",
                return_value=_review_response(review_id, owner_id),
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                first = await client.get(
                    f"/api/agent/reviews/{review_id}/status",
                    headers={"Authorization": "Bearer tenant-token"},
                )
                second = await client.get(
                    f"/api/agent/reviews/{review_id}/status",
                    headers={"Authorization": "Bearer tenant-token"},
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"].isdigit()
    assert second.headers["X-ThreatGenix-Limit-Type"] == "token_rate"
    assert second.json()["detail"]["retry_after_seconds"] >= 1
    get_review.assert_awaited_once()


@pytest.mark.asyncio
async def test_agent_orchestration_quota_blocks_before_service_call(monkeypatch):
    monkeypatch.setattr(settings, "agent_token_rate_limit", 100)
    monkeypatch.setattr(settings, "agent_tenant_rate_limit", 100)
    monkeypatch.setattr(settings, "agent_bundle_storage_quota_bytes", 100)
    owner_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.review_agent.orchestrate_application_review",
            new_callable=AsyncMock,
        ) as orchestrate:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    "/api/agent/reviews/orchestrations",
                    json={
                        "review": {
                            "app_name": "ExampleApp",
                            "input_kind": "diff",
                            "bundle_hash": "bundle-1",
                            "requested_tools": ["semgrep"],
                            "intake_answers": {"business_purpose": "Customer export."},
                        },
                        "bundle": {
                            "bundle_kind": "diff",
                            "source": "cli",
                            "manifest": [
                                {
                                    "path": "apps/api/users.py",
                                    "file_kind": "source",
                                    "sha256": "a" * 64,
                                    "byte_size": 101,
                                    "source": "cli",
                                }
                            ],
                        },
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 429
    assert response.json()["detail"]["metric"] == "bundle_storage_bytes"
    assert response.headers["X-ThreatGenix-Limit-Type"] == "tenant_quota"
    orchestrate.assert_not_awaited()


@pytest.mark.asyncio
async def test_agent_retry_storm_rate_limit_blocks_duplicate_orchestration(monkeypatch):
    monkeypatch.setattr(settings, "agent_token_rate_limit", 1)
    monkeypatch.setattr(settings, "agent_tenant_rate_limit", 100)
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()
    service_response = ApplicationReviewOrchestrationResponse(
        status="completed",
        steps=[ReviewOrchestrationStep(name="review", status="pass", detail="created")],
        review=_review_response(review_id, owner_id),
        web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
    )

    async def override_get_db():
        yield db

    async def override_user():
        return user

    payload = {
        "review": {
            "app_name": "ExampleApp",
            "input_kind": "diff",
            "commit_sha": "abc123",
            "requested_tools": ["semgrep"],
            "intake_answers": {"business_purpose": "Customer export."},
        }
    }
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.review_agent.orchestrate_application_review",
            new_callable=AsyncMock,
            return_value=service_response,
        ) as orchestrate:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                first = await client.post(
                    "/api/agent/reviews/orchestrations",
                    headers={"Authorization": "Bearer tenant-token"},
                    json=payload,
                )
                second = await client.post(
                    "/api/agent/reviews/orchestrations",
                    headers={"Authorization": "Bearer tenant-token"},
                    json=payload,
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["metric"] == "api_calls"
    orchestrate.assert_awaited_once()
