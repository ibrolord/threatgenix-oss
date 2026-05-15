"""Tests for authenticated, user-scoped LLM provider endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import llm as llm_api
from app.database import get_db
from app.main import app
from app.services.auth import get_current_user

BASE_URL = "http://test"
API_PREFIX = "/api/llm"
FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


async def override_get_current_user():
    return FakeUser()


async def override_get_db():
    yield AsyncMock()


@pytest.fixture(autouse=True)
def reset_overrides():
    saved_overrides = dict(app.dependency_overrides)
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved_overrides)


@pytest.mark.asyncio
async def test_list_providers_requires_authentication():
    saved_overrides = dict(app.dependency_overrides)
    app.dependency_overrides.clear()
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/providers")
    finally:
        app.dependency_overrides.update(saved_overrides)

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_switch_provider_uses_byok_aware_user_scoped_preference():
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_db] = override_get_db

    with (
        patch(
            "app.api.llm.get_llm_client_for_user_byok",
            new_callable=AsyncMock,
            return_value=type("Client", (), {"provider_name": "openai", "model_name": "gpt-4o"})(),
        ) as mock_get_client,
        patch("app.api.llm.set_provider_preference_for_user") as mock_set_preference,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{API_PREFIX}/provider",
                json={"provider": "openai", "model": "gpt-4o"},
            )

    assert response.status_code == 200
    assert response.json() == {"provider": "openai", "model": "gpt-4o"}
    mock_get_client.assert_awaited_once()
    assert mock_get_client.await_args.args[:2] == (FAKE_USER_ID, "openai")
    assert mock_get_client.await_args.kwargs == {"model": "gpt-4o"}
    mock_set_preference.assert_called_once_with(FAKE_USER_ID, "openai", "gpt-4o")


@pytest.mark.asyncio
async def test_switch_provider_records_resolved_byok_model_override():
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_db] = override_get_db

    with (
        patch(
            "app.api.llm.get_llm_client_for_user_byok",
            new_callable=AsyncMock,
            return_value=type("Client", (), {"provider_name": "openai", "model_name": "gpt-4o-byok"})(),
        ) as mock_get_client,
        patch("app.api.llm.set_provider_preference_for_user") as mock_set_preference,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{API_PREFIX}/provider",
                json={"provider": "openai", "model": "gpt-4o-requested"},
            )

    assert response.status_code == 200
    assert response.json() == {"provider": "openai", "model": "gpt-4o-byok"}
    assert mock_get_client.await_args.kwargs == {"model": "gpt-4o-requested"}
    mock_set_preference.assert_called_once_with(FAKE_USER_ID, "openai", "gpt-4o-byok")


@pytest.mark.asyncio
async def test_list_providers_includes_user_byok_provider():
    app.dependency_overrides[get_current_user] = override_get_current_user

    class Result:
        @staticmethod
        def scalars():
            class Scalars:
                @staticmethod
                def all():
                    return ["anthropic"]

            return Scalars()

    class FakeDB:
        async def execute(self, _stmt):
            return Result()

    async def override_byok_db():
        yield FakeDB()

    app.dependency_overrides[get_db] = override_byok_db

    with patch("app.api.llm.get_available_providers", return_value=[{"name": "bedrock"}]):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/providers")

    assert response.status_code == 200
    available = response.json()["available"]
    assert {
        "name": "anthropic",
        "display_name": "Anthropic",
        "default_model": "claude-sonnet-4-20250514",
        "source": "byok",
    } in available


@pytest.mark.asyncio
async def test_provider_health_reports_canadian_bedrock_runtime(monkeypatch):
    app.dependency_overrides[get_current_user] = override_get_current_user
    monkeypatch.setattr(llm_api.settings, "llm_provider", "bedrock")
    monkeypatch.setattr(llm_api.settings, "allow_external_ai_providers_in_production", False)
    monkeypatch.setattr(llm_api.settings, "bedrock_region", "ca-central-1")
    monkeypatch.setattr(llm_api.settings, "bedrock_model_id", "ca.amazon.nova-lite-v1:0")
    monkeypatch.setattr(
        llm_api.settings,
        "bedrock_enhancement_model_id",
        "ca.anthropic.claude-sonnet-4-20250514-v1:0",
    )

    with (
        patch("app.api.llm.get_available_providers", return_value=[{"name": "bedrock"}]),
        patch(
            "app.api.llm.get_active_provider_info_for_user",
            return_value={"provider": "bedrock", "model": "ca.amazon.nova-lite-v1:0"},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["canada_residency_enforced"] is True
    assert body["external_ai_providers_enabled"] is False
    assert body["data_residency_mode"] == "canada_only"
    assert body["warnings"] == []


@pytest.mark.asyncio
async def test_list_provider_models_returns_model_catalog(monkeypatch):
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_db] = override_get_db

    with (
        patch(
            "app.api.llm.get_available_providers",
            return_value=[{"name": "openai", "display_name": "OpenAI", "default_model": "gpt-5.5"}],
        ),
        patch(
            "app.api.llm._provider_model_ids",
            new_callable=AsyncMock,
            return_value=(["gpt-5.5", "gpt-5.4"], "live"),
        ) as mock_model_ids,
        patch("app.api.llm._stored_user_provider_key", new_callable=AsyncMock, return_value=None),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/providers/openai/models")

    assert response.status_code == 200
    assert response.json() == {
        "provider": "openai",
        "models": ["gpt-5.5", "gpt-5.4"],
        "source": "live",
    }
    mock_model_ids.assert_awaited_once()


def test_openai_model_filter_excludes_non_generation_models():
    assert llm_api._is_openai_generation_model("gpt-5.5")
    assert llm_api._is_openai_generation_model("o3")
    assert not llm_api._is_openai_generation_model("gpt-image-2")
    assert not llm_api._is_openai_generation_model("text-embedding-3-large")


@pytest.mark.asyncio
async def test_provider_health_degrades_on_non_canadian_bedrock_config(monkeypatch):
    app.dependency_overrides[get_current_user] = override_get_current_user
    monkeypatch.setattr(llm_api.settings, "llm_provider", "bedrock")
    monkeypatch.setattr(llm_api.settings, "allow_external_ai_providers_in_production", False)
    monkeypatch.setattr(llm_api.settings, "bedrock_region", "us-east-1")
    monkeypatch.setattr(llm_api.settings, "bedrock_model_id", "anthropic.claude-sonnet-4-v1:0")
    monkeypatch.setattr(
        llm_api.settings,
        "bedrock_enhancement_model_id",
        "anthropic.claude-sonnet-4-v1:0",
    )

    with (
        patch("app.api.llm.get_available_providers", return_value=[{"name": "bedrock"}]),
        patch(
            "app.api.llm.get_active_provider_info_for_user",
            return_value={"provider": "bedrock", "model": "unavailable"},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["canada_residency_enforced"] is False
    assert any("ca-central-1" in warning for warning in body["warnings"])
    assert any("generation smoke test" in action for action in body["next_actions"])


@pytest.mark.asyncio
async def test_provider_health_degrades_on_non_canadian_active_bedrock_model(monkeypatch):
    app.dependency_overrides[get_current_user] = override_get_current_user
    monkeypatch.setattr(llm_api.settings, "llm_provider", "bedrock")
    monkeypatch.setattr(llm_api.settings, "allow_external_ai_providers_in_production", False)
    monkeypatch.setattr(llm_api.settings, "bedrock_region", "ca-central-1")
    monkeypatch.setattr(llm_api.settings, "bedrock_model_id", "ca.amazon.nova-lite-v1:0")
    monkeypatch.setattr(
        llm_api.settings,
        "bedrock_enhancement_model_id",
        "ca.anthropic.claude-sonnet-4-20250514-v1:0",
    )

    with (
        patch("app.api.llm.get_available_providers", return_value=[{"name": "bedrock"}]),
        patch(
            "app.api.llm.get_active_provider_info_for_user",
            return_value={
                "provider": "bedrock",
                "model": "us.anthropic.claude-opus-4-5-20251101-v1:0",
            },
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["canada_residency_enforced"] is False
    assert any("active Bedrock model" in warning for warning in body["warnings"])
    assert any("external AI opt-in" in action for action in body["next_actions"])


@pytest.mark.asyncio
async def test_provider_health_reports_external_ai_opt_in(monkeypatch):
    app.dependency_overrides[get_current_user] = override_get_current_user
    monkeypatch.setattr(llm_api.settings, "llm_provider", "anthropic")
    monkeypatch.setattr(llm_api.settings, "allow_external_ai_providers_in_production", True)
    monkeypatch.setattr(llm_api.settings, "bedrock_region", "ca-central-1")
    monkeypatch.setattr(llm_api.settings, "bedrock_model_id", "ca.amazon.nova-lite-v1:0")
    monkeypatch.setattr(
        llm_api.settings,
        "bedrock_enhancement_model_id",
        "ca.anthropic.claude-sonnet-4-20250514-v1:0",
    )

    with (
        patch("app.api.llm.get_available_providers", return_value=[{"name": "anthropic"}]),
        patch(
            "app.api.llm.get_active_provider_info_for_user",
            return_value={"provider": "anthropic", "model": "claude-opus-4-1"},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["canada_residency_enforced"] is False
    assert body["external_ai_providers_enabled"] is True
    assert body["data_residency_mode"] == "external_opt_in"
    assert any("External AI providers" in warning for warning in body["warnings"])
