import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user
from app.services.dfd_property_options import suggest_property_option

BASE_URL = "http://test"
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


class FakeThreatModel:
    def __init__(self, *, threat_model_id: uuid.UUID | None = None, options: list[dict] | None = None):
        self.id = threat_model_id or uuid.uuid4()
        self.system_name = "Payments Platform"
        self.description = "Event-driven payment processing system."
        self.data_classification = "Restricted"
        self.owner_id = FAKE_USER_ID
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.dfd_views = None
        self.dfd_property_options = options


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


def _option_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/dfd/property-options"


@pytest.mark.asyncio
async def test_list_property_options_returns_custom_aliases():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(
        threat_model_id=threat_model_id,
        options=[
            {
                "id": str(uuid.uuid4()),
                "field": "authentication_type",
                "label": "OIDC / Cognito",
                "canonical_value": "oauth2",
                "description": "Team-specific auth label.",
                "ai_generated": True,
            }
        ],
    )

    with patch("app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_option_url(threat_model_id))

    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["field"] == "authentication_type"
    assert payload[0]["label"] == "OIDC / Cognito"
    assert payload[0]["canonical_value"] == "oauth2"


@pytest.mark.asyncio
async def test_property_option_create_and_delete_round_trip():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(threat_model_id=threat_model_id, options=None)
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            create_response = await client.post(
                _option_url(threat_model_id),
                json={
                    "field": "authentication_type",
                    "label": "OIDC / Cognito",
                    "canonical_value": "oauth2",
                    "description": "Maps team wording to OAuth 2.",
                },
            )

            assert create_response.status_code == 201
            created = create_response.json()
            assert created["field"] == "authentication_type"
            assert created["canonical_value"] == "oauth2"
            assert fake_tm.dfd_property_options is not None
            assert len(fake_tm.dfd_property_options) == 1

            delete_response = await client.delete(f"{_option_url(threat_model_id)}/{created['id']}")

    app.dependency_overrides[get_db] = override_get_db

    assert delete_response.status_code == 204
    assert fake_tm.dfd_property_options is None


@pytest.mark.asyncio
async def test_property_option_create_accepts_custom_stored_values():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(threat_model_id=threat_model_id, options=None)
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            create_response = await client.post(
                _option_url(threat_model_id),
                json={
                    "field": "authentication_type",
                    "label": "Passkey / FIDO2",
                    "canonical_value": "fido2",
                    "description": "Custom entry outside the built-in auth list.",
                },
            )

    app.dependency_overrides[get_db] = override_get_db

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["field"] == "authentication_type"
    assert created["label"] == "Passkey / FIDO2"
    assert created["canonical_value"] == "fido2"
    assert fake_tm.dfd_property_options is not None
    assert fake_tm.dfd_property_options[0]["canonical_value"] == "fido2"


def test_suggest_property_option_falls_back_to_auth_heuristic():
    with patch(
        "app.services.dfd_property_options.get_llm_client_for_user",
        side_effect=RuntimeError("no llm"),
    ):
        response = suggest_property_option(
            user_id=FAKE_USER_ID,
            field="authentication_type",
            prompt="Suggest an alias for OIDC via Cognito",
            threat_model_name="Payments Platform",
            threat_model_description="Processes internal payment events.",
            raw_options=None,
        )

    assert response.degraded_reason is not None
    assert response.option.field == "authentication_type"
    assert response.option.canonical_value == "oauth2"
