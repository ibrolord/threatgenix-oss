import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user
from app.services.dfd_component_templates import suggest_component_template

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
    def __init__(self, *, threat_model_id: uuid.UUID | None = None, templates: list[dict] | None = None):
        self.id = threat_model_id or uuid.uuid4()
        self.system_name = "Payments Platform"
        self.description = "Event-driven payment processing system."
        self.data_classification = "Restricted"
        self.owner_id = FAKE_USER_ID
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.dfd_views = None
        self.dfd_component_templates = templates


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


def _component_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/dfd/component-templates"


@pytest.mark.asyncio
async def test_list_component_templates_returns_builtins_and_custom_templates():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(
      threat_model_id=threat_model_id,
      templates=[
          {
              "id": str(uuid.uuid4()),
              "label": "Kafka Broker",
              "description": "Reusable event broker stencil.",
              "semantic_node_type": "data_store",
              "shape": "queue",
              "group": "Custom",
              "default_name": "Kafka Broker",
              "default_properties": {"store_type": "queue"},
              "built_in": False,
              "ai_generated": True,
          }
      ],
    )

    with patch("app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_component_url(threat_model_id))

    assert response.status_code == 200
    payload = response.json()
    labels = {item["label"] for item in payload}
    assert "Process" in labels
    assert "Kafka Broker" in labels


@pytest.mark.asyncio
async def test_component_template_create_and_delete_round_trip():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(threat_model_id=threat_model_id, templates=None)
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            create_response = await client.post(
                _component_url(threat_model_id),
                json={
                    "label": "Payment Queue",
                    "description": "Internal async payment queue.",
                    "semantic_node_type": "data_store",
                    "shape": "queue",
                    "group": "Custom",
                    "default_name": "Payment Queue",
                    "default_properties": {"store_type": "queue"},
                },
            )

            assert create_response.status_code == 201
            created = create_response.json()
            assert created["label"] == "Payment Queue"
            assert fake_tm.dfd_component_templates is not None
            assert len(fake_tm.dfd_component_templates) == 1

            delete_response = await client.delete(
                f"{_component_url(threat_model_id)}/{created['id']}"
            )

    app.dependency_overrides[get_db] = override_get_db

    assert delete_response.status_code == 204
    assert fake_tm.dfd_component_templates is None


def test_suggest_component_template_falls_back_to_queue_heuristic():
    with patch(
        "app.services.dfd_component_templates.get_llm_client_for_user",
        side_effect=RuntimeError("no llm"),
    ):
        response = suggest_component_template(
            user_id=FAKE_USER_ID,
            prompt="Suggest a Kafka broker for internal payment events",
            threat_model_name="Payments Platform",
            threat_model_description="Processes internal payment events.",
            raw_templates=None,
        )

    assert response.degraded_reason is not None
    assert response.template.semantic_node_type == "data_store"
    assert response.template.shape == "queue"
    assert response.template.default_properties.store_type == "queue"
