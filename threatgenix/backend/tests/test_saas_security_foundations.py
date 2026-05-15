from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.auth import _default_organization_name
from app.config import settings
from app.database import get_db
from app.main import app
from app.models.organization import Organization
from app.models.user import User
from app.services.entitlement import check_org_entitlement
from app.services.model_collaboration import get_model_role, require_model_permission


BASE_URL = "http://test"


@pytest.fixture(autouse=True)
def _clean_overrides():
    saved = dict(app.dependency_overrides)
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


def test_default_organization_name_normalizes_full_name_and_email() -> None:
    assert _default_organization_name("  Priya   Sharma ", "PRIYA@EXAMPLE.TEST") == "Priya Sharma's Organization"
    assert _default_organization_name("", "security.review@example.com") == "Security Review Organization"


@pytest.mark.asyncio
async def test_register_creates_org_and_dev_verification_header(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_expose_dev_tokens", True)

    no_existing_user = MagicMock()
    no_existing_user.scalar_one_or_none.return_value = None

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[no_existing_user, MagicMock()])

    added: list[object] = []

    def _add(obj: object) -> None:
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", uuid.uuid4())
        added.append(obj)

    db.add = MagicMock(side_effect=_add)

    async def _refresh(user: User) -> None:
        user.email_verified = False

    db.refresh = _refresh

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/auth/register",
            json={
                "email": "Priya@Example.Test",
                "password": "SecurePass123",
                "full_name": " Priya   Sharma ",
            },
        )

    assert response.status_code == 201, response.text
    assert response.json()["email"] == "priya@example.test"
    assert response.json()["organization_name"] == "Priya Sharma's Organization"
    assert response.headers["X-Dev-Email-Verification-Code"]
    assert any(isinstance(obj, Organization) for obj in added)
    assert any(isinstance(obj, User) and obj.organization is not None for obj in added)


def test_dev_token_exposure_requires_explicit_non_production_flag(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_expose_dev_tokens", False)
    monkeypatch.setattr(settings, "app_env", "development")
    assert settings.auth_expose_dev_tokens_enabled is False

    monkeypatch.setattr(settings, "auth_expose_dev_tokens", True)
    assert settings.auth_expose_dev_tokens_enabled is True

    monkeypatch.setattr(settings, "app_env", "production")
    assert settings.auth_expose_dev_tokens_enabled is False


@pytest.mark.asyncio
async def test_password_reset_response_does_not_enumerate_accounts_by_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_expose_dev_tokens", False)
    monkeypatch.setattr(settings, "app_env", "development")

    existing_user = User(
        id=uuid.uuid4(),
        email="analyst@example.test",
        hashed_password="hashed",
        full_name="Analyst",
        is_active=True,
    )
    user_result = MagicMock()
    user_result.scalar_one_or_none.return_value = existing_user

    existing_db = AsyncMock()
    existing_db.execute = AsyncMock(side_effect=[user_result, MagicMock()])
    existing_db.add = MagicMock()

    async def override_existing_db():
        yield existing_db

    app.dependency_overrides[get_db] = override_existing_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        existing_response = await client.post(
            "/api/auth/request-password-reset",
            json={"email": "analyst@example.test"},
        )

    app.dependency_overrides.pop(get_db, None)

    missing_result = MagicMock()
    missing_result.scalar_one_or_none.return_value = None
    missing_db = AsyncMock()
    missing_db.execute = AsyncMock(return_value=missing_result)
    missing_db.add = MagicMock()

    async def override_missing_db():
        yield missing_db

    app.dependency_overrides[get_db] = override_missing_db
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        missing_response = await client.post(
            "/api/auth/request-password-reset",
            json={"email": "missing@example.test"},
        )

    assert existing_response.status_code == 200
    assert missing_response.status_code == 200
    assert existing_response.json() == missing_response.json()
    assert "reset_token" not in existing_response.json()
    existing_db.add.assert_called_once()
    existing_db.commit.assert_awaited_once()
    missing_db.add.assert_not_called()
    missing_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_entitlement_denies_inactive_org_and_unknown_feature() -> None:
    user = MagicMock(spec=User)
    user.organization = Organization(name="Northstar Bank", subscription_tier="enterprise", is_active=False)
    user.organization_id = user.organization.id

    assert await check_org_entitlement(user, AsyncMock(), "pdf_export") is False

    user.organization.is_active = True
    assert await check_org_entitlement(user, AsyncMock(), "unregistered_feature") is False


@pytest.mark.asyncio
async def test_entitlement_requires_org_outside_development(monkeypatch) -> None:
    monkeypatch.setattr(settings, "app_env", "production")
    user = MagicMock(spec=User)
    user.organization = None
    user.organization_id = None

    assert await check_org_entitlement(user, AsyncMock(), "pdf_export") is False


def test_collaborator_role_cannot_cross_tenant_boundary() -> None:
    owner_org_id = uuid.uuid4()
    caller_org_id = uuid.uuid4()

    threat_model = MagicMock()
    threat_model.owner_id = uuid.uuid4()
    threat_model.organization_id = None
    threat_model.owner = MagicMock(organization_id=owner_org_id)
    threat_model.collaborators = [
        {
            "id": str(uuid.uuid4()),
            "email": "reviewer@example.com",
            "role": "reviewer",
            "status": "active",
            "invited_by": "owner@example.com",
            "invited_at": "2026-04-27T00:00:00Z",
            "updated_at": "2026-04-27T00:00:00Z",
        }
    ]

    caller = MagicMock(spec=User)
    caller.id = uuid.uuid4()
    caller.email = "reviewer@example.com"
    caller.organization_id = caller_org_id

    assert get_model_role(threat_model, caller) is None

    caller.organization_id = owner_org_id
    assert get_model_role(threat_model, caller) == "reviewer"


def test_org_admin_has_workspace_access_without_per_model_collaborator() -> None:
    org_id = uuid.uuid4()

    threat_model = MagicMock()
    threat_model.id = uuid.uuid4()
    threat_model.owner_id = uuid.uuid4()
    threat_model.organization_id = org_id
    threat_model.owner = MagicMock(organization_id=org_id)
    threat_model.collaborators = []

    caller = MagicMock(spec=User)
    caller.id = uuid.uuid4()
    caller.email = "admin@example.com"
    caller.organization_id = org_id
    caller.role = "admin"

    assert get_model_role(threat_model, caller) == "owner"
    assert require_model_permission(threat_model, caller, "admin") is threat_model

    caller.role = "security_engineer"
    assert get_model_role(threat_model, caller) == "editor"
    assert require_model_permission(threat_model, caller, "write") is threat_model


def test_org_model_access_denies_other_tenants_even_with_matching_collaborator_email() -> None:
    threat_model = MagicMock()
    threat_model.owner_id = uuid.uuid4()
    threat_model.organization_id = uuid.uuid4()
    threat_model.owner = MagicMock(organization_id=threat_model.organization_id)
    threat_model.collaborators = [
        {
            "id": str(uuid.uuid4()),
            "email": "analyst@example.com",
            "role": "editor",
            "status": "active",
            "invited_by": "owner@example.com",
            "invited_at": "2026-04-27T00:00:00Z",
            "updated_at": "2026-04-27T00:00:00Z",
        }
    ]

    caller = MagicMock(spec=User)
    caller.id = uuid.uuid4()
    caller.email = "analyst@example.com"
    caller.organization_id = uuid.uuid4()
    caller.role = "admin"

    assert get_model_role(threat_model, caller) is None
