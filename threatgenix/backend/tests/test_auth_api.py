from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user

BASE_URL = "http://test"


class FakeUser:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.email = "test@example.com"
        self.full_name = "Test User"
        self.role = "admin"
        self.is_active = True
        self.organization_id = None
        self.organization = None
        self.report_template_library = None


@pytest.fixture()
def auth_test_context():
    fake_user = FakeUser()
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_get_current_user():
        return fake_user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    try:
        yield fake_user, db
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_me_returns_normalized_report_template_library(auth_test_context):
    fake_user, _db = auth_test_context
    fake_user.report_template_library = [
        {
            "id": "banking-review",
            "name": "Banking Review",
            "description": "Shared review pack",
            "audience": "financial_services",
            "cover_title": "Shared Banking Review",
            "cover_subtitle": "Library template",
            "sections": [
                {
                    "id": "scope",
                    "kind": "built_in",
                    "source_section_id": "scope",
                    "title": "Scope",
                }
            ],
        }
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.get("/api/auth/me")

    assert response.status_code == 200
    body = response.json()
    assert body["report_template_library"][0]["id"] == "banking-review"
    assert body["report_template_library"][0]["built_in"] is False


@pytest.mark.asyncio
async def test_synthetic_smoke_account_delete_rejects_regular_user(auth_test_context):
    _fake_user, db = auth_test_context

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.delete("/api/auth/synthetic-smoke-account")

    assert response.status_code == 403
    db.delete.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_synthetic_smoke_account_delete_removes_smoke_user(auth_test_context):
    fake_user, db = auth_test_context
    fake_user.email = "codex-prod-smoke-123@example.com"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.delete("/api/auth/synthetic-smoke-account")

    assert response.status_code == 204
    db.execute.assert_awaited()
    db.delete.assert_awaited_once_with(fake_user)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_report_template_library_persists_custom_templates(auth_test_context):
    fake_user, db = auth_test_context

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.put(
            "/api/auth/report-template-library",
            json={
                "report_template_library": [
                    {
                        "id": "shared-review-pack",
                        "name": "Shared Review Pack",
                        "description": "Reusable template",
                        "audience": "governance",
                        "cover_title": "Shared Review Pack",
                        "cover_subtitle": "Library",
                        "built_in": False,
                        "sections": [
                            {
                                "id": "executive_summary",
                                "kind": "built_in",
                                "source_section_id": "executive_summary",
                                "title": "Executive Summary",
                            },
                            {
                                "id": "custom-approval",
                                "kind": "custom_text",
                                "title": "Approval Notes",
                                "body": "Capture organization-specific sign-off notes.",
                            },
                        ],
                    }
                ]
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["report_template_library"][0]["id"] == "shared-review-pack"
    assert fake_user.report_template_library == [
        {
            "id": "shared-review-pack",
            "name": "Shared Review Pack",
            "description": "Reusable template",
            "audience": "governance",
            "cover_title": "Shared Review Pack",
            "cover_subtitle": "Library",
            "sections": [
                {
                    "id": "executive_summary",
                    "kind": "built_in",
                    "source_section_id": "executive_summary",
                    "title": "Executive Summary",
                    "intro_text": None,
                    "body": None,
                },
                {
                    "id": "custom-approval",
                    "kind": "custom_text",
                    "source_section_id": None,
                    "title": "Approval Notes",
                    "intro_text": None,
                    "body": "Capture organization-specific sign-off notes.",
                },
            ],
        }
    ]
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(fake_user)


@pytest.mark.asyncio
async def test_me_prefers_organization_report_template_library(auth_test_context):
    fake_user, _db = auth_test_context
    fake_user.organization_id = uuid.uuid4()
    fake_user.organization = type(
        "FakeOrganization",
        (),
        {
            "name": "Northstar Bank",
            "report_template_library": [
                {
                    "id": "org-bank-pack",
                    "name": "Org Banking Pack",
                    "description": "Organization templates",
                    "audience": "financial_services",
                    "cover_title": "Organization Banking Pack",
                    "cover_subtitle": "Org Library",
                    "sections": [
                        {
                            "id": "scope",
                            "kind": "built_in",
                            "source_section_id": "scope",
                            "title": "Scope",
                        }
                    ],
                }
            ],
        },
    )()
    fake_user.report_template_library = [
        {
            "id": "user-pack",
            "name": "User Pack",
            "description": "User templates",
            "audience": "governance",
            "cover_title": "User Pack",
            "cover_subtitle": "User Library",
            "sections": [],
        }
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.get("/api/auth/me")

    assert response.status_code == 200
    body = response.json()
    assert body["organization_name"] == "Northstar Bank"
    assert body["report_template_library"][0]["id"] == "org-bank-pack"
