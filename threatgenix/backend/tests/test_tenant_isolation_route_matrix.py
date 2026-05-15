from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import dfd, evidence, threat_models, threats
from app.database import get_db
from app.main import app
from app.services.auth import get_current_user


BASE_URL = "http://test"


@dataclass(frozen=True)
class RouteCase:
    label: str
    method: str
    path_factory: Callable[[uuid.UUID, uuid.UUID], str]


class _ScalarResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _ForeignModelSession:
    def __init__(self, threat_model: object) -> None:
        self.threat_model = threat_model

    async def execute(self, *_args: object, **_kwargs: object) -> _ScalarResult:
        return _ScalarResult(self.threat_model)


OWNED_RESOURCE_ROUTES = (
    RouteCase(
        "threat model detail",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}",
    ),
    RouteCase(
        "threat model as code export",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/tmac",
    ),
    RouteCase(
        "DFD graph",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/dfd",
    ),
    RouteCase(
        "DFD quality gates",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/dfd/quality-gates",
    ),
    RouteCase(
        "threat list",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/threats",
    ),
    RouteCase(
        "threat summary",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/threats/summary",
    ),
    RouteCase(
        "scan detail",
        "GET",
        lambda threat_model_id, scan_id: f"/api/threat-models/{threat_model_id}/scans/{scan_id}",
    ),
    RouteCase(
        "evidence status",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/evidence/status",
    ),
    RouteCase(
        "validation lab summary",
        "GET",
        lambda threat_model_id, _scan_id: f"/api/threat-models/{threat_model_id}/validation-lab",
    ),
)


@pytest.fixture(autouse=True)
def _clean_overrides():
    saved = dict(app.dependency_overrides)
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route_case",
    OWNED_RESOURCE_ROUTES,
    ids=[case.label for case in OWNED_RESOURCE_ROUTES],
)
async def test_owned_resource_routes_reject_cross_tenant_access(
    monkeypatch: pytest.MonkeyPatch,
    route_case: RouteCase,
) -> None:
    caller = SimpleNamespace(
        id=uuid.uuid4(),
        email="caller@example.test",
        organization_id=None,
        role="admin",
    )
    foreign_threat_model = SimpleNamespace(
        id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        organization_id=None,
        owner=SimpleNamespace(organization_id=None),
        collaborators=[],
    )

    async def current_user_override() -> SimpleNamespace:
        return caller

    async def db_override():
        yield _ForeignModelSession(foreign_threat_model)

    async def foreign_get_threat_model(_db: object, _threat_model_id: uuid.UUID) -> object:
        return foreign_threat_model

    for module in (threat_models, dfd, threats, evidence):
        monkeypatch.setattr(module, "get_threat_model", foreign_get_threat_model)

    app.dependency_overrides[get_current_user] = current_user_override
    app.dependency_overrides[get_db] = db_override

    transport = ASGITransport(app=app)
    threat_model_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.request(
            route_case.method,
            route_case.path_factory(threat_model_id, scan_id),
        )

    assert response.status_code == 403, (
        f"{route_case.label} should deny cross-tenant access, "
        f"got {response.status_code}: {response.text}"
    )
    assert response.json()["detail"] == "Access denied"
