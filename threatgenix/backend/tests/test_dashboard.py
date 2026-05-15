"""Tests for the F-16 Dashboard portfolio summary feature."""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.threat_model import PortfolioSummary, PortfolioTrendResponse, ThreatModelListItem
from app.services.auth import get_current_user

BASE_URL = "http://test"
DASHBOARD_URL = "/api/dashboard/summary"
TRENDS_URL = "/api/dashboard/trends"

_fake_user = SimpleNamespace(
    id=uuid.uuid4(),
    email="test@eq.bank",
    is_active=True,
    organization_id=uuid.uuid4(),
)


async def override_get_db():
    """Fake DB dependency that yields a mock session."""
    yield AsyncMock()


async def override_get_current_user():
    return _fake_user


@pytest.fixture(autouse=True)
def dashboard_dependency_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_list_item(
    system_name: str = "System",
    classification: str = "Internal",
    threat_count: int = 0,
    updated_at: datetime | None = None,
) -> ThreatModelListItem:
    return ThreatModelListItem(
        id=uuid.uuid4(),
        system_name=system_name,
        data_classification=classification,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=updated_at or datetime(2026, 1, 2, tzinfo=timezone.utc),
        threat_count=threat_count,
    )


def _portfolio_summary(**overrides) -> PortfolioSummary:
    base = {
        "total_models": 0,
        "total_threats": 0,
        "threats_by_severity": {},
        "threats_by_status": {},
        "threats_by_stride": {},
        "residual_risk_by_level": {},
        "models_by_classification": {},
        "controls_by_status": {},
        "open_reviews": 0,
        "models_pending_review": 0,
        "models_with_drift": 0,
        "shared_models": 0,
        "open_assignments": 0,
        "overdue_assignments": 0,
        "unread_notifications": 0,
        "recent_models": [],
    }
    base.update(overrides)
    return PortfolioSummary(**base)


def _empty_summary() -> PortfolioSummary:
    return _portfolio_summary()


def _populated_summary() -> PortfolioSummary:
    """Summary representing a portfolio with 3 models and 10 threats."""
    return _portfolio_summary(
        total_models=3,
        total_threats=10,
        threats_by_severity={"Critical": 2, "High": 3, "Medium": 4, "Low": 1},
        threats_by_status={"Open": 7, "Accepted": 2, "Dismissed": 1},
        threats_by_stride={
            "Spoofing": 2,
            "Tampering": 3,
            "Information Disclosure": 2,
            "Denial of Service": 1,
            "Elevation of Privilege": 2,
        },
        residual_risk_by_level={"High": 4, "Medium": 3, "Low": 2, "Negligible": 1},
        models_by_classification={"Internal": 1, "Confidential": 1, "Restricted": 1},
        controls_by_status={"implemented": 4, "planned": 2},
        open_reviews=2,
        models_pending_review=1,
        models_with_drift=1,
        shared_models=2,
        open_assignments=3,
        overdue_assignments=1,
        unread_notifications=4,
        recent_models=[
            _make_list_item("Payment Gateway", "Restricted", 5, datetime(2026, 3, 3, tzinfo=timezone.utc)),
            _make_list_item("Core Banking API", "Confidential", 3, datetime(2026, 2, 2, tzinfo=timezone.utc)),
            _make_list_item("Public Portal", "Internal", 2, datetime(2026, 1, 1, tzinfo=timezone.utc)),
        ],
    )


# ---------------------------------------------------------------------------
# 1. Empty database returns zeros
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_summary_empty_database():
    """GET /api/dashboard/summary with no data returns all zeros and empty lists."""
    summary = _empty_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    assert response.status_code == 200
    body = response.json()
    assert body["total_models"] == 0
    assert body["total_threats"] == 0
    assert body["threats_by_severity"] == {}
    assert body["threats_by_status"] == {}
    assert body["threats_by_stride"] == {}
    assert body["models_by_classification"] == {}
    assert body["recent_models"] == []


@pytest.mark.asyncio
async def test_dashboard_summary_uses_organization_scope():
    """Dashboard aggregates by SaaS tenant, not only by the signed-in owner."""
    summary = _empty_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary) as mock_summary:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)

    assert response.status_code == 200
    db_arg = mock_summary.call_args.args[0]
    mock_summary.assert_awaited_once_with(
        db_arg,
        owner_id=_fake_user.id,
        organization_id=_fake_user.organization_id,
    )


# ---------------------------------------------------------------------------
# 2. Populated database returns correct aggregates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_summary_with_models_and_threats():
    """GET /api/dashboard/summary returns correct aggregate counts."""
    summary = _populated_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    assert response.status_code == 200
    body = response.json()
    assert body["total_models"] == 3
    assert body["total_threats"] == 10
    assert body["residual_risk_by_level"] == {"High": 4, "Medium": 3, "Low": 2, "Negligible": 1}
    assert body["controls_by_status"] == {"implemented": 4, "planned": 2}
    assert body["open_reviews"] == 2
    assert body["models_pending_review"] == 1
    assert body["models_with_drift"] == 1
    assert body["shared_models"] == 2
    assert body["open_assignments"] == 3
    assert body["overdue_assignments"] == 1
    assert body["unread_notifications"] == 4
    assert len(body["recent_models"]) == 3


# ---------------------------------------------------------------------------
# 3. threats_by_severity counts are correct
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threats_by_severity_counts():
    """Severity breakdown sums to total_threats."""
    summary = _populated_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    body = response.json()
    severity = body["threats_by_severity"]
    assert severity == {"Critical": 2, "High": 3, "Medium": 4, "Low": 1}
    assert sum(severity.values()) == body["total_threats"]


# ---------------------------------------------------------------------------
# 4. threats_by_status counts are correct
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threats_by_status_counts():
    """Status breakdown sums to total_threats."""
    summary = _populated_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    body = response.json()
    status = body["threats_by_status"]
    assert status == {"Open": 7, "Accepted": 2, "Dismissed": 1}
    assert sum(status.values()) == body["total_threats"]


# ---------------------------------------------------------------------------
# 5. threats_by_stride counts are correct
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threats_by_stride_counts():
    """STRIDE breakdown matches expected categories and sums to total_threats."""
    summary = _populated_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    body = response.json()
    stride = body["threats_by_stride"]
    assert stride == {
        "Spoofing": 2,
        "Tampering": 3,
        "Information Disclosure": 2,
        "Denial of Service": 1,
        "Elevation of Privilege": 2,
    }
    assert sum(stride.values()) == body["total_threats"]


# ---------------------------------------------------------------------------
# 6. models_by_classification counts are correct
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_models_by_classification_counts():
    """Classification breakdown sums to total_models."""
    summary = _populated_summary()
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    body = response.json()
    classification = body["models_by_classification"]
    assert classification == {"Internal": 1, "Confidential": 1, "Restricted": 1}
    assert sum(classification.values()) == body["total_models"]


# ---------------------------------------------------------------------------
# 7. recent_models returns max 5, ordered by updated_at DESC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recent_models_max_five_ordered_desc():
    """recent_models contains at most 5 items, ordered by updated_at descending."""
    # Build 7 models; the service should only return 5
    models = [
        _make_list_item(f"System-{i}", "Internal", i, datetime(2026, 1, i + 1, tzinfo=timezone.utc))
        for i in range(7, 0, -1)  # 7..1, already descending
    ]
    # Only the 5 most recent should be returned by the service
    summary = _portfolio_summary(
        total_models=7,
        models_by_classification={"Internal": 7},
        recent_models=models[:5],  # top 5 by updated_at desc
    )
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    body = response.json()
    recent = body["recent_models"]
    assert len(recent) <= 5
    assert len(recent) == 5
    # Verify descending order by updated_at
    updated_times = [m["updated_at"] for m in recent]
    assert updated_times == sorted(updated_times, reverse=True)


@pytest.mark.asyncio
async def test_recent_models_fewer_than_five():
    """When fewer than 5 models exist, all are returned."""
    models = [
        _make_list_item("Only System", "Public", 1, datetime(2026, 2, 1, tzinfo=timezone.utc)),
    ]
    summary = _portfolio_summary(
        total_models=1,
        total_threats=1,
        threats_by_severity={"Low": 1},
        threats_by_status={"Open": 1},
        threats_by_stride={"Spoofing": 1},
        residual_risk_by_level={"Low": 1},
        models_by_classification={"Public": 1},
        controls_by_status={"planned": 1},
        recent_models=models,
    )
    with patch("app.api.dashboard.get_portfolio_summary", new_callable=AsyncMock, return_value=summary):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(DASHBOARD_URL)
    body = response.json()
    assert len(body["recent_models"]) == 1
    assert body["recent_models"][0]["system_name"] == "Only System"


# ---------------------------------------------------------------------------
# Schema validation tests (unit-level, no HTTP)
# ---------------------------------------------------------------------------


class TestPortfolioSummarySchema:
    """Verify PortfolioSummary Pydantic schema behaviour."""

    def test_empty_summary_serializes(self):
        summary = _empty_summary()
        data = summary.model_dump()
        assert data["total_models"] == 0
        assert data["total_threats"] == 0
        assert data["controls_by_status"] == {}
        assert data["open_reviews"] == 0
        assert data["recent_models"] == []

    def test_populated_summary_serializes(self):
        summary = _populated_summary()
        data = summary.model_dump()
        assert data["total_models"] == 3
        assert sum(data["threats_by_severity"].values()) == 10
        assert data["models_pending_review"] == 1
        assert data["shared_models"] == 2

    def test_recent_models_contain_expected_fields(self):
        summary = _populated_summary()
        data = summary.model_dump()
        for model in data["recent_models"]:
            assert "id" in model
            assert "system_name" in model
            assert "data_classification" in model
            assert "created_at" in model
            assert "updated_at" in model
            assert "threat_count" in model


@pytest.mark.asyncio
async def test_portfolio_trends_returns_activity_points():
    trend = PortfolioTrendResponse(
        points=[
            {
                "date": "2026-04-14",
                "snapshot_count": 1,
                "threat_count": 10,
                "high_risk_threat_count": 4,
                "review_events": 1,
                "control_events": 2,
            },
            {
                "date": "2026-04-15",
                "snapshot_count": 2,
                "threat_count": 12,
                "high_risk_threat_count": 5,
                "review_events": 2,
                "control_events": 1,
            },
        ],
        latest_summary="Latest activity on 2026-04-15: 2 saved version(s).",
    )
    with patch("app.api.dashboard.get_portfolio_trends", new_callable=AsyncMock, return_value=trend):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(TRENDS_URL)
    assert response.status_code == 200
    body = response.json()
    assert len(body["points"]) == 2
    assert body["points"][1]["snapshot_count"] == 2
