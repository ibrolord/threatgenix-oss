from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.scans import _build_scan_correlation_entries
from app.database import get_db
from app.main import app
from app.schemas.scan import ThreatScanCorrelationResponse
from app.services.auth import get_current_user

BASE_URL = "http://test"
FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


async def override_get_db():
    yield AsyncMock()


async def override_get_current_user():
    return FakeUser()


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


def _entry(
    *,
    threat_id: uuid.UUID | None = None,
    display_id: str,
    scan_status: str,
    templates: list[str] | None = None,
    matched_targets: list[str] | None = None,
    cve_ids: list[str] | None = None,
):
    return ThreatScanCorrelationResponse(
        scan_job_id=uuid.uuid4(),
        scan_completed_at=datetime(2026, 4, 16, 10, 0, tzinfo=timezone.utc),
        threat_id=threat_id or uuid.uuid4(),
        threat_display_id=display_id,
        threat_description=f"{display_id} description",
        severity="High",
        stride_category="Tampering",
        scan_status=scan_status,
        evidence_count=1,
        cve_ids=cve_ids or [],
        matched_targets=matched_targets or [],
        templates=templates or [],
        evidence=[
            {
                "finding_id": str(uuid.uuid4()),
                "template_id": "template-id",
                "template_name": (templates or ["template"])[0],
                "severity": "high",
                "matched_at": (matched_targets or ["https://api.example.com"])[0],
                "cve_ids": cve_ids or [],
                "tool_name": "nuclei",
                "tool_version": None,
                "validation_target": (matched_targets or ["https://api.example.com"])[0],
                "deterministic": True,
            }
        ],
        validation_tools=["nuclei"],
        deterministic_evidence_count=1,
    )


@pytest.mark.asyncio
async def test_get_latest_scan_correlation_returns_summary_counts():
    threat_model_id = uuid.uuid4()
    latest_scan = SimpleNamespace(
        id=uuid.uuid4(),
        completed_at=datetime(2026, 4, 16, 10, 0, tzinfo=timezone.utc),
    )
    entries = [
        _entry(display_id="T-001", scan_status="confirmed", templates=["xss"], matched_targets=["https://one.example"]),
        _entry(display_id="T-002", scan_status="mitigated"),
        _entry(display_id="T-003", scan_status="not_found"),
        _entry(display_id="T-004", scan_status="unverifiable"),
    ]

    with patch("app.api.scans._get_threat_model_for_owner", new_callable=AsyncMock), patch(
        "app.api.scans._get_latest_completed_scan", new_callable=AsyncMock, return_value=latest_scan
    ), patch(
        "app.api.scans._build_scan_correlation_entries", new_callable=AsyncMock, return_value=entries
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                f"/api/threat-models/{threat_model_id}/scans/latest/threat-correlation"
            )

    assert response.status_code == 200
    body = response.json()
    assert body["scan_job_id"] == str(latest_scan.id)
    assert body["total_correlations"] == 4
    assert body["confirmed_count"] == 1
    assert body["mitigated_count"] == 1
    assert body["not_found_count"] == 1
    assert body["unverifiable_count"] == 1
    assert body["entries"][0]["threat_display_id"] == "T-001"


@pytest.mark.asyncio
async def test_get_latest_threat_scan_correlation_returns_matching_entry():
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    latest_scan = SimpleNamespace(
        id=uuid.uuid4(),
        completed_at=datetime(2026, 4, 16, 10, 0, tzinfo=timezone.utc),
    )
    matching = _entry(
        threat_id=threat_id,
        display_id="T-007",
        scan_status="confirmed",
        templates=["sqli"],
        matched_targets=["https://payments.example.com"],
        cve_ids=["CVE-2026-0001"],
    )

    with patch("app.api.scans._get_threat_model_for_owner", new_callable=AsyncMock), patch(
        "app.api.scans._get_latest_completed_scan", new_callable=AsyncMock, return_value=latest_scan
    ), patch(
        "app.api.scans._build_scan_correlation_entries",
        new_callable=AsyncMock,
        return_value=[_entry(display_id="T-001", scan_status="not_found"), matching],
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                f"/api/threat-models/{threat_model_id}/scans/latest/threat-correlation/{threat_id}"
            )

    assert response.status_code == 200
    body = response.json()
    assert body["threat_id"] == str(threat_id)
    assert body["threat_display_id"] == "T-007"
    assert body["templates"] == ["sqli"]
    assert body["matched_targets"] == ["https://payments.example.com"]
    assert body["cve_ids"] == ["CVE-2026-0001"]


@pytest.mark.asyncio
async def test_build_scan_correlation_maps_path_finding_back_to_node_target():
    threat_model_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    scan_job = SimpleNamespace(
        id=scan_id,
        threat_model_id=threat_model_id,
        completed_at=datetime(2026, 4, 16, 10, 0, tzinfo=timezone.utc),
        targets={str(node_id): "https://api.example.com"},
    )
    node = SimpleNamespace(
        id=node_id,
        name="Public API",
        scan_target_url="https://api.example.com",
    )
    threat_result = SimpleNamespace(
        scan_status="confirmed",
        cve_ids=["CVE-2026-0001"],
        evidence=[
            {
                "finding_id": str(finding_id),
                "template_name": "Auth bypass",
                "template_id": "auth-bypass",
                "severity": "high",
                "matched_at": "https://api.example.com/vendor/diagnostics/session",
                "cve_ids": ["CVE-2026-0001"],
                "tool_name": "nuclei",
                "tool_version": None,
                "validation_target": "https://api.example.com",
                "deterministic": True,
            }
        ],
    )
    threat = SimpleNamespace(
        id=threat_id,
        display_id="T-007",
        description="Unauthenticated diagnostics endpoint",
        severity="High",
        stride_category="Spoofing",
    )

    node_scalars = MagicMock()
    node_scalars.all.return_value = [node]
    node_result = MagicMock()
    node_result.scalars.return_value = node_scalars
    correlation_result = MagicMock()
    correlation_result.all.return_value = [(threat_result, threat)]
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[node_result, correlation_result])

    entries = await _build_scan_correlation_entries(db, scan_job)

    assert len(entries) == 1
    assert entries[0].matched_targets == ["https://api.example.com/vendor/diagnostics/session"]
    assert entries[0].matched_node_ids == [node_id]
    assert entries[0].matched_node_labels == ["Public API"]
    assert entries[0].cve_ids == ["CVE-2026-0001"]
    assert entries[0].validation_tools == ["nuclei"]
    assert entries[0].deterministic_evidence_count == 1
    assert entries[0].evidence[0].tool_name == "nuclei"
    assert entries[0].evidence[0].validation_target == "https://api.example.com"
    assert entries[0].evidence[0].deterministic is True


@pytest.mark.asyncio
async def test_get_latest_threat_scan_correlation_returns_404_when_missing():
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    latest_scan = SimpleNamespace(
        id=uuid.uuid4(),
        completed_at=datetime(2026, 4, 16, 10, 0, tzinfo=timezone.utc),
    )

    with patch("app.api.scans._get_threat_model_for_owner", new_callable=AsyncMock), patch(
        "app.api.scans._get_latest_completed_scan", new_callable=AsyncMock, return_value=latest_scan
    ), patch(
        "app.api.scans._build_scan_correlation_entries",
        new_callable=AsyncMock,
        return_value=[_entry(display_id="T-001", scan_status="confirmed")],
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                f"/api/threat-models/{threat_model_id}/scans/latest/threat-correlation/{threat_id}"
            )

    assert response.status_code == 404
    assert response.json()["detail"] == "No scan correlation found for this threat"


@pytest.mark.asyncio
async def test_get_latest_scan_correlation_returns_404_when_no_completed_scan():
    threat_model_id = uuid.uuid4()

    with patch("app.api.scans._get_threat_model_for_owner", new_callable=AsyncMock), patch(
        "app.api.scans._get_latest_completed_scan",
        new_callable=AsyncMock,
        side_effect=HTTPException(status_code=404, detail="No completed scan found"),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                f"/api/threat-models/{threat_model_id}/scans/latest/threat-correlation"
            )

    assert response.status_code == 404
    assert response.json()["detail"] == "No completed scan found"


@pytest.mark.asyncio
async def test_get_latest_validation_runbook_returns_null_when_no_completed_scan():
    threat_model_id = uuid.uuid4()

    with patch("app.api.scans._get_threat_model_for_owner", new_callable=AsyncMock), patch(
        "app.api.scans._get_latest_completed_scan",
        new_callable=AsyncMock,
        side_effect=HTTPException(status_code=404, detail="No completed scan found"),
    ), patch("app.api.scans.build_validation_runbook", new_callable=AsyncMock) as build_runbook:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                f"/api/threat-models/{threat_model_id}/scans/latest/runbook"
            )

    assert response.status_code == 200
    assert response.json() is None
    build_runbook.assert_not_awaited()
