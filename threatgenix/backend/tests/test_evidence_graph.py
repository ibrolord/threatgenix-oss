from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.evidence import EvidenceStatusResponse
from app.services.auth import get_current_user
from app.services.evidence_freshness import derive_freshness_status
from app.services.evidence_graph import (
    build_evidence_status,
    confidence_label,
    native_key,
    stable_hash,
)
from app.services.evidence_projection import EvidenceProjectionBuilder

BASE_URL = "http://test"


def test_evidence_freshness_statuses_are_conservative():
    now = datetime(2026, 4, 29, tzinfo=timezone.utc)

    assert (
        derive_freshness_status(observed_at=now - timedelta(days=3), now=now) == "fresh"
    )
    assert (
        derive_freshness_status(observed_at=now - timedelta(days=21), now=now)
        == "aging"
    )
    assert (
        derive_freshness_status(observed_at=now - timedelta(days=60), now=now)
        == "stale"
    )
    assert (
        derive_freshness_status(expires_at=now - timedelta(seconds=1), now=now)
        == "expired"
    )
    assert derive_freshness_status(now=now) == "unknown"


def test_evidence_helper_outputs_are_stable():
    assert confidence_label(82) == "validated"
    assert confidence_label(63) == "strongly_indicated"
    assert confidence_label(40) == "contextual"
    assert confidence_label(12) == "theoretical"
    assert confidence_label(0) == "unknown"
    assert native_key("dfd_nodes", "abc") == "native:dfd_nodes:abc"
    assert stable_hash({"b": 2, "a": 1}) == stable_hash({"a": 1, "b": 2})


def test_evidence_projection_builder_reuses_canonical_entities():
    db = SimpleNamespace(add=MagicMock())
    threat_model_id = uuid.uuid4()
    builder = EvidenceProjectionBuilder(
        db,  # type: ignore[arg-type]
        SimpleNamespace(id=threat_model_id),
    )

    first = builder.add_entity(
        entity_type="scan_target",
        canonical_key="scan_target:shared",
        display_name="Shared target",
    )
    second = builder.add_entity(
        entity_type="scan_target",
        canonical_key="scan_target:shared",
        display_name="Shared target duplicate",
    )

    assert second is first
    db.add.assert_called_once_with(first)


class _ScalarResult:
    def __init__(self, value: int):
        self.value = value

    def scalar_one(self) -> int:
        return self.value


class _RowsResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


@pytest.mark.asyncio
async def test_evidence_status_marks_stale_graph_inputs():
    threat_model_id = uuid.uuid4()
    db = AsyncMock()
    db.execute = AsyncMock(
        side_effect=[
            _ScalarResult(1),  # source count
            _ScalarResult(0),  # errored sources
            _ScalarResult(1),  # stale/expired items
            _ScalarResult(0),  # stale/expired sources
            _ScalarResult(0),  # sources older than model
            _ScalarResult(3),  # item count
            _ScalarResult(2),  # entity count
            _ScalarResult(1),  # relationship count
            _ScalarResult(0),  # observation count
            _ScalarResult(1),  # finding count
            _RowsResult([]),  # sources by type
            _RowsResult([]),  # items by type
            _RowsResult([]),  # entities by type
            _RowsResult([]),  # findings by kind
            _RowsResult([]),  # freshness
        ]
    )

    with patch(
        "app.services.evidence_graph.build_coverage_gaps",
        new_callable=AsyncMock,
        return_value=[],
    ):
        status = await build_evidence_status(
            db,
            SimpleNamespace(
                id=threat_model_id,
                updated_at=datetime(2026, 4, 29, tzinfo=timezone.utc),
            ),
        )

    assert status.projection_status == "stale"
    assert status.source_count == 1
    assert status.item_count == 3


@pytest.mark.asyncio
async def test_evidence_status_endpoint_uses_model_permission():
    user_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id, email="analyst@example.com", organization_id=None
    )
    threat_model = SimpleNamespace(
        id=threat_model_id,
        owner_id=user_id,
        owner=user,
        repository_evidence=None,
        cloud_scan_evidence=None,
        iac_evidence=None,
    )
    status = EvidenceStatusResponse(
        threat_model_id=threat_model_id,
        projection_status="not_built",
        generated_at=datetime(2026, 4, 29, tzinfo=timezone.utc),
        source_count=0,
        item_count=0,
        entity_count=0,
        relationship_count=0,
        observation_count=0,
        finding_count=0,
    )

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.evidence.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.evidence.build_evidence_status",
                new_callable=AsyncMock,
                return_value=status,
            ) as build_status,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/threat-models/{threat_model_id}/evidence/status"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["projection_status"] == "not_built"
    build_status.assert_awaited_once()


@pytest.mark.asyncio
async def test_evidence_rebuild_endpoint_requires_write_permission():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    threat_model = SimpleNamespace(
        id=threat_model_id,
        owner_id=owner_id,
        owner=user,
        repository_evidence=None,
        cloud_scan_evidence=None,
        iac_evidence=None,
    )
    status = EvidenceStatusResponse(
        threat_model_id=threat_model_id,
        projection_status="current",
        generated_at=datetime(2026, 4, 29, tzinfo=timezone.utc),
        source_count=1,
        item_count=1,
        entity_count=1,
        relationship_count=0,
        observation_count=0,
        finding_count=0,
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
                "app.api.evidence.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.evidence.rebuild_evidence_graph",
                new_callable=AsyncMock,
                return_value=status,
            ) as rebuild,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-models/{threat_model_id}/evidence/rebuild"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["projection_status"] == "current"
    rebuild.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_evidence_coverage_endpoint_returns_graph_metrics():
    user_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id, email="analyst@example.com", organization_id=None
    )
    threat_model = SimpleNamespace(
        id=threat_model_id,
        owner_id=user_id,
        owner=user,
        repository_evidence=None,
        cloud_scan_evidence=None,
        iac_evidence=None,
    )
    status = EvidenceStatusResponse(
        threat_model_id=threat_model_id,
        projection_status="current",
        generated_at=datetime(2026, 4, 29, tzinfo=timezone.utc),
        source_count=2,
        item_count=3,
        entity_count=4,
        relationship_count=5,
        observation_count=1,
        finding_count=2,
    )
    coverage = {
        "status": status.model_dump(),
        "relationship_types": [{"key": "flows_to", "count": 3}],
        "finding_link_types": [{"key": "supports", "count": 2}],
        "unlinked_finding_count": 0,
        "validated_finding_count": 1,
        "contextual_finding_count": 1,
        "stale_or_expired_item_count": 0,
    }

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.evidence.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.evidence.build_evidence_coverage",
                new_callable=AsyncMock,
                return_value=coverage,
            ) as build_coverage,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/threat-models/{threat_model_id}/evidence/coverage"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["relationship_types"] == [{"key": "flows_to", "count": 3}]
    build_coverage.assert_awaited_once()


@pytest.mark.asyncio
async def test_evidence_neighborhood_requires_entity_locator():
    user_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id, email="analyst@example.com", organization_id=None
    )
    threat_model = SimpleNamespace(
        id=threat_model_id,
        owner_id=user_id,
        owner=user,
        repository_evidence=None,
        cloud_scan_evidence=None,
        iac_evidence=None,
    )

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.evidence.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.evidence.get_entity_neighborhood",
                new_callable=AsyncMock,
            ) as neighborhood,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/threat-models/{threat_model_id}/evidence/neighborhood"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 400
    assert "entity_id" in response.json()["detail"]
    neighborhood.assert_not_awaited()


@pytest.mark.asyncio
async def test_evidence_chain_endpoint_accepts_source_object_lookup():
    user_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id, email="analyst@example.com", organization_id=None
    )
    threat_model = SimpleNamespace(
        id=threat_model_id,
        owner_id=user_id,
        owner=user,
        repository_evidence=None,
        cloud_scan_evidence=None,
        iac_evidence=None,
    )
    now = datetime(2026, 4, 29, tzinfo=timezone.utc)
    chain = {
        "finding": {
            "id": finding_id,
            "threat_model_id": threat_model_id,
            "finding_key": "finding:threat:T-1",
            "finding_kind": "modeled_threat",
            "title": "T-1: Spoofing",
            "description": "Missing authentication boundary.",
            "severity": "High",
            "status": "open",
            "source_id": None,
            "primary_evidence_item_id": None,
            "confidence_score": 55,
            "confidence_label": "contextual",
            "freshness_status": "unknown",
            "source_system": "Rules",
            "source_object_type": "threat",
            "source_object_id": "T-1",
            "first_seen_at": now,
            "last_seen_at": now,
            "resolved_at": None,
            "metadata": {},
            "created_at": now,
            "updated_at": now,
        },
        "source": None,
        "primary_item": None,
        "evidence_items": [],
        "observations": [],
        "entities": [],
        "links": [],
    }

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.evidence.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ),
            patch(
                "app.api.evidence.get_evidence_chain",
                new_callable=AsyncMock,
                return_value=chain,
            ) as evidence_chain,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/threat-models/{threat_model_id}/evidence/evidence-chain",
                    params={
                        "source_object_type": "threat",
                        "source_object_id": "T-1",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["finding"]["source_object_id"] == "T-1"
    evidence_chain.assert_awaited_once()
