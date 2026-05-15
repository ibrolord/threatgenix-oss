"""API-level tests for the /threat-diff endpoint (C-01).

These tests use mocks for the DB layer and FastAPI test client.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.services.auth import get_current_user

BASE_URL = "http://test"
FAKE_USER_ID = uuid.uuid4()
FAKE_TM_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


class FakeThreatModel:
    """Mimics ThreatModel ORM object."""

    def __init__(
        self,
        tm_id: uuid.UUID | None = None,
        last_analyzed_threats: list[dict] | None = None,
        owner_id: uuid.UUID | None = FAKE_USER_ID,
    ):
        self.id = tm_id or FAKE_TM_ID
        self.system_name = "Test Banking System"
        self.description = "A test system"
        self.data_classification = "Internal"
        self.regulatory_scope = []
        self.deployment_model = "cloud"
        self.owner_id = owner_id
        self.last_analyzed_threats = last_analyzed_threats
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


class FakeDFDNode:
    """Mimics DFDNode ORM object for model_validate."""

    def __init__(self, node_id, node_type, name, trust_boundary_id=None, properties=None):
        self.id = node_id
        self.node_type = node_type
        self.name = name
        self.position_x = 0.0
        self.position_y = 0.0
        self.trust_boundary_id = trust_boundary_id
        self.properties = properties or {}
        self.threat_model_id = FAKE_TM_ID


class FakeDFDEdge:
    """Mimics DFDEdge ORM object for model_validate."""

    def __init__(self, edge_id, source_node_id, target_node_id, label=""):
        self.id = edge_id
        self.source_node_id = source_node_id
        self.target_node_id = target_node_id
        self.label = label
        self.properties = {}
        self.threat_model_id = FAKE_TM_ID


class FakeTrustBoundary:
    """Mimics TrustBoundary ORM object for model_validate."""

    def __init__(self, boundary_id, name, node_ids):
        self.id = boundary_id
        self.name = name
        self.node_ids = node_ids
        self.threat_model_id = FAKE_TM_ID


# Deterministic IDs
NODE_EE = uuid.UUID("20000000-0000-0000-0000-000000000001")
NODE_P = uuid.UUID("20000000-0000-0000-0000-000000000002")
EDGE_ID = uuid.UUID("20000000-0000-0000-0000-0000000000e1")
BOUNDARY_ID = uuid.UUID("20000000-0000-0000-0000-0000000000b1")


# ---------------------------------------------------------------------------
# Dependency overrides
# ---------------------------------------------------------------------------

async def override_get_current_user():
    return FakeUser()


async def override_get_db():
    yield AsyncMock()


# Apply overrides via autouse fixture to ensure they're set for every test
@pytest.fixture(autouse=True)
def _apply_overrides():
    """Ensure auth + db overrides are set before every test in this module."""
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_db] = override_get_db
    yield
    # Restore overrides after each test (in case a test removed them)
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_db] = override_get_db


def _scalars_result(items):
    """Build a MagicMock that mimics result.scalars().all() -> items."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threat_diff_no_baseline_returns_has_baseline_false():
    """When last_analyzed_threats is None, endpoint returns has_baseline=False."""
    fake_tm = FakeThreatModel(tm_id=FAKE_TM_ID, last_analyzed_threats=None)

    with patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{FAKE_TM_ID}/threat-diff"
            )

    assert response.status_code == 200
    body = response.json()
    assert body["has_baseline"] is False
    assert body["added"] == []
    assert body["removed"] == []
    assert body["counts"]["added"] == 0
    assert body["counts"]["removed"] == 0


@pytest.mark.asyncio
async def test_threat_diff_with_baseline_returns_diff():
    """When baseline exists and current rules differ, endpoint returns correct diff."""
    # Baseline has 2 threats
    baseline_threats = [
        {
            "rule_id": "S-01",
            "stride_category": "Spoofing",
            "threat_subtype": "Identity spoofing",
            "severity": "High",
            "description": "An attacker could spoof identity",
            "affected_node_ids": [str(NODE_EE), str(NODE_P)],
            "affected_edge_ids": [str(EDGE_ID)],
        },
        {
            "rule_id": "D-01",
            "stride_category": "Denial of Service",
            "threat_subtype": "Flood attack",
            "severity": "Medium",
            "description": "External entity could flood the process",
            "affected_node_ids": [str(NODE_EE), str(NODE_P)],
            "affected_edge_ids": [str(EDGE_ID)],
        },
    ]
    fake_tm = FakeThreatModel(tm_id=FAKE_TM_ID, last_analyzed_threats=baseline_threats)

    # Current rules engine returns D-01 (unchanged) + T-01 (new); S-01 removed
    current_threats = [
        GeneratedThreat(
            rule_id="D-01",
            display_id="T-001",
            stride_category="Denial of Service",
            threat_subtype="Flood attack",
            severity="Medium",
            description="External entity could flood the process",
            affected_node_ids=[str(NODE_EE), str(NODE_P)],
            affected_edge_ids=[str(EDGE_ID)],
            source="Rules",
        ),
        GeneratedThreat(
            rule_id="T-01",
            display_id="T-002",
            stride_category="Tampering",
            threat_subtype="Data tampering in transit",
            severity="High",
            description="Data could be tampered in transit",
            affected_node_ids=[str(NODE_EE), str(NODE_P)],
            affected_edge_ids=[str(EDGE_ID)],
            source="Rules",
        ),
    ]
    mock_rules_output = RuleEngineOutput(
        threats=current_threats,
        execution_time_ms=1.0,
        rules_evaluated=10,
        rules_fired=2,
    )

    # Build fake DFD objects
    fake_nodes = [
        FakeDFDNode(NODE_EE, "external_entity", "Browser"),
        FakeDFDNode(NODE_P, "process", "Server", trust_boundary_id=BOUNDARY_ID),
    ]
    fake_edges = [
        FakeDFDEdge(EDGE_ID, NODE_EE, NODE_P, "HTTP request"),
    ]
    fake_boundaries = [
        FakeTrustBoundary(BOUNDARY_ID, "Internal", [NODE_P]),
    ]

    # The threat-diff endpoint with get_threat_model patched will call db.execute for:
    # 1. select(DFDNode)
    # 2. select(DFDEdge)
    # 3. select(TrustBoundary)
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(side_effect=[
        _scalars_result(fake_nodes),
        _scalars_result(fake_edges),
        _scalars_result(fake_boundaries),
    ])

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_db

    try:
        with (
            patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
            patch("app.api.threats.evaluate_rules", return_value=mock_rules_output),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-models/{FAKE_TM_ID}/threat-diff"
                )

        assert response.status_code == 200
        body = response.json()
        assert body["has_baseline"] is True
        # S-01 removed, T-01 added, D-01 unchanged
        assert body["counts"]["added"] == 1
        assert body["counts"]["removed"] == 1
        assert body["counts"]["total_before"] == 2
        assert body["counts"]["total_after"] == 2

        added_rule_ids = {t["rule_id"] for t in body["added"]}
        removed_rule_ids = {t["rule_id"] for t in body["removed"]}
        assert "T-01" in added_rule_ids
        assert "S-01" in removed_rule_ids
    finally:
        app.dependency_overrides[get_db] = override_get_db


@pytest.mark.asyncio
async def test_threat_diff_requires_auth():
    """Calling /threat-diff without auth should return 401.

    This test clears ALL dependency overrides to simulate an unauthenticated
    request. Other test modules may also set overrides at module level, so
    we must clear and restore the entire dict.
    """
    saved_overrides = dict(app.dependency_overrides)
    app.dependency_overrides.clear()

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{FAKE_TM_ID}/threat-diff"
            )
        # Should get 401 or 403 (depends on auth implementation)
        assert response.status_code in (401, 403), \
            f"Expected 401/403 without auth, got {response.status_code}"
    finally:
        app.dependency_overrides.update(saved_overrides)


@pytest.mark.asyncio
async def test_threat_diff_404_for_nonexistent_model():
    """Calling /threat-diff with a non-existent threat_model_id should return 404."""
    fake_id = uuid.uuid4()

    with patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=None):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_id}/threat-diff"
            )

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_analyze_saves_rules_only_snapshot():
    """POST /analyze?rules_only=true should save ONLY rules-engine threats in last_analyzed_threats."""
    fake_tm = FakeThreatModel(tm_id=FAKE_TM_ID, last_analyzed_threats=None)

    # Rules engine output: 2 threats
    rules_threats = [
        GeneratedThreat(
            rule_id="S-01",
            display_id="T-001",
            stride_category="Spoofing",
            threat_subtype="Identity spoofing",
            severity="High",
            description="Spoofing threat from rules engine",
            affected_node_ids=[str(NODE_EE), str(NODE_P)],
            affected_edge_ids=[str(EDGE_ID)],
            source="Rules",
        ),
        GeneratedThreat(
            rule_id="D-02",
            display_id="T-002",
            stride_category="Denial of Service",
            threat_subtype="Resource exhaustion",
            severity="Low",
            description="DoS threat from rules engine",
            affected_node_ids=[str(NODE_P)],
            affected_edge_ids=[],
            source="Rules",
        ),
    ]
    mock_rules_output = RuleEngineOutput(
        threats=rules_threats,
        execution_time_ms=1.0,
        rules_evaluated=10,
        rules_fired=2,
    )

    # Build fake DFD objects
    fake_nodes = [
        FakeDFDNode(NODE_EE, "external_entity", "Browser"),
        FakeDFDNode(NODE_P, "process", "Server", trust_boundary_id=BOUNDARY_ID),
    ]
    fake_edges = [
        FakeDFDEdge(EDGE_ID, NODE_EE, NODE_P, "HTTP request"),
    ]
    fake_boundaries = [
        FakeTrustBoundary(BOUNDARY_ID, "Internal", [NODE_P]),
    ]

    # The analyze endpoint with get_threat_model patched calls db.execute for:
    # 1. select(DFDNode)
    # 2. select(DFDEdge)
    # 3. select(TrustBoundary)
    # 4. select(latest Document) — for doc excerpt / quality warnings
    # 5. pg_advisory_xact_lock
    # 6. select(existing Threat) — for triage preservation
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(side_effect=[
        _scalars_result(fake_nodes),
        _scalars_result(fake_edges),
        _scalars_result(fake_boundaries),
        MagicMock(scalar_one_or_none=MagicMock(return_value=None)),
        MagicMock(),  # pg_advisory_xact_lock
        _scalars_result([]),  # select existing threats (empty — first analysis)
        # _recompute_clusters: delete old clusters + select all persisted threats
        MagicMock(),  # delete(ThreatCluster)
        _scalars_result([]),  # select(Threat) for clustering
    ])
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_db

    try:
        with (
            patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
            patch("app.api.threats.evaluate_rules", return_value=mock_rules_output),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-models/{FAKE_TM_ID}/analyze?rules_only=true"
                )

        assert response.status_code == 200

        # Verify last_analyzed_threats was set on the threat model
        snapshot = fake_tm.last_analyzed_threats
        assert snapshot is not None, "last_analyzed_threats should have been set"
        assert isinstance(snapshot, list)
        assert len(snapshot) == 2, \
            f"Snapshot should have 2 rules-only threats, got {len(snapshot)}"

        # Verify snapshot contains ONLY rules-engine threats (not AI)
        snapshot_rule_ids = {t["rule_id"] for t in snapshot}
        assert snapshot_rule_ids == {"S-01", "D-02"}, \
            f"Snapshot should contain only rules threats, got {snapshot_rule_ids}"

        # Verify each entry has the expected keys
        for entry in snapshot:
            assert "rule_id" in entry
            assert "stride_category" in entry
            assert "severity" in entry
            assert "description" in entry
            assert "affected_node_ids" in entry
            assert "affected_edge_ids" in entry
            # Verify node IDs are strings
            for nid in entry["affected_node_ids"]:
                assert isinstance(nid, str), f"Node ID should be string, got {type(nid)}"
    finally:
        app.dependency_overrides[get_db] = override_get_db
