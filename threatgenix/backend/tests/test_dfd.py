"""Tests for DFD endpoint and generation service (F-04)."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.api import dfd as dfd_api
from app.database import get_db
from app.main import app
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.schemas.dfd import (
    DFDBulkSave,
    DFDEdgeUpdate,
    DFDDecompositionViewCreate,
    DFDWorkspaceViewCreate,
    DFDNodeCreate,
    DFDNodeUpdate,
    DFDQuickAddEdge,
    DFDQuickAddRequest,
    DFDViewLayoutSnapshot,
    DFDViewResponse,
    TrustBoundaryCreate,
)
from app.services.auth import get_current_user
from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, DFDResponse
from app.services.dfd_generator import normalize_name, resolve_node_by_name
from app.services.dfd_layout import compute_layout
from app.services.dfd_views import build_default_views

BASE_URL = "http://test"


async def override_get_db():
    yield AsyncMock()


FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


async def override_get_current_user():
    return FakeUser()


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user


def _api_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/dfd"


def test_dfd_schema_accepts_custom_dropdown_values():
    node_update = DFDNodeUpdate.model_validate(
        {
            "properties": {
                "authentication_type": "fido2",
                "authorization_model": "scoped_policy_graph",
                "network_exposure": "partner_vpn",
                "privilege_level": "break_glass",
            }
        }
    )
    edge_update = DFDEdgeUpdate.model_validate(
        {
            "properties": {
                "data_classification": "Highly Restricted",
                "lifecycle_stage": "post_settlement_archive",
                "directionality": "callback_chain",
                "transfer_mode": "event_sourcing_replay",
                "tls_version": "quic-tls",
            }
        }
    )
    boundary = TrustBoundaryCreate.model_validate(
        {
            "name": "Partner Zone",
            "node_ids": [],
            "boundary_type": "partner_network",
        }
    )

    assert node_update.properties is not None
    assert node_update.properties.authentication_type == "fido2"
    assert node_update.properties.authorization_model == "scoped_policy_graph"
    assert node_update.properties.network_exposure == "partner_vpn"
    assert node_update.properties.privilege_level == "break_glass"

    assert edge_update.properties is not None
    assert edge_update.properties.data_classification == "Highly Restricted"
    assert edge_update.properties.lifecycle_stage == "post_settlement_archive"
    assert edge_update.properties.directionality == "callback_chain"
    assert edge_update.properties.transfer_mode == "event_sourcing_replay"
    assert edge_update.properties.tls_version == "quic-tls"

    assert boundary.boundary_type == "partner_network"


def test_dfd_node_scan_target_validators_accept_http_targets_and_normalize_ports():
    node = DFDNodeCreate(
        node_type="process",
        name="API Gateway",
        scan_target_url=" https://api.example.com/health ",
        scan_target_ports="443, 8443",
    )

    assert node.scan_target_url == "https://api.example.com/health"
    assert node.scan_target_ports == "443,8443"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scan_target_url", "file:///etc/passwd"),
        ("scan_target_url", "javascript:alert(1)"),
        ("scan_target_ports", "443; rm -rf /"),
        ("scan_target_ports", "0,443"),
        ("scan_target_ports", "65536"),
    ],
)
def test_dfd_node_scan_target_validators_reject_unsafe_scan_targets(
    field: str, value: str
):
    payload = {
        "node_type": "process",
        "name": "API Gateway",
        "scan_target_url": "https://api.example.com",
        "scan_target_ports": "443",
        field: value,
    }

    with pytest.raises(ValidationError):
        DFDNodeUpdate.model_validate(payload)


def test_normalize_node_properties_derives_flags_from_custom_dropdown_values():
    properties = dfd_api._normalize_node_properties(
        {
            "authentication_type": "fido2",
            "input_validation": "schema allowlist",
            "encryption_at_rest": "KMS envelope",
            "backup_strategy": "cross-region snapshots",
            "network_exposure": "public edge partner",
            "trust_level": "partner enclave",
            "data_classification": "Highly Restricted",
        }
    )

    assert properties["uses_auth"] is True
    assert properties["authenticated"] is True
    assert properties["validates_input"] is True
    assert properties["encrypted_at_rest"] is True
    assert properties["has_backup"] is True
    assert properties["internet_facing"] is True
    assert properties["trusted"] is False
    assert properties["handles_sensitive_data"] is True


class FakeThreatModel:
    def __init__(self, id=None):
        self.id = id or uuid.uuid4()
        self.system_name = "Test System"
        self.description = ""
        self.data_classification = "Internal"
        self.owner_id = FAKE_USER_ID
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.dfd_views = None
        self.repository_evidence = None


class MutableBoundary:
    def __init__(
        self,
        id: uuid.UUID,
        name: str = "Boundary",
        node_ids: list[uuid.UUID] | None = None,
        *,
        position_x: float = 0.0,
        position_y: float = 0.0,
        width: float = 280.0,
        height: float = 180.0,
    ):
        self.id = id
        self.name = name
        self.node_ids = list(node_ids or [])
        self.position_x = position_x
        self.position_y = position_y
        self.width = width
        self.height = height


def _scalar_one_result(value):
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    return result


def _scalars_all_result(values):
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = values
    result = MagicMock()
    result.scalars.return_value = mock_scalars
    return result


def _make_mock_db(*execute_results, add_side_effect=None):
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=list(execute_results))
    db.add = MagicMock(side_effect=add_side_effect)
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.rollback = AsyncMock()
    db.delete = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


# ─── GET DFD Tests ──────────────────────────────────────────────────


def _repo_seed_evidence() -> dict:
    return {
        "source_type": "archive",
        "filename": "repo.zip",
        "file_count": 4,
        "dfd_seed_suggestions": [
            {
                "id": "repo-seed-api-layer",
                "node_type": "process",
                "label": "API layer",
                "rationale": "Repository route definitions indicate an API surface.",
                "source_refs": ["GET /api/reviews"],
                "confidence": 0.82,
            },
            {
                "id": "repo-seed-postgresql",
                "node_type": "data_store",
                "label": "PostgreSQL",
                "rationale": "Repository dependency hints indicate a data store.",
                "source_refs": ["PostgreSQL"],
                "confidence": 0.72,
            },
            {
                "id": "repo-seed-sqs",
                "node_type": "queue",
                "label": "Amazon SQS",
                "rationale": "Repository publisher hints indicate asynchronous flow.",
                "source_refs": ["Amazon SQS"],
                "confidence": 0.7,
            },
        ],
        "dfd_seed_flow_suggestions": [
            {
                "id": "repo-flow-api-postgresql",
                "source_seed_id": "repo-seed-api-layer",
                "target_seed_id": "repo-seed-postgresql",
                "label": "reads/writes persisted data",
                "rationale": "Repository data-store hints and route evidence indicate persisted application state.",
                "source_refs": ["POST /payments/charge"],
                "confidence": 0.68,
                "directionality": "request",
                "transfer_mode": "synchronous",
                "lifecycle_stage": "storage",
            },
            {
                "id": "repo-flow-api-sqs",
                "source_seed_id": "repo-seed-api-layer",
                "target_seed_id": "repo-seed-sqs",
                "label": "publishes async work",
                "rationale": "Repository queue clients indicate asynchronous work or notification flow.",
                "source_refs": ["Amazon SQS publisher/client"],
                "confidence": 0.66,
                "directionality": "event",
                "transfer_mode": "asynchronous",
                "lifecycle_stage": "notification",
            },
        ],
        "dfd_seed_boundary_suggestions": [
            {
                "id": "repo-boundary-data-tier-boundary",
                "name": "Data Tier Boundary",
                "boundary_type": "regulatory",
                "seed_ids": ["repo-seed-postgresql"],
                "rationale": "Repository data-store hints indicate a data boundary.",
                "source_refs": ["PostgreSQL"],
                "confidence": 0.66,
            },
            {
                "id": "repo-boundary-async-messaging-boundary",
                "name": "Async Messaging Boundary",
                "boundary_type": "cloud",
                "seed_ids": ["repo-seed-sqs"],
                "rationale": "Repository queue hints indicate asynchronous infrastructure.",
                "source_refs": ["Amazon SQS"],
                "confidence": 0.62,
            },
        ],
        "parsed_at": "2026-05-01T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_preview_repository_dfd_suggestions_does_not_mutate():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.repository_evidence = _repo_seed_evidence()
    existing_node = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=tm_id,
        node_type="process",
        name="API layer",
        position_x=0,
        position_y=0,
        trust_boundary_id=None,
        properties={},
    )
    db = _make_mock_db(
        _scalars_all_result([existing_node]),
        _scalars_all_result([]),
        _scalars_all_result([]),
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.preview_repository_dfd_suggestions(
            tm_id,
            db=db,
            current_user=FakeUser(),
        )

    assert response.existing_node_count == 1
    assert response.unmatched_suggestion_count == 2
    assert response.inferred_flow_count == 2
    assert response.inferred_boundary_count == 2
    assert response.suggestions[0].match_status == "matched_existing"
    assert response.suggestions[0].matched_node_id == existing_node.id
    assert response.suggestions[1].match_status == "new"
    assert response.suggestions[2].node_type == "managed_service"
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_apply_repository_dfd_suggestions_creates_selected_nodes_and_edges():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.repository_evidence = _repo_seed_evidence()
    existing_node = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=tm_id,
        node_type="process",
        name="API layer",
        position_x=0,
        position_y=0,
        trust_boundary_id=None,
        properties={},
    )
    added_models: list[object] = []

    def add_side_effect(model):
        added_models.append(model)

    boundary_flush_observations: list[dict[str, uuid.UUID | None]] = []

    async def flush_side_effect():
        boundary_flush_observations.append(
            {
                node.name: node.trust_boundary_id
                for node in added_models
                if isinstance(node, DFDNode)
            }
        )

    db = _make_mock_db(
        _scalars_all_result([existing_node]),
        _scalars_all_result([]),
        _scalars_all_result([]),
        add_side_effect=add_side_effect,
    )
    db.flush = AsyncMock(side_effect=flush_side_effect)

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.apply_repository_dfd_suggestions(
            tm_id,
            dfd_api.DFDRepositorySeedApplyRequest(
                suggestion_ids=["repo-seed-postgresql", "repo-seed-sqs"]
            ),
            db=db,
            current_user=FakeUser(),
        )

    created_nodes = [model for model in added_models if isinstance(model, DFDNode)]
    created_edges = [model for model in added_models if isinstance(model, DFDEdge)]
    created_boundaries = [
        model for model in added_models if isinstance(model, TrustBoundary)
    ]
    assert response.summary.requested_suggestion_count == 2
    assert response.summary.created_nodes == 2
    assert response.summary.created_edges == 2
    assert response.summary.created_boundaries == 2
    assert response.summary.skipped_suggestions == []
    assert {node.name for node in created_nodes} == {"PostgreSQL", "Amazon SQS"}
    assert {node.node_type for node in created_nodes} == {"data_store", "managed_service"}
    assert all(edge.source_node_id == existing_node.id for edge in created_edges)
    assert {edge.label for edge in created_edges} == {
        "publishes async work",
        "reads/writes persisted data",
    }
    queue_edge = next(edge for edge in created_edges if edge.label == "publishes async work")
    assert queue_edge.properties["directionality"] == "event"
    assert queue_edge.properties["transfer_mode"] == "asynchronous"
    assert {boundary.name for boundary in created_boundaries} == {
        "Async Messaging Boundary",
        "Data Tier Boundary",
    }
    assert all(boundary.node_ids for boundary in created_boundaries)
    assert {node.trust_boundary_id for node in created_nodes} == {
        boundary.id for boundary in created_boundaries
    }
    assert boundary_flush_observations
    assert len(boundary_flush_observations) == len(created_boundaries)
    assert all(
        trust_boundary_id is None
        for trust_boundary_id in boundary_flush_observations[0].values()
    )
    assert len(response.dfd.nodes) == 3
    assert len(response.dfd.trust_boundaries) == 2
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_dfd_empty_returns_200():
    """GET DFD when no DFD data exists -> 200 with empty lists."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    # Mock the DB queries to return empty results
    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_api_url(tm_id))

    assert response.status_code == 200
    body = response.json()
    assert body["nodes"] == []
    assert body["edges"] == []
    assert body["trust_boundaries"] == []

    # Reset override
    app.dependency_overrides[get_db] = override_get_db


@pytest.mark.asyncio
async def test_get_dfd_not_found_returns_404():
    """GET DFD for non-existent threat model -> 404."""
    tm_id = uuid.uuid4()

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=None
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_api_url(tm_id))

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_get_dfd_with_data_returns_nodes_edges_boundaries():
    """GET DFD returns populated DFD data."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    node_id_1 = uuid.uuid4()
    node_id_2 = uuid.uuid4()
    edge_id = uuid.uuid4()
    boundary_id = uuid.uuid4()

    class FakeNode:
        id = node_id_1
        node_type = "process"
        name = "API Gateway"
        position_x = 0.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    class FakeNode2:
        id = node_id_2
        node_type = "data_store"
        name = "User DB"
        position_x = 120.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    class FakeEdge:
        id = edge_id
        source_node_id = node_id_1
        target_node_id = node_id_2
        label = "query"
        properties = {}

    class FakeBoundary:
        id = boundary_id
        name = "DMZ"
        node_ids = [node_id_1]
        position_x = 0.0
        position_y = 0.0
        width = 220.0
        height = 120.0

    # Set up mock DB to return different results for each query
    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()
        if call_count == 1:
            mock_scalars.all.return_value = [FakeNode(), FakeNode2()]
        elif call_count == 2:
            mock_scalars.all.return_value = [FakeEdge()]
        else:
            mock_scalars.all.return_value = [FakeBoundary()]
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_api_url(tm_id))

    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 2
    assert len(body["edges"]) == 1
    assert len(body["trust_boundaries"]) == 1
    assert body["nodes"][0]["name"] == "API Gateway"
    assert body["edges"][0]["label"] == "query"
    assert body["trust_boundaries"][0]["name"] == "DMZ"

    # Reset override
    app.dependency_overrides[get_db] = override_get_db


# ─── Name Normalization Tests (Block 8) ─────────────────────────────


def test_normalize_name_basic():
    assert normalize_name("API Gateway") == "api gateway"


def test_normalize_name_hyphens_underscores():
    assert normalize_name("api-gateway_service") == "api gateway service"


def test_normalize_name_extra_whitespace():
    assert normalize_name("  API   Gateway  ") == "api gateway"


def test_normalize_name_mixed():
    assert normalize_name("  My-Cool_Service  Name ") == "my cool service name"


def test_resolve_node_by_name_found():
    node_id = uuid.uuid4()
    nodes = {"api gateway": node_id}
    assert resolve_node_by_name("API Gateway", nodes) == node_id


def test_resolve_node_by_name_with_hyphens():
    node_id = uuid.uuid4()
    nodes = {"api gateway": node_id}
    assert resolve_node_by_name("api-gateway", nodes) == node_id


def test_resolve_node_by_name_not_found():
    nodes = {"api gateway": uuid.uuid4()}
    assert resolve_node_by_name("nonexistent", nodes) is None


# ─── Layout Tests (Block 10) ────────────────────────────────────────


def test_compute_layout_groups_by_type():
    nodes = [
        {"id": "1", "node_type": "external_entity"},
        {"id": "2", "node_type": "process"},
        {"id": "3", "node_type": "data_store"},
    ]
    positions = compute_layout(nodes, [])
    # external_entity at x=0, process at x=120, data_store at x=240
    assert positions["1"][0] == 0.0
    assert positions["2"][0] == 120.0
    assert positions["3"][0] == 240.0


@pytest.mark.asyncio
async def test_import_iac_into_dfd_returns_reconciled_graph():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.iac_evidence = {
        "source_type": "archive",
        "filename": "infra.zip",
        "reference": "prod/payments",
        "resource_count": 3,
        "resource_types": ["Deployment", "Service", "aws_db_instance"],
        "resource_names": [
            "Deployment:payments-api",
            "Service:payments-public",
            "aws_db_instance.payments",
        ],
        "public_exposure": ["payments-public load balancer"],
        "iam_bindings": [],
        "network_paths": ["payments-public network entry"],
        "secret_refs": [],
        "warnings": [],
        "parsed_at": "2026-04-16T00:00:00Z",
    }

    imported_dfd = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=uuid.uuid4(),
                node_type="api_gateway",
                name="payments-public",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                scan_target_url=None,
                scan_target_ports=None,
                properties={"internet_facing": True},
                security_controls=[],
            )
        ],
        edges=[],
        trust_boundaries=[],
    )
    persisted_dfd = imported_dfd

    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_dfd_response",
            new_callable=AsyncMock,
            return_value=DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
        ),
        patch(
            "app.api.dfd.build_iac_import_draft",
            return_value=MagicMock(
                dfd=imported_dfd,
                imported_resource_count=3,
                semantic_resource_count=1,
                warnings=[],
            ),
        ),
        patch(
            "app.api.dfd.merge_iac_import_into_dfd",
            return_value=(
                imported_dfd,
                MagicMock(
                    mode="merge",
                    imported_resource_count=3,
                    semantic_resource_count=1,
                    matched_existing_nodes=0,
                    created_nodes=1,
                    updated_nodes=0,
                    created_edges=0,
                    created_boundaries=0,
                    warnings=[],
                ),
            ),
        ),
        patch(
            "app.api.dfd._persist_root_dfd",
            new_callable=AsyncMock,
            return_value=persisted_dfd,
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{_api_url(tm_id)}/import-iac", json={"mode": "merge"}
            )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["mode"] == "merge"
    assert body["summary"]["created_nodes"] == 1
    assert body["dfd"]["nodes"][0]["name"] == "payments-public"


def test_compute_layout_multiple_in_same_rank():
    nodes = [
        {"id": "1", "node_type": "process"},
        {"id": "2", "node_type": "process"},
        {"id": "3", "node_type": "process"},
    ]
    positions = compute_layout(nodes, [], nodesep=80)
    # All at x=120 (process rank), spaced by nodesep on y
    assert positions["1"][0] == 120.0
    assert positions["2"][0] == 120.0
    assert positions["3"][0] == 120.0
    # Y positions should be spaced
    assert positions["2"][1] - positions["1"][1] == 80.0


def test_compute_layout_empty():
    positions = compute_layout([], [])
    assert positions == {}


@pytest.mark.asyncio
async def test_bulk_save_dfd_preserves_existing_ids_for_relationships():
    """Bulk save should preserve node/edge/boundary IDs so references stay valid."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    boundary_id = uuid.uuid4()
    node_a_id = uuid.uuid4()
    node_b_id = uuid.uuid4()
    edge_id = uuid.uuid4()

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.put(
                _api_url(tm_id),
                json={
                    "nodes": [
                        {
                            "id": str(node_a_id),
                            "node_type": "process",
                            "name": "API Gateway",
                            "position_x": 10,
                            "position_y": 20,
                            "trust_boundary_id": str(boundary_id),
                            "scan_target_url": "https://api.example.com",
                            "scan_target_ports": "443,8443",
                            "properties": {"uses_auth": True},
                        },
                        {
                            "id": str(node_b_id),
                            "node_type": "data_store",
                            "name": "User DB",
                            "position_x": 30,
                            "position_y": 40,
                            "trust_boundary_id": None,
                            "properties": {},
                        },
                    ],
                    "edges": [
                        {
                            "id": str(edge_id),
                            "source_node_id": str(node_a_id),
                            "target_node_id": str(node_b_id),
                            "label": "query",
                            "properties": {
                                "protocol": "SQL",
                                "data_payload": "Customer record lookup",
                                "data_classification": "Restricted",
                                "encryption_in_transit": True,
                            },
                        }
                    ],
                    "trust_boundaries": [
                        {
                            "id": str(boundary_id),
                            "name": "DMZ",
                            "node_ids": [str(node_a_id)],
                            "boundary_type": "network",
                        }
                    ],
                },
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["nodes"][0]["id"] == str(node_a_id)
    assert body["nodes"][0]["trust_boundary_id"] == str(boundary_id)
    assert body["nodes"][0]["scan_target_url"] == "https://api.example.com"
    assert body["nodes"][0]["scan_target_ports"] == "443,8443"
    assert body["edges"][0]["id"] == str(edge_id)
    assert body["edges"][0]["source_node_id"] == str(node_a_id)
    assert body["edges"][0]["target_node_id"] == str(node_b_id)
    assert body["edges"][0]["properties"]["protocol"] == "SQL"
    assert body["edges"][0]["properties"]["data_classification"] == "Restricted"
    assert body["trust_boundaries"][0]["id"] == str(boundary_id)
    assert body["trust_boundaries"][0]["node_ids"] == [str(node_a_id)]
    assert body["trust_boundaries"][0]["boundary_type"] == "network"
    assert body["trust_boundaries"][0]["position_x"] == -10
    assert body["trust_boundaries"][0]["position_y"] == 0
    assert body["trust_boundaries"][0]["width"] == 220
    assert body["trust_boundaries"][0]["height"] == 104


def test_bulk_save_rejects_cyclic_parent_boundary_references():
    boundary_a_id = uuid.uuid4()
    boundary_b_id = uuid.uuid4()

    with pytest.raises(HTTPException) as excinfo:
        dfd_api._materialize_dfd_response_from_bulk_save(
            DFDBulkSave(
                nodes=[],
                edges=[],
                trust_boundaries=[
                    {
                        "id": boundary_a_id,
                        "name": "Boundary A",
                        "node_ids": [],
                        "parent_boundary_id": boundary_b_id,
                    },
                    {
                        "id": boundary_b_id,
                        "name": "Boundary B",
                        "node_ids": [],
                        "parent_boundary_id": boundary_a_id,
                    },
                ],
            )
        )

    assert excinfo.value.status_code == 400
    assert (
        excinfo.value.detail == "DFD payload contains cyclic parent boundary references"
    )


@pytest.mark.asyncio
async def test_create_node_with_boundary_updates_boundary_node_ids():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    node_id = uuid.uuid4()
    boundary_id = uuid.uuid4()
    boundary = MutableBoundary(boundary_id, node_ids=[])
    db = _make_mock_db(_scalars_all_result([boundary]))

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.create_node(
            tm_id,
            DFDNodeCreate(
                id=node_id,
                node_type="process",
                name="API Gateway",
                trust_boundary_id=boundary_id,
                scan_target_url="https://gateway.example.com",
                scan_target_ports="443",
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.id == node_id
    assert response.trust_boundary_id == boundary_id
    assert response.scan_target_url == "https://gateway.example.com"
    assert response.scan_target_ports == "443"
    assert boundary.node_ids == [node_id]
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_node_moves_boundary_membership():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    node_id = uuid.uuid4()
    old_boundary_id = uuid.uuid4()
    new_boundary_id = uuid.uuid4()
    node = DFDNode(
        id=node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=0,
        position_y=0,
        trust_boundary_id=old_boundary_id,
        properties={},
    )
    old_boundary = MutableBoundary(old_boundary_id, node_ids=[node_id])
    new_boundary = MutableBoundary(new_boundary_id, node_ids=[])
    db = _make_mock_db(
        _scalar_one_result(node),
        _scalars_all_result([old_boundary, new_boundary]),
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.update_node(
            tm_id,
            node_id,
            DFDNodeUpdate(trust_boundary_id=new_boundary_id),
            db=db,
            current_user=FakeUser(),
        )

    assert response.trust_boundary_id == new_boundary_id
    assert node.trust_boundary_id == new_boundary_id
    assert old_boundary.node_ids == []
    assert new_boundary.node_ids == [node_id]
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_node_removes_boundary_membership():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    node_id = uuid.uuid4()
    boundary_id = uuid.uuid4()
    node = DFDNode(
        id=node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=0,
        position_y=0,
        trust_boundary_id=boundary_id,
        properties={},
    )
    boundary = MutableBoundary(boundary_id, node_ids=[node_id])
    db = _make_mock_db(
        _scalar_one_result(node),
        _scalars_all_result([boundary]),
        MagicMock(),
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.delete_node(
            tm_id,
            node_id,
            db=db,
            current_user=FakeUser(),
        )

    assert response.status_code == 204
    assert node.trust_boundary_id is None
    assert boundary.node_ids == []
    db.delete.assert_awaited_once_with(node)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_boundary_sets_member_node_trust_boundary_ids():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    boundary_id = uuid.uuid4()
    existing_boundary_id = uuid.uuid4()
    node_a_id = uuid.uuid4()
    node_b_id = uuid.uuid4()
    node_a = DFDNode(
        id=node_a_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=0,
        position_y=0,
        trust_boundary_id=existing_boundary_id,
        properties={},
    )
    node_b = DFDNode(
        id=node_b_id,
        threat_model_id=tm_id,
        node_type="data_store",
        name="User DB",
        position_x=0,
        position_y=0,
        trust_boundary_id=None,
        properties={},
    )
    existing_boundary = MutableBoundary(existing_boundary_id, node_ids=[node_a_id])
    db = _make_mock_db(
        _scalars_all_result([node_a, node_b]),
        _scalars_all_result([existing_boundary]),
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.create_boundary(
            tm_id,
            TrustBoundaryCreate(
                id=boundary_id,
                name="DMZ",
                node_ids=[node_a_id, node_b_id],
                boundary_type="network",
            ),
            db=db,
            current_user=FakeUser(),
        )

    created_boundary = db.add.call_args.args[0]
    assert response.id == boundary_id
    assert response.node_ids == [node_a_id, node_b_id]
    assert node_a.trust_boundary_id == boundary_id
    assert node_b.trust_boundary_id == boundary_id
    assert existing_boundary.node_ids == []
    assert created_boundary.node_ids == [node_a_id, node_b_id]
    assert created_boundary.position_x == -20
    assert created_boundary.position_y == -20
    assert created_boundary.width == 220
    assert created_boundary.height == 104
    assert created_boundary.boundary_type == "network"
    assert response.boundary_type == "network"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_empty_boundary_uses_requested_geometry():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    boundary_id = uuid.uuid4()
    db = _make_mock_db()

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.create_boundary(
            tm_id,
            TrustBoundaryCreate(
                id=boundary_id,
                name="Empty Zone",
                node_ids=[],
                position_x=320,
                position_y=180,
                width=300,
                height=200,
            ),
            db=db,
            current_user=FakeUser(),
        )

    created_boundary = db.add.call_args.args[0]
    assert response.id == boundary_id
    assert response.node_ids == []
    assert response.position_x == 320
    assert response.position_y == 180
    assert response.width == 300
    assert response.height == 200
    assert created_boundary.position_x == 320
    assert created_boundary.position_y == 180
    assert created_boundary.width == 300
    assert created_boundary.height == 200
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_boundary_clears_member_node_trust_boundary_ids():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    boundary_id = uuid.uuid4()
    boundary = MutableBoundary(boundary_id, node_ids=[])
    node_a = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=0,
        position_y=0,
        trust_boundary_id=boundary_id,
        properties={},
    )
    node_b = DFDNode(
        id=uuid.uuid4(),
        threat_model_id=tm_id,
        node_type="external_entity",
        name="Customer",
        position_x=0,
        position_y=0,
        trust_boundary_id=boundary_id,
        properties={},
    )
    db = _make_mock_db(
        _scalar_one_result(boundary),
        _scalars_all_result([node_a, node_b]),
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.delete_boundary(
            tm_id,
            boundary_id,
            db=db,
            current_user=FakeUser(),
        )

    assert response.status_code == 204
    assert node_a.trust_boundary_id is None
    assert node_b.trust_boundary_id is None
    db.delete.assert_awaited_once_with(boundary)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_quick_add_success_from_source_handle():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    origin_node_id = uuid.uuid4()
    new_node_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    origin_node = DFDNode(
        id=origin_node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=10,
        position_y=20,
        trust_boundary_id=None,
        properties={},
    )
    added_models = []

    def add_side_effect(model):
        added_models.append(model)
        if isinstance(model, DFDEdge) and model.id is None:
            model.id = edge_id

    db = _make_mock_db(_scalar_one_result(origin_node), add_side_effect=add_side_effect)

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.quick_add_node(
            tm_id,
            DFDQuickAddRequest(
                origin_node_id=origin_node_id,
                origin_handle="source",
                node=DFDNodeCreate(
                    id=new_node_id,
                    node_type="data_store",
                    name="User DB",
                    position_x=200,
                    position_y=20,
                ),
                edge=DFDQuickAddEdge(
                    label="query",
                    properties={
                        "protocol": "SQL",
                        "data_payload": "Customer lookup",
                        "data_classification": "Restricted",
                    },
                ),
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.node.id == new_node_id
    assert response.edge.id == edge_id
    assert response.edge.source_node_id == origin_node_id
    assert response.edge.target_node_id == new_node_id
    assert response.edge.properties.protocol == "SQL"
    assert response.edge.properties.data_payload == "Customer lookup"
    assert len(added_models) == 2
    db.commit.assert_awaited_once()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_edge_persists_semantic_properties():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    edge_id = uuid.uuid4()
    source_id = uuid.uuid4()
    target_id = uuid.uuid4()
    edge = DFDEdge(
        id=edge_id,
        threat_model_id=tm_id,
        source_node_id=source_id,
        target_node_id=target_id,
        label="HTTPS request",
        properties={},
    )
    db = _make_mock_db(_scalar_one_result(edge))

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.update_edge(
            tm_id,
            edge_id,
            DFDEdgeUpdate(
                label="OAuth token validation",
                properties={
                    "protocol": "HTTPS",
                    "data_payload": "JWT claims",
                    "data_classification": "Restricted",
                    "auth_mechanism": "mTLS",
                    "encryption_in_transit": True,
                    "directionality": "request",
                },
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.label == "OAuth token validation"
    assert response.properties.protocol == "HTTPS"
    assert response.properties.auth_mechanism == "mTLS"
    assert edge.label == "OAuth token validation"
    assert edge.properties["data_payload"] == "JWT claims"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_quick_add_success_from_target_handle():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    origin_node_id = uuid.uuid4()
    new_node_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    origin_node = DFDNode(
        id=origin_node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=10,
        position_y=20,
        trust_boundary_id=None,
        properties={},
    )

    def add_side_effect(model):
        if isinstance(model, DFDEdge) and model.id is None:
            model.id = edge_id

    db = _make_mock_db(_scalar_one_result(origin_node), add_side_effect=add_side_effect)

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.quick_add_node(
            tm_id,
            DFDQuickAddRequest(
                origin_node_id=origin_node_id,
                origin_handle="target",
                node=DFDNodeCreate(
                    id=new_node_id,
                    node_type="external_entity",
                    name="Customer",
                    position_x=-100,
                    position_y=20,
                ),
                edge=DFDQuickAddEdge(label="request"),
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.edge.id == edge_id
    assert response.edge.source_node_id == new_node_id
    assert response.edge.target_node_id == origin_node_id
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_quick_add_rolls_back_on_edge_failure():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    origin_node_id = uuid.uuid4()
    new_node_id = uuid.uuid4()
    origin_node = DFDNode(
        id=origin_node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=10,
        position_y=20,
        trust_boundary_id=None,
        properties={},
    )

    def add_side_effect(model):
        if isinstance(model, DFDEdge):
            raise RuntimeError("edge insert failed")

    db = _make_mock_db(_scalar_one_result(origin_node), add_side_effect=add_side_effect)

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        with pytest.raises(HTTPException) as exc_info:
            await dfd_api.quick_add_node(
                tm_id,
                DFDQuickAddRequest(
                    origin_node_id=origin_node_id,
                    origin_handle="source",
                    node=DFDNodeCreate(
                        id=new_node_id,
                        node_type="data_store",
                        name="User DB",
                        position_x=200,
                        position_y=20,
                    ),
                ),
                db=db,
                current_user=FakeUser(),
            )

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Failed to quick add node"
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_quick_add_preserves_boundary_membership_in_both_node_and_boundary():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    boundary_id = uuid.uuid4()
    origin_node_id = uuid.uuid4()
    new_node_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    origin_node = DFDNode(
        id=origin_node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=10,
        position_y=20,
        trust_boundary_id=boundary_id,
        properties={},
    )
    boundary = MutableBoundary(boundary_id, node_ids=[origin_node_id])

    def add_side_effect(model):
        if isinstance(model, DFDEdge) and model.id is None:
            model.id = edge_id

    db = _make_mock_db(
        _scalar_one_result(origin_node),
        _scalars_all_result([boundary]),
        add_side_effect=add_side_effect,
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        response = await dfd_api.quick_add_node(
            tm_id,
            DFDQuickAddRequest(
                origin_node_id=origin_node_id,
                origin_handle="source",
                node=DFDNodeCreate(
                    id=new_node_id,
                    node_type="process",
                    name="Worker",
                    position_x=200,
                    position_y=20,
                    trust_boundary_id=boundary_id,
                ),
                edge=DFDQuickAddEdge(label="call"),
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.node.trust_boundary_id == boundary_id
    assert boundary.node_ids == [origin_node_id, new_node_id]
    assert response.edge.id == edge_id
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_quick_add_404_for_missing_origin_node():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    db = _make_mock_db(_scalar_one_result(None))

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        with pytest.raises(HTTPException) as exc_info:
            await dfd_api.quick_add_node(
                tm_id,
                DFDQuickAddRequest(
                    origin_node_id=uuid.uuid4(),
                    origin_handle="source",
                    node=DFDNodeCreate(
                        id=uuid.uuid4(),
                        node_type="process",
                        name="Worker",
                    ),
                ),
                db=db,
                current_user=FakeUser(),
            )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Origin node not found"
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_quick_add_rejects_invalid_boundary_reference():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    boundary_id = uuid.uuid4()
    origin_node_id = uuid.uuid4()
    new_node_id = uuid.uuid4()
    origin_node = DFDNode(
        id=origin_node_id,
        threat_model_id=tm_id,
        node_type="process",
        name="API Gateway",
        position_x=10,
        position_y=20,
        trust_boundary_id=None,
        properties={},
    )
    db = _make_mock_db(
        _scalar_one_result(origin_node),
        _scalars_all_result([]),
    )

    with patch(
        "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        with pytest.raises(HTTPException) as exc_info:
            await dfd_api.quick_add_node(
                tm_id,
                DFDQuickAddRequest(
                    origin_node_id=origin_node_id,
                    origin_handle="source",
                    node=DFDNodeCreate(
                        id=new_node_id,
                        node_type="process",
                        name="Worker",
                        trust_boundary_id=boundary_id,
                    ),
                ),
                db=db,
                current_user=FakeUser(),
            )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == dfd_api.INVALID_BOUNDARY_REFERENCE
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_decomposition_view_seeds_child_graph():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    customer_id = uuid.uuid4()
    gateway_id = uuid.uuid4()
    store_id = uuid.uuid4()
    incoming_edge_id = uuid.uuid4()
    outgoing_edge_id = uuid.uuid4()
    root_dfd = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=customer_id,
                node_type="external_entity",
                name="Customer App",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=gateway_id,
                node_type="process",
                name="API Gateway",
                position_x=180,
                position_y=0,
                trust_boundary_id=None,
                properties={"runtime_type": "gateway"},
            ),
            DFDNodeResponse(
                id=store_id,
                node_type="data_store",
                name="Customer Store",
                position_x=360,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=incoming_edge_id,
                source_node_id=customer_id,
                target_node_id=gateway_id,
                label="Login request",
                properties={"protocol": "HTTPS"},
            ),
            DFDEdgeResponse(
                id=outgoing_edge_id,
                source_node_id=gateway_id,
                target_node_id=store_id,
                label="Profile lookup",
                properties={"protocol": "SQL"},
            ),
        ],
        trust_boundaries=[],
    )
    default_views = build_default_views(root_dfd)
    container_view = default_views[1]
    db = AsyncMock()

    async def fake_persist_custom_views(_db, **kwargs):
        return kwargs["views"]

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_threat_model_views_and_root_dfd",
            new_callable=AsyncMock,
            return_value=(fake_tm, root_dfd, default_views),
        ),
        patch(
            "app.api.dfd._persist_custom_views",
            new_callable=AsyncMock,
            side_effect=fake_persist_custom_views,
        ),
    ):
        response = await dfd_api.create_decomposition_view(
            tm_id,
            DFDDecompositionViewCreate(
                parent_node_id=gateway_id,
                parent_view_id=container_view.id,
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.view_type == "decomposition"
    assert response.parent_view_id == container_view.id
    assert response.parent_node_id == gateway_id
    assert response.graph is not None
    assert any(node.name == "API Gateway Internal" for node in response.graph.nodes)
    assert any(node.name == "Customer App" for node in response.graph.nodes)
    assert any(node.name == "Customer Store" for node in response.graph.nodes)
    assert len(response.graph.edges) == 2


@pytest.mark.asyncio
async def test_create_decomposition_view_for_container_seeds_runtime_graph():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    ingress_id = uuid.uuid4()
    container_id = uuid.uuid4()
    dependency_id = uuid.uuid4()
    root_dfd = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=ingress_id,
                node_type="api_gateway",
                name="Ingress Gateway",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={"runtime_type": "gateway"},
            ),
            DFDNodeResponse(
                id=container_id,
                node_type="container",
                name="Payments Pod",
                position_x=220,
                position_y=0,
                trust_boundary_id=None,
                properties={
                    "runtime_type": "container",
                    "isolation_boundary": "container",
                },
            ),
            DFDNodeResponse(
                id=dependency_id,
                node_type="managed_service",
                name="Token Service",
                position_x=460,
                position_y=0,
                trust_boundary_id=None,
                properties={"service_name": "Token Service"},
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=uuid.uuid4(),
                source_node_id=ingress_id,
                target_node_id=container_id,
                label="HTTPS ingress",
                properties={"protocol": "HTTPS"},
            ),
            DFDEdgeResponse(
                id=uuid.uuid4(),
                source_node_id=container_id,
                target_node_id=dependency_id,
                label="token lookup",
                properties={"protocol": "HTTPS"},
            ),
        ],
        trust_boundaries=[],
    )
    default_views = build_default_views(root_dfd)
    system_view = default_views[1]
    db = AsyncMock()

    async def fake_persist_custom_views(_db, **kwargs):
        return kwargs["views"]

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_threat_model_views_and_root_dfd",
            new_callable=AsyncMock,
            return_value=(fake_tm, root_dfd, default_views),
        ),
        patch(
            "app.api.dfd._persist_custom_views",
            new_callable=AsyncMock,
            side_effect=fake_persist_custom_views,
        ),
    ):
        response = await dfd_api.create_decomposition_view(
            tm_id,
            DFDDecompositionViewCreate(
                parent_node_id=container_id,
                parent_view_id=system_view.id,
            ),
            db=db,
            current_user=FakeUser(),
        )

    assert response.view_type == "decomposition"
    assert response.graph is not None
    assert any(node.name == "Payments Pod Workload" for node in response.graph.nodes)
    assert any(
        node.name == "Telemetry / Policy Sidecar" for node in response.graph.nodes
    )
    assert any(node.name == "Secrets / Config" for node in response.graph.nodes)
    assert response.graph.trust_boundaries[0].name == "Payments Pod Runtime Boundary"
    assert response.graph.trust_boundaries[0].boundary_type == "cloud"


@pytest.mark.asyncio
async def test_create_workspace_view_can_duplicate_source_view_graph():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    root_dfd = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=uuid.uuid4(),
                node_type="process",
                name="Payments API",
                position_x=120,
                position_y=80,
                trust_boundary_id=None,
                properties={},
            )
        ],
        edges=[],
        trust_boundaries=[],
    )
    default_views = build_default_views(root_dfd)
    system_view = default_views[1]

    async def fake_persist_custom_views(_db, **kwargs):
        return kwargs["views"]

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_threat_model_views_and_root_dfd",
            new_callable=AsyncMock,
            return_value=(fake_tm, root_dfd, default_views),
        ),
        patch(
            "app.api.dfd._persist_custom_views",
            new_callable=AsyncMock,
            side_effect=fake_persist_custom_views,
        ),
    ):
        response = await dfd_api.create_workspace_view(
            tm_id,
            DFDWorkspaceViewCreate(
                name="Settlement Flow", source_view_id=system_view.id
            ),
            db=AsyncMock(),
            current_user=FakeUser(),
        )

    assert response.view_type == "workspace"
    assert response.parent_view_id is None
    assert response.parent_node_id is None
    assert response.graph is not None
    assert len(response.graph.nodes) == 1
    assert response.graph.nodes[0].name == "Payments API"


@pytest.mark.asyncio
async def test_get_dfd_returns_decomposition_graph_when_view_id_is_selected():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    decomposition_view = DFDViewResponse(
        id=uuid.uuid4(),
        view_type="decomposition",
        name="API Gateway Decomposition",
        node_ids=[],
        edge_ids=[],
        boundary_ids=[],
        layout_snapshot=DFDViewLayoutSnapshot(),
        parent_view_id=uuid.uuid4(),
        parent_node_id=uuid.uuid4(),
        graph=DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=uuid.uuid4(),
                    node_type="process",
                    name="Gateway Handler",
                    position_x=120,
                    position_y=80,
                    trust_boundary_id=None,
                    properties={},
                )
            ],
            edges=[],
            trust_boundaries=[],
        ),
        is_auto_generated=False,
    )
    db = AsyncMock()

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_threat_model_views_and_root_dfd",
            new_callable=AsyncMock,
            return_value=(
                fake_tm,
                DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
                [decomposition_view],
            ),
        ),
    ):
        response = await dfd_api.get_dfd(
            tm_id,
            view_id=decomposition_view.id,
            db=db,
            current_user=FakeUser(),
        )

    assert len(response.nodes) == 1
    assert response.nodes[0].name == "Gateway Handler"


@pytest.mark.asyncio
async def test_get_dfd_returns_workspace_graph_when_view_id_is_selected():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    workspace_view = DFDViewResponse(
        id=uuid.uuid4(),
        view_type="workspace",
        name="Settlement Flow",
        node_ids=[],
        edge_ids=[],
        boundary_ids=[],
        layout_snapshot=DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=uuid.uuid4(),
                    node_type="process",
                    name="Settlement Worker",
                    position_x=120,
                    position_y=80,
                    trust_boundary_id=None,
                    properties={},
                )
            ],
            edges=[],
            trust_boundaries=[],
        ),
        is_auto_generated=False,
    )
    db = AsyncMock()

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_threat_model_views_and_root_dfd",
            new_callable=AsyncMock,
            return_value=(
                fake_tm,
                DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
                [workspace_view],
            ),
        ),
    ):
        response = await dfd_api.get_dfd(
            tm_id,
            view_id=workspace_view.id,
            db=db,
            current_user=FakeUser(),
        )

    assert len(response.nodes) == 1
    assert response.nodes[0].name == "Settlement Worker"


@pytest.mark.asyncio
async def test_bulk_save_dfd_updates_decomposition_graph_snapshot():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    decomposition_view = DFDViewResponse(
        id=uuid.uuid4(),
        view_type="decomposition",
        name="API Gateway Decomposition",
        node_ids=[],
        edge_ids=[],
        boundary_ids=[],
        layout_snapshot=DFDViewLayoutSnapshot(),
        parent_view_id=uuid.uuid4(),
        parent_node_id=uuid.uuid4(),
        graph=DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
        is_auto_generated=False,
    )
    persisted_views: dict[str, list[DFDViewResponse]] = {}
    db = AsyncMock()

    async def fake_persist_custom_views(_db, **kwargs):
        persisted_views["views"] = kwargs["views"]
        return kwargs["views"]

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_editable_view_context",
            new_callable=AsyncMock,
            return_value=(
                fake_tm,
                DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
                [decomposition_view],
                decomposition_view,
            ),
        ),
        patch(
            "app.api.dfd._persist_custom_views",
            new_callable=AsyncMock,
            side_effect=fake_persist_custom_views,
        ),
    ):
        response = await dfd_api.bulk_save_dfd(
            tm_id,
            DFDBulkSave(
                nodes=[
                    DFDNodeCreate(
                        id=uuid.uuid4(),
                        node_type="process",
                        name="Gateway Handler",
                        position_x=120,
                        position_y=80,
                    )
                ],
                edges=[],
                trust_boundaries=[
                    TrustBoundaryCreate(
                        id=uuid.uuid4(),
                        name="Privileged Zone",
                        node_ids=[],
                        position_x=80,
                        position_y=40,
                        width=260,
                        height=180,
                        boundary_type="privilege",
                    )
                ],
            ),
            view_id=decomposition_view.id,
            db=db,
            current_user=FakeUser(),
        )

    assert len(response.nodes) == 1
    assert response.nodes[0].name == "Gateway Handler"
    saved_view = persisted_views["views"][0]
    assert saved_view.graph is not None
    assert saved_view.graph.nodes[0].name == "Gateway Handler"
    assert saved_view.graph.trust_boundaries[0].boundary_type == "privilege"


@pytest.mark.asyncio
async def test_bulk_save_dfd_updates_workspace_graph_snapshot():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    workspace_view = DFDViewResponse(
        id=uuid.uuid4(),
        view_type="workspace",
        name="Settlement Flow",
        node_ids=[],
        edge_ids=[],
        boundary_ids=[],
        layout_snapshot=DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
        is_auto_generated=False,
    )
    persisted_views: dict[str, list[DFDViewResponse]] = {}

    async def fake_persist_custom_views(_db, **kwargs):
        persisted_views["views"] = kwargs["views"]
        return kwargs["views"]

    with (
        patch(
            "app.api.dfd.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
        ),
        patch(
            "app.api.dfd._load_editable_view_context",
            new_callable=AsyncMock,
            return_value=(
                fake_tm,
                DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
                [workspace_view],
                workspace_view,
            ),
        ),
        patch(
            "app.api.dfd._persist_custom_views",
            new_callable=AsyncMock,
            side_effect=fake_persist_custom_views,
        ),
    ):
        response = await dfd_api.bulk_save_dfd(
            tm_id,
            DFDBulkSave(
                nodes=[
                    DFDNodeCreate(
                        id=uuid.uuid4(),
                        node_type="process",
                        name="Settlement Worker",
                        position_x=120,
                        position_y=80,
                    )
                ],
                edges=[],
                trust_boundaries=[],
            ),
            view_id=workspace_view.id,
            db=AsyncMock(),
            current_user=FakeUser(),
        )

    assert len(response.nodes) == 1
    assert response.nodes[0].name == "Settlement Worker"
    saved_view = persisted_views["views"][0]
    assert saved_view.graph is not None
    assert saved_view.graph.nodes[0].name == "Settlement Worker"
