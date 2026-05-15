import uuid
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.dfd import (
    DFDQualityGateResult,
    DFDQualityGateSummary,
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.threat_model import ArchitectureValidationSummary, ThreatModelListItem
from app.services.auth import get_current_user

BASE_URL = "http://test"
API_PREFIX = "/api/threat-models"

FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True
    organization_id = uuid.uuid4()
    organization = type(
        "FakeOrganization",
        (),
        {
            "id": organization_id,
            "name": "Test Organization",
            "subscription_tier": "enterprise",
            "is_active": True,
        },
    )()


async def override_get_db():
    """Fake DB dependency that yields a mock session."""
    yield AsyncMock()


async def override_get_current_user():
    return FakeUser()


# Override the DB dependency for all tests in this module
app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user


class FakeThreatModel:
    """A plain object that mimics ThreatModel ORM attributes for Pydantic's from_attributes."""

    def __init__(
        self,
        id: Optional[uuid.UUID] = None,
        system_name: str = "Test System",
        description: str = "A test system",
        data_classification: str = "Internal",
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.id = id or uuid.uuid4()
        self.system_name = system_name
        self.description = description
        self.data_classification = data_classification
        self.regulatory_scope = []
        self.deployment_model = None
        self.repository_evidence = None
        self.cloud_scan_evidence = None
        self.iac_evidence = None
        self.environment_context_summary = None
        self.report_template = "default"
        self.report_templates = None
        self.owner_id = FAKE_USER_ID
        self.organization_id = FakeUser.organization_id
        self.organization = None
        self.owner = None
        self.dfd_views = None
        self.assumptions = None
        self.model_snapshots = None
        self.review_records = None
        self.control_library = None
        self.collaborators = None
        self.assignments = None
        self.notifications = None
        self.created_at = created_at or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = updated_at or datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.archived_at = None


def _scalars_all_result(values):
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = values
    result = MagicMock()
    result.scalars.return_value = mock_scalars
    return result


def _scalar_one_result(value):
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    return result


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


@pytest.mark.asyncio
async def test_create_threat_model_returns_201():
    fake_tm = FakeThreatModel()
    with patch("app.api.threat_models.create_threat_model", new_callable=AsyncMock, return_value=fake_tm) as mock_create:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                API_PREFIX,
                json={
                    "system_name": "Test System",
                    "description": "A test system",
                    "data_classification": "Internal",
                },
            )
    assert response.status_code == 201
    body = response.json()
    assert body["system_name"] == "Test System"
    assert body["description"] == "A test system"
    assert body["data_classification"] == "Internal"
    assert "id" in body
    assert "created_at" in body
    assert "updated_at" in body
    mock_create.assert_awaited_once()
    assert mock_create.call_args.kwargs["owner_id"] == FAKE_USER_ID
    assert mock_create.call_args.kwargs["organization_id"] == FakeUser.organization_id


@pytest.mark.asyncio
async def test_list_threat_models_empty():
    with patch("app.api.threat_models.list_threat_models", new_callable=AsyncMock, return_value=[]) as mock_list:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(API_PREFIX)
    assert response.status_code == 200
    assert response.json() == []
    mock_list.assert_awaited_once()
    assert mock_list.call_args.kwargs["owner_id"] == FAKE_USER_ID
    assert mock_list.call_args.kwargs["organization_id"] == FakeUser.organization_id


@pytest.mark.asyncio
async def test_list_threat_models_sorted_by_updated_at_desc():
    items = [
        ThreatModelListItem(
            id=uuid.uuid4(),
            system_name="Newer",
            data_classification="Public",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            threat_count=2,
        ),
        ThreatModelListItem(
            id=uuid.uuid4(),
            system_name="Older",
            data_classification="Internal",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            threat_count=0,
        ),
    ]
    with patch("app.api.threat_models.list_threat_models", new_callable=AsyncMock, return_value=items):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(API_PREFIX)
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[0]["system_name"] == "Newer"
    assert body[1]["system_name"] == "Older"
    assert body[0]["threat_count"] == 2
    assert body[1]["threat_count"] == 0


@pytest.mark.asyncio
async def test_get_threat_model_by_id():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(tm_id)
    assert body["system_name"] == "Test System"


@pytest.mark.asyncio
async def test_archive_threat_model_sets_archive_timestamp():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    db = AsyncMock()

    async def override_archive_db():
        yield db

    app.dependency_overrides[get_db] = override_archive_db
    try:
        with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.patch(f"{API_PREFIX}/{tm_id}/archive")
    finally:
        app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(tm_id)
    assert body["archived_at"] is not None
    assert fake_tm.archived_at is not None
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(fake_tm)


@pytest.mark.asyncio
async def test_get_threat_model_with_null_report_templates_serializes_empty_list():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.report_templates = None
    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["report_templates"], list)
    assert body["report_templates"]
    assert body["report_templates"][0]["built_in"] is True


@pytest.mark.asyncio
async def test_get_threat_model_not_found():
    missing_id = uuid.uuid4()
    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=None):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{missing_id}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_create_threat_model_missing_system_name():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            API_PREFIX,
            json={
                "description": "No name",
                "data_classification": "Public",
            },
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_threat_model_invalid_data_classification():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            API_PREFIX,
            json={
                "system_name": "Test",
                "data_classification": "TopSecret",
            },
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_export_blocked_when_dfd_quality_gates_fail():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    class FakeNode:
        id = uuid.uuid4()
        node_type = "data_store"
        name = "Database"
        position_x = 0.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(
        side_effect=[
            _scalars_all_result([FakeNode()]),
            _scalars_all_result([]),
            _scalars_all_result([]),
        ]
    )

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm), patch(
        "app.api.threat_models.generate_report",
        new_callable=AsyncMock,
        return_value=b"pdf-bytes",
    ) as generate_report_mock:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{API_PREFIX}/{tm_id}/report",
                json={"threat_model_id": str(tm_id), "dfd_image_base64": ""},
            )

    assert response.status_code == 422
    assert "blocked" in str(response.json()["detail"]).lower()
    generate_report_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_list_assumptions_returns_existing_register_entries():
    tm_id = uuid.uuid4()
    assumption_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.assumptions = [
        {
            "id": str(assumption_id),
            "title": "Gateway only accepts mTLS traffic",
            "description": "Customer-facing ingress is terminated upstream.",
            "status": "open",
            "anchor_kind": "node",
            "anchor_id": str(uuid.uuid4()),
            "anchor_label": "API Gateway",
            "created_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
        }
    ]

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}/assumptions")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == str(assumption_id)
    assert body[0]["anchor_label"] == "API Gateway"


@pytest.mark.asyncio
async def test_create_assumption_validates_anchor_and_persists_register():
    tm_id = uuid.uuid4()
    anchor_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(side_effect=[_scalar_one_result(anchor_id)])
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{API_PREFIX}/{tm_id}/assumptions",
                json={
                    "title": "Public edge terminates upstream WAF controls",
                    "description": "The gateway is only reachable through the managed WAF.",
                    "status": "open",
                    "anchor_kind": "node",
                    "anchor_id": str(anchor_id),
                    "anchor_label": "API Gateway",
                },
            )

    assert response.status_code == 201
    body = response.json()
    assert body["title"] == "Public edge terminates upstream WAF controls"
    assert fake_tm.assumptions is not None
    assert len(fake_tm.assumptions) == 1
    assert fake_tm.assumptions[0]["anchor_label"] == "API Gateway"
    mock_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_assumption_reanchors_when_new_anchor_is_valid():
    tm_id = uuid.uuid4()
    old_anchor_id = uuid.uuid4()
    new_anchor_id = uuid.uuid4()
    assumption_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.assumptions = [
        {
            "id": str(assumption_id),
            "title": "Old assumption",
            "description": "Original boundary assumption.",
            "status": "open",
            "anchor_kind": "boundary",
            "anchor_id": str(old_anchor_id),
            "anchor_label": "DMZ",
            "created_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
        }
    ]
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(side_effect=[_scalar_one_result(new_anchor_id)])
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                f"{API_PREFIX}/{tm_id}/assumptions/{assumption_id}",
                json={
                    "title": "Updated assumption",
                    "anchor_kind": "node",
                    "anchor_id": str(new_anchor_id),
                    "anchor_label": "Authentication Service",
                    "status": "challenged",
                },
            )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "challenged"
    assert body["anchor_kind"] == "node"
    assert fake_tm.assumptions[0]["anchor_label"] == "Authentication Service"


@pytest.mark.asyncio
async def test_delete_assumption_removes_entry_from_register():
    tm_id = uuid.uuid4()
    assumption_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.assumptions = [
        {
            "id": str(assumption_id),
            "title": "Temporary assumption",
            "description": "",
            "status": "open",
            "anchor_kind": "edge",
            "anchor_id": str(uuid.uuid4()),
            "anchor_label": "OAuth token validation",
            "created_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
        }
    ]
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.delete(f"{API_PREFIX}/{tm_id}/assumptions/{assumption_id}")

    assert response.status_code == 204
    assert fake_tm.assumptions is None
    mock_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_scorecard_aggregates_review_and_mitigation_signals():
    tm_id = uuid.uuid4()
    gateway_id = uuid.uuid4()
    worker_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    boundary_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_records = [
        {
            "id": str(uuid.uuid4()),
            "snapshot_id": str(uuid.uuid4()),
            "title": "Security review",
            "status": "pending",
            "assignee": "reviewer@example.com",
            "created_by": "test@example.com",
            "created_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
            "signed_off_at": None,
            "comments": [],
        }
    ]
    fake_tm.control_library = [
        {
            "id": str(uuid.uuid4()),
            "title": "Gateway WAF policy",
            "description": "Managed WAF enforces request filtering.",
            "category": "preventive",
            "status": "implemented",
            "owner": "platform@example.com",
            "evidence": "Terraform module tg-waf",
            "mapped_threat_ids": [str(uuid.uuid4())],
            "updated_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
        }
    ]
    fake_tm.assumptions = [
        {
            "id": str(uuid.uuid4()),
            "title": "Ingress stays behind the managed edge",
            "description": "",
            "status": "open",
            "anchor_kind": "node",
            "anchor_id": str(gateway_id),
            "anchor_label": "API Gateway",
            "created_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Audit logs are exported daily",
            "description": "",
            "status": "validated",
            "anchor_kind": "boundary",
            "anchor_id": str(boundary_id),
            "anchor_label": "PCI Zone",
            "created_at": datetime(2026, 4, 13, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 14, tzinfo=timezone.utc).isoformat(),
        },
    ]

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm), patch(
        "app.api.threat_models.load_current_dfd",
        new_callable=AsyncMock,
        return_value=DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=gateway_id,
                    node_type="api_gateway",
                    name="API Gateway",
                    position_x=0,
                    position_y=0,
                    trust_boundary_id=boundary_id,
                    scan_target_url="https://gateway.example.com",
                    scan_target_ports=None,
                    properties={},
                    security_controls=[],
                ),
                DFDNodeResponse(
                    id=worker_id,
                    node_type="process",
                    name="Webhook Worker",
                    position_x=200,
                    position_y=0,
                    trust_boundary_id=None,
                    scan_target_url=None,
                    scan_target_ports=None,
                    properties={},
                    security_controls=[],
                ),
            ],
            edges=[
                DFDEdgeResponse(
                    id=edge_id,
                    source_node_id=gateway_id,
                    target_node_id=worker_id,
                    label="Ingress webhook",
                    properties={},
                    tls_version="tls_1_2",
                    is_response=False,
                    response_to_id=None,
                    data_objects=[],
                )
            ],
            trust_boundaries=[
                TrustBoundaryResponse(
                    id=boundary_id,
                    name="PCI Zone",
                    node_ids=[gateway_id],
                    position_x=0,
                    position_y=0,
                    width=320,
                    height=180,
                    boundary_type="regulatory",
                    parent_boundary_id=None,
                )
            ],
        ),
    ), patch(
        "app.api.threat_models.load_current_threat_snapshot",
        new_callable=AsyncMock,
        return_value=[
            {
                "id": str(uuid.uuid4()),
                "display_id": "TM-001",
                "description": "Spoofing on the public edge",
                "severity": "High",
                "stride_category": "Spoofing",
                "status": "Open",
                "mitigation_plan": None,
                "mitigation_owner": None,
                "due_date": None,
                "mitigation_notes": None,
                "control_effectiveness": "none",
                "residual_risk_level": None,
                "affected_node_ids": [str(gateway_id)],
                "affected_edge_ids": [str(edge_id)],
            },
            {
                "id": str(uuid.uuid4()),
                "display_id": "TM-002",
                "description": "Tampering on the admin plane",
                "severity": "Medium",
                "stride_category": "Tampering",
                "status": "Mitigated",
                "mitigation_plan": "Restrict privileged actions behind approval flow.",
                "mitigation_owner": "security@example.com",
                "due_date": "2026-04-30",
                "mitigation_notes": None,
                "control_effectiveness": "substantial",
                "residual_risk_level": "Low",
                "affected_node_ids": [str(worker_id)],
                "affected_edge_ids": [],
            },
        ],
    ), patch(
        "app.api.threat_models.build_architecture_validation_summary",
        new_callable=AsyncMock,
        return_value=ArchitectureValidationSummary(
            completeness_score=72,
            discovered_components=4,
            discovered_repository_components=3,
            discovered_cloud_services=1,
            modeled_components=3,
            mapped_discovered_components=2,
            latest_scan_status="completed",
            latest_scan_finding_count=3,
            correlated_scan_results=1,
            unmapped_repository_components=["Webhook Worker"],
            unmapped_cloud_services=[],
            nodes_without_scan_targets=["API Gateway"],
            unvalidated_threats=["TM-001"],
            drift_flags=[],
        ),
    ), patch(
        "app.api.threat_models.evaluate_quality_gates",
        return_value=DFDQualityGateSummary(
            blocking_count=1,
            warning_count=2,
            results=[
                DFDQualityGateResult(
                    gate_id="missing_context_view",
                    title="Missing Context View",
                    severity="block",
                    message="Add the system boundary.",
                    affected_node_ids=[],
                    affected_edge_ids=[],
                    affected_boundary_ids=[],
                )
            ],
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}/scorecard")

    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "action_required"
    assert body["assumption_summary"] == {
        "total": 2,
        "open": 1,
        "validated": 1,
        "challenged": 0,
    }
    assert body["mitigation_summary"]["active"] == 1
    assert body["mitigation_summary"]["with_plan"] == 0
    assert body["control_summary"]["implemented"] == 1
    assert body["review_summary"]["pending"] == 1
    assert body["coverage_summary"]["total_elements"] == 4
    assert body["coverage_summary"]["covered_elements"] == 4
    assert body["coverage_summary"]["missing_stride_categories"] == [
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ]
    assert body["review_freshness"]["status"] == "pending"
    assert body["collaboration_summary"]["collaborators_total"] == 0
    assert body["residual_risk_by_level"]["Low"] == 1
    assert any("blocking DFD quality gate" in action for action in body["top_actions"])
    assert any("mitigation plans" in action for action in body["top_actions"])
    assert any("missing STRIDE categories" in action for action in body["top_actions"])


@pytest.mark.asyncio
async def test_get_scorecard_marks_approved_review_as_stale_after_model_changes():
    tm_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    gateway_id = uuid.uuid4()
    auth_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.model_snapshots = [
        {
            "id": str(snapshot_id),
            "name": "Approved Baseline",
            "description": "Initial sign-off",
            "created_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
            "created_by": "architect@example.com",
            "node_count": 1,
            "edge_count": 0,
            "boundary_count": 0,
            "threat_count": 1,
            "dfd": {
                "nodes": [{"id": str(gateway_id), "name": "API Gateway"}],
                "edges": [],
                "trust_boundaries": [],
            },
            "threats": [{"display_id": "TM-001"}],
        }
    ]
    fake_tm.review_records = [
        {
            "id": str(uuid.uuid4()),
            "snapshot_id": str(snapshot_id),
            "title": "Architecture sign-off",
            "status": "approved",
            "assignee": "reviewer@example.com",
            "created_by": "test@example.com",
            "created_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 11, tzinfo=timezone.utc).isoformat(),
            "signed_off_at": datetime(2026, 4, 11, tzinfo=timezone.utc).isoformat(),
            "comments": [],
        }
    ]

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm), patch(
        "app.api.threat_models.load_current_dfd",
        new_callable=AsyncMock,
        return_value=DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=gateway_id,
                    node_type="api_gateway",
                    name="API Gateway",
                    position_x=0,
                    position_y=0,
                    trust_boundary_id=None,
                    scan_target_url="https://gateway.example.com",
                    scan_target_ports=None,
                    properties={},
                    security_controls=[],
                ),
                DFDNodeResponse(
                    id=auth_id,
                    node_type="process",
                    name="Auth Service",
                    position_x=200,
                    position_y=0,
                    trust_boundary_id=None,
                    scan_target_url=None,
                    scan_target_ports=None,
                    properties={},
                    security_controls=[],
                ),
            ],
            edges=[],
            trust_boundaries=[],
        ),
    ), patch(
        "app.api.threat_models.load_current_threat_snapshot",
        new_callable=AsyncMock,
        return_value=[
            {
                "id": str(uuid.uuid4()),
                "display_id": "TM-001",
                "description": "Spoofing on the public edge",
                "severity": "High",
                "stride_category": "Spoofing",
                "status": "Mitigated",
                "mitigation_plan": "Protected behind WAF and mTLS.",
                "mitigation_owner": "security@example.com",
                "due_date": "2026-04-15",
                "mitigation_notes": None,
                "control_effectiveness": "substantial",
                "residual_risk_level": "Low",
                "affected_node_ids": [str(gateway_id)],
                "affected_edge_ids": [],
            },
            {
                "id": str(uuid.uuid4()),
                "display_id": "TM-002",
                "description": "Elevation via new auth path",
                "severity": "High",
                "stride_category": "Elevation of Privilege",
                "status": "Open",
                "mitigation_plan": None,
                "mitigation_owner": None,
                "due_date": None,
                "mitigation_notes": None,
                "control_effectiveness": "none",
                "residual_risk_level": None,
                "affected_node_ids": [str(auth_id)],
                "affected_edge_ids": [],
            },
        ],
    ), patch(
        "app.api.threat_models.build_architecture_validation_summary",
        new_callable=AsyncMock,
        return_value=ArchitectureValidationSummary(
            completeness_score=96,
            discovered_components=2,
            modeled_components=2,
            mapped_discovered_components=2,
            latest_scan_status="completed",
            latest_scan_finding_count=1,
            correlated_scan_results=1,
            unmapped_repository_components=[],
            unmapped_cloud_services=[],
            nodes_without_scan_targets=[],
            unvalidated_threats=[],
            drift_flags=[],
        ),
    ), patch(
        "app.api.threat_models.evaluate_quality_gates",
        return_value=DFDQualityGateSummary(blocking_count=0, warning_count=0, results=[]),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}/scorecard")

    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "action_required"
    assert body["review_freshness"]["status"] == "stale"
    assert body["review_freshness"]["reviewed_snapshot_name"] == "Approved Baseline"
    assert body["review_freshness"]["changes_since_review"]["node_delta"] == 1
    assert body["review_freshness"]["changes_since_review"]["threat_delta"] == 1
    assert "no longer matches" in body["overall_summary"].lower()
    assert any("changed after the last approved snapshot" in action for action in body["top_actions"])


@pytest.mark.asyncio
async def test_list_model_versions_returns_snapshots():
    tm_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.model_snapshots = [
        {
            "id": str(snapshot_id),
            "name": "Baseline",
            "description": "Initial approved model",
            "created_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
            "created_by": "architect@example.com",
            "node_count": 6,
            "edge_count": 5,
            "boundary_count": 2,
            "threat_count": 8,
        }
    ]

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}/versions")

    assert response.status_code == 200
    body = response.json()
    assert body[0]["id"] == str(snapshot_id)
    assert body[0]["name"] == "Baseline"


@pytest.mark.asyncio
async def test_create_model_version_persists_snapshot_record():
    tm_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    snapshot_payload = {
        "id": str(snapshot_id),
        "name": "Post hardening",
        "description": "Added admin isolation",
        "created_at": datetime(2026, 4, 16, tzinfo=timezone.utc).isoformat(),
        "created_by": "test@example.com",
        "node_count": 8,
        "edge_count": 7,
        "boundary_count": 3,
        "threat_count": 11,
        "dfd": {"nodes": [], "edges": [], "trust_boundaries": []},
        "threats": [],
    }

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm), patch(
        "app.api.threat_models.build_snapshot_record",
        new_callable=AsyncMock,
        return_value=snapshot_payload,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{API_PREFIX}/{tm_id}/versions",
                json={"name": "Post hardening", "description": "Added admin isolation"},
            )

    assert response.status_code == 201
    assert fake_tm.model_snapshots is not None
    assert fake_tm.model_snapshots[0]["name"] == "Post hardening"
    mock_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_diff_model_versions_compares_snapshot_pairs():
    tm_id = uuid.uuid4()
    left_id = uuid.uuid4()
    right_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.model_snapshots = [
        {
            "id": str(left_id),
            "name": "Baseline",
            "description": "",
            "created_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
            "created_by": "test@example.com",
            "node_count": 2,
            "edge_count": 1,
            "boundary_count": 1,
            "threat_count": 1,
            "dfd": {"nodes": [{"name": "API Gateway"}], "edges": [], "trust_boundaries": []},
            "threats": [{"display_id": "TM-001"}],
        },
        {
            "id": str(right_id),
            "name": "Current",
            "description": "",
            "created_at": datetime(2026, 4, 11, tzinfo=timezone.utc).isoformat(),
            "created_by": "test@example.com",
            "node_count": 3,
            "edge_count": 2,
            "boundary_count": 1,
            "threat_count": 2,
            "dfd": {"nodes": [{"name": "API Gateway"}, {"name": "Auth Service"}], "edges": [], "trust_boundaries": []},
            "threats": [{"display_id": "TM-001"}, {"display_id": "TM-002"}],
        },
    ]

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{API_PREFIX}/{tm_id}/versions/diff",
                json={"left_snapshot_id": str(left_id), "right_snapshot_id": str(right_id)},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["node_delta"] == 1
    assert "Auth Service" in body["added_nodes"]
    assert "TM-002" in body["added_threats"]


@pytest.mark.asyncio
async def test_create_and_update_model_review_tracks_comments_and_signoff():
    tm_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    review_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.model_snapshots = [
        {
            "id": str(snapshot_id),
            "name": "Baseline",
            "description": "",
            "created_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
            "created_by": "test@example.com",
            "node_count": 2,
            "edge_count": 1,
            "boundary_count": 1,
            "threat_count": 1,
        }
    ]
    fake_tm.review_records = [
        {
            "id": str(review_id),
            "snapshot_id": str(snapshot_id),
            "title": "Architecture sign-off",
            "status": "pending",
            "assignee": "reviewer@example.com",
            "created_by": "test@example.com",
            "created_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
            "signed_off_at": None,
            "comments": [],
        }
    ]
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            create_response = await client.post(
                f"{API_PREFIX}/{tm_id}/reviews",
                json={
                    "snapshot_id": str(snapshot_id),
                    "title": "Security review",
                    "assignee": "security@example.com",
                },
            )
            update_response = await client.patch(
                f"{API_PREFIX}/{tm_id}/reviews/{review_id}",
                json={"status": "approved", "comment": "Ready to ship."},
            )

    assert create_response.status_code == 201
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["status"] == "approved"
    assert updated["signed_off_at"] is not None
    assert updated["comments"][0]["comment"] == "Ready to ship."
    assert mock_db.commit.await_count == 2


@pytest.mark.asyncio
async def test_control_library_crud_updates_model_state():
    tm_id = uuid.uuid4()
    control_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.control_library = [
        {
            "id": str(control_id),
            "title": "WAF policy",
            "description": "Managed edge control.",
            "category": "preventive",
            "status": "planned",
            "owner": "platform@example.com",
            "evidence": None,
            "mapped_threat_ids": [],
            "updated_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
        }
    ]
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            create_response = await client.post(
                f"{API_PREFIX}/{tm_id}/controls",
                json={
                    "title": "mTLS enforcement",
                    "description": "Require mutual TLS on service links.",
                    "category": "preventive",
                    "status": "implemented",
                },
            )
            update_response = await client.patch(
                f"{API_PREFIX}/{tm_id}/controls/{control_id}",
                json={"status": "partial", "owner": "security@example.com"},
            )
            delete_response = await client.delete(f"{API_PREFIX}/{tm_id}/controls/{control_id}")

    assert create_response.status_code == 201
    assert update_response.status_code == 200
    assert update_response.json()["status"] == "partial"
    assert delete_response.status_code == 204
    assert fake_tm.control_library is not None
    assert len(fake_tm.control_library) == 1
    assert mock_db.commit.await_count == 3


@pytest.mark.asyncio
async def test_collaborator_and_assignment_workflow_persists_records():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.model_snapshots = []
    fake_tm.review_records = []
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            collaborator_response = await client.post(
                f"{API_PREFIX}/{tm_id}/collaborators",
                json={"email": "reviewer@example.com", "role": "reviewer"},
            )
            assignment_response = await client.post(
                f"{API_PREFIX}/{tm_id}/assignments",
                json={
                    "title": "Validate ingress controls",
                    "description": "Confirm the edge matches the WAF design.",
                    "assignee": "reviewer@example.com",
                    "priority": "high",
                },
            )

    assert collaborator_response.status_code == 201
    assert assignment_response.status_code == 201
    assert fake_tm.collaborators is not None
    assert fake_tm.assignments is not None
    assert fake_tm.notifications is not None
    assert fake_tm.collaborators[0]["email"] == "reviewer@example.com"
    assert fake_tm.assignments[0]["title"] == "Validate ingress controls"
    assert fake_tm.notifications[0]["type"] == "assignment_created"


@pytest.mark.asyncio
async def test_update_assignment_and_notification_roundtrip():
    tm_id = uuid.uuid4()
    assignment_id = uuid.uuid4()
    notification_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.assignments = [
        {
            "id": str(assignment_id),
            "title": "Verify scan coverage",
            "description": "",
            "assignee": "analyst@example.com",
            "priority": "medium",
            "status": "open",
            "due_date": None,
            "threat_id": None,
            "review_id": None,
            "anchor_kind": None,
            "anchor_id": None,
            "anchor_label": None,
            "created_by": "test@example.com",
            "created_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
            "updated_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
            "comments": [],
        }
    ]
    fake_tm.notifications = [
        {
            "id": str(notification_id),
            "type": "review_requested",
            "title": "Review opened",
            "message": "A new review is pending.",
            "status": "unread",
            "actor": "test@example.com",
            "target_kind": "review",
            "target_id": None,
            "created_at": datetime(2026, 4, 15, tzinfo=timezone.utc).isoformat(),
        }
    ]
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            assignment_response = await client.patch(
                f"{API_PREFIX}/{tm_id}/assignments/{assignment_id}",
                json={"status": "done", "comment": "Coverage is complete."},
            )
            notification_response = await client.patch(
                f"{API_PREFIX}/{tm_id}/notifications/{notification_id}",
                json={"status": "read"},
            )

    assert assignment_response.status_code == 200
    assert notification_response.status_code == 200
    assert assignment_response.json()["status"] == "done"
    assert assignment_response.json()["comments"][0]["comment"] == "Coverage is complete."
    assert notification_response.json()["status"] == "read"


@pytest.mark.asyncio
async def test_attack_paths_endpoint_returns_derived_paths():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    ingress_id = uuid.uuid4()
    target_id = uuid.uuid4()

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm), patch(
        "app.api.threat_models.load_current_dfd",
        new_callable=AsyncMock,
        return_value=DFDResponse(
            nodes=[
                {
                    "id": str(ingress_id),
                    "node_type": "external_entity",
                    "name": "Internet",
                    "position_x": 0,
                    "position_y": 0,
                    "trust_boundary_id": None,
                    "properties": {},
                },
                {
                    "id": str(target_id),
                    "node_type": "data_store",
                    "name": "Customer Database",
                    "position_x": 1,
                    "position_y": 1,
                    "trust_boundary_id": None,
                    "properties": {"data_classification": "Restricted"},
                },
            ],
            edges=[
                {
                    "id": str(uuid.uuid4()),
                    "source_node_id": str(ingress_id),
                    "target_node_id": str(target_id),
                    "label": "Direct data path",
                    "properties": {},
                }
            ],
            trust_boundaries=[],
        ),
    ), patch(
        "app.api.threat_models.load_current_threat_snapshot",
        new_callable=AsyncMock,
        return_value=[
            {
                "id": str(uuid.uuid4()),
                "display_id": "TM-050",
                "description": "Information disclosure over public path",
                "severity": "High",
                "stride_category": "Information Disclosure",
                "affected_node_ids": [str(target_id)],
                "affected_edge_ids": [],
            }
        ],
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}/attack-paths")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["title"] == "Internet to Customer Database"
    assert body[0]["supporting_threats"][0]["display_id"] == "TM-050"


@pytest.mark.asyncio
async def test_get_validation_summary_returns_architecture_gaps():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    with patch("app.api.threat_models.get_threat_model", new_callable=AsyncMock, return_value=fake_tm), patch(
        "app.api.threat_models.build_architecture_validation_summary",
        new_callable=AsyncMock,
        return_value=ArchitectureValidationSummary(
            completeness_score=68,
            discovered_components=7,
            discovered_repository_components=4,
            discovered_cloud_services=3,
            modeled_components=5,
            mapped_discovered_components=4,
            latest_scan_status="completed",
            latest_scan_finding_count=5,
            correlated_scan_results=3,
            unmapped_repository_components=["Async Worker"],
            unmapped_cloud_services=["Public S3 bucket"],
            nodes_without_scan_targets=["API Gateway"],
            unvalidated_threats=["TM-007"],
            drift_flags=["Cloud exposure: public-admin-endpoint"],
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{API_PREFIX}/{tm_id}/validation-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["completeness_score"] == 68
    assert body["discovered_repository_components"] == 4
    assert body["discovered_cloud_services"] == 3
    assert body["unmapped_repository_components"] == ["Async Worker"]
    assert body["drift_flags"] == ["Cloud exposure: public-admin-endpoint"]


@pytest.mark.asyncio
async def test_list_threat_models_includes_open_count():
    """Models with threats should return open_count and has_been_analyzed=True."""
    items = [
        ThreatModelListItem(
            id=uuid.uuid4(),
            system_name="Analyzed System",
            data_classification="Confidential",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            threat_count=3,
            open_count=2,
            has_been_analyzed=True,
        ),
    ]
    with patch("app.api.threat_models.list_threat_models", new_callable=AsyncMock, return_value=items):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(API_PREFIX)
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["threat_count"] == 3
    assert body[0]["open_count"] == 2
    assert body[0]["has_been_analyzed"] is True


@pytest.mark.asyncio
async def test_list_threat_models_unanalyzed_model():
    """Models with no threats should return open_count=0 and has_been_analyzed=False."""
    items = [
        ThreatModelListItem(
            id=uuid.uuid4(),
            system_name="New System",
            data_classification="Public",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            threat_count=0,
            open_count=0,
            has_been_analyzed=False,
        ),
    ]
    with patch("app.api.threat_models.list_threat_models", new_callable=AsyncMock, return_value=items):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(API_PREFIX)
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["threat_count"] == 0
    assert body[0]["open_count"] == 0
    assert body[0]["has_been_analyzed"] is False
