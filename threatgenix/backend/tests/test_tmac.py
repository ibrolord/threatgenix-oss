from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import yaml
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.assistant import AssistantResponse
from app.schemas.tmac import TMACBuiltInView, TMACBuiltInViewType, TMACDocument
from app.services.auth import get_current_user
from app.services.tmac import (
    _apply_document_scope_to_model_record,
    _built_in_view_to_raw,
    _remap_document_for_create_new,
    _scoped_document,
    build_tmac_scaffold,
    import_tmac_document,
)
from tests.evals.scenario_aurora_utility_der import AURORA_UTILITY_DER_SCENARIO

BASE_URL = "http://test"


class FakeUser:
    id = uuid.uuid4()
    email = "tmac@example.com"
    full_name = "TMAC Tester"
    role = "admin"
    is_active = True


class FakeThreatModel:
    def __init__(self, id: uuid.UUID | None = None):
        self.id = id or uuid.uuid4()
        self.system_name = "TMAC Demo"
        self.description = "Demo"
        self.data_classification = "Internal"
        self.regulatory_scope = []
        self.deployment_model = "cloud"
        self.owner_id = FakeUser.id
        self.repository_evidence = None
        self.cloud_scan_evidence = None
        self.iac_evidence = None
        self.environment_context_summary = None
        self.report_template = "default"
        self.report_watermark_text = None
        self.report_logo_base64 = None
        self.arch_diagrams = None
        self.assumptions = None
        self.model_snapshots = None
        self.review_records = None
        self.control_library = None
        self.dfd_component_templates = None
        self.dfd_property_options = None
        self.collaborators = None
        self.assignments = None
        self.notifications = None
        self.last_analyzed_threats = None
        self.dfd_views = None
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


async def override_get_db():
    yield AsyncMock()


async def override_get_current_user():
    return FakeUser()


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_validate_tmac_scaffold_route_returns_summary():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/threat-models/tmac/validate",
            json={"content": build_tmac_scaffold()},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["format"] == "yaml"
    assert body["summary"]["built_in_view_count"] == 4
    assert body["summary"]["node_count"] == 0


@pytest.mark.asyncio
async def test_validate_tmac_autofills_missing_node_positions():
    node_a = uuid.uuid4()
    node_b = uuid.uuid4()
    edge_id = uuid.uuid4()

    payload = {
        "tmac_version": "1.0",
        "metadata": {
            "system_name": "Positionless Model",
            "description": "",
            "data_classification": "Internal",
            "regulatory_scope": [],
            "deployment_model": "cloud",
        },
        "dfd": {
            "nodes": [
                {
                    "id": str(node_a),
                    "node_type": "external_entity",
                    "name": "Customer Browser",
                    "properties": {},
                },
                {
                    "id": str(node_b),
                    "node_type": "process",
                    "name": "API Gateway",
                    "properties": {},
                },
            ],
            "edges": [
                {
                    "id": str(edge_id),
                    "source_node_id": str(node_a),
                    "target_node_id": str(node_b),
                    "label": "HTTPS Request",
                    "properties": {},
                }
            ],
            "trust_boundaries": [],
        },
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post("/api/threat-models/tmac/validate", json={"content": yaml.safe_dump(payload)})

    assert response.status_code == 200
    body = response.json()
    assert body["format"] == "yaml"
    assert body["summary"]["node_count"] == 2
    assert body["warnings"] == []


@pytest.mark.asyncio
async def test_preview_import_route_returns_summary_without_target():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/threat-models/tmac/import",
            json={"content": build_tmac_scaffold(), "mode": "preview"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "preview"
    assert body["created_new"] is False
    assert body["summary"]["built_in_view_count"] == 4


@pytest.mark.asyncio
async def test_create_new_import_route_rejects_target_model_id():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/threat-models/tmac/import",
            json={
                "content": build_tmac_scaffold(),
                "mode": "create_new",
                "target_threat_model_id": str(uuid.uuid4()),
            },
        )

    assert response.status_code == 400
    assert "must not include target_threat_model_id" in response.json()["detail"]


@pytest.mark.asyncio
async def test_validate_tmac_rejects_missing_threat_node_reference():
    payload = {
        "tmac_version": "1.0",
        "metadata": {
            "system_name": "Invalid Model",
            "description": "",
            "data_classification": "Internal",
            "regulatory_scope": [],
            "deployment_model": "cloud",
            "created_at": None,
            "updated_at": None,
        },
        "evidence": {},
        "reporting": {"report_template": "default", "arch_diagrams": []},
        "dfd": {
            "nodes": [
                {
                    "id": str(uuid.uuid4()),
                    "node_type": "process",
                    "name": "API",
                    "position_x": 0,
                    "position_y": 0,
                    "trust_boundary_id": None,
                    "properties": {},
                    "security_controls": [],
                }
            ],
            "edges": [],
            "trust_boundaries": [],
        },
        "views": {"built_in_views": [], "custom_views": []},
        "threats": [
            {
                "id": str(uuid.uuid4()),
                "display_id": "T-001",
                "description": "Broken threat ref",
                "stride_category": "Spoofing",
                "severity": "High",
                "source": "Manual",
                "status": "Open",
                "ai_enhanced": False,
                "provider_managed": False,
                "affected_node_ids": [str(uuid.uuid4())],
                "affected_edge_ids": [],
                "control_effectiveness": "none",
                "created_at": "2026-04-17T00:00:00Z",
                "updated_at": "2026-04-17T00:00:00Z",
            }
        ],
        "assumptions": [],
        "controls": [],
        "component_templates": [],
        "property_options": [],
        "governance": {"model_snapshots": [], "review_records": []},
        "collaboration": {"collaborators": [], "assignments": [], "notifications": []},
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/threat-models/tmac/validate",
            json={"content": yaml.safe_dump(payload, sort_keys=False)},
        )

    assert response.status_code == 422
    body = response.json()
    assert "missing affected node ids" in str(body["detail"]).lower()


@pytest.mark.asyncio
async def test_validate_tmac_rejects_missing_component_template_reference():
    payload = {
        "tmac_version": "1.0",
        "metadata": {
            "system_name": "Invalid Template Ref",
            "description": "",
            "data_classification": "Internal",
            "regulatory_scope": [],
            "deployment_model": "cloud",
            "created_at": None,
            "updated_at": None,
        },
        "evidence": {},
        "reporting": {"report_template": "default", "arch_diagrams": []},
        "dfd": {
            "nodes": [
                {
                    "id": str(uuid.uuid4()),
                    "node_type": "process",
                    "name": "API",
                    "position_x": 0,
                    "position_y": 0,
                    "trust_boundary_id": None,
                    "properties": {"component_template_id": "missing-template"},
                    "security_controls": [],
                }
            ],
            "edges": [],
            "trust_boundaries": [],
        },
        "views": {"built_in_views": [], "custom_views": []},
        "threats": [],
        "assumptions": [],
        "controls": [],
        "component_templates": [],
        "property_options": [],
        "governance": {"model_snapshots": [], "review_records": []},
        "collaboration": {"collaborators": [], "assignments": [], "notifications": []},
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/threat-models/tmac/validate",
            json={"content": yaml.safe_dump(payload, sort_keys=False)},
        )

    assert response.status_code == 422
    body = response.json()
    assert "missing component template" in str(body["detail"]).lower()


def test_scoped_document_can_strip_operational_state_and_binary_assets():
    payload = yaml.safe_load(build_tmac_scaffold())
    snapshot_id = uuid.uuid4()
    review_id = uuid.uuid4()
    collaborator_id = uuid.uuid4()
    assignment_id = uuid.uuid4()
    payload["reporting"] = {
        "report_template": "default",
        "report_watermark_text": "Restricted",
        "report_logo_base64": "ZmFrZS1sb2dv",
        "arch_diagrams": [{"name": "Overview", "image_base64": "ZmFrZS1pbWFnZQ=="}],
    }
    payload["governance"] = {
        "model_snapshots": [
            {
                "id": str(snapshot_id),
                "name": "Approved Snapshot",
                "description": "",
                "created_at": "2026-04-17T00:00:00Z",
                "created_by": "reviewer@example.com",
                "node_count": 0,
                "edge_count": 0,
                "boundary_count": 0,
                "threat_count": 0,
                "dfd": {"nodes": [], "edges": [], "trust_boundaries": []},
                "threats": [],
            }
        ],
        "review_records": [
            {
                "id": str(review_id),
                "snapshot_id": str(snapshot_id),
                "title": "Quarterly Review",
                "status": "approved",
                "assignee": None,
                "created_by": "reviewer@example.com",
                "created_at": "2026-04-17T00:00:00Z",
                "updated_at": "2026-04-17T00:00:00Z",
                "signed_off_at": "2026-04-17T00:00:00Z",
                "comments": [],
            }
        ],
    }
    payload["collaboration"] = {
        "collaborators": [
            {
                "id": str(collaborator_id),
                "email": "editor@example.com",
                "role": "editor",
                "status": "active",
                "invited_by": "owner@example.com",
                "invited_at": "2026-04-17T00:00:00Z",
                "updated_at": "2026-04-17T00:00:00Z",
            }
        ],
        "assignments": [
            {
                "id": str(assignment_id),
                "title": "Review Threats",
                "description": "",
                "assignee": "editor@example.com",
                "priority": "medium",
                "status": "open",
                "due_date": None,
                "threat_id": None,
                "review_id": str(review_id),
                "anchor_kind": "review",
                "anchor_id": str(review_id),
                "anchor_label": "Quarterly Review",
                "created_by": "owner@example.com",
                "created_at": "2026-04-17T00:00:00Z",
                "updated_at": "2026-04-17T00:00:00Z",
                "comments": [],
            }
        ],
        "notifications": [
            {
                "id": str(uuid.uuid4()),
                "type": "assignment_created",
                "title": "Assignment created",
                "message": "Review Threats",
                "status": "unread",
                "actor": "owner@example.com",
                "target_kind": "assignment",
                "target_id": str(assignment_id),
                "created_at": "2026-04-17T00:00:00Z",
            }
        ],
    }

    document = TMACDocument.model_validate(payload)
    scoped = _scoped_document(
        document,
        include_operational_state=False,
        include_binary_assets=False,
    )

    assert scoped.reporting.report_logo_base64 is None
    assert scoped.reporting.arch_diagrams == []
    assert scoped.governance.model_snapshots == []
    assert scoped.governance.review_records == []
    assert scoped.collaboration.collaborators == []
    assert scoped.collaboration.assignments == []
    assert scoped.collaboration.notifications == []


def test_apply_document_scope_preserves_existing_non_core_state_by_default():
    payload = yaml.safe_load(build_tmac_scaffold())
    payload["reporting"] = {
        "report_template": "executive",
        "report_watermark_text": "Restricted",
        "report_logo_base64": "bmV3LWxvZ28=",
        "arch_diagrams": [{"name": "New Diagram", "image_base64": "bmV3LWltYWdl"}],
    }
    payload["governance"] = {
        "model_snapshots": [
            {
                "id": str(uuid.uuid4()),
                "name": "Snapshot",
                "description": "",
                "created_at": "2026-04-17T00:00:00Z",
                "created_by": "reviewer@example.com",
                "node_count": 0,
                "edge_count": 0,
                "boundary_count": 0,
                "threat_count": 0,
                "dfd": {"nodes": [], "edges": [], "trust_boundaries": []},
                "threats": [],
            }
        ],
        "review_records": [],
    }
    payload["collaboration"] = {
        "collaborators": [
            {
                "id": str(uuid.uuid4()),
                "email": "editor@example.com",
                "role": "editor",
                "status": "active",
                "invited_by": "owner@example.com",
                "invited_at": "2026-04-17T00:00:00Z",
                "updated_at": "2026-04-17T00:00:00Z",
            }
        ],
        "assignments": [],
        "notifications": [],
    }
    document = TMACDocument.model_validate(payload)

    existing_snapshot = {"id": str(uuid.uuid4()), "name": "Existing Snapshot"}
    threat_model = FakeThreatModel()
    threat_model.report_logo_base64 = "existing-logo"
    threat_model.arch_diagrams = [{"name": "Existing Diagram", "image_base64": "existing-diagram"}]
    threat_model.model_snapshots = [existing_snapshot]
    threat_model.review_records = [{"id": str(uuid.uuid4()), "title": "Existing Review"}]
    threat_model.collaborators = [{"id": str(uuid.uuid4()), "email": "existing@example.com"}]
    threat_model.assignments = [{"id": str(uuid.uuid4()), "title": "Existing Assignment"}]
    threat_model.notifications = [{"id": str(uuid.uuid4()), "title": "Existing Notification"}]

    warnings = _apply_document_scope_to_model_record(
        threat_model,
        document,
        apply_operational_state=False,
        apply_binary_assets=False,
    )

    assert threat_model.report_template == "executive"
    assert threat_model.report_watermark_text == "Restricted"
    assert threat_model.report_logo_base64 == "existing-logo"
    assert threat_model.arch_diagrams == [{"name": "Existing Diagram", "image_base64": "existing-diagram"}]
    assert threat_model.model_snapshots == [existing_snapshot]
    assert "Operational TMAC sections were ignored" in " ".join(warnings)
    assert "Embedded reporting assets were ignored" in " ".join(warnings)


def test_built_in_view_raw_generates_id_for_scaffold_views():
    raw = _built_in_view_to_raw(
        TMACBuiltInView(
            view_type=TMACBuiltInViewType.context,
            name="Context View",
        )
    )

    assert raw["id"] is not None


def test_create_new_remap_generates_fresh_document_ids_and_preserves_links():
    document = TMACDocument.model_validate(AURORA_UTILITY_DER_SCENARIO["tmac"])
    first = _remap_document_for_create_new(document, threat_model_id=uuid.uuid4())
    second = _remap_document_for_create_new(document, threat_model_id=uuid.uuid4())

    first_node_ids = {node.id for node in first.dfd.nodes}
    second_node_ids = {node.id for node in second.dfd.nodes}
    first_edge_ids = {edge.id for edge in first.dfd.edges}
    second_edge_ids = {edge.id for edge in second.dfd.edges}
    first_boundary_ids = {boundary.id for boundary in first.dfd.trust_boundaries}
    second_boundary_ids = {boundary.id for boundary in second.dfd.trust_boundaries}
    first_threat_ids = {threat.id for threat in first.threats}

    assert first.metadata.id != document.metadata.id
    assert second.metadata.id != document.metadata.id
    assert first_node_ids.isdisjoint(second_node_ids)
    assert first_edge_ids.isdisjoint(second_edge_ids)
    assert first_boundary_ids.isdisjoint(second_boundary_ids)

    for node in first.dfd.nodes:
        if node.trust_boundary_id is not None:
            assert node.trust_boundary_id in first_boundary_ids
    for edge in first.dfd.edges:
        assert edge.source_node_id in first_node_ids
        assert edge.target_node_id in first_node_ids
        if edge.response_to_id is not None:
            assert edge.response_to_id in first_edge_ids
    for boundary in first.dfd.trust_boundaries:
        assert set(boundary.node_ids).issubset(first_node_ids)
        if boundary.parent_boundary_id is not None:
            assert boundary.parent_boundary_id in first_boundary_ids
    for assumption in first.assumptions:
        if assumption.anchor_kind == "node":
            assert assumption.anchor_id in first_node_ids
        elif assumption.anchor_kind == "edge":
            assert assumption.anchor_id in first_edge_ids
        else:
            assert assumption.anchor_id in first_boundary_ids
    for control in first.controls:
        assert set(control.mapped_threat_ids).issubset(first_threat_ids)
    for view in first.views.custom_views:
        graph = view.graph
        assert graph is not None
        graph_node_ids = {node.id for node in graph.nodes}
        graph_edge_ids = {edge.id for edge in graph.edges}
        graph_boundary_ids = {boundary.id for boundary in graph.trust_boundaries}
        assert set(view.node_ids).issubset(graph_node_ids)
        assert set(view.edge_ids).issubset(graph_edge_ids)
        assert set(view.boundary_ids).issubset(graph_boundary_ids)
        if view.parent_node_id is not None:
            parent_graph = graph
            if view.parent_view_id is not None:
                matching_parent = next(candidate for candidate in first.views.custom_views if candidate.id == view.parent_view_id)
                assert matching_parent.graph is not None
                parent_graph = matching_parent.graph
            assert view.parent_node_id in {node.id for node in parent_graph.nodes}
    snapshot_ids = {snapshot.id for snapshot in first.governance.model_snapshots}
    review_ids = {review.id for review in first.governance.review_records}
    assignment_ids = {assignment.id for assignment in first.collaboration.assignments}
    control_ids = {control.id for control in first.controls}
    for review in first.governance.review_records:
        assert review.snapshot_id in snapshot_ids
    for assignment in first.collaboration.assignments:
        if assignment.threat_id is not None:
            assert assignment.threat_id in first_threat_ids
        if assignment.review_id is not None:
            assert assignment.review_id in review_ids
    for notification in first.collaboration.notifications:
        if notification.target_kind == "snapshot":
            assert notification.target_id in snapshot_ids
        elif notification.target_kind == "review":
            assert notification.target_id in review_ids
        elif notification.target_kind == "assignment":
            assert notification.target_id in assignment_ids
        elif notification.target_kind == "control":
            assert notification.target_id in control_ids
        elif notification.target_kind == "threat_model":
            assert notification.target_id == first.metadata.id


@pytest.mark.asyncio
async def test_create_new_import_remaps_ids_between_runs():
    content = yaml.safe_dump(AURORA_UTILITY_DER_SCENARIO["tmac"], sort_keys=False)
    added_models: list[FakeThreatModel | object] = []

    class FakeDB:
        def add(self, instance):
            added_models.append(instance)

        async def flush(self):
            for instance in added_models:
                if getattr(instance, "id", None) is None:
                    instance.id = uuid.uuid4()
            return None

        async def commit(self):
            return None

        async def refresh(self, instance):
            return None

    mock_db = FakeDB()

    captured_boundary_sets: list[set[uuid.UUID]] = []
    captured_snapshot_sets: list[set[uuid.UUID]] = []

    async def capture_root_dfd(_db, *, threat_model_id, dfd):
        captured_boundary_sets.append({boundary.id for boundary in dfd.trust_boundaries})

    async def capture_threats(_db, *, threat_model_id, threats):
        return None

    with patch("app.services.tmac._persist_root_dfd", new=AsyncMock(side_effect=capture_root_dfd)), patch(
        "app.services.tmac._persist_threats",
        new=AsyncMock(side_effect=capture_threats),
    ):
        first = await import_tmac_document(
            mock_db,
            content=content,
            mode="create_new",
            current_user_id=FakeUser.id,
            apply_operational_state=True,
        )
        first_model = added_models[-1]
        captured_snapshot_sets.append(
            {uuid.UUID(item["id"]) for item in (first_model.model_snapshots or [])}
        )
        second = await import_tmac_document(
            mock_db,
            content=content,
            mode="create_new",
            current_user_id=FakeUser.id,
            apply_operational_state=True,
        )
        second_model = added_models[-1]
        captured_snapshot_sets.append(
            {uuid.UUID(item["id"]) for item in (second_model.model_snapshots or [])}
        )

    assert first.created_new is True
    assert second.created_new is True
    assert first.threat_model_id != second.threat_model_id
    assert captured_boundary_sets[0].isdisjoint(captured_boundary_sets[1])
    assert captured_snapshot_sets[0].isdisjoint(captured_snapshot_sets[1])


@pytest.mark.asyncio
async def test_assistant_tmac_help_is_deterministic():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=threat_model_id)

    with patch("app.api.assistant.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{threat_model_id}/assistant/respond",
                json={"message": "/tmac help"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "ask"
    assert "/tmac scaffold" in body["answer"]
    assert "/tmac diff" in body["answer"]


@pytest.mark.asyncio
async def test_assistant_tmac_validate_uses_backend_validator():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=threat_model_id)

    with patch("app.api.assistant.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{threat_model_id}/assistant/respond",
                json={"message": f"/tmac validate\n{build_tmac_scaffold()}"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "ask"
    assert "TMAC is valid" in body["answer"]


@pytest.mark.asyncio
async def test_assistant_tmac_validate_returns_200_for_invalid_content():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=threat_model_id)

    with patch("app.api.assistant.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{threat_model_id}/assistant/respond",
                json={"message": "/tmac validate\nnot: [valid"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "ask"
    assert "Validation error:" in body["answer"]


@pytest.mark.asyncio
async def test_assistant_tmac_requires_exact_command_token():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=threat_model_id)

    with patch("app.api.assistant.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{threat_model_id}/assistant/respond",
                json={"message": "/tmac validates this should not parse"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "ask"
    assert "Unknown TMAC command" in body["answer"]


@pytest.mark.asyncio
async def test_assistant_route_accepts_large_tmac_editor_payloads():
    threat_model_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=threat_model_id)
    long_message = "x" * 5_000
    long_answer = "y" * 8_000

    with (
        patch(
            "app.api.assistant.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.assistant._handle_tmac_command",
            new_callable=AsyncMock,
            return_value=AssistantResponse(
                mode="build",
                answer=long_answer,
                references=[],
            ),
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{threat_model_id}/assistant/respond",
                json={"message": long_message, "mode_hint": "build"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "build"
    assert body["answer"] == long_answer
