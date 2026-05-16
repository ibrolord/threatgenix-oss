"""E2E Demo Flow Smoke Test -- exercises the full Priya demo script via FastAPI TestClient.

"Upload doc -> see DFD -> edit it -> generate threats -> see compliance -> export CSV."

Uses AsyncClient + ASGITransport (no DB, all mocked) to verify every API contract
in the demo path works end-to-end at the HTTP layer.
"""

import io
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.document import (
    DocumentParseResult,
    ExtractionOutcome,
    ParsedBoundary,
    ParsedComponent,
    ParsedFlow,
)
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.services.auth import get_current_user

BASE_URL = "http://test"

FAKE_USER_ID = uuid.uuid4()
FAKE_TM_ID = uuid.uuid4()
FAKE_DOC_ID = uuid.uuid4()
FAKE_THREAT_ID = uuid.uuid4()
FAKE_NODE_ID_1 = uuid.uuid4()
FAKE_NODE_ID_2 = uuid.uuid4()
FAKE_EDGE_ID = uuid.uuid4()
FAKE_BOUNDARY_ID = uuid.uuid4()
FAKE_AUDIT_ID = uuid.uuid4()


# ─── Fake objects ─────────────────────────────────────────────────────

class FakeUser:
    id = FAKE_USER_ID
    email = "priya@example.test"
    full_name = "Priya Demo"
    role = "admin"
    is_active = True
    hashed_password = "$2b$12$fakehash"


class FakeThreatModel:
    def __init__(self, id=None):
        self.id = id or FAKE_TM_ID
        self.system_name = "Northstar Bank Mobile Banking App"
        self.description = "Personal banking, e-Transfer, bill payments"
        self.data_classification = "Confidential"
        self.owner_id = FAKE_USER_ID
        self.regulatory_scope = []
        self.deployment_model = None
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


class FakeNode:
    def __init__(self, id, node_type, name, px=0.0, py=0.0, tb_id=None):
        self.id = id
        self.node_type = node_type
        self.name = name
        self.position_x = px
        self.position_y = py
        self.trust_boundary_id = tb_id
        self.properties = {}
        self.threat_model_id = FAKE_TM_ID


class FakeEdge:
    def __init__(self, id, src, tgt, label="data flow"):
        self.id = id
        self.source_node_id = src
        self.target_node_id = tgt
        self.label = label
        self.properties = {}
        self.threat_model_id = FAKE_TM_ID


class FakeBoundary:
    def __init__(self, id, name, node_ids):
        self.id = id
        self.name = name
        self.node_ids = node_ids
        self.threat_model_id = FAKE_TM_ID


class FakeThreat:
    def __init__(self, id, display_id, stride, severity, status="Open"):
        self.id = id
        self.display_id = display_id
        self.description = f"Threat {display_id}: {stride} risk"
        self.stride_category = stride
        self.threat_subtype = "Identity Spoofing" if stride == "Spoofing" else None
        self.severity = severity
        self.source = "Rules"
        self.status = status
        self.dismiss_reason = None
        self.rule_id = "S-01"
        self.ai_enhanced = False
        self.original_rule_threat_id = None
        self.affected_node_ids = [FAKE_NODE_ID_1]
        self.affected_edge_ids = []
        self.relevance_rationale = None
        self.mitigation_owner = None
        self.mitigation_status = None
        self.mitigation_notes = None
        self.mitigation_due = None
        self.closed_at = None
        self.created_at = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.threat_model_id = FAKE_TM_ID


class FakeComplianceMapping:
    _counter = 0

    def __init__(self, stride, subtype, control_id, control_name, framework="NIST 800-53"):
        FakeComplianceMapping._counter += 1
        self.id = FakeComplianceMapping._counter
        self.stride_category = stride
        self.threat_subtype = subtype
        self.nist_control_id = control_id
        self.nist_control_name = control_name
        self.control_id = control_id
        self.control_name = control_name
        self.framework = framework


class FakeIntelSync:
    def __init__(self, source, status="complete"):
        self.source = source
        self.status = status
        self.last_synced_at = datetime(2026, 3, 15, tzinfo=timezone.utc)
        self.record_count = 100


# ─── Dependency overrides ────────────────────────────────────────────

async def override_get_current_user():
    return FakeUser()


# ─── Helpers ─────────────────────────────────────────────────────────

def _make_simple_pdf_bytes() -> bytes:
    import fitz
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Northstar Bank Mobile Banking App architecture document.")
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def _make_fake_parse_result() -> DocumentParseResult:
    return DocumentParseResult(
        components=[
            ParsedComponent(name="API Gateway", component_type="process", confidence=0.9, description="Gateway"),
            ParsedComponent(name="User DB", component_type="data_store", confidence=0.85, description="Database"),
        ],
        flows=[
            ParsedFlow(source="API Gateway", target="User DB", label="query", confidence=0.8),
        ],
        boundaries=[
            ParsedBoundary(name="DMZ", contains=["API Gateway"]),
        ],
        raw_text_excerpt="Northstar Bank Mobile Banking App...",
    )


def _make_rule_engine_output() -> RuleEngineOutput:
    return RuleEngineOutput(
        threats=[
            GeneratedThreat(
                rule_id="S-01",
                display_id="T-001",
                stride_category="Spoofing",
                threat_subtype="Identity Spoofing",
                severity="High",
                description="An attacker may spoof the API Gateway.",
                affected_node_ids=[str(FAKE_NODE_ID_1)],
                affected_edge_ids=[],
                source="Rules",
            ),
            GeneratedThreat(
                rule_id="T-01",
                display_id="T-002",
                stride_category="Tampering",
                threat_subtype="Data Tampering",
                severity="Critical",
                description="An attacker may tamper with data in transit.",
                affected_node_ids=[str(FAKE_NODE_ID_2)],
                affected_edge_ids=[str(FAKE_EDGE_ID)],
                source="Rules",
            ),
        ],
        execution_time_ms=2.5,
        rules_evaluated=15,
        rules_fired=2,
    )


# ─── The Smoke Test ─────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_overrides():
    """Ensure app.dependency_overrides is clean before and after each test."""
    saved = dict(app.dependency_overrides)
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


@pytest.mark.asyncio
class TestDemoFlowSmoke:
    """Full demo flow: register -> login -> create model -> upload PDF -> DFD ->
    edit DFD -> generate threats -> list threats -> triage -> compliance -> summary -> threat intel."""

    async def test_step_01_health_check(self):
        """Step 0: Health check works."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            resp = await client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"

    async def test_step_02_register_user(self):
        """Step 1: Register a new user -> 201."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # no existing user
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock(side_effect=lambda obj: setattr(obj, "id", FAKE_USER_ID))

        async def mock_refresh(obj):
            obj.id = FAKE_USER_ID
            obj.email = "priya@example.test"
            obj.full_name = "Priya Demo"
            obj.role = "analyst"
            obj.is_active = True
            obj.email_verified = False
        mock_db.refresh = mock_refresh
        mock_db.flush = AsyncMock()

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                resp = await client.post("/api/auth/register", json={
                    "email": "priya@example.test",
                    "password": "SecureP@ss123",
                    "full_name": "Priya Demo",
                })
            assert resp.status_code == 201, f"Register failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["email"] == "priya@example.test"
            assert "id" in body
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_03_login_user(self):
        """Step 2: Login -> get JWT token."""
        fake_user = FakeUser()
        from app.services.auth import hash_password
        fake_user.hashed_password = hash_password("SecureP@ss123")

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fake_user
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                resp = await client.post("/api/auth/login", json={
                    "email": "priya@example.test",
                    "password": "SecureP@ss123",
                })
            assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert "access_token" in body
            assert body["token_type"] == "bearer"
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_04_create_threat_model(self):
        """Step 3: Create a threat model -> 201."""
        fake_tm = FakeThreatModel()
        app.dependency_overrides[get_current_user] = override_get_current_user

        with patch("app.api.threat_models.create_threat_model", new_callable=AsyncMock, return_value=fake_tm):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                resp = await client.post("/api/threat-models", json={
                    "system_name": "Northstar Bank Mobile Banking App",
                    "description": "Personal banking, e-Transfer, bill payments",
                    "data_classification": "Confidential",
                })
        assert resp.status_code == 201, f"Create model failed: {resp.status_code} {resp.text}"
        body = resp.json()
        assert body["system_name"] == "Northstar Bank Mobile Banking App"
        assert body["data_classification"] == "Confidential"

    async def test_step_05_upload_document(self):
        """Step 4: Upload a PDF document -> 201 with parsed components."""
        app.dependency_overrides[get_current_user] = override_get_current_user
        fake_tm = FakeThreatModel()
        fake_parse = _make_fake_parse_result()
        fake_extraction = ExtractionOutcome(parse_result=fake_parse)
        pdf_bytes = _make_simple_pdf_bytes()

        mock_db = AsyncMock()
        mock_db.add = MagicMock(side_effect=lambda obj: setattr(obj, "id", FAKE_DOC_ID))

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.documents.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch(
                    "app.api.documents.get_llm_client_for_user_async",
                    new_callable=AsyncMock,
                    return_value=object(),
                ),
                patch("app.api.documents.parse_uploaded_document", new_callable=AsyncMock, return_value=MagicMock(
                    file_bytes=pdf_bytes,
                    filename="banking_app.pdf",
                    file_kind="pdf",
                    page_count=3,
                    raw_text="Northstar Bank Mobile Banking App architecture",
                    diagram_pages=[],
                    diagram_artifacts=[],
                    diagram_parse_result=DocumentParseResult(components=[], flows=[], boundaries=[]),
                )),
                patch("app.api.documents.extract_components_from_text", new_callable=AsyncMock, return_value=fake_extraction),
                patch("app.api.documents.generate_dfd_from_parse_result", new_callable=AsyncMock),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.post(
                        f"/api/threat-models/{FAKE_TM_ID}/documents",
                        files={"file": ("banking_app.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
                    )
            assert resp.status_code == 201, f"Upload failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["page_count"] == 3
            assert len(body["parse_result"]["components"]) == 2
            assert len(body["parse_result"]["flows"]) == 1
            assert len(body["parse_result"]["boundaries"]) == 1
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_06_get_dfd(self):
        """Step 5: View DFD -> nodes, edges, trust boundaries."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        nodes = [
            FakeNode(FAKE_NODE_ID_1, "process", "API Gateway", 100.0, 200.0),
            FakeNode(FAKE_NODE_ID_2, "data_store", "User DB", 300.0, 200.0),
        ]
        edges = [FakeEdge(FAKE_EDGE_ID, FAKE_NODE_ID_1, FAKE_NODE_ID_2, "query")]
        boundaries = [FakeBoundary(FAKE_BOUNDARY_ID, "DMZ", [FAKE_NODE_ID_1])]

        call_count = 0

        async def mock_execute(stmt, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_scalars = MagicMock()
            if call_count == 1:
                mock_scalars.all.return_value = nodes
            elif call_count == 2:
                mock_scalars.all.return_value = edges
            else:
                mock_scalars.all.return_value = boundaries
            mock_result = MagicMock()
            mock_result.scalars.return_value = mock_scalars
            return mock_result

        mock_db = AsyncMock()
        mock_db.execute = mock_execute

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with patch("app.api.dfd._verify_threat_model", new_callable=AsyncMock):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.get(f"/api/threat-models/{FAKE_TM_ID}/dfd")
            assert resp.status_code == 200, f"Get DFD failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert len(body["nodes"]) == 2
            assert len(body["edges"]) == 1
            assert len(body["trust_boundaries"]) == 1
            # Check nodes have different positions (layout engine working)
            positions = [(n["position_x"], n["position_y"]) for n in body["nodes"]]
            assert len(set(positions)) > 1, "Layout broken: all nodes at same position"
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_07_edit_dfd_add_node(self):
        """Step 6a: Edit DFD -> add a new node."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        new_node_id = uuid.uuid4()
        mock_db = AsyncMock()
        mock_db.add = MagicMock(side_effect=lambda obj: setattr(obj, "id", new_node_id))

        async def mock_refresh(obj):
            obj.id = new_node_id
            obj.threat_model_id = FAKE_TM_ID
            obj.node_type = "external_entity"
            obj.name = "Interac e-Transfer Gateway"
            obj.position_x = 500.0
            obj.position_y = 300.0
            obj.trust_boundary_id = None
            obj.properties = {}
        mock_db.refresh = mock_refresh

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with patch("app.api.dfd._verify_threat_model", new_callable=AsyncMock):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.post(
                        f"/api/threat-models/{FAKE_TM_ID}/dfd/nodes",
                        json={
                            "node_type": "external_entity",
                            "name": "Interac e-Transfer Gateway",
                            "position_x": 500.0,
                            "position_y": 300.0,
                        },
                    )
            assert resp.status_code == 201, f"Create node failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["name"] == "Interac e-Transfer Gateway"
            assert body["node_type"] == "external_entity"
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_08_edit_dfd_rename_node(self):
        """Step 6b: Edit DFD -> rename a node (inline editing)."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        existing_node = FakeNode(FAKE_NODE_ID_1, "process", "API Gateway", 100.0, 200.0)

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_node
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def mock_refresh(obj):
            obj.name = "Payment API Gateway"
        mock_db.refresh = mock_refresh

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with patch("app.api.dfd._verify_threat_model", new_callable=AsyncMock):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.patch(
                        f"/api/threat-models/{FAKE_TM_ID}/dfd/nodes/{FAKE_NODE_ID_1}",
                        json={"name": "Payment API Gateway"},
                    )
            assert resp.status_code == 200, f"Rename node failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["name"] == "Payment API Gateway"
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_09_edit_dfd_add_edge(self):
        """Step 6c: Edit DFD -> add an edge between nodes."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        new_edge_id = uuid.uuid4()
        mock_db = AsyncMock()
        mock_db.add = MagicMock(side_effect=lambda obj: setattr(obj, "id", new_edge_id))

        async def mock_refresh(obj):
            obj.id = new_edge_id
            obj.threat_model_id = FAKE_TM_ID
            obj.source_node_id = FAKE_NODE_ID_1
            obj.target_node_id = FAKE_NODE_ID_2
            obj.label = "payment routing"
            obj.properties = {}
        mock_db.refresh = mock_refresh

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with patch("app.api.dfd._verify_threat_model", new_callable=AsyncMock):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.post(
                        f"/api/threat-models/{FAKE_TM_ID}/dfd/edges",
                        json={
                            "source_node_id": str(FAKE_NODE_ID_1),
                            "target_node_id": str(FAKE_NODE_ID_2),
                            "label": "payment routing",
                        },
                    )
            assert resp.status_code == 201, f"Create edge failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["label"] == "payment routing"
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_10_generate_threats(self):
        """Step 7: Generate threats via rules engine -> non-empty list."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        nodes = [
            FakeNode(FAKE_NODE_ID_1, "process", "API Gateway"),
            FakeNode(FAKE_NODE_ID_2, "data_store", "User DB"),
        ]
        edges = [FakeEdge(FAKE_EDGE_ID, FAKE_NODE_ID_1, FAKE_NODE_ID_2)]
        boundaries = [FakeBoundary(FAKE_BOUNDARY_ID, "DMZ", [FAKE_NODE_ID_1])]
        fake_output = _make_rule_engine_output()

        call_count = 0

        async def mock_execute(stmt, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_scalars = MagicMock()
            if call_count == 1:
                mock_scalars.all.return_value = nodes
            elif call_count == 2:
                mock_scalars.all.return_value = edges
            else:
                mock_scalars.all.return_value = boundaries
            mock_result = MagicMock()
            mock_result.scalars.return_value = mock_scalars
            return mock_result

        mock_db = AsyncMock()
        mock_db.execute = mock_execute
        mock_db.add = MagicMock()

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch("app.api.threats.evaluate_rules", return_value=fake_output),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.post(f"/api/threat-models/{FAKE_TM_ID}/threats/generate")
            assert resp.status_code == 200, f"Generate threats failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert len(body["threats"]) == 2
            assert body["rules_evaluated"] == 15
            assert body["rules_fired"] == 2
            # Verify STRIDE categories
            categories = {t["stride_category"] for t in body["threats"]}
            assert "Spoofing" in categories
            assert "Tampering" in categories
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)

    async def test_step_11_list_threats(self):
        """Step 8: List threats -> returns generated threats with compliance controls."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        threats = [
            FakeThreat(FAKE_THREAT_ID, "T-001", "Spoofing", "High"),
            FakeThreat(uuid.uuid4(), "T-002", "Tampering", "Critical"),
        ]

        mock_db = AsyncMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = threats
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch("app.api.threats.lookup_controls_batch", new_callable=AsyncMock, return_value={}),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.get(f"/api/threat-models/{FAKE_TM_ID}/threats")
            assert resp.status_code == 200, f"List threats failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert len(body) == 2
            assert body[0]["display_id"] == "T-001"
            assert body[1]["display_id"] == "T-002"
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)

    async def test_step_12_stride_filter(self):
        """Step 8b: Filter threats by STRIDE category."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        spoofing_threats = [FakeThreat(FAKE_THREAT_ID, "T-001", "Spoofing", "High")]

        mock_db = AsyncMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = spoofing_threats
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch("app.api.threats.lookup_controls_batch", new_callable=AsyncMock, return_value={}),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.get(
                        f"/api/threat-models/{FAKE_TM_ID}/threats",
                        params={"stride_category": "Spoofing"},
                    )
            assert resp.status_code == 200
            body = resp.json()
            assert all(t["stride_category"] == "Spoofing" for t in body)
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)

    async def test_step_13_triage_threat_accept(self):
        """Step 9: Triage a threat -> Accept."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        fake_threat = FakeThreat(FAKE_THREAT_ID, "T-001", "Spoofing", "High")

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fake_threat
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()

        async def mock_refresh(obj):
            pass
        mock_db.refresh = mock_refresh

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch("app.api.threats.lookup_controls_batch", new_callable=AsyncMock, return_value={}),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.patch(
                        f"/api/threat-models/{FAKE_TM_ID}/threats/{FAKE_THREAT_ID}/triage",
                        json={"status": "Accepted"},
                    )
            assert resp.status_code == 200, f"Triage failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["status"] == "Accepted"
            assert body["dismiss_reason"] is None
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)

    async def test_step_14_triage_threat_dismiss_with_reason(self):
        """Step 9b: Triage a threat -> Dismiss with reason."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        fake_threat = FakeThreat(FAKE_THREAT_ID, "T-001", "Spoofing", "High")

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = fake_threat
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()

        async def mock_refresh(obj):
            pass
        mock_db.refresh = mock_refresh

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch("app.api.threats.lookup_controls_batch", new_callable=AsyncMock, return_value={}),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.patch(
                        f"/api/threat-models/{FAKE_TM_ID}/threats/{FAKE_THREAT_ID}/triage",
                        json={"status": "Dismissed", "dismiss_reason": "False positive - covered by WAF"},
                    )
            assert resp.status_code == 200, f"Dismiss failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["status"] == "Dismissed"
            assert body["dismiss_reason"] == "False positive - covered by WAF"
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)

    async def test_step_15_compliance_mappings(self):
        """Step 10: Get compliance mappings."""
        fake_mappings = [
            FakeComplianceMapping("Spoofing", "Identity Spoofing", "IA-2", "Identification and Authentication"),
            FakeComplianceMapping("Tampering", "Data Tampering", "SI-7", "Software, Firmware, and Information Integrity"),
        ]

        mock_db = AsyncMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = fake_mappings
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                resp = await client.get("/api/compliance-mappings")
            assert resp.status_code == 200, f"Compliance failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert len(body) >= 2

            # Also test by-stride
            mock_scalars.all.return_value = [fake_mappings[0]]
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                resp2 = await client.get("/api/compliance-mappings/by-stride/Spoofing")
            assert resp2.status_code == 200
        finally:
            app.dependency_overrides.pop(get_db, None)

    async def test_step_16_threat_summary(self):
        """Step 11: Get threat summary -> by_stride, by_severity, by_status."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        threats = [
            FakeThreat(uuid.uuid4(), "T-001", "Spoofing", "High", "Open"),
            FakeThreat(uuid.uuid4(), "T-002", "Tampering", "Critical", "Accepted"),
            FakeThreat(uuid.uuid4(), "T-003", "Spoofing", "Medium", "Open"),
        ]

        mock_db = AsyncMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = threats
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.get(f"/api/threat-models/{FAKE_TM_ID}/threats/summary")
            assert resp.status_code == 200, f"Summary failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["total"] == 3
            assert body["by_stride"]["Spoofing"] == 2
            assert body["by_stride"]["Tampering"] == 1
            assert body["by_severity"]["High"] == 1
            assert body["by_severity"]["Critical"] == 1
            assert body["by_status"]["Open"] == 2
            assert body["by_status"]["Accepted"] == 1
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)

    async def test_step_17_threat_intel_status(self):
        """Step 12: Check threat intel status endpoint."""
        statuses = [
            {"source": "MITRE ATT&CK", "status": "complete", "last_synced_at": "2026-03-15T00:00:00Z", "record_count": 100},
            {"source": "CAPEC", "status": "complete", "last_synced_at": "2026-03-15T00:00:00Z", "record_count": 200},
            {"source": "CWE", "status": "pending", "last_synced_at": None, "record_count": 0},
            {"source": "CISA KEV", "status": "complete", "last_synced_at": "2026-03-15T00:00:00Z", "record_count": 50},
            {"source": "CCCS", "status": "complete", "last_synced_at": "2026-03-15T00:00:00Z", "record_count": 30},
            {"source": "CRI Profile", "status": "complete", "last_synced_at": "2026-03-15T00:00:00Z", "record_count": 80},
        ]

        mock_db = AsyncMock()

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override
        app.dependency_overrides[get_current_user] = override_get_current_user

        try:
            with patch("app.services.threat_intel.sync.get_sync_status", new_callable=AsyncMock, return_value=statuses):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.get("/api/threat-intel/status")
            assert resp.status_code == 200, f"Intel status failed: {resp.status_code} {resp.text}"
            body = resp.json()
            assert body["total_sources"] == 6
            assert body["synced"] == 5  # 5 complete, 1 pending
            assert len(body["sources"]) == 6
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(get_current_user, None)

    async def test_step_18_export_csv(self):
        """Step 13: Export threats as CSV."""
        app.dependency_overrides[get_current_user] = override_get_current_user

        from app.api.threats import _require_owner
        async def override_require_owner(threat_model_id):
            return FakeUser()
        app.dependency_overrides[_require_owner] = override_require_owner

        fake_tm = FakeThreatModel()
        threats = [
            FakeThreat(FAKE_THREAT_ID, "T-001", "Spoofing", "High"),
        ]

        mock_db = AsyncMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = threats
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        try:
            with (
                patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
                patch("app.api.threats.lookup_controls_batch", new_callable=AsyncMock, return_value={}),
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                    resp = await client.get(f"/api/threat-models/{FAKE_TM_ID}/threats/export.csv")
            assert resp.status_code == 200, f"Export CSV failed: {resp.status_code} {resp.text}"
            assert "text/csv" in resp.headers.get("content-type", "")
            # Parse CSV content
            content = resp.text
            lines = content.strip().split("\n")
            assert len(lines) >= 2, "CSV should have header + at least 1 data row"
            assert "T-001" in lines[1]
            assert "Spoofing" in lines[1]
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(_require_owner, None)
