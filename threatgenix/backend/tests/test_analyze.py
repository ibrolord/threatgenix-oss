"""Tests for POST /api/threat-models/{id}/analyze endpoint (Block B24)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user
from app.api.threats import _require_owner
from app.schemas.ai_pass import AIPassOutput, AIThreatRaw
from app.schemas.rules import GeneratedThreat, RuleEngineOutput

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


async def override_require_owner(threat_model_id):
    return FakeUser()


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user
app.dependency_overrides[_require_owner] = override_require_owner


def _analyze_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/analyze"


class FakeThreatModel:
    def __init__(self, id: uuid.UUID | None = None):
        self.id = id or uuid.uuid4()
        self.system_name = "Test System"
        self.description = ""
        self.data_classification = "Internal"
        self.regulatory_scope = []
        self.deployment_model = None
        self.environment_context_summary = None
        self.owner_id = FAKE_USER_ID
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


# Fixed UUIDs for deterministic tests
NODE_ID_1 = uuid.uuid4()
NODE_ID_2 = uuid.uuid4()
EDGE_ID = uuid.uuid4()
BOUNDARY_ID = uuid.uuid4()


def _make_fake_nodes_edges_boundaries():
    """Create fake DFD data that the rules engine can process."""

    class FakeNode:
        id = NODE_ID_1
        node_type = "process"
        name = "API Gateway"
        position_x = 0.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    class FakeNode2:
        id = NODE_ID_2
        node_type = "data_store"
        name = "User DB"
        position_x = 120.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    class FakeEdge:
        id = EDGE_ID
        source_node_id = NODE_ID_1
        target_node_id = NODE_ID_2
        label = "query"
        properties = {}

    class FakeBoundary:
        id = BOUNDARY_ID
        name = "DMZ"
        node_ids = [NODE_ID_1]

    return [FakeNode(), FakeNode2()], [FakeEdge()], [FakeBoundary()]


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
                affected_node_ids=[str(uuid.uuid4())],
                affected_edge_ids=[str(uuid.uuid4())],
                source="Rules",
            ),
        ],
        execution_time_ms=1.5,
        rules_evaluated=10,
        rules_fired=1,
    )


def _make_ai_output() -> AIPassOutput:
    return AIPassOutput(
        threats=[
            AIThreatRaw(
                description="Transaction Replay Attack: Attacker replays API Gateway transactions",
                stride_category="Tampering",
                severity="High",
                enhances_rule_threat_id=None,
                reasoning="Banking APIs are vulnerable to replay attacks.",
            ),
        ],
        model_id="anthropic.claude-3-sonnet-20240229-v1:0",
        input_tokens=100,
        output_tokens=50,
        latency_ms=500.0,
    )


class FakeDocument:
    """Minimal fake Document model for DB queries."""

    id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    filename = "design.pdf"
    page_count = 5
    raw_text = "This is a banking system design document with PCI scope."
    uploaded_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
    parsed_components = {
        "parse_result": {
            "components": [
                {
                    "name": "API Gateway",
                    "component_type": "process",
                    "extraction_source": "diagram",
                    "evidence_page": 2,
                    "evidence_snippet": "API Gateway",
                }
            ],
            "flows": [
                {
                    "source": "API Gateway",
                    "target": "Payment Service",
                    "label": "payment request",
                    "extraction_source": "llm",
                }
            ],
            "boundaries": [],
            "raw_text_excerpt": "This is a banking system design document with PCI scope.",
        },
        "evidence": {
            "component_count": 1,
            "flow_count": 1,
            "boundary_count": 0,
            "diagram_pages": [2],
            "extraction_sources": ["diagram", "llm"],
            "low_confidence_areas": [],
            "raw_text_excerpt": "This is a banking system design document with PCI scope.",
            "detected_doc_type": "architecture_design",
        },
    }


def _mock_db_with_dfd(nodes, edges, boundaries, *, include_document: bool = True):
    """Create a mock DB that returns DFD data across sequential execute calls.

    For the analyze endpoint, the call order is:
    1. nodes query
    2. edges query
    3. boundaries query
    4. (if AI enabled) document query
    5. delete existing threats
    """
    call_count = 0

    async def mock_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()

        if call_count == 1:
            mock_scalars.all.return_value = nodes
        elif call_count == 2:
            mock_scalars.all.return_value = edges
        elif call_count == 3:
            mock_scalars.all.return_value = boundaries
        elif call_count == 4 and include_document:
            # Document query (scalar_one_or_none)
            mock_result = MagicMock()
            mock_result.scalars.return_value = mock_scalars
            mock_result.scalar_one_or_none.return_value = (
                FakeDocument() if include_document else None
            )
            return mock_result
        else:
            # delete statement or subsequent queries
            mock_scalars.all.return_value = []

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_result.scalar_one_or_none.return_value = None
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    mock_db.add = MagicMock()
    return mock_db


def _mock_db_with_dfd_rules_only(nodes, edges, boundaries):
    """Create a mock DB for rules_only=true (no document query needed)."""
    call_count = 0

    async def mock_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()

        if call_count == 1:
            mock_scalars.all.return_value = nodes
        elif call_count == 2:
            mock_scalars.all.return_value = edges
        elif call_count == 3:
            mock_scalars.all.return_value = boundaries
        else:
            # delete statement
            mock_scalars.all.return_value = []

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    mock_db.add = MagicMock()
    return mock_db


def _mock_db_rules_only_with_existing(nodes, edges, boundaries, existing_threats):
    """Create a mock DB for rules_only=true with pre-existing threats."""
    call_count = 0

    async def mock_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_result.scalar_one_or_none.return_value = None

        if call_count == 1:
            mock_scalars.all.return_value = nodes
        elif call_count == 2:
            mock_scalars.all.return_value = edges
        elif call_count == 3:
            mock_scalars.all.return_value = boundaries
        elif call_count == 4:
            mock_result.scalar_one_or_none.return_value = FakeDocument()
            mock_scalars.all.return_value = []
        elif call_count == 6:
            mock_scalars.all.return_value = existing_threats
        else:
            mock_scalars.all.return_value = []

        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    mock_db.add = MagicMock()
    mock_db.delete = AsyncMock()
    return mock_db


def _mock_db_empty():
    """Create a mock DB that returns empty nodes (first query)."""

    async def mock_execute(stmt, *args, **kwargs):
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    return mock_db


# ─── POST /analyze Tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_rules_only_returns_only_rule_threats():
    """POST analyze with rules_only=true -> only rule threats, no AI."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_output = _make_rule_engine_output()

    mock_db = _mock_db_with_dfd_rules_only(nodes, edges, boundaries)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_output),
        patch("app.api.threats.enhance_threats", new_callable=AsyncMock) as mock_ai,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                _analyze_url(tm_id), params={"rules_only": "true"}
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body["threats"]) == 1
    assert body["threats"][0]["display_id"] == "T-001"
    assert body["threats"][0]["source"] == "Rules"
    assert body["ai_skipped_reason"] is not None
    # AI should NOT have been called
    mock_ai.assert_not_awaited()


@pytest.mark.asyncio
async def test_analyze_preserves_manual_threats():
    """POST analyze should preserve manual threats across re-analysis."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_output = _make_rule_engine_output()
    now = datetime(2026, 3, 20, 12, 0, 0, tzinfo=timezone.utc)

    class ExistingManualThreat:
        id = uuid.uuid4()
        threat_model_id = tm_id
        display_id = "T-099"
        description = "Custom operator override abuse"
        stride_category = "Elevation of Privilege"
        threat_subtype = "Operator override abuse"
        severity = "High"
        source = "Manual"
        status = "Open"
        dismiss_reason = None
        rule_id = None
        ai_enhanced = False
        provider_managed = False
        original_rule_threat_id = None
        affected_node_ids = []
        affected_edge_ids = []
        relevance_rationale = None
        mitigation_plan = None
        mitigation_owner = None
        due_date = None
        mitigation_notes = None
        closed_at = None
        created_at = now
        updated_at = now

    mock_db = _mock_db_rules_only_with_existing(
        nodes,
        edges,
        boundaries,
        [ExistingManualThreat()],
    )

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_output),
        patch("app.api.threats.enhance_threats", new_callable=AsyncMock) as mock_ai,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                _analyze_url(tm_id), params={"rules_only": "true"}
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert [threat["display_id"] for threat in body["threats"]] == ["T-001", "T-099"]
    assert body["threats"][1]["source"] == "Manual"
    mock_db.delete.assert_not_called()
    mock_ai.assert_not_awaited()


@pytest.mark.asyncio
async def test_analyze_with_ai_returns_rule_and_ai_threats():
    """POST analyze with rules_only=false + mocked AI -> rule + AI threats."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()
    fake_ai_output = _make_ai_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    # merge_ai_threats will produce rule threats + AI threats
    merged_threats = list(fake_rules_output.threats) + [
        GeneratedThreat(
            rule_id="AI-001",
            display_id="T-002",
            stride_category="Tampering",
            threat_subtype="Transaction Replay Attack",
            severity="High",
            description="Transaction Replay Attack: Attacker replays API Gateway transactions",
            affected_node_ids=[str(NODE_ID_1)],
            affected_edge_ids=[],
            source="AI",
        ),
    ]

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch(
            "app.api.threats.enhance_threats",
            new_callable=AsyncMock,
            return_value=(fake_ai_output, None),
        ),
        patch("app.api.threats.merge_ai_threats", return_value=merged_threats),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body["threats"]) == 2
    sources = {t["source"] for t in body["threats"]}
    assert "Rules" in sources
    assert "AI" in sources
    assert body["threats"][0]["display_id"] == "T-001"
    assert body["threats"][1]["display_id"] == "T-002"
    assert body["ai_skipped_reason"] is None


@pytest.mark.asyncio
async def test_analyze_merges_ai_threats_even_when_warning_present():
    """POST analyze should preserve AI threats when enhancement returns warnings."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()
    fake_ai_output = _make_ai_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    merged_threats = list(fake_rules_output.threats) + [
        GeneratedThreat(
            rule_id="AI-001",
            display_id="T-002",
            stride_category="Tampering",
            threat_subtype="Transaction Replay Attack",
            severity="High",
            description="Transaction Replay Attack: Attacker replays API Gateway transactions",
            affected_node_ids=[str(NODE_ID_1)],
            affected_edge_ids=[],
            source="AI",
        ),
    ]

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch(
            "app.api.threats.enhance_threats",
            new_callable=AsyncMock,
            return_value=(
                fake_ai_output,
                "Threat intelligence unavailable: pgvector type unavailable.",
            ),
        ),
        patch("app.api.threats.merge_ai_threats", return_value=merged_threats),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body["threats"]) == 2
    assert {item["source"] for item in body["threats"]} == {"Rules", "AI"}
    assert (
        body["ai_skipped_reason"]
        == "Threat intelligence unavailable: pgvector type unavailable."
    )


@pytest.mark.asyncio
async def test_analyze_ai_failure_graceful_degradation():
    """POST analyze with AI failure -> returns rule threats only."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch(
            "app.api.threats.enhance_threats",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Bedrock unavailable"),
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    # Should still return the rule threats despite AI failure
    assert len(body["threats"]) == 1
    assert body["threats"][0]["source"] == "Rules"
    assert body["threats"][0]["display_id"] == "T-001"
    assert body["ai_skipped_reason"] is not None
    # S-16: ai_skipped_reason must not leak exception internals
    assert "Bedrock unavailable" not in body["ai_skipped_reason"]


@pytest.mark.asyncio
async def test_analyze_ai_exception_skipped_reason_sanitized():
    """S-16: generic Exception must not leak type name or exception details."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()
    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch(
            "app.api.threats.enhance_threats",
            new_callable=AsyncMock,
            side_effect=ValueError("arn:aws:iam::123456789012:user/internal-secret"),
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["ai_skipped_reason"] is not None
    # Must not expose AWS credentials or exception type
    assert "123456789012" not in body["ai_skipped_reason"]
    assert "ValueError" not in body["ai_skipped_reason"]
    assert "arn:aws" not in body["ai_skipped_reason"]


@pytest.mark.asyncio
async def test_analyze_uses_isolated_session_for_ai_enhancement():
    """POST analyze should use a separate DB session for AI/threat-intel work."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()
    fake_ai_output = _make_ai_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)
    isolated_db = AsyncMock()
    captured: dict[str, object] = {}

    async def db_override():
        yield mock_db

    class FakeSessionManager:
        async def __aenter__(self):
            return isolated_db

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_enhance_threats(*args, **kwargs):
        captured["db"] = kwargs.get("db")
        return fake_ai_output, "AI enhancement skipped by test"

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch("app.api.threats.enhance_threats", new=fake_enhance_threats),
        patch("app.api.threats.async_session", return_value=FakeSessionManager()),
        patch("app.api.threats.AsyncSession", AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    assert captured["db"] is isolated_db
    assert captured["db"] is not mock_db


@pytest.mark.asyncio
async def test_analyze_passes_environment_context_to_ai_enhancement():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.environment_context_summary = "## Repository Evidence\n- Frameworks: FastAPI, React"
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()
    fake_ai_output = _make_ai_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)
    isolated_db = AsyncMock()
    captured: dict[str, object] = {}

    async def db_override():
        yield mock_db

    class FakeSessionManager:
        async def __aenter__(self):
            return isolated_db

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_enhance_threats(*args, **kwargs):
        captured["environment_context_summary"] = kwargs.get("environment_context_summary")
        return fake_ai_output, None

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch("app.api.threats.enhance_threats", new=fake_enhance_threats),
        patch("app.api.threats.async_session", return_value=FakeSessionManager()),
        patch("app.api.threats.AsyncSession", AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    assert captured["environment_context_summary"] == fake_tm.environment_context_summary


@pytest.mark.asyncio
async def test_analyze_passes_document_context_summary_to_ai_enhancement():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_rules_output = _make_rule_engine_output()
    fake_ai_output = _make_ai_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)
    isolated_db = AsyncMock()
    captured: dict[str, object] = {}

    async def db_override():
        yield mock_db

    class FakeSessionManager:
        async def __aenter__(self):
            return isolated_db

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_enhance_threats(*args, **kwargs):
        captured["document_context_summary"] = kwargs.get("document_context_summary")
        return fake_ai_output, None

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_rules_output),
        patch("app.api.threats.enhance_threats", new=fake_enhance_threats),
        patch("app.api.threats.async_session", return_value=FakeSessionManager()),
        patch("app.api.threats.AsyncSession", AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    summary = str(captured["document_context_summary"])
    assert "architecture design" in summary.lower()
    assert "diagram pages detected: 2" in summary.lower()
    assert "api gateway" in summary.lower()


@pytest.mark.asyncio
async def test_analyze_no_dfd_returns_400():
    """POST analyze with no DFD -> 400."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    mock_db = _mock_db_empty()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 400
    assert "No DFD found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_analyze_invalid_model_returns_404():
    """POST analyze with invalid threat model -> 404."""
    tm_id = uuid.uuid4()

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=None
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_analyze_url(tm_id))

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_analyze_is_idempotent():
    """POST analyze twice -> idempotent (same count each time)."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_output = _make_rule_engine_output()

    for _ in range(2):
        mock_db = _mock_db_with_dfd_rules_only(nodes, edges, boundaries)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        with (
            patch(
                "app.api.threats.get_threat_model",
                new_callable=AsyncMock,
                return_value=fake_tm,
            ),
            patch("app.api.threats.evaluate_rules", return_value=fake_output),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    _analyze_url(tm_id), params={"rules_only": "true"}
                )

        assert response.status_code == 200
        body = response.json()
        assert len(body["threats"]) == 1

    app.dependency_overrides[get_db] = override_get_db
