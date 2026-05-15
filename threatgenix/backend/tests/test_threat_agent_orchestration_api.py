from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.threat_agent_orchestration import (
    AgentToolCapabilityResponse,
    AgentRunMetadata,
    ThreatRemediationRunResponse,
    ThreatValidationRunResponse,
)
from app.services.auth import get_current_user

BASE_URL = "http://test"


def _metadata(agent_type: str) -> AgentRunMetadata:
    return AgentRunMetadata(
        agent_type=agent_type,
        agent_version="2026.05.v1",
        input_schema_version="agent-input.v1",
        output_schema_version="agent-output.v1",
        policy_version="human-triggered-v1",
        tool_harness_versions={"semgrep": "fixture"},
        model_provider=None,
        model_name=None,
        prompt_version=None,
        model_output_hash=None,
        deterministic_fallback_used=True,
    )


def _validation_response(
    *,
    run_id: uuid.UUID,
    owner_id: uuid.UUID,
    threat_model_id: uuid.UUID,
    threat_id: uuid.UUID,
) -> ThreatValidationRunResponse:
    now = datetime(2026, 5, 3, tzinfo=timezone.utc)
    return ThreatValidationRunResponse(
        id=run_id,
        tenant_key=f"user:{owner_id}",
        owner_id=owner_id,
        organization_id=None,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
        application_review_id=None,
        orchestration_job_id=uuid.uuid4(),
        status="completed",
        conclusion="confirmed",
        question="Validate sensitive export route authorization.",
        requested_tools=["semgrep"],
        evidence_refs=[
            {
                "id": str(uuid.uuid4()),
                "item_type": "scanner_finding",
                "source_refs": [{"path": "src/api/exports.py"}],
            }
        ],
        summary="Semgrep evidence supports the authorization finding.",
        failure_reason=None,
        metadata=_metadata("threat_validation"),
        created_at=now,
        updated_at=now,
    )


def _remediation_response(
    *,
    run_id: uuid.UUID,
    validation_run_id: uuid.UUID,
    owner_id: uuid.UUID,
    threat_model_id: uuid.UUID,
    threat_id: uuid.UUID,
    status: str = "awaiting_confirmation",
) -> ThreatRemediationRunResponse:
    now = datetime(2026, 5, 3, tzinfo=timezone.utc)
    return ThreatRemediationRunResponse(
        id=run_id,
        tenant_key=f"user:{owner_id}",
        owner_id=owner_id,
        organization_id=None,
        validation_run_id=validation_run_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
        application_review_id=None,
        orchestration_job_id=uuid.uuid4(),
        agent_type="code_fix",
        status=status,
        fix_summary="Add an authorization check before exporting sensitive data.",
        patch_preview="src/api/exports.py: require authenticated admin scope.",
        ticket_draft={
            "title": "Fix export authorization gap",
            "body": "Evidence: src/api/exports.py and semgrep finding.",
        },
        pr_draft={
            "title": "Require authorization on sensitive export route",
            "body": "Draft only; human confirmation required.",
        },
        external_ticket_id="SEC-123" if status == "handoff_created" else None,
        external_ticket_url="https://tickets.example/SEC-123" if status == "handoff_created" else None,
        external_pr_url=None,
        evidence_refs=[],
        failure_reason=None,
        metadata=_metadata("code_fix"),
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_start_validation_run_commits_and_returns_confirmed_result():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    run_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    threat = SimpleNamespace(id=threat_id, threat_model_id=threat_model_id)
    scan_job_id = uuid.uuid4()
    run = SimpleNamespace(
        id=run_id,
        domain_agent_results=[
            {
                "tools": [
                    {
                        "tool": "semgrep",
                        "status": "authorized",
                        "scan_job_id": str(scan_job_id),
                    }
                ]
            }
        ],
    )
    response_model = _validation_response(
        run_id=run_id,
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
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
                "app.api.threat_agent_orchestration._get_threat_for_review",
                new_callable=AsyncMock,
                return_value=threat,
            ) as get_threat,
            patch(
                "app.api.threat_agent_orchestration.create_threat_validation_run",
                new_callable=AsyncMock,
                return_value=run,
            ) as create_run,
            patch(
                "app.api.threat_agent_orchestration.serialize_validation_run",
                new_callable=AsyncMock,
                return_value=response_model,
            ),
            patch(
                "app.api.threat_agent_orchestration.inline_validation_execution_enabled",
                return_value=True,
            ),
            patch(
                "app.api.threat_agent_orchestration.run_scan_job",
                new_callable=AsyncMock,
            ) as run_scan,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-models/{threat_model_id}/threats/{threat_id}/validation-runs",
                    json={
                        "domain_agents": ["sast", "llm_security"],
                        "requested_tools": ["semgrep"],
                        "domain_agent_tools": {
                            "llm_security": ["ai-red-team", "pentest-report"],
                        },
                        "domain_agent_instructions": {
                            "llm_security": "Focus on indirect prompt injection through retrieval.",
                        },
                        "domain_agent_targets": {
                            "semgrep": {
                                "target_type": "repository_path",
                                "target": "/tmp/threatgenix-demo-repo",
                                "authorization_acknowledged": True,
                            }
                        },
                        "question": "Validate sensitive export route authorization.",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == str(run_id)
    assert payload["conclusion"] == "confirmed"
    assert payload["metadata"]["model_provider"] is None
    assert payload["metadata"]["deterministic_fallback_used"] is True
    get_threat.assert_awaited_once()
    create_run.assert_awaited_once()
    assert create_run.await_args.kwargs["requested_tools"] == ["semgrep"]
    assert create_run.await_args.kwargs["domain_agents"] == ["sast", "llm_security"]
    assert create_run.await_args.kwargs["domain_agent_tools"] == {
        "llm_security": ["ai-red-team", "pentest-report"],
    }
    assert create_run.await_args.kwargs["domain_agent_instructions"] == {
        "llm_security": "Focus on indirect prompt injection through retrieval.",
    }
    assert create_run.await_args.kwargs["domain_agent_targets"]["semgrep"].target == (
        "/tmp/threatgenix-demo-repo"
    )
    db.commit.assert_awaited_once()
    run_scan.assert_awaited_once_with(scan_job_id)


@pytest.mark.asyncio
async def test_agent_tool_catalog_returns_domain_capabilities():
    owner_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)

    async def override_user():
        return user

    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.threat_agent_orchestration.list_agent_tool_capabilities",
            return_value=[
                AgentToolCapabilityResponse(
                    domain_agent="sast",
                    tool="semgrep",
                    label="Semgrep",
                    supported_target_types=["repository_path"],
                    best_for=["source-code checks"],
                    runtime_risk="low",
                    requires_network=False,
                    requires_human_approval=True,
                    available=True,
                    enabled=True,
                    readiness_status="ready",
                )
            ],
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get("/api/agent-tools/catalog")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["domain_agent"] == "sast"
    assert payload[0]["tool"] == "semgrep"
    assert payload[0]["requires_human_approval"] is True


@pytest.mark.asyncio
async def test_propose_scan_plan_preserves_tool_modes_and_requires_approval():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    run_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    threat = SimpleNamespace(id=threat_id, threat_model_id=threat_model_id)
    run = SimpleNamespace(id=run_id)
    response_model = _validation_response(
        run_id=run_id,
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
    ).model_copy(
        update={
            "status": "created",
            "conclusion": None,
            "summary": "Agent scan plan proposed.",
        }
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
                "app.api.threat_agent_orchestration._get_threat_for_review",
                new_callable=AsyncMock,
                return_value=threat,
            ),
            patch(
                "app.api.threat_agent_orchestration.create_threat_scan_plan",
                new_callable=AsyncMock,
                return_value=run,
            ) as create_plan,
            patch(
                "app.api.threat_agent_orchestration.serialize_validation_run",
                new_callable=AsyncMock,
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-models/{threat_model_id}/threats/{threat_id}/scan-plans",
                    json={
                        "domain_agents": ["sast", "iac"],
                        "domain_agent_tool_mode": {"sast": "recommended", "iac": "all"},
                        "domain_agent_tools": {"sast": ["semgrep"]},
                        "excluded_tools": {"iac": ["trivy"]},
                        "required_tools": {"iac": ["checkov"]},
                        "domain_agent_instructions": {
                            "sast": "Prioritize export route authorization evidence.",
                        },
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "created"
    assert payload["conclusion"] is None
    create_plan.assert_awaited_once()
    assert create_plan.await_args.kwargs["domain_agent_tool_mode"] == {
        "sast": "recommended",
        "iac": "all",
    }
    assert create_plan.await_args.kwargs["excluded_tools"] == {"iac": ["trivy"]}
    assert create_plan.await_args.kwargs["required_tools"] == {"iac": ["checkov"]}
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_approve_scan_plan_requires_access_and_passes_targets():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    run_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    validation_run = SimpleNamespace(
        id=run_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
    )
    response_model = _validation_response(
        run_id=run_id,
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
    ).model_copy(update={"status": "running", "conclusion": None})
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
                "app.api.threat_agent_orchestration._get_validation_or_404",
                new_callable=AsyncMock,
                return_value=validation_run,
            ),
            patch(
                "app.api.threat_agent_orchestration._require_run_review_access",
                new_callable=AsyncMock,
            ) as require_access,
            patch(
                "app.api.threat_agent_orchestration.approve_threat_scan_plan",
                new_callable=AsyncMock,
                return_value=validation_run,
            ) as approve_plan,
            patch(
                "app.api.threat_agent_orchestration.serialize_validation_run",
                new_callable=AsyncMock,
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/scan-plans/{run_id}/approve",
                    json={
                        "domain_agent_targets": {
                            "semgrep": {
                                "tool_name": "semgrep",
                                "target_type": "repository_path",
                                "target": "/tmp/threatgenix-demo-repo",
                                "scope": "internal",
                                "authorization_acknowledged": True,
                            }
                        },
                        "approval_note": "Authorized local source validation.",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "running"
    require_access.assert_awaited_once_with(db, user, threat_model_id)
    approve_plan.assert_awaited_once()
    target = approve_plan.await_args.kwargs["body"].domain_agent_targets["semgrep"]
    assert target.target == "/tmp/threatgenix-demo-repo"
    assert target.scope == "internal"
    assert target.authorization_acknowledged is True
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_remediation_run_requires_validation_access_and_commits():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    validation_run_id = uuid.uuid4()
    remediation_run_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    validation_run = SimpleNamespace(
        id=validation_run_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
    )
    remediation_run = SimpleNamespace(id=remediation_run_id)
    response_model = _remediation_response(
        run_id=remediation_run_id,
        validation_run_id=validation_run_id,
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
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
                "app.api.threat_agent_orchestration._get_validation_or_404",
                new_callable=AsyncMock,
                return_value=validation_run,
            ) as get_validation,
            patch(
                "app.api.threat_agent_orchestration._require_run_review_access",
                new_callable=AsyncMock,
            ) as require_access,
            patch(
                "app.api.threat_agent_orchestration.create_threat_remediation_run",
                new_callable=AsyncMock,
                return_value=remediation_run,
            ) as create_run,
            patch(
                "app.api.threat_agent_orchestration.serialize_remediation_run",
                new_callable=AsyncMock,
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-validations/{validation_run_id}/remediation-runs",
                    json={"agent_type": "code_fix"},
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == str(remediation_run_id)
    assert payload["status"] == "awaiting_confirmation"
    assert payload["agent_type"] == "code_fix"
    get_validation.assert_awaited_once()
    require_access.assert_awaited_once()
    create_run.assert_awaited_once()
    assert create_run.await_args.kwargs["agent_type"] == "code_fix"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_confirm_handoff_requires_explicit_confirmation_before_external_record():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    validation_run_id = uuid.uuid4()
    remediation_run_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    remediation_run = SimpleNamespace(
        id=remediation_run_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
        validation_run_id=validation_run_id,
    )
    response_model = _remediation_response(
        run_id=remediation_run_id,
        validation_run_id=validation_run_id,
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        threat_id=threat_id,
        status="handoff_created",
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
                "app.api.threat_agent_orchestration._get_remediation_or_404",
                new_callable=AsyncMock,
                return_value=remediation_run,
            ) as get_remediation,
            patch(
                "app.api.threat_agent_orchestration._require_run_review_access",
                new_callable=AsyncMock,
            ),
            patch(
                "app.api.threat_agent_orchestration.confirm_remediation_handoff",
                new_callable=AsyncMock,
                return_value=remediation_run,
            ) as confirm_handoff,
            patch(
                "app.api.threat_agent_orchestration.serialize_remediation_run",
                new_callable=AsyncMock,
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/threat-remediations/{remediation_run_id}/confirm-handoff",
                    json={
                        "confirmed": True,
                        "provider": "jira",
                        "external_ticket_id": "SEC-123",
                        "external_ticket_url": "https://tickets.example/SEC-123",
                        "confirmed_by": "Priya",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "handoff_created"
    assert payload["external_ticket_id"] == "SEC-123"
    get_remediation.assert_awaited_once()
    confirm_handoff.assert_awaited_once()
    assert confirm_handoff.await_args.kwargs["body"].confirmed is True
    assert confirm_handoff.await_args.kwargs["body"].provider == "jira"
    db.commit.assert_awaited_once()
