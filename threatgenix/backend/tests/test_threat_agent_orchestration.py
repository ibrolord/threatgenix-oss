from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.agent_model_adapter import (
    DeterministicFallbackAgentModelAdapter,
    LLMAgentModelAdapter,
    validate_agent_model_payload,
)
from app.services import threat_agent_orchestration as orchestration_service
from app.services.threat_agent_orchestration import ThreatAgentOrchestrationError
from app.schemas.threat_agent_orchestration import ThreatRemediationHandoffConfirmRequest
from app.services.threat_agent_orchestration import build_exploitability_assessment
from app.services.threat_agent_orchestration import confirm_remediation_handoff
from app.services.threat_agent_orchestration import create_threat_remediation_run
from app.services.threat_agent_orchestration import evaluate_validation_conclusion
from app.services.threat_agent_orchestration import rerun_threat_validation
from app.services.threat_agent_orchestration import refresh_validation_run_from_controlled_scans
from app.services.threat_agent_orchestration import _build_domain_agent_results
from app.services.threat_agent_orchestration import _resolve_domain_agent_plan
from app.services.threat_agent_orchestration import _tools_for_domain_agent_plan

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "threat_agent_orchestration"


def _entry(*, item_type: str, title: str = "Evidence", body: str = "body"):
    return SimpleNamespace(title=title, body=body, item_type=item_type)


def _entry_from_fixture(item: dict) -> SimpleNamespace:
    return SimpleNamespace(
        title=item["title"],
        body=item["body"],
        item_type=item["item_type"],
    )


def test_domain_agent_plan_defaults_to_sast_agent() -> None:
    plan = _resolve_domain_agent_plan()

    assert plan == [
        {
            "domain_agent": "sast",
            "label": "SAST Agent",
            "tools": ["semgrep"],
            "instructions": "Validate source-code exploitability and cite file, rule, and code-path evidence.",
        }
    ]
    assert _tools_for_domain_agent_plan(plan) == ["semgrep"]


def test_domain_agent_plan_supports_multiple_tools_per_domain() -> None:
    plan = _resolve_domain_agent_plan(domain_agents=["iac", "dependency", "llm_security"])

    by_agent = {item["domain_agent"]: item for item in plan}
    assert by_agent["iac"]["tools"] == ["checkov", "trivy"]
    assert by_agent["dependency"]["tools"] == ["osv-scanner", "trivy"]
    assert by_agent["llm_security"]["tools"] == ["ai-red-team"]
    assert _tools_for_domain_agent_plan(plan) == [
        "ai-red-team",
        "checkov",
        "trivy",
        "osv-scanner",
    ]


def test_domain_agent_plan_keeps_explicit_tool_requests_precise() -> None:
    plan = _resolve_domain_agent_plan(requested_tools=["semgrep", "ai-red-team"])

    by_agent = {item["domain_agent"]: item for item in plan}
    assert by_agent["sast"]["tools"] == ["semgrep"]
    assert by_agent["llm_security"]["tools"] == ["ai-red-team"]
    assert "checkov" not in _tools_for_domain_agent_plan(plan)


def test_domain_agent_plan_preserves_special_instructions() -> None:
    plan = _resolve_domain_agent_plan(
        domain_agents=["llm_security"],
        domain_agent_instructions={
            "llm_security": "Focus on indirect prompt injection through retrieval.",
        },
    )

    assert plan[0]["domain_agent"] == "llm_security"
    assert plan[0]["tools"] == ["ai-red-team"]
    assert plan[0]["instructions"] == "Focus on indirect prompt injection through retrieval."


def test_domain_agent_plan_supports_explicit_tools_per_agent() -> None:
    plan = _resolve_domain_agent_plan(
        domain_agent_tools={
            "llm_security": ["ai-red-team", "pentest-report"],
            "configuration": ["external-report", "pentest-report"],
        },
        domain_agent_instructions={
            "llm_security": "Validate prompt injection evidence before remediation.",
            "configuration": "Prioritize runtime setting drift.",
        },
    )

    by_agent = {item["domain_agent"]: item for item in plan}
    assert by_agent["llm_security"]["tools"] == ["ai-red-team", "pentest-report"]
    assert by_agent["configuration"]["tools"] == ["external-report", "pentest-report"]
    assert by_agent["llm_security"]["instructions"] == (
        "Validate prompt injection evidence before remediation."
    )
    assert _tools_for_domain_agent_plan(plan) == [
        "ai-red-team",
        "pentest-report",
        "external-report",
    ]


def test_domain_agent_plan_preserves_explicit_empty_tool_selection() -> None:
    plan = _resolve_domain_agent_plan(
        domain_agents=["dast"],
        domain_agent_tools={"dast": []},
    )

    assert plan == [
        {
            "domain_agent": "dast",
            "label": "DAST Agent",
            "tools": [],
            "instructions": "Validate reachable HTTP/API evidence only when target authorization and scanner policy allow it.",
        }
    ]
    assert _tools_for_domain_agent_plan(plan) == []


def test_domain_agent_plan_supports_tool_modes_and_overrides() -> None:
    all_mode = _resolve_domain_agent_plan(
        domain_agents=["iac"],
        domain_agent_tool_mode={"iac": "all"},
        excluded_tools={"iac": ["trivy"]},
    )
    assert all_mode[0]["tools"] == ["checkov"]

    manual_mode = _resolve_domain_agent_plan(
        domain_agents=["configuration"],
        domain_agent_tool_mode={"configuration": "manual"},
        domain_agent_tools={"configuration": ["external-report"]},
        required_tools={"configuration": ["pentest-report"]},
    )
    assert manual_mode[0]["tools"] == ["external-report", "pentest-report"]


def test_domain_agent_plan_rejects_unknown_tool_and_instruction_target() -> None:
    with pytest.raises(ThreatAgentOrchestrationError, match="Unsupported validation tool"):
        _resolve_domain_agent_plan(requested_tools=["made-up-scanner"])

    with pytest.raises(ThreatAgentOrchestrationError, match="not allowed for SAST Agent"):
        _resolve_domain_agent_plan(domain_agent_tools={"sast": ["nuclei"]})

    with pytest.raises(ThreatAgentOrchestrationError, match="instruction target"):
        _resolve_domain_agent_plan(
            domain_agents=["sast"],
            domain_agent_instructions={"unknown": "do a thing"},
        )


@pytest.mark.asyncio
async def test_domain_agent_results_persist_completed_and_skipped_tools(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service

    monkeypatch.setattr(service.settings, "agent_controlled_runner_enabled", False)
    added = []
    db = SimpleNamespace(add=lambda item: added.append(item))
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=uuid.uuid4())
    plan = _resolve_domain_agent_plan(domain_agents=["sast", "dast"])
    evidence_refs = [
        {
            "id": str(uuid.uuid4()),
            "source_type": "scan_finding",
            "item_type": "scanner_finding",
            "title": "Semgrep missing authorization finding",
            "source_refs": [{"path": "backend/app/api/exports.py"}],
        }
    ]

    results = await _build_domain_agent_results(
        db,
        current_user=SimpleNamespace(id=uuid.uuid4()),
        job=job,
        threat=SimpleNamespace(threat_model_id=job.threat_model_id),
        plan=plan,
        evidence_refs=evidence_refs,
        domain_agent_targets={},
    )

    by_agent = {item["domain_agent"]: item for item in results}
    assert by_agent["sast"]["status"] == "evidence_attached"
    assert by_agent["sast"]["tools"][0]["status"] == "evidence_attached"
    assert by_agent["dast"]["status"] == "skipped"
    assert "DAST is disabled" in by_agent["dast"]["skipped_reason"]
    assert any(getattr(item, "task_kind", None) == "evidence_projection" for item in added)
    assert any(getattr(item, "task_kind", None) == "tool_execution" for item in added)


@pytest.mark.asyncio
async def test_domain_agent_results_create_controlled_runner_scan_job(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service
    from app.schemas.threat_agent_orchestration import DomainAgentTargetRequest

    monkeypatch.setattr(service.settings, "agent_controlled_runner_enabled", True)
    monkeypatch.setattr(service, "validation_run_submission_enabled", lambda: True)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/tmp")

    added = []

    async def flush():
        for item in added:
            if getattr(item, "id", None) is None:
                item.id = uuid.uuid4()

    db = SimpleNamespace(add=lambda item: added.append(item), flush=flush)
    user = SimpleNamespace(id=uuid.uuid4())
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=uuid.uuid4(), inputs={})
    node_id = uuid.uuid4()
    threat = SimpleNamespace(id=uuid.uuid4(), threat_model_id=job.threat_model_id)
    plan = _resolve_domain_agent_plan(domain_agents=["sast"])

    results = await _build_domain_agent_results(
        db,
        current_user=user,
        job=job,
        threat=threat,
        plan=plan,
        evidence_refs=[],
        domain_agent_targets={
            "semgrep": DomainAgentTargetRequest(
                target_type="repository_path",
                target="/tmp/threatgenix-demo-repo",
                target_node_id=node_id,
                authorization_acknowledged=True,
            )
        },
    )

    tool_result = results[0]["tools"][0]
    assert tool_result["status"] == "authorized"
    assert tool_result["scan_job_id"]
    assert results[0]["status"] == "running"
    scan_job = next(item for item in added if item.__class__.__name__ == "ScanJob")
    authorization = next(item for item in added if item.__class__.__name__ == "ScanAuthorization")
    assert scan_job.targets == {str(node_id): "/tmp/threatgenix-demo-repo"}
    assert authorization.targets_snapshot == scan_job.targets
    assert job.inputs["controlled_runner_scan_jobs"][0]["tool_name"] == "semgrep"


@pytest.mark.asyncio
async def test_domain_agent_target_forces_fresh_runner_over_existing_evidence(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service
    from app.schemas.threat_agent_orchestration import DomainAgentTargetRequest

    monkeypatch.setattr(service.settings, "agent_controlled_runner_enabled", True)
    monkeypatch.setattr(service, "validation_run_submission_enabled", lambda: True)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/tmp")

    added = []

    async def flush():
        for item in added:
            if getattr(item, "id", None) is None:
                item.id = uuid.uuid4()

    db = SimpleNamespace(add=lambda item: added.append(item), flush=flush)
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=uuid.uuid4(), inputs={})
    evidence_refs = [
        {
            "id": str(uuid.uuid4()),
            "source_type": "scan_finding",
            "item_type": "scanner_finding",
            "title": "Existing Semgrep evidence",
            "scanner": "semgrep",
        }
    ]

    results = await _build_domain_agent_results(
        db,
        current_user=SimpleNamespace(id=uuid.uuid4()),
        job=job,
        threat=SimpleNamespace(id=uuid.uuid4(), threat_model_id=job.threat_model_id),
        plan=_resolve_domain_agent_plan(domain_agents=["sast"]),
        evidence_refs=evidence_refs,
        domain_agent_targets={
            "semgrep": DomainAgentTargetRequest(
                target_type="repository_path",
                target="/tmp/threatgenix-demo-repo",
                authorization_acknowledged=True,
            )
        },
    )

    assert results[0]["tools"][0]["status"] == "authorized"
    assert results[0]["tools"][0]["scan_job_id"]
    assert results[0]["tools"][0]["evidence_refs"] == []
    assert results[0]["evidence_refs"] == []
    assert any(item.__class__.__name__ == "ScanJob" for item in added)


@pytest.mark.asyncio
async def test_domain_agent_runner_rejects_path_targets_outside_allowed_roots(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service
    from app.schemas.threat_agent_orchestration import DomainAgentTargetRequest

    monkeypatch.setattr(service.settings, "agent_controlled_runner_enabled", True)
    monkeypatch.setattr(service, "validation_run_submission_enabled", lambda: True)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/tmp/allowed-agent-targets")

    added = []
    db = SimpleNamespace(add=lambda item: added.append(item), flush=AsyncMock())
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=uuid.uuid4(), inputs={})

    results = await _build_domain_agent_results(
        db,
        current_user=SimpleNamespace(id=uuid.uuid4()),
        job=job,
        threat=SimpleNamespace(id=uuid.uuid4(), threat_model_id=job.threat_model_id),
        plan=_resolve_domain_agent_plan(domain_agents=["sast"]),
        evidence_refs=[],
        domain_agent_targets={
            "semgrep": DomainAgentTargetRequest(
                target_type="repository_path",
                target="/etc",
                authorization_acknowledged=True,
            )
        },
    )

    tool_result = results[0]["tools"][0]
    assert tool_result["status"] == "skipped"
    assert "outside configured allowed roots" in tool_result["skipped_reason"]
    assert not any(item.__class__.__name__ == "ScanJob" for item in added)


@pytest.mark.asyncio
async def test_domain_agent_runner_requires_explicit_target_authorization(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service
    from app.schemas.threat_agent_orchestration import DomainAgentTargetRequest

    monkeypatch.setattr(service.settings, "agent_controlled_runner_enabled", True)
    monkeypatch.setattr(service, "validation_run_submission_enabled", lambda: True)

    added = []
    db = SimpleNamespace(add=lambda item: added.append(item), flush=AsyncMock())
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=uuid.uuid4(), inputs={})

    results = await _build_domain_agent_results(
        db,
        current_user=SimpleNamespace(id=uuid.uuid4()),
        job=job,
        threat=SimpleNamespace(id=uuid.uuid4(), threat_model_id=job.threat_model_id),
        plan=_resolve_domain_agent_plan(domain_agents=["sast"]),
        evidence_refs=[],
        domain_agent_targets={
            "semgrep": DomainAgentTargetRequest(
                target_type="repository_path",
                target="/tmp/threatgenix-demo-repo",
                authorization_acknowledged=False,
            )
        },
    )

    tool_result = results[0]["tools"][0]
    assert tool_result["status"] == "skipped"
    assert "authorization acknowledgment" in tool_result["skipped_reason"]
    assert not any(item.__class__.__name__ == "ScanJob" for item in added)


@pytest.mark.asyncio
async def test_refresh_controlled_scans_rejects_cross_scope_scan_job() -> None:
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    scan_job_id = uuid.uuid4()
    run = SimpleNamespace(
        status="running",
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        application_review_id=uuid.uuid4(),
        evidence_refs=[],
        domain_agent_results=[
            {
                "domain_agent": "sast",
                "label": "SAST Agent",
                "status": "running",
                "tools": [
                    {
                        "tool": "semgrep",
                        "status": "authorized",
                        "scan_job_id": str(scan_job_id),
                        "evidence_refs": [],
                    }
                ],
                "evidence_refs": [],
            }
        ],
        threat=SimpleNamespace(
            display_id="T-001",
            description="Sensitive export route may be missing authorization.",
            threat_subtype="Missing Authorization",
            rule_id="python.flask.security.missing-authorization",
        ),
        orchestration_job=None,
        exploitability={},
        conclusion=None,
        failure_reason=None,
        summary=None,
    )
    cross_scope_job = SimpleNamespace(
        id=scan_job_id,
        owner_id=uuid.uuid4(),
        threat_model_id=threat_model_id,
        status="completed",
        findings=[SimpleNamespace()],
    )

    class _Scalars:
        def all(self):
            return [cross_scope_job]

    class _Result:
        def scalars(self):
            return _Scalars()

    db = SimpleNamespace(
        execute=AsyncMock(return_value=_Result()),
        flush=AsyncMock(),
        refresh=AsyncMock(),
    )

    refreshed = await refresh_validation_run_from_controlled_scans(db, run)

    tool_result = refreshed.domain_agent_results[0]["tools"][0]
    assert tool_result["status"] == "failed"
    assert "tenant and threat model scope" in tool_result["skipped_reason"]
    assert refreshed.evidence_refs == []
    assert refreshed.status == "failed"


def test_validation_requires_more_evidence_without_review() -> None:
    conclusion = evaluate_validation_conclusion(
        has_review=False,
        evidence_refs=[],
        entries=[],
    )

    assert conclusion == "more_evidence_required"


def test_validation_confirms_with_trusted_scanner_evidence() -> None:
    conclusion = evaluate_validation_conclusion(
        has_review=True,
        evidence_refs=[
            {
                "id": str(uuid.uuid4()),
                "item_type": "scanner_finding",
                "content_hash": "a" * 64,
            }
        ],
        entries=[_entry(item_type="scanner_finding", title="Semgrep finding")],
    )

    assert conclusion == "confirmed"


def test_demo_export_route_fixture_confirms_priya_validation_case() -> None:
    fixture = json.loads((FIXTURES_DIR / "priya_export_route_validation.json").read_text())
    threat = SimpleNamespace(
        display_id="T-DEMO-001",
        description=fixture["threat"]["description"],
        threat_subtype="Missing Authorization",
        rule_id="python.flask.security.missing-authorization",
    )
    entries = [_entry_from_fixture(item) for item in fixture["entries"]]
    exploitability = build_exploitability_assessment(
        has_review=True,
        threat=threat,
        evidence_refs=fixture["evidence_refs"],
        entries=entries,
    )

    conclusion = evaluate_validation_conclusion(
        has_review=True,
        evidence_refs=fixture["evidence_refs"],
        entries=entries,
        exploitability=exploitability,
    )

    assert fixture["threat"]["description"] == "Sensitive export route may be missing authorization."
    assert fixture["evidence_refs"][0]["source_refs"][0]["path"] == "backend/app/api/exports.py"
    assert exploitability.status == "exploitable"
    assert exploitability.attacker_profile == "authenticated low-privilege tenant user"
    assert exploitability.confidence == "high"
    assert "scoped export authorization" in " ".join(exploitability.preconditions).casefold()
    assert conclusion == "confirmed"


def test_blocking_control_marks_validation_not_supported() -> None:
    threat = SimpleNamespace(
        display_id="T-CTRL-001",
        description="Sensitive export route may be missing authorization.",
        threat_subtype="Missing Authorization",
        rule_id=None,
    )
    entries = [
        _entry(
            item_type="scanner_finding",
            title="Scanner signal with compensating control",
            body="Authorization guard present through policy middleware and blocked by control.",
        )
    ]
    evidence_refs = [
        {
            "id": str(uuid.uuid4()),
            "item_type": "scanner_finding",
            "content_hash": "b" * 64,
            "source_refs": [{"path": "backend/app/api/exports.py"}],
        }
    ]
    exploitability = build_exploitability_assessment(
        has_review=True,
        threat=threat,
        evidence_refs=evidence_refs,
        entries=entries,
    )

    conclusion = evaluate_validation_conclusion(
        has_review=True,
        evidence_refs=evidence_refs,
        entries=entries,
        exploitability=exploitability,
    )

    assert exploitability.status == "blocked_by_control"
    assert conclusion == "not_supported"


def test_validation_routes_conflicting_evidence_to_human_review() -> None:
    conclusion = evaluate_validation_conclusion(
        has_review=True,
        evidence_refs=[
            {
                "id": str(uuid.uuid4()),
                "item_type": "scanner_finding",
                "content_hash": "a" * 64,
            }
        ],
        entries=[
            _entry(
                item_type="scanner_finding",
                title="Conflicting scanner evidence",
                body="A compensating control may exist.",
            )
        ],
    )

    assert conclusion == "needs_human_review"


@pytest.mark.asyncio
async def test_fallback_model_adapter_drafts_code_fix_without_truth_claims() -> None:
    adapter = DeterministicFallbackAgentModelAdapter()

    result = await adapter.generate_structured(
        agent_type="code_fix",
        context_packet={
            "threat": {
                "display_id": "T-001",
                "description": "Sensitive export route may be missing authorization.",
            },
            "evidence_refs": [
                {
                    "source_refs": [{"path": "src/api/exports.py"}],
                }
            ],
        },
        output_schema={},
    )

    payload = validate_agent_model_payload(result.payload)
    assert result.deterministic_fallback_used is True
    assert result.model_output_hash
    assert "src/api/exports.py" in payload["ticket_draft"]["body"]
    assert "validated as fixed" not in str(payload).casefold()


def test_model_payload_rejects_prohibited_truth_claims() -> None:
    with pytest.raises(ValueError, match="prohibited truth claim"):
        validate_agent_model_payload(
            {
                "summary": "This is secure.",
                "patch_preview": "done",
                "ticket_draft": {"title": "Draft ticket", "body": "Draft only."},
                "pr_draft": {"title": "Draft PR", "body": "Draft only."},
            }
        )


def test_model_payload_rejects_malformed_nested_drafts() -> None:
    with pytest.raises(ValueError, match="ticket_draft must be an object"):
        validate_agent_model_payload(
            {
                "summary": "Draft only.",
                "patch_preview": "Add authorization before export.",
                "ticket_draft": None,
                "pr_draft": {"title": "Draft", "body": "Draft only."},
            }
        )

    with pytest.raises(ValueError, match="pr_draft.body must be a non-empty string"):
        validate_agent_model_payload(
            {
                "summary": "Draft only.",
                "patch_preview": "Add authorization before export.",
                "ticket_draft": {"title": "Draft", "body": "Draft only."},
                "pr_draft": {"title": "Draft"},
            }
        )


def test_model_payload_normalizes_json_string_nested_drafts() -> None:
    payload = validate_agent_model_payload(
        {
            "summary": "Draft only.",
            "patch_preview": "Add authorization and security controls before export.",
            "ticket_draft": json.dumps(
                {
                    "title": "Draft ticket",
                    "body": "Draft only.",
                    "labels": ["security"],
                }
            ),
            "pr_draft": json.dumps(
                {
                    "title": "Draft PR",
                    "body": "Draft only.",
                    "target_files": ["backend/app/api/exports.py"],
                }
            ),
        }
    )

    assert payload["ticket_draft"]["labels"] == ["security"]
    assert payload["pr_draft"]["target_files"] == ["backend/app/api/exports.py"]


@pytest.mark.parametrize(
    "claim",
    [
        "This issue is fixed.",
        "The app is safe to deploy.",
        "The risk is accepted.",
        "Scanner verified remediation.",
        "This is compliant.",
        "No risk remains.",
    ],
)
def test_model_payload_rejects_overclaim_synonyms(claim: str) -> None:
    with pytest.raises(ValueError, match="prohibited truth claim"):
        validate_agent_model_payload(
            {
                "summary": claim,
                "patch_preview": "draft only",
                "ticket_draft": {"title": "Draft ticket", "body": "Draft only."},
                "pr_draft": {"title": "Draft PR", "body": "Draft only."},
            }
        )


def test_default_agent_model_adapter_respects_live_model_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orchestration_service.settings, "agent_model_drafting_enabled", False)
    monkeypatch.setattr(orchestration_service.settings, "audit_force_ai_unavailable", False)

    assert isinstance(
        orchestration_service._default_agent_model_adapter(),
        DeterministicFallbackAgentModelAdapter,
    )

    monkeypatch.setattr(orchestration_service.settings, "agent_model_drafting_enabled", True)
    monkeypatch.setattr(orchestration_service.settings, "agent_model_drafting_timeout_seconds", 42.5)
    live_adapter = orchestration_service._default_agent_model_adapter()
    assert isinstance(live_adapter, LLMAgentModelAdapter)
    assert live_adapter._timeout_seconds == 42.5

    monkeypatch.setattr(orchestration_service.settings, "audit_force_ai_unavailable", True)
    assert isinstance(
        orchestration_service._default_agent_model_adapter(),
        DeterministicFallbackAgentModelAdapter,
    )


@pytest.mark.asyncio
async def test_remediation_drafting_requires_confirmed_or_human_review_validation() -> None:
    validation_run = SimpleNamespace(
        id=uuid.uuid4(),
        conclusion="more_evidence_required",
        threat=SimpleNamespace(id=uuid.uuid4()),
    )
    current_user = SimpleNamespace(id=uuid.uuid4(), organization_id=None)

    with pytest.raises(ThreatAgentOrchestrationError, match="confirmed validation"):
        await create_threat_remediation_run(
            SimpleNamespace(),
            current_user=current_user,
            validation_run=validation_run,
            agent_type="code_fix",
        )


@pytest.mark.asyncio
async def test_github_issue_handoff_requires_token_and_repository(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service

    monkeypatch.setattr(service.settings, "agent_github_handoff_enabled", True)
    run = SimpleNamespace(
        id=uuid.uuid4(),
        status="awaiting_confirmation",
        handoff_delivery_status="recorded",
        external_ticket_id=None,
        external_ticket_url=None,
        external_pr_url=None,
        evidence_refs=[],
        orchestration_job=None,
        threat=None,
        ticket_draft={"title": "Fix export route", "body": "Evidence-backed draft."},
        fix_summary="Add export authorization.",
        patch_preview="backend/app/api/exports.py",
        threat_id=uuid.uuid4(),
    )
    db = SimpleNamespace(add=lambda _item: None, flush=AsyncMock(), refresh=AsyncMock())
    current_user = SimpleNamespace(id=uuid.uuid4())

    with pytest.raises(ThreatAgentOrchestrationError, match="github_repository"):
        await confirm_remediation_handoff(
            db,
            current_user=current_user,
            run=run,
            body=ThreatRemediationHandoffConfirmRequest(
                confirmed=True,
                provider="github_issue",
                access_token="github-token",
            ),
        )

    with pytest.raises(ThreatAgentOrchestrationError, match="access token"):
        await confirm_remediation_handoff(
            db,
            current_user=current_user,
            run=run,
            body=ThreatRemediationHandoffConfirmRequest(
                confirmed=True,
                provider="github_issue",
                github_repository="northstar/export-api",
            ),
        )


@pytest.mark.asyncio
async def test_github_issue_handoff_delivers_with_connector_without_persisting_token(
    monkeypatch,
) -> None:
    from app.services import threat_agent_orchestration as service

    async def fake_create_ticket(*, body, action):
        assert body.access_token.get_secret_value() == "github-token"
        assert body.github_repository == "northstar/export-api"
        assert action.ticket_draft.title == "Fix export route"
        return SimpleNamespace(
            external_ticket_id="#42",
            external_ticket_url="https://github.com/northstar/export-api/issues/42",
        )

    monkeypatch.setattr(service.settings, "agent_github_handoff_enabled", True)
    monkeypatch.setattr(service, "create_remediation_provider_ticket", fake_create_ticket)
    run = SimpleNamespace(
        id=uuid.uuid4(),
        status="awaiting_confirmation",
        handoff_delivery_status="recorded",
        handoff_provider=None,
        handoff_error=None,
        handoff_idempotency_key=None,
        external_ticket_id=None,
        external_ticket_url=None,
        external_pr_url=None,
        evidence_refs=[],
        orchestration_job=None,
        threat=None,
        ticket_draft={"title": "Fix export route", "body": "Evidence-backed draft."},
        fix_summary="Add export authorization.",
        patch_preview="backend/app/api/exports.py",
        threat_id=uuid.uuid4(),
    )
    db = SimpleNamespace(add=lambda _item: None, flush=AsyncMock(), refresh=AsyncMock())
    current_user = SimpleNamespace(id=uuid.uuid4())

    updated = await confirm_remediation_handoff(
        db,
        current_user=current_user,
        run=run,
        body=ThreatRemediationHandoffConfirmRequest(
            confirmed=True,
            provider="github_issue",
            github_repository="northstar/export-api",
            access_token="github-token",
            handoff_idempotency_key="validation-1:code-fix",
        ),
    )

    assert updated.status == "handoff_created"
    assert updated.handoff_delivery_status == "delivered"
    assert updated.external_ticket_id == "#42"
    assert updated.external_ticket_url == "https://github.com/northstar/export-api/issues/42"
    assert updated.handoff_idempotency_key == "validation-1:code-fix"
    assert not hasattr(updated, "access_token")


@pytest.mark.asyncio
async def test_github_issue_handoff_idempotency_reuses_same_key_and_rejects_conflict() -> None:
    run = SimpleNamespace(
        id=uuid.uuid4(),
        status="handoff_created",
        handoff_delivery_status="delivered",
        handoff_provider="github_issue",
        handoff_error=None,
        handoff_idempotency_key="validation-1:code-fix",
        external_ticket_id="#42",
        external_ticket_url="https://github.com/northstar/export-api/issues/42",
        external_pr_url=None,
        evidence_refs=[],
        orchestration_job=None,
        threat=None,
        ticket_draft={"title": "Fix export route", "body": "Evidence-backed draft."},
        fix_summary="Add export authorization.",
        patch_preview="backend/app/api/exports.py",
        threat_id=uuid.uuid4(),
    )
    db = SimpleNamespace(add=lambda _item: None, flush=AsyncMock(), refresh=AsyncMock())
    current_user = SimpleNamespace(id=uuid.uuid4())

    reused = await confirm_remediation_handoff(
        db,
        current_user=current_user,
        run=run,
        body=ThreatRemediationHandoffConfirmRequest(
            confirmed=True,
            provider="github_issue",
            github_repository="northstar/export-api",
            access_token="github-token",
            handoff_idempotency_key="validation-1:code-fix",
        ),
    )

    assert reused.external_ticket_id == "#42"
    assert reused.handoff_idempotency_key == "validation-1:code-fix"

    with pytest.raises(ThreatAgentOrchestrationError, match="different idempotency key"):
        await confirm_remediation_handoff(
            db,
            current_user=current_user,
            run=run,
            body=ThreatRemediationHandoffConfirmRequest(
                confirmed=True,
                provider="github_issue",
                github_repository="northstar/export-api",
                access_token="github-token",
                handoff_idempotency_key="different-key",
            ),
        )
    assert run.handoff_idempotency_key == "validation-1:code-fix"


@pytest.mark.asyncio
async def test_github_issue_handoff_failure_does_not_mark_delivered(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service
    from app.services.remediation_connectors import RemediationConnectorError

    async def fake_create_ticket(*, body, action):
        raise RemediationConnectorError("GitHub Issue creation returned HTTP 403.")

    monkeypatch.setattr(service.settings, "agent_github_handoff_enabled", True)
    monkeypatch.setattr(service, "create_remediation_provider_ticket", fake_create_ticket)
    run = SimpleNamespace(
        id=uuid.uuid4(),
        status="awaiting_confirmation",
        handoff_delivery_status="recorded",
        handoff_provider=None,
        handoff_error=None,
        handoff_idempotency_key=None,
        external_ticket_id=None,
        external_ticket_url=None,
        external_pr_url=None,
        evidence_refs=[],
        orchestration_job=None,
        threat=None,
        ticket_draft={"title": "Fix export route", "body": "Evidence-backed draft."},
        fix_summary="Add export authorization.",
        patch_preview="backend/app/api/exports.py",
        threat_id=uuid.uuid4(),
    )
    db = SimpleNamespace(add=lambda _item: None, flush=AsyncMock(), refresh=AsyncMock())
    current_user = SimpleNamespace(id=uuid.uuid4())

    updated = await confirm_remediation_handoff(
        db,
        current_user=current_user,
        run=run,
        body=ThreatRemediationHandoffConfirmRequest(
            confirmed=True,
            provider="github_issue",
            github_repository="northstar/export-api",
            access_token="github-token",
        ),
    )

    assert updated.status == "awaiting_confirmation"
    assert updated.handoff_delivery_status == "failed"
    assert updated.external_ticket_id is None
    assert "HTTP 403" in updated.handoff_error


@pytest.mark.asyncio
async def test_rerun_routes_remediation_evidence_to_human_review(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service

    new_run = SimpleNamespace(
        id=uuid.uuid4(),
        evidence_refs=[],
        exploitability={
            "status": "exploitable",
            "confidence": "high",
            "rationale": "Prior scanner evidence supported the path.",
        },
        conclusion="confirmed",
        summary="Prior validation summary.",
        orchestration_job=SimpleNamespace(id=uuid.uuid4(), threat_model_id=uuid.uuid4()),
    )
    prior_run = SimpleNamespace(
        id=uuid.uuid4(),
        threat=SimpleNamespace(
            id=uuid.uuid4(),
            display_id="T-DEMO-001",
            threat_model_id=uuid.uuid4(),
        ),
        application_review_id=None,
        requested_tools=["semgrep"],
        question="Validate sensitive export route authorization.",
    )
    remediation_ref = {
        "type": "remediation_evidence",
        "title": "Confirmed handoff evidence",
        "evidence_summary": "Ticket SEC-123 has the scoped authorization remediation attached.",
    }

    async def fake_create(*args, **kwargs):
        return new_run

    async def fake_remediation_evidence(*args, **kwargs):
        return [remediation_ref]

    async def fake_integrity_check(*args, **kwargs):
        return []

    monkeypatch.setattr(service, "create_threat_validation_run", fake_create)
    monkeypatch.setattr(service, "_remediation_evidence_for_validation", fake_remediation_evidence)
    monkeypatch.setattr(service, "verify_validation_evidence_integrity", fake_integrity_check)

    db = SimpleNamespace(
        add=lambda _event: None,
        flush=AsyncMock(),
        refresh=AsyncMock(),
    )
    current_user = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4())

    rerun = await rerun_threat_validation(db, current_user=current_user, run=prior_run)

    assert rerun.conclusion == "needs_human_review"
    assert rerun.exploitability["status"] == "conflicting_evidence"
    assert rerun.evidence_refs == [remediation_ref]
    assert "fresh code or scanner signal" in rerun.summary
