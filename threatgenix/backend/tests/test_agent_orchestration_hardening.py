from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import database
from app.services.agent_model_adapter import AgentModelResult, LLMAgentModelAdapter
from app.services.agent_orchestration_hardening import (
    AgentProbeRateLimitExceeded,
    EvidenceIntegrityFinding,
    NoMutationRuntimeMonitor,
    NoMutationViolation,
    agent_event_payload_hash,
    build_agent_audit_export,
    compare_model_adapter_outputs,
    enforce_validation_probe_rate_limit,
    reset_validation_probe_rate_limit_state,
    validate_iac_draft_artifact,
    verify_agent_audit_export,
    verify_validation_evidence_integrity,
)
from app.services.threat_agent_orchestration import ThreatAgentOrchestrationError, create_threat_remediation_run


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeDb:
    def __init__(self, value=None):
        self.value = value
        self.added = []

    async def execute(self, _stmt):
        return _ScalarResult(self.value)

    def add(self, value):
        self.added.append(value)


class _FakeScanDb(_FakeDb):
    def __init__(self, *, finding, scan_job):
        super().__init__(None)
        self.finding = finding
        self.scan_job = scan_job

    async def get(self, model, row_id):
        if model.__name__ == "ScanFinding" and row_id == self.finding.id:
            return self.finding
        if model.__name__ == "ScanJob" and row_id == self.scan_job.id:
            return self.scan_job
        return None


def _matching_evidence_pair():
    evidence_id = uuid.uuid4()
    review_id = uuid.uuid4()
    ref = {
        "id": str(evidence_id),
        "review_id": str(review_id),
        "source_type": "scan_finding",
        "item_type": "scanner_finding",
        "title": "Missing auth",
        "content_hash": "a" * 64,
        "source_refs": [{"path": "backend/app/api/exports.py", "line": 8}],
        "status": "active",
    }
    entry = SimpleNamespace(
        id=evidence_id,
        tenant_key="tenant-a",
        review_id=review_id,
        source_type="scan_finding",
        item_type="scanner_finding",
        title="Missing auth",
        content_hash="a" * 64,
        source_refs=[{"path": "backend/app/api/exports.py", "line": 8}],
        status="active",
    )
    run = SimpleNamespace(
        tenant_key="tenant-a",
        application_review_id=review_id,
        evidence_refs=[ref],
    )
    return run, entry, ref


@pytest.mark.asyncio
async def test_evidence_integrity_accepts_active_matching_context_entry() -> None:
    run, entry, _ref = _matching_evidence_pair()

    findings = await verify_validation_evidence_integrity(_FakeDb(entry), run)

    assert findings == []


@pytest.mark.asyncio
async def test_evidence_integrity_detects_tampered_hash_and_source_refs() -> None:
    run, entry, ref = _matching_evidence_pair()
    ref["content_hash"] = "b" * 64
    ref["source_refs"] = [{"path": "backend/app/api/other.py", "line": 99}]

    findings = await verify_validation_evidence_integrity(_FakeDb(entry), run)

    finding_ids = {finding.finding_id for finding in findings}
    assert "evidence_content_hash_mismatch" in finding_ids
    assert "evidence_source_refs_mismatch" in finding_ids


@pytest.mark.asyncio
async def test_evidence_integrity_keeps_seeded_scanner_context_on_context_path() -> None:
    run, entry, ref = _matching_evidence_pair()
    ref["source_object_id"] = str(uuid.uuid4())

    findings = await verify_validation_evidence_integrity(_FakeDb(entry), run)

    assert findings == []


@pytest.mark.asyncio
async def test_evidence_integrity_accepts_real_scan_finding_ref() -> None:
    finding_id = uuid.uuid4()
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    owner_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        scan_job_id=scan_job_id,
        validation_metadata={"output_sha256": "c" * 64},
    )
    scan_job = SimpleNamespace(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        status="completed",
    )
    run = SimpleNamespace(
        tenant_key="tenant-a",
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        application_review_id=uuid.uuid4(),
        evidence_refs=[
            {
                "id": str(finding_id),
                "source_type": "scan_finding",
                "source_object_id": str(scan_job_id),
                "item_type": "scanner_finding",
                "content_hash": "c" * 64,
                "source_refs": [{"scan_job_id": str(scan_job_id), "tool": "semgrep"}],
            }
        ],
    )

    findings = await verify_validation_evidence_integrity(
        _FakeScanDb(finding=finding, scan_job=scan_job),
        run,
    )

    assert findings == []


@pytest.mark.asyncio
async def test_evidence_integrity_rejects_cross_owner_scan_finding_ref() -> None:
    finding_id = uuid.uuid4()
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        scan_job_id=scan_job_id,
        validation_metadata={"output_sha256": "c" * 64},
    )
    scan_job = SimpleNamespace(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=uuid.uuid4(),
        status="completed",
    )
    run = SimpleNamespace(
        tenant_key="tenant-a",
        threat_model_id=threat_model_id,
        owner_id=uuid.uuid4(),
        application_review_id=uuid.uuid4(),
        evidence_refs=[
            {
                "id": str(finding_id),
                "source_type": "scan_finding",
                "source_object_id": str(scan_job_id),
                "item_type": "scanner_finding",
                "content_hash": "b" * 64,
                "source_refs": [{"scan_job_id": str(uuid.uuid4()), "tool": "semgrep"}],
            }
        ],
    )

    findings = await verify_validation_evidence_integrity(
        _FakeScanDb(finding=finding, scan_job=scan_job),
        run,
    )

    finding_ids = {finding.finding_id for finding in findings}
    assert "scan_job_owner_mismatch" in finding_ids
    assert "scan_content_hash_mismatch" in finding_ids
    assert "scan_source_ref_job_mismatch" in finding_ids


def test_audit_export_verifier_detects_tampered_record() -> None:
    event_payload = {"agent_event": "validation.concluded", "conclusion": "confirmed"}
    event_payload["event_payload_hash"] = agent_event_payload_hash(
        event_type="completed",
        level="info",
        message="Validation concluded as confirmed.",
        payload=event_payload,
    )
    event = SimpleNamespace(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        task_id=None,
        threat_model_id=uuid.uuid4(),
        event_type="completed",
        level="info",
        message="Validation concluded as confirmed.",
        payload=event_payload,
        created_at=datetime.now(timezone.utc),
    )

    export = build_agent_audit_export([event])
    assert verify_agent_audit_export(export) == []

    export["records"][0]["message"] = "Validation concluded as secure."
    findings = verify_agent_audit_export(export)

    assert {finding["finding_id"] for finding in findings} >= {
        "audit_payload_hash_mismatch",
        "audit_event_hash_mismatch",
    }


@pytest.mark.asyncio
async def test_model_comparison_uses_deterministic_fallback_when_no_provider_is_configured() -> None:
    comparison = await compare_model_adapter_outputs(
        agent_type="code_fix",
        context_packet={"threat": {"display_id": "T-001", "description": "Missing authorization."}},
        output_schema={},
    )

    assert comparison["fallback_required"] is True
    assert comparison["providers_configured"] == []
    assert comparison["all_outputs_schema_valid"] is True
    assert comparison["results"][0]["provider"] == "deterministic_fallback"


@pytest.mark.asyncio
async def test_model_comparison_rejects_provider_overclaim_but_keeps_fallback() -> None:
    class OverclaimingAdapter:
        async def generate_structured(self, **_kwargs):
            return AgentModelResult(
                payload={
                    "summary": "The app is secure.",
                    "patch_preview": "No work.",
                    "ticket_draft": {},
                    "pr_draft": {},
                },
                model_provider="test-provider",
                model_name="bad-model",
                deterministic_fallback_used=False,
            )

    comparison = await compare_model_adapter_outputs(
        agent_type="code_fix",
        context_packet={"threat": {"display_id": "T-001", "description": "Missing authorization."}},
        output_schema={},
        adapters={"bad-provider": OverclaimingAdapter()},
    )

    assert comparison["all_outputs_schema_valid"] is False
    assert comparison["results"][0]["status"] == "failed"
    assert comparison["results"][1]["provider"] == "deterministic_fallback"
    assert comparison["results"][1]["status"] == "schema_valid"


@pytest.mark.asyncio
async def test_llm_agent_adapter_falls_back_when_provider_returns_no_payload() -> None:
    class EmptyClient:
        provider_name = "empty"
        model_name = "empty-model"

        def call_with_tools(self, *_args, **_kwargs):
            return None

    result = await LLMAgentModelAdapter(llm_client=EmptyClient()).generate_structured(
        agent_type="code_fix",
        context_packet={"threat": {"display_id": "T-001", "description": "Missing authorization."}},
        output_schema={},
    )

    assert result.deterministic_fallback_used is True
    assert result.model_output_hash


@pytest.mark.asyncio
async def test_llm_agent_adapter_retries_malformed_provider_output() -> None:
    class RepairableClient:
        provider_name = "repairable"
        model_name = "repairable-model"

        def __init__(self) -> None:
            self.calls = 0

        def call_with_tools(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                return {
                    "summary": "Draft only.",
                    "patch_preview": "Add authorization before export.",
                    "ticket_draft": None,
                    "pr_draft": {"title": "Draft", "body": "Draft only."},
                }
            return {
                "summary": "Draft only.",
                "patch_preview": "Add authorization before export.",
                "ticket_draft": {"title": "Draft ticket", "body": "Draft only."},
                "pr_draft": {"title": "Draft PR", "body": "Draft only.", "target_files": []},
            }

    client = RepairableClient()
    result = await LLMAgentModelAdapter(llm_client=client).generate_structured(
        agent_type="code_fix",
        context_packet={"threat": {"display_id": "T-001", "description": "Missing authorization."}},
        output_schema={},
    )

    assert client.calls == 2
    assert result.deterministic_fallback_used is False
    assert result.model_provider == "repairable"
    assert result.payload["ticket_draft"]["title"] == "Draft ticket"


def test_no_mutation_monitor_blocks_direct_runtime_mutation() -> None:
    monitor = NoMutationRuntimeMonitor()
    monitor.record("draft_ticket", target="manual")

    with pytest.raises(NoMutationViolation):
        monitor.record("terraform apply", target="prod")


def test_iac_draft_validation_accepts_least_privilege_terraform_snippet() -> None:
    result = validate_iac_draft_artifact(
        path="main.tf",
        content='variable "allowed_cidr" {\n  type = string\n}\n',
    )

    assert result.valid is True
    assert result.artifact_type == "terraform"


def test_iac_draft_validation_rejects_broad_public_ingress() -> None:
    result = validate_iac_draft_artifact(
        path="main.tf",
        content='''
resource "aws_security_group_rule" "bad" {
  type = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}
''',
    )

    assert result.valid is False
    assert "broad public ingress" in " ".join(result.diagnostics)


def test_validation_probe_rate_limit_blocks_repeated_same_threat_probe() -> None:
    reset_validation_probe_rate_limit_state()
    threat_id = uuid.uuid4()
    enforce_validation_probe_rate_limit(tenant_key="tenant-a", threat_id=threat_id, now=100.0, limit=2)
    enforce_validation_probe_rate_limit(tenant_key="tenant-a", threat_id=threat_id, now=101.0, limit=2)

    with pytest.raises(AgentProbeRateLimitExceeded):
        enforce_validation_probe_rate_limit(tenant_key="tenant-a", threat_id=threat_id, now=102.0, limit=2)

    reset_validation_probe_rate_limit_state()


@pytest.mark.asyncio
async def test_get_db_rolls_back_when_endpoint_raises(monkeypatch) -> None:
    class FakeSession:
        def __init__(self):
            self.rollback_count = 0

        async def rollback(self):
            self.rollback_count += 1

    class FakeContext:
        def __init__(self, session):
            self.session = session

        async def __aenter__(self):
            return self.session

        async def __aexit__(self, *_args):
            return None

    session = FakeSession()
    monkeypatch.setattr(database, "async_session", lambda: FakeContext(session))
    generator = database.get_db()
    yielded = await generator.__anext__()
    assert yielded is session

    with pytest.raises(RuntimeError):
        await generator.athrow(RuntimeError("boom"))

    assert session.rollback_count == 1


@pytest.mark.asyncio
async def test_remediation_drafting_rejects_tampered_validation_evidence(monkeypatch) -> None:
    from app.services import threat_agent_orchestration as service

    async def fake_integrity_check(*_args, **_kwargs):
        return [
            EvidenceIntegrityFinding(
                finding_id="evidence_content_hash_mismatch",
                evidence_id=str(uuid.uuid4()),
                reason="hash mismatch",
            )
        ]

    monkeypatch.setattr(service, "verify_validation_evidence_integrity", fake_integrity_check)
    validation_run = SimpleNamespace(
        id=uuid.uuid4(),
        conclusion="confirmed",
        threat=SimpleNamespace(id=uuid.uuid4()),
        evidence_refs=[{"id": str(uuid.uuid4()), "content_hash": "a" * 64}],
    )
    current_user = SimpleNamespace(id=uuid.uuid4(), organization_id=None)

    with pytest.raises(ThreatAgentOrchestrationError, match="integrity check failed"):
        await create_threat_remediation_run(
            _FakeDb(),
            current_user=current_user,
            validation_run=validation_run,
            agent_type="code_fix",
        )
