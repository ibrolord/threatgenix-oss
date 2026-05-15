from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.api.validation_lab import create_validation_schedule
from app.models.dfd import DFDNode
from app.models.scan import (
    ScanExecutionArtifact,
    ScanFinding,
    ScanJob,
    ValidationCaseEvent,
    ValidationCaseState,
    ValidationSchedule,
)
from app.schemas.scan import (
    ValidationRunbookCoverageResponse,
    ValidationRunbookFindingResponse,
    ValidationRunbookResponse,
    ValidationRunbookThreatResponse,
)
from app.schemas.validation_lab import (
    ProductSecurityValidationCaseResponse,
    ValidationCaseStateUpdateRequest,
    ValidationScheduleCreateRequest,
)
from app.services.validation_lab import (
    bind_validation_evidence_to_node,
    build_product_security_cases,
    create_try_sandbox_scan,
    merge_product_security_case_state,
    next_run_at_for_cadence,
    update_product_security_case_state,
    validation_schedule_response,
)
from app.services.validation_sandbox import VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV


class FakeUser:
    id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    email = "test@example.com"


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def one_or_none(self):
        return self._value


class FakeDB:
    def __init__(self, execute_values: list[object] | None = None) -> None:
        self.added: list[object] = []
        self.execute_values = execute_values or [
            SimpleNamespace(
                owner_id=FakeUser.id,
                collaborators=None,
            )
        ]
        self.committed = False

    async def execute(self, statement):
        del statement
        return _Result(self.execute_values.pop(0))

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, obj: object) -> None:
        now = datetime(2026, 4, 26, tzinfo=timezone.utc)
        if getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        if getattr(obj, "created_at", None) is None:
            obj.created_at = now
        if getattr(obj, "updated_at", None) is None:
            obj.updated_at = now


def test_next_run_at_for_cadence_returns_expected_offsets():
    now = datetime(2026, 4, 26, tzinfo=timezone.utc)

    assert next_run_at_for_cadence("manual", from_time=now) is None
    assert next_run_at_for_cadence("daily", from_time=now).day == 27
    assert next_run_at_for_cadence("weekly", from_time=now).day == 3
    assert next_run_at_for_cadence("monthly", from_time=now).month == 5


def test_validation_schedule_response_blocks_path_tools_without_allowed_roots(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.delenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", raising=False)
    monkeypatch.delenv("VALIDATION_SCAN_ALLOWED_PATHS", raising=False)
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        scope="external",
        cadence="weekly",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
        response = validation_schedule_response(schedule)

    assert response.runnable is False
    assert response.blocked_reason
    assert "allowed root" in response.blocked_reason


def test_validation_schedule_response_blocks_path_outside_allowed_roots(monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(allowed))
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target=str(outside),
        scope="external",
        cadence="weekly",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
        response = validation_schedule_response(schedule)

    assert response.runnable is False
    assert "outside configured allowed roots" in (response.blocked_reason or "")


def test_validation_schedule_response_blocks_unsafe_live_url(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="External Nuclei",
        tool_name="nuclei",
        target_type="url",
        target="http://127.0.0.1:8080",
        scope="external",
        cadence="weekly",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    response = validation_schedule_response(schedule)

    assert response.runnable is False
    assert "loopback" in (response.blocked_reason or "")


def test_validation_schedule_response_blocks_advisory_db_tools_without_container(
    monkeypatch, tmp_path
):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "process")
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Dependency SCA",
        tool_name="osv-scanner",
        target_type="lockfile",
        target=str(lockfile),
        scope="external",
        cadence="manual",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    with patch("shutil.which", return_value="/usr/local/bin/osv-scanner"):
        response = validation_schedule_response(schedule)

    assert response.runnable is False
    assert "advisory_db network policy" in (response.blocked_reason or "")


def test_validation_schedule_response_allows_advisory_db_tools_with_local_opt_in(
    monkeypatch, tmp_path
):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "process")
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Dependency SCA",
        tool_name="osv-scanner",
        target_type="lockfile",
        target=str(lockfile),
        scope="external",
        cadence="manual",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    with patch("shutil.which", return_value="/usr/local/bin/osv-scanner"):
        response = validation_schedule_response(schedule)

    assert response.runnable is True
    assert response.blocked_reason is None


def test_validation_schedule_response_rejects_advisory_db_opt_in_in_production(
    monkeypatch, tmp_path
):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "process")
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Dependency SCA",
        tool_name="osv-scanner",
        target_type="lockfile",
        target=str(lockfile),
        scope="external",
        cadence="manual",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    with patch("shutil.which", return_value="/usr/local/bin/osv-scanner"):
        response = validation_schedule_response(schedule)

    assert response.runnable is False
    assert "advisory_db network policy" in (response.blocked_reason or "")


def test_validation_schedule_response_blocks_managed_process_target_network(
    monkeypatch,
):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "process")
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="External Nuclei",
        tool_name="nuclei",
        target_type="url",
        target="https://api.example.com",
        scope="external",
        cadence="manual",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    with patch("shutil.which", return_value="/usr/local/bin/nuclei"):
        response = validation_schedule_response(schedule)

    assert response.runnable is False
    assert "target_only network policy" in (response.blocked_reason or "")


@pytest.mark.asyncio
async def test_create_validation_schedule_requires_authorization_acknowledgement(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    db = FakeDB()
    body = ValidationScheduleCreateRequest(
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=False,
    )

    with pytest.raises(HTTPException) as exc:
        await create_validation_schedule(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc.value.status_code == 400
    assert db.added == []


@pytest.mark.asyncio
async def test_create_validation_schedule_persists_policy_checked_target(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    db = FakeDB()
    threat_model_id = uuid.uuid4()
    body = ValidationScheduleCreateRequest(
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target=str(repo),
        cadence="weekly",
        enabled=True,
        authorization_acknowledged=True,
    )

    response = await create_validation_schedule(
        threat_model_id,
        body,
        db,  # type: ignore[arg-type]
        FakeUser(),  # type: ignore[arg-type]
    )

    assert db.committed is True
    assert response.threat_model_id == threat_model_id
    assert response.tool_name == "semgrep"
    assert response.target_type == "repository_path"
    assert response.next_run_at is not None
    assert any(isinstance(item, ValidationSchedule) for item in db.added)


@pytest.mark.asyncio
async def test_create_validation_schedule_rejects_unsafe_live_url(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    db = FakeDB()
    body = ValidationScheduleCreateRequest(
        name="External Nuclei",
        tool_name="nuclei",
        target_type="url",
        target="http://127.0.0.1:8080",
        authorization_acknowledged=True,
    )

    with pytest.raises(HTTPException) as exc:
        await create_validation_schedule(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc.value.status_code == 422
    assert "loopback" in exc.value.detail
    assert db.added == []


@pytest.mark.asyncio
async def test_create_validation_schedule_blocks_live_execution_in_try_sandbox(monkeypatch):
    monkeypatch.delenv("THREATGENIX_VALIDATION_RUNTIME_MODE", raising=False)
    db = FakeDB()
    body = ValidationScheduleCreateRequest(
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=True,
    )

    with pytest.raises(HTTPException) as exc:
        await create_validation_schedule(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc.value.status_code == 403
    assert "Try Sandbox" in exc.value.detail
    assert db.added == []


@pytest.mark.asyncio
async def test_create_validation_schedule_blocks_api_local_execution_in_managed_mode(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.delenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", raising=False)
    db = FakeDB()
    body = ValidationScheduleCreateRequest(
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=True,
    )

    with pytest.raises(HTTPException) as exc:
        await create_validation_schedule(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc.value.status_code == 403
    assert "Managed validation runner is not enabled" in exc.value.detail
    assert db.added == []


@pytest.mark.asyncio
async def test_create_validation_schedule_allows_managed_runner_queue(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    repo = tmp_path / "worker-staged-repo"
    db = FakeDB()
    body = ValidationScheduleCreateRequest(
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target=str(repo),
        authorization_acknowledged=True,
    )

    schedule = await create_validation_schedule(
        uuid.uuid4(),
        body,
        db,  # type: ignore[arg-type]
        FakeUser(),  # type: ignore[arg-type]
    )

    assert db.committed is True
    assert schedule.tool_name == "semgrep"
    assert schedule.target == str(repo)
    assert any(isinstance(item, ValidationSchedule) for item in db.added)


@pytest.mark.asyncio
async def test_create_try_sandbox_scan_persists_ingest_artifact(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr("app.services.validation_lab.run_semantic_mapping", _noop_mapping)

    scan = await create_try_sandbox_scan(
        db,  # type: ignore[arg-type]
        uuid.uuid4(),
        FakeUser(),  # type: ignore[arg-type]
    )

    artifact = next(item for item in db.added if isinstance(item, ScanExecutionArtifact))
    assert isinstance(scan, ScanJob)
    assert db.committed is True
    assert scan.tool_name == "semgrep"
    assert artifact.source == "ingest"
    assert artifact.sandbox_mode == "try_sandbox"
    assert artifact.policy_decision == "curated try-sandbox evidence; no scanner executed"
    finding = next(item for item in db.added if isinstance(item, ScanFinding))
    assert finding.evidence_origin == "try_sandbox"
    assert finding.synthetic is True


@pytest.mark.asyncio
async def test_bind_validation_evidence_to_node_remaps_completed_scan(monkeypatch):
    threat_model_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    node_id = uuid.uuid4()
    scan_job = ScanJob(
        id=scan_id,
        threat_model_id=threat_model_id,
        owner_id=uuid.uuid4(),
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"direct": "/repo"},
        finding_count=1,
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=scan_id,
        template_id="python.jwt.decode-without-verify",
        template_name="JWT verification disabled",
        severity="high",
        matched_at="app/auth.py:42",
        cve_ids=[],
        tags=["jwt", "semgrep"],
        raw_output={"path": "app/auth.py"},
    )
    node = DFDNode(
        id=node_id,
        threat_model_id=threat_model_id,
        node_type="process",
        name="Authentication Service",
        properties={},
    )
    db = FakeDB(execute_values=[(finding, scan_job), node, None])
    mapped_ids: list[uuid.UUID] = []

    async def fake_mapping(db_arg, scan_job_id):
        del db_arg
        mapped_ids.append(scan_job_id)

    async def fake_runbook(db_arg, scan_job_id):
        del db_arg
        assert scan_job_id == scan_id
        return SimpleNamespace(
            coverage=SimpleNamespace(
                target_binding="node_bound",
                mapped_threat_count=1,
                unbound_finding_count=0,
            )
        )

    monkeypatch.setattr("app.services.validation_lab.run_semantic_mapping", fake_mapping)
    monkeypatch.setattr("app.services.validation_lab.build_validation_runbook", fake_runbook)

    response = await bind_validation_evidence_to_node(
        db,  # type: ignore[arg-type]
        threat_model_id,
        finding.id,
        node_id,
    )

    assert response is not None
    assert response.target_node_id == node_id
    assert response.binding_target == "path:app/auth.py"
    assert response.target_binding == "node_bound"
    assert response.mapped_threat_count == 1
    assert scan_job.targets == {str(node_id): "path:app/auth.py"}
    assert mapped_ids == [scan_id]
    assert db.committed is True


def test_build_product_security_cases_from_runbook_evidence():
    scan_job_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    runbook = ValidationRunbookResponse(
        coverage=ValidationRunbookCoverageResponse(
            scan_job_id=scan_job_id,
            scan_completed_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
            tool_names=["semgrep", "pentest-report"],
            target_binding="mixed",
            finding_count=4,
            deterministic_finding_count=2,
            assisted_finding_count=2,
            artifact_count=1,
            mapped_threat_count=3,
            validated_threat_count=3,
            indicated_threat_count=0,
            unbound_finding_count=1,
            untested_threat_count=0,
            confidence_counts={"validated": 3, "indicated": 0, "untested": 0},
            validated_risk_score=86,
            indicated_risk_score=0,
            ai_assisted_risk_score=42,
        ),
        executive_summary="Semgrep validated one source-code threat.",
        mapped_threats=[
            ValidationRunbookThreatResponse(
                threat_id=threat_id,
                threat_display_id="T-001",
                threat_description="JWT validation can be bypassed by unsigned tokens.",
                severity="High",
                stride_category="Spoofing",
                scan_status="confirmed",
                confidence_label="validated",
                explanation="Node-bound Semgrep evidence validates the spoofing path.",
                evidence_count=2,
                risk_score=86,
                evidence_quality="strong",
                proof_class="deterministic",
                next_action="Open a remediation ticket and retest.",
                cve_ids=[],
                validation_tools=["semgrep"],
            ),
            ValidationRunbookThreatResponse(
                threat_id=uuid.uuid4(),
                threat_display_id="T-002",
                threat_description="Internet-exposed SSH can become a cloud workload escalation path.",
                severity="High",
                stride_category="Elevation of Privilege",
                scan_status="confirmed",
                confidence_label="validated",
                explanation="Checkov evidence validates the exposed management path.",
                evidence_count=1,
                risk_score=70,
                evidence_quality="strong",
                proof_class="deterministic",
                next_action="Open a cloud remediation ticket and retest.",
                cve_ids=[],
                validation_tools=["checkov"],
            ),
            ValidationRunbookThreatResponse(
                threat_id=uuid.uuid4(),
                threat_display_id="T-003",
                threat_description="AI-assisted transcript suggests a possible authorization bypass.",
                severity="Medium",
                stride_category="Elevation of Privilege",
                scan_status="confirmed",
                confidence_label="validated",
                explanation="AI-assisted evidence is useful but still needs deterministic or human attested proof.",
                evidence_count=1,
                risk_score=60,
                evidence_quality="moderate",
                proof_class="ai_assisted",
                next_action="Gather deterministic validation evidence.",
                cve_ids=[],
                validation_tools=["semantic-enrichment"],
            )
        ],
        unbound_findings=[
            ValidationRunbookFindingResponse(
                finding_id=finding_id,
                title="Pentest noted weak service-to-service auth",
                severity="medium",
                tool_name="pentest-report",
                target="Q2 pentest report",
                matched_at="Q2 pentest report",
                cve_ids=[],
                tags=["pentest", "auth"],
                confidence_label="indicated",
                evidence_scope="unbound",
                proof_class="ai_assisted",
                evidence_quality="moderate",
                risk_score=42,
                next_action="Bind to the service component that owns this auth path.",
                explanation="External report evidence needs a DFD node before it can validate a semantic threat.",
            )
        ],
    )

    cases = build_product_security_cases(runbook)

    validated_case = next(case for case in cases if case.case_id == str(threat_id))
    assert validated_case.status == "validated"
    assert validated_case.proof_level == "validated"
    assert validated_case.confidence_label == "high"
    assert validated_case.evidence_sources == ["semgrep"]
    assert "Open a fix ticket" in validated_case.remediation_action
    assert validated_case.recommended_checks[0].tool_name == "semgrep"
    assert validated_case.recommended_checks[0].priority == "P2"
    assert "caller assume another identity" in validated_case.product_questions[0]

    checkov_case = next(case for case in cases if case.title == "T-002 · Elevation of Privilege")
    assert checkov_case.recommended_checks[0].tool_name == "checkov"
    assert checkov_case.recommended_checks[0].target_type == "iac_directory"

    assisted_case = next(case for case in cases if case.title == "T-003 · Elevation of Privilege")
    assert assisted_case.status == "relevant"
    assert assisted_case.proof_level == "relevant"

    unbound_case = next(case for case in cases if case.case_id == str(finding_id))
    assert unbound_case.status == "needs_binding"
    assert unbound_case.proof_level == "observed"
    assert unbound_case.case_type == "unbound_finding"
    assert unbound_case.evidence_sources == ["pentest-report"]
    assert unbound_case.recommended_checks == []
    assert "Bind this evidence" in unbound_case.remediation_action


def test_merge_product_security_case_state_adds_workflow_and_audit():
    case_id = uuid.uuid4()
    case = ProductSecurityValidationCaseResponse(
        case_id=str(case_id),
        case_type="threat",
        title="T-001 · Spoofing",
        hypothesis="JWT validation bypass",
        severity="High",
        stride_category="Spoofing",
        status="validated",
        confidence_label="high",
        confidence_score=92,
        proof_level="validated",
        proof_class="deterministic",
        evidence_quality="strong",
        evidence_count=1,
        evidence_sources=["semgrep"],
        risk_score=80,
        product_questions=[],
        recommended_checks=[],
        next_action="Retest after fix.",
        remediation_action="Open a fix ticket.",
    )
    state = ValidationCaseState(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        case_key=str(case_id),
        case_type="threat",
        workflow_status="investigating",
        workflow_priority="P1",
        owner_label="Product Security",
        due_date=date(2026, 5, 1),
        analyst_note="Checking exploitability.",
        last_decision="Needs source retest.",
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )
    event = ValidationCaseEvent(
        id=uuid.uuid4(),
        case_state_id=state.id,
        threat_model_id=state.threat_model_id,
        actor_id=uuid.uuid4(),
        action="updated",
        changes={"workflow_status": {"from": "open", "to": "investigating"}},
        note="Needs source retest.",
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )

    merged = merge_product_security_case_state([case], [state], {state.id: [event]})

    assert merged[0].workflow_status == "investigating"
    assert merged[0].workflow_priority == "P1"
    assert merged[0].owner_label == "Product Security"
    assert merged[0].due_date == date(2026, 5, 1)
    assert merged[0].audit_events[0].changes["workflow_status"]["to"] == "investigating"


def test_validation_case_decision_status_requires_rationale():
    with pytest.raises(ValueError, match="last_decision or analyst_note"):
        ValidationCaseStateUpdateRequest(workflow_status="accepted")


def test_validation_case_decision_status_accepts_rationale():
    body = ValidationCaseStateUpdateRequest(
        workflow_status="dismissed",
        last_decision="Scanner evidence was reviewed and the risk is not applicable.",
    )

    assert body.workflow_status == "dismissed"
    assert body.last_decision == "Scanner evidence was reviewed and the risk is not applicable."


@pytest.mark.asyncio
async def test_update_product_security_case_state_persists_due_date(monkeypatch):
    threat_model_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    runbook = ValidationRunbookResponse(
        coverage=ValidationRunbookCoverageResponse(
            scan_job_id=uuid.uuid4(),
            scan_completed_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
            tool_names=["checkov"],
            target_binding="node_bound",
            finding_count=1,
            deterministic_finding_count=1,
            assisted_finding_count=0,
            artifact_count=1,
            mapped_threat_count=1,
            validated_threat_count=1,
            indicated_threat_count=0,
            unbound_finding_count=0,
            untested_threat_count=0,
            confidence_counts={"validated": 1, "indicated": 0, "untested": 0},
            validated_risk_score=70,
            indicated_risk_score=0,
            ai_assisted_risk_score=0,
        ),
        executive_summary="Checkov validated a cloud control gap.",
        mapped_threats=[
            ValidationRunbookThreatResponse(
                threat_id=threat_id,
                threat_display_id="T-004",
                threat_description="SSH exposure creates a workload escalation path.",
                severity="High",
                stride_category="Elevation of Privilege",
                scan_status="confirmed",
                confidence_label="validated",
                explanation="Checkov evidence validates the path.",
                evidence_count=1,
                risk_score=70,
                evidence_quality="strong",
                proof_class="deterministic",
                next_action="Open a cloud remediation ticket and retest.",
                cve_ids=[],
                validation_tools=["checkov"],
            )
        ],
        unbound_findings=[],
    )
    db = FakeDB(execute_values=[None])

    async def fake_latest_runbook(db_arg, threat_model_id_arg):
        del db_arg
        assert threat_model_id_arg == threat_model_id
        return runbook

    async def fake_validation_case_events(db_arg, case_state_id):
        del db_arg, case_state_id
        return []

    monkeypatch.setattr("app.services.validation_lab._latest_runbook", fake_latest_runbook)
    monkeypatch.setattr("app.services.validation_lab._validation_case_events", fake_validation_case_events)

    response = await update_product_security_case_state(
        db,  # type: ignore[arg-type]
        threat_model_id,
        str(threat_id),
        ValidationCaseStateUpdateRequest(
            workflow_status="investigating",
            workflow_priority="P1",
            owner_label="Product Security",
            due_date=date(2026, 5, 3),
            analyst_note="Browser pass checked the workflow.",
            last_decision="Retest after remediation.",
        ),
        FakeUser(),  # type: ignore[arg-type]
    )

    state = next(item for item in db.added if isinstance(item, ValidationCaseState))
    event = next(item for item in db.added if isinstance(item, ValidationCaseEvent))
    assert db.committed is True
    assert state.due_date == date(2026, 5, 3)
    assert response.due_date == date(2026, 5, 3)
    assert event.changes["due_date"]["to"] == "2026-05-03"


async def _noop_mapping(db, scan_job_id):
    del db, scan_job_id
