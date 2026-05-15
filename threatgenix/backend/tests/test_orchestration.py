from __future__ import annotations

import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.models.orchestration import (
    OrchestrationEvent,
    OrchestrationJob,
    OrchestrationTask,
)
from app.schemas.orchestration import OrchestrationJobCreate, OrchestrationTaskCreate
from app.services.orchestration import (
    OrchestrationIdempotencyConflict,
    create_orchestration_job,
)
from app.services import orchestration_worker
from app.services.orchestration_worker import (
    OrchestrationTaskBlocked,
    _execute_agent_reasoning,
    _execute_validation_tool_task,
    _mark_task_blocked,
    _mark_stale_running_task,
    update_orchestration_job_status,
)


class _FakeSession:
    def __init__(self, execute_result: object | None = None) -> None:
        self.added: list[object] = []
        self.flush_count = 0
        self.execute_result = execute_result

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1

    async def execute(self, statement: object):
        del statement

        class _Result:
            def __init__(self, item: object | None) -> None:
                self.item = item

            def scalar_one_or_none(self):
                return self.item

        return _Result(self.execute_result)


class _NoClaimResult:
    def first(self):
        return None


class _ClaimCaptureSession:
    def __init__(self) -> None:
        self.statements: list[object] = []
        self.added: list[object] = []
        self.flush_count = 0

    async def execute(self, statement: object):
        self.statements.append(statement)
        return _NoClaimResult()

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


@pytest.mark.asyncio
async def test_create_orchestration_job_materializes_requested_tool_tasks():
    db = _FakeSession()
    threat_model = SimpleNamespace(id=uuid.uuid4())
    owner_id = uuid.uuid4()

    job = await create_orchestration_job(
        db,  # type: ignore[arg-type]
        threat_model,  # type: ignore[arg-type]
        owner_id=owner_id,
        request=OrchestrationJobCreate(
            job_kind="validation_run",
            objective="Run authorized validation tools against mapped targets.",
            requested_tools=["nuclei", "nuclei", "semgrep"],
            tasks=[
                OrchestrationTaskCreate(
                    task_kind="tool_execution",
                    tool_name="nuclei",
                    input_payload={"target": "https://api.example.com"},
                )
            ],
        ),
    )

    jobs = [item for item in db.added if isinstance(item, OrchestrationJob)]
    tasks = [item for item in db.added if isinstance(item, OrchestrationTask)]
    events = [item for item in db.added if isinstance(item, OrchestrationEvent)]

    assert job.id is not None
    assert jobs == [job]
    assert [task.tool_name for task in tasks] == ["nuclei", "semgrep"]
    assert job.requested_tools == ["nuclei", "semgrep"]
    assert all(task.job_id == job.id for task in tasks)
    assert events[0].event_type == "created"
    assert events[0].payload["requested_tools"] == ["nuclei", "semgrep"]
    assert db.flush_count == 2


def test_orchestration_job_rejects_oversized_requested_tool_name():
    with pytest.raises(ValidationError):
        OrchestrationJobCreate(
            job_kind="validation_run",
            objective="Run authorized validation tools against mapped targets.",
            requested_tools=["x" * 121],
        )


def test_orchestration_job_rejects_unsupported_requested_tool_name():
    with pytest.raises(ValidationError):
        OrchestrationJobCreate(
            job_kind="validation_run",
            objective="Run authorized validation tools against mapped targets.",
            requested_tools=["unknown-tool"],
        )


def test_orchestration_task_rejects_unsupported_tool_execution_tool_name():
    with pytest.raises(ValidationError):
        OrchestrationTaskCreate(
            task_kind="tool_execution",
            tool_name="../../bin/sh",
        )


@pytest.mark.asyncio
async def test_create_orchestration_job_reuses_idempotent_request():
    threat_model = SimpleNamespace(id=uuid.uuid4())
    owner_id = uuid.uuid4()
    existing = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=threat_model.id,
        owner_id=owner_id,
        job_kind="validation_run",
        objective="Run authorized validation tools against mapped targets.",
        requested_tools=["nuclei"],
        idempotency_key="retry-key-1",
    )
    existing.tasks = [
        OrchestrationTask(
            id=uuid.uuid4(),
            job_id=existing.id,
            threat_model_id=threat_model.id,
            task_kind="tool_execution",
            tool_name="nuclei",
            input_payload={"source": "requested_tools"},
            max_attempts=1,
        )
    ]
    existing.events = []
    db = _FakeSession(execute_result=existing)

    job = await create_orchestration_job(
        db,  # type: ignore[arg-type]
        threat_model,  # type: ignore[arg-type]
        owner_id=owner_id,
        request=OrchestrationJobCreate(
            job_kind="validation_run",
            objective="Run authorized validation tools against mapped targets.",
            requested_tools=["nuclei"],
            idempotency_key="retry-key-1",
        ),
    )

    assert job is existing
    assert db.added == []
    assert db.flush_count == 0


@pytest.mark.asyncio
async def test_claim_next_orchestration_task_preserves_tenant_and_job_scope():
    threat_model_id = uuid.uuid4()
    job_id = uuid.uuid4()
    db = _ClaimCaptureSession()

    task = await orchestration_worker.claim_next_orchestration_task(
        db,  # type: ignore[arg-type]
        threat_model_id=threat_model_id,
        job_id=job_id,
    )

    assert task is None
    assert db.added == []
    assert db.flush_count == 0
    assert len(db.statements) == 1
    statement = db.statements[0]
    compiled_params = statement.compile().params  # type: ignore[attr-defined]
    assert threat_model_id in compiled_params.values()
    assert job_id in compiled_params.values()
    for_update = statement._for_update_arg  # type: ignore[attr-defined]
    assert for_update is not None
    assert for_update.skip_locked is True


@pytest.mark.asyncio
async def test_validation_tool_task_requires_authorization_acknowledgement():
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run semgrep against an authorized repository target.",
        requested_tools=["semgrep"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="semgrep",
        input_payload={
            "target_type": "repository_path",
            "target": "/tmp/repo",
        },
        max_attempts=1,
    )
    task.job = job

    with pytest.raises(OrchestrationTaskBlocked, match="authorization_acknowledged"):
        await _execute_validation_tool_task(_FakeSession(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_validation_tool_task_blocks_when_live_runtime_disabled(monkeypatch):
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run semgrep against an authorized repository target.",
        requested_tools=["semgrep"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="semgrep",
        input_payload={
            "authorization_acknowledged": True,
            "target_type": "repository_path",
            "target": "/tmp/repo",
        },
        max_attempts=1,
    )
    task.job = job
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: False)
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_blocked_reason", lambda: "blocked")

    with pytest.raises(OrchestrationTaskBlocked, match="blocked"):
        await _execute_validation_tool_task(_FakeSession(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_validation_tool_task_blocks_path_targets_outside_allowlist(monkeypatch):
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run semgrep against an authorized repository target.",
        requested_tools=["semgrep"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="semgrep",
        input_payload={
            "authorization_acknowledged": True,
            "target_type": "repository_path",
            "target": "/tmp/repo",
        },
        max_attempts=1,
    )
    task.job = job
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: True)

    def _deny_target_access(target: str, target_type: str) -> str:
        raise orchestration_worker.ValidationSandboxTargetError(
            f"validation target is outside configured allowed roots: {target}"
        )

    monkeypatch.setattr(
        orchestration_worker,
        "validate_validation_target_access",
        _deny_target_access,
    )

    with pytest.raises(OrchestrationTaskBlocked, match="outside configured allowed roots"):
        await _execute_validation_tool_task(_FakeSession(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_validation_tool_task_rejects_cross_model_target_node(monkeypatch):
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run semgrep against an authorized repository target.",
        requested_tools=["semgrep"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="semgrep",
        input_payload={
            "authorization_acknowledged": True,
            "target_type": "repository_path",
            "target": "/tmp/repo",
            "target_node_id": str(uuid.uuid4()),
        },
        max_attempts=1,
    )
    task.job = job
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: True)
    monkeypatch.setattr(
        orchestration_worker,
        "validate_validation_target_access",
        lambda target, target_type: target,
    )

    with pytest.raises(OrchestrationTaskBlocked, match="target_node_id does not belong"):
        await _execute_validation_tool_task(_FakeSession(execute_result=None), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_validation_tool_task_blocks_managed_process_network_policy(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "process")
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: True)
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run nuclei against an authorized target.",
        requested_tools=["nuclei"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="nuclei",
        input_payload={
            "authorization_acknowledged": True,
            "target_type": "url",
            "target": "https://api.example.com",
        },
        max_attempts=1,
    )
    task.job = job

    with pytest.raises(OrchestrationTaskBlocked, match="target_only network policy"):
        await _execute_validation_tool_task(_FakeSession(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_update_orchestration_job_status_marks_policy_blocked_tasks_blocked():
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run authorized validation tools.",
        requested_tools=["semgrep"],
        status="running",
    )
    job.tasks = [
        OrchestrationTask(
            id=uuid.uuid4(),
            job_id=job.id,
            threat_model_id=job.threat_model_id,
            task_kind="tool_execution",
            tool_name="semgrep",
            status="blocked",
            error_message="authorization_acknowledged=true is required.",
            max_attempts=1,
        )
    ]
    db = _FakeSession(execute_result=job)

    await update_orchestration_job_status(db, job.id)  # type: ignore[arg-type]

    assert job.status == "blocked"
    assert job.completed_at is not None
    assert job.error_message == (
        "Orchestration blocked with 1 blocked task(s) and 0 cancelled task(s)."
    )


@pytest.mark.asyncio
async def test_update_orchestration_job_status_keeps_failed_when_any_task_failed():
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run authorized validation tools.",
        requested_tools=["semgrep"],
        status="running",
    )
    job.tasks = [
        OrchestrationTask(
            id=uuid.uuid4(),
            job_id=job.id,
            threat_model_id=job.threat_model_id,
            task_kind="tool_execution",
            tool_name="semgrep",
            status="failed",
            error_message="scanner exited 2",
            max_attempts=1,
        ),
        OrchestrationTask(
            id=uuid.uuid4(),
            job_id=job.id,
            threat_model_id=job.threat_model_id,
            task_kind="human_review",
            status="blocked",
            error_message="human review required",
            max_attempts=1,
        ),
    ]
    db = _FakeSession(execute_result=job)

    await update_orchestration_job_status(db, job.id)  # type: ignore[arg-type]

    assert job.status == "failed"
    assert job.error_message == (
        "Orchestration finished with 1 failed task(s), "
        "1 blocked task(s), and 0 cancelled task(s)."
    )


@pytest.mark.asyncio
async def test_mark_task_blocked_records_blocked_event():
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        task_kind="tool_execution",
        tool_name="semgrep",
        status="running",
        max_attempts=1,
    )
    db = _FakeSession()

    await _mark_task_blocked(db, task, "missing authorization")  # type: ignore[arg-type]

    assert task.status == "blocked"
    events = [item for item in db.added if isinstance(item, OrchestrationEvent)]
    assert events[0].event_type == "blocked"
    assert events[0].payload == {"reason": "missing authorization"}


def test_mark_stale_running_task_requeues_when_attempts_remain():
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        task_kind="tool_execution",
        tool_name="semgrep",
        status="running",
        attempt_count=1,
        max_attempts=2,
        started_at=orchestration_worker._now() - timedelta(seconds=120),
    )
    db = _FakeSession()

    _mark_stale_running_task(db, task, stale_after_seconds=60)  # type: ignore[arg-type]

    assert task.status == "pending"
    assert task.started_at is None
    assert task.completed_at is None
    assert "running timeout" in (task.error_message or "")
    events = [item for item in db.added if isinstance(item, OrchestrationEvent)]
    assert events[0].event_type == "failed"
    assert events[0].level == "warning"
    assert events[0].payload["recovery_action"] == "retry"


def test_mark_stale_running_task_fails_when_attempts_exhausted():
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        task_kind="tool_execution",
        tool_name="semgrep",
        status="running",
        attempt_count=1,
        max_attempts=1,
        started_at=orchestration_worker._now() - timedelta(seconds=120),
    )
    db = _FakeSession()

    _mark_stale_running_task(db, task, stale_after_seconds=60)  # type: ignore[arg-type]

    assert task.status == "failed"
    assert task.completed_at is not None
    events = [item for item in db.added if isinstance(item, OrchestrationEvent)]
    assert events[0].event_type == "failed"
    assert events[0].level == "error"
    assert events[0].payload["recovery_action"] == "failed"


@pytest.mark.asyncio
async def test_agent_reasoning_task_requires_prompt():
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="security_audit",
        objective="Summarize evidence.",
        requested_tools=[],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="agent_reasoning",
        agent_name="security-review-agent",
        input_payload={},
        max_attempts=1,
    )
    task.job = job

    with pytest.raises(OrchestrationTaskBlocked, match="prompt is required"):
        await _execute_agent_reasoning(_FakeSession(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_create_orchestration_job_rejects_idempotency_key_body_mismatch():
    threat_model = SimpleNamespace(id=uuid.uuid4())
    owner_id = uuid.uuid4()
    existing = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=threat_model.id,
        owner_id=owner_id,
        job_kind="validation_run",
        objective="Run authorized validation tools against mapped targets.",
        requested_tools=["nuclei"],
        idempotency_key="retry-key-2",
        inputs={},
        policy={},
    )
    existing.tasks = [
        OrchestrationTask(
            id=uuid.uuid4(),
            job_id=existing.id,
            threat_model_id=threat_model.id,
            task_kind="tool_execution",
            tool_name="nuclei",
            input_payload={"source": "requested_tools"},
            max_attempts=1,
        )
    ]
    existing.events = []
    db = _FakeSession(execute_result=existing)

    with pytest.raises(OrchestrationIdempotencyConflict):
        await create_orchestration_job(
            db,  # type: ignore[arg-type]
            threat_model,  # type: ignore[arg-type]
            owner_id=owner_id,
            request=OrchestrationJobCreate(
                job_kind="validation_run",
                objective="Run a different validation objective.",
                requested_tools=["nuclei"],
                idempotency_key="retry-key-2",
            ),
        )

    assert db.added == []
    assert db.flush_count == 0
