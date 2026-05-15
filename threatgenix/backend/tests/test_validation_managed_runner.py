"""Tests for the managed isolated runner: runtime mode + polling loop."""
from __future__ import annotations

import asyncio
import os
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Runtime mode
# ---------------------------------------------------------------------------


def test_managed_mode_blocks_api_local_live_execution(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.delenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", raising=False)
    from importlib import reload

    import app.services.validation_runtime as vr

    reload(vr)
    assert vr.live_validation_execution_enabled() is False
    assert vr.validation_runtime_state().mode == "managed"
    assert vr.validation_runtime_state().live_execution_enabled is False
    assert vr.validation_runtime_state().run_submission_enabled is False


def test_managed_mode_with_runner_accepts_api_submission_without_inline_execution(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.delenv("THREATGENIX_VALIDATION_EXECUTION_CONTEXT", raising=False)
    from importlib import reload

    import app.services.validation_runtime as vr

    reload(vr)
    state = vr.validation_runtime_state()
    assert state.mode == "managed"
    assert state.run_submission_enabled is True
    assert state.managed_runner_enabled is True
    assert state.live_execution_enabled is False
    assert state.inline_execution_enabled is False
    assert state.worker_execution_enabled is False
    assert vr.validation_run_submission_enabled() is True
    assert vr.inline_validation_execution_enabled() is False
    assert vr.validation_worker_execution_enabled() is False


def test_managed_worker_context_can_execute_scanners(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_EXECUTION_CONTEXT", "worker")
    from importlib import reload

    import app.services.validation_runtime as vr

    reload(vr)
    state = vr.validation_runtime_state()
    assert state.run_submission_enabled is True
    assert state.inline_execution_enabled is False
    assert state.worker_execution_enabled is True
    assert vr.validation_worker_execution_enabled() is True


def test_worker_main_uses_dev_settings_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    import app.config as app_config
    import worker_main

    monkeypatch.setattr(app_config.settings, "app_env", "development")

    worker_main._validate_env()

    assert os.environ["THREATGENIX_VALIDATION_EXECUTION_CONTEXT"] == "worker"


def test_worker_main_requires_database_url_in_production(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    import app.config as app_config
    import worker_main

    monkeypatch.setattr(app_config.settings, "app_env", "production")

    with pytest.raises(SystemExit):
        worker_main._validate_env()


def test_worker_main_health_server_skips_without_cloud_run_port(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    import worker_main

    assert worker_main._start_health_server() is None


def test_worker_main_health_server_serves_cloud_run_port(monkeypatch):
    monkeypatch.setenv("PORT", "0")
    import worker_main

    server = worker_main._start_health_server()
    assert server is not None
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
            body = response.read().decode("utf-8")
        assert response.status == 200
        assert "validation-worker" in body
    finally:
        server.shutdown()
        server.server_close()


def test_try_sandbox_mode_blocks_execution(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "try_sandbox")
    from importlib import reload

    import app.services.validation_runtime as vr

    reload(vr)
    assert vr.live_validation_execution_enabled() is False


def test_self_hosted_mode_still_enabled(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    from importlib import reload

    import app.services.validation_runtime as vr

    reload(vr)
    assert vr.live_validation_execution_enabled() is True
    assert vr.validation_run_submission_enabled() is True
    assert vr.validation_worker_execution_enabled() is True


def test_managed_mode_title():
    from importlib import reload

    import app.services.validation_runtime as vr

    with patch.dict("os.environ", {"THREATGENIX_VALIDATION_RUNTIME_MODE": "managed"}):
        reload(vr)
        state = vr.validation_runtime_state()
    assert "managed" in state.title.lower() or "runner" in state.title.lower()


def test_unknown_mode_falls_back_to_try_sandbox(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "bogus_mode")
    from importlib import reload

    import app.services.validation_runtime as vr

    reload(vr)
    assert vr.validation_runtime_mode() == "try_sandbox"
    assert vr.live_validation_execution_enabled() is False


@pytest.mark.asyncio
async def test_scan_worker_refuses_pending_job_when_runtime_is_unset(monkeypatch):
    monkeypatch.delenv("THREATGENIX_VALIDATION_RUNTIME_MODE", raising=False)
    from app.services.scan_worker import _execute_scan

    job = MagicMock()
    job.id = uuid.uuid4()
    job.status = "pending"
    job.tool_name = "nuclei"
    job.target_type = "url"
    job.error_message = None
    job.completed_at = None

    result = MagicMock()
    result.scalar_one_or_none.return_value = job

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    await _execute_scan(db, job.id)

    assert job.status == "failed"
    assert "Live validation execution is disabled" in job.error_message
    assert job.completed_at is not None
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_scan_worker_refuses_pending_job_in_hosted_saas_alias(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "hosted_saas")
    from app.services.scan_worker import _execute_scan

    job = MagicMock()
    job.id = uuid.uuid4()
    job.status = "pending"
    job.tool_name = "nuclei"
    job.target_type = "url"
    job.error_message = None
    job.completed_at = None

    result = MagicMock()
    result.scalar_one_or_none.return_value = job

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    await _execute_scan(db, job.id)

    assert job.status == "failed"
    assert "Live validation execution is disabled" in job.error_message
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_scan_worker_allows_managed_runner_context_past_runtime_gate(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_EXECUTION_CONTEXT", "worker")
    from app.services.scan_worker import _execute_scan

    job = MagicMock()
    job.id = uuid.uuid4()
    job.status = "pending"
    job.tool_name = "unknown-tool"
    job.target_type = "url"
    job.error_message = None
    job.completed_at = None

    result = MagicMock()
    result.scalar_one_or_none.return_value = job

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    await _execute_scan(db, job.id)

    assert job.status == "failed"
    assert job.error_message == "Unsupported validation tool: unknown-tool"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_managed_worker_process_mode_blocks_target_network_tools(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_EXECUTION_CONTEXT", "worker")
    monkeypatch.delenv("THREATGENIX_VALIDATION_SANDBOX_MODE", raising=False)
    from app.services.scan_worker import _execute_scan

    job = MagicMock()
    job.id = uuid.uuid4()
    job.status = "pending"
    job.tool_name = "nuclei"
    job.target_type = "url"
    job.error_message = None
    job.completed_at = None

    result = MagicMock()
    result.scalar_one_or_none.return_value = job

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    await _execute_scan(db, job.id)

    assert job.status == "failed"
    assert job.failure_code == "policy_denied"
    assert "requires an isolated network runner" in job.error_message
    db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# _claim_next_pending_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_returns_none_on_empty_queue():
    """When no pending jobs exist, _claim_next_pending_job returns None."""
    from app.services.scan_worker import _claim_next_pending_job

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_tx_ctx = AsyncMock()
    mock_tx_ctx.__aenter__ = AsyncMock(return_value=None)
    mock_tx_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_session.begin = MagicMock(return_value=mock_tx_ctx)

    with patch("app.services.scan_worker.async_session", return_value=mock_ctx):
        result = await _claim_next_pending_job("test-runner")

    assert result is None


@pytest.mark.asyncio
async def test_claim_marks_job_running():
    """When a pending job exists, _claim_next_pending_job sets status=running and returns its id."""
    from app.services.scan_worker import _claim_next_pending_job

    job_id = uuid.uuid4()
    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = "pending"
    mock_job.started_at = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_tx_ctx = AsyncMock()
    mock_tx_ctx.__aenter__ = AsyncMock(return_value=None)
    mock_tx_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_session.begin = MagicMock(return_value=mock_tx_ctx)

    with patch("app.services.scan_worker.async_session", return_value=mock_ctx):
        result = await _claim_next_pending_job("test-runner")

    assert result == job_id
    assert mock_job.status == "running"
    assert mock_job.started_at is not None


@pytest.mark.asyncio
async def test_record_runner_heartbeat_extends_current_job_lease():
    from app.services.scan_worker import _record_runner_heartbeat

    job_id = uuid.uuid4()
    mock_job = SimpleNamespace(
        id=job_id,
        status="running",
        runner_id=None,
        heartbeat_at=None,
        lease_expires_at=None,
        max_attempts=None,
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.services.scan_worker.async_session", return_value=mock_ctx),
        patch(
            "app.services.scan_worker.record_worker_heartbeat",
            new_callable=AsyncMock,
        ) as record_heartbeat,
    ):
        await _record_runner_heartbeat(
            "runner-1",
            status="running",
            current_scan_job_id=job_id,
        )

    record_heartbeat.assert_awaited_once()
    assert mock_job.runner_id == "runner-1"
    assert mock_job.heartbeat_at is not None
    assert mock_job.lease_expires_at is not None
    assert mock_job.max_attempts is not None
    mock_session.commit.assert_awaited_once()


class _ConcurrentClaimResult:
    def __init__(self, item: object | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item


class _ConcurrentScanStore:
    def __init__(self, jobs: list[object]) -> None:
        self.jobs = {job.id: job for job in jobs}
        self.lock = asyncio.Lock()
        self.heartbeats: dict[str, object] = {}
        self.findings_by_job: dict[uuid.UUID, list[object]] = defaultdict(list)
        self.artifacts_by_job: dict[uuid.UUID, list[object]] = defaultdict(list)
        self.projections_by_model: dict[uuid.UUID, list[str]] = defaultdict(list)
        self.tenant_by_model = {
            job.threat_model_id: job.targets["repo"].split("/")[-2] for job in jobs
        }
        self.commit_count = 0

    def next_pending_job(self):
        pending_jobs = [
            job
            for job in self.jobs.values()
            if job.status == "pending"
            and (job.attempt_count or 0) < (job.max_attempts or 1)
        ]
        if not pending_jobs:
            return None
        return sorted(pending_jobs, key=lambda job: (job.created_at, str(job.id)))[0]


class _ConcurrentScanTransaction:
    def __init__(self, store: _ConcurrentScanStore) -> None:
        self.store = store

    async def __aenter__(self) -> None:
        await self.store.lock.acquire()

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        self.store.lock.release()
        return False


class _ConcurrentScanSession:
    def __init__(self, store: _ConcurrentScanStore) -> None:
        self.store = store

    def begin(self) -> _ConcurrentScanTransaction:
        return _ConcurrentScanTransaction(self.store)

    async def execute(self, statement: object):
        compiled = str(statement)
        params = statement.compile().params
        if "validation_worker_heartbeats" in compiled:
            runner_id = next(
                (value for value in params.values() if isinstance(value, str)),
                None,
            )
            return _ConcurrentClaimResult(self.store.heartbeats.get(runner_id))
        if "scan_jobs" in compiled:
            if getattr(statement, "_for_update_arg", None) is not None:
                return _ConcurrentClaimResult(self.store.next_pending_job())
            job_id = next(
                (value for value in params.values() if isinstance(value, uuid.UUID)),
                None,
            )
            return _ConcurrentClaimResult(self.store.jobs.get(job_id))
        return _ConcurrentClaimResult(None)

    def add(self, item: object) -> None:
        class_name = item.__class__.__name__
        if class_name == "ValidationWorkerHeartbeat":
            self.store.heartbeats[item.runner_id] = item
        elif class_name == "ScanFinding":
            self.store.findings_by_job[item.scan_job_id].append(item)
        elif class_name == "ScanExecutionArtifact":
            self.store.artifacts_by_job[item.scan_job_id].append(item)

    async def commit(self) -> None:
        self.store.commit_count += 1

    async def rollback(self) -> None:
        return None

    async def refresh(self, item: object) -> None:
        del item


class _ConcurrentScanSessionContext:
    def __init__(self, store: _ConcurrentScanStore) -> None:
        self.store = store

    async def __aenter__(self) -> _ConcurrentScanSession:
        return _ConcurrentScanSession(self.store)

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _SingleItemRegistry:
    def __init__(self, item: object, *, name_attr: str) -> None:
        self.item = item
        self.name_attr = name_attr

    def get(self, name: str):
        if name != getattr(self.item, self.name_attr):
            raise KeyError(name)
        return self.item


class _ConcurrentFakeSemgrepAdapter:
    name = "semgrep"
    deterministic = True

    def __init__(self, target_tenants: dict[str, str]) -> None:
        self.target_tenants = target_tenants
        self.started_targets: list[str] = []
        self.all_started = asyncio.Event()

    def is_available(self) -> bool:
        return True

    async def run(self, target: str, **kwargs):
        from app.services.validation_tools import ValidationEvidence, ValidationToolResult

        del kwargs
        self.started_targets.append(target)
        if len(self.started_targets) == len(self.target_tenants):
            self.all_started.set()
        await asyncio.wait_for(self.all_started.wait(), timeout=1)
        tenant_marker = self.target_tenants[target]
        return ValidationToolResult(
            tool_name=self.name,
            target=target,
            findings=[
                ValidationEvidence(
                    tool_name=self.name,
                    target=target,
                    severity="medium",
                    finding_title=f"{tenant_marker} tenant-isolated finding",
                    cve_ids=[],
                    tags=[tenant_marker, "tenant-isolation"],
                    matched_url=target,
                    raw_output={
                        "tenant_marker": tenant_marker,
                        "target": target,
                    },
                    template_id=f"tenant-isolation-{tenant_marker}",
                )
            ],
            returncode=0,
            stderr="",
            command=["semgrep", "scan", target],
            resolved_target=target,
            stdout_bytes=128,
        )


@pytest.mark.asyncio
async def test_concurrent_managed_workers_claim_once_and_keep_tenant_evidence_isolated(
    monkeypatch,
):
    """Multiple managed workers should not double-claim jobs or mix tenant evidence."""
    from app.services.scan_worker import (
        _claim_next_pending_job,
        _record_runner_heartbeat,
        run_scan_job,
    )
    from app.models.scan import ScanJob
    from app.services.validation_execution_policy import (
        NETWORK_NONE,
        TARGET_REPOSITORY_PATH,
        ValidationExecutionPolicy,
    )

    now = datetime.now(timezone.utc)
    tenant_jobs = []
    target_tenants = {}
    for index, tenant_marker in enumerate(("tenant-a", "tenant-b", "tenant-c")):
        target = f"/tmp/{tenant_marker}/repo"
        target_tenants[target] = tenant_marker
        tenant_jobs.append(
            ScanJob(
                id=uuid.uuid4(),
                threat_model_id=uuid.uuid4(),
                owner_id=uuid.uuid4(),
                status="pending",
                scan_type="unauthenticated",
                scope="external",
                tool_name="semgrep",
                target_type=TARGET_REPOSITORY_PATH,
                targets={"repo": target},
                nuclei_templates=[],
                attempt_count=0,
                max_attempts=3,
                finding_count=0,
                created_at=now.replace(microsecond=index),
            )
        )

    store = _ConcurrentScanStore(tenant_jobs)
    adapter = _ConcurrentFakeSemgrepAdapter(target_tenants)
    policy = ValidationExecutionPolicy(
        tool_name="semgrep",
        supported_targets=[TARGET_REPOSITORY_PATH],
        runs_in_sandbox_required=False,
        execution_enabled=True,
        network_mode=NETWORK_NONE,
        max_runtime_seconds=30,
        max_output_bytes=50_000,
        artifact_capture_enabled=True,
    )

    async def _fake_projection(db, job):
        del db
        expected_tenant = store.tenant_by_model[job.threat_model_id]
        projected_tenants = [
            finding.raw_output["tenant_marker"]
            for finding in store.findings_by_job[job.id]
        ]
        assert projected_tenants == [expected_tenant]
        store.projections_by_model[job.threat_model_id].extend(projected_tenants)

    async def _worker_path(runner_id: str):
        await _record_runner_heartbeat(runner_id, status="idle")
        claimed_job_id = await _claim_next_pending_job(runner_id)
        if claimed_job_id is None:
            return None
        await _record_runner_heartbeat(
            runner_id,
            status="running",
            current_scan_job_id=claimed_job_id,
        )
        await run_scan_job(claimed_job_id)
        await _record_runner_heartbeat(runner_id, status="idle")
        return claimed_job_id

    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_EXECUTION_CONTEXT", "worker")
    with (
        patch(
            "app.services.scan_worker.async_session",
            side_effect=lambda: _ConcurrentScanSessionContext(store),
        ),
        patch("app.services.scan_worker.validation_worker_execution_enabled", return_value=True),
        patch(
            "app.services.scan_worker.default_validation_tool_registry",
            return_value=_SingleItemRegistry(adapter, name_attr="name"),
        ),
        patch(
            "app.services.scan_worker.default_validation_execution_policy_registry",
            return_value=_SingleItemRegistry(policy, name_attr="tool_name"),
        ),
        patch(
            "app.services.scan_worker._rebuild_evidence_projection_after_scan",
            side_effect=_fake_projection,
        ),
        patch("app.services.scan_mapper.run_semantic_mapping", new_callable=AsyncMock),
    ):
        claimed_ids = await asyncio.gather(
            *[_worker_path(f"runner-{index}") for index in range(5)]
        )

    claimed_ids = [claimed_id for claimed_id in claimed_ids if claimed_id is not None]
    assert set(claimed_ids) == {job.id for job in tenant_jobs}
    assert len(claimed_ids) == len(set(claimed_ids))
    assert sorted(adapter.started_targets) == sorted(target_tenants)

    for job in tenant_jobs:
        tenant_marker = store.tenant_by_model[job.threat_model_id]
        assert job.status == "completed"
        assert job.attempt_count == 1
        assert job.runner_id is not None
        assert job.claimed_at is not None
        assert job.heartbeat_at is not None
        assert job.lease_expires_at is not None
        assert job.finding_count == 1
        assert job.error_message is None
        assert [
            finding.raw_output["tenant_marker"]
            for finding in store.findings_by_job[job.id]
        ] == [tenant_marker]
        assert store.projections_by_model[job.threat_model_id] == [tenant_marker]

    projected_model_ids = set(store.projections_by_model)
    assert projected_model_ids == {job.threat_model_id for job in tenant_jobs}
    assert set(store.heartbeats) == {f"runner-{index}" for index in range(5)}
    assert all(heartbeat.status == "idle" for heartbeat in store.heartbeats.values())
    assert all(
        heartbeat.current_scan_job_id is None
        for heartbeat in store.heartbeats.values()
    )
    assert store.commit_count >= len(tenant_jobs) * 3


@pytest.mark.asyncio
async def test_claim_query_uses_skip_locked_pending_ordering():
    """The managed runner claim query should be safe for multiple worker replicas."""
    from app.services.scan_worker import _claim_next_pending_job

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_tx_ctx = AsyncMock()
    mock_tx_ctx.__aenter__ = AsyncMock(return_value=None)
    mock_tx_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_session.begin = MagicMock(return_value=mock_tx_ctx)

    with patch("app.services.scan_worker.async_session", return_value=mock_ctx):
        result = await _claim_next_pending_job("test-runner")

    assert result is None
    statement = mock_session.execute.await_args.args[0]
    compiled = str(statement)
    compiled_params = statement.compile().params
    for_update = statement._for_update_arg
    assert for_update is not None
    assert for_update.skip_locked is True
    assert "scan_jobs.status" in compiled
    assert "scan_jobs.created_at" in compiled
    assert "pending" in compiled_params.values()


@pytest.mark.asyncio
async def test_completed_scan_rebuilds_evidence_projection():
    from app.services.scan_worker import _rebuild_evidence_projection_after_scan

    threat_model_id = uuid.uuid4()
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=threat_model_id)
    threat_model = SimpleNamespace(id=threat_model_id)
    status = SimpleNamespace(finding_count=3, source_count=4)

    result = MagicMock()
    result.scalar_one_or_none.return_value = threat_model

    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    with patch(
        "app.services.evidence_projection.rebuild_evidence_graph",
        new_callable=AsyncMock,
        return_value=status,
    ) as rebuild:
        await _rebuild_evidence_projection_after_scan(db, job)

    rebuild.assert_awaited_once_with(db, threat_model)
    db.commit.assert_awaited_once()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_evidence_projection_failure_does_not_raise_from_scan_completion():
    from app.services.scan_worker import _rebuild_evidence_projection_after_scan

    threat_model_id = uuid.uuid4()
    job = SimpleNamespace(id=uuid.uuid4(), threat_model_id=threat_model_id)
    threat_model = SimpleNamespace(id=threat_model_id)

    result = MagicMock()
    result.scalar_one_or_none.return_value = threat_model

    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    with patch(
        "app.services.evidence_projection.rebuild_evidence_graph",
        new_callable=AsyncMock,
        side_effect=RuntimeError("projection failed"),
    ) as rebuild:
        await _rebuild_evidence_projection_after_scan(db, job)

    rebuild.assert_awaited_once_with(db, threat_model)
    db.commit.assert_not_awaited()
    db.rollback.assert_awaited_once()


# ---------------------------------------------------------------------------
# run_polling_loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_polling_loop_processes_one_job_then_shuts_down():
    """run_polling_loop claims a job, calls run_scan_job, then stops on shutdown signal."""
    from app.services.scan_worker import run_polling_loop

    job_id = uuid.uuid4()
    call_count = 0

    async def _fake_claim(runner_id: str):
        assert runner_id
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return job_id
        # Second call: return None and trigger shutdown via the event
        return None

    executed: list[uuid.UUID] = []

    async def _fake_run_scan_job(jid):
        executed.append(jid)

    # Patch: fast poll interval, fast backoff so the test doesn't actually sleep
    with (
        patch("app.services.scan_worker._reap_stuck_jobs", new_callable=AsyncMock),
        patch("app.services.scan_worker._claim_next_pending_job", side_effect=_fake_claim),
        patch("app.services.scan_worker.run_scan_job", side_effect=_fake_run_scan_job),
        patch("app.services.scan_worker._record_runner_heartbeat", new_callable=AsyncMock),
    ):
        # Let the loop run briefly then cancel it
        task = asyncio.create_task(
            run_polling_loop(poll_interval_seconds=0.01, idle_backoff_max=0.01)
        )
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert job_id in executed


@pytest.mark.asyncio
async def test_polling_loop_backoff_on_empty_queue():
    """When the queue is empty the loop backs off without crashing."""
    from app.services.scan_worker import run_polling_loop

    async def _always_empty(runner_id: str):
        assert runner_id
        return None

    with (
        patch("app.services.scan_worker._reap_stuck_jobs", new_callable=AsyncMock),
        patch("app.services.scan_worker._claim_next_pending_job", side_effect=_always_empty),
        patch("app.services.scan_worker._record_runner_heartbeat", new_callable=AsyncMock),
    ):
        task = asyncio.create_task(
            run_polling_loop(poll_interval_seconds=0.01, idle_backoff_max=0.05)
        )
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    # No assertions needed — the test passes if no exception is raised


@pytest.mark.asyncio
async def test_polling_loop_processes_orchestration_task_when_scan_queue_empty():
    """The managed worker also drains durable orchestration tasks when scans are idle."""
    from app.services.scan_worker import run_polling_loop

    orchestration_task_id = uuid.uuid4()
    orchestration_calls = 0

    async def _always_empty_scan_queue(runner_id: str):
        assert runner_id
        return None

    async def _fake_run_one_orchestration_task():
        nonlocal orchestration_calls
        orchestration_calls += 1
        if orchestration_calls == 1:
            return orchestration_task_id
        return None

    with (
        patch("app.services.scan_worker._reap_stuck_jobs", new_callable=AsyncMock),
        patch(
            "app.services.scan_worker._claim_next_pending_job",
            side_effect=_always_empty_scan_queue,
        ),
        patch("app.services.scan_worker._record_runner_heartbeat", new_callable=AsyncMock),
        patch(
            "app.services.orchestration_worker.run_one_pending_orchestration_task",
            side_effect=_fake_run_one_orchestration_task,
        ),
    ):
        task = asyncio.create_task(
            run_polling_loop(poll_interval_seconds=0.01, idle_backoff_max=0.01)
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert orchestration_calls >= 1


@pytest.mark.asyncio
async def test_polling_loop_reaps_stuck_jobs_on_startup():
    """A restarted worker should not wait a full interval before reaping stale running jobs."""
    from app.services.scan_worker import run_polling_loop

    reap_calls = 0

    async def _fake_reap():
        nonlocal reap_calls
        reap_calls += 1
        return 0

    async def _always_empty(runner_id: str):
        assert runner_id
        return None

    with (
        patch("app.services.scan_worker._reap_stuck_jobs", side_effect=_fake_reap),
        patch("app.services.scan_worker._claim_next_pending_job", side_effect=_always_empty),
        patch("app.services.scan_worker._record_runner_heartbeat", new_callable=AsyncMock),
    ):
        task = asyncio.create_task(
            run_polling_loop(
                poll_interval_seconds=0.01,
                idle_backoff_max=0.01,
                reap_interval_seconds=60,
            )
        )
        await asyncio.sleep(0.03)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert reap_calls >= 1
