from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.models.scan import ScanAuthorization, ScanJob, ValidationSchedule
from app.services.validation_scheduler import enqueue_due_validation_runs


class _ScalarsAllResult:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class FakeSchedulerDB:
    def __init__(self, schedules: list[ValidationSchedule]) -> None:
        self.schedules = schedules
        self.added: list[object] = []
        self.committed = False

    async def execute(self, statement):
        del statement
        return _ScalarsAllResult(self.schedules)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        for item in self.added:
            if isinstance(item, ScanJob) and item.id is None:
                item.id = uuid.uuid4()

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, obj: object) -> None:
        del obj


@pytest.mark.asyncio
async def test_enqueue_due_validation_runs_creates_pending_scan_job(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    repo = tmp_path / "repo"
    repo.mkdir()
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        target_node_id=node_id,
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target=str(repo),
        scope="external",
        cadence="daily",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        next_run_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )
    db = FakeSchedulerDB([schedule])
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))

    with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
        jobs = await enqueue_due_validation_runs(
            db,  # type: ignore[arg-type]
            now=datetime(2026, 4, 27, tzinfo=timezone.utc),
        )

    assert len(jobs) == 1
    assert db.committed is True
    assert jobs[0].status == "pending"
    assert jobs[0].tool_name == "semgrep"
    assert jobs[0].targets == {str(node_id): str(repo)}
    assert schedule.last_run_at == datetime(2026, 4, 27, tzinfo=timezone.utc)
    assert schedule.next_run_at is not None
    assert any(isinstance(item, ScanAuthorization) for item in db.added)


@pytest.mark.asyncio
async def test_enqueue_due_validation_runs_skips_blocked_schedule(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        scope="external",
        cadence="daily",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        next_run_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )
    db = FakeSchedulerDB([schedule])
    monkeypatch.delenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", raising=False)

    with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
        jobs = await enqueue_due_validation_runs(
            db,  # type: ignore[arg-type]
            now=datetime(2026, 4, 27, tzinfo=timezone.utc),
        )

    assert jobs == []
    assert db.committed is True
    assert db.added == []
    assert schedule.next_run_at is not None


@pytest.mark.asyncio
async def test_enqueue_due_validation_runs_noops_in_try_sandbox(monkeypatch):
    monkeypatch.delenv("THREATGENIX_VALIDATION_RUNTIME_MODE", raising=False)
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        scope="external",
        cadence="daily",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        next_run_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )
    db = FakeSchedulerDB([schedule])

    jobs = await enqueue_due_validation_runs(
        db,  # type: ignore[arg-type]
        now=datetime(2026, 4, 27, tzinfo=timezone.utc),
    )

    assert jobs == []
    assert db.committed is False
    assert db.added == []


@pytest.mark.asyncio
async def test_enqueue_due_validation_runs_allows_managed_runner(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    repo = tmp_path / "repo"
    repo.mkdir()
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    schedule = ValidationSchedule(
        id=uuid.uuid4(),
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        name="Repository SAST",
        tool_name="semgrep",
        target_type="repository_path",
        target=str(repo),
        scope="external",
        cadence="daily",
        enabled=True,
        authorization_required=True,
        authorization_acknowledged_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        next_run_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 26, tzinfo=timezone.utc),
    )
    db = FakeSchedulerDB([schedule])
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))

    with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
        jobs = await enqueue_due_validation_runs(
            db,  # type: ignore[arg-type]
            now=datetime(2026, 4, 27, tzinfo=timezone.utc),
        )

    assert len(jobs) == 1
    assert jobs[0].status == "pending"
    assert jobs[0].tool_name == "semgrep"
    assert db.committed is True
