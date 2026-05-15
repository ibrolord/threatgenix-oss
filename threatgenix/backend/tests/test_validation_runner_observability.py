from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.scan import ValidationWorkerHeartbeat
from app.services.validation_runner_observability import (
    get_runner_queue_status,
    record_worker_heartbeat,
    validation_worker_version,
)


def test_validation_worker_version_is_bounded(monkeypatch):
    monkeypatch.setenv("FLY_IMAGE_REF", "registry.fly.io/threatgenix-api:" + "a" * 260)

    version = validation_worker_version()

    assert version is not None
    assert version.startswith("registry.fly.io/threatgenix-api:")
    assert len(version) == 50


@pytest.mark.asyncio
async def test_record_worker_heartbeat_refreshes_existing_runner_metadata(monkeypatch):
    monkeypatch.setenv("FLY_IMAGE_REF", "registry.fly.io/threatgenix-api:release-2026-04-29")
    heartbeat = ValidationWorkerHeartbeat(
        runner_id="runner-1",
        hostname="old-host",
        process_id=1,
        fly_machine_id="old-machine",
        started_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        status="idle",
        sandbox_mode="process",
        runtime_mode="managed",
        version="old-version",
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = heartbeat
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    await record_worker_heartbeat(db, runner_id="runner-1", status="running")

    assert heartbeat.hostname != "old-host"
    assert heartbeat.process_id != 1
    assert heartbeat.version == "registry.fly.io/threatgenix-api:release-2026-04-29"[:50]
    assert heartbeat.status == "running"


@pytest.mark.asyncio
async def test_runner_queue_status_uses_lease_expiry_for_stale_running(monkeypatch):
    captured = []
    values = [
        0,  # pending
        1,  # running
        0,  # failed
        None,  # oldest pending
        None,  # oldest running
        1,  # stale running
        1,  # active workers
        None,  # last heartbeat
    ]

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

        def scalar_one_or_none(self):
            return self.value

    class DB:
        async def execute(self, statement):
            captured.append(statement)
            return Result(values[len(captured) - 1])

    monkeypatch.setattr(
        "app.services.validation_runner_observability.managed_validation_runner_enabled",
        lambda: True,
    )

    status = await get_runner_queue_status(DB())  # type: ignore[arg-type]

    stale_query = str(captured[5])
    assert "scan_jobs.lease_expires_at" in stale_query
    assert status.stale_running_count == 1
    assert status.status == "degraded"


@pytest.mark.asyncio
async def test_runner_queue_status_self_hosted_without_worker_is_ready(monkeypatch):
    values = [0, 0, 0, None, None, 0, 0, None]

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

        def scalar_one_or_none(self):
            return self.value

    class DB:
        async def execute(self, _statement):
            return Result(values.pop(0))

    monkeypatch.setattr(
        "app.services.validation_runner_observability.managed_validation_runner_enabled",
        lambda: False,
    )

    status = await get_runner_queue_status(DB())  # type: ignore[arg-type]

    assert status.active_worker_count == 0
    assert status.status == "ready"
    assert "not required" in status.detail
