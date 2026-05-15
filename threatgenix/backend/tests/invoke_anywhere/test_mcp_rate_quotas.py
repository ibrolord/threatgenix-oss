from __future__ import annotations

import pytest

from app.config import settings
from app.services.agent_access_limits import (
    AgentAccessLimitExceeded,
    AgentAccessUsage,
    enforce_agent_access_limits,
    reset_agent_access_limits,
)


@pytest.fixture(autouse=True)
def _reset_agent_access_limits():
    reset_agent_access_limits()
    yield
    reset_agent_access_limits()


def test_agent_access_tracks_token_and_tenant_rate_limits(monkeypatch):
    monkeypatch.setattr(settings, "agent_access_window_seconds", 60)
    monkeypatch.setattr(settings, "agent_token_rate_limit", 1)
    monkeypatch.setattr(settings, "agent_tenant_rate_limit", 10)

    first = enforce_agent_access_limits(
        tenant_key="tenant:a",
        token_fingerprint="token-a",
        usage=AgentAccessUsage(),
        now=10,
    )

    assert first.rate_limit["token_remaining"] == 0
    with pytest.raises(AgentAccessLimitExceeded) as exc_info:
        enforce_agent_access_limits(
            tenant_key="tenant:a",
            token_fingerprint="token-a",
            usage=AgentAccessUsage(),
            now=11,
        )
    assert exc_info.value.limit_type == "token_rate"
    assert exc_info.value.metric == "api_calls"
    assert exc_info.value.detail["retry_after_seconds"] >= 1


def test_agent_access_enforces_scan_ai_and_bundle_quotas(monkeypatch):
    monkeypatch.setattr(settings, "agent_access_window_seconds", 60)
    monkeypatch.setattr(settings, "agent_token_rate_limit", 100)
    monkeypatch.setattr(settings, "agent_tenant_rate_limit", 100)
    monkeypatch.setattr(settings, "agent_scan_minute_quota", 4)
    monkeypatch.setattr(settings, "agent_ai_token_quota", 1_000)
    monkeypatch.setattr(settings, "agent_bundle_storage_quota_bytes", 512)

    first = enforce_agent_access_limits(
        tenant_key="tenant:a",
        token_fingerprint="token-a",
        usage=AgentAccessUsage(scan_minutes=2, ai_tokens=500, bundle_storage_bytes=256),
        now=10,
    )

    assert first.quotas["scan_minutes"]["remaining"] == 2
    assert first.quotas["ai_tokens"]["remaining"] == 500
    assert first.quotas["bundle_storage_bytes"]["remaining"] == 256
    with pytest.raises(AgentAccessLimitExceeded) as exc_info:
        enforce_agent_access_limits(
            tenant_key="tenant:a",
            token_fingerprint="token-a",
            usage=AgentAccessUsage(scan_minutes=3, ai_tokens=100, bundle_storage_bytes=1),
            now=11,
        )
    assert exc_info.value.limit_type == "tenant_quota"
    assert exc_info.value.metric == "scan_minutes"


def test_agent_access_window_reset_allows_follow_up(monkeypatch):
    monkeypatch.setattr(settings, "agent_access_window_seconds", 60)
    monkeypatch.setattr(settings, "agent_token_rate_limit", 1)
    monkeypatch.setattr(settings, "agent_tenant_rate_limit", 1)

    enforce_agent_access_limits(
        tenant_key="tenant:a",
        token_fingerprint="token-a",
        usage=AgentAccessUsage(),
        now=10,
    )
    second = enforce_agent_access_limits(
        tenant_key="tenant:a",
        token_fingerprint="token-a",
        usage=AgentAccessUsage(),
        now=71,
    )

    assert second.rate_limit["token_remaining"] == 0
