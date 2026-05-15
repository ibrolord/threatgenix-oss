"""Tenant and token access limits for agent/MCP review surfaces."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Literal

from fastapi import Request

from app.config import settings

AgentUsageMetric = Literal["api_calls", "scan_minutes", "ai_tokens", "bundle_storage_bytes"]


@dataclass(frozen=True)
class AgentAccessUsage:
    api_calls: int = 1
    scan_minutes: int = 0
    ai_tokens: int = 0
    bundle_storage_bytes: int = 0


@dataclass(frozen=True)
class AgentAccessDecision:
    rate_limit: dict[str, int | str]
    quotas: dict[str, dict[str, int]]


class AgentAccessLimitExceeded(Exception):
    def __init__(
        self,
        *,
        limit_type: str,
        metric: str,
        retry_after_seconds: int,
        detail: dict[str, object],
    ) -> None:
        super().__init__(str(detail.get("message") or "Agent access limit exceeded."))
        self.limit_type = limit_type
        self.metric = metric
        self.retry_after_seconds = retry_after_seconds
        self.detail = detail


@dataclass
class _Bucket:
    reset_at: float
    used: int = 0


_rate_buckets: dict[tuple[str, str], _Bucket] = {}
_quota_buckets: dict[tuple[str, str], _Bucket] = {}


def reset_agent_access_limits() -> None:
    """Clear in-process counters for deterministic tests and local development."""
    _rate_buckets.clear()
    _quota_buckets.clear()


def token_fingerprint_for_request(request: Request, fallback: str) -> str:
    authorization = request.headers.get("authorization") or ""
    scheme, _, value = authorization.partition(" ")
    token = value.strip() if scheme.lower() == "bearer" else authorization.strip()
    material = token or fallback
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def enforce_agent_access_limits(
    *,
    tenant_key: str,
    token_fingerprint: str,
    usage: AgentAccessUsage,
    now: float | None = None,
) -> AgentAccessDecision:
    current_time = time.time() if now is None else now
    window_seconds = max(int(settings.agent_access_window_seconds), 1)

    token_bucket = _bucket_for(_rate_buckets, ("token", token_fingerprint), current_time, window_seconds)
    tenant_bucket = _bucket_for(_rate_buckets, ("tenant", tenant_key), current_time, window_seconds)
    _assert_available(
        limit_type="token_rate",
        metric="api_calls",
        used=token_bucket.used,
        increment=usage.api_calls,
        limit=max(int(settings.agent_token_rate_limit), 1),
        retry_after_seconds=_bucket_retry_after_seconds(token_bucket, current_time),
    )
    _assert_available(
        limit_type="tenant_rate",
        metric="api_calls",
        used=tenant_bucket.used,
        increment=usage.api_calls,
        limit=max(int(settings.agent_tenant_rate_limit), 1),
        retry_after_seconds=_bucket_retry_after_seconds(tenant_bucket, current_time),
    )

    quota_limits = _quota_limits()
    quota_increments = {
        "scan_minutes": usage.scan_minutes,
        "ai_tokens": usage.ai_tokens,
        "bundle_storage_bytes": usage.bundle_storage_bytes,
    }
    quota_buckets = {
        metric: _bucket_for(_quota_buckets, (tenant_key, metric), current_time, window_seconds)
        for metric in quota_limits
    }
    for metric, limit in quota_limits.items():
        _assert_available(
            limit_type="tenant_quota",
            metric=metric,
            used=quota_buckets[metric].used,
            increment=max(quota_increments[metric], 0),
            limit=max(int(limit), 0),
            retry_after_seconds=_bucket_retry_after_seconds(quota_buckets[metric], current_time),
        )

    token_bucket.used += usage.api_calls
    tenant_bucket.used += usage.api_calls
    for metric, increment in quota_increments.items():
        quota_buckets[metric].used += max(increment, 0)

    return AgentAccessDecision(
        rate_limit={
            "window_seconds": window_seconds,
            "token_limit": int(settings.agent_token_rate_limit),
            "token_remaining": max(int(settings.agent_token_rate_limit) - token_bucket.used, 0),
            "tenant_limit": int(settings.agent_tenant_rate_limit),
            "tenant_remaining": max(int(settings.agent_tenant_rate_limit) - tenant_bucket.used, 0),
            "retry_after_seconds": _bucket_retry_after_seconds(token_bucket, current_time),
            "token_fingerprint": token_fingerprint,
        },
        quotas={
            metric: {
                "window_seconds": window_seconds,
                "limit": int(limit),
                "used": quota_buckets[metric].used,
                "remaining": max(int(limit) - quota_buckets[metric].used, 0),
            }
            for metric, limit in quota_limits.items()
        },
    )


def _quota_limits() -> dict[str, int]:
    return {
        "scan_minutes": int(settings.agent_scan_minute_quota),
        "ai_tokens": int(settings.agent_ai_token_quota),
        "bundle_storage_bytes": int(settings.agent_bundle_storage_quota_bytes),
    }


def _bucket_for(
    buckets: dict[tuple[str, str], _Bucket],
    key: tuple[str, str],
    now: float,
    window_seconds: int,
) -> _Bucket:
    bucket = buckets.get(key)
    if bucket is None or bucket.reset_at <= now:
        bucket = _Bucket(reset_at=now + window_seconds)
        buckets[key] = bucket
    return bucket


def _bucket_retry_after_seconds(bucket: _Bucket, now: float) -> int:
    return max(int(bucket.reset_at - now), 1)


def _assert_available(
    *,
    limit_type: str,
    metric: str,
    used: int,
    increment: int,
    limit: int,
    retry_after_seconds: int,
) -> None:
    if limit <= 0 or increment <= 0:
        return
    if used + increment <= limit:
        return
    remaining = max(limit - used, 0)
    raise AgentAccessLimitExceeded(
        limit_type=limit_type,
        metric=metric,
        retry_after_seconds=retry_after_seconds,
        detail={
            "message": f"ThreatGenix agent {metric} limit exceeded.",
            "limit_type": limit_type,
            "metric": metric,
            "limit": limit,
            "used": used,
            "requested": increment,
            "remaining": remaining,
            "retry_after_seconds": retry_after_seconds,
        },
    )
