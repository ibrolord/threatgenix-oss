"""Freshness helpers for evidence graph projections."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

FreshnessStatus = str


DEFAULT_AGING_AFTER = timedelta(days=14)
DEFAULT_STALE_AFTER = timedelta(days=45)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def derive_freshness_status(
    *,
    observed_at: datetime | None = None,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
    now: datetime | None = None,
    aging_after: timedelta = DEFAULT_AGING_AFTER,
    stale_after: timedelta = DEFAULT_STALE_AFTER,
) -> FreshnessStatus:
    """Return a conservative freshness label for an evidence item/source."""
    current = normalize_datetime(now) or utc_now()
    normalized_expires_at = normalize_datetime(expires_at)
    if normalized_expires_at is not None and normalized_expires_at <= current:
        return "expired"

    anchor = normalize_datetime(observed_at) or normalize_datetime(collected_at)
    if anchor is None:
        return "unknown"

    age = current - anchor
    if age <= aging_after:
        return "fresh"
    if age <= stale_after:
        return "aging"
    return "stale"


def freshness_from_source_status(status: str) -> FreshnessStatus:
    if status == "expired":
        return "expired"
    if status == "stale":
        return "stale"
    if status == "active":
        return "fresh"
    return "unknown"
