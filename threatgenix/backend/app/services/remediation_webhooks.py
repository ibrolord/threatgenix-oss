"""Signed remediation evidence webhook helpers."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from app.config import settings
from app.models.remediation_webhook import RemediationWebhookNonce
from app.schemas.security_review import AgentRemediationEvidenceWebhookRequest
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

SIGNATURE_HEADER = "x-ssr-webhook-signature"
TIMESTAMP_HEADER = "x-ssr-webhook-timestamp"
NONCE_HEADER = "x-ssr-webhook-nonce"
SIGNATURE_SCHEME = "hmac_sha256_v1"
SIGNATURE_PREFIX = "sha256="
SIGNATURE_TOLERANCE_SECONDS = 300
REPLAY_NONCE_TTL_SECONDS = SIGNATURE_TOLERANCE_SECONDS

_SEEN_NONCES: dict[str, float] = {}


class RemediationWebhookSignatureError(ValueError):
    """Raised when an inbound remediation callback is unsigned or invalid."""


def remediation_webhook_required_headers_template() -> dict[str, str]:
    return {
        "X-SSR-Webhook-Timestamp": "<unix_timestamp_seconds>",
        "X-SSR-Webhook-Nonce": "<unique_random_nonce>",
        "X-SSR-Webhook-Signature": "sha256=<hmac_sha256(timestamp.nonce.raw_body)>",
    }


def remediation_webhook_signature_base_string() -> str:
    return "timestamp + '.' + nonce + '.' + raw_request_body"


def sign_remediation_webhook_body(
    *,
    timestamp: str,
    nonce: str,
    raw_body: bytes,
    secret: str | None = None,
) -> str:
    signing_secret = (
        secret or settings.remediation_webhook_signature_secret or settings.secret_key
    ).encode("utf-8")
    digest = hmac.new(
        signing_secret,
        _signature_payload(timestamp=timestamp, nonce=nonce, raw_body=raw_body),
        hashlib.sha256,
    ).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def verify_remediation_webhook_signature(
    *,
    headers: Mapping[str, str],
    raw_body: bytes,
    scope: str,
    now: float | None = None,
) -> None:
    current_time = time.time() if now is None else now
    normalized_headers = {key.casefold(): value for key, value in headers.items()}
    timestamp = _required_header(normalized_headers, TIMESTAMP_HEADER)
    nonce = _required_header(normalized_headers, NONCE_HEADER)
    signature = _required_header(normalized_headers, SIGNATURE_HEADER)
    _validate_timestamp(timestamp, now=current_time)
    _consume_nonce(scope=scope, nonce=nonce, now=current_time)
    expected = sign_remediation_webhook_body(
        timestamp=timestamp,
        nonce=nonce,
        raw_body=raw_body,
    )
    if not hmac.compare_digest(signature, expected):
        _forget_nonce(scope=scope, nonce=nonce)
        raise RemediationWebhookSignatureError("Invalid remediation webhook signature.")


async def verify_remediation_webhook_signature_durable(
    *,
    headers: Mapping[str, str],
    raw_body: bytes,
    scope: str,
    db: AsyncSession,
    provider: str | None = None,
    now: float | None = None,
) -> None:
    current_time = time.time() if now is None else now
    normalized_headers = {key.casefold(): value for key, value in headers.items()}
    timestamp = _required_header(normalized_headers, TIMESTAMP_HEADER)
    nonce = _required_header(normalized_headers, NONCE_HEADER)
    signature = _required_header(normalized_headers, SIGNATURE_HEADER)
    _validate_timestamp(timestamp, now=current_time)
    expected = sign_remediation_webhook_body(
        timestamp=timestamp,
        nonce=nonce,
        raw_body=raw_body,
    )
    if not hmac.compare_digest(signature, expected):
        raise RemediationWebhookSignatureError("Invalid remediation webhook signature.")
    await _consume_nonce_durable(
        db=db,
        scope=scope,
        nonce=nonce,
        provider=provider,
        now=current_time,
    )


def normalize_remediation_webhook_event(
    body: AgentRemediationEvidenceWebhookRequest,
) -> str:
    if body.provider == "github_pr" or body.pull_request_url:
        return "pull_request_evidence"
    if body.provider == "github_issue":
        return "issue_evidence"
    if body.provider in {"linear", "jira"}:
        return "ticket_evidence"
    return "manual_evidence"


def _signature_payload(*, timestamp: str, nonce: str, raw_body: bytes) -> bytes:
    return f"{timestamp}.{nonce}.".encode("utf-8") + raw_body


def _required_header(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    if value is None or not value.strip():
        raise RemediationWebhookSignatureError(
            f"Missing remediation webhook header: {name}."
        )
    return value.strip()


def _validate_timestamp(timestamp: str, *, now: float) -> None:
    try:
        observed = int(timestamp)
    except ValueError as exc:
        raise RemediationWebhookSignatureError(
            "Invalid remediation webhook timestamp."
        ) from exc
    if abs(now - observed) > SIGNATURE_TOLERANCE_SECONDS:
        raise RemediationWebhookSignatureError(
            "Remediation webhook timestamp is outside the replay window."
        )


def _consume_nonce(*, scope: str, nonce: str, now: float) -> None:
    _purge_expired_nonces(now)
    key = f"{scope}:{nonce}"
    if key in _SEEN_NONCES:
        raise RemediationWebhookSignatureError(
            "Remediation webhook nonce has already been used."
        )
    _SEEN_NONCES[key] = now + REPLAY_NONCE_TTL_SECONDS


async def _consume_nonce_durable(
    *,
    db: AsyncSession,
    scope: str,
    nonce: str,
    provider: str | None,
    now: float,
) -> None:
    observed = datetime.fromtimestamp(now, tz=UTC)
    await db.execute(
        delete(RemediationWebhookNonce).where(
            RemediationWebhookNonce.expires_at <= observed
        )
    )
    db.add(
        RemediationWebhookNonce(
            scope=scope,
            nonce_hash=_nonce_hash(nonce),
            provider=provider,
            expires_at=observed + timedelta(seconds=REPLAY_NONCE_TTL_SECONDS),
        )
    )
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise RemediationWebhookSignatureError(
            "Remediation webhook nonce has already been used."
        ) from exc


def _nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _forget_nonce(*, scope: str, nonce: str) -> None:
    _SEEN_NONCES.pop(f"{scope}:{nonce}", None)


def _purge_expired_nonces(now: float) -> None:
    expired = [key for key, expires_at in _SEEN_NONCES.items() if expires_at <= now]
    for key in expired:
        _SEEN_NONCES.pop(key, None)
