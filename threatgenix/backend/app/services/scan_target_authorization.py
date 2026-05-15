"""Tenant-scoped target authorization checks for live validation scans."""

from __future__ import annotations

import os
import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from uuid import UUID

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.scan import ScanTargetAuthorization
from app.services.validation_env import validation_env_value
from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target
from app.services.validation_isolated_runner import IsolatedRunnerConfigurationError

NUCLEI_REQUIRE_TARGET_VERIFICATION_ENV = (
    "THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION"
)
_TOKEN_PREFIX = "tgxv1"
_HTTP_PROOF_PATH = "/.well-known/threatgenix-validation.txt"
_CHALLENGE_TTL_MINUTES = 30
_AUTHORIZATION_TTL_DAYS = 30
_MAX_PROOF_BYTES = 16_384


class ScanTargetAuthorizationError(ValueError):
    """Raised when a live target proof cannot be verified."""


@dataclass(frozen=True)
class TargetAuthorizationChallenge:
    target_url: str
    hostname: str
    normalized_host: str
    proof_token: str
    proof_method: str
    proof_url: str
    expires_at: datetime


def normalized_live_target_host(target: str) -> str:
    parsed = urlparse(target.strip())
    host = (parsed.hostname or "").strip().casefold()
    if not host:
        raise LiveTargetSafetyError("Live URL scan target host is required.")
    return host


def nuclei_target_verification_required() -> bool:
    raw = validation_env_value(NUCLEI_REQUIRE_TARGET_VERIFICATION_ENV)
    if raw is None:
        return True
    if raw.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return _production_like_app_env()


async def require_verified_nuclei_target_authorization(
    db: AsyncSession,
    *,
    owner_id: UUID | None,
    threat_model_id: UUID | None,
    target: str,
) -> ScanTargetAuthorization | None:
    """Require an active tenant proof before isolated Nuclei execution.

    Development can opt out for controlled local tests. Staging and production
    cannot opt out, because an acknowledgement checkbox is not proof of control
    over the target being scanned.
    """
    if not nuclei_target_verification_required():
        return None
    if owner_id is None or threat_model_id is None:
        raise IsolatedRunnerConfigurationError(
            "Nuclei isolated execution requires tenant and threat model context."
        )
    host = normalized_live_target_host(target)
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(ScanTargetAuthorization)
        .where(
            ScanTargetAuthorization.owner_id == owner_id,
            ScanTargetAuthorization.threat_model_id == threat_model_id,
            ScanTargetAuthorization.normalized_host == host,
            ScanTargetAuthorization.status == "verified",
            ScanTargetAuthorization.verified_at <= now,
            or_(
                ScanTargetAuthorization.expires_at.is_(None),
                ScanTargetAuthorization.expires_at > now,
            ),
        )
        .order_by(ScanTargetAuthorization.verified_at.desc())
        .limit(1)
    )
    authorization = result.scalar_one_or_none()
    if authorization is None:
        raise IsolatedRunnerConfigurationError(
            "Nuclei isolated execution requires active target ownership verification."
        )
    return authorization


def build_target_authorization_challenge(
    *,
    owner_id: UUID,
    threat_model_id: UUID,
    target_url: str,
    now: datetime | None = None,
) -> TargetAuthorizationChallenge:
    """Build a short-lived proof token for a Nuclei target authorization."""
    safe_target = target_url.strip()
    validate_live_url_target(safe_target)
    parsed = urlparse(safe_target)
    host = parsed.hostname or ""
    normalized_host = normalized_live_target_host(safe_target)
    issued_at = now or datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=_CHALLENGE_TTL_MINUTES)
    proof_token = _sign_challenge_token(
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        normalized_host=normalized_host,
        expires_at=expires_at,
    )
    return TargetAuthorizationChallenge(
        target_url=safe_target,
        hostname=host,
        normalized_host=normalized_host,
        proof_token=proof_token,
        proof_method="http_file",
        proof_url=_default_http_proof_url(safe_target),
        expires_at=expires_at,
    )


async def verify_http_target_authorization(
    db: AsyncSession,
    *,
    owner_id: UUID,
    threat_model_id: UUID,
    target_url: str,
    proof_token: str,
    proof_url: str | None = None,
    now: datetime | None = None,
) -> ScanTargetAuthorization:
    """Verify a public HTTP proof file and persist a tenant-scoped target grant."""
    checked_at = now or datetime.now(timezone.utc)
    safe_target = target_url.strip()
    validate_live_url_target(safe_target)
    normalized_host = normalized_live_target_host(safe_target)
    _verify_challenge_token(
        proof_token,
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        normalized_host=normalized_host,
        now=checked_at,
    )
    reference = (proof_url or _default_http_proof_url(safe_target)).strip()
    _validate_http_proof_url(reference, safe_target)
    body = await _fetch_http_proof(reference)
    if proof_token not in body:
        raise ScanTargetAuthorizationError(
            "HTTP proof file did not contain the active ThreatGenix challenge token."
        )

    parsed = urlparse(safe_target)
    authorization = ScanTargetAuthorization(
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        hostname=parsed.hostname or normalized_host,
        normalized_host=normalized_host,
        target_url=safe_target,
        proof_method="http_file",
        proof_reference=reference,
        status="verified",
        verified_at=checked_at,
        expires_at=checked_at + timedelta(days=_AUTHORIZATION_TTL_DAYS),
    )
    db.add(authorization)
    await db.commit()
    await db.refresh(authorization)
    return authorization


def _production_like_app_env() -> bool:
    raw = os.getenv("APP_ENV") or os.getenv("THREATGENIX_APP_ENV") or ""
    return raw.strip().lower() in {"production", "staging"}


def _sign_challenge_token(
    *,
    owner_id: UUID,
    threat_model_id: UUID,
    normalized_host: str,
    expires_at: datetime,
) -> str:
    payload = {
        "host": normalized_host,
        "owner_id": str(owner_id),
        "threat_model_id": str(threat_model_id),
        "expires_at": int(expires_at.timestamp()),
        "nonce": secrets.token_urlsafe(18),
    }
    encoded = _b64url(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    signature = _b64url(
        hmac.new(
            settings.secret_key.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    return f"{_TOKEN_PREFIX}.{encoded}.{signature}"


def _verify_challenge_token(
    token: str,
    *,
    owner_id: UUID,
    threat_model_id: UUID,
    normalized_host: str,
    now: datetime,
) -> None:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != _TOKEN_PREFIX:
        raise ScanTargetAuthorizationError("Target authorization token is malformed.")
    encoded_payload = parts[1]
    expected_signature = _b64url(
        hmac.new(
            settings.secret_key.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(expected_signature, parts[2]):
        raise ScanTargetAuthorizationError(
            "Target authorization token signature is invalid."
        )
    try:
        payload = json.loads(_unb64url(encoded_payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ScanTargetAuthorizationError(
            "Target authorization token payload is invalid."
        ) from exc
    if payload.get("owner_id") != str(owner_id) or payload.get(
        "threat_model_id"
    ) != str(threat_model_id):
        raise ScanTargetAuthorizationError(
            "Target authorization token does not match this tenant or threat model."
        )
    if payload.get("host") != normalized_host:
        raise ScanTargetAuthorizationError(
            "Target authorization token does not match this host."
        )
    try:
        expires_at = datetime.fromtimestamp(
            int(payload.get("expires_at")), tz=timezone.utc
        )
    except (TypeError, ValueError, OSError) as exc:
        raise ScanTargetAuthorizationError(
            "Target authorization token expiry is invalid."
        ) from exc
    if expires_at <= now:
        raise ScanTargetAuthorizationError("Target authorization token has expired.")


def _default_http_proof_url(target_url: str) -> str:
    parsed = urlparse(target_url.strip())
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return f"{parsed.scheme}://{netloc}{_HTTP_PROOF_PATH}"


def _validate_http_proof_url(proof_url: str, target_url: str) -> None:
    validate_live_url_target(proof_url)
    proof = urlparse(proof_url)
    target = urlparse(target_url)
    if proof.username or proof.password:
        raise ScanTargetAuthorizationError(
            "HTTP proof URL must not include credentials."
        )
    if proof.scheme not in {"http", "https"}:
        raise ScanTargetAuthorizationError("HTTP proof URL must be http(s).")
    if (proof.hostname or "").casefold() != (target.hostname or "").casefold():
        raise ScanTargetAuthorizationError(
            "HTTP proof URL must use the same host as the scan target."
        )
    if proof.path != _HTTP_PROOF_PATH:
        raise ScanTargetAuthorizationError(
            f"HTTP proof URL must use {_HTTP_PROOF_PATH}."
        )


async def _fetch_http_proof(proof_url: str) -> str:
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(10.0),
            headers={"User-Agent": "threatgenix-target-verifier/1.0"},
        ) as client:
            async with client.stream("GET", proof_url) as response:
                if response.status_code != 200:
                    raise ScanTargetAuthorizationError(
                        f"HTTP proof URL returned HTTP {response.status_code}."
                    )
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > _MAX_PROOF_BYTES:
                        raise ScanTargetAuthorizationError(
                            "HTTP proof file is too large."
                        )
                    chunks.append(chunk)
    except httpx.HTTPError as exc:
        raise ScanTargetAuthorizationError(
            f"HTTP proof URL could not be fetched: {exc}"
        ) from exc
    return b"".join(chunks).decode("utf-8", errors="replace")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
