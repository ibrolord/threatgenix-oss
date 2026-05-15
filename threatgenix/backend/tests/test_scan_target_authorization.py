from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.scan import ScanTargetAuthorization
import app.services.scan_target_authorization as target_auth
from app.services.scan_target_authorization import (
    ScanTargetAuthorizationError,
    build_target_authorization_challenge,
    normalized_live_target_host,
    nuclei_target_verification_required,
    require_verified_nuclei_target_authorization,
    verify_http_target_authorization,
)
from app.services.validation_isolated_runner import IsolatedRunnerConfigurationError


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _DB:
    def __init__(self, value):
        self.execute = AsyncMock(return_value=_Result(value))


class _WritableDB(_DB):
    def __init__(self):
        super().__init__(None)
        self.added = []
        self.commit = AsyncMock()
        self.refresh = AsyncMock()

    def add(self, value):
        self.added.append(value)


def test_normalized_live_target_host_rejects_missing_host():
    with pytest.raises(ValueError, match="host"):
        normalized_live_target_host("https:///missing")


def test_nuclei_target_verification_cannot_be_disabled_in_staging(monkeypatch):
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION", "false")

    assert nuclei_target_verification_required() is True


@pytest.mark.asyncio
async def test_require_verified_target_authorization_passes_active_record():
    now = datetime.now(timezone.utc)
    auth = ScanTargetAuthorization(
        id=uuid4(),
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        hostname="scan.example.com",
        normalized_host="scan.example.com",
        proof_method="dns_txt",
        status="verified",
        verified_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(days=1),
    )
    db = _DB(auth)

    result = await require_verified_nuclei_target_authorization(
        db,  # type: ignore[arg-type]
        owner_id=auth.owner_id,
        threat_model_id=auth.threat_model_id,
        target="https://scan.example.com/login",
    )

    assert result is auth
    assert db.execute.await_count == 1


@pytest.mark.asyncio
async def test_require_verified_target_authorization_blocks_missing_record():
    with pytest.raises(IsolatedRunnerConfigurationError, match="ownership"):
        await require_verified_nuclei_target_authorization(
            _DB(None),  # type: ignore[arg-type]
            owner_id=uuid4(),
            threat_model_id=uuid4(),
            target="https://scan.example.com",
        )


@pytest.mark.asyncio
async def test_require_verified_target_authorization_requires_tenant_context():
    with pytest.raises(IsolatedRunnerConfigurationError, match="tenant"):
        await require_verified_nuclei_target_authorization(
            _DB(None),  # type: ignore[arg-type]
            owner_id=None,
            threat_model_id=uuid4(),
            target="https://scan.example.com",
        )


def test_target_authorization_challenge_is_bound_to_tenant_model_and_host(
    monkeypatch,
):
    monkeypatch.setattr(target_auth.settings, "secret_key", "unit-test-secret")
    owner_id = uuid4()
    threat_model_id = uuid4()

    challenge = build_target_authorization_challenge(
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        target_url="http://8.8.8.8/login",
    )

    assert challenge.proof_method == "http_file"
    assert challenge.normalized_host == "8.8.8.8"
    assert challenge.proof_url == "http://8.8.8.8/.well-known/threatgenix-validation.txt"
    with pytest.raises(ScanTargetAuthorizationError, match="signature"):
        target_auth._verify_challenge_token(  # noqa: SLF001
            challenge.proof_token + "tamper",
            owner_id=owner_id,
            threat_model_id=threat_model_id,
            normalized_host="8.8.8.8",
            now=datetime.now(timezone.utc),
        )


@pytest.mark.asyncio
async def test_verify_http_target_authorization_persists_verified_record(
    monkeypatch,
):
    monkeypatch.setattr(target_auth.settings, "secret_key", "unit-test-secret")
    owner_id = uuid4()
    threat_model_id = uuid4()
    challenge = build_target_authorization_challenge(
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        target_url="http://8.8.8.8/login",
    )
    monkeypatch.setattr(
        target_auth,
        "_fetch_http_proof",
        AsyncMock(return_value=f"verified\n{challenge.proof_token}\n"),
    )
    db = _WritableDB()

    authorization = await verify_http_target_authorization(
        db,  # type: ignore[arg-type]
        owner_id=owner_id,
        threat_model_id=threat_model_id,
        target_url="http://8.8.8.8/login",
        proof_token=challenge.proof_token,
    )

    assert authorization in db.added
    assert authorization.status == "verified"
    assert authorization.normalized_host == "8.8.8.8"
    assert authorization.proof_method == "http_file"
    assert authorization.proof_reference == challenge.proof_url
    assert db.commit.await_count == 1
    assert db.refresh.await_count == 1
