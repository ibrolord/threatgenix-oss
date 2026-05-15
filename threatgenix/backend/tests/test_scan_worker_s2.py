"""Tests for Phase S2 scan worker additions: auth header injection, credential lookup."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
import base64
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.services.credential_crypto import encrypt_secret
from app.services.scan_worker import _build_auth_headers, _build_execution_artifact
from app.services.validation_execution_policy import (
    NETWORK_TARGET_ONLY,
    TARGET_URL,
    ValidationExecutionPolicy,
)
from app.services.validation_tools import NUCLEI_TOOL_NAME, ValidationToolResult


def _make_cred(cred_type: str, secret: str, header_name: str | None = None):
    cred = MagicMock()
    cred.credential_type = cred_type
    cred.header_name = header_name
    cred.encrypted_secret = encrypt_secret(secret)
    return cred


class TestBuildAuthHeaders:
    def test_bearer_token_injects_authorization_header(self):
        cred = _make_cred("bearer_token", "my-token")
        headers = _build_auth_headers(cred)
        assert headers == ["-H", "Authorization: Bearer my-token"]

    def test_api_key_header_uses_provided_header_name(self):
        cred = _make_cred("api_key_header", "key-123", header_name="X-API-Key")
        headers = _build_auth_headers(cred)
        assert headers == ["-H", "X-API-Key: key-123"]

    def test_api_key_header_defaults_to_x_api_key_when_header_name_none(self):
        cred = _make_cred("api_key_header", "key-abc", header_name=None)
        headers = _build_auth_headers(cred)
        assert headers[1].startswith("X-API-Key: ")

    def test_basic_auth_encodes_as_base64(self):
        cred = _make_cred("basic_auth", "admin:password")
        headers = _build_auth_headers(cred)
        assert len(headers) == 2
        assert headers[0] == "-H"
        header_value = headers[1]
        assert header_value.startswith("Authorization: Basic ")
        encoded = header_value.split(" ")[-1]
        decoded = base64.b64decode(encoded).decode()
        assert decoded == "admin:password"

    def test_cookie_injects_cookie_header(self):
        cred = _make_cred("cookie", "session_id=abc123; csrf=def456")
        headers = _build_auth_headers(cred)
        assert headers == ["-H", "Cookie: session_id=abc123; csrf=def456"]

    def test_unknown_type_returns_empty_list(self):
        cred = _make_cred("bearer_token", "x")
        cred.credential_type = "unknown_future_type"
        headers = _build_auth_headers(cred)
        assert headers == []

    def test_secret_not_logged(self, caplog):
        """Ensure the plaintext secret does not appear in log output."""
        import logging
        cred = _make_cred("bearer_token", "SUPER-SECRET-VALUE")
        with caplog.at_level(logging.DEBUG, logger="threatgenix.scan_worker"):
            _build_auth_headers(cred)
        for record in caplog.records:
            assert "SUPER-SECRET-VALUE" not in record.getMessage()


class TestScanCreateRequestValidation:
    """Pydantic model_validator: authenticated scan requires credential_id."""

    def test_authenticated_without_credential_raises(self):
        from pydantic import ValidationError
        from app.schemas.scan import ScanCreateRequest

        with pytest.raises(ValidationError, match="credential_id"):
            ScanCreateRequest(
                scan_type="authenticated",
                scope="external",
                authorization_acknowledged=True,
                credential_id=None,
            )

    def test_authenticated_with_credential_ok(self):
        from app.schemas.scan import ScanCreateRequest

        req = ScanCreateRequest(
            scan_type="authenticated",
            scope="external",
            authorization_acknowledged=True,
            credential_id=uuid.uuid4(),
        )
        assert req.scan_type.value == "authenticated"

    def test_unauthenticated_without_credential_ok(self):
        from app.schemas.scan import ScanCreateRequest

        req = ScanCreateRequest(
            scan_type="unauthenticated",
            scope="external",
            authorization_acknowledged=True,
        )
        assert req.credential_id is None

    def test_unauthenticated_with_credential_rejected(self):
        from pydantic import ValidationError
        from app.schemas.scan import ScanCreateRequest

        with pytest.raises(ValidationError, match="credential_id"):
            ScanCreateRequest(
                scan_type="unauthenticated",
                scope="external",
                authorization_acknowledged=True,
                credential_id=uuid.uuid4(),
            )

    def test_authenticated_repository_path_rejects_credential(self):
        from pydantic import ValidationError
        from app.schemas.scan import ScanCreateRequest

        with pytest.raises(ValidationError, match="url targets"):
            ScanCreateRequest(
                scan_type="authenticated",
                scope="external",
                tool_name="semgrep",
                target_type="repository_path",
                authorization_acknowledged=True,
                credential_id=uuid.uuid4(),
            )


def test_execution_artifact_redacts_plaintext_auth_header_from_command():
    secret = "SUPER-SECRET-SCAN-TOKEN"
    policy = ValidationExecutionPolicy(
        tool_name=NUCLEI_TOOL_NAME,
        supported_targets=[TARGET_URL],
        runs_in_sandbox_required=True,
        execution_enabled=True,
        network_mode=NETWORK_TARGET_ONLY,
        max_runtime_seconds=60,
        max_output_bytes=4096,
        artifact_capture_enabled=True,
    )
    result = ValidationToolResult(
        tool_name=NUCLEI_TOOL_NAME,
        target="https://api.example.com",
        command=[
            "nuclei",
            "-u",
            "https://api.example.com",
            "-H",
            f"Authorization: Bearer {secret}",
        ],
        resolved_target="https://api.example.com",
    )

    artifact = _build_execution_artifact(
        scan_job_id=uuid.uuid4(),
        tool=SimpleNamespace(name=NUCLEI_TOOL_NAME, deterministic=True),
        target="https://api.example.com",
        target_type=TARGET_URL,
        policy=policy,
        policy_decision="execution permitted by validation policy",
        result=result,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    command = " ".join(artifact.command)
    assert secret not in command
    assert "Authorization: [redacted]" in command
    assert artifact.command_redacted is True


class TestExecuteScanDecryptFailure:
    """Verify credential decryption failure path in _execute_scan."""

    @pytest.mark.asyncio
    async def test_decrypt_failure_marks_job_failed(self, monkeypatch):
        """When _build_auth_headers raises, job.status should be 'failed' and error_message should mention decryption."""
        from unittest.mock import AsyncMock

        from app.services.scan_worker import _execute_scan

        monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")

        # Create a mock job
        job = MagicMock()
        job.id = uuid.uuid4()
        job.status = "pending"
        job.scan_type = "authenticated"
        job.credential_id = uuid.uuid4()
        job.owner_id = uuid.uuid4()
        job.threat_model_id = uuid.uuid4()
        job.completed_at = None
        job.started_at = None
        job.error_message = None

        # Create a fake credential
        credential = _make_cred("bearer_token", "fake-token")

        # Mock the DB session and related functions
        mock_db = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = job
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch(
            "app.services.scan_worker._nuclei_available", return_value=True
        ), patch(
            "app.services.scan_worker._build_auth_headers",
            side_effect=Exception("bad key"),
        ), patch(
            "app.services.scan_credential_service.get_credential_for_job",
            return_value=credential,
        ):

            # Execute the scan
            await _execute_scan(mock_db, job.id)

            # Assert job status is failed
            assert job.status == "failed"

            # Assert error_message contains "decryption"
            assert "decryption" in job.error_message.lower()

            # Assert db.commit() was called
            mock_db.commit.assert_called()


class TestExecuteScanCredentialBroker:
    """Verify credential broker failures stop authenticated scans safely."""

    @pytest.mark.asyncio
    async def test_deleted_credential_marks_job_failed_without_secret(self, monkeypatch, caplog):
        from unittest.mock import AsyncMock
        import logging

        from app.services.scan_worker import _execute_scan

        monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")

        job = MagicMock()
        job.id = uuid.uuid4()
        job.status = "pending"
        job.scan_type = "authenticated"
        job.credential_id = uuid.uuid4()
        job.owner_id = uuid.uuid4()
        job.threat_model_id = uuid.uuid4()
        job.completed_at = None
        job.started_at = None
        job.error_message = None
        job.failure_code = None
        job.tool_name = NUCLEI_TOOL_NAME
        job.target_type = TARGET_URL

        mock_db = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = job
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        leaked_secret = "DELETED-CRED-PLAINTEXT"
        with caplog.at_level(logging.DEBUG, logger="threatgenix.scan_worker"), patch(
            "app.services.scan_worker._nuclei_available", return_value=True
        ), patch(
            "app.services.scan_credential_service.get_credential_for_job",
            return_value=None,
        ):
            await _execute_scan(mock_db, job.id)

        assert job.status == "failed"
        assert job.failure_code == "target_invalid"
        assert "not found or access denied" in job.error_message
        assert leaked_secret not in job.error_message
        for record in caplog.records:
            assert leaked_secret not in record.getMessage()
