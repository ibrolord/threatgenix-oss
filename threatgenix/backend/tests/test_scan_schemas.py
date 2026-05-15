"""Tests for scan schemas."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.scans import _validate_live_url_target_or_422
from app.schemas.scan import (
    AUTHORIZATION_TEXT,
    EvidenceIngestRequest,
    ScanCreateRequest,
    ValidationRunRequest,
)


def test_scan_create_requires_authorization():
    """authorization_acknowledged must be provided (it has no default)."""
    with pytest.raises(ValidationError):
        # Missing required field
        ScanCreateRequest(scan_type="unauthenticated", scope="external")


def test_scan_create_authorization_false_raises():
    """Passing authorization_acknowledged=False should still be structurally valid
    (the schema accepts it; business logic rejects it at the API layer).
    This test documents the schema-level behaviour."""
    req = ScanCreateRequest(
        scan_type="unauthenticated",
        scope="external",
        authorization_acknowledged=False,
    )
    assert req.authorization_acknowledged is False


def test_scan_create_valid():
    req = ScanCreateRequest(
        scan_type="unauthenticated",
        scope="external",
        authorization_acknowledged=True,
    )
    assert req.authorization_acknowledged is True
    assert req.scan_type.value == "unauthenticated"
    assert req.scope.value == "external"


def test_authorization_text_is_present():
    assert len(AUTHORIZATION_TEXT) > 50
    assert "authorized" in AUTHORIZATION_TEXT.lower()


def test_scan_create_defaults():
    req = ScanCreateRequest(authorization_acknowledged=True)
    assert req.scan_type.value == "unauthenticated"
    assert req.scope.value == "external"


def test_scan_create_target_overrides_default_empty():
    req = ScanCreateRequest(authorization_acknowledged=True)
    assert req.target_overrides == {}


def test_scan_create_target_overrides_accepted():
    node_id = "node-123"
    url = "https://api.example.com"
    req = ScanCreateRequest(
        authorization_acknowledged=True,
        target_overrides={node_id: url},
    )
    assert req.target_overrides[node_id] == url


def test_scan_create_invalid_scan_type():
    with pytest.raises(ValidationError):
        ScanCreateRequest(
            scan_type="burp_suite",  # not a valid ScanType value
            authorization_acknowledged=True,
        )


def test_scan_create_invalid_scope():
    with pytest.raises(ValidationError):
        ScanCreateRequest(
            scope="dmz",  # not a valid ScanScope value
            authorization_acknowledged=True,
        )


def test_scan_create_internal_scope():
    req = ScanCreateRequest(
        scope="internal",
        authorization_acknowledged=True,
    )
    assert req.scope.value == "internal"


def test_scan_create_full_scope():
    req = ScanCreateRequest(
        scope="full",
        authorization_acknowledged=True,
    )
    assert req.scope.value == "full"


def test_trufflehog_is_accepted_as_live_and_import_validation_tool():
    run_req = ValidationRunRequest(
        tool_name="trufflehog",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=True,
    )
    ingest_req = EvidenceIngestRequest(
        tool_name="trufflehog",
        target_type="repository_path",
        target="/repo",
        raw_output='{"DetectorName":"AWS","Verified":true}',
    )

    assert run_req.tool_name == "trufflehog"
    assert ingest_req.tool_name == "trufflehog"


def test_scan_create_authenticated_type():
    import uuid

    req = ScanCreateRequest(
        scan_type="authenticated",
        authorization_acknowledged=True,
        credential_id=uuid.uuid4(),
    )
    assert req.scan_type.value == "authenticated"


def test_authorization_text_mentions_legal_responsibility():
    assert (
        "legal" in AUTHORIZATION_TEXT.lower()
        or "responsibility" in AUTHORIZATION_TEXT.lower()
    )


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data",
        "https://localhost/admin",
        "http://10.0.0.5",
        "http://[::1]/",
    ],
)
def test_live_url_target_rejects_local_private_and_metadata_hosts(target: str):
    with pytest.raises(HTTPException):
        _validate_live_url_target_or_422(target)


def test_live_url_target_accepts_public_https_url(monkeypatch):
    monkeypatch.setattr(
        "app.services.target_safety.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
    )
    _validate_live_url_target_or_422("https://api.example.com/health")


def test_live_url_target_rejects_dns_resolution_to_private_ip(monkeypatch):
    monkeypatch.setattr(
        "app.services.target_safety.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.5", 443))],
    )
    with pytest.raises(HTTPException):
        _validate_live_url_target_or_422("https://scanner-target.example/health")
