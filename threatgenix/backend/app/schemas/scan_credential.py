"""Pydantic schemas for scan credentials (Phase S2)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


def _normalize_expires_at(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    if value <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")
    return value


class CredentialType(str, Enum):
    bearer_token = "bearer_token"
    api_key_header = "api_key_header"
    basic_auth = "basic_auth"
    cookie = "cookie"


class ScanCredentialCreate(BaseModel):
    """Create a new encrypted credential."""
    name: str = Field(..., min_length=1, max_length=200)
    credential_type: CredentialType
    # For api_key_header: name of the header (e.g. "X-API-Key")
    header_name: str | None = Field(None, max_length=200)
    # The plaintext secret — encrypted server-side before storage, never returned
    secret: str = Field(..., min_length=1)
    # Optional short-lived retention deadline. Expired credentials are not returned by the broker.
    expires_at: datetime | None = None

    _future_expires_at = field_validator("expires_at")(_normalize_expires_at)


class ScanCredentialUpdate(BaseModel):
    """Update credential metadata or rotate the secret.

    All fields are optional. Omit ``secret`` to leave it unchanged.
    """
    name: str | None = Field(None, min_length=1, max_length=200)
    header_name: str | None = Field(None, max_length=200)
    secret: str | None = Field(None, min_length=1)
    expires_at: datetime | None = None

    _future_expires_at = field_validator("expires_at")(_normalize_expires_at)


class ScanCredentialResponse(BaseModel):
    """Safe public representation — secret is NEVER included."""
    id: UUID
    threat_model_id: UUID
    name: str
    credential_type: str
    # header_name exposed so the UI can show "injects X-API-Key header"
    header_name: str | None
    expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
