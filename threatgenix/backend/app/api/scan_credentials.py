"""Scan Credential API — CRUD for encrypted scan credentials (Phase S2)."""
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanCredential
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.scan_credential import (
    ScanCredentialCreate,
    ScanCredentialResponse,
    ScanCredentialUpdate,
)
from app.services.auth import get_current_user
from app.services.credential_crypto import encrypt_secret
from app.services.model_collaboration import require_model_permission

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/scan-credentials",
    tags=["scan-credentials"],
)
logger = logging.getLogger("threatgenix.scan_credentials")


async def _get_threat_model_for_owner(
    threat_model_id: UUID,
    db: AsyncSession,
    current_user: User,
    permission: str = "admin",
) -> ThreatModel:
    result = await db.execute(
        select(ThreatModel).where(ThreatModel.id == threat_model_id)
    )
    tm = result.scalar_one_or_none()
    return require_model_permission(tm, current_user, permission)  # type: ignore[arg-type]


async def _get_credential(
    credential_id: UUID,
    threat_model_id: UUID,
    db: AsyncSession,
    current_user: User,
) -> ScanCredential:
    result = await db.execute(
        select(ScanCredential).where(
            ScanCredential.id == credential_id,
            ScanCredential.threat_model_id == threat_model_id,
            ScanCredential.owner_id == current_user.id,
        )
    )
    cred = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    return cred


# ---------------------------------------------------------------------------
# POST — create credential
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanCredentialResponse, status_code=201)
async def create_credential(
    threat_model_id: UUID,
    body: ScanCredentialCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanCredentialResponse:
    """Store a new encrypted scan credential. The plaintext secret is never returned."""
    await _get_threat_model_for_owner(threat_model_id, db, current_user)

    if body.credential_type.value == "api_key_header" and not (body.header_name or "").strip():
        raise HTTPException(
            status_code=422,
            detail="header_name is required for credential_type='api_key_header'",
        )

    cred = ScanCredential(
        threat_model_id=threat_model_id,
        owner_id=current_user.id,
        name=body.name,
        credential_type=body.credential_type.value,
        header_name=body.header_name,
        encrypted_secret=encrypt_secret(body.secret),
        expires_at=body.expires_at,
    )
    db.add(cred)
    await db.commit()
    await db.refresh(cred)
    logger.info(
        "credential_created id=%s type=%s threat_model=%s",
        cred.id, cred.credential_type, threat_model_id,
    )
    return ScanCredentialResponse.model_validate(cred)


# ---------------------------------------------------------------------------
# GET — list credentials for a threat model
# ---------------------------------------------------------------------------

@router.get("", response_model=list[ScanCredentialResponse])
async def list_credentials(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanCredentialResponse]:
    """List credentials for a threat model. Secrets are never included."""
    await _get_threat_model_for_owner(threat_model_id, db, current_user)

    result = await db.execute(
        select(ScanCredential)
        .where(
            ScanCredential.threat_model_id == threat_model_id,
            ScanCredential.owner_id == current_user.id,
        )
        .order_by(ScanCredential.created_at.desc())
    )
    creds = result.scalars().all()
    return [ScanCredentialResponse.model_validate(c) for c in creds]


# ---------------------------------------------------------------------------
# PATCH — update name / header_name / rotate secret
# ---------------------------------------------------------------------------

@router.patch("/{credential_id}", response_model=ScanCredentialResponse)
async def update_credential(
    threat_model_id: UUID,
    credential_id: UUID,
    body: ScanCredentialUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanCredentialResponse:
    """Update credential metadata or rotate the secret.

    Omitting ``secret`` leaves the existing encrypted value unchanged.
    """
    await _get_threat_model_for_owner(threat_model_id, db, current_user)
    cred = await _get_credential(credential_id, threat_model_id, db, current_user)

    if body.name is not None:
        cred.name = body.name
    if body.header_name is not None:
        if not body.header_name.strip():
            raise HTTPException(
                status_code=422,
                detail="header_name must not be blank",
            )
        cred.header_name = body.header_name.strip()
    if body.secret is not None:
        cred.encrypted_secret = encrypt_secret(body.secret)
    if "expires_at" in body.model_fields_set:
        cred.expires_at = body.expires_at

    await db.commit()
    await db.refresh(cred)
    logger.info("credential_updated id=%s", credential_id)
    return ScanCredentialResponse.model_validate(cred)


# ---------------------------------------------------------------------------
# DELETE — remove credential
# ---------------------------------------------------------------------------

@router.delete("/{credential_id}", status_code=204, response_model=None)
async def delete_credential(
    threat_model_id: UUID,
    credential_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete a credential. Scan jobs that referenced it retain credential_id=NULL."""
    await _get_threat_model_for_owner(threat_model_id, db, current_user)
    cred = await _get_credential(credential_id, threat_model_id, db, current_user)
    await db.delete(cred)
    await db.commit()
    logger.info("credential_deleted id=%s", credential_id)
