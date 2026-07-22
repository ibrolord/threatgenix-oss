"""Auth endpoints: register, login, logout, me."""

import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from jose import jwt as _jwt
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.limiter import limiter
from app.models.organization import Organization
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    RequestPasswordResetRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from app.schemas.report import ReportTemplateLibraryUpdate
from app.services.report_templates import (
    load_custom_report_templates,
    serialize_custom_report_templates,
)
from app.services.auth import (
    ALGORITHM,
    create_access_token,
    get_current_user,
    hash_password,
    oauth2_scheme,
    revoke_token,
    verify_password,
)
from app.services.email_verification import create_verification_code, verify_email_code
from app.services.password_reset import create_reset_token, reset_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _default_organization_name(full_name: str, email: str) -> str:
    normalized_full_name = re.sub(r"\s+", " ", (full_name or "")).strip()
    if normalized_full_name:
        if normalized_full_name.endswith("s"):
            return f"{normalized_full_name}' Organization"
        return f"{normalized_full_name}'s Organization"

    local_part = email.split("@", 1)[0].strip()
    words = [part for part in re.split(r"[^A-Za-z0-9]+", local_part) if part]
    title = " ".join(word.capitalize() for word in words) or "ThreatGenix"
    return f"{title} Organization"


def _serialize_user_response(user: User) -> UserResponse:
    organization = getattr(user, "organization", None)
    report_template_library = load_custom_report_templates(
        getattr(organization, "report_template_library", None)
        or getattr(user, "report_template_library", None)
    )
    return UserResponse.model_validate(
        {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "email_verified": getattr(user, "email_verified", False),
            "organization_id": getattr(user, "organization_id", None),
            "organization_name": getattr(organization, "name", None),
            "organization_subscription_tier": getattr(organization, "subscription_tier", None),
            "organization_is_active": getattr(organization, "is_active", None),
            "report_template_library": report_template_library,
        }
    )


def _is_synthetic_smoke_email(email: str) -> bool:
    return email.startswith("codex-prod-smoke-") and email.endswith("@example.com")


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    data: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    organization = Organization(
        name=_default_organization_name(data.full_name, data.email),
    )
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
        role="admin",
        is_active=True,
        email_verified=False,
        organization=organization,
    )
    db.add(organization)
    db.add(user)
    await db.flush()

    # Generate email verification code. Production delivery must happen through
    # email; local/dev tests can read the short-lived code from a response header.
    verification_code = await create_verification_code(db, user.id)
    if settings.auth_expose_dev_tokens_enabled:
        response.headers["X-Dev-Email-Verification-Code"] = verification_code

    await db.commit()
    await db.refresh(user)
    return _serialize_user_response(user)


@router.post("/verify-email")
async def verify_email(data: VerifyEmailRequest, db: AsyncSession = Depends(get_db)):
    """Verify a user's email address using the 6-char code from registration."""
    success = await verify_email_code(db, data.email, data.code)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")
    await db.commit()
    return {"detail": "Email verified successfully"}


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.auth_login_rate_limit)
async def login(request: Request, data: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if settings.auth_require_email_verification and not getattr(user, "email_verified", False):
        raise HTTPException(status_code=403, detail="Email verification required")
    organization = getattr(user, "organization", None)
    if organization is not None and not getattr(organization, "is_active", True):
        raise HTTPException(status_code=403, detail="Organization disabled")

    token = create_access_token(user.id)
    return TokenResponse(access_token=token)


@router.post("/logout", status_code=204)
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: User = Depends(get_current_user),
) -> None:
    """Invalidate the current access token by revoking its JTI."""
    try:
        payload = _jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if jti:
            revoke_token(jti)
    except Exception:
        pass  # token already invalid — that's fine for logout


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return _serialize_user_response(current_user)


@router.delete("/synthetic-smoke-account", status_code=204, response_model=None)
async def delete_synthetic_smoke_account(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete only disposable production-smoke accounts created by the smoke script."""
    email = str(getattr(current_user, "email", ""))
    if not _is_synthetic_smoke_email(email):
        raise HTTPException(status_code=403, detail="Only synthetic smoke accounts can be deleted")

    organization_id = getattr(current_user, "organization_id", None)
    await db.execute(delete(ThreatModel).where(ThreatModel.owner_id == current_user.id))
    await db.delete(current_user)

    if organization_id is not None:
        remaining = await db.execute(
            select(User.id)
            .where(User.organization_id == organization_id, User.id != current_user.id)
            .limit(1)
        )
        if remaining.scalar_one_or_none() is None:
            organization = await db.get(Organization, organization_id)
            if organization is not None:
                await db.delete(organization)

    await db.commit()


@router.put("/report-template-library", response_model=UserResponse)
async def update_report_template_library(
    body: ReportTemplateLibraryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    try:
        serialized_templates = serialize_custom_report_templates(body.report_template_library) or None
        if getattr(current_user, "organization", None) is not None:
            current_user.organization.report_template_library = serialized_templates
        else:
            current_user.report_template_library = serialized_templates
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await db.commit()
    await db.refresh(current_user)
    return _serialize_user_response(current_user)


@router.post("/request-password-reset")
async def request_password_reset(
    data: RequestPasswordResetRequest, db: AsyncSession = Depends(get_db)
):
    """Generate a password reset token without exposing account existence."""
    token = await create_reset_token(db, data.email)
    await db.commit()
    if token is None:
        # Return 200 even for unknown emails to prevent user enumeration
        return {"detail": "If that email exists, a reset link has been sent."}
    body = {"detail": "If that email exists, a reset link has been sent."}
    if settings.auth_expose_dev_tokens_enabled:
        body["reset_token"] = token
    return body


@router.post("/reset-password")
async def do_reset_password(
    data: ResetPasswordRequest, db: AsyncSession = Depends(get_db)
):
    """Reset password using a valid reset token."""
    success = await reset_password(db, data.token, data.new_password)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    await db.commit()
    return {"detail": "Password has been reset successfully"}
