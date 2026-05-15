"""Application review risk acceptance lifecycle service."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application_risk_acceptance import ApplicationRiskAcceptance
from app.models.user import User
from app.schemas.application_risk_acceptance import ApplicationRiskAcceptanceCreate
from app.services.application_review import get_application_review, tenant_key_for_user


class RiskAcceptanceError(ValueError):
    """Raised when risk acceptance cannot be granted or changed."""


def require_risk_acceptance_approver(current_user: User) -> None:
    if getattr(current_user, "role", None) != "accept_risk_approver":
        raise RiskAcceptanceError("accept_risk_approver role is required to accept risk.")


async def create_application_risk_acceptance(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
    request: ApplicationRiskAcceptanceCreate,
) -> ApplicationRiskAcceptance:
    require_risk_acceptance_approver(current_user)
    now = _utc_now()
    expires_at = _aware_utc(request.expires_at)
    if expires_at <= now:
        raise RiskAcceptanceError("Risk acceptance expiry must be in the future.")
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise RiskAcceptanceError("Review was not found for this tenant.")
    acceptance = ApplicationRiskAcceptance(
        tenant_key=tenant_key,
        app_name=review.app_name,
        review_id=review.id,
        finding_stable_id=request.finding_stable_id,
        scope_type=request.scope_type,
        scope_value=request.scope_value,
        justification=request.justification,
        compensating_control=request.compensating_control,
        approver_id=current_user.id,
        approved_at=now,
        expires_at=expires_at,
        status="active",
        audit_events=[
            _audit_event(
                action="granted",
                actor_id=current_user.id,
                detail={
                    "scope_type": request.scope_type,
                    "scope_value": request.scope_value,
                    "expires_at": expires_at.isoformat(),
                },
                observed_at=now,
            )
        ],
    )
    db.add(acceptance)
    await db.flush()
    return acceptance


async def list_application_risk_acceptances(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
    include_revoked: bool = True,
) -> list[ApplicationRiskAcceptance]:
    statement = select(ApplicationRiskAcceptance).where(
        ApplicationRiskAcceptance.tenant_key == tenant_key,
        ApplicationRiskAcceptance.review_id == review_id,
    )
    if not include_revoked:
        statement = statement.where(ApplicationRiskAcceptance.status != "revoked")
    result = await db.execute(statement.order_by(ApplicationRiskAcceptance.created_at.desc()))
    return list(result.scalars().all())


async def get_application_risk_acceptance(
    db: AsyncSession,
    *,
    tenant_key: str,
    acceptance_id: UUID,
) -> ApplicationRiskAcceptance | None:
    result = await db.execute(
        select(ApplicationRiskAcceptance).where(
            ApplicationRiskAcceptance.tenant_key == tenant_key,
            ApplicationRiskAcceptance.id == acceptance_id,
        )
    )
    return result.scalar_one_or_none()


async def revoke_application_risk_acceptance(
    db: AsyncSession,
    *,
    current_user: User,
    acceptance_id: UUID,
    review_id: UUID | None = None,
    reason: str,
) -> ApplicationRiskAcceptance:
    require_risk_acceptance_approver(current_user)
    tenant_key = tenant_key_for_user(current_user)
    acceptance = await get_application_risk_acceptance(
        db,
        tenant_key=tenant_key,
        acceptance_id=acceptance_id,
    )
    if acceptance is None:
        raise RiskAcceptanceError("Risk acceptance was not found for this tenant.")
    if review_id is not None and acceptance.review_id != review_id:
        raise RiskAcceptanceError("Risk acceptance was not found for this review.")
    now = _utc_now()
    if acceptance.status != "revoked":
        acceptance.status = "revoked"
        acceptance.revoked_at = now
        acceptance.revoked_by_id = current_user.id
        acceptance.revoked_reason = reason
        acceptance.audit_events = [
            *(acceptance.audit_events or []),
            _audit_event(
                action="revoked",
                actor_id=current_user.id,
                detail={"reason": reason},
                observed_at=now,
            ),
        ]
        await db.flush()
    return acceptance


async def expire_application_risk_acceptances(
    db: AsyncSession,
    *,
    tenant_key: str | None = None,
    now: datetime | None = None,
) -> list[ApplicationRiskAcceptance]:
    observed_at = now or _utc_now()
    statement = select(ApplicationRiskAcceptance).where(
        ApplicationRiskAcceptance.status == "active",
        ApplicationRiskAcceptance.expires_at <= observed_at,
    )
    if tenant_key is not None:
        statement = statement.where(ApplicationRiskAcceptance.tenant_key == tenant_key)
    result = await db.execute(statement)
    expired = list(result.scalars().all())
    for acceptance in expired:
        acceptance.status = "expired"
        acceptance.audit_events = [
            *(acceptance.audit_events or []),
            _audit_event(
                action="expired",
                actor_id=None,
                detail={"expires_at": acceptance.expires_at.isoformat()},
                observed_at=observed_at,
            ),
        ]
    if expired:
        await db.flush()
    return expired


def risk_acceptance_matches_entry(
    acceptance: ApplicationRiskAcceptance | dict,
    *,
    app_name: str,
    entry_facets: dict,
    entry_source_refs: list[dict],
    entry_content_hash: str,
) -> bool:
    if _acceptance_value(acceptance, "status") != "active":
        return False
    expires_at = _acceptance_value(acceptance, "expires_at")
    if isinstance(expires_at, str):
        expires_at = _parse_iso_datetime(expires_at)
    if isinstance(expires_at, datetime) and _aware_utc(expires_at) <= _utc_now():
        return False
    scope_type = str(_acceptance_value(acceptance, "scope_type") or "")
    scope_value = str(_acceptance_value(acceptance, "scope_value") or "")
    finding_stable_id = _acceptance_value(acceptance, "finding_stable_id")
    if finding_stable_id and str(finding_stable_id) in _entry_stable_ids(
        entry_facets,
        entry_source_refs,
        entry_content_hash,
    ):
        return True
    if scope_type == "app":
        return scope_value == app_name
    if scope_type == "finding":
        return scope_value in _entry_stable_ids(entry_facets, entry_source_refs, entry_content_hash)
    if scope_type == "rule":
        return scope_value in {
            str(entry_facets.get("template_id") or ""),
            str(entry_facets.get("rule_id") or ""),
            str(entry_facets.get("finding_key") or ""),
        }
    if scope_type == "route":
        return scope_value in _entry_paths(entry_source_refs, entry_facets)
    return False


def _entry_stable_ids(entry_facets: dict, source_refs: list[dict], content_hash: str) -> set[str]:
    values = {
        content_hash,
        str(entry_facets.get("finding_key") or ""),
        str(entry_facets.get("template_id") or ""),
        str(entry_facets.get("rule_id") or ""),
    }
    for ref in source_refs:
        if ref.get("type") == "finding_key":
            values.add(str(ref.get("key") or ""))
        if ref.get("type") == "scan_finding":
            values.add(str(ref.get("id") or ""))
    return {value for value in values if value}


def _entry_paths(source_refs: list[dict], entry_facets: dict) -> set[str]:
    values = {str(entry_facets.get("matched_at") or "")}
    for ref in source_refs:
        if ref.get("type") == "path":
            values.add(str(ref.get("path") or ""))
    return {value for value in values if value}


def _acceptance_value(acceptance: ApplicationRiskAcceptance | dict, key: str):
    if isinstance(acceptance, dict):
        if key == "status":
            return acceptance.get("status") or acceptance.get("acceptance_state")
        return acceptance.get(key)
    return getattr(acceptance, key)


def _audit_event(
    *,
    action: str,
    actor_id: UUID | None,
    detail: dict,
    observed_at: datetime,
) -> dict:
    return {
        "action": action,
        "actor_id": str(actor_id) if actor_id is not None else None,
        "observed_at": observed_at.isoformat(),
        "detail": detail,
    }


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _aware_utc(parsed)
