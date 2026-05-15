"""Billing entitlement gate: check whether a user's organization can use a feature."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.organization import Organization
from app.models.user import User


FEATURES_BY_TIER: dict[str, set[str]] = {
    # Free stays permissive for the current pilot surface, but still runs
    # through the entitlement gate so inactive or missing SaaS tenants are
    # blocked in deployed environments.
    "free": {"ai_enhancement", "pdf_export"},
    "pro": {"ai_enhancement", "pdf_export", "validation_lab"},
    "enterprise": {
        "ai_enhancement",
        "pdf_export",
        "validation_lab",
        "live_validation_execution",
        "managed_validation_runner",
    },
}


async def _load_organization(user: User, db: AsyncSession) -> Organization | None:
    organization = getattr(user, "organization", None)
    if organization is not None:
        return organization

    organization_id = getattr(user, "organization_id", None)
    if organization_id is None:
        return None

    result = await db.execute(
        select(Organization).where(Organization.id == organization_id)
    )
    return result.scalar_one_or_none()


async def check_org_entitlement(user: User, db: AsyncSession, feature: str) -> bool:
    """Return True if *user*'s organization is entitled to *feature*.

    Supported feature keys (for future gating):
      - "ai_enhancement"   — POST /threats/{id}/analyze
      - "pdf_export"       — POST /threat-models/{id}/report

    Development allows legacy users without an organization so older local
    fixtures keep working. Staging/production require an active organization.
    """
    feature_key = feature.strip()
    organization = await _load_organization(user, db)
    if organization is None:
        return settings.app_env not in {"production", "staging"}
    if not getattr(organization, "is_active", True):
        return False

    tier = str(getattr(organization, "subscription_tier", "free") or "free").casefold()
    return feature_key in FEATURES_BY_TIER.get(tier, set())
