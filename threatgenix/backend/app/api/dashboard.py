"""Dashboard portfolio summary endpoint (F-16)."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.threat_model import PortfolioSummary, PortfolioTrendResponse
from app.services.auth import get_current_user
from app.services.threat_model import get_portfolio_summary, get_portfolio_trends

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=PortfolioSummary)
async def portfolio_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PortfolioSummary:
    """Return aggregate portfolio statistics for the dashboard."""
    return await get_portfolio_summary(
        db,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )


@router.get("/trends", response_model=PortfolioTrendResponse)
async def portfolio_trends(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PortfolioTrendResponse:
    """Return time-based portfolio activity and risk trends."""
    return await get_portfolio_trends(
        db,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )
