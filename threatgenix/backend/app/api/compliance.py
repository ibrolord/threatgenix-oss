"""Compliance mapping API endpoints (Block B16)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.compliance import ComplianceMapping
from app.schemas.compliance import ComplianceMappingResponse

router = APIRouter(
    prefix="/api/compliance-mappings",
    tags=["compliance"],
)


@router.get("", response_model=list[ComplianceMappingResponse])
async def list_compliance_mappings(
    db: AsyncSession = Depends(get_db),
    frameworks: Optional[list[str]] = Query(None, description="Filter by framework(s)"),
) -> list[ComplianceMappingResponse]:
    """Return all compliance mapping records, optionally filtered by framework."""
    stmt = select(ComplianceMapping)
    if frameworks is not None:
        stmt = stmt.where(ComplianceMapping.framework.in_(frameworks))
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [ComplianceMappingResponse.model_validate(r) for r in rows]


@router.get("/by-stride/{stride_category}", response_model=list[ComplianceMappingResponse])
async def get_compliance_mappings_by_stride(
    stride_category: str,
    db: AsyncSession = Depends(get_db),
) -> list[ComplianceMappingResponse]:
    """Return compliance mappings filtered by STRIDE category."""
    result = await db.execute(
        select(ComplianceMapping).where(
            ComplianceMapping.stride_category == stride_category,
        )
    )
    rows = result.scalars().all()
    return [ComplianceMappingResponse.model_validate(r) for r in rows]
