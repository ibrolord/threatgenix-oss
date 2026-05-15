"""Validation tool inventory API."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends

from app.models.user import User
from app.schemas.validation_tools import ValidationToolInventoryResponse
from app.services.auth import get_current_user
from app.services.validation_execution_policy import (
    build_red_team_tool_catalog,
    build_validation_tool_inventory,
)

router = APIRouter(prefix="/api/validation-tools", tags=["validation-tools"])


@router.get("", response_model=ValidationToolInventoryResponse)
async def list_validation_tools(
    current_user: User = Depends(get_current_user),
) -> ValidationToolInventoryResponse:
    del current_user
    return ValidationToolInventoryResponse(
        tools=[asdict(tool) for tool in build_validation_tool_inventory()],
        red_team_tools=[asdict(tool) for tool in build_red_team_tool_catalog()],
    )
