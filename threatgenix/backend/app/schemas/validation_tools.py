"""Schemas for validation tool inventory and execution policy state."""
from __future__ import annotations

from pydantic import BaseModel


class ValidationToolInventoryItemResponse(BaseModel):
    name: str
    active: bool
    available: bool
    deterministic: bool
    runtime_strategy: str = "unavailable"
    runtime_detail: str = ""
    readiness_status: str = "blocked"
    blocker_reasons: list[str] = []
    setup_actions: list[str] = []
    install_hint: str | None = None
    enablement_env: str | None = None
    local_allowlist_required: bool = False
    local_allowlist_configured: bool = False
    sandbox_mode: str = "process"
    container_runtime_available: bool = False
    container_image: str | None = None
    container_image_present: bool = False
    container_pull_policy: str = "never"
    supported_targets: list[str]
    runs_in_sandbox_required: bool
    execution_enabled: bool
    network_mode: str
    max_runtime_seconds: int
    max_output_bytes: int
    artifact_capture_enabled: bool
    category: str
    proof_mode: str
    safety_boundary: str
    documentation_url: str
    recommended_for: list[str]


class RedTeamToolProfileResponse(BaseModel):
    name: str
    label: str
    category: str
    status: str
    supported_targets: list[str]
    network_mode: str
    recommended_for: list[str]
    safety_boundary: str
    integration_notes: str
    documentation_url: str


class ValidationToolInventoryResponse(BaseModel):
    tools: list[ValidationToolInventoryItemResponse]
    red_team_tools: list[RedTeamToolProfileResponse] = []
