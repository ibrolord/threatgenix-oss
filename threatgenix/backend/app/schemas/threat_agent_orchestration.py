"""Schemas for threat-scoped model-agnostic agent orchestration."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr, field_validator

from app.schemas.orchestration import OrchestrationEventResponse
from app.schemas.scan import ScanScope, ValidationTargetType


AgentType = Literal["threat_validation", "code_fix", "iac_fix", "configuration_fix"]
FixAgentType = Literal["code_fix", "iac_fix", "configuration_fix"]
DomainValidationAgentType = Literal[
    "sast",
    "dast",
    "llm_security",
    "iac",
    "dependency",
    "secrets",
    "configuration",
]
ThreatValidationStatus = Literal["created", "running", "completed", "failed", "blocked"]
ThreatValidationConclusion = Literal[
    "confirmed",
    "not_supported",
    "needs_human_review",
    "more_evidence_required",
    "failed",
]
ExploitabilityStatus = Literal[
    "exploitable",
    "not_exploitable",
    "theoretical",
    "blocked_by_control",
    "needs_more_evidence",
    "conflicting_evidence",
]
ExploitabilityConfidence = Literal["low", "medium", "high"]
ThreatRemediationStatus = Literal[
    "drafting",
    "awaiting_confirmation",
    "handoff_created",
    "failed",
    "cancelled",
]
HandoffProvider = Literal["github_pull_request", "github_issue", "linear", "jira", "manual"]
DomainAgentToolExecutionStatus = Literal[
    "planned",
    "authorized",
    "evidence_attached",
    "completed",
    "skipped",
    "failed",
]
DomainAgentExecutionStatus = Literal[
    "planned",
    "running",
    "evidence_attached",
    "completed",
    "skipped",
    "failed",
]
HandoffDeliveryStatus = Literal["recorded", "delivered", "failed"]
DomainAgentToolMode = Literal["recommended", "all", "manual"]


class AgentToolCapabilityResponse(BaseModel):
    domain_agent: DomainValidationAgentType
    tool: str
    label: str
    supported_target_types: list[ValidationTargetType] = Field(default_factory=list)
    best_for: list[str] = Field(default_factory=list)
    runtime_risk: Literal["low", "medium", "high"] = "low"
    requires_network: bool = False
    requires_credentials: bool = False
    requires_human_approval: bool = True
    available: bool = False
    enabled: bool = False
    readiness_status: str = "unavailable"
    setup_actions: list[str] = Field(default_factory=list)
    recommendation_notes: str | None = None


class AgentRunMetadata(BaseModel):
    agent_type: AgentType
    agent_version: str
    input_schema_version: str
    output_schema_version: str
    policy_version: str
    tool_harness_versions: dict[str, str] = Field(default_factory=dict)
    model_provider: str | None = None
    model_name: str | None = None
    prompt_version: str | None = None
    model_output_hash: str | None = None
    deterministic_fallback_used: bool = True


class DomainAgentPlanItem(BaseModel):
    domain_agent: DomainValidationAgentType
    label: str
    tools: list[str] = Field(default_factory=list)
    instructions: str | None = None


class DomainAgentToolExecutionResult(BaseModel):
    tool: str
    status: DomainAgentToolExecutionStatus
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    task_id: str | None = None
    scan_job_id: str | None = None
    skipped_reason: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class DomainAgentExecutionResult(BaseModel):
    domain_agent: DomainValidationAgentType
    label: str
    status: DomainAgentExecutionStatus
    tools: list[DomainAgentToolExecutionResult] = Field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    skipped_reason: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class DomainAgentTargetRequest(BaseModel):
    tool_name: str | None = Field(default=None, max_length=80)
    target_type: ValidationTargetType
    target: str = Field(min_length=1, max_length=2_000)
    target_node_id: UUID | None = None
    scope: ScanScope = ScanScope.external
    authorization_acknowledged: bool = False

    @field_validator("tool_name", "target")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None


class ThreatValidationRunCreate(BaseModel):
    application_review_id: UUID | None = None
    requested_tools: list[str] = Field(default_factory=list, max_length=20)
    domain_agents: list[DomainValidationAgentType] = Field(default_factory=list, max_length=20)
    domain_agent_tools: dict[str, list[str]] = Field(default_factory=dict)
    domain_agent_tool_mode: dict[str, DomainAgentToolMode] = Field(default_factory=dict)
    domain_agent_instructions: dict[str, str] = Field(default_factory=dict)
    domain_agent_targets: dict[str, DomainAgentTargetRequest] = Field(default_factory=dict)
    excluded_tools: dict[str, list[str]] = Field(default_factory=dict)
    required_tools: dict[str, list[str]] = Field(default_factory=dict)
    question: str | None = Field(default=None, max_length=2_000)

    @field_validator("requested_tools")
    @classmethod
    def validate_requested_tools(cls, value: list[str]) -> list[str]:
        normalized = []
        for item in value:
            candidate = item.strip()
            if not candidate:
                raise ValueError("requested tools must not be blank")
            normalized.append(candidate)
        return list(dict.fromkeys(normalized))

    @field_validator("domain_agent_tools")
    @classmethod
    def validate_domain_agent_tools(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _normalize_tool_map(value, field_name="domain agent tools")

    @field_validator("excluded_tools", "required_tools")
    @classmethod
    def validate_tool_maps(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _normalize_tool_map(value, field_name="tool map")

    @field_validator("domain_agent_tool_mode")
    @classmethod
    def validate_domain_agent_tool_mode(
        cls, value: dict[str, DomainAgentToolMode]
    ) -> dict[str, DomainAgentToolMode]:
        normalized: dict[str, DomainAgentToolMode] = {}
        for key, mode in value.items():
            agent_key = key.strip()
            if not agent_key:
                raise ValueError("domain agent tool mode keys must not be blank")
            normalized[agent_key] = mode
        return normalized

    @field_validator("domain_agent_instructions")
    @classmethod
    def validate_domain_agent_instructions(cls, value: dict[str, str]) -> dict[str, str]:
        return _normalize_instruction_map(value)

    @field_validator("domain_agent_targets")
    @classmethod
    def validate_domain_agent_targets(
        cls, value: dict[str, DomainAgentTargetRequest]
    ) -> dict[str, DomainAgentTargetRequest]:
        return _normalize_target_map(value)


def _normalize_tool_map(value: dict[str, list[str]], *, field_name: str) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, tools in value.items():
        agent_key = key.strip()
        if not agent_key:
            raise ValueError(f"{field_name} keys must not be blank")
        tool_names: list[str] = []
        for tool in tools:
            tool_name = tool.strip()
            if not tool_name:
                raise ValueError(f"{field_name} must not contain blank tools")
            tool_names.append(tool_name)
        if len(tool_names) > 20:
            raise ValueError(f"{field_name} must contain 20 tools or fewer")
        normalized[agent_key] = list(dict.fromkeys(tool_names))
    return normalized


def _normalize_instruction_map(value: dict[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, instruction in value.items():
        agent_key = key.strip()
        if not agent_key:
            raise ValueError("domain agent instruction keys must not be blank")
        text = instruction.strip()
        if len(text) > 2_000:
            raise ValueError("domain agent instructions must be 2000 characters or less")
        if text:
            normalized[agent_key] = text
    return normalized


def _normalize_target_map(
    value: dict[str, DomainAgentTargetRequest]
) -> dict[str, DomainAgentTargetRequest]:
    normalized: dict[str, DomainAgentTargetRequest] = {}
    for key, target in value.items():
        target_key = key.strip()
        if not target_key:
            raise ValueError("domain agent target keys must not be blank")
        normalized[target_key] = target
    return normalized


class ThreatScanPlanCreate(ThreatValidationRunCreate):
    pass


class ThreatScanPlanApproveRequest(BaseModel):
    domain_agents: list[DomainValidationAgentType] | None = Field(default=None, max_length=20)
    domain_agent_tools: dict[str, list[str]] | None = None
    domain_agent_tool_mode: dict[str, DomainAgentToolMode] | None = None
    domain_agent_instructions: dict[str, str] | None = None
    domain_agent_targets: dict[str, DomainAgentTargetRequest] = Field(default_factory=dict)
    excluded_tools: dict[str, list[str]] | None = None
    required_tools: dict[str, list[str]] | None = None
    approval_note: str | None = Field(default=None, max_length=2_000)

    @field_validator("domain_agent_tools", "excluded_tools", "required_tools")
    @classmethod
    def validate_optional_tool_maps(
        cls, value: dict[str, list[str]] | None
    ) -> dict[str, list[str]] | None:
        if value is None:
            return None
        return _normalize_tool_map(value, field_name="tool map")

    @field_validator("domain_agent_tool_mode")
    @classmethod
    def validate_optional_domain_agent_tool_mode(
        cls, value: dict[str, DomainAgentToolMode] | None
    ) -> dict[str, DomainAgentToolMode] | None:
        if value is None:
            return None
        normalized: dict[str, DomainAgentToolMode] = {}
        for key, mode in value.items():
            agent_key = key.strip()
            if not agent_key:
                raise ValueError("domain agent tool mode keys must not be blank")
            normalized[agent_key] = mode
        return normalized

    @field_validator("domain_agent_instructions")
    @classmethod
    def validate_domain_agent_instructions(
        cls, value: dict[str, str] | None
    ) -> dict[str, str] | None:
        if value is None:
            return None
        return _normalize_instruction_map(value)

    @field_validator("domain_agent_targets")
    @classmethod
    def validate_domain_agent_targets(
        cls, value: dict[str, DomainAgentTargetRequest]
    ) -> dict[str, DomainAgentTargetRequest]:
        return _normalize_target_map(value)


class ThreatScanPlanRejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2_000)


class AgentTraceResponse(BaseModel):
    events: list[OrchestrationEventResponse] = Field(default_factory=list)


class ExploitabilityAssessment(BaseModel):
    status: ExploitabilityStatus = "needs_more_evidence"
    attacker_profile: str | None = None
    attack_path: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    blocking_controls: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: ExploitabilityConfidence = "low"
    rationale: str | None = None


class ThreatValidationRunResponse(BaseModel):
    id: UUID
    tenant_key: str
    owner_id: UUID
    organization_id: UUID | None = None
    threat_model_id: UUID
    threat_id: UUID
    application_review_id: UUID | None = None
    orchestration_job_id: UUID | None = None
    status: ThreatValidationStatus
    conclusion: ThreatValidationConclusion | None = None
    question: str
    requested_tools: list[str] = Field(default_factory=list)
    domain_agent_plan: list[DomainAgentPlanItem] = Field(default_factory=list)
    domain_agent_results: list[DomainAgentExecutionResult] = Field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    exploitability: ExploitabilityAssessment = Field(default_factory=ExploitabilityAssessment)
    summary: str | None = None
    failure_reason: str | None = None
    metadata: AgentRunMetadata
    trace: AgentTraceResponse = Field(default_factory=AgentTraceResponse)
    created_at: datetime
    updated_at: datetime


class ThreatRemediationRunCreate(BaseModel):
    agent_type: FixAgentType


class ThreatRemediationHandoffConfirmRequest(BaseModel):
    confirmed: bool
    provider: HandoffProvider = "manual"
    github_repository: str | None = Field(default=None, max_length=300)
    access_token: SecretStr | None = Field(default=None, repr=False)
    handoff_idempotency_key: str | None = Field(default=None, max_length=240)
    external_ticket_id: str | None = Field(default=None, max_length=240)
    external_ticket_url: str | None = Field(default=None, max_length=2_000)
    external_pr_url: str | None = Field(default=None, max_length=2_000)
    confirmed_by: str | None = Field(default=None, max_length=240)

    @field_validator("github_repository", "handoff_idempotency_key")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None


class ThreatRemediationEvidenceRequest(BaseModel):
    provider: HandoffProvider = "manual"
    evidence_summary: str = Field(min_length=1, max_length=2_000)
    external_ticket_id: str | None = Field(default=None, max_length=240)
    external_ticket_url: str | None = Field(default=None, max_length=2_000)
    external_pr_url: str | None = Field(default=None, max_length=2_000)
    commit_sha: str | None = Field(default=None, max_length=80)
    evidence_url: str | None = Field(default=None, max_length=2_000)


class ThreatRemediationRunResponse(BaseModel):
    id: UUID
    tenant_key: str
    owner_id: UUID
    organization_id: UUID | None = None
    validation_run_id: UUID
    threat_model_id: UUID
    threat_id: UUID
    application_review_id: UUID | None = None
    orchestration_job_id: UUID | None = None
    agent_type: FixAgentType
    status: ThreatRemediationStatus
    fix_summary: str | None = None
    patch_preview: str | None = None
    ticket_draft: dict[str, Any] = Field(default_factory=dict)
    pr_draft: dict[str, Any] = Field(default_factory=dict)
    external_ticket_id: str | None = None
    external_ticket_url: str | None = None
    external_pr_url: str | None = None
    handoff_delivery_status: HandoffDeliveryStatus = "recorded"
    handoff_provider: HandoffProvider | None = None
    handoff_error: str | None = None
    handoff_idempotency_key: str | None = None
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    failure_reason: str | None = None
    metadata: AgentRunMetadata
    trace: AgentTraceResponse = Field(default_factory=AgentTraceResponse)
    created_at: datetime
    updated_at: datetime
