"""Schemas for the validation lab workspace."""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.scan import (
    ScanJobResponse,
    ScanScope,
    ValidationRunbookResponse,
    ValidationTargetType,
    ValidationToolName,
)
from app.schemas.validation_tools import (
    RedTeamToolProfileResponse,
    ValidationToolInventoryItemResponse,
)

ValidationCadence = Literal["manual", "daily", "weekly", "monthly"]
ValidationCaseWorkflowStatus = Literal["open", "investigating", "mitigated", "accepted", "dismissed", "refuted"]
ValidationCaseWorkflowPriority = Literal["P1", "P2", "P3"]
_DECISION_RATIONALE_STATUSES = {"accepted", "dismissed", "refuted"}


class ValidationScheduleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    tool_name: ValidationToolName
    target_type: ValidationTargetType
    target: str = Field(..., min_length=1, max_length=2_000)
    target_node_id: UUID | None = None
    scope: ScanScope = ScanScope.external
    cadence: ValidationCadence = "manual"
    enabled: bool = False
    authorization_acknowledged: bool = Field(
        ..., description="Must be True to save a runnable validation schedule."
    )

    @model_validator(mode="after")
    def strip_names(self) -> "ValidationScheduleCreateRequest":
        self.name = self.name.strip()
        self.target = self.target.strip()
        return self


class ValidationScheduleUpdateRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    tool_name: ValidationToolName | None = None
    target_type: ValidationTargetType | None = None
    target: str | None = Field(None, min_length=1, max_length=2_000)
    target_node_id: UUID | None = None
    clear_target_node_id: bool = False
    scope: ScanScope | None = None
    cadence: ValidationCadence | None = None
    enabled: bool | None = None
    authorization_acknowledged: bool | None = Field(
        None,
        description="Required when enabling, changing target, or changing tool.",
    )

    @model_validator(mode="after")
    def strip_optional_strings(self) -> "ValidationScheduleUpdateRequest":
        if self.name is not None:
            self.name = self.name.strip()
        if self.target is not None:
            self.target = self.target.strip()
        return self


class ValidationScheduleRunRequest(BaseModel):
    authorization_acknowledged: bool = Field(
        ..., description="Must be True to execute a saved validation schedule."
    )


class ValidationScheduleResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    name: str
    tool_name: str
    target_type: str
    target: str
    target_node_id: UUID | None = None
    scope: str
    cadence: str
    enabled: bool
    authorization_required: bool
    authorization_acknowledged_at: datetime | None = None
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    runnable: bool
    blocked_reason: str | None = None

    model_config = {"from_attributes": True}


class ValidationTargetBundleResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    owner_id: UUID
    organization_id: UUID | None = None
    name: str
    filename: str
    content_type: str | None = None
    byte_size: int
    sha256: str
    status: str
    storage_backend: str
    manifest: dict
    target_ref: str
    retention_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ValidationTargetAuthorizationChallengeRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def strip_target(self) -> "ValidationTargetAuthorizationChallengeRequest":
        self.target_url = self.target_url.strip()
        return self


class ValidationTargetAuthorizationChallengeResponse(BaseModel):
    target_url: str
    hostname: str
    normalized_host: str
    proof_method: Literal["http_file"]
    proof_url: str
    proof_token: str
    expires_at: datetime


class ValidationTargetAuthorizationVerifyRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2_000)
    proof_method: Literal["http_file"] = "http_file"
    proof_token: str = Field(..., min_length=1, max_length=2_000)
    proof_url: str | None = Field(None, min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def strip_values(self) -> "ValidationTargetAuthorizationVerifyRequest":
        self.target_url = self.target_url.strip()
        self.proof_token = self.proof_token.strip()
        if self.proof_url is not None:
            self.proof_url = self.proof_url.strip()
        return self


class ValidationTargetAuthorizationResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    owner_id: UUID
    hostname: str
    normalized_host: str
    target_url: str | None = None
    proof_method: str
    proof_reference: str | None = None
    status: str
    verified_at: datetime
    expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ValidationSafetyControlResponse(BaseModel):
    name: str
    status: Literal["enforced", "configured", "missing", "planned"]
    detail: str


class ValidationRuntimeResponse(BaseModel):
    mode: Literal["try_sandbox", "self_hosted", "managed"]
    run_submission_enabled: bool = False
    live_execution_enabled: bool
    inline_execution_enabled: bool = False
    worker_execution_enabled: bool = False
    managed_runner_enabled: bool = False
    try_sandbox_enabled: bool
    title: str
    detail: str


class ValidationRunnerStatusResponse(BaseModel):
    status: Literal["ready", "queued", "running", "degraded", "unavailable"]
    detail: str
    pending_count: int = 0
    running_count: int = 0
    failed_count: int = 0
    oldest_pending_age_seconds: int | None = None
    oldest_running_age_seconds: int | None = None
    stale_running_count: int = 0
    active_worker_count: int = 0
    last_heartbeat_at: datetime | None = None


class ValidationSetupLaneResponse(BaseModel):
    name: str
    status: Literal["active", "available", "blocked", "planned"]
    summary: str
    controls: list[str]


class ValidationToolSetupProfileResponse(BaseModel):
    tool_name: str
    label: str
    setup_mode: str
    runner_profile: str
    prerequisites: list[str]
    configuration: list[str]
    safety_gates: list[str]


class ValidationRecommendedRunResponse(BaseModel):
    tool_name: str
    target_type: str
    priority: Literal["P1", "P2", "P3"]
    reason: str
    blocked_reason: str | None = None


class AgenticToolCapabilityResponse(BaseModel):
    tool_name: str
    label: str
    category: str
    target_types: list[str]
    proves: list[str]
    best_for: list[str]
    evidence_schema: list[str]
    execution_boundary: str
    noise_controls: list[str]
    critic_checks: list[str]


class AgenticToolWorkflowStepResponse(BaseModel):
    step: Literal["plan", "policy_gate", "execute", "bind", "critic", "report"]
    owner: str
    detail: str


class AgenticToolRecommendationResponse(BaseModel):
    recommendation_id: str
    priority: Literal["P1", "P2", "P3"]
    tool_name: str
    target_type: str
    objective: str
    rationale: str
    evidence_gap: str
    expected_evidence: str
    blocked_reason: str | None = None
    saved_target_id: UUID | None = None
    safety_gates: list[str]
    critic_checks: list[str]
    workflow: list[AgenticToolWorkflowStepResponse]


class AgenticToolBenchResponse(BaseModel):
    status: Literal["ready", "needs_targets", "blocked", "needs_evidence"]
    summary: str
    planning_inputs: list[str]
    capabilities: list[AgenticToolCapabilityResponse]
    recommendations: list[AgenticToolRecommendationResponse]
    execution_contract: list[AgenticToolWorkflowStepResponse]
    global_critic_rules: list[str]


class ValidationCaseCheckResponse(BaseModel):
    tool_name: str
    target_type: str
    priority: Literal["P1", "P2", "P3"]
    reason: str


class ValidationCaseEventResponse(BaseModel):
    id: UUID
    action: Literal["created", "updated"]
    changes: dict = {}
    note: str | None = None
    actor_id: UUID | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ValidationCaseStateUpdateRequest(BaseModel):
    workflow_status: ValidationCaseWorkflowStatus | None = None
    workflow_priority: ValidationCaseWorkflowPriority | None = None
    clear_priority: bool = False
    owner_label: str | None = Field(None, max_length=200)
    clear_owner: bool = False
    due_date: date | None = None
    clear_due_date: bool = False
    analyst_note: str | None = Field(None, max_length=4_000)
    last_decision: str | None = Field(None, max_length=4_000)

    @model_validator(mode="after")
    def normalize_strings(self) -> "ValidationCaseStateUpdateRequest":
        if self.owner_label is not None:
            self.owner_label = self.owner_label.strip() or None
        if self.analyst_note is not None:
            self.analyst_note = self.analyst_note.strip() or None
        if self.last_decision is not None:
            self.last_decision = self.last_decision.strip() or None
        if (
            self.workflow_status in _DECISION_RATIONALE_STATUSES
            and not self.last_decision
            and not self.analyst_note
        ):
            raise ValueError(
                "last_decision or analyst_note is required when accepting, dismissing, or refuting a validation case"
            )
        return self


class ValidationEvidenceBindingRequest(BaseModel):
    target_node_id: UUID


class ValidationEvidenceBindingResponse(BaseModel):
    finding_id: UUID
    scan_id: UUID
    threat_model_id: UUID
    target_node_id: UUID
    target_node_name: str
    binding_target: str
    target_binding: Literal["node_bound", "global", "mixed", "none"]
    mapped_threat_count: int
    unbound_finding_count: int
    message: str


class ProductSecurityValidationCaseResponse(BaseModel):
    case_id: str
    case_type: Literal["threat", "unbound_finding"]
    title: str
    hypothesis: str
    severity: str
    stride_category: str | None = None
    status: Literal["needs_evidence", "needs_binding", "relevant", "validated"]
    confidence_label: Literal["low", "medium", "high"]
    confidence_score: int = Field(ge=0, le=100)
    proof_level: Literal["none", "observed", "relevant", "validated", "human_attested"]
    proof_class: Literal["deterministic", "ai_assisted", "policy", "runtime", "unknown"]
    evidence_quality: Literal["strong", "moderate", "weak"]
    evidence_count: int
    evidence_sources: list[str] = []
    risk_score: int = Field(ge=0, le=100)
    product_questions: list[str] = []
    recommended_checks: list[ValidationCaseCheckResponse] = []
    next_action: str
    remediation_action: str
    workflow_status: ValidationCaseWorkflowStatus = "open"
    workflow_priority: ValidationCaseWorkflowPriority | None = None
    owner_label: str | None = None
    due_date: date | None = None
    analyst_note: str | None = None
    last_decision: str | None = None
    workflow_updated_at: datetime | None = None
    audit_events: list[ValidationCaseEventResponse] = []


class ValidationGapResponse(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    detail: str
    next_action: str


class ValidationEvidenceLedgerEntryResponse(BaseModel):
    scan_id: UUID
    tool_name: str
    target_type: str
    status: str
    target_binding: Literal["node_bound", "global", "mixed", "none"]
    finding_count: int
    mapped_threat_count: int
    validated_threat_count: int
    indicated_threat_count: int
    unbound_finding_count: int
    artifact_count: int
    deterministic_finding_count: int
    assisted_finding_count: int
    output_sha256: str | None = None
    error_message: str | None = None
    completed_at: datetime | None = None
    created_at: datetime


class ValidationDemoScenarioResponse(BaseModel):
    title: str
    summary: str
    tool_name: str
    target_type: str
    target: str
    raw_output: str
    expected_signal: str


class ValidationLabPostureResponse(BaseModel):
    schedule_count: int
    enabled_schedule_count: int
    recent_scan_count: int
    ready_tool_count: int
    deterministic_tool_count: int
    ai_assisted_tool_count: int
    validated_threat_count: int = 0
    indicated_threat_count: int = 0
    untested_threat_count: int = 0
    validated_risk_score: int = 0
    indicated_risk_score: int = 0
    ai_assisted_risk_score: int = 0


class ValidationLabSummaryResponse(BaseModel):
    threat_model_id: UUID
    runtime: ValidationRuntimeResponse
    runner_status: ValidationRunnerStatusResponse
    posture: ValidationLabPostureResponse
    tools: list[ValidationToolInventoryItemResponse]
    red_team_tools: list[RedTeamToolProfileResponse] = []
    setup_lanes: list[ValidationSetupLaneResponse] = []
    tool_setup_profiles: list[ValidationToolSetupProfileResponse] = []
    target_bundles: list[ValidationTargetBundleResponse] = []
    schedules: list[ValidationScheduleResponse]
    recent_scans: list[ScanJobResponse]
    latest_runbook: ValidationRunbookResponse | None = None
    product_security_cases: list[ProductSecurityValidationCaseResponse] = []
    evidence_ledger: list[ValidationEvidenceLedgerEntryResponse] = []
    gaps: list[ValidationGapResponse] = []
    demo_scenario: ValidationDemoScenarioResponse | None = None
    safety_controls: list[ValidationSafetyControlResponse]
    recommended_next_runs: list[ValidationRecommendedRunResponse]
    agentic_tool_bench: AgenticToolBenchResponse | None = None
