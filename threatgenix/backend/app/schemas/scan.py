"""Pydantic schemas for the vulnerability scanner (Phase S1 + S2)."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


class ScanType(str, Enum):
    unauthenticated = "unauthenticated"
    authenticated = "authenticated"


class ScanScope(str, Enum):
    external = "external"
    internal = "internal"
    full = "full"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ThreatScanStatus(str, Enum):
    confirmed = "confirmed"
    mitigated = "mitigated"
    unverifiable = "unverifiable"
    not_found = "not_found"


ValidationToolName = Literal[
    "nuclei",
    "semgrep",
    "osv-scanner",
    "trivy",
    "checkov",
    "trufflehog",
    "ai-red-team",
]
EvidenceImportToolName = Literal[
    "nuclei",
    "semgrep",
    "osv-scanner",
    "trivy",
    "checkov",
    "trufflehog",
    "ai-red-team",
    "external-report",
    "pentest-report",
]
ValidationTargetType = Literal[
    "url",
    "repository_path",
    "lockfile",
    "container_image",
    "iac_directory",
    "ai_system",
]


AUTHORIZATION_TEXT = (
    "I confirm that I am authorized to perform security testing on all targets listed "
    "in this scan. I understand that unauthorized scanning may violate computer crime laws "
    "including the Computer Fraud and Abuse Act and equivalent regulations. By proceeding, "
    "I accept full legal responsibility for ensuring proper authorization exists for each target."
)


class ScanCreateRequest(BaseModel):
    """Request body to create + authorize a scan job."""

    scan_type: ScanType = ScanType.unauthenticated
    scope: ScanScope = ScanScope.external
    tool_name: ValidationToolName = Field(
        "nuclei",
        description="Validation tool to execute. Live execution is policy-gated by runtime mode and target authorization.",
    )
    target_type: ValidationTargetType = Field(
        "url",
        description="Target type for policy evaluation. Live DFD scans currently use url targets.",
    )
    # Override node scan targets; if empty, uses scan_target_url from DFD nodes
    target_overrides: dict[str, str] = Field(default_factory=dict)  # {node_id: url}
    authorization_acknowledged: bool = Field(
        ..., description="Must be True to proceed"
    )
    # S2: optional credential for authenticated scans
    credential_id: UUID | None = Field(
        None,
        description="ScanCredential ID to use for authenticated scan. Required when scan_type=authenticated.",
    )
    # Note: client IP is derived server-side from request headers; not accepted from body

    @model_validator(mode="after")
    def authenticated_requires_credential(self) -> "ScanCreateRequest":
        if self.credential_id is not None and self.target_type != "url":
            raise ValueError("credential_id is only supported for url targets")
        if self.scan_type == ScanType.authenticated and self.target_type != "url":
            raise ValueError("authenticated scans are only supported for url targets")
        if self.scan_type == ScanType.authenticated and self.credential_id is None:
            raise ValueError(
                "credential_id is required when scan_type is 'authenticated'"
            )
        if self.scan_type != ScanType.authenticated and self.credential_id is not None:
            raise ValueError(
                "credential_id is only allowed when scan_type is 'authenticated'"
            )
        return self


class ScanJobResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    status: str
    scan_type: str
    scope: str
    tool_name: str = "nuclei"
    target_type: str = "url"
    targets: dict
    finding_count: int
    credential_id: UUID | None
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    failure_code: Optional[str] = None
    runner_id: Optional[str] = None
    claimed_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    lease_expires_at: Optional[datetime] = None
    attempt_count: int = 0
    max_attempts: int = 3
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("attempt_count", "max_attempts", mode="before")
    @classmethod
    def default_attempt_counters(cls, value: object, info) -> object:
        if value is not None:
            return value
        if info.field_name == "max_attempts":
            return 3
        return 0


class ScanFindingResponse(BaseModel):
    id: UUID
    template_id: str
    template_name: str
    severity: str
    matched_at: str
    extracted_results: Optional[str]
    cve_ids: list[str]
    tags: list[str]
    cvss_score: Optional[float]
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    validation_target: Optional[str] = None
    deterministic: Optional[bool] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanExecutionArtifactResponse(BaseModel):
    id: UUID
    scan_job_id: UUID
    source: str
    tool_name: str
    target_type: str
    target: str
    resolved_target: Optional[str]
    status: str
    deterministic: bool
    sandboxed: bool
    sandbox_mode: Optional[str] = None
    container_image: Optional[str] = None
    resource_limits: dict = Field(default_factory=dict)
    policy_decision: Optional[str]
    command: list[str] = Field(default_factory=list)
    command_redacted: bool
    returncode: Optional[int]
    timed_out: bool
    output_limit_exceeded: bool
    stdout_bytes: int
    output_sha256: Optional[str] = None
    stderr_summary: Optional[str]
    network_mode: Optional[str]
    max_runtime_seconds: Optional[int]
    max_output_bytes: Optional[int]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_ms: Optional[int]
    created_at: datetime

    @field_validator("resource_limits", mode="before")
    @classmethod
    def default_resource_limits(cls, value: object) -> dict:
        return value or {}

    model_config = {"from_attributes": True}


class ScanThreatResultResponse(BaseModel):
    id: UUID
    threat_id: UUID
    scan_status: str
    evidence: list[dict]
    cve_ids: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanCorrelationEvidenceResponse(BaseModel):
    finding_id: str
    template_id: str
    template_name: str
    severity: str
    matched_at: str
    cve_ids: list[str] = []
    tool_name: str | None = None
    tool_version: str | None = None
    validation_target: str | None = None
    deterministic: bool | None = None
    evidence_scope: str | None = None
    confidence_label: str | None = None
    match_explanation: str | None = None
    matched_node_ids: list[str] = []


class ThreatScanCorrelationResponse(BaseModel):
    scan_job_id: UUID
    scan_completed_at: datetime | None = None
    threat_id: UUID
    threat_display_id: str
    threat_description: str
    severity: str
    stride_category: str
    scan_status: str
    evidence_count: int
    cve_ids: list[str] = []
    matched_targets: list[str] = []
    templates: list[str] = []
    matched_node_ids: list[UUID] = []
    matched_node_labels: list[str] = []
    finding_titles: list[str] = []
    validation_tools: list[str] = []
    deterministic_evidence_count: int = 0
    evidence: list[ScanCorrelationEvidenceResponse] = []


class ScanCorrelationSummaryResponse(BaseModel):
    scan_job_id: UUID
    scan_completed_at: datetime | None = None
    total_correlations: int
    confirmed_count: int
    mitigated_count: int
    not_found_count: int
    unverifiable_count: int
    entries: list[ThreatScanCorrelationResponse] = []


class ValidationRunbookFindingResponse(BaseModel):
    finding_id: UUID
    title: str
    severity: str
    tool_name: str | None = None
    target: str | None = None
    matched_at: str
    cve_ids: list[str] = []
    tags: list[str] = []
    confidence_label: Literal["validated", "indicated", "untested"] = "untested"
    evidence_scope: str = "unbound"
    proof_class: Literal["deterministic", "ai_assisted", "policy", "runtime", "unknown"] = "unknown"
    evidence_quality: Literal["strong", "moderate", "weak"] = "weak"
    risk_score: int = Field(0, ge=0, le=100)
    next_action: str = "Bind this evidence to an affected DFD node or mark it not applicable."
    explanation: str


class ValidationRunbookThreatResponse(BaseModel):
    threat_id: UUID
    threat_display_id: str
    threat_description: str
    severity: str
    stride_category: str
    scan_status: str
    confidence_label: Literal["validated", "indicated", "untested"]
    explanation: str
    evidence_count: int
    risk_score: int = Field(0, ge=0, le=100)
    evidence_quality: Literal["strong", "moderate", "weak"] = "weak"
    proof_class: Literal["deterministic", "ai_assisted", "policy", "runtime", "unknown"] = "unknown"
    next_action: str = "Add validation evidence for this threat."
    cve_ids: list[str] = []
    validation_tools: list[str] = []


class ValidationRunbookCoverageResponse(BaseModel):
    scan_job_id: UUID
    scan_completed_at: datetime | None = None
    tool_names: list[str] = []
    target_binding: Literal["node_bound", "global", "mixed", "none"]
    finding_count: int
    deterministic_finding_count: int = 0
    assisted_finding_count: int = 0
    artifact_count: int
    mapped_threat_count: int
    validated_threat_count: int
    indicated_threat_count: int
    unbound_finding_count: int
    untested_threat_count: int
    confidence_counts: dict[str, int] = {}
    validated_risk_score: int = Field(0, ge=0, le=100)
    indicated_risk_score: int = Field(0, ge=0, le=100)
    ai_assisted_risk_score: int = Field(0, ge=0, le=100)


class ValidationRunbookResponse(BaseModel):
    coverage: ValidationRunbookCoverageResponse
    executive_summary: str
    gaps: list[str] = []
    mapped_threats: list[ValidationRunbookThreatResponse] = []
    unbound_findings: list[ValidationRunbookFindingResponse] = []


class ScanJobDetailResponse(ScanJobResponse):
    findings: list[ScanFindingResponse] = []
    threat_results: list[ScanThreatResultResponse] = []
    execution_artifacts: list[ScanExecutionArtifactResponse] = []


class EvidenceIngestRequest(BaseModel):
    """Parse pre-captured tool output without executing a scanner."""

    tool_name: EvidenceImportToolName
    target_type: ValidationTargetType
    target: str = Field(..., min_length=1, max_length=2_000)
    raw_output: str = Field(..., min_length=1, max_length=10_000_000)
    target_node_id: UUID | None = Field(
        None,
        description="Optional DFD node whose target produced this evidence.",
    )


class ValidationArtifactBundleItemResponse(BaseModel):
    id: UUID
    bundle_id: UUID
    scan_job_id: UUID | None = None
    scan_execution_artifact_id: UUID | None = None
    tool_name: str
    target_type: str
    target: str
    target_node_id: UUID | None = None
    source_path: str
    raw_output_sha256: str
    raw_output_bytes: int
    status: str
    finding_count: int
    error_message: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ValidationArtifactBundleResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    owner_id: UUID
    organization_id: UUID | None = None
    filename: str
    content_type: str | None = None
    byte_size: int
    sha256: str
    status: str
    manifest: dict
    storage_backend: str
    storage_key: str | None = None
    error_message: str | None = None
    item_count: int
    created_at: datetime
    updated_at: datetime
    items: list[ValidationArtifactBundleItemResponse] = []

    model_config = {"from_attributes": True}


class ValidationArtifactBundleImportResponse(BaseModel):
    bundle: ValidationArtifactBundleResponse
    created_scans: list[ScanJobDetailResponse] = []


class ValidationRunRequest(BaseModel):
    """Create a live validation run for one explicit target."""

    tool_name: ValidationToolName
    target_type: ValidationTargetType
    target: str = Field(..., min_length=1, max_length=2_000)
    target_node_id: UUID | None = Field(
        None,
        description="Optional DFD node whose target is being validated.",
    )
    scope: ScanScope = ScanScope.external
    authorization_acknowledged: bool = Field(
        ..., description="Must be True to execute a validation tool"
    )
