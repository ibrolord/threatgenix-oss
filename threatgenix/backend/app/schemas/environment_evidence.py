from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


RepositoryEvidenceSource = Literal["archive", "manifest_bundle", "single_file"]
CloudScanProvider = Literal["prowler", "scoutsuite", "unknown"]
GitHubImportTransport = Literal["https", "ssh"]
RepositoryConnectionProvider = Literal["github"]
IacEvidenceSource = Literal["archive", "manifest_bundle", "single_file"]
RepositoryDfdSeedType = Literal[
    "process",
    "data_store",
    "queue",
    "external_entity",
    "infrastructure",
]
RepositoryDfdBoundaryType = Literal[
    "network",
    "organizational",
    "regulatory",
    "privilege",
    "cloud",
]
CodeSurfaceKind = Literal[
    "route",
    "handler",
    "webhook",
    "background_worker",
    "external_call",
    "data_store",
    "privileged_operation",
    "infrastructure",
]
CodeControlType = Literal[
    "authentication",
    "authorization",
    "signature_verification",
    "audit_logging",
    "rate_limiting",
    "validation",
    "idempotency",
    "replay_protection",
    "secret_retrieval",
    "encryption",
]
CodeControlStrength = Literal["strong", "partial", "missing"]
CodeRiskSeverity = Literal["Critical", "High", "Medium", "Low"]
CodeRiskType = Literal[
    "missing_authentication",
    "missing_validation",
    "unsigned_outbound_call",
    "sensitive_data_exposure",
    "unmodeled_public_surface",
]
FindingCodeRelationship = Literal[
    "confirms_missing_control",
    "shows_compensating_control",
    "needs_evidence",
    "unmodeled_surface",
]


class CodeSurface(BaseModel):
    id: str
    kind: CodeSurfaceKind
    name: str
    method: str | None = None
    path: str | None = None
    source_file: str
    line_number: int | None = None
    auth_guards: list[str] = Field(default_factory=list)
    sensitive_data_signals: list[str] = Field(default_factory=list)
    validation_signals: list[str] = Field(default_factory=list)
    outbound_call_signals: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class CodeControlSignal(BaseModel):
    id: str
    surface_id: str
    control_type: CodeControlType
    strength: CodeControlStrength
    evidence: str


class CodeRiskSignal(BaseModel):
    id: str
    surface_id: str
    risk_type: CodeRiskType
    severity: CodeRiskSeverity
    evidence: str


class FindingCodeLink(BaseModel):
    finding_key: str | None = None
    surface_id: str
    surface_name: str
    source_file: str
    line_number: int | None = None
    relationship: FindingCodeRelationship
    summary: str
    control_signal_ids: list[str] = Field(default_factory=list)
    risk_signal_ids: list[str] = Field(default_factory=list)


class CodeEvidenceSummary(BaseModel):
    surface_count: int = 0
    route_count: int = 0
    control_signal_count: int = 0
    risk_signal_count: int = 0
    linked_finding_count: int = 0
    externally_reachable_surface_count: int = 0
    unprotected_sensitive_surface_count: int = 0
    verified_control_count: int = 0
    missing_control_count: int = 0


class RepositoryConnection(BaseModel):
    provider: RepositoryConnectionProvider
    repository: str
    transport: GitHubImportTransport = "https"
    ref: str | None = None
    reference: str | None = None
    connected_at: datetime
    last_synced_at: datetime


class GitHubPullRequestChangedFile(BaseModel):
    path: str
    status: str
    previous_path: str | None = None
    additions: int | None = None
    deletions: int | None = None
    changes: int | None = None


class GitHubPullRequestMetadata(BaseModel):
    provider: RepositoryConnectionProvider = "github"
    repository: str
    number: int
    url: str | None = None
    title: str | None = None
    state: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None
    head_sha: str | None = None
    changed_files: list[GitHubPullRequestChangedFile] = Field(default_factory=list)
    changed_file_count: int = 0
    truncated: bool = False
    fetched_at: datetime


class RepositoryDfdSeedSuggestion(BaseModel):
    id: str
    node_type: RepositoryDfdSeedType
    label: str
    rationale: str
    source_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class RepositoryDfdSeedFlowSuggestion(BaseModel):
    id: str
    source_seed_id: str
    target_seed_id: str
    label: str
    rationale: str
    source_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    directionality: Literal["request", "event", "bidirectional"] = "request"
    transfer_mode: Literal["synchronous", "asynchronous", "batch", "streaming", "near_real_time"] = (
        "synchronous"
    )
    lifecycle_stage: Literal["processing", "storage", "egress", "notification"] = "processing"


class RepositoryDfdSeedBoundarySuggestion(BaseModel):
    id: str
    name: str
    boundary_type: RepositoryDfdBoundaryType
    seed_ids: list[str] = Field(default_factory=list)
    rationale: str
    source_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class RepositoryEvidence(BaseModel):
    source_type: RepositoryEvidenceSource
    filename: str
    connection: RepositoryConnection | None = None
    pull_request: GitHubPullRequestMetadata | None = None
    reference: str | None = None
    file_count: int = 0
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    api_routes: list[str] = Field(default_factory=list)
    webhook_endpoints: list[str] = Field(default_factory=list)
    route_auth_map: list["RouteAuthEntry"] = Field(default_factory=list)
    unprotected_routes: list[str] = Field(default_factory=list)
    sensitive_routes: list[str] = Field(default_factory=list)
    routes_with_raw_input: list[str] = Field(default_factory=list)
    risky_routes: list[str] = Field(default_factory=list)
    auth_surfaces: list[str] = Field(default_factory=list)
    auth_mechanisms: list[str] = Field(default_factory=list)
    data_stores: list[str] = Field(default_factory=list)
    queues: list[str] = Field(default_factory=list)
    external_integrations: list[str] = Field(default_factory=list)
    outbound_calls: list[str] = Field(default_factory=list)
    deployment_clues: list[str] = Field(default_factory=list)
    infrastructure_resources: list[str] = Field(default_factory=list)
    security_sensitive_paths: list[str] = Field(default_factory=list)
    code_surfaces: list[CodeSurface] = Field(default_factory=list)
    code_control_signals: list[CodeControlSignal] = Field(default_factory=list)
    code_risk_signals: list[CodeRiskSignal] = Field(default_factory=list)
    finding_code_links: list[FindingCodeLink] = Field(default_factory=list)
    code_evidence_summary: CodeEvidenceSummary = Field(default_factory=CodeEvidenceSummary)
    dfd_seed_suggestions: list[RepositoryDfdSeedSuggestion] = Field(default_factory=list)
    dfd_seed_flow_suggestions: list[RepositoryDfdSeedFlowSuggestion] = Field(default_factory=list)
    dfd_seed_boundary_suggestions: list[RepositoryDfdSeedBoundarySuggestion] = Field(
        default_factory=list
    )
    warnings: list[str] = Field(default_factory=list)
    parsed_at: datetime


class RouteAuthEntry(BaseModel):
    method: str
    path: str
    auth_guards: list[str] = Field(default_factory=list)
    sensitive_data_signals: list[str] = Field(default_factory=list)
    validation_signals: list[str] = Field(default_factory=list)
    outbound_call_signals: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    source_file: str = ""
    line_number: int | None = None


class CloudFinding(BaseModel):
    category: str
    severity: str
    service: str = ""
    resource: str = ""
    detail: str
    source_finding_id: str | None = None


class CloudScanEvidence(BaseModel):
    provider: CloudScanProvider
    filename: str
    finding_count: int = 0
    high_signal_findings: list[CloudFinding] = Field(default_factory=list)
    exposed_services: list[str] = Field(default_factory=list)
    identity_risks: list[str] = Field(default_factory=list)
    encryption_gaps: list[str] = Field(default_factory=list)
    logging_gaps: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    parsed_at: datetime


class IacEvidence(BaseModel):
    source_type: IacEvidenceSource
    filename: str
    reference: str | None = None
    resource_count: int = 0
    resource_types: list[str] = Field(default_factory=list)
    resource_names: list[str] = Field(default_factory=list)
    public_exposure: list[str] = Field(default_factory=list)
    iam_bindings: list[str] = Field(default_factory=list)
    network_paths: list[str] = Field(default_factory=list)
    secret_refs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    parsed_at: datetime


class EnvironmentEvidenceResponse(BaseModel):
    repository_evidence: RepositoryEvidence | None = None
    cloud_scan_evidence: CloudScanEvidence | None = None
    iac_evidence: IacEvidence | None = None
    environment_context_summary: str | None = None


class GitHubRepositoryImportRequest(BaseModel):
    repository: str = Field(min_length=1, max_length=500)
    transport: GitHubImportTransport = "https"
    ref: str | None = Field(default=None, max_length=200)
    reference: str | None = Field(default=None, max_length=255)
    pull_request_number: int | None = Field(default=None, ge=1)
    pull_request_url: str | None = Field(default=None, max_length=500)
    ssh_private_key: str | None = Field(default=None, max_length=20_000)


class GitHubRepositoryRefreshRequest(BaseModel):
    ssh_private_key: str | None = Field(default=None, max_length=20_000)
