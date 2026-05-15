from datetime import date, datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.dfd import DFDQualityGateSummary
from app.schemas.environment_evidence import (
    CloudScanEvidence,
    IacEvidence,
    RepositoryEvidence,
)
from app.schemas.report import ReportTemplateDefinition

VALID_REGULATORY_FRAMEWORKS = [
    "OSFI B-13",
    "PCI DSS",
    "PIPEDA",
    "FINTRAC",
    "NIST",
    "ISO 27001",
]


class ThreatModelCreate(BaseModel):
    system_name: str = Field(..., min_length=1, max_length=255)
    description: str = Field("", max_length=500)
    data_classification: Literal["Public", "Internal", "Confidential", "Restricted"]
    regulatory_scope: list[str] = Field(
        default_factory=list,
        description="Selected regulatory frameworks (e.g. OSFI B-13, PCI DSS, PIPEDA, FINTRAC)",
    )
    deployment_model: Optional[Literal["on-prem", "cloud", "hybrid"]] = None
    analyst_name: Optional[str] = None
    analyst_attestation: Optional[str] = None
    next_review_date: Optional[date] = None
    out_of_scope_statement: Optional[str] = None


class ThreatModelResponse(BaseModel):
    id: UUID
    owner_id: UUID | None = None
    organization_id: UUID | None = None
    organization_name: str | None = None
    system_name: str
    description: str
    data_classification: str
    regulatory_scope: list[str] = []
    deployment_model: Optional[str] = None
    repository_evidence: RepositoryEvidence | None = None
    cloud_scan_evidence: CloudScanEvidence | None = None
    iac_evidence: IacEvidence | None = None
    environment_context_summary: str | None = None
    report_template: str = "default"
    report_templates: list[ReportTemplateDefinition] = []
    report_watermark_text: Optional[str] = None
    report_logo_base64: Optional[str] = None
    arch_diagrams: Optional[list[dict]] = None
    analyst_name: Optional[str] = None
    analyst_attestation: Optional[str] = None
    next_review_date: Optional[date] = None
    out_of_scope_statement: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ThreatModelAssumptionResponse(BaseModel):
    id: UUID
    title: str
    description: str = ""
    status: Literal["open", "validated", "challenged"] = "open"
    anchor_kind: Literal["node", "edge", "boundary"]
    anchor_id: UUID
    anchor_label: str
    created_at: datetime
    updated_at: datetime


class ThreatModelAssumptionCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)
    description: str = Field("", max_length=2000)
    status: Literal["open", "validated", "challenged"] = "open"
    anchor_kind: Literal["node", "edge", "boundary"]
    anchor_id: UUID
    anchor_label: Optional[str] = Field(default=None, max_length=255)


class ThreatModelAssumptionUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[Literal["open", "validated", "challenged"]] = None
    anchor_kind: Optional[Literal["node", "edge", "boundary"]] = None
    anchor_id: Optional[UUID] = None
    anchor_label: Optional[str] = Field(default=None, max_length=255)


class ThreatModelListItem(BaseModel):
    id: UUID
    owner_id: UUID | None = None
    organization_id: UUID | None = None
    organization_name: str | None = None
    system_name: str
    data_classification: str
    created_at: datetime
    updated_at: datetime
    threat_count: int = 0
    open_count: int = 0
    has_been_analyzed: bool = False

    model_config = {"from_attributes": True}


class ThreatModelVersionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field("", max_length=500)


class ThreatModelVersionResponse(BaseModel):
    id: UUID
    name: str
    description: str = ""
    created_at: datetime
    created_by: str
    node_count: int
    edge_count: int
    boundary_count: int
    threat_count: int


class ThreatModelVersionDiffRequest(BaseModel):
    left_snapshot_id: UUID
    right_snapshot_id: UUID | None = None


class ThreatModelVersionDiffResponse(BaseModel):
    left_label: str
    right_label: str
    node_delta: int
    edge_delta: int
    boundary_delta: int
    threat_delta: int
    added_nodes: list[str] = []
    removed_nodes: list[str] = []
    added_threats: list[str] = []
    removed_threats: list[str] = []


class ThreatModelReviewCommentResponse(BaseModel):
    id: UUID
    author: str
    comment: str
    created_at: datetime


class ThreatModelReviewCreate(BaseModel):
    snapshot_id: UUID
    title: str = Field(..., min_length=1, max_length=160)
    assignee: Optional[str] = Field(default=None, max_length=160)


class ThreatModelReviewUpdate(BaseModel):
    status: Optional[Literal["pending", "approved", "changes_requested"]] = None
    assignee: Optional[str] = Field(default=None, max_length=160)
    comment: Optional[str] = Field(default=None, max_length=2000)


class ThreatModelReviewResponse(BaseModel):
    id: UUID
    snapshot_id: UUID
    title: str
    status: Literal["pending", "approved", "changes_requested"] = "pending"
    assignee: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    signed_off_at: datetime | None = None
    comments: list[ThreatModelReviewCommentResponse] = []


class ThreatModelControlCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)
    description: str = Field("", max_length=2000)
    category: Literal["preventive", "detective", "corrective", "compensating"] = "preventive"
    status: Literal["planned", "implemented", "partial", "deferred"] = "planned"
    owner: Optional[str] = Field(default=None, max_length=160)
    evidence: Optional[str] = Field(default=None, max_length=1000)
    mapped_threat_ids: list[UUID] = Field(default_factory=list)


class ThreatModelControlUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    category: Optional[Literal["preventive", "detective", "corrective", "compensating"]] = None
    status: Optional[Literal["planned", "implemented", "partial", "deferred"]] = None
    owner: Optional[str] = Field(default=None, max_length=160)
    evidence: Optional[str] = Field(default=None, max_length=1000)
    mapped_threat_ids: Optional[list[UUID]] = None


class ThreatModelControlResponse(BaseModel):
    id: UUID
    title: str
    description: str = ""
    category: Literal["preventive", "detective", "corrective", "compensating"] = "preventive"
    status: Literal["planned", "implemented", "partial", "deferred"] = "planned"
    owner: Optional[str] = None
    evidence: Optional[str] = None
    mapped_threat_ids: list[UUID] = []
    updated_at: datetime


class ArchitectureValidationSummary(BaseModel):
    completeness_score: int
    discovered_components: int
    discovered_repository_components: int = 0
    discovered_cloud_services: int = 0
    modeled_components: int
    mapped_discovered_components: int
    latest_scan_status: str | None = None
    latest_scan_finding_count: int = 0
    correlated_scan_results: int = 0
    unmapped_repository_components: list[str] = []
    unmapped_cloud_services: list[str] = []
    nodes_without_scan_targets: list[str] = []
    unvalidated_threats: list[str] = []
    drift_flags: list[str] = []


class ThreatModelAssumptionSummary(BaseModel):
    total: int
    open: int
    validated: int
    challenged: int


class ThreatModelMitigationSummary(BaseModel):
    total: int
    active: int
    mitigated: int
    accepted: int
    dismissed: int
    with_plan: int
    with_owner: int
    with_due_date: int
    with_residual_risk: int


class ThreatModelControlSummary(BaseModel):
    total: int
    planned: int
    implemented: int
    partial: int
    deferred: int
    with_evidence: int
    mapped_to_threats: int
    with_owner: int


class ThreatModelReviewSummary(BaseModel):
    total: int
    pending: int
    approved: int
    changes_requested: int
    latest_status: Literal["pending", "approved", "changes_requested"] | None = None
    latest_title: str | None = None
    latest_updated_at: datetime | None = None


class ThreatModelElementCoverageSummary(BaseModel):
    total: int
    with_threats: int
    with_assumptions: int
    with_stride_coverage: int
    without_stride_coverage: int
    fully_stride_covered: int
    average_stride_categories: float = 0.0
    uncovered_labels: list[str] = []


class ThreatModelCoverageSummary(BaseModel):
    coverage_score: int
    total_elements: int
    covered_elements: int
    stride_categories_seen: list[str] = []
    missing_stride_categories: list[str] = []
    nodes: ThreatModelElementCoverageSummary
    edges: ThreatModelElementCoverageSummary
    boundaries: ThreatModelElementCoverageSummary


class ThreatModelReviewFreshnessSummary(BaseModel):
    status: Literal["current", "stale", "pending", "changes_requested", "unreviewed"]
    summary: str
    reviewed_snapshot_id: UUID | None = None
    reviewed_snapshot_name: str | None = None
    latest_review_title: str | None = None
    latest_review_status: Literal["pending", "approved", "changes_requested"] | None = None
    reviewed_at: datetime | None = None
    changes_since_review: ThreatModelVersionDiffResponse | None = None


ThreatModelCollaboratorRole = Literal["owner", "editor", "reviewer", "viewer"]
ThreatModelCollaboratorStatus = Literal["active", "invited", "disabled"]
ThreatModelAssignmentStatus = Literal["open", "in_progress", "blocked", "done"]
ThreatModelAssignmentPriority = Literal["critical", "high", "medium", "low"]
ThreatModelNotificationStatus = Literal["unread", "read"]
ThreatModelNotificationType = Literal[
    "review_requested",
    "review_updated",
    "assignment_created",
    "assignment_updated",
    "snapshot_created",
    "control_updated",
]


class ThreatModelCollaboratorCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    role: ThreatModelCollaboratorRole = "viewer"


class ThreatModelCollaboratorUpdate(BaseModel):
    role: ThreatModelCollaboratorRole | None = None
    status: ThreatModelCollaboratorStatus | None = None


class ThreatModelCollaboratorResponse(BaseModel):
    id: UUID
    email: str
    role: ThreatModelCollaboratorRole
    status: ThreatModelCollaboratorStatus
    invited_by: str
    invited_at: datetime
    updated_at: datetime


class ThreatModelAssignmentCommentResponse(BaseModel):
    id: UUID
    author: str
    comment: str
    created_at: datetime


class ThreatModelAssignmentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)
    description: str = Field("", max_length=2000)
    assignee: str = Field(..., min_length=3, max_length=255)
    priority: ThreatModelAssignmentPriority = "medium"
    due_date: datetime | None = None
    threat_id: UUID | None = None
    review_id: UUID | None = None
    anchor_kind: Literal["node", "edge", "boundary", "threat", "review"] | None = None
    anchor_id: UUID | None = None
    anchor_label: str | None = Field(default=None, max_length=255)


class ThreatModelAssignmentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    assignee: str | None = Field(default=None, min_length=3, max_length=255)
    priority: ThreatModelAssignmentPriority | None = None
    status: ThreatModelAssignmentStatus | None = None
    due_date: datetime | None = None
    comment: str | None = Field(default=None, max_length=2000)


class ThreatModelAssignmentResponse(BaseModel):
    id: UUID
    title: str
    description: str = ""
    assignee: str
    priority: ThreatModelAssignmentPriority = "medium"
    status: ThreatModelAssignmentStatus = "open"
    due_date: datetime | None = None
    threat_id: UUID | None = None
    review_id: UUID | None = None
    anchor_kind: Literal["node", "edge", "boundary", "threat", "review"] | None = None
    anchor_id: UUID | None = None
    anchor_label: str | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    comments: list[ThreatModelAssignmentCommentResponse] = []


class ThreatModelNotificationResponse(BaseModel):
    id: UUID
    type: ThreatModelNotificationType
    title: str
    message: str
    status: ThreatModelNotificationStatus = "unread"
    actor: str
    target_kind: Literal["snapshot", "review", "assignment", "control", "threat_model"] | None = None
    target_id: UUID | None = None
    created_at: datetime


class ThreatModelNotificationUpdate(BaseModel):
    status: ThreatModelNotificationStatus


class ThreatModelCollaborationSummary(BaseModel):
    collaborators_total: int
    active_collaborators: int
    editors: int
    reviewers: int
    viewers: int
    open_assignments: int
    overdue_assignments: int
    unread_notifications: int


class AttackPathThreatRef(BaseModel):
    id: UUID
    display_id: str
    severity: str
    stride_category: str
    description: str


class AttackPathStep(BaseModel):
    node_id: UUID
    label: str
    node_type: str
    trust_boundary_id: UUID | None = None


class AttackPathResponse(BaseModel):
    id: UUID
    title: str
    summary: str
    risk_score: int
    boundary_crossings: int
    path_nodes: list[AttackPathStep]
    supporting_threats: list[AttackPathThreatRef]


class ThreatModelScorecardResponse(BaseModel):
    overall_status: Literal["good", "attention", "action_required"]
    overall_summary: str
    architecture_validation: ArchitectureValidationSummary
    coverage_summary: ThreatModelCoverageSummary
    quality_gates: DFDQualityGateSummary
    assumption_summary: ThreatModelAssumptionSummary
    mitigation_summary: ThreatModelMitigationSummary
    control_summary: ThreatModelControlSummary
    review_summary: ThreatModelReviewSummary
    review_freshness: ThreatModelReviewFreshnessSummary
    collaboration_summary: ThreatModelCollaborationSummary
    residual_risk_by_level: dict[str, int]
    top_actions: list[str] = []


class PortfolioTrendPoint(BaseModel):
    date: str
    snapshot_count: int = 0
    threat_count: int = 0
    high_risk_threat_count: int = 0
    review_events: int = 0
    control_events: int = 0


class PortfolioTrendResponse(BaseModel):
    points: list[PortfolioTrendPoint]
    latest_summary: str


class PortfolioSummary(BaseModel):
    total_models: int
    total_threats: int
    threats_by_severity: dict[str, int]
    threats_by_status: dict[str, int]
    threats_by_stride: dict[str, int]
    residual_risk_by_level: dict[str, int]
    models_by_classification: dict[str, int]
    controls_by_status: dict[str, int]
    open_reviews: int
    models_pending_review: int
    models_with_drift: int
    shared_models: int
    open_assignments: int
    overdue_assignments: int
    unread_notifications: int
    recent_models: list[ThreatModelListItem]
