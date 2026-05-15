from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.dfd import (
    DFDComponentTemplateResponse,
    DFDPropertyOptionResponse,
    DFDResponse,
    DFDViewLayoutSnapshot,
    DFDViewResponse,
)
from app.schemas.environment_evidence import (
    CloudScanEvidence,
    IacEvidence,
    RepositoryEvidence,
)
from app.schemas.report import ArchDiagram, ReportTemplateDefinition
from app.schemas.threat_model import (
    ThreatModelAssignmentResponse,
    ThreatModelAssumptionResponse,
    ThreatModelCollaboratorResponse,
    ThreatModelControlResponse,
    ThreatModelNotificationResponse,
    ThreatModelReviewResponse,
)

TMAC_VERSION = "1.0"


class TMACFormat(str, Enum):
    yaml = "yaml"
    json = "json"


class TMACImportMode(str, Enum):
    preview = "preview"
    replace = "replace"
    create_new = "create_new"


class TMACBuiltInViewType(str, Enum):
    context = "context"
    container = "container"
    deep_dive = "deep_dive"
    data_lifecycle = "data_lifecycle"


class TMACMetadata(BaseModel):
    id: UUID | None = None
    system_name: str = Field(..., min_length=1, max_length=255)
    description: str = Field(default="", max_length=500)
    data_classification: str
    regulatory_scope: list[str] = Field(default_factory=list)
    deployment_model: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class TMACEvidence(BaseModel):
    repository_evidence: RepositoryEvidence | None = None
    cloud_scan_evidence: CloudScanEvidence | None = None
    iac_evidence: IacEvidence | None = None
    environment_context_summary: str | None = None


class TMACReporting(BaseModel):
    report_template: str = "default"
    report_watermark_text: str | None = None
    report_logo_base64: str | None = None
    arch_diagrams: list[ArchDiagram] = Field(default_factory=list)
    report_templates: list[ReportTemplateDefinition] = Field(default_factory=list)


class TMACBuiltInView(BaseModel):
    id: UUID | None = None
    view_type: TMACBuiltInViewType
    name: str = Field(..., min_length=1, max_length=120)
    layout_snapshot: DFDViewLayoutSnapshot = Field(default_factory=DFDViewLayoutSnapshot)


class TMACViews(BaseModel):
    built_in_views: list[TMACBuiltInView] = Field(default_factory=list)
    custom_views: list[DFDViewResponse] = Field(default_factory=list)


class TMACThreat(BaseModel):
    id: UUID
    display_id: str = Field(..., min_length=1, max_length=20)
    description: str = Field(..., min_length=1)
    stride_category: str
    threat_subtype: str | None = None
    severity: str
    source: str
    status: str
    dismiss_reason: str | None = None
    rule_id: str | None = None
    ai_enhanced: bool = False
    provider_managed: bool = False
    original_rule_threat_id: UUID | None = None
    affected_node_ids: list[UUID] = Field(default_factory=list)
    affected_edge_ids: list[UUID] = Field(default_factory=list)
    relevance_rationale: str | None = None
    mitigation_plan: str | None = None
    mitigation_owner: str | None = None
    due_date: date | None = None
    mitigation_notes: str | None = None
    control_effectiveness: Literal["none", "partial", "substantial", "full"] = "none"
    residual_risk_level: Literal["Critical", "High", "Medium", "Low", "Negligible"] | None = None
    closed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class TMACSnapshotThreat(BaseModel):
    id: UUID
    display_id: str
    description: str
    severity: str
    stride_category: str
    status: str
    mitigation_plan: str | None = None
    mitigation_owner: str | None = None
    due_date: date | None = None
    mitigation_notes: str | None = None
    control_effectiveness: Literal["none", "partial", "substantial", "full"] = "none"
    residual_risk_level: Literal["Critical", "High", "Medium", "Low", "Negligible"] | None = None
    affected_node_ids: list[UUID] = Field(default_factory=list)
    affected_edge_ids: list[UUID] = Field(default_factory=list)


class TMACSnapshotRecord(BaseModel):
    id: UUID
    name: str
    description: str = ""
    created_at: datetime
    created_by: str
    node_count: int
    edge_count: int
    boundary_count: int
    threat_count: int
    dfd: DFDResponse
    threats: list[TMACSnapshotThreat] = Field(default_factory=list)


class TMACGovernance(BaseModel):
    model_snapshots: list[TMACSnapshotRecord] = Field(default_factory=list)
    review_records: list[ThreatModelReviewResponse] = Field(default_factory=list)


class TMACCollaboration(BaseModel):
    collaborators: list[ThreatModelCollaboratorResponse] = Field(default_factory=list)
    assignments: list[ThreatModelAssignmentResponse] = Field(default_factory=list)
    notifications: list[ThreatModelNotificationResponse] = Field(default_factory=list)


class TMACDocument(BaseModel):
    tmac_version: str = TMAC_VERSION
    metadata: TMACMetadata
    evidence: TMACEvidence = Field(default_factory=TMACEvidence)
    reporting: TMACReporting = Field(default_factory=TMACReporting)
    dfd: DFDResponse
    views: TMACViews = Field(default_factory=TMACViews)
    threats: list[TMACThreat] = Field(default_factory=list)
    assumptions: list[ThreatModelAssumptionResponse] = Field(default_factory=list)
    controls: list[ThreatModelControlResponse] = Field(default_factory=list)
    component_templates: list[DFDComponentTemplateResponse] = Field(default_factory=list)
    property_options: list[DFDPropertyOptionResponse] = Field(default_factory=list)
    governance: TMACGovernance = Field(default_factory=TMACGovernance)
    collaboration: TMACCollaboration = Field(default_factory=TMACCollaboration)


class TMACSummary(BaseModel):
    node_count: int = 0
    edge_count: int = 0
    boundary_count: int = 0
    built_in_view_count: int = 0
    custom_view_count: int = 0
    threat_count: int = 0
    assumption_count: int = 0
    control_count: int = 0
    component_template_count: int = 0
    property_option_count: int = 0
    snapshot_count: int = 0
    review_count: int = 0
    collaborator_count: int = 0
    assignment_count: int = 0
    notification_count: int = 0


class TMACContentRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=2_000_000)


class TMACValidationResponse(BaseModel):
    format: TMACFormat
    summary: TMACSummary
    warnings: list[str] = Field(default_factory=list)


class TMACImportRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=2_000_000)
    mode: TMACImportMode = TMACImportMode.preview
    target_threat_model_id: UUID | None = None
    apply_operational_state: bool = False
    apply_binary_assets: bool = False


class TMACImportResponse(BaseModel):
    mode: TMACImportMode
    threat_model_id: UUID | None = None
    system_name: str
    created_new: bool = False
    applied_operational_state: bool = False
    applied_binary_assets: bool = False
    summary: TMACSummary
    warnings: list[str] = Field(default_factory=list)


class TMACDiffRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=2_000_000)


class TMACDiffResponse(BaseModel):
    current_summary: TMACSummary
    incoming_summary: TMACSummary
    changed_sections: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
