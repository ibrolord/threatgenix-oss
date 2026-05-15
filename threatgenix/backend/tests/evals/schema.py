from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


SeverityLiteral = Literal["Critical", "High", "Medium", "Low"]
RunMode = Literal[
    "gold_dfd_full",
    "gold_dfd_rules_only",
    "structured_full",
    "narrative_full",
    "narrative_repaired_full",
    "delta_reanalyze",
    "gold_dfd_full_ai_unavailable",
    "gold_dfd_full_invalid_model_config",
    "gold_dfd_full_threat_intel_unavailable",
    "structured_full_ai_unavailable",
    "structured_full_invalid_model_config",
    "structured_full_threat_intel_unavailable",
]
AdjudicationVerdict = Literal["PASS", "PARTIAL", "FAIL"]
FinalCampaignVerdict = Literal[
    "world class",
    "Strong but not world-class",
    "Promising but unreliable",
    "Not ready",
]


class ScenarioMetadata(BaseModel):
    scenario_id: str
    title: str
    industry: str
    difficulty: Literal["hard", "extreme"]
    analyst_persona: str
    description: str
    system_name: str
    data_classification: Literal["Public", "Internal", "Confidential", "Restricted"]
    regulatory_scope: list[str] = Field(default_factory=list)
    deployment_model: Optional[Literal["on-prem", "cloud", "hybrid"]] = None
    critical_components: list[str] = Field(default_factory=list)
    critical_flows: list[str] = Field(default_factory=list)
    critical_boundaries: list[str] = Field(default_factory=list)
    narrative_doc: str
    structured_doc: str
    delta_doc: str


class ThreatThemeExpectation(BaseModel):
    id: str
    title: str
    description: str
    severity: SeverityLiteral
    stride_categories: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)


class GoldThreatThemeSet(BaseModel):
    critical_themes: list[ThreatThemeExpectation] = Field(default_factory=list)
    important_themes: list[ThreatThemeExpectation] = Field(default_factory=list)
    expected_stride_coverage: list[str] = Field(default_factory=list)
    critical_assets: list[str] = Field(default_factory=list)
    critical_boundaries: list[str] = Field(default_factory=list)
    top_severity_expectations: list[str] = Field(default_factory=list)
    must_not_hallucinate: list[str] = Field(default_factory=list)


class DFDNodeArtifact(BaseModel):
    id: UUID
    node_type: Literal["process", "data_store", "external_entity"]
    name: str
    position_x: float = 0
    position_y: float = 0
    trust_boundary_id: Optional[UUID] = None
    properties: dict = Field(default_factory=dict)


class DFDEdgeArtifact(BaseModel):
    id: UUID
    source_node_id: UUID
    target_node_id: UUID
    label: str = ""
    properties: dict = Field(default_factory=dict)


class TrustBoundaryArtifact(BaseModel):
    id: UUID
    name: str
    node_ids: list[UUID] = Field(default_factory=list)


class DFDArtifact(BaseModel):
    nodes: list[DFDNodeArtifact] = Field(default_factory=list)
    edges: list[DFDEdgeArtifact] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundaryArtifact] = Field(default_factory=list)


class ThreatArtifact(BaseModel):
    id: Optional[UUID] = None
    display_id: str
    description: str
    stride_category: str
    severity: str
    source: str
    status: Optional[str] = None
    rule_id: Optional[str] = None
    threat_subtype: Optional[str] = None
    relevance_rationale: Optional[str] = None
    affected_node_ids: list[UUID] = Field(default_factory=list)
    affected_edge_ids: list[UUID] = Field(default_factory=list)
    compliance_controls: list[dict] = Field(default_factory=list)


class DFDArtifactSummary(BaseModel):
    node_count: int
    edge_count: int
    boundary_count: int
    node_names: list[str]
    boundary_names: list[str]
    flow_labels: list[str]
    node_type_counts: dict[str, int]
    boundary_membership: dict[str, list[str]]


class RepairAction(BaseModel):
    action: Literal[
        "add_node",
        "add_edge",
        "fix_boundary",
        "rename_node",
        "delete_node",
        "delete_edge",
    ]
    detail: str
    target_id: Optional[str] = None
    extra: dict = Field(default_factory=dict)


class RepairScriptResult(BaseModel):
    applied: bool = False
    actions: list[RepairAction] = Field(default_factory=list)
    missing_critical_components_before: list[str] = Field(default_factory=list)
    missing_critical_flows_before: list[str] = Field(default_factory=list)
    hallucinated_nodes_before: list[str] = Field(default_factory=list)


class OperationalChecks(BaseModel):
    upload_status_code: Optional[int] = None
    analyze_status_code: Optional[int] = None
    rules_only_status_code: Optional[int] = None
    threat_diff_status_code: Optional[int] = None
    export_csv_status_code: Optional[int] = None
    no_5xx: bool = True
    export_matches_list_count: bool = False
    triage_persistence_ok: Optional[bool] = None
    degraded_mode_ok: bool = False
    ai_skipped_reason: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class DegradationEvidence(BaseModel):
    mode: Optional[str] = None
    triggered_by: Optional[str] = None
    expected: bool = False
    observed: bool = False
    details: list[str] = Field(default_factory=list)


class JudgeInput(BaseModel):
    generated_at: datetime
    scenario: ScenarioMetadata
    mode: RunMode
    is_degraded_variant: bool = False
    gold_dfd_summary: DFDArtifactSummary
    actual_dfd_summary: DFDArtifactSummary
    gold_threat_themes: GoldThreatThemeSet
    must_not_hallucinate: list[str] = Field(default_factory=list)
    actual_threats: list[ThreatArtifact] = Field(default_factory=list)
    top_20_threats: list[ThreatArtifact] = Field(default_factory=list)
    rules_only_threats: list[ThreatArtifact] = Field(default_factory=list)
    diff_output: dict = Field(default_factory=dict)
    triage_persistence_evidence: dict = Field(default_factory=dict)
    degradation_evidence: DegradationEvidence = Field(default_factory=DegradationEvidence)
    repair_result: Optional[RepairScriptResult] = None
    operational_checks: OperationalChecks = Field(default_factory=OperationalChecks)


class ClaudeJudgeResult(BaseModel):
    supported_top10_count: int = 0
    unsupported_threat_ids: list[str] = Field(default_factory=list)
    wrong_stride_ids: list[str] = Field(default_factory=list)
    wrong_severity_ids: list[str] = Field(default_factory=list)
    duplicate_clusters: list[list[str]] = Field(default_factory=list)
    missing_critical_themes: list[str] = Field(default_factory=list)
    blocker_findings: list[str] = Field(default_factory=list)
    score_correctness_0_100: float = 0
    verdict: AdjudicationVerdict
    low_confidence_ambiguity: bool = False


class GeminiJudgeResult(BaseModel):
    generic_threat_ids: list[str] = Field(default_factory=list)
    missing_high_value_themes: list[str] = Field(default_factory=list)
    misprioritized_ids: list[str] = Field(default_factory=list)
    top10_quality_score_0_100: float = 0
    overall_world_class_score_0_100: float = 0
    world_class_verdict: AdjudicationVerdict
    notes: list[str] = Field(default_factory=list)
    low_confidence_ambiguity: bool = False


class RunScorecard(BaseModel):
    scenario_id: str
    mode: RunMode
    run_directory: Path
    correctness_score: float
    world_class_score: float
    coverage_score: float
    operational_reliability_score: float
    weighted_run_score: float
    adjudication: AdjudicationVerdict
    manual_review_required: bool = False
    blocker_findings: list[str] = Field(default_factory=list)
    missing_themes: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}


class CampaignSummary(BaseModel):
    generated_at: datetime
    overall_weighted_score: float
    final_verdict: FinalCampaignVerdict
    run_scorecards: list[RunScorecard]
    manual_review_queue: list[dict] = Field(default_factory=list)
    failures: list[dict] = Field(default_factory=list)
