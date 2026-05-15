from __future__ import annotations

import re
from datetime import date, datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, field_validator, model_validator

from app.schemas.security_review import SecurityReviewRiskAcceptanceRequest


class ThreatResponse(BaseModel):
    id: UUID
    display_id: str
    description: str
    stride_category: str
    threat_subtype: Optional[str] = None
    severity: str
    source: str
    status: str
    dismiss_reason: Optional[str]
    rule_id: Optional[str]
    ai_enhanced: bool
    provider_managed: bool = False
    original_rule_threat_id: Optional[UUID]
    affected_node_ids: list[UUID]
    affected_edge_ids: list[UUID]
    relevance_rationale: Optional[str] = None
    mitigation_plan: Optional[str] = None
    mitigation_owner: Optional[str] = None
    due_date: Optional[date] = None
    mitigation_notes: Optional[str] = None
    control_effectiveness: Literal["none", "partial", "substantial", "full"] = "none"
    residual_risk_level: Optional[
        Literal["Critical", "High", "Medium", "Low", "Negligible"]
    ] = None
    closed_at: Optional[datetime] = None
    compliance_controls: list["ComplianceControlRef"] = []
    qualification_score: Optional[int] = None
    qualification_label: Optional[str] = None
    qualification_note: Optional[str] = None
    # Qualification workflow v2 fields
    auto_score: Optional[int] = None
    analyst_score: Optional[int] = None
    analyst_score_rationale: Optional[str] = None
    ai_likelihood_score: Optional[int] = None
    ai_likelihood_assessment: Optional[str] = None
    ai_likelihood_generated_at: Optional[datetime] = None
    cluster_id: Optional[UUID] = None
    false_positive_reason: Optional[str] = None
    qualification_completed_at: Optional[datetime] = None
    scan_status: Optional[
        Literal["confirmed", "mitigated", "unverifiable", "not_found"]
    ] = None
    created_at: datetime

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def _derive_qualification_label(self) -> "ThreatResponse":
        if self.qualification_score is None:
            self.qualification_label = None
        elif self.qualification_score >= 70:
            self.qualification_label = "Priority"
        elif self.qualification_score >= 45:
            self.qualification_label = "Investigate"
        elif self.qualification_score >= 20:
            self.qualification_label = "Review"
        else:
            self.qualification_label = "Low Signal"
        return self


class ThreatIntelTechniqueRef(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: Optional[str] = None
    url: Optional[str] = None
    match_type: Literal["exact", "semantic"]


class ThreatIntelPatternRef(BaseModel):
    capec_id: str
    name: str
    description: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[str] = None
    related_cwe_ids: list[str] = []
    related_attack_ids: list[str] = []
    match_type: Literal["exact", "semantic"]


class ThreatIntelWeaknessRef(BaseModel):
    cwe_id: str
    name: str
    description: Optional[str] = None
    consequences: Optional[str] = None
    is_top_25: bool = False
    match_type: Literal["exact", "semantic"]


class ThreatIntelAdvisoryRef(BaseModel):
    advisory_id: str
    title: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    url: Optional[str] = None
    published_date: Optional[str] = None
    referenced_cves: list[str] = []
    referenced_attack_ids: list[str] = []
    match_type: Literal["exact", "semantic"]


class ThreatIntelKevRef(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    known_ransomware_use: Optional[str] = None
    date_added: Optional[str] = None
    match_type: Literal["scan_cve", "threat_text", "technology_keyword"]


class ThreatIntelCriControlRef(BaseModel):
    cri_control_id: str
    cri_control_name: str
    cri_function: str
    mapping_type: str
    attack_technique_id: str


class ThreatIntelSeveritySignal(BaseModel):
    source: str
    label: str
    reference_id: str
    value: str
    normalized_severity: Optional[str] = None
    note: Optional[str] = None


class ThreatIntelResponse(BaseModel):
    local_severity: str
    highest_external_severity: Optional[str] = None
    semantic_matches_inferred: bool = False
    unavailable_reason: Optional[str] = None
    scan_cve_ids: list[str] = []
    severity_signals: list[ThreatIntelSeveritySignal] = []
    attack_techniques: list[ThreatIntelTechniqueRef] = []
    attack_patterns: list[ThreatIntelPatternRef] = []
    weaknesses: list[ThreatIntelWeaknessRef] = []
    advisories: list[ThreatIntelAdvisoryRef] = []
    kev_entries: list[ThreatIntelKevRef] = []
    cri_controls: list[ThreatIntelCriControlRef] = []


class AnalyzeResponse(BaseModel):
    threats: list[ThreatResponse]
    ai_skipped_reason: Optional[str] = None


class ThreatSummary(BaseModel):
    total: int
    by_stride: dict[str, int]  # {"Spoofing": 3, "Tampering": 5, ...}
    by_severity: dict[str, int]  # {"Critical": 1, "High": 4, ...}
    by_status: dict[str, int]  # {"Open": 8, "Accepted": 2, ...}


class ResidualRiskSummary(BaseModel):
    total: int
    by_level: dict[str, int]


class ThreatTriageRequest(BaseModel):
    status: Literal["Open", "In Progress", "Mitigated", "Accepted", "Dismissed"]
    severity: Optional[Literal["Critical", "High", "Medium", "Low"]] = None
    dismiss_reason: Optional[str] = None
    mitigation_plan: Optional[str] = None
    mitigation_owner: Optional[str] = None
    due_date: Optional[date] = None
    mitigation_notes: Optional[str] = None
    control_effectiveness: Optional[Literal["none", "partial", "substantial", "full"]] = None
    residual_risk_level: Optional[
        Literal["Critical", "High", "Medium", "Low", "Negligible"]
    ] = None
    risk_acceptance: Optional[SecurityReviewRiskAcceptanceRequest] = None


class BulkTriageRequest(BaseModel):
    threat_ids: list[UUID]
    status: Literal["Open", "In Progress", "Mitigated", "Accepted", "Dismissed"]
    dismiss_reason: Optional[str] = None


class ComplianceControlRef(BaseModel):
    control_id: str
    control_name: str
    framework: str = "NIST 800-53"


class ThreatDiffSummary(BaseModel):
    rule_id: str
    stride_category: str
    severity: str
    description: str  # truncated snippet (first 80 chars)


class ThreatDiffResponse(BaseModel):
    added: list[ThreatDiffSummary]
    removed: list[ThreatDiffSummary]
    counts: dict  # {"added": N, "removed": N, "total_before": N, "total_after": N}
    has_baseline: bool  # False if user never analyzed


class ThreatCatalogEntry(BaseModel):
    rule_id: str
    stride_category: str
    threat_subtype: str
    severity: str
    description_template: str
    condition_type: str

def _strip_html(value: str | None) -> str | None:
    """Strip HTML/script tags to prevent stored XSS in manual threat fields."""
    if value is None:
        return None
    return re.sub(r"<[^>]+>", "", value)


class ManualThreatCreate(BaseModel):
    rule_id: Optional[str] = None  # from catalog or optional custom identifier
    threat_subtype: Optional[str] = None  # required for custom threats without catalog entry
    description: Optional[str] = None  # override or required for custom
    severity: Optional[str] = None  # override
    stride_category: Optional[str] = None  # for custom threats not in catalog
    affected_node_ids: list[str] = []

    @field_validator("threat_subtype")
    @classmethod
    def sanitize_subtype(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 200:
            raise ValueError("threat_subtype must be 200 characters or fewer")
        return _strip_html(v)

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 4000:
            raise ValueError("description must be 4000 characters or fewer")
        return _strip_html(v)


class ThreatQualifyRequest(BaseModel):
    """Atomic qualification mutation: analyst score + action + optional note."""
    analyst_score: int
    action: Literal["confirm", "dismiss", "defer"]
    analyst_score_rationale: Optional[str] = None
    false_positive_reason: Optional[
        Literal[
            "compensating_control",
            "not_applicable",
            "duplicate",
            "architecture_mismatch",
            "accepted_risk",
            "other",
        ]
    ] = None
    # Legacy field preserved for backward compat (old qualify endpoint used note only)
    qualification_note: Optional[str] = None

    @field_validator("analyst_score")
    @classmethod
    def _validate_analyst_score(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("analyst_score must be between 0 and 100")
        return v

    @field_validator("analyst_score_rationale")
    @classmethod
    def _validate_rationale(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 1000:
            raise ValueError("analyst_score_rationale must be 1000 characters or fewer")
        return v or None

    @model_validator(mode="after")
    def _validate_dismiss_reason(self) -> "ThreatQualifyRequest":
        if self.action == "dismiss" and self.false_positive_reason is None:
            raise ValueError("false_positive_reason is required when action is 'dismiss'")
        return self


class ThreatClusterResponse(BaseModel):
    id: UUID
    threat_model_id: UUID
    cluster_label: str
    cluster_reason: str
    representative_threat_id: Optional[UUID] = None
    threat_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class QualificationProgressResponse(BaseModel):
    """Computed progress — no session table, derived from threat state."""
    threat_model_id: UUID
    total_open: int
    qualified: int
    unqualified: int
    progress_pct: float
    cluster_count: int
    clusters_resolved: int


class ThreatAuditEntry(BaseModel):
    id: UUID
    action: str
    old_status: Optional[str]
    new_status: str
    reason: Optional[str]
    changed_by: str  # user email
    changed_at: datetime

    model_config = {"from_attributes": True}
