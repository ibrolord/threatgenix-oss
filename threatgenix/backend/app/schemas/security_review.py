from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator

from app.schemas.environment_evidence import FindingCodeLink

FindingKind = Literal[
    "threat",
    "vulnerability",
    "drift",
    "compliance_gap",
    "control_gap",
    "evidence_gap",
    "hardening",
]
FindingSource = Literal[
    "dfd",
    "document",
    "scan",
    "cloud",
    "iac",
    "repository",
    "compliance",
    "threat_intel",
    "sdlc",
    "manual",
]
SeverityLevel = Literal["Critical", "High", "Medium", "Low"]
ResidualRiskLevel = Literal["Critical", "High", "Medium", "Low", "Negligible"]
ControlEffectiveness = Literal["none", "partial", "substantial", "full"]
DataClassification = Literal["Restricted", "Confidential", "Internal", "Public"]
ScanStatus = Literal["confirmed", "mitigated", "unverifiable", "not_found"]
EvidenceStrength = Literal["strong", "partial", "weak", "missing"]
BusinessCriticality = Literal["mission_critical", "high", "moderate", "low"]
ChangeSurface = Literal["runtime", "deployment", "code", "design", "unknown"]

TruthStatus = Literal["validated", "strongly_indicated", "contextual", "theoretical"]
ExploitabilityRating = Literal["proven", "high", "medium", "low"]
ImpactRating = Literal["severe", "high", "moderate", "low"]
RegulatoryPressure = Literal["red_line", "high", "moderate", "low"]
UrgencyRating = Literal["immediate", "current_cycle", "planned", "defer"]
ActionBucket = Literal[
    "bright_red_line",
    "engineer_now",
    "verify_control",
    "fill_evidence_gap",
    "planned_hardening",
    "monitor",
]
PriorityBand = Literal["p0_blocker", "p1_now", "p2_sprint", "p3_backlog", "p4_monitor"]
NoiseDisposition = Literal["focus", "queue", "background", "suppress"]
EvidenceAdjustmentField = Literal[
    "truth_status",
    "exploitability",
    "business_impact",
    "regulatory_pressure",
    "action_bucket",
    "priority",
    "noise_disposition",
]
ReviewDeltaDisposition = Literal[
    "new", "resolved", "reopened", "escalated", "deescalated", "unchanged"
]
QueueBucket = Literal["fix_now", "verify", "gather_evidence", "backlog"]
ReviewStatus = Literal["open", "in_progress", "mitigated", "accepted", "dismissed"]
ReviewConfidence = Literal["high", "medium", "low"]
ReviewArtifactKind = Literal[
    "remediation_note", "verification_note", "evidence_request"
]
ReviewDisplayKind = Literal[
    "threat",
    "hardening",
    "misconfiguration",
    "compliance_gap",
    "control_gap",
    "evidence_gap",
    "pr_risk",
    "incident_signal",
]
ReviewPrimaryMode = Literal["review", "findings", "compliance", "model_health"]
ReviewSourceProvenance = Literal[
    "rules_engine",
    "framework_seed",
    "app_review_projection",
    "manual",
    "external_import",
]
ReviewSourceSystem = Literal["threatgenix", "external"]
ReviewSourceObjectType = Literal["threat", "application_review_finding", "manual"]
AgentReleaseDecision = Literal[
    "ship",
    "block",
    "fix_now",
    "verify",
    "gather_evidence",
    "accept_risk",
]
AgentCiFailPolicy = Literal[
    "block_only",
    "block_or_fix_now",
    "block_fix_now_or_verify",
    "never",
]
AgentEvidenceType = Literal[
    "code",
    "dfd",
    "document",
    "scan",
    "cloud",
    "iac",
    "control",
    "threat_intel",
    "manual",
    "repository",
    "unknown",
]


class SecurityReviewEvidenceAdjustment(BaseModel):
    """Explicitly records how evidence changed a verdict.

    This is critical for auditability and to show users why compensating
    controls or environment evidence changed the final recommendation.
    """

    evidence_type: FindingSource
    evidence_value: str
    field_affected: EvidenceAdjustmentField
    original_value: str
    adjusted_value: str
    justification: str


class SecurityReviewAttackPath(BaseModel):
    """Rolls multiple findings into one path-level risk summary."""

    path_id: str
    finding_keys: list[str] = Field(default_factory=list)
    finding_titles: list[str] = Field(default_factory=list)
    chain_description: str
    entry_point: str | None = None
    target_asset: str | None = None
    hop_count: int = 0
    support_count: int = 0
    composite_exploitability: ExploitabilityRating
    composite_priority: PriorityBand
    path_nodes: list[str] = Field(default_factory=list)
    evidence_sources: list[FindingSource] = Field(default_factory=list)
    relationship_reasons: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)


class SecurityReviewRiskAcceptance(BaseModel):
    """Persistent acceptance state required for continuous review."""

    finding_title: str
    status: Literal["active", "expired", "reopened"]
    accepted_by: str | None = None
    accepted_at: str | None = None
    expires_at: str | None = None
    acceptance_rationale: str | None = None
    compensating_control: str | None = None
    reopen_triggers: list[str] = Field(default_factory=list)


class SecurityReviewRiskAcceptanceRequest(BaseModel):
    """Governed accepted-risk payload for review findings."""

    accepted_by: str | None = None
    expires_at: str | None = None
    acceptance_rationale: str
    compensating_control: str | None = None

    @field_validator("acceptance_rationale")
    @classmethod
    def _validate_acceptance_rationale(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("acceptance_rationale must not be blank")
        return candidate

    @field_validator("accepted_by", "expires_at", "compensating_control")
    @classmethod
    def _normalize_optional_string(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None


class SecurityReviewDelta(BaseModel):
    """What changed since the last review run."""

    disposition: ReviewDeltaDisposition = "unchanged"
    days_since_last_review: int | None = None
    new_findings_count: int = 0
    resolved_count: int = 0
    reopened_count: int = 0
    escalated_count: int = 0


class SecurityReviewContext(BaseModel):
    """Typed context for one review decision.

    This is intentionally broader than a threat record so the same decision layer
    can score threat findings, scan results, drift findings, compliance gaps, and
    evidence gaps without pretending they are all the same artifact.
    """

    finding_kind: FindingKind
    finding_key: str | None = None
    title: str
    description: str | None = None
    finding_sources: list[FindingSource] = Field(default_factory=list)
    affected_node_ids: list[str] = Field(default_factory=list)
    affected_edge_ids: list[str] = Field(default_factory=list)
    entry_point: str | None = None
    target_asset: str | None = None
    threat_severity: SeverityLevel | None = None
    residual_risk_level: ResidualRiskLevel | None = None
    control_effectiveness: ControlEffectiveness = "none"
    scan_status: ScanStatus | None = None
    has_known_exploited_vulnerability: bool = False
    has_exact_threat_intel: bool = False
    has_semantic_threat_intel: bool = False
    internet_facing: bool = False
    public_exposure: bool = False
    privileged_access: bool = False
    crosses_trust_boundary: bool = False
    control_plane_asset: bool = False
    crown_jewel: bool = False
    data_classification: DataClassification = "Internal"
    regulatory_scope: list[str] = Field(default_factory=list)
    business_criticality: BusinessCriticality = "moderate"
    business_capability: str | None = None
    evidence_strength: EvidenceStrength = "partial"
    change_surface: ChangeSurface = "unknown"
    active_change_window: bool = False
    compensating_controls_present: bool = False
    owner_known: bool = True
    remediation_exists: bool = False
    existing_risk_acceptance: SecurityReviewRiskAcceptance | None = None
    previous_priority: PriorityBand | None = None
    previous_truth_status: TruthStatus | None = None
    days_since_last_review: int | None = None
    code_links: list[FindingCodeLink] = Field(default_factory=list)
    evidence_anchors: list["SecurityReviewEvidenceAnchor"] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("title must not be blank")
        return candidate

    @field_validator("regulatory_scope")
    @classmethod
    def _normalize_regulatory_scope(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            candidate = item.strip()
            if not candidate:
                continue
            key = candidate.casefold()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(candidate)
        return normalized


class SecurityReviewScoreBreakdown(BaseModel):
    reality: int
    exploitability: int
    business_impact: int
    regulatory_pressure: int
    noise_penalty: int
    total: int


class SecurityReviewDecision(BaseModel):
    priority: PriorityBand
    action_bucket: ActionBucket
    truth_status: TruthStatus
    urgency: UrgencyRating
    exploitability: ExploitabilityRating
    business_impact: ImpactRating
    regulatory_pressure: RegulatoryPressure
    noise_disposition: NoiseDisposition
    numeric_score: int
    score_breakdown: SecurityReviewScoreBreakdown
    evidence_adjustments: list[SecurityReviewEvidenceAdjustment] = Field(
        default_factory=list
    )
    related_attack_paths: list[SecurityReviewAttackPath] = Field(default_factory=list)
    risk_acceptance: SecurityReviewRiskAcceptance | None = None
    review_delta: SecurityReviewDelta | None = None
    rationale: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class SecurityReviewBucketCount(BaseModel):
    key: str
    label: str
    count: int


class SecurityReviewFindingSummary(BaseModel):
    finding_key: str | None = None
    threat_id: str | None = None
    display_id: str | None = None
    finding_kind: FindingKind
    title: str
    priority: PriorityBand
    action_bucket: ActionBucket
    truth_status: TruthStatus
    urgency: UrgencyRating
    noise_disposition: NoiseDisposition
    numeric_score: int
    entry_point: str | None = None
    target_asset: str | None = None
    rationale_excerpt: str | None = None
    next_step: str | None = None
    related_attack_path_count: int = 0
    evidence_adjustment_count: int = 0
    systemic: bool = False


class SecurityReviewCoverageSummary(BaseModel):
    total_findings: int = 0
    threat_findings: int = 0
    systemic_findings: int = 0
    open_threats: int = 0
    public_entry_points: int = 0
    privileged_surfaces: int = 0
    restricted_assets: int = 0
    attack_paths: int = 0
    attached_evidence_sources: int = 0
    missing_evidence_sources: int = 0


class SecurityReviewRiskAcceptanceSummary(BaseModel):
    active: int = 0
    reopened: int = 0
    expired: int = 0


class SecurityReviewDeltaSummary(BaseModel):
    new_findings: int = 0
    resolved_findings: int = 0
    reopened_findings: int = 0
    escalated_findings: int = 0
    deescalated_findings: int = 0


class SecurityReviewApplicationSummary(BaseModel):
    generated_at: str
    system_name: str
    overall_priority: PriorityBand
    overall_action_bucket: ActionBucket
    focus_statement: str
    rationale: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    coverage: SecurityReviewCoverageSummary = Field(
        default_factory=SecurityReviewCoverageSummary
    )
    priority_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    action_bucket_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    truth_status_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    noise_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    top_findings: list[SecurityReviewFindingSummary] = Field(default_factory=list)
    blind_spots: list[SecurityReviewFindingSummary] = Field(default_factory=list)
    attack_paths: list[SecurityReviewAttackPath] = Field(default_factory=list)
    risk_acceptance_summary: SecurityReviewRiskAcceptanceSummary = Field(
        default_factory=SecurityReviewRiskAcceptanceSummary
    )
    review_delta_summary: SecurityReviewDeltaSummary = Field(
        default_factory=SecurityReviewDeltaSummary
    )


class SecurityReviewStateRecord(BaseModel):
    id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    queue_bucket: QueueBucket | None = None
    review_status: ReviewStatus | None = None
    last_non_terminal_bucket: QueueBucket | None = None
    owner: str | None = None
    due_at: str | None = None
    note: str | None = None
    artifacts: list["SecurityReviewArtifact"] = Field(default_factory=list)
    risk_acceptance: SecurityReviewRiskAcceptance | None = None
    created_at: str
    updated_at: str


class SecurityReviewStateUpdate(BaseModel):
    queue_bucket: QueueBucket | None = None
    review_status: ReviewStatus | None = None
    last_non_terminal_bucket: QueueBucket | None = None
    owner: str | None = None
    due_at: str | None = None
    note: str | None = None
    artifacts: list["SecurityReviewArtifact"] | None = None
    risk_acceptance: SecurityReviewRiskAcceptance | None = None


class SecurityReviewArtifact(BaseModel):
    id: str
    kind: ReviewArtifactKind
    title: str
    summary: str
    body: str
    created_at: str


class SecurityReviewArtifactCreate(BaseModel):
    kind: ReviewArtifactKind


class SecurityReviewEvidenceAnchor(BaseModel):
    type: AgentEvidenceType = "unknown"
    reference: str
    claim: str
    validated: bool = False
    source_object_type: str | None = None
    source_object_id: str | None = None
    location: str | None = None
    relationship: str | None = None
    strength: EvidenceStrength | None = None


class SecurityReviewFinding(BaseModel):
    id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    threat_id: str | None = None
    display_id: str | None = None
    wire_kind: FindingKind | Literal["pr_risk", "incident_signal"]
    display_kind: ReviewDisplayKind
    source_provenance: ReviewSourceProvenance
    source_system: ReviewSourceSystem = "threatgenix"
    title: str
    priority: PriorityBand
    numeric_score: int = 0
    wire_action_bucket: ActionBucket | None = None
    queue_bucket: QueueBucket | None = None
    computed_queue_bucket: QueueBucket | None = None
    truth_status: TruthStatus | None = None
    exploitability: ExploitabilityRating | None = None
    urgency: UrgencyRating | None = None
    business_impact: ImpactRating | None = None
    regulatory_pressure: RegulatoryPressure | None = None
    confidence: ReviewConfidence
    is_real: bool = False
    is_urgent: bool = False
    is_exploitable_in_context: bool = False
    is_regulatory_or_control_relevant: bool = False
    needs_engineering_change: bool = False
    needs_evidence: bool = False
    why_now: str
    impacted_assets: list[str] = Field(default_factory=list)
    entry_point: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    linked_threat_ids: list[str] = Field(default_factory=list)
    linked_change_ids: list[str] = Field(default_factory=list)
    linked_control_ids: list[str] = Field(default_factory=list)
    code_links: list[FindingCodeLink] = Field(default_factory=list)
    evidence_anchors: list[SecurityReviewEvidenceAnchor] = Field(default_factory=list)
    owner: str | None = None
    due_at: str | None = None
    note: str | None = None
    artifacts: list[SecurityReviewArtifact] = Field(default_factory=list)
    risk_acceptance: SecurityReviewRiskAcceptance | None = None
    review_status: ReviewStatus
    last_non_terminal_bucket: QueueBucket | None = None
    primary_mode: ReviewPrimaryMode
    noise_disposition: NoiseDisposition
    computed_recommendation_changed: bool = False
    systemic: bool = False
    next_best_action: str | None = None
    next_step: str | None = None
    rationale_excerpt: str | None = None


class SecurityReviewFindingListResponse(BaseModel):
    generated_at: str
    system_name: str
    queue_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    review_status_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    default_finding_id: str | None = None
    findings: list[SecurityReviewFinding] = Field(default_factory=list)


class AgentEvidenceRef(SecurityReviewEvidenceAnchor):
    pass


class AgentFindingVerification(BaseModel):
    required: bool
    suggested_test: str | None = None
    evidence_needed: list[str] = Field(default_factory=list)


class AgentCiContract(BaseModel):
    fail_policy: AgentCiFailPolicy = "block_only"
    blocking_decisions: list[AgentReleaseDecision] = Field(
        default_factory=lambda: ["block"]
    )
    should_fail: bool = False
    exit_code: int = 0
    reason: str = (
        "CI should continue because the release decision is not configured as a "
        "failing condition."
    )


class AgentSecurityReviewFinding(BaseModel):
    decision: AgentReleaseDecision
    finding_id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    title: str
    priority: PriorityBand
    confidence: ReviewConfidence
    risk_path: list[str] = Field(default_factory=list)
    evidence: list[AgentEvidenceRef] = Field(default_factory=list)
    fix_instructions: list[str] = Field(default_factory=list)
    verification: AgentFindingVerification


class AgentSecurityReviewResponse(BaseModel):
    generated_at: str
    system_name: str
    decision: AgentReleaseDecision
    decision_reason: str
    pass_semantics: str
    ci: AgentCiContract = Field(default_factory=AgentCiContract)
    findings: list[AgentSecurityReviewFinding] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)


class AgentRemediationWebhookSetup(BaseModel):
    provider: Literal["github", "linear", "jira"]
    provider_label: str
    callback_url: str
    action_marker: str
    action_marker_hint: str
    event_filters: list[str] = Field(default_factory=list)
    registration_steps: list[str] = Field(default_factory=list)
    required_headers: dict[str, str] = Field(default_factory=dict)
    signature_scheme: Literal["hmac_sha256_v1"] = "hmac_sha256_v1"
    signature_base_string: str
    signing_secret_hint: str


class AgentRemediationTicketDraft(BaseModel):
    provider: Literal["github_issue", "linear", "jira"]
    title: str
    body: str
    labels: list[str] = Field(default_factory=list)
    priority: PriorityBand
    confirmation_required: bool = True
    external_creation_status: Literal["draft_only", "created"] = "draft_only"
    connector_creation_status: Literal[
        "available_with_confirmation",
        "created",
    ] = "available_with_confirmation"
    connector_confirmation_hint: str = (
        "Direct provider creation requires explicit confirmation and a "
        "customer-owned provider token at action time."
    )
    callback_security_status: Literal["signed_hmac_required"] = "signed_hmac_required"
    callback_security_hint: str = (
        "Provider evidence callbacks must include timestamp, nonce, and "
        "HMAC-SHA256 signature headers before evidence is ingested."
    )
    callback_setup: AgentRemediationWebhookSetup | None = None
    callback_setups: list[AgentRemediationWebhookSetup] = Field(default_factory=list)
    external_ticket_id: str | None = None
    external_ticket_url: str | None = None


class AgentRemediationTransition(BaseModel):
    status: Literal[
        "needs_action",
        "ready_for_rerun",
        "ready_for_verify",
        "ready_for_clearance",
        "evidence_still_missing",
    ]
    current_decision: AgentReleaseDecision
    expected_next_decision: AgentReleaseDecision
    rationale: str
    artifact_count: int = 0
    latest_artifact_at: str | None = None
    evidence_count: int = 0


class AgentRemediationHistoryEntry(BaseModel):
    action_id: str
    finding_id: str
    artifact_kind: ReviewArtifactKind
    artifact_title: str
    created_at: str
    transition_status: str


class AgentRemediationAction(BaseModel):
    action_id: str
    finding_id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    title: str
    current_decision: AgentReleaseDecision
    action_kind: Literal["patch_guidance", "verification", "evidence_request"]
    artifact_kind: ReviewArtifactKind
    priority: PriorityBand
    instruction: str
    verification_required: bool
    evidence_needed: list[str] = Field(default_factory=list)
    expected_next_decision: AgentReleaseDecision
    rerun_required: bool = True
    ticket_draft: AgentRemediationTicketDraft
    transition: AgentRemediationTransition


class AgentRemediationPlanResponse(BaseModel):
    generated_at: str
    system_name: str
    current_decision: AgentReleaseDecision
    loop_status: Literal["ready", "no_action_required"]
    summary: str
    actions: list[AgentRemediationAction] = Field(default_factory=list)
    action_history: list[AgentRemediationHistoryEntry] = Field(default_factory=list)
    rerun_instructions: list[str] = Field(default_factory=list)
    plan_markdown: str


class AgentRemediationPlanApplyRequest(BaseModel):
    action_ids: list[str] | None = None
    max_actions: int = Field(default=8, ge=1, le=25)


class AgentRemediationPlanApplyResponse(BaseModel):
    generated_at: str
    system_name: str
    created_artifact_count: int
    updated_finding_ids: list[str] = Field(default_factory=list)
    plan: AgentRemediationPlanResponse


class AgentRemediationTicketCreateRequest(BaseModel):
    action_id: str
    provider: Literal["github_issue", "linear", "jira"] = "github_issue"
    confirmed: bool = False
    external_ticket_id: str | None = None
    external_ticket_url: str | None = None
    created_by: str | None = None


class AgentRemediationTicketCreateResponse(BaseModel):
    generated_at: str
    system_name: str
    created_ticket_count: int
    updated_finding_ids: list[str] = Field(default_factory=list)
    plan: AgentRemediationPlanResponse


class AgentRemediationConnectorTicketCreateRequest(BaseModel):
    action_id: str
    provider: Literal["github_issue", "linear", "jira"] = "github_issue"
    confirmed: bool = False
    access_token: SecretStr | None = Field(
        None,
        description=(
            "Customer-owned provider credential used only for this outbound "
            "ticket creation request. It is not returned in responses."
        ),
    )
    github_repository: str | None = Field(
        None,
        description="GitHub repository as owner/repo or a github.com URL.",
    )
    linear_team_id: str | None = None
    jira_base_url: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = "Task"
    created_by: str | None = None

    @field_validator("action_id")
    @classmethod
    def _validate_action_id(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("action_id must not be blank")
        return candidate

    @field_validator(
        "github_repository",
        "linear_team_id",
        "jira_base_url",
        "jira_project_key",
        "jira_issue_type",
        "created_by",
    )
    @classmethod
    def _normalize_optional_string(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None


class AgentRemediationConnectorTicketCreateResponse(BaseModel):
    generated_at: str
    system_name: str
    provider: Literal["github_issue", "linear", "jira"]
    created_ticket_count: int
    updated_finding_ids: list[str] = Field(default_factory=list)
    external_ticket_id: str
    external_ticket_url: str | None = None
    callback_url: str
    callback_payload_template: dict[str, str | None]
    callback_security_scheme: Literal["hmac_sha256_v1"] = "hmac_sha256_v1"
    callback_required_headers: dict[str, str] = Field(default_factory=dict)
    callback_signature_base_string: str = ""
    plan: AgentRemediationPlanResponse


class AgentRemediationEvidenceWebhookRequest(BaseModel):
    action_id: str | None = None
    source_object_type: ReviewSourceObjectType | None = None
    source_object_id: str | None = None
    provider: Literal["github_pr", "github_issue", "linear", "jira", "manual"] = "manual"
    external_ticket_id: str | None = None
    pull_request_url: str | None = None
    commit_sha: str | None = None
    evidence_url: str | None = None
    evidence_summary: str
    received_at: str | None = None


class AgentRemediationEvidenceWebhookResponse(BaseModel):
    generated_at: str
    system_name: str
    ingested_artifact_count: int
    updated_finding_ids: list[str] = Field(default_factory=list)
    callback_security_status: Literal["verified"] = "verified"
    normalized_provider_event: Literal[
        "pull_request_evidence",
        "issue_evidence",
        "ticket_evidence",
        "manual_evidence",
    ]
    plan: AgentRemediationPlanResponse


class AgentRemediationProviderWebhookTestRequest(BaseModel):
    provider: Literal["github", "linear", "jira"]
    payload_text: str
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("payload_text")
    @classmethod
    def _validate_payload_text(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("payload_text must not be blank")
        return candidate


class AgentRemediationProviderWebhookTestResponse(BaseModel):
    generated_at: str
    system_name: str
    provider: Literal["github", "linear", "jira"]
    callback_security_status: Literal["verified"] = "verified"
    nonce_status: Literal["accepted"] = "accepted"
    normalized_provider_event: Literal[
        "pull_request_evidence",
        "issue_evidence",
        "ticket_evidence",
        "manual_evidence",
    ]
    action_id: str
    finding_id: str
    action_title: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    external_ticket_id: str | None = None
    pull_request_url: str | None = None
    commit_sha: str | None = None
    evidence_url: str | None = None
    evidence_summary: str
    next_step: str = (
        "Signature, nonce, provider parsing, and action mapping are verified. "
        "Enable the live callback only when the customer-owned relay signs the "
        "exact raw provider payload."
    )
    plan: AgentRemediationPlanResponse


class CustomerSecurityPacketFinding(BaseModel):
    title: str
    release_decision: AgentReleaseDecision
    customer_status: Literal[
        "validated_risk",
        "accepted_risk",
        "needs_verification",
        "evidence_gap",
    ]
    summary: str
    evidence_summary: str
    next_step: str | None = None


class CustomerSecurityPacketSourceFingerprint(BaseModel):
    source_type: Literal[
        "review_summary",
        "review_findings",
        "agent_decision",
        "repository",
        "pull_request",
        "scan",
        "cloud_scan",
        "iac",
    ]
    source_id: str
    label: str
    fingerprint: str
    collected_at: str | None = None


class CustomerSecurityPacketResponse(BaseModel):
    generated_at: str
    system_name: str
    audience: Literal["customer_security_review"] = "customer_security_review"
    packet_version: Literal["customer_packet_v1"] = "customer_packet_v1"
    packet_hash: str = ""
    redaction_profile: Literal["customer_safe_v1"] = "customer_safe_v1"
    release_decision: AgentReleaseDecision
    decision_summary: str
    scope: list[str] = Field(default_factory=list)
    proven: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    validated_risks: list[CustomerSecurityPacketFinding] = Field(default_factory=list)
    accepted_risks: list[CustomerSecurityPacketFinding] = Field(default_factory=list)
    evidence_gaps: list[CustomerSecurityPacketFinding] = Field(default_factory=list)
    source_fingerprints: list[CustomerSecurityPacketSourceFingerprint] = Field(
        default_factory=list
    )
    redaction_notes: list[str] = Field(default_factory=list)
    customer_safe_markdown: str


SecurityReviewContext.model_rebuild()
SecurityReviewDecision.model_rebuild()
SecurityReviewApplicationSummary.model_rebuild()
