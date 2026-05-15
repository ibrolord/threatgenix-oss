// Mirrors backend Pydantic schemas exactly

export type OpenText<T extends string> = T | (string & {});

export type TLSVersion = OpenText<
  "none" | "tls_1_0" | "tls_1_1" | "tls_1_2" | "tls_1_3" | "other"
>;
export type KnownBoundaryType =
  | "network"
  | "organizational"
  | "regulatory"
  | "privilege"
  | "cloud";
export type BoundaryType = OpenText<KnownBoundaryType>;

export interface SecurityControl {
  control_type: string;
  name: string;
  covers: string[];
  notes?: string;
}

export interface DataObject {
  name: string;
  classification?: string;
  description?: string;
}

export type RegulatoryFramework =
  | "OSFI B-13"
  | "PCI DSS"
  | "PIPEDA"
  | "FINTRAC"
  | "NIST"
  | "ISO 27001";

export type DeploymentModel = "on-prem" | "cloud" | "hybrid";
export type ReportSectionId =
  | "executive_summary"
  | "scope"
  | "system_context"
  | "dfd"
  | "arch_diagrams"
  | "threats"
  | "controls"
  | "compliance"
  | "scan_validation"
  | "responsibility_matrix"
  | "assumptions"
  | "methodology";

export interface ReportTemplateSection {
  id: string;
  kind: "built_in" | "custom_text";
  source_section_id?: ReportSectionId | null;
  title: string;
  intro_text?: string | null;
  body?: string | null;
}

export interface ReportTemplateDefinition {
  id: string;
  name: string;
  description: string;
  audience: string;
  cover_title: string;
  cover_subtitle?: string | null;
  sections: ReportTemplateSection[];
  built_in: boolean;
}

export interface UserResponse {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  email_verified?: boolean;
  organization_id?: string | null;
  organization_name?: string | null;
  organization_subscription_tier?: string | null;
  organization_is_active?: boolean | null;
  report_template_library: ReportTemplateDefinition[];
}

export interface ThreatModelCreate {
  system_name: string;
  description?: string;
  data_classification: "Public" | "Internal" | "Confidential" | "Restricted";
  regulatory_scope?: RegulatoryFramework[];
  deployment_model?: DeploymentModel | null;
}

export interface ThreatModelResponse {
  id: string;
  owner_id?: string | null;
  organization_id?: string | null;
  organization_name?: string | null;
  system_name: string;
  description: string;
  data_classification: string;
  regulatory_scope: RegulatoryFramework[];
  deployment_model: DeploymentModel | null;
  repository_evidence: RepositoryEvidence | null;
  cloud_scan_evidence: CloudScanEvidence | null;
  iac_evidence: IacEvidence | null;
  environment_context_summary: string | null;
  report_template?: string;
  report_templates: ReportTemplateDefinition[];
  report_watermark_text?: string | null;
  report_logo_base64?: string | null;
  arch_diagrams?: { name: string; image_base64: string }[] | null;
  analyst_name?: string | null;
  analyst_attestation?: string | null;
  next_review_date?: string | null;
  out_of_scope_statement?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ThreatModelListItem {
  id: string;
  owner_id?: string | null;
  organization_id?: string | null;
  organization_name?: string | null;
  system_name: string;
  data_classification: string;
  created_at: string;
  updated_at: string;
  threat_count: number;
}

export type EvidenceConfidenceLabel =
  | "validated"
  | "strongly_indicated"
  | "contextual"
  | "theoretical"
  | "unknown"
  | "suppressed";

export type EvidenceFreshnessStatus = "fresh" | "aging" | "stale" | "expired" | "unknown";
export type EvidenceProjectionStatus = "not_built" | "current" | "stale" | "error";

export interface EvidenceCountBucket {
  key: string;
  count: number;
}

export interface EvidenceCoverageGap {
  gap_type: string;
  severity: "blocking" | "warning" | "info";
  title: string;
  detail: string;
  remediation: string;
}

export interface EvidenceStatusResponse {
  threat_model_id: string;
  projection_status: EvidenceProjectionStatus;
  generated_at: string;
  source_count: number;
  item_count: number;
  entity_count: number;
  relationship_count: number;
  observation_count: number;
  finding_count: number;
  sources_by_type: EvidenceCountBucket[];
  items_by_type: EvidenceCountBucket[];
  entities_by_type: EvidenceCountBucket[];
  findings_by_kind: EvidenceCountBucket[];
  freshness: EvidenceCountBucket[];
  coverage_gaps: EvidenceCoverageGap[];
}

export type TMACFormat = "yaml" | "json";
export type TMACImportMode = "preview" | "replace" | "create_new";

export interface TMACSummary {
  node_count: number;
  edge_count: number;
  boundary_count: number;
  built_in_view_count: number;
  custom_view_count: number;
  threat_count: number;
  assumption_count: number;
  control_count: number;
  component_template_count: number;
  property_option_count: number;
  snapshot_count: number;
  review_count: number;
  collaborator_count: number;
  assignment_count: number;
  notification_count: number;
}

export interface TMACValidationResponse {
  format: TMACFormat;
  summary: TMACSummary;
  warnings: string[];
}

export interface TMACImportRequest {
  content: string;
  mode?: TMACImportMode;
  target_threat_model_id?: string | null;
  apply_operational_state?: boolean;
  apply_binary_assets?: boolean;
}

export interface TMACImportResponse {
  mode: TMACImportMode;
  threat_model_id?: string | null;
  system_name: string;
  created_new: boolean;
  applied_operational_state: boolean;
  applied_binary_assets: boolean;
  summary: TMACSummary;
  warnings: string[];
}

export interface TMACDiffResponse {
  current_summary: TMACSummary;
  incoming_summary: TMACSummary;
  changed_sections: string[];
  warnings: string[];
}

export type AssumptionAnchorKind = "node" | "edge" | "boundary";
export type AssumptionStatus = "open" | "validated" | "challenged";

export interface ThreatModelAssumptionResponse {
  id: string;
  title: string;
  description: string;
  status: AssumptionStatus;
  anchor_kind: AssumptionAnchorKind;
  anchor_id: string;
  anchor_label: string;
  created_at: string;
  updated_at: string;
}

export interface ThreatModelAssumptionCreate {
  title: string;
  description?: string;
  status?: AssumptionStatus;
  anchor_kind: AssumptionAnchorKind;
  anchor_id: string;
  anchor_label?: string | null;
}

export interface ThreatModelAssumptionUpdate {
  title?: string;
  description?: string;
  status?: AssumptionStatus;
  anchor_kind?: AssumptionAnchorKind;
  anchor_id?: string;
  anchor_label?: string | null;
}

export interface AssumptionAnchorTarget {
  kind: AssumptionAnchorKind;
  id: string;
  label: string;
}

export interface ThreatModelVersionCreate {
  name: string;
  description?: string;
}

export interface ThreatModelVersionResponse {
  id: string;
  name: string;
  description: string;
  created_at: string;
  created_by: string;
  node_count: number;
  edge_count: number;
  boundary_count: number;
  threat_count: number;
}

export interface ThreatModelVersionDiffRequest {
  left_snapshot_id: string;
  right_snapshot_id?: string | null;
}

export interface ThreatModelVersionDiffResponse {
  left_label: string;
  right_label: string;
  node_delta: number;
  edge_delta: number;
  boundary_delta: number;
  threat_delta: number;
  added_nodes: string[];
  removed_nodes: string[];
  added_threats: string[];
  removed_threats: string[];
}

export interface ThreatModelReviewCommentResponse {
  id: string;
  author: string;
  comment: string;
  created_at: string;
}

export interface ThreatModelReviewCreate {
  snapshot_id: string;
  title: string;
  assignee?: string | null;
}

export interface ThreatModelReviewUpdate {
  status?: "pending" | "approved" | "changes_requested";
  assignee?: string | null;
  comment?: string | null;
}

export interface ThreatModelReviewResponse {
  id: string;
  snapshot_id: string;
  title: string;
  status: "pending" | "approved" | "changes_requested";
  assignee: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  signed_off_at: string | null;
  comments: ThreatModelReviewCommentResponse[];
}

export interface ThreatModelControlCreate {
  title: string;
  description?: string;
  category?: "preventive" | "detective" | "corrective" | "compensating";
  status?: "planned" | "implemented" | "partial" | "deferred";
  owner?: string | null;
  evidence?: string | null;
  mapped_threat_ids?: string[];
}

export interface ThreatModelControlUpdate {
  title?: string;
  description?: string;
  category?: "preventive" | "detective" | "corrective" | "compensating";
  status?: "planned" | "implemented" | "partial" | "deferred";
  owner?: string | null;
  evidence?: string | null;
  mapped_threat_ids?: string[];
}

export interface ThreatModelControlResponse {
  id: string;
  title: string;
  description: string;
  category: "preventive" | "detective" | "corrective" | "compensating";
  status: "planned" | "implemented" | "partial" | "deferred";
  owner: string | null;
  evidence: string | null;
  mapped_threat_ids: string[];
  updated_at: string;
}

export interface ArchitectureValidationSummary {
  completeness_score: number;
  discovered_components: number;
  discovered_repository_components: number;
  discovered_cloud_services: number;
  modeled_components: number;
  mapped_discovered_components: number;
  latest_scan_status: string | null;
  latest_scan_finding_count: number;
  correlated_scan_results: number;
  unmapped_repository_components: string[];
  unmapped_cloud_services: string[];
  nodes_without_scan_targets: string[];
  unvalidated_threats: string[];
  drift_flags: string[];
}

export interface ThreatModelAssumptionSummary {
  total: number;
  open: number;
  validated: number;
  challenged: number;
}

export interface ThreatModelMitigationSummary {
  total: number;
  active: number;
  mitigated: number;
  accepted: number;
  dismissed: number;
  with_plan: number;
  with_owner: number;
  with_due_date: number;
  with_residual_risk: number;
}

export interface ThreatModelControlSummary {
  total: number;
  planned: number;
  implemented: number;
  partial: number;
  deferred: number;
  with_evidence: number;
  mapped_to_threats: number;
  with_owner: number;
}

export interface ThreatModelReviewSummary {
  total: number;
  pending: number;
  approved: number;
  changes_requested: number;
  latest_status: "pending" | "approved" | "changes_requested" | null;
  latest_title: string | null;
  latest_updated_at: string | null;
}

export interface ThreatModelElementCoverageSummary {
  total: number;
  with_threats: number;
  with_assumptions: number;
  with_stride_coverage: number;
  without_stride_coverage: number;
  fully_stride_covered: number;
  average_stride_categories: number;
  uncovered_labels: string[];
}

export interface ThreatModelCoverageSummary {
  coverage_score: number;
  total_elements: number;
  covered_elements: number;
  stride_categories_seen: string[];
  missing_stride_categories: string[];
  nodes: ThreatModelElementCoverageSummary;
  edges: ThreatModelElementCoverageSummary;
  boundaries: ThreatModelElementCoverageSummary;
}

export interface ThreatModelReviewFreshnessSummary {
  status: "current" | "stale" | "pending" | "changes_requested" | "unreviewed";
  summary: string;
  reviewed_snapshot_id: string | null;
  reviewed_snapshot_name: string | null;
  latest_review_title: string | null;
  latest_review_status: "pending" | "approved" | "changes_requested" | null;
  reviewed_at: string | null;
  changes_since_review: ThreatModelVersionDiffResponse | null;
}

export type ThreatModelCollaboratorRole =
  | "owner"
  | "editor"
  | "reviewer"
  | "viewer";
export type ThreatModelCollaboratorStatus = "active" | "invited" | "disabled";
export type ThreatModelAssignmentStatus =
  | "open"
  | "in_progress"
  | "blocked"
  | "done";
export type ThreatModelAssignmentPriority =
  | "critical"
  | "high"
  | "medium"
  | "low";
export type ThreatModelNotificationStatus = "unread" | "read";

export interface ThreatModelCollaboratorCreate {
  email: string;
  role: ThreatModelCollaboratorRole;
}

export interface ThreatModelCollaboratorUpdate {
  role?: ThreatModelCollaboratorRole;
  status?: ThreatModelCollaboratorStatus;
}

export interface ThreatModelCollaboratorResponse {
  id: string;
  email: string;
  role: ThreatModelCollaboratorRole;
  status: ThreatModelCollaboratorStatus;
  invited_by: string;
  invited_at: string;
  updated_at: string;
}

export interface ThreatModelAssignmentCommentResponse {
  id: string;
  author: string;
  comment: string;
  created_at: string;
}

export interface ThreatModelAssignmentCreate {
  title: string;
  description?: string;
  assignee: string;
  priority?: ThreatModelAssignmentPriority;
  due_date?: string | null;
  threat_id?: string | null;
  review_id?: string | null;
  anchor_kind?: "node" | "edge" | "boundary" | "threat" | "review" | null;
  anchor_id?: string | null;
  anchor_label?: string | null;
}

export interface ThreatModelAssignmentUpdate {
  title?: string;
  description?: string;
  assignee?: string;
  priority?: ThreatModelAssignmentPriority;
  status?: ThreatModelAssignmentStatus;
  due_date?: string | null;
  comment?: string | null;
}

export interface ThreatModelAssignmentResponse {
  id: string;
  title: string;
  description: string;
  assignee: string;
  priority: ThreatModelAssignmentPriority;
  status: ThreatModelAssignmentStatus;
  due_date: string | null;
  threat_id: string | null;
  review_id: string | null;
  anchor_kind: "node" | "edge" | "boundary" | "threat" | "review" | null;
  anchor_id: string | null;
  anchor_label: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  comments: ThreatModelAssignmentCommentResponse[];
}

export interface ThreatModelNotificationResponse {
  id: string;
  type:
    | "review_requested"
    | "review_updated"
    | "assignment_created"
    | "assignment_updated"
    | "snapshot_created"
    | "control_updated";
  title: string;
  message: string;
  status: ThreatModelNotificationStatus;
  actor: string;
  target_kind:
    | "snapshot"
    | "review"
    | "assignment"
    | "control"
    | "threat_model"
    | null;
  target_id: string | null;
  created_at: string;
}

export interface ThreatModelCollaborationSummary {
  collaborators_total: number;
  active_collaborators: number;
  editors: number;
  reviewers: number;
  viewers: number;
  open_assignments: number;
  overdue_assignments: number;
  unread_notifications: number;
}

export interface AttackPathThreatRef {
  id: string;
  display_id: string;
  severity: string;
  stride_category: string;
  description: string;
}

export interface AttackPathStep {
  node_id: string;
  label: string;
  node_type: string;
  trust_boundary_id: string | null;
}

export interface AttackPathResponse {
  id: string;
  title: string;
  summary: string;
  risk_score: number;
  boundary_crossings: number;
  path_nodes: AttackPathStep[];
  supporting_threats: AttackPathThreatRef[];
}

export interface ThreatModelScorecardResponse {
  overall_status: "good" | "attention" | "action_required";
  overall_summary: string;
  architecture_validation: ArchitectureValidationSummary;
  coverage_summary: ThreatModelCoverageSummary;
  quality_gates: DFDQualityGateSummary;
  assumption_summary: ThreatModelAssumptionSummary;
  mitigation_summary: ThreatModelMitigationSummary;
  control_summary: ThreatModelControlSummary;
  review_summary: ThreatModelReviewSummary;
  review_freshness: ThreatModelReviewFreshnessSummary;
  collaboration_summary: ThreatModelCollaborationSummary;
  residual_risk_by_level: Record<string, number>;
  top_actions: string[];
}

export interface PortfolioTrendPoint {
  date: string;
  snapshot_count: number;
  threat_count: number;
  high_risk_threat_count: number;
  review_events: number;
  control_events: number;
}

export interface PortfolioTrendResponse {
  points: PortfolioTrendPoint[];
  latest_summary: string;
}

// DFD

export type NodeType =
  | "process"
  | "data_store"
  | "external_entity"
  | "human_actor"
  | "iam_role"
  | "managed_service"
  | "api_gateway"
  | "container"
  | "serverless";

export type ComponentShape =
  | "rounded_rect"
  | "square"
  | "pill"
  | "cylinder"
  | "hexagon"
  | "cloud"
  | "stacked"
  | "diamond"
  | "gateway"
  | "queue";

export type DFDPropertyOptionField =
  | "data_classification"
  | "authentication_type"
  | "authorization_model"
  | "network_exposure"
  | "privilege_level"
  | "runtime_type"
  | "isolation_boundary"
  | "input_validation"
  | "logging_level"
  | "encryption_at_rest"
  | "backup_strategy"
  | "entity_scope"
  | "entity_kind"
  | "trust_level"
  | "responsibility";

export interface NodeProperties {
  component_template_id?: string;
  component_label?: string;
  component_shape?: ComponentShape;
  component_description?: string;
  property_display_labels?: Record<string, string>;
  internet_facing?: boolean;
  data_classification?: OpenText<
    "Public" | "Internal" | "Confidential" | "Restricted"
  >;
  authentication_type?: OpenText<
    "none" | "api_key" | "oauth2" | "mtls" | "saml" | "jwt"
  >;
  authorization_model?: OpenText<"none" | "rbac" | "abac" | "acl" | "policy">;
  network_exposure?: OpenText<"internet" | "dmz" | "internal" | "vpc_private">;
  privilege_level?: OpenText<
    "standard" | "elevated" | "privileged" | "admin" | "system"
  >;
  // process
  uses_auth?: boolean;
  validates_input?: boolean;
  uses_encryption?: boolean;
  handles_sensitive_data?: boolean;
  runtime_type?: OpenText<
    "service" | "worker" | "function" | "job" | "gateway" | "container"
  >;
  isolation_boundary?: OpenText<
    | "shared_host"
    | "container"
    | "sandbox"
    | "dedicated_host"
    | "managed_service"
  >;
  accepted_input?: string;
  input_validation?: OpenText<"none" | "partial" | "strict">;
  logging_level?: OpenText<"none" | "errors_only" | "audit" | "full">;
  handles_pii?: boolean;
  handles_financial_data?: boolean;
  // data_store
  stores_credentials?: boolean;
  encrypted_at_rest?: boolean;
  has_backup?: boolean;
  store_type?: string;
  store_purpose?: string;
  read_access_scope?: string;
  write_access_scope?: string;
  encryption_at_rest?: OpenText<
    "none" | "application_level" | "transparent" | "hsm"
  >;
  backup_strategy?: OpenText<"none" | "local" | "geo_redundant">;
  integrity_controls?: string;
  stores_secrets?: boolean;
  // external_entity
  trusted?: boolean;
  authenticated?: boolean;
  entity_scope?: OpenText<"internal" | "external">;
  entity_kind?: OpenText<
    "human" | "device" | "system" | "saas" | "api" | "service"
  >;
  trust_level?: OpenText<
    "untrusted" | "semi_trusted" | "trusted" | "privileged"
  >;
  // cloud node types
  service_name?: string;
  function_name?: string;
  // shared responsibility
  responsibility?: OpenText<"provider" | "customer" | "shared">;
  // vulnerability scanning
  scan_target_url?: string;
  scan_target_ports?: string;
  // security controls
  security_controls?: SecurityControl[];
}

export interface DFDNodeCreate {
  id?: string;
  node_type: NodeType;
  name: string;
  position_x?: number;
  position_y?: number;
  trust_boundary_id?: string | null;
  scan_target_url?: string | null;
  scan_target_ports?: string | null;
  properties?: NodeProperties;
}

export interface DFDNodeResponse {
  id: string;
  node_type: NodeType;
  name: string;
  position_x: number;
  position_y: number;
  trust_boundary_id: string | null;
  scan_target_url?: string | null;
  scan_target_ports?: string | null;
  properties: Record<string, unknown>;
}

export interface DFDNodeUpdate {
  name?: string;
  node_type?: NodeType;
  position_x?: number;
  position_y?: number;
  trust_boundary_id?: string | null;
  scan_target_url?: string | null;
  scan_target_ports?: string | null;
  properties?: NodeProperties;
}

export type EdgeDirectionality = OpenText<
  "request" | "response" | "event" | "bidirectional"
>;

export interface EdgeProperties {
  protocol?: string;
  data_payload?: string;
  data_classification?: OpenText<
    "Public" | "Internal" | "Confidential" | "Restricted"
  >;
  lifecycle_stage?: OpenText<
    | "ingress"
    | "processing"
    | "storage"
    | "egress"
    | "replication"
    | "backup"
    | "analytics"
    | "notification"
  >;
  auth_mechanism?: string;
  encryption_in_transit?: boolean;
  directionality?: EdgeDirectionality;
  transfer_mode?: OpenText<
    "synchronous" | "asynchronous" | "batch" | "streaming" | "near_real_time"
  >;
  sequence_note?: string;
  carries_credentials?: boolean;
  carries_pii?: boolean;
  carries_secrets?: boolean;
  rate_limited?: boolean;
  integrity_protected?: boolean;
  data_types?: string[];
  tls_version?: TLSVersion;
  is_response?: boolean;
  response_to_id?: string | null;
  data_objects?: DataObject[];
  carries_financial_data?: boolean;
}

export interface DFDEdgeCreate {
  id?: string;
  source_node_id: string;
  target_node_id: string;
  label?: string;
  properties?: EdgeProperties;
}

export interface DFDEdgeUpdate {
  label?: string;
  properties?: EdgeProperties;
}

export interface DFDEdgeResponse {
  id: string;
  source_node_id: string;
  target_node_id: string;
  label: string;
  properties: EdgeProperties;
}

export interface TrustBoundaryCreate {
  id?: string;
  name?: string;
  node_ids: string[];
  position_x?: number;
  position_y?: number;
  width?: number;
  height?: number;
  boundary_type?: BoundaryType;
  parent_boundary_id?: string | null;
}

export interface TrustBoundaryResponse {
  id: string;
  name: string;
  node_ids: string[];
  position_x: number;
  position_y: number;
  width: number;
  height: number;
  boundary_type?: BoundaryType;
  parent_boundary_id?: string | null;
}

export interface DFDComponentTemplateDraft {
  label: string;
  description?: string | null;
  semantic_node_type: NodeType;
  shape: ComponentShape;
  group?: string;
  default_name?: string | null;
  semantic_type_label?: string | null;
  default_properties?: NodeProperties;
  ai_generated?: boolean;
  rationale?: string | null;
}

export interface DFDComponentTemplateResponse extends DFDComponentTemplateDraft {
  id: string;
  built_in: boolean;
}

export interface DFDComponentTemplateSuggestRequest {
  prompt: string;
}

export interface DFDComponentTemplateSuggestResponse {
  template: DFDComponentTemplateDraft;
  degraded_reason?: string | null;
}

export interface DFDPropertyOptionDraft {
  field: DFDPropertyOptionField;
  label: string;
  canonical_value: string;
  description?: string | null;
  ai_generated?: boolean;
  rationale?: string | null;
}

export interface DFDPropertyOptionResponse extends DFDPropertyOptionDraft {
  id: string;
}

export interface DFDPropertyOptionSuggestRequest {
  field: DFDPropertyOptionField;
  prompt: string;
}

export interface DFDPropertyOptionSuggestResponse {
  option: DFDPropertyOptionDraft;
  degraded_reason?: string | null;
}

export interface DFDResponse {
  nodes: DFDNodeResponse[];
  edges: DFDEdgeResponse[];
  trust_boundaries: TrustBoundaryResponse[];
}

export interface DFDQuickAddEdge {
  label?: string;
  properties?: EdgeProperties;
}

export interface DFDQuickAddRequest {
  origin_node_id: string;
  origin_handle: "source" | "target";
  node: DFDNodeCreate;
  edge?: DFDQuickAddEdge;
}

export interface DFDQuickAddResponse {
  node: DFDNodeResponse;
  edge: DFDEdgeResponse;
}

export interface DFDIacImportRequest {
  mode?: "merge" | "replace";
}

export interface DFDIacImportSummary {
  mode: "merge" | "replace";
  imported_resource_count: number;
  semantic_resource_count: number;
  matched_existing_nodes: number;
  created_nodes: number;
  updated_nodes: number;
  created_edges: number;
  created_boundaries: number;
  warnings: string[];
}

export interface DFDIacImportResponse {
  dfd: DFDResponse;
  summary: DFDIacImportSummary;
}

export interface DFDRepositorySeedPreview {
  suggestion_id: string;
  label: string;
  node_type: NodeType;
  rationale: string;
  source_refs: string[];
  confidence: number;
  match_status: "new" | "matched_existing";
  matched_node_id: string | null;
  matched_node_name: string | null;
  proposed_node: DFDNodeCreate;
}

export interface DFDRepositorySeedPreviewResponse {
  suggestions: DFDRepositorySeedPreview[];
  existing_node_count: number;
  unmatched_suggestion_count: number;
  inferred_flow_count: number;
  inferred_boundary_count: number;
}

export interface DFDRepositorySeedApplyRequest {
  suggestion_ids?: string[];
}

export interface DFDRepositorySeedApplySummary {
  requested_suggestion_count: number;
  matched_existing_nodes: number;
  created_nodes: number;
  created_edges: number;
  created_boundaries: number;
  skipped_suggestions: string[];
  warnings: string[];
}

export interface DFDRepositorySeedApplyResponse {
  dfd: DFDResponse;
  summary: DFDRepositorySeedApplySummary;
}

export type DFDViewType =
  | "context"
  | "container"
  | "deep_dive"
  | "data_lifecycle"
  | "decomposition"
  | "workspace";

export interface DFDViewNodeLayout {
  id: string;
  position_x: number;
  position_y: number;
}

export interface DFDViewBoundaryLayout {
  id: string;
  position_x: number;
  position_y: number;
  width?: number | null;
  height?: number | null;
}

export interface DFDViewLayoutSnapshot {
  nodes: DFDViewNodeLayout[];
  boundaries: DFDViewBoundaryLayout[];
}

export interface DFDViewResponse {
  id: string;
  view_type: DFDViewType;
  name: string;
  node_ids: string[];
  edge_ids: string[];
  boundary_ids: string[];
  layout_snapshot: DFDViewLayoutSnapshot;
  parent_view_id?: string | null;
  parent_node_id?: string | null;
  graph?: DFDResponse | null;
  is_auto_generated: boolean;
}

export interface DFDViewUpdate {
  name?: string;
  layout_snapshot?: DFDViewLayoutSnapshot;
}

export interface DFDDecompositionViewCreate {
  parent_node_id: string;
  parent_view_id?: string | null;
  name?: string;
}

export interface DFDWorkspaceViewCreate {
  name: string;
  source_view_id?: string | null;
}

export interface DFDQualityGateResult {
  gate_id: string;
  title: string;
  severity: "block" | "warn";
  message: string;
  affected_node_ids: string[];
  affected_edge_ids: string[];
  affected_boundary_ids: string[];
}

export interface DFDQualityGateSummary {
  blocking_count: number;
  warning_count: number;
  results: DFDQualityGateResult[];
}

export interface DFDBulkSave {
  nodes: DFDNodeCreate[];
  edges: DFDEdgeCreate[];
  trust_boundaries?: TrustBoundaryCreate[];
}

// Document

export interface ParsedComponent {
  name: string;
  component_type: NodeType;
  confidence: number;
  description: string;
  extraction_source?: string;
  evidence_page?: number | null;
  evidence_snippet?: string;
}

export interface ParsedFlow {
  source: string;
  target: string;
  label: string;
  confidence: number;
  data_types?: string[];
  extraction_source?: string;
  evidence_page?: number | null;
  evidence_snippet?: string;
}

export interface ParsedBoundary {
  name: string;
  contains: string[];
  extraction_source?: string;
  evidence_page?: number | null;
  evidence_snippet?: string;
}

export interface DocumentParseResult {
  components: ParsedComponent[];
  flows: ParsedFlow[];
  boundaries: ParsedBoundary[];
  raw_text_excerpt: string;
}

export interface DocumentExtractionEvidence {
  component_count: number;
  flow_count: number;
  boundary_count: number;
  diagram_pages: number[];
  diagram_artifacts: string[];
  extraction_sources: string[];
  low_confidence_areas: string[];
  raw_text_excerpt: string;
  detected_doc_type: string | null;
}

export interface DocumentUploadResponse {
  document_id: string;
  filename: string;
  page_count: number;
  parse_result: DocumentParseResult;
  extraction_status: "complete" | "partial";
  warnings: string[];
  evidence: DocumentExtractionEvidence;
}

export type RepositoryEvidenceSource =
  | "archive"
  | "manifest_bundle"
  | "single_file";
export type CloudScanProvider = "prowler" | "scoutsuite" | "unknown";
export type RepositoryConnectionProvider = "github";
export type CodeSurfaceKind =
  | "route"
  | "handler"
  | "webhook"
  | "background_worker"
  | "external_call"
  | "data_store"
  | "privileged_operation"
  | "infrastructure";
export type CodeControlType =
  | "authentication"
  | "authorization"
  | "signature_verification"
  | "audit_logging"
  | "rate_limiting"
  | "validation"
  | "idempotency"
  | "replay_protection"
  | "secret_retrieval"
  | "encryption";
export type CodeControlStrength = "strong" | "partial" | "missing";
export type CodeRiskSeverity = "Critical" | "High" | "Medium" | "Low";
export type CodeRiskType =
  | "missing_authentication"
  | "missing_validation"
  | "unsigned_outbound_call"
  | "sensitive_data_exposure"
  | "unmodeled_public_surface";
export type FindingCodeRelationship =
  | "confirms_missing_control"
  | "shows_compensating_control"
  | "needs_evidence"
  | "unmodeled_surface";

export interface CodeSurface {
  id: string;
  kind: CodeSurfaceKind;
  name: string;
  method: string | null;
  path: string | null;
  source_file: string;
  line_number: number | null;
  auth_guards: string[];
  sensitive_data_signals: string[];
  validation_signals: string[];
  outbound_call_signals: string[];
  risk_flags: string[];
  tags: string[];
}

export interface CodeControlSignal {
  id: string;
  surface_id: string;
  control_type: CodeControlType;
  strength: CodeControlStrength;
  evidence: string;
}

export interface CodeRiskSignal {
  id: string;
  surface_id: string;
  risk_type: CodeRiskType;
  severity: CodeRiskSeverity;
  evidence: string;
}

export interface FindingCodeLink {
  finding_key: string | null;
  surface_id: string;
  surface_name: string;
  source_file: string;
  line_number: number | null;
  relationship: FindingCodeRelationship;
  summary: string;
  control_signal_ids: string[];
  risk_signal_ids: string[];
}

export interface CodeEvidenceSummary {
  surface_count: number;
  route_count: number;
  control_signal_count: number;
  risk_signal_count: number;
  linked_finding_count: number;
  externally_reachable_surface_count: number;
  unprotected_sensitive_surface_count: number;
  verified_control_count: number;
  missing_control_count: number;
}

export interface RepositoryConnection {
  provider: RepositoryConnectionProvider;
  repository: string;
  transport: "https" | "ssh";
  ref: string | null;
  reference: string | null;
  connected_at: string;
  last_synced_at: string;
}

export interface GitHubPullRequestChangedFile {
  path: string;
  status: string;
  previous_path: string | null;
  additions: number | null;
  deletions: number | null;
  changes: number | null;
}

export interface GitHubPullRequestMetadata {
  provider: RepositoryConnectionProvider;
  repository: string;
  number: number;
  url: string | null;
  title: string | null;
  state: string | null;
  base_ref: string | null;
  head_ref: string | null;
  head_sha: string | null;
  changed_files: GitHubPullRequestChangedFile[];
  changed_file_count: number;
  truncated: boolean;
  fetched_at: string;
}

export interface RepositoryDfdSeedSuggestion {
  id: string;
  node_type: "process" | "data_store" | "queue" | "external_entity" | "infrastructure";
  label: string;
  rationale: string;
  source_refs: string[];
  confidence: number;
}

export interface RepositoryDfdSeedFlowSuggestion {
  id: string;
  source_seed_id: string;
  target_seed_id: string;
  label: string;
  rationale: string;
  source_refs: string[];
  confidence: number;
  directionality: "request" | "event" | "bidirectional";
  transfer_mode: "synchronous" | "asynchronous" | "batch" | "streaming" | "near_real_time";
  lifecycle_stage: "processing" | "storage" | "egress" | "notification";
}

export interface RepositoryDfdSeedBoundarySuggestion {
  id: string;
  name: string;
  boundary_type: "network" | "organizational" | "regulatory" | "privilege" | "cloud";
  seed_ids: string[];
  rationale: string;
  source_refs: string[];
  confidence: number;
}

export interface RepositoryEvidence {
  source_type: RepositoryEvidenceSource;
  filename: string;
  connection: RepositoryConnection | null;
  pull_request?: GitHubPullRequestMetadata | null;
  reference: string | null;
  file_count: number;
  languages: string[];
  frameworks: string[];
  entrypoints: string[];
  api_routes: string[];
  webhook_endpoints: string[];
  route_auth_map: RouteAuthEntry[];
  unprotected_routes: string[];
  sensitive_routes: string[];
  routes_with_raw_input: string[];
  risky_routes: string[];
  auth_surfaces: string[];
  auth_mechanisms: string[];
  data_stores: string[];
  queues: string[];
  external_integrations: string[];
  outbound_calls: string[];
  deployment_clues: string[];
  infrastructure_resources: string[];
  security_sensitive_paths: string[];
  code_surfaces: CodeSurface[];
  code_control_signals: CodeControlSignal[];
  code_risk_signals: CodeRiskSignal[];
  finding_code_links: FindingCodeLink[];
  code_evidence_summary: CodeEvidenceSummary;
  dfd_seed_suggestions?: RepositoryDfdSeedSuggestion[];
  dfd_seed_flow_suggestions?: RepositoryDfdSeedFlowSuggestion[];
  dfd_seed_boundary_suggestions?: RepositoryDfdSeedBoundarySuggestion[];
  warnings: string[];
  parsed_at: string;
}

export interface RouteAuthEntry {
  method: string;
  path: string;
  auth_guards: string[];
  sensitive_data_signals: string[];
  validation_signals: string[];
  outbound_call_signals: string[];
  risk_flags: string[];
  source_file: string;
  line_number: number | null;
}

export interface CloudFinding {
  category: string;
  severity: string;
  service: string;
  resource: string;
  detail: string;
  source_finding_id?: string | null;
}

export interface CloudScanEvidence {
  provider: CloudScanProvider;
  filename: string;
  finding_count: number;
  high_signal_findings: CloudFinding[];
  exposed_services: string[];
  identity_risks: string[];
  encryption_gaps: string[];
  logging_gaps: string[];
  warnings: string[];
  parsed_at: string;
}

export type IacEvidenceSource = "archive" | "manifest_bundle" | "single_file";

export interface IacEvidence {
  source_type: IacEvidenceSource;
  filename: string;
  reference: string | null;
  resource_count: number;
  resource_types: string[];
  resource_names: string[];
  public_exposure: string[];
  iam_bindings: string[];
  network_paths: string[];
  secret_refs: string[];
  warnings: string[];
  parsed_at: string;
}

export interface EnvironmentEvidenceResponse {
  repository_evidence: RepositoryEvidence | null;
  cloud_scan_evidence: CloudScanEvidence | null;
  iac_evidence: IacEvidence | null;
  environment_context_summary: string | null;
}

export interface GitHubRepositoryImportRequest {
  repository: string;
  transport?: "https" | "ssh";
  ref?: string | null;
  reference?: string | null;
  pull_request_number?: number | null;
  pull_request_url?: string | null;
  ssh_private_key?: string | null;
}

export interface GitHubRepositoryRefreshRequest {
  ssh_private_key?: string | null;
}

// Threats

export interface ComplianceControlRef {
  control_id: string;
  control_name: string;
  framework: string;
}

export type QualificationLabel =
  | "Priority"
  | "Investigate"
  | "Review"
  | "Low Signal";

export interface ThreatResponse {
  id: string;
  display_id: string;
  description: string;
  stride_category: string;
  threat_subtype?: string | null;
  severity: string;
  source: string;
  status: string;
  dismiss_reason: string | null;
  rule_id: string | null;
  ai_enhanced: boolean;
  provider_managed: boolean;
  original_rule_threat_id: string | null;
  affected_node_ids: string[];
  affected_edge_ids: string[];
  relevance_rationale: string | null;
  mitigation_plan: string | null;
  mitigation_owner: string | null;
  due_date: string | null;
  mitigation_notes: string | null;
  control_effectiveness: "none" | "partial" | "substantial" | "full";
  residual_risk_level:
    | "Critical"
    | "High"
    | "Medium"
    | "Low"
    | "Negligible"
    | null;
  closed_at: string | null;
  compliance_controls: ComplianceControlRef[];
  qualification_score: number | null;
  qualification_label: QualificationLabel | null;
  qualification_note: string | null;
  // Qualification workflow v2
  auto_score: number | null;
  analyst_score: number | null;
  analyst_score_rationale: string | null;
  ai_likelihood_score: number | null;
  ai_likelihood_assessment: string | null;
  ai_likelihood_generated_at: string | null;
  cluster_id: string | null;
  false_positive_reason: string | null;
  qualification_completed_at: string | null;
  created_at: string;
  scan_status?: ThreatScanStatus;
}

export type AgentType = "threat_validation" | "code_fix" | "iac_fix" | "configuration_fix";
export type FixAgentType = "code_fix" | "iac_fix" | "configuration_fix";
export type ThreatValidationConclusion =
  | "confirmed"
  | "not_supported"
  | "needs_human_review"
  | "more_evidence_required"
  | "failed";

export interface AgentRunMetadata {
  agent_type: AgentType;
  agent_version: string;
  input_schema_version: string;
  output_schema_version: string;
  policy_version: string;
  tool_harness_versions: Record<string, string>;
  model_provider: string | null;
  model_name: string | null;
  prompt_version: string | null;
  model_output_hash: string | null;
  deterministic_fallback_used: boolean;
}

export interface AgentTraceEvent {
  id: string;
  job_id: string;
  task_id?: string | null;
  threat_model_id: string;
  event_type: string;
  level: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AgentTraceResponse {
  events: AgentTraceEvent[];
}

export interface ThreatValidationRunCreate {
  application_review_id?: string | null;
  requested_tools?: string[];
  domain_agents?: DomainValidationAgentType[];
  domain_agent_tools?: Partial<Record<DomainValidationAgentType, string[]>>;
  domain_agent_tool_mode?: Partial<Record<DomainValidationAgentType, DomainAgentToolMode>>;
  domain_agent_instructions?: Partial<Record<DomainValidationAgentType, string>>;
  domain_agent_targets?: Partial<Record<string, DomainAgentTargetRequest>>;
  excluded_tools?: Partial<Record<DomainValidationAgentType, string[]>>;
  required_tools?: Partial<Record<DomainValidationAgentType, string[]>>;
  question?: string | null;
}

export type ThreatScanPlanCreate = ThreatValidationRunCreate;

export interface ThreatScanPlanApproveRequest {
  domain_agents?: DomainValidationAgentType[] | null;
  domain_agent_tools?: Partial<Record<DomainValidationAgentType, string[]>> | null;
  domain_agent_tool_mode?: Partial<Record<DomainValidationAgentType, DomainAgentToolMode>> | null;
  domain_agent_instructions?: Partial<Record<DomainValidationAgentType, string>> | null;
  domain_agent_targets?: Partial<Record<string, DomainAgentTargetRequest>>;
  excluded_tools?: Partial<Record<DomainValidationAgentType, string[]>> | null;
  required_tools?: Partial<Record<DomainValidationAgentType, string[]>> | null;
  approval_note?: string | null;
}

export interface ThreatScanPlanRejectRequest {
  reason: string;
}

export interface DomainAgentTargetRequest {
  tool_name?: string | null;
  target_type: ValidationTargetType;
  target: string;
  target_node_id?: string | null;
  scope?: "external" | "internal" | "full";
  authorization_acknowledged: boolean;
}

export type DomainValidationAgentType =
  | "sast"
  | "dast"
  | "llm_security"
  | "iac"
  | "dependency"
  | "secrets"
  | "configuration";

export type DomainAgentToolMode = "recommended" | "all" | "manual";

export interface AgentToolCapability {
  domain_agent: DomainValidationAgentType;
  tool: string;
  label: string;
  supported_target_types: ValidationTargetType[];
  best_for: string[];
  runtime_risk: "low" | "medium" | "high";
  requires_network: boolean;
  requires_credentials: boolean;
  requires_human_approval: boolean;
  available: boolean;
  enabled: boolean;
  readiness_status: string;
  setup_actions: string[];
  recommendation_notes?: string | null;
}

export interface DomainAgentPlanItem {
  domain_agent: DomainValidationAgentType;
  label: string;
  tools: string[];
  instructions?: string | null;
}

export interface DomainAgentToolExecutionResult {
  tool: string;
  status: "planned" | "authorized" | "evidence_attached" | "completed" | "skipped" | "failed";
  evidence_refs: Record<string, unknown>[];
  task_id?: string | null;
  scan_job_id?: string | null;
  skipped_reason?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface DomainAgentExecutionResult {
  domain_agent: DomainValidationAgentType;
  label: string;
  status: "planned" | "running" | "evidence_attached" | "completed" | "skipped" | "failed";
  tools: DomainAgentToolExecutionResult[];
  evidence_refs: Record<string, unknown>[];
  skipped_reason?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export type ExploitabilityStatus =
  | "exploitable"
  | "not_exploitable"
  | "theoretical"
  | "blocked_by_control"
  | "needs_more_evidence"
  | "conflicting_evidence";

export interface ExploitabilityAssessment {
  status: ExploitabilityStatus;
  attacker_profile?: string | null;
  attack_path: string[];
  preconditions: string[];
  blocking_controls: string[];
  evidence_refs: string[];
  confidence: "low" | "medium" | "high";
  rationale?: string | null;
}

export interface ThreatValidationRun {
  id: string;
  tenant_key: string;
  owner_id: string;
  organization_id?: string | null;
  threat_model_id: string;
  threat_id: string;
  application_review_id?: string | null;
  orchestration_job_id?: string | null;
  status: "created" | "running" | "completed" | "failed" | "blocked";
  conclusion?: ThreatValidationConclusion | null;
  question: string;
  requested_tools: string[];
  domain_agent_plan: DomainAgentPlanItem[];
  domain_agent_results: DomainAgentExecutionResult[];
  evidence_refs: Record<string, unknown>[];
  exploitability: ExploitabilityAssessment;
  summary?: string | null;
  failure_reason?: string | null;
  metadata: AgentRunMetadata;
  trace: AgentTraceResponse;
  created_at: string;
  updated_at: string;
}

export interface ThreatRemediationRunCreate {
  agent_type: FixAgentType;
}

export interface ThreatRemediationHandoffConfirmRequest {
  confirmed: boolean;
  provider?: "github_pull_request" | "github_issue" | "linear" | "jira" | "manual";
  github_repository?: string | null;
  access_token?: string | null;
  handoff_idempotency_key?: string | null;
  external_ticket_id?: string | null;
  external_ticket_url?: string | null;
  external_pr_url?: string | null;
  confirmed_by?: string | null;
}

export interface ThreatRemediationEvidenceRequest {
  provider?: "github_pull_request" | "github_issue" | "linear" | "jira" | "manual";
  evidence_summary: string;
  external_ticket_id?: string | null;
  external_ticket_url?: string | null;
  external_pr_url?: string | null;
  commit_sha?: string | null;
  evidence_url?: string | null;
}

export interface ThreatRemediationRun {
  id: string;
  tenant_key: string;
  owner_id: string;
  organization_id?: string | null;
  validation_run_id: string;
  threat_model_id: string;
  threat_id: string;
  application_review_id?: string | null;
  orchestration_job_id?: string | null;
  agent_type: FixAgentType;
  status: "drafting" | "awaiting_confirmation" | "handoff_created" | "failed" | "cancelled";
  fix_summary?: string | null;
  patch_preview?: string | null;
  ticket_draft: Record<string, unknown>;
  pr_draft: Record<string, unknown>;
  external_ticket_id?: string | null;
  external_ticket_url?: string | null;
  external_pr_url?: string | null;
  handoff_delivery_status: "recorded" | "delivered" | "failed";
  handoff_provider?: "github_pull_request" | "github_issue" | "linear" | "jira" | "manual" | null;
  handoff_error?: string | null;
  handoff_idempotency_key?: string | null;
  evidence_refs: Record<string, unknown>[];
  failure_reason?: string | null;
  metadata: AgentRunMetadata;
  trace: AgentTraceResponse;
  created_at: string;
  updated_at: string;
}

export type QualifyAction = "confirm" | "dismiss" | "defer";

export type FalsePositiveReason =
  | "compensating_control"
  | "not_applicable"
  | "duplicate"
  | "architecture_mismatch"
  | "accepted_risk"
  | "other";

export interface ThreatQualifyRequest {
  analyst_score: number;
  action: QualifyAction;
  analyst_score_rationale?: string | null;
  false_positive_reason?: FalsePositiveReason | null;
  qualification_note?: string | null;
}

export interface ThreatClusterResponse {
  id: string;
  threat_model_id: string;
  cluster_label: string;
  cluster_reason: string;
  representative_threat_id: string | null;
  threat_count: number;
  created_at: string;
}

export interface QualificationProgressResponse {
  threat_model_id: string;
  total_open: number;
  qualified: number;
  unqualified: number;
  progress_pct: number;
  cluster_count: number;
  clusters_resolved: number;
}

export interface ThreatIntelTechniqueRef {
  technique_id: string;
  name: string;
  tactic: string;
  description: string | null;
  url: string | null;
  match_type: "exact" | "semantic";
}

export interface ThreatIntelPatternRef {
  capec_id: string;
  name: string;
  description: string | null;
  severity: string | null;
  likelihood: string | null;
  related_cwe_ids: string[];
  related_attack_ids: string[];
  match_type: "exact" | "semantic";
}

export interface ThreatIntelWeaknessRef {
  cwe_id: string;
  name: string;
  description: string | null;
  consequences: string | null;
  is_top_25: boolean;
  match_type: "exact" | "semantic";
}

export interface ThreatIntelAdvisoryRef {
  advisory_id: string;
  title: string;
  summary: string | null;
  severity: string | null;
  url: string | null;
  published_date: string | null;
  referenced_cves: string[];
  referenced_attack_ids: string[];
  match_type: "exact" | "semantic";
}

export interface ThreatIntelKevRef {
  cve_id: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  known_ransomware_use: string | null;
  date_added: string | null;
  match_type: "scan_cve" | "threat_text" | "technology_keyword";
}

export interface ThreatIntelEpssRef {
  cve_id: string;
  score: number;
  percentile: number;
  date: string | null;
  match_type: "scan_cve" | "threat_text" | "dependency_match";
}

export interface ThreatIntelDependencyRef {
  dependency_name: string;
  dependency_ecosystem: string;
  dependency_version: string;
  vulnerability_id: string;
  severity: string | null;
  cve_ids: string[];
  kev_listed: boolean;
  epss_score: number | null;
  epss_percentile: number | null;
  fixed_versions: string[];
  scorecard_score: number | null;
  source_projects: string[];
  match_type: "scan_cve" | "threat_text" | "repository_context";
}

export interface ThreatIntelCriControlRef {
  cri_control_id: string;
  cri_control_name: string;
  cri_function: string;
  mapping_type: string;
  attack_technique_id: string;
}

export interface ThreatIntelSeveritySignal {
  source: string;
  label: string;
  reference_id: string;
  value: string;
  normalized_severity: string | null;
  note: string | null;
}

export interface ThreatIntelContextualAssessment {
  threat_classes: Array<
    | "design_risk"
    | "implementation_config_risk"
    | "dependency_vulnerability"
    | "active_exploitation_risk"
    | "detection_gap"
    | "control_gap"
  >;
  confidence: "Low" | "Medium" | "High";
  ssvc_decision: "Track" | "Track*" | "Attend" | "Act";
  why_applicable: string[];
  what_to_verify: string[];
  decision_rationale: string[];
}

export interface ThreatIntelResponse {
  local_severity: string;
  highest_external_severity: string | null;
  semantic_matches_inferred: boolean;
  unavailable_reason: string | null;
  scan_cve_ids: string[];
  severity_signals: ThreatIntelSeveritySignal[];
  epss_entries: ThreatIntelEpssRef[];
  attack_techniques: ThreatIntelTechniqueRef[];
  attack_patterns: ThreatIntelPatternRef[];
  weaknesses: ThreatIntelWeaknessRef[];
  advisories: ThreatIntelAdvisoryRef[];
  kev_entries: ThreatIntelKevRef[];
  dependency_matches: ThreatIntelDependencyRef[];
  cri_controls: ThreatIntelCriControlRef[];
  contextual_assessment: ThreatIntelContextualAssessment;
}

export type SecurityReviewFindingSource =
  | "dfd"
  | "document"
  | "scan"
  | "cloud"
  | "iac"
  | "repository"
  | "compliance"
  | "threat_intel"
  | "sdlc"
  | "manual";

export type SecurityReviewEvidenceAdjustmentField =
  | "truth_status"
  | "exploitability"
  | "business_impact"
  | "regulatory_pressure"
  | "action_bucket"
  | "priority"
  | "noise_disposition";

export interface SecurityReviewEvidenceAdjustment {
  evidence_type: SecurityReviewFindingSource;
  evidence_value: string;
  field_affected: SecurityReviewEvidenceAdjustmentField;
  original_value: string;
  adjusted_value: string;
  justification: string;
}

export interface SecurityReviewAttackPath {
  path_id: string;
  finding_keys: string[];
  finding_titles: string[];
  chain_description: string;
  entry_point: string | null;
  target_asset: string | null;
  hop_count: number;
  support_count?: number;
  composite_exploitability: "proven" | "high" | "medium" | "low";
  composite_priority:
    | "p0_blocker"
    | "p1_now"
    | "p2_sprint"
    | "p3_backlog"
    | "p4_monitor";
  path_nodes?: string[];
  evidence_sources?: SecurityReviewFindingSource[];
  relationship_reasons?: string[];
  verification_steps?: string[];
}

export interface SecurityReviewRiskAcceptance {
  finding_title: string;
  status: "active" | "expired" | "reopened";
  accepted_by: string | null;
  accepted_at: string | null;
  expires_at: string | null;
  acceptance_rationale: string | null;
  compensating_control: string | null;
  reopen_triggers: string[];
}

export interface SecurityReviewRiskAcceptanceRequest {
  accepted_by?: string | null;
  expires_at?: string | null;
  acceptance_rationale: string;
  compensating_control?: string | null;
}

export interface SecurityReviewDelta {
  disposition:
    | "new"
    | "resolved"
    | "reopened"
    | "escalated"
    | "deescalated"
    | "unchanged";
  days_since_last_review: number | null;
  new_findings_count: number;
  resolved_count: number;
  reopened_count: number;
  escalated_count: number;
}

export interface SecurityReviewScoreBreakdown {
  reality: number;
  exploitability: number;
  business_impact: number;
  regulatory_pressure: number;
  noise_penalty: number;
  total: number;
}

export interface SecurityReviewDecision {
  priority: "p0_blocker" | "p1_now" | "p2_sprint" | "p3_backlog" | "p4_monitor";
  action_bucket:
    | "bright_red_line"
    | "engineer_now"
    | "verify_control"
    | "fill_evidence_gap"
    | "planned_hardening"
    | "monitor";
  truth_status:
    | "validated"
    | "strongly_indicated"
    | "contextual"
    | "theoretical";
  urgency: "immediate" | "current_cycle" | "planned" | "defer";
  exploitability: "proven" | "high" | "medium" | "low";
  business_impact: "severe" | "high" | "moderate" | "low";
  regulatory_pressure: "red_line" | "high" | "moderate" | "low";
  noise_disposition: "focus" | "queue" | "background" | "suppress";
  numeric_score: number;
  score_breakdown: SecurityReviewScoreBreakdown;
  evidence_adjustments: SecurityReviewEvidenceAdjustment[];
  related_attack_paths: SecurityReviewAttackPath[];
  risk_acceptance: SecurityReviewRiskAcceptance | null;
  review_delta: SecurityReviewDelta | null;
  rationale: string[];
  next_steps: string[];
}

export interface SecurityReviewBucketCount {
  key: string;
  label: string;
  count: number;
}

export interface SecurityReviewFindingSummary {
  finding_key: string | null;
  threat_id: string | null;
  display_id: string | null;
  finding_kind:
    | "threat"
    | "vulnerability"
    | "drift"
    | "compliance_gap"
    | "control_gap"
    | "evidence_gap"
    | "hardening";
  title: string;
  priority: "p0_blocker" | "p1_now" | "p2_sprint" | "p3_backlog" | "p4_monitor";
  action_bucket:
    | "bright_red_line"
    | "engineer_now"
    | "verify_control"
    | "fill_evidence_gap"
    | "planned_hardening"
    | "monitor";
  truth_status:
    | "validated"
    | "strongly_indicated"
    | "contextual"
    | "theoretical";
  urgency: "immediate" | "current_cycle" | "planned" | "defer";
  noise_disposition: "focus" | "queue" | "background" | "suppress";
  numeric_score: number;
  entry_point: string | null;
  target_asset: string | null;
  rationale_excerpt: string | null;
  next_step: string | null;
  related_attack_path_count: number;
  evidence_adjustment_count: number;
  systemic: boolean;
}

export interface SecurityReviewCoverageSummary {
  total_findings: number;
  threat_findings: number;
  systemic_findings: number;
  open_threats: number;
  public_entry_points: number;
  privileged_surfaces: number;
  restricted_assets: number;
  attack_paths: number;
  attached_evidence_sources: number;
  missing_evidence_sources: number;
}

export interface SecurityReviewRiskAcceptanceSummary {
  active: number;
  reopened: number;
  expired: number;
}

export interface SecurityReviewDeltaSummary {
  new_findings: number;
  resolved_findings: number;
  reopened_findings: number;
  escalated_findings: number;
  deescalated_findings: number;
}

export interface SecurityReviewApplicationSummary {
  generated_at: string;
  system_name: string;
  overall_priority:
    | "p0_blocker"
    | "p1_now"
    | "p2_sprint"
    | "p3_backlog"
    | "p4_monitor";
  overall_action_bucket:
    | "bright_red_line"
    | "engineer_now"
    | "verify_control"
    | "fill_evidence_gap"
    | "planned_hardening"
    | "monitor";
  focus_statement: string;
  rationale: string[];
  next_steps: string[];
  coverage: SecurityReviewCoverageSummary;
  priority_counts: SecurityReviewBucketCount[];
  action_bucket_counts: SecurityReviewBucketCount[];
  truth_status_counts: SecurityReviewBucketCount[];
  noise_counts: SecurityReviewBucketCount[];
  top_findings: SecurityReviewFindingSummary[];
  blind_spots: SecurityReviewFindingSummary[];
  attack_paths: SecurityReviewAttackPath[];
  risk_acceptance_summary: SecurityReviewRiskAcceptanceSummary;
  review_delta_summary: SecurityReviewDeltaSummary;
}

export type ReviewQueueBucket =
  | "fix_now"
  | "verify"
  | "gather_evidence"
  | "backlog";
export type ReviewStatus =
  | "open"
  | "in_progress"
  | "mitigated"
  | "accepted"
  | "dismissed";
export type ReviewArtifactKind =
  | "remediation_note"
  | "verification_note"
  | "evidence_request";
export type ReviewDisplayKind =
  | "threat"
  | "hardening"
  | "misconfiguration"
  | "compliance_gap"
  | "control_gap"
  | "evidence_gap"
  | "pr_risk"
  | "incident_signal";
export type ReviewSourceProvenance =
  | "rules_engine"
  | "framework_seed"
  | "app_review_projection"
  | "manual"
  | "external_import";
export type ReviewSourceObjectType =
  | "threat"
  | "application_review_finding"
  | "manual";
export type ReviewConfidence = "high" | "medium" | "low";
export type ReviewPrimaryMode =
  | "review"
  | "findings"
  | "compliance"
  | "model_health";

export interface SecurityReviewFinding {
  id: string;
  source_object_type: ReviewSourceObjectType;
  source_object_id: string;
  threat_id: string | null;
  display_id: string | null;
  wire_kind:
    | "threat"
    | "vulnerability"
    | "drift"
    | "compliance_gap"
    | "control_gap"
    | "evidence_gap"
    | "hardening"
    | "pr_risk"
    | "incident_signal";
  display_kind: ReviewDisplayKind;
  source_provenance: ReviewSourceProvenance;
  source_system: "threatgenix" | "external";
  title: string;
  priority: "p0_blocker" | "p1_now" | "p2_sprint" | "p3_backlog" | "p4_monitor";
  wire_action_bucket:
    | "bright_red_line"
    | "engineer_now"
    | "verify_control"
    | "fill_evidence_gap"
    | "planned_hardening"
    | "monitor"
    | null;
  queue_bucket: ReviewQueueBucket | null;
  computed_queue_bucket: ReviewQueueBucket | null;
  truth_status:
    | "validated"
    | "strongly_indicated"
    | "contextual"
    | "theoretical"
    | null;
  numeric_score: number;
  exploitability: "proven" | "high" | "medium" | "low" | null;
  urgency: "immediate" | "current_cycle" | "planned" | "defer" | null;
  business_impact: "severe" | "high" | "moderate" | "low" | null;
  regulatory_pressure: "red_line" | "high" | "moderate" | "low" | null;
  confidence: ReviewConfidence;
  is_real: boolean;
  is_urgent: boolean;
  is_exploitable_in_context: boolean;
  is_regulatory_or_control_relevant: boolean;
  needs_engineering_change: boolean;
  needs_evidence: boolean;
  why_now: string;
  impacted_assets: string[];
  entry_point: string | null;
  evidence_refs: string[];
  linked_threat_ids: string[];
  linked_change_ids: string[];
  linked_control_ids: string[];
  code_links: FindingCodeLink[];
  evidence_anchors?: AgentEvidenceRef[];
  owner: string | null;
  due_at: string | null;
  note: string | null;
  artifacts: SecurityReviewArtifact[];
  risk_acceptance?: SecurityReviewRiskAcceptance | null;
  review_status: ReviewStatus;
  last_non_terminal_bucket: ReviewQueueBucket | null;
  primary_mode: ReviewPrimaryMode;
  noise_disposition: "focus" | "queue" | "background" | "suppress";
  computed_recommendation_changed: boolean;
  systemic: boolean;
  next_best_action: string | null;
  next_step: string | null;
  rationale_excerpt: string | null;
}

export interface SecurityReviewFindingListResponse {
  generated_at: string;
  system_name: string;
  queue_counts: SecurityReviewBucketCount[];
  review_status_counts: SecurityReviewBucketCount[];
  default_finding_id: string | null;
  findings: SecurityReviewFinding[];
}

export type AgentReleaseDecision =
  | "ship"
  | "block"
  | "fix_now"
  | "verify"
  | "gather_evidence"
  | "accept_risk";

export type AgentCiFailPolicy =
  | "block_only"
  | "block_or_fix_now"
  | "block_fix_now_or_verify"
  | "never";

export type AgentEvidenceType =
  | "code"
  | "dfd"
  | "document"
  | "scan"
  | "cloud"
  | "iac"
  | "control"
  | "threat_intel"
  | "manual"
  | "repository"
  | "unknown";

export interface AgentEvidenceRef {
  type: AgentEvidenceType;
  reference: string;
  claim: string;
  validated: boolean;
  source_object_type?: string | null;
  source_object_id?: string | null;
  location?: string | null;
  relationship?: string | null;
  strength?: "strong" | "partial" | "weak" | "missing" | null;
}

export interface AgentFindingVerification {
  required: boolean;
  suggested_test: string | null;
  evidence_needed: string[];
}

export interface AgentCiContract {
  fail_policy: AgentCiFailPolicy;
  blocking_decisions: AgentReleaseDecision[];
  should_fail: boolean;
  exit_code: number;
  reason: string;
}

export interface AgentSecurityReviewFinding {
  decision: AgentReleaseDecision;
  finding_id: string;
  source_object_type: ReviewSourceObjectType;
  source_object_id: string;
  title: string;
  priority: SecurityReviewFinding["priority"];
  confidence: ReviewConfidence;
  risk_path: string[];
  evidence: AgentEvidenceRef[];
  fix_instructions: string[];
  verification: AgentFindingVerification;
}

export interface AgentSecurityReviewResponse {
  generated_at: string;
  system_name: string;
  decision: AgentReleaseDecision;
  decision_reason: string;
  pass_semantics: string;
  ci?: AgentCiContract;
  findings: AgentSecurityReviewFinding[];
  evidence_gaps: string[];
}

export interface AgentRemediationWebhookSetup {
  provider: "github" | "linear" | "jira";
  provider_label: string;
  callback_url: string;
  action_marker: string;
  action_marker_hint: string;
  event_filters: string[];
  registration_steps: string[];
  required_headers: Record<string, string>;
  signature_scheme: "hmac_sha256_v1";
  signature_base_string: string;
  signing_secret_hint: string;
}

export interface AgentRemediationTicketDraft {
  provider: "github_issue" | "linear" | "jira";
  title: string;
  body: string;
  labels: string[];
  priority: SecurityReviewFinding["priority"];
  confirmation_required: boolean;
  external_creation_status: "draft_only" | "created";
  connector_creation_status?: "available_with_confirmation" | "created";
  connector_confirmation_hint?: string;
  callback_security_status?: "signed_hmac_required";
  callback_security_hint?: string;
  callback_setup?: AgentRemediationWebhookSetup | null;
  callback_setups?: AgentRemediationWebhookSetup[];
  external_ticket_id: string | null;
  external_ticket_url: string | null;
}

export interface AgentRemediationTransition {
  status:
    | "needs_action"
    | "ready_for_rerun"
    | "ready_for_verify"
    | "ready_for_clearance"
    | "evidence_still_missing";
  current_decision: AgentReleaseDecision;
  expected_next_decision: AgentReleaseDecision;
  rationale: string;
  artifact_count: number;
  latest_artifact_at: string | null;
  evidence_count: number;
}

export interface AgentRemediationHistoryEntry {
  action_id: string;
  finding_id: string;
  artifact_kind: ReviewArtifactKind;
  artifact_title: string;
  created_at: string;
  transition_status: string;
}

export interface AgentRemediationAction {
  action_id: string;
  finding_id: string;
  source_object_type: SecurityReviewFinding["source_object_type"];
  source_object_id: string;
  title: string;
  current_decision: AgentReleaseDecision;
  action_kind: "patch_guidance" | "verification" | "evidence_request";
  artifact_kind: ReviewArtifactKind;
  priority: string;
  instruction: string;
  verification_required: boolean;
  evidence_needed: string[];
  expected_next_decision: AgentReleaseDecision;
  rerun_required: boolean;
  ticket_draft: AgentRemediationTicketDraft;
  transition: AgentRemediationTransition;
}

export interface AgentRemediationPlanResponse {
  generated_at: string;
  system_name: string;
  current_decision: AgentReleaseDecision;
  loop_status: "ready" | "no_action_required";
  summary: string;
  actions: AgentRemediationAction[];
  action_history: AgentRemediationHistoryEntry[];
  rerun_instructions: string[];
  plan_markdown: string;
}

export interface AgentRemediationPlanApplyResponse {
  generated_at: string;
  system_name: string;
  created_artifact_count: number;
  updated_finding_ids: string[];
  plan: AgentRemediationPlanResponse;
}

export interface AgentRemediationTicketCreateRequest {
  action_id: string;
  provider?: "github_issue" | "linear" | "jira";
  confirmed: boolean;
  external_ticket_id?: string | null;
  external_ticket_url?: string | null;
  created_by?: string | null;
}

export interface AgentRemediationTicketCreateResponse {
  generated_at: string;
  system_name: string;
  created_ticket_count: number;
  updated_finding_ids: string[];
  plan: AgentRemediationPlanResponse;
}

export interface AgentRemediationConnectorTicketCreateRequest {
  action_id: string;
  provider?: "github_issue" | "linear" | "jira";
  confirmed: boolean;
  access_token: string;
  github_repository?: string | null;
  linear_team_id?: string | null;
  jira_base_url?: string | null;
  jira_project_key?: string | null;
  jira_issue_type?: string | null;
  created_by?: string | null;
}

export interface AgentRemediationConnectorTicketCreateResponse {
  generated_at: string;
  system_name: string;
  provider: "github_issue" | "linear" | "jira";
  created_ticket_count: number;
  updated_finding_ids: string[];
  external_ticket_id: string;
  external_ticket_url: string | null;
  callback_url: string;
  callback_payload_template: Record<string, string | null>;
  callback_security_scheme: "hmac_sha256_v1";
  callback_required_headers: Record<string, string>;
  callback_signature_base_string: string;
  plan: AgentRemediationPlanResponse;
}

export interface AgentRemediationEvidenceWebhookRequest {
  action_id?: string | null;
  source_object_type?: SecurityReviewFinding["source_object_type"] | null;
  source_object_id?: string | null;
  provider?: "github_pr" | "github_issue" | "linear" | "jira" | "manual";
  external_ticket_id?: string | null;
  pull_request_url?: string | null;
  commit_sha?: string | null;
  evidence_url?: string | null;
  evidence_summary: string;
  received_at?: string | null;
}

export interface AgentRemediationEvidenceWebhookResponse {
  generated_at: string;
  system_name: string;
  ingested_artifact_count: number;
  updated_finding_ids: string[];
  callback_security_status: "verified";
  normalized_provider_event:
    | "pull_request_evidence"
    | "issue_evidence"
    | "ticket_evidence"
    | "manual_evidence";
  plan: AgentRemediationPlanResponse;
}

export interface AgentRemediationProviderWebhookTestRequest {
  provider: "github" | "linear" | "jira";
  payload_text: string;
  headers: Record<string, string>;
}

export interface AgentRemediationProviderWebhookTestResponse {
  generated_at: string;
  system_name: string;
  provider: "github" | "linear" | "jira";
  callback_security_status: "verified";
  nonce_status: "accepted";
  normalized_provider_event:
    | "pull_request_evidence"
    | "issue_evidence"
    | "ticket_evidence"
    | "manual_evidence";
  action_id: string;
  finding_id: string;
  action_title: string;
  source_object_type: SecurityReviewFinding["source_object_type"];
  source_object_id: string;
  external_ticket_id: string | null;
  pull_request_url: string | null;
  commit_sha: string | null;
  evidence_url: string | null;
  evidence_summary: string;
  next_step: string;
  plan: AgentRemediationPlanResponse;
}

export interface CustomerSecurityPacketFinding {
  title: string;
  release_decision: AgentReleaseDecision;
  customer_status:
    | "validated_risk"
    | "accepted_risk"
    | "needs_verification"
    | "evidence_gap";
  summary: string;
  evidence_summary: string;
  next_step: string | null;
}

export interface CustomerSecurityPacketSourceFingerprint {
  source_type:
    | "review_summary"
    | "review_findings"
    | "agent_decision"
    | "repository"
    | "pull_request"
    | "scan"
    | "cloud_scan"
    | "iac";
  source_id: string;
  label: string;
  fingerprint: string;
  collected_at: string | null;
}

export interface CustomerSecurityPacketResponse {
  generated_at: string;
  system_name: string;
  audience: "customer_security_review";
  packet_version: "customer_packet_v1";
  packet_hash: string;
  redaction_profile: "customer_safe_v1";
  release_decision: AgentReleaseDecision;
  decision_summary: string;
  scope: string[];
  proven: string[];
  assumptions: string[];
  unknowns: string[];
  validated_risks: CustomerSecurityPacketFinding[];
  accepted_risks: CustomerSecurityPacketFinding[];
  evidence_gaps: CustomerSecurityPacketFinding[];
  source_fingerprints: CustomerSecurityPacketSourceFingerprint[];
  redaction_notes: string[];
  customer_safe_markdown: string;
}

export interface SecurityReviewArtifact {
  id: string;
  kind: ReviewArtifactKind;
  title: string;
  summary: string;
  body: string;
  created_at: string;
}

export interface SecurityReviewStateUpdate {
  queue_bucket?: ReviewQueueBucket | null;
  review_status?: ReviewStatus | null;
  owner?: string | null;
  due_at?: string | null;
  note?: string | null;
  risk_acceptance?: SecurityReviewRiskAcceptance | null;
}

export interface SecurityReviewArtifactCreate {
  kind: ReviewArtifactKind;
}

export interface AnalyzeResponse {
  threats: ThreatResponse[];
  ai_skipped_reason: string | null;
}

export interface ThreatTriageRequest {
  status: "Open" | "In Progress" | "Mitigated" | "Accepted" | "Dismissed";
  severity?: "Critical" | "High" | "Medium" | "Low" | null;
  dismiss_reason?: string | null;
  mitigation_plan?: string | null;
  mitigation_owner?: string | null;
  due_date?: string | null;
  mitigation_notes?: string | null;
  control_effectiveness?: "none" | "partial" | "substantial" | "full" | null;
  residual_risk_level?:
    | "Critical"
    | "High"
    | "Medium"
    | "Low"
    | "Negligible"
    | null;
  risk_acceptance?: SecurityReviewRiskAcceptanceRequest | null;
}

export interface ResidualRiskSummary {
  total: number;
  by_level: Record<
    "Critical" | "High" | "Medium" | "Low" | "Negligible",
    number
  >;
}

export interface BulkTriageRequest {
  threat_ids: string[];
  status: "Accepted" | "Dismissed";
  dismiss_reason?: string | null;
}

export interface ThreatSummary {
  total: number;
  by_stride: Record<string, number>;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
}

// Dashboard

export interface PortfolioSummary {
  total_models: number;
  total_threats: number;
  threats_by_severity: Record<string, number>;
  threats_by_status: Record<string, number>;
  threats_by_stride: Record<string, number>;
  residual_risk_by_level: Record<string, number>;
  models_by_classification: Record<string, number>;
  controls_by_status: Record<string, number>;
  open_reviews: number;
  models_pending_review: number;
  models_with_drift: number;
  shared_models: number;
  open_assignments: number;
  overdue_assignments: number;
  unread_notifications: number;
  recent_models: ThreatModelListItem[];
}

// Audit History

export interface ThreatAuditEntry {
  id: string;
  action: string;
  old_status: string | null;
  new_status: string;
  reason: string | null;
  changed_by: string;
  changed_at: string;
}

// Threat Diff (Static Suggestion Preview)

export interface ThreatDiffSummary {
  rule_id: string;
  stride_category: string;
  severity: string;
  description: string;
}

export interface ThreatDiffResponse {
  added: ThreatDiffSummary[];
  removed: ThreatDiffSummary[];
  counts: {
    added: number;
    removed: number;
    total_before: number;
    total_after: number;
  };
  has_baseline: boolean;
}

// Threat Catalog

export interface ThreatCatalogEntry {
  rule_id: string;
  stride_category: string;
  threat_subtype: string;
  severity: string;
  description_template: string;
  condition_type: string;
}

export interface ManualThreatCreate {
  rule_id?: string | null;
  threat_subtype?: string;
  description?: string;
  severity?: string;
  stride_category?: string;
  affected_node_ids?: string[];
}

// Report

export interface ReportRequest {
  threat_model_id: string;
  dfd_image_base64?: string;
}

// Assistant

export type AssistantMode = "ask" | "explain" | "review" | "build";
export type AssistantAnchorKind = "node" | "edge" | "boundary" | "threat";
export type AssistantFindingSeverity = "high" | "medium" | "low" | "info";
export type AssistantProposalType =
  | "create_connected_node"
  | "create_node"
  | "create_edge"
  | "create_boundary"
  | "update_node"
  | "create_assumption";
export type AssistantGuidedStepStatus = "done" | "current" | "up_next";

export interface AssistantAnchor {
  kind: AssistantAnchorKind;
  id: string;
}

export interface AssistantRequest {
  message: string;
  mode_hint?: AssistantMode | null;
  anchor?: AssistantAnchor | null;
  review_finding_id?: string | null;
}

export interface AssistantReference {
  kind: AssistantAnchorKind;
  id: string;
  label: string;
}

export interface AssistantReviewFinding {
  severity: AssistantFindingSeverity;
  title: string;
  description: string;
  references: AssistantReference[];
}

export interface ApplicationReview {
  id: string;
  tenant_key: string;
  owner_id: string;
  organization_id: string | null;
  threat_model_id: string | null;
  parent_review_id: string | null;
  review_lineage_id: string;
  app_name: string;
  invocation_surface: "cli" | "mcp" | "api" | "pr" | "web";
  input_kind: "diff" | "snapshot" | "metadata";
  status:
    | "created"
    | "intake_required"
    | "bundle_required"
    | "bundle_received"
    | "scanning"
    | "extracting_context"
    | "indexing"
    | "building_graph"
    | "deciding"
    | "explaining"
    | "completed"
    | "blocked_by_policy"
    | "blocked_by_permission"
    | "failed_retryable"
    | "failed_terminal"
    | "cancelled";
  decision: "pass" | "block" | "fix" | "verify" | "gather_evidence" | null;
  commit_sha: string | null;
  bundle_hash: string | null;
  scope_fingerprint: string;
  idempotency_key: string;
  requested_tools: string[];
  scope: Record<string, unknown>;
  context: Record<string, unknown>;
  policy: Record<string, unknown>;
  result_summary: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApplicationReviewContextEntry {
  id: string;
  review_id: string;
  source_type: string;
  source_object_id: string | null;
  item_type: string;
  title: string;
  body: string;
  keywords: string[];
  facets: Record<string, unknown>;
  retrieval_text: string;
  source_refs: Record<string, unknown>[];
  content_hash: string;
  status: string;
  stale_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApplicationReviewContextSearchResponse {
  review_id: string;
  query: string;
  results: ApplicationReviewContextEntry[];
}

export interface ApplicationReviewContextPacketEntry {
  entry_id: string;
  item_type: string;
  title: string;
  untrusted_text: string;
  source_refs: Record<string, unknown>[];
  content_hash: string;
}

export interface ApplicationReviewContextPacket {
  version: string;
  review_id: string;
  app_name: string;
  commit_sha: string | null;
  deterministic_decision: string | null;
  policy: Record<string, unknown>;
  evidence_snapshot_hash: string;
  entries: ApplicationReviewContextPacketEntry[];
  missing_evidence: string[];
}

export interface ApplicationReviewGroundedFixPlanStep {
  title: string;
  remediation: string;
  cited_content_hashes: string[];
}

export interface ApplicationReviewGroundedAIOutput {
  summary: string;
  proposed_decision: "pass" | "block" | "fix" | "verify" | "gather_evidence" | null;
  cited_content_hashes: string[];
  fix_plan: ApplicationReviewGroundedFixPlanStep[];
}

export interface ApplicationReviewGroundedAIValidation {
  valid: boolean;
  errors: string[];
}

export interface ApplicationReviewAIExplanation {
  review_id: string;
  packet: ApplicationReviewContextPacket;
  output: ApplicationReviewGroundedAIOutput | null;
  validation: ApplicationReviewGroundedAIValidation;
  explanation_status: "ready" | "missing_evidence" | "invalid";
  prompt_contract: string[];
}

export interface ApplicationReviewDecision {
  review_id: string;
  decision: "pass" | "block" | "fix" | "verify" | "gather_evidence";
  reason: string;
  evidence_hashes: string[];
  scanner_only: boolean;
  evidence_snapshot_hash: string | null;
  decision_engine_version: string | null;
  replayed: boolean;
  decision_trace: string[];
}

export interface ApplicationReviewEvidenceChainStep {
  step_type: string;
  label: string;
  source_ref: Record<string, unknown> | null;
  content_hash: string | null;
}

export interface ApplicationReviewEvidenceChain {
  chain_id: string;
  title: string;
  item_type: string;
  status: string;
  stale_reason: string | null;
  content_hash: string;
  source_refs: Record<string, unknown>[];
  steps: ApplicationReviewEvidenceChainStep[];
}

export interface ApplicationReviewGraphNode {
  id: string;
  label: string;
  node_type: string;
  evidence_hashes: string[];
  status: string | null;
}

export interface ApplicationReviewGraphEdge {
  source: string;
  target: string;
  relationship: string;
  evidence_hashes: string[];
}

export interface ApplicationReviewGraphSlice {
  nodes: ApplicationReviewGraphNode[];
  edges: ApplicationReviewGraphEdge[];
  missing_context: string[];
}

export interface ApplicationReviewArtifactFixPlanStep {
  title: string;
  action: string;
  verification: string;
  cited_content_hashes: string[];
  source_refs: Record<string, unknown>[];
}

export interface ApplicationReviewRerunHistoryEntry {
  review_id: string;
  parent_review_id: string | null;
  status: string;
  decision: string | null;
  commit_sha: string | null;
  evidence_snapshot_hash: string | null;
  updated_at: string;
}

export interface ApplicationReviewArtifact {
  review: ApplicationReview;
  web_url: string;
  decision_record: Record<string, unknown> | null;
  raw_evidence: ApplicationReviewContextEntry[];
  raw_evidence_count: number;
  has_stale_evidence: boolean;
  missing_evidence: string[];
  source_ref_count: number;
  evidence_chains: ApplicationReviewEvidenceChain[];
  graph_slice: ApplicationReviewGraphSlice;
  fix_plan: ApplicationReviewArtifactFixPlanStep[];
  accepted_risks: ApplicationReviewContextEntry[];
  rerun_history: ApplicationReviewRerunHistoryEntry[];
  redacted: boolean;
}

export interface AgentCommandHint {
  label: string;
  command: string;
  description: string;
}

export interface AgentToolHint {
  name: string;
  method: string;
  endpoint: string;
  description: string;
}

export interface AgentReviewStatus {
  review: ApplicationReview;
  web_url: string;
  api_status_url: string;
  terminal_commands: AgentCommandHint[];
  agent_tools: AgentToolHint[];
}

export interface AssistantActionArtifact {
  kind: ReviewArtifactKind;
  title: string;
  summary: string;
  body: string;
  review_finding_id: string;
  source_object_type: ReviewSourceObjectType;
  source_object_id: string;
  references: AssistantReference[];
}

export interface AssistantProposal {
  proposal_type: AssistantProposalType;
  title: string;
  summary: string;
  anchor_node_id?: string | null;
  anchor_handle?: "source" | "target" | null;
  node_id?: string | null;
  node_type?: NodeType | null;
  node_name?: string | null;
  position_x?: number | null;
  position_y?: number | null;
  source_node_id?: string | null;
  target_node_id?: string | null;
  edge_label: string;
  edge_properties: Record<string, unknown>;
  boundary_name?: string | null;
  boundary_node_ids: string[];
  name_patch?: string | null;
  properties_patch: Record<string, unknown>;
  assumption_title?: string | null;
  assumption_description?: string | null;
  assumption_status?: "open" | "validated" | "challenged" | null;
  assumption_anchor_kind?: "node" | "edge" | "boundary" | null;
  assumption_anchor_id?: string | null;
  assumption_anchor_label?: string | null;
}

export interface AssistantProposalBundle {
  title: string;
  summary: string;
  proposals: AssistantProposal[];
}

export interface AssistantGuidedStep {
  id: string;
  title: string;
  description: string;
  prompt: string;
  status: AssistantGuidedStepStatus;
  anchor?: AssistantAnchor | null;
  references: AssistantReference[];
  provenance: string[];
  proposal_bundle?: AssistantProposalBundle | null;
}

export interface AssistantResponse {
  mode: AssistantMode;
  answer: string;
  references: AssistantReference[];
  findings: AssistantReviewFinding[];
  action_artifacts: AssistantActionArtifact[];
  guided_steps: AssistantGuidedStep[];
  proposal: AssistantProposal | null;
  degraded_reason: string | null;
}

export interface AssistantMutationOutcome {
  threats: ThreatResponse[];
  addedThreats: ThreatResponse[];
  removedThreats: ThreatResponse[];
  aiSkippedReason: string | null;
}

// Vulnerability Scanning

export type ScanType = "unauthenticated" | "authenticated";
export type ScanScope = "external" | "internal" | "full";
export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";
export type ThreatScanStatus =
  | "confirmed"
  | "mitigated"
  | "unverifiable"
  | "not_found";
export type CredentialType =
  | "bearer_token"
  | "api_key_header"
  | "basic_auth"
  | "cookie";
export type ValidationTargetType =
  | "url"
  | "repository_path"
  | "lockfile"
  | "container_image"
  | "iac_directory"
  | "ai_system";

export interface ScanJob {
  id: string;
  threat_model_id: string;
  status: ScanStatus;
  scan_type: ScanType;
  scope: ScanScope;
  tool_name: string;
  target_type: ValidationTargetType;
  targets: Record<string, string>;
  finding_count: number;
  credential_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  failure_code?: string | null;
  runner_id?: string | null;
  claimed_at?: string | null;
  heartbeat_at?: string | null;
  lease_expires_at?: string | null;
  attempt_count?: number;
  max_attempts?: number;
  created_at: string;
}

export interface ScanFinding {
  id: string;
  template_id: string;
  template_name: string;
  severity: string;
  matched_at: string;
  extracted_results: string | null;
  cve_ids: string[];
  tags: string[];
  cvss_score: number | null;
  tool_name?: string | null;
  tool_version?: string | null;
  validation_target?: string | null;
  deterministic?: boolean | null;
  binding_confidence?: string | null;
  false_positive?: boolean | null;
  bound_stride_category?: string | null;
  bound_threat_template?: string | null;
  attack_technique?: string | null;
  created_at: string;
}

export interface ScanExecutionArtifact {
  id: string;
  scan_job_id: string;
  source: "execution" | "ingest";
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  resolved_target: string | null;
  status: "completed" | "failed" | "timed_out" | "blocked";
  deterministic: boolean;
  sandboxed: boolean;
  sandbox_mode?: string | null;
  container_image?: string | null;
  resource_limits?: Record<string, string>;
  policy_decision: string | null;
  command: string[];
  command_redacted: boolean;
  returncode: number | null;
  timed_out: boolean;
  output_limit_exceeded: boolean;
  stdout_bytes: number;
  output_sha256?: string | null;
  stderr_summary: string | null;
  network_mode: string | null;
  max_runtime_seconds: number | null;
  max_output_bytes: number | null;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  created_at: string;
}

export interface ScanThreatResult {
  id: string;
  threat_id: string;
  scan_status: ThreatScanStatus;
  evidence: Array<{
    finding_id: string;
    template_id: string;
    template_name: string;
    severity: string;
    matched_at: string;
    cve_ids: string[];
    tool_name?: string | null;
    tool_version?: string | null;
    validation_target?: string | null;
    deterministic?: boolean | null;
    evidence_scope?: string;
    confidence_label?: "validated" | "indicated" | "untested";
    risk_score?: number;
    proof_class?: "deterministic" | "ai_assisted" | "policy" | "runtime" | "unknown";
    evidence_quality?: "strong" | "moderate" | "weak";
    match_explanation?: string;
    matched_node_ids?: string[];
  }>;
  cve_ids: string[];
  created_at: string;
  updated_at?: string;
}

export interface ScanJobDetail extends ScanJob {
  findings: ScanFinding[];
  threat_results: ScanThreatResult[];
  execution_artifacts: ScanExecutionArtifact[];
}

export interface ValidationArtifactBundleItem {
  id: string;
  bundle_id: string;
  scan_job_id: string | null;
  scan_execution_artifact_id: string | null;
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  target_node_id: string | null;
  source_path: string;
  raw_output_sha256: string;
  raw_output_bytes: number;
  status: "imported" | "failed";
  finding_count: number;
  error_message: string | null;
  created_at: string;
}

export interface ValidationArtifactBundle {
  id: string;
  threat_model_id: string;
  owner_id: string;
  organization_id: string | null;
  filename: string;
  content_type: string | null;
  byte_size: number;
  sha256: string;
  status: "imported" | "partial" | "failed";
  manifest: Record<string, unknown>;
  storage_backend: "metadata_only" | "object_store";
  storage_key: string | null;
  error_message: string | null;
  item_count: number;
  created_at: string;
  updated_at: string;
  items: ValidationArtifactBundleItem[];
}

export interface ValidationArtifactBundleImportResponse {
  bundle: ValidationArtifactBundle;
  created_scans: ScanJobDetail[];
}

export interface ThreatScanCorrelationResponse {
  scan_job_id: string;
  scan_completed_at: string | null;
  threat_id: string;
  threat_display_id: string;
  threat_description: string;
  severity: string;
  stride_category: string;
  scan_status: ThreatScanStatus;
  evidence_count: number;
  cve_ids: string[];
  matched_targets: string[];
  templates: string[];
  matched_node_ids: string[];
  matched_node_labels: string[];
  finding_titles: string[];
  validation_tools?: string[];
  deterministic_evidence_count?: number;
  evidence: Array<{
    finding_id: string;
    template_id: string;
    template_name: string;
    severity: string;
    matched_at: string;
    cve_ids: string[];
    tool_name?: string | null;
    tool_version?: string | null;
    validation_target?: string | null;
    deterministic?: boolean | null;
    evidence_scope?: string;
    confidence_label?: "validated" | "indicated" | "untested";
    risk_score?: number;
    proof_class?: "deterministic" | "ai_assisted" | "policy" | "runtime" | "unknown";
    evidence_quality?: "strong" | "moderate" | "weak";
    match_explanation?: string;
    matched_node_ids?: string[];
  }>;
}

export interface ScanCorrelationSummaryResponse {
  scan_job_id: string;
  scan_completed_at: string | null;
  total_correlations: number;
  confirmed_count: number;
  mitigated_count: number;
  not_found_count: number;
  unverifiable_count: number;
  entries: ThreatScanCorrelationResponse[];
}

export interface ValidationRunbookFindingResponse {
  finding_id: string;
  title: string;
  severity: string;
  tool_name?: string | null;
  target?: string | null;
  matched_at: string;
  cve_ids: string[];
  tags: string[];
  confidence_label: "validated" | "indicated" | "untested";
  evidence_scope: string;
  proof_class: "deterministic" | "ai_assisted" | "policy" | "runtime" | "unknown";
  evidence_quality: "strong" | "moderate" | "weak";
  risk_score: number;
  next_action: string;
  explanation: string;
}

export interface ValidationRunbookThreatResponse {
  threat_id: string;
  threat_display_id: string;
  threat_description: string;
  severity: string;
  stride_category: string;
  scan_status: ThreatScanStatus;
  confidence_label: "validated" | "indicated" | "untested";
  explanation: string;
  evidence_count: number;
  risk_score: number;
  evidence_quality: "strong" | "moderate" | "weak";
  proof_class: "deterministic" | "ai_assisted" | "policy" | "runtime" | "unknown";
  next_action: string;
  cve_ids: string[];
  validation_tools: string[];
}

export interface ValidationRunbookCoverageResponse {
  scan_job_id: string;
  scan_completed_at: string | null;
  tool_names: string[];
  target_binding: "node_bound" | "global" | "mixed" | "none";
  finding_count: number;
  deterministic_finding_count: number;
  assisted_finding_count: number;
  artifact_count: number;
  mapped_threat_count: number;
  validated_threat_count: number;
  indicated_threat_count: number;
  unbound_finding_count: number;
  untested_threat_count: number;
  confidence_counts: Record<string, number>;
  validated_risk_score: number;
  indicated_risk_score: number;
  ai_assisted_risk_score: number;
}

export interface ValidationRunbookResponse {
  coverage: ValidationRunbookCoverageResponse;
  executive_summary: string;
  gaps: string[];
  mapped_threats: ValidationRunbookThreatResponse[];
  unbound_findings: ValidationRunbookFindingResponse[];
}

export interface ScanCreateRequest {
  scan_type: ScanType;
  scope: ScanScope;
  tool_name?: string;
  target_type?: ValidationTargetType;
  authorization_acknowledged: boolean;
  credential_id?: string | null;
}

export interface EvidenceIngestRequest {
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  raw_output: string;
  target_node_id?: string | null;
}

export interface ValidationRunRequest {
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  target_node_id?: string | null;
  scope?: ScanScope;
  authorization_acknowledged: boolean;
}

export interface ValidationToolInventoryItem {
  name: string;
  active: boolean;
  available: boolean;
  deterministic: boolean;
  runtime_strategy: string;
  runtime_detail: string;
  readiness_status: string;
  blocker_reasons: string[];
  setup_actions: string[];
  install_hint?: string | null;
  enablement_env?: string | null;
  local_allowlist_required: boolean;
  local_allowlist_configured: boolean;
  sandbox_mode: string;
  container_runtime_available: boolean;
  container_image?: string | null;
  container_image_present: boolean;
  container_pull_policy: string;
  supported_targets: string[];
  runs_in_sandbox_required: boolean;
  execution_enabled: boolean;
  network_mode: string;
  max_runtime_seconds: number;
  max_output_bytes: number;
  artifact_capture_enabled: boolean;
  category: string;
  proof_mode: string;
  safety_boundary: string;
  documentation_url: string;
  recommended_for: string[];
}

export interface RedTeamToolProfile {
  name: string;
  label: string;
  category: string;
  status: string;
  supported_targets: string[];
  network_mode: string;
  recommended_for: string[];
  safety_boundary: string;
  integration_notes: string;
  documentation_url: string;
}

export interface ValidationToolInventoryResponse {
  tools: ValidationToolInventoryItem[];
  red_team_tools: RedTeamToolProfile[];
}

export type ValidationCadence = "manual" | "daily" | "weekly" | "monthly";

export interface ValidationSchedule {
  id: string;
  threat_model_id: string;
  name: string;
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  target_node_id: string | null;
  scope: ScanScope;
  cadence: ValidationCadence;
  enabled: boolean;
  authorization_required: boolean;
  authorization_acknowledged_at: string | null;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
  updated_at: string;
  runnable: boolean;
  blocked_reason: string | null;
}

export interface ValidationScheduleCreateRequest {
  name: string;
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  target_node_id?: string | null;
  scope?: ScanScope;
  cadence?: ValidationCadence;
  enabled?: boolean;
  authorization_acknowledged: boolean;
}

export interface ValidationScheduleUpdateRequest {
  name?: string;
  tool_name?: string;
  target_type?: ValidationTargetType;
  target?: string;
  target_node_id?: string | null;
  clear_target_node_id?: boolean;
  scope?: ScanScope;
  cadence?: ValidationCadence;
  enabled?: boolean;
  authorization_acknowledged?: boolean;
}

export interface ValidationSafetyControl {
  name: string;
  status: "enforced" | "configured" | "missing" | "planned";
  detail: string;
}

export interface ValidationRuntime {
  mode: "try_sandbox" | "self_hosted" | "managed";
  run_submission_enabled?: boolean;
  live_execution_enabled: boolean;
  inline_execution_enabled?: boolean;
  worker_execution_enabled?: boolean;
  managed_runner_enabled?: boolean;
  try_sandbox_enabled: boolean;
  title: string;
  detail: string;
}

export interface ValidationRunnerStatus {
  status: "ready" | "queued" | "running" | "degraded" | "unavailable";
  detail: string;
  pending_count: number;
  running_count: number;
  failed_count: number;
  oldest_pending_age_seconds: number | null;
  oldest_running_age_seconds: number | null;
  stale_running_count: number;
  active_worker_count: number;
  last_heartbeat_at: string | null;
}

export interface ValidationSetupLane {
  name: string;
  status: "active" | "available" | "blocked" | "planned";
  summary: string;
  controls: string[];
}

export interface ValidationToolSetupProfile {
  tool_name: string;
  label: string;
  setup_mode: string;
  runner_profile: string;
  prerequisites: string[];
  configuration: string[];
  safety_gates: string[];
}

export interface ValidationRecommendedRun {
  tool_name: string;
  target_type: ValidationTargetType;
  priority: "P1" | "P2" | "P3";
  reason: string;
  blocked_reason: string | null;
}

export interface AgenticToolCapability {
  tool_name: string;
  label: string;
  category: string;
  target_types: string[];
  proves: string[];
  best_for: string[];
  evidence_schema: string[];
  execution_boundary: string;
  noise_controls: string[];
  critic_checks: string[];
}

export interface AgenticToolWorkflowStep {
  step: "plan" | "policy_gate" | "execute" | "bind" | "critic" | "report";
  owner: string;
  detail: string;
}

export interface AgenticToolRecommendation {
  recommendation_id: string;
  priority: "P1" | "P2" | "P3";
  tool_name: string;
  target_type: ValidationTargetType;
  objective: string;
  rationale: string;
  evidence_gap: string;
  expected_evidence: string;
  blocked_reason: string | null;
  saved_target_id: string | null;
  safety_gates: string[];
  critic_checks: string[];
  workflow: AgenticToolWorkflowStep[];
}

export interface AgenticToolBench {
  status: "ready" | "needs_targets" | "blocked" | "needs_evidence";
  summary: string;
  planning_inputs: string[];
  capabilities: AgenticToolCapability[];
  recommendations: AgenticToolRecommendation[];
  execution_contract: AgenticToolWorkflowStep[];
  global_critic_rules: string[];
}

export interface ValidationCaseCheck {
  tool_name: string;
  target_type: ValidationTargetType;
  priority: "P1" | "P2" | "P3";
  reason: string;
}

export type ValidationCaseWorkflowStatus = "open" | "investigating" | "mitigated" | "accepted" | "dismissed" | "refuted";
export type ValidationCaseWorkflowPriority = "P1" | "P2" | "P3";

export interface ValidationCaseAuditEvent {
  id: string;
  action: "created" | "updated";
  changes: Record<string, { from?: unknown; to?: unknown }>;
  note: string | null;
  actor_id: string | null;
  created_at: string;
}

export interface ValidationCaseStateUpdateRequest {
  workflow_status?: ValidationCaseWorkflowStatus | null;
  workflow_priority?: ValidationCaseWorkflowPriority | null;
  clear_priority?: boolean;
  owner_label?: string | null;
  clear_owner?: boolean;
  due_date?: string | null;
  clear_due_date?: boolean;
  analyst_note?: string | null;
  last_decision?: string | null;
}

export interface ValidationEvidenceBindingRequest {
  target_node_id: string;
}

export interface ValidationEvidenceBindingResponse {
  finding_id: string;
  scan_id: string;
  threat_model_id: string;
  target_node_id: string;
  target_node_name: string;
  binding_target: string;
  target_binding: "node_bound" | "global" | "mixed" | "none";
  mapped_threat_count: number;
  unbound_finding_count: number;
  message: string;
}

export interface ProductSecurityValidationCase {
  case_id: string;
  case_type: "threat" | "unbound_finding";
  title: string;
  hypothesis: string;
  severity: string;
  stride_category: string | null;
  status: "needs_evidence" | "needs_binding" | "relevant" | "validated";
  confidence_label: "low" | "medium" | "high";
  confidence_score: number;
  proof_level: "none" | "observed" | "relevant" | "validated" | "human_attested";
  proof_class: "deterministic" | "ai_assisted" | "policy" | "runtime" | "unknown";
  evidence_quality: "strong" | "moderate" | "weak";
  evidence_count: number;
  evidence_sources: string[];
  risk_score: number;
  product_questions: string[];
  recommended_checks: ValidationCaseCheck[];
  next_action: string;
  remediation_action: string;
  workflow_status: ValidationCaseWorkflowStatus;
  workflow_priority: ValidationCaseWorkflowPriority | null;
  owner_label: string | null;
  due_date: string | null;
  analyst_note: string | null;
  last_decision: string | null;
  workflow_updated_at: string | null;
  audit_events: ValidationCaseAuditEvent[];
}

export interface ValidationGap {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  detail: string;
  next_action: string;
}

export interface ValidationEvidenceLedgerEntry {
  scan_id: string;
  tool_name: string;
  target_type: ValidationTargetType;
  status: string;
  target_binding: "node_bound" | "global" | "mixed" | "none";
  finding_count: number;
  mapped_threat_count: number;
  validated_threat_count: number;
  indicated_threat_count: number;
  unbound_finding_count: number;
  artifact_count: number;
  deterministic_finding_count: number;
  assisted_finding_count: number;
  output_sha256: string | null;
  error_message: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface ValidationDemoScenario {
  title: string;
  summary: string;
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  raw_output: string;
  expected_signal: string;
}

export interface ValidationTargetBundle {
  id: string;
  threat_model_id: string;
  owner_id: string;
  organization_id: string | null;
  name: string;
  filename: string;
  content_type: string | null;
  byte_size: number;
  sha256: string;
  status: string;
  storage_backend: string;
  manifest: Record<string, unknown>;
  target_ref: string;
  retention_expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ValidationLabPosture {
  schedule_count: number;
  enabled_schedule_count: number;
  recent_scan_count: number;
  ready_tool_count: number;
  deterministic_tool_count: number;
  ai_assisted_tool_count: number;
  validated_threat_count: number;
  indicated_threat_count: number;
  untested_threat_count: number;
  validated_risk_score: number;
  indicated_risk_score: number;
  ai_assisted_risk_score: number;
}

export interface ValidationLabSummary {
  threat_model_id: string;
  runtime: ValidationRuntime;
  runner_status: ValidationRunnerStatus;
  posture: ValidationLabPosture;
  tools: ValidationToolInventoryItem[];
  red_team_tools: RedTeamToolProfile[];
  setup_lanes: ValidationSetupLane[];
  tool_setup_profiles: ValidationToolSetupProfile[];
  target_bundles?: ValidationTargetBundle[];
  schedules: ValidationSchedule[];
  recent_scans: ScanJob[];
  latest_runbook: ValidationRunbookResponse | null;
  product_security_cases: ProductSecurityValidationCase[];
  evidence_ledger: ValidationEvidenceLedgerEntry[];
  gaps: ValidationGap[];
  demo_scenario: ValidationDemoScenario | null;
  safety_controls: ValidationSafetyControl[];
  recommended_next_runs: ValidationRecommendedRun[];
  agentic_tool_bench: AgenticToolBench | null;
}

// Scan Credentials (Phase S2)

export interface ScanCredential {
  id: string;
  threat_model_id: string;
  name: string;
  credential_type: CredentialType;
  header_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanCredentialCreate {
  name: string;
  credential_type: CredentialType;
  header_name?: string | null;
  secret: string;
}

export interface ScanCredentialUpdate {
  name?: string;
  header_name?: string | null;
  secret?: string;
}

// ─── BYOK (Bring Your Own Key) ──────────────────────────────────

export interface BYOKKeyResponse {
  provider: string;
  display_name: string;
  masked_key: string;
  model_override: string | null;
  created_at: string;
}

export interface BYOKKeyRequest {
  api_key: string;
  model_override?: string | null;
}

export interface BYOKTestResult {
  status: "ok" | "error";
  provider: string;
  detail?: string;
}

export interface LLMProviderHealth {
  status: "ready" | "degraded" | "unconfigured";
  active_provider: string;
  active_model: string;
  server_provider: string;
  bedrock_region: string;
  bedrock_model_id: string;
  bedrock_enhancement_model_id: string;
  canada_residency_enforced: boolean;
  external_ai_providers_enabled: boolean;
  data_residency_mode: "canada_only" | "external_opt_in";
  configured_provider_count: number;
  warnings: string[];
  next_actions: string[];
}

export type OrchestrationStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "blocked";

export interface OrchestrationTask {
  id: string;
  job_id: string;
  threat_model_id: string;
  task_kind: "agent_reasoning" | "tool_execution" | "evidence_projection" | "human_review";
  agent_name: string | null;
  tool_name: string | null;
  status: OrchestrationStatus;
  input_payload: Record<string, unknown>;
  output_payload: Record<string, unknown>;
  error_message: string | null;
  attempt_count: number;
  max_attempts: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface OrchestrationEvent {
  id: string;
  job_id: string;
  task_id: string | null;
  threat_model_id: string;
  event_type: string;
  level: "debug" | "info" | "warning" | "error";
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface OrchestrationJob {
  id: string;
  threat_model_id: string;
  owner_id: string;
  job_kind: "evidence_rebuild" | "validation_run" | "security_audit" | "environment_audit" | "custom";
  status: OrchestrationStatus;
  objective: string;
  requested_tools: string[];
  idempotency_key: string | null;
  inputs: Record<string, unknown>;
  policy: Record<string, unknown>;
  result_summary: string | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  tasks: OrchestrationTask[];
  events: OrchestrationEvent[];
}
