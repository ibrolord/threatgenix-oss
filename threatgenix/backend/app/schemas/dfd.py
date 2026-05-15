from enum import Enum
from typing import Literal, Optional
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class NodeResponsibility(str, Enum):
    provider = "provider"
    customer = "customer"
    shared = "shared"


class AuthenticationType(str, Enum):
    none = "none"
    api_key = "api_key"
    oauth2 = "oauth2"
    mtls = "mtls"
    saml = "saml"
    jwt = "jwt"


class AuthorizationModel(str, Enum):
    none = "none"
    rbac = "rbac"
    abac = "abac"
    acl = "acl"
    policy = "policy"


class NetworkExposure(str, Enum):
    internet = "internet"
    dmz = "dmz"
    internal = "internal"
    vpc_private = "vpc_private"


class PrivilegeLevel(str, Enum):
    standard = "standard"
    elevated = "elevated"
    privileged = "privileged"
    admin = "admin"
    system = "system"


class ProcessRuntimeType(str, Enum):
    service = "service"
    worker = "worker"
    function = "function"
    job = "job"
    gateway = "gateway"
    container = "container"


class IsolationBoundary(str, Enum):
    shared_host = "shared_host"
    container = "container"
    sandbox = "sandbox"
    dedicated_host = "dedicated_host"
    managed_service = "managed_service"


class EdgeDirectionality(str, Enum):
    request = "request"
    response = "response"
    event = "event"
    bidirectional = "bidirectional"


class DataClassification(str, Enum):
    public = "Public"
    internal = "Internal"
    confidential = "Confidential"
    restricted = "Restricted"


class InputValidationLevel(str, Enum):
    none = "none"
    partial = "partial"
    strict = "strict"


class LoggingLevel(str, Enum):
    none = "none"
    errors_only = "errors_only"
    audit = "audit"
    full = "full"


class EncryptionAtRest(str, Enum):
    none = "none"
    application_level = "application_level"
    transparent = "transparent"
    hsm = "hsm"


class BackupStrategy(str, Enum):
    none = "none"
    local = "local"
    geo_redundant = "geo_redundant"


class EntityScope(str, Enum):
    internal = "internal"
    external = "external"


class ExternalEntityKind(str, Enum):
    human = "human"
    device = "device"
    system = "system"
    saas = "saas"
    api = "api"
    service = "service"


class TrustLevel(str, Enum):
    untrusted = "untrusted"
    semi_trusted = "semi_trusted"
    trusted = "trusted"
    privileged = "privileged"


class TransferMode(str, Enum):
    synchronous = "synchronous"
    asynchronous = "asynchronous"
    batch = "batch"
    streaming = "streaming"
    near_real_time = "near_real_time"


class DataLifecycleStage(str, Enum):
    ingress = "ingress"
    processing = "processing"
    storage = "storage"
    egress = "egress"
    replication = "replication"
    backup = "backup"
    analytics = "analytics"
    notification = "notification"


class DFDViewType(str, Enum):
    context = "context"
    container = "container"
    deep_dive = "deep_dive"
    data_lifecycle = "data_lifecycle"
    decomposition = "decomposition"
    workspace = "workspace"


class TLSVersion(str, Enum):
    none = "none"
    tls_1_0 = "tls_1_0"
    tls_1_1 = "tls_1_1"
    tls_1_2 = "tls_1_2"
    tls_1_3 = "tls_1_3"
    other = "other"


class BoundaryType(str, Enum):
    network = "network"
    organizational = "organizational"
    regulatory = "regulatory"
    privilege = "privilege"
    cloud = "cloud"


class ComponentShape(str, Enum):
    rounded_rect = "rounded_rect"
    square = "square"
    pill = "pill"
    cylinder = "cylinder"
    hexagon = "hexagon"
    cloud = "cloud"
    stacked = "stacked"
    diamond = "diamond"
    gateway = "gateway"
    queue = "queue"


def _validate_scan_target_url(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("scan_target_url must be an http or https URL")
    return candidate


def _validate_scan_target_ports(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None

    normalized_ports: list[str] = []
    for raw_port in candidate.split(","):
        port_text = raw_port.strip()
        if not port_text or not port_text.isdigit():
            raise ValueError(
                "scan_target_ports must be comma-separated integers between 1 and 65535"
            )
        port = int(port_text)
        if port < 1 or port > 65535:
            raise ValueError(
                "scan_target_ports must be comma-separated integers between 1 and 65535"
            )
        normalized_ports.append(str(port))
    return ",".join(normalized_ports)


class SecurityControl(BaseModel):
    """Named security control applied to a node (e.g. WAF, SIEM, HSM)."""

    control_type: str  # e.g. "WAF", "SIEM", "HSM", "MFA", "IDS"
    name: str  # e.g. "AWS WAF", "Splunk", "Thales HSM"
    covers: list[str] = Field(
        default_factory=list
    )  # e.g. ["input_validation", "rate_limiting"]
    notes: Optional[str] = None


class DataObject(BaseModel):
    """Typed data element flowing across an edge (NIST 800-154 data-centric modeling)."""

    name: str  # e.g. "PAN", "JWT Token", "Account Balance"
    classification: Optional[str] = None  # PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED
    description: Optional[str] = None


class NodeProperties(BaseModel):
    """Security properties for DFD nodes. Drives rule suppression in the rules engine."""

    component_template_id: Optional[str] = None
    component_label: Optional[str] = None
    component_shape: Optional[ComponentShape] = None
    component_description: Optional[str] = None
    property_display_labels: Optional[dict[str, str]] = None
    # All node types
    internet_facing: Optional[bool] = None
    data_classification: Optional[DataClassification | str] = None
    authentication_type: Optional[AuthenticationType | str] = None
    authorization_model: Optional[AuthorizationModel | str] = None
    network_exposure: Optional[NetworkExposure | str] = None
    privilege_level: Optional[PrivilegeLevel | str] = None
    # process
    uses_auth: Optional[bool] = None
    validates_input: Optional[bool] = None
    uses_encryption: Optional[bool] = None
    handles_sensitive_data: Optional[bool] = None
    runtime_type: Optional[ProcessRuntimeType | str] = None
    isolation_boundary: Optional[IsolationBoundary | str] = None
    accepted_input: Optional[str] = None
    input_validation: Optional[InputValidationLevel | str] = None
    logging_level: Optional[LoggingLevel | str] = None
    handles_pii: Optional[bool] = None
    handles_financial_data: Optional[bool] = None
    # data_store
    stores_credentials: Optional[bool] = None
    encrypted_at_rest: Optional[bool] = None
    has_backup: Optional[bool] = None
    store_type: Optional[str] = None
    store_purpose: Optional[str] = None
    read_access_scope: Optional[str] = None
    write_access_scope: Optional[str] = None
    encryption_at_rest: Optional[EncryptionAtRest | str] = None
    backup_strategy: Optional[BackupStrategy | str] = None
    integrity_controls: Optional[str] = None
    stores_secrets: Optional[bool] = None
    # external_entity
    trusted: Optional[bool] = None
    authenticated: Optional[bool] = None
    entity_scope: Optional[EntityScope | str] = None
    entity_kind: Optional[ExternalEntityKind | str] = None
    trust_level: Optional[TrustLevel | str] = None
    # cloud node types
    service_name: Optional[str] = None  # managed_service — e.g. "S3", "RDS"
    function_name: Optional[str] = None  # serverless — e.g. "process-payment"
    # shared responsibility annotation
    responsibility: Optional[NodeResponsibility | str] = None
    # Explicit source-code mapping evidence for repository-derived reviews
    mapped_code_surface_ids: list[str] = Field(default_factory=list)
    mapped_code_source_refs: list[str] = Field(default_factory=list)
    code_mapping_evidence: Optional[str] = None
    code_mapping_review_status: Optional[Literal["pending", "approved", "changes_requested"]] = None
    code_mapping_reviewed_by: Optional[str] = None
    code_mapping_reviewed_at: Optional[str] = None
    # security controls applied to this node
    security_controls: list[SecurityControl] = Field(default_factory=list)


DFDNodeTypeLiteral = Literal[
    "process",
    "data_store",
    "external_entity",
    "human_actor",
    "iam_role",
    "managed_service",
    "api_gateway",
    "container",
    "serverless",
]

DFDPropertyOptionFieldLiteral = Literal[
    "data_classification",
    "authentication_type",
    "authorization_model",
    "network_exposure",
    "privilege_level",
    "runtime_type",
    "isolation_boundary",
    "input_validation",
    "logging_level",
    "encryption_at_rest",
    "backup_strategy",
    "entity_scope",
    "entity_kind",
    "trust_level",
    "responsibility",
]


class EdgeProperties(BaseModel):
    protocol: Optional[str] = None
    data_payload: Optional[str] = None
    data_classification: Optional[DataClassification | str] = None
    lifecycle_stage: Optional[DataLifecycleStage | str] = None
    auth_mechanism: Optional[str] = None
    encryption_in_transit: Optional[bool] = None
    directionality: Optional[EdgeDirectionality | str] = None
    transfer_mode: Optional[TransferMode | str] = None
    sequence_note: Optional[str] = None
    carries_credentials: Optional[bool] = None
    carries_pii: Optional[bool] = None
    carries_secrets: Optional[bool] = None
    rate_limited: Optional[bool] = None
    integrity_protected: Optional[bool] = None
    data_types: list[str] = Field(default_factory=list)
    tls_version: Optional[TLSVersion | str] = None
    is_response: Optional[bool] = None
    response_to_id: Optional[UUID] = None
    data_objects: list[DataObject] = Field(default_factory=list)
    carries_financial_data: Optional[bool] = None

    model_config = {"extra": "allow"}


class DFDNodeCreate(BaseModel):
    id: Optional[UUID] = None
    node_type: DFDNodeTypeLiteral
    name: str = Field(..., max_length=255)
    position_x: float = 0
    position_y: float = 0
    trust_boundary_id: Optional[UUID] = None
    scan_target_url: Optional[str] = None
    scan_target_ports: Optional[str] = None
    properties: NodeProperties = Field(default_factory=NodeProperties)

    @field_validator("scan_target_url")
    @classmethod
    def _validate_scan_target_url(cls, value: Optional[str]) -> Optional[str]:
        return _validate_scan_target_url(value)

    @field_validator("scan_target_ports")
    @classmethod
    def _validate_scan_target_ports(cls, value: Optional[str]) -> Optional[str]:
        return _validate_scan_target_ports(value)


class DFDNodeResponse(BaseModel):
    id: UUID
    node_type: str
    name: str
    position_x: float
    position_y: float
    trust_boundary_id: Optional[UUID]
    scan_target_url: Optional[str] = None
    scan_target_ports: Optional[str] = None
    properties: dict
    security_controls: Optional[list[dict]] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class DFDNodeUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    node_type: Optional[DFDNodeTypeLiteral] = None
    position_x: Optional[float] = None
    position_y: Optional[float] = None
    trust_boundary_id: Optional[UUID] = None
    scan_target_url: Optional[str] = None
    scan_target_ports: Optional[str] = None
    properties: Optional[NodeProperties] = None

    @field_validator("scan_target_url")
    @classmethod
    def _validate_scan_target_url(cls, value: Optional[str]) -> Optional[str]:
        return _validate_scan_target_url(value)

    @field_validator("scan_target_ports")
    @classmethod
    def _validate_scan_target_ports(cls, value: Optional[str]) -> Optional[str]:
        return _validate_scan_target_ports(value)


class DFDEdgeCreate(BaseModel):
    id: Optional[UUID] = None
    source_node_id: UUID
    target_node_id: UUID
    label: str = Field(default="", max_length=255)
    properties: EdgeProperties = Field(default_factory=EdgeProperties)


class DFDEdgeUpdate(BaseModel):
    label: Optional[str] = Field(default=None, max_length=255)
    properties: Optional[EdgeProperties] = None


class DFDEdgeResponse(BaseModel):
    id: UUID
    source_node_id: UUID
    target_node_id: UUID
    label: str
    properties: EdgeProperties = Field(default_factory=EdgeProperties)
    tls_version: Optional[str] = None
    is_response: Optional[bool] = False
    response_to_id: Optional[UUID] = None
    data_objects: Optional[list[dict]] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class TrustBoundaryCreate(BaseModel):
    id: Optional[UUID] = None
    name: str = "Trust Boundary"
    node_ids: list[UUID]
    position_x: Optional[float] = None
    position_y: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None
    boundary_type: Optional[str] = None
    parent_boundary_id: Optional[UUID] = None


class TrustBoundaryResponse(BaseModel):
    id: UUID
    name: str
    node_ids: list[UUID]
    position_x: float = 0
    position_y: float = 0
    width: float = 280
    height: float = 180
    boundary_type: Optional[str] = None
    parent_boundary_id: Optional[UUID] = None

    model_config = {"from_attributes": True}


class DFDComponentTemplateDraft(BaseModel):
    label: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=400)
    semantic_node_type: DFDNodeTypeLiteral
    semantic_type_label: Optional[str] = Field(default=None, max_length=120)
    shape: ComponentShape
    group: str = Field(default="Custom", min_length=1, max_length=60)
    default_name: Optional[str] = Field(default=None, max_length=120)
    default_properties: NodeProperties = Field(default_factory=NodeProperties)
    ai_generated: bool = False
    rationale: Optional[str] = Field(default=None, max_length=600)


class DFDComponentTemplateCreate(DFDComponentTemplateDraft):
    pass


class DFDComponentTemplateResponse(DFDComponentTemplateDraft):
    id: str = Field(..., min_length=1, max_length=80)
    built_in: bool = False


class DFDComponentTemplateSuggestRequest(BaseModel):
    prompt: str = Field(..., min_length=3, max_length=1000)


class DFDComponentTemplateSuggestResponse(BaseModel):
    template: DFDComponentTemplateDraft
    degraded_reason: Optional[str] = None


class DFDPropertyOptionDraft(BaseModel):
    field: DFDPropertyOptionFieldLiteral
    label: str = Field(..., min_length=1, max_length=120)
    canonical_value: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=400)
    ai_generated: bool = False
    rationale: Optional[str] = Field(default=None, max_length=600)


class DFDPropertyOptionCreate(DFDPropertyOptionDraft):
    pass


class DFDPropertyOptionResponse(DFDPropertyOptionDraft):
    id: str = Field(..., min_length=1, max_length=80)


class DFDPropertyOptionSuggestRequest(BaseModel):
    field: DFDPropertyOptionFieldLiteral
    prompt: str = Field(..., min_length=3, max_length=1000)


class DFDPropertyOptionSuggestResponse(BaseModel):
    option: DFDPropertyOptionDraft
    degraded_reason: Optional[str] = None


class DFDResponse(BaseModel):
    nodes: list[DFDNodeResponse]
    edges: list[DFDEdgeResponse]
    trust_boundaries: list[TrustBoundaryResponse]


class DFDQuickAddEdge(BaseModel):
    label: str = ""
    properties: EdgeProperties = Field(default_factory=EdgeProperties)


class DFDQuickAddRequest(BaseModel):
    origin_node_id: UUID
    origin_handle: Literal["source", "target"]
    node: DFDNodeCreate
    edge: DFDQuickAddEdge = Field(default_factory=DFDQuickAddEdge)


class DFDQuickAddResponse(BaseModel):
    node: DFDNodeResponse
    edge: DFDEdgeResponse


class DFDIacImportRequest(BaseModel):
    mode: Literal["merge", "replace"] = "merge"


class DFDIacImportSummary(BaseModel):
    mode: Literal["merge", "replace"]
    imported_resource_count: int
    semantic_resource_count: int
    matched_existing_nodes: int = 0
    created_nodes: int = 0
    updated_nodes: int = 0
    created_edges: int = 0
    created_boundaries: int = 0
    warnings: list[str] = Field(default_factory=list)


class DFDIacImportResponse(BaseModel):
    dfd: DFDResponse
    summary: DFDIacImportSummary


class DFDRepositorySeedPreview(BaseModel):
    suggestion_id: str
    label: str
    node_type: DFDNodeTypeLiteral
    rationale: str
    source_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    match_status: Literal["new", "matched_existing"]
    matched_node_id: UUID | None = None
    matched_node_name: str | None = None
    proposed_node: DFDNodeCreate


class DFDRepositorySeedPreviewResponse(BaseModel):
    suggestions: list[DFDRepositorySeedPreview] = Field(default_factory=list)
    existing_node_count: int = 0
    unmatched_suggestion_count: int = 0
    inferred_flow_count: int = 0
    inferred_boundary_count: int = 0


class DFDRepositorySeedApplyRequest(BaseModel):
    suggestion_ids: list[str] = Field(default_factory=list)


class DFDRepositorySeedApplySummary(BaseModel):
    requested_suggestion_count: int = 0
    matched_existing_nodes: int = 0
    created_nodes: int = 0
    created_edges: int = 0
    created_boundaries: int = 0
    skipped_suggestions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DFDRepositorySeedApplyResponse(BaseModel):
    dfd: DFDResponse
    summary: DFDRepositorySeedApplySummary


class DFDViewNodeLayout(BaseModel):
    id: UUID
    position_x: float
    position_y: float


class DFDViewBoundaryLayout(BaseModel):
    id: UUID
    position_x: float
    position_y: float
    width: Optional[float] = None
    height: Optional[float] = None


class DFDViewLayoutSnapshot(BaseModel):
    nodes: list[DFDViewNodeLayout] = Field(default_factory=list)
    boundaries: list[DFDViewBoundaryLayout] = Field(default_factory=list)


class DFDViewResponse(BaseModel):
    id: UUID
    view_type: DFDViewType
    name: str
    node_ids: list[UUID] = Field(default_factory=list)
    edge_ids: list[UUID] = Field(default_factory=list)
    boundary_ids: list[UUID] = Field(default_factory=list)
    layout_snapshot: DFDViewLayoutSnapshot = Field(
        default_factory=DFDViewLayoutSnapshot
    )
    parent_view_id: UUID | None = None
    parent_node_id: UUID | None = None
    graph: DFDResponse | None = None
    is_auto_generated: bool = True


class DFDViewUpdate(BaseModel):
    name: Optional[str] = None
    layout_snapshot: Optional[DFDViewLayoutSnapshot] = None


class DFDDecompositionViewCreate(BaseModel):
    parent_node_id: UUID
    parent_view_id: UUID | None = None
    name: Optional[str] = None


class DFDWorkspaceViewCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    source_view_id: UUID | None = None


class DFDQualityGateResult(BaseModel):
    gate_id: str
    title: str
    severity: Literal["block", "warn"]
    message: str
    affected_node_ids: list[UUID] = Field(default_factory=list)
    affected_edge_ids: list[UUID] = Field(default_factory=list)
    affected_boundary_ids: list[UUID] = Field(default_factory=list)


class DFDQualityGateSummary(BaseModel):
    blocking_count: int
    warning_count: int
    results: list[DFDQualityGateResult] = Field(default_factory=list)


class DFDBulkSave(BaseModel):
    nodes: list[DFDNodeCreate]
    edges: list[DFDEdgeCreate]
    trust_boundaries: list[TrustBoundaryCreate] = []
