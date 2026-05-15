"""DFD endpoints: GET, individual CRUD, and bulk save (Blocks 11 + F-05)."""

from collections.abc import Iterable
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.database import get_db
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.user import User
from app.schemas.dfd import (
    DFDComponentTemplateCreate,
    DFDComponentTemplateResponse,
    DFDComponentTemplateSuggestRequest,
    DFDComponentTemplateSuggestResponse,
    DFDPropertyOptionCreate,
    DFDPropertyOptionResponse,
    DFDPropertyOptionSuggestRequest,
    DFDPropertyOptionSuggestResponse,
    DFDBulkSave,
    DFDIacImportRequest,
    DFDIacImportResponse,
    DFDIacImportSummary,
    DFDRepositorySeedApplyRequest,
    DFDRepositorySeedApplyResponse,
    DFDRepositorySeedApplySummary,
    DFDRepositorySeedPreview,
    DFDRepositorySeedPreviewResponse,
    DFDDecompositionViewCreate,
    DFDWorkspaceViewCreate,
    DFDEdgeCreate,
    DFDEdgeResponse,
    DFDEdgeUpdate,
    DFDQualityGateSummary,
    DFDQuickAddRequest,
    DFDQuickAddResponse,
    DFDNodeCreate,
    DFDNodeResponse,
    DFDNodeUpdate,
    DFDResponse,
    DFDViewResponse,
    DFDViewLayoutSnapshot,
    DFDViewUpdate,
    TrustBoundaryCreate,
    TrustBoundaryResponse,
)
from app.schemas.environment_evidence import (
    IacEvidence,
    RepositoryDfdSeedBoundarySuggestion,
    RepositoryDfdSeedFlowSuggestion,
    RepositoryDfdSeedSuggestion,
    RepositoryEvidence,
)
from app.services.auth import get_current_user
from app.services.dfd_component_templates import (
    create_component_template,
    delete_component_template,
    list_component_templates,
    suggest_component_template,
)
from app.services.dfd_property_options import (
    create_property_option,
    delete_property_option,
    list_property_options,
    suggest_property_option,
)
from app.services.dfd_iac_import import (
    DFDIacImportSummary as ServiceDFDIacImportSummary,
    build_iac_import_draft,
    merge_iac_import_into_dfd,
)
from app.services.dfd_quality_gates import evaluate_quality_gates
from app.services.dfd_semantics import (
    infer_handles_sensitive_data,
    infer_internet_facing_exposure,
    infer_select_presence,
    infer_trusted_boundary,
)
from app.services.dfd_views import (
    clone_dfd_response,
    empty_dfd_response,
    find_view_response,
    get_view_graph,
    is_custom_graph_view,
    is_decomposable_node_type,
    is_editable_view,
    load_view_responses,
    serialize_view_responses,
    sync_default_views,
)
from app.services.model_collaboration import require_model_permission
from app.services.threat_model import get_threat_model

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/dfd",
    tags=["dfd"],
)

INVALID_BOUNDARY_REFERENCE = "Invalid trust boundary reference"
INVALID_BOUNDARY_NODE_REFERENCE = "Invalid boundary node references"
BOUNDARY_PADDING = 20.0
BOUNDARY_NODE_WIDTH = 180.0
BOUNDARY_NODE_HEIGHT = 64.0
DEFAULT_BOUNDARY_WIDTH = 280.0
DEFAULT_BOUNDARY_HEIGHT = 180.0
REPOSITORY_SEED_NODE_TYPES = {
    "process": "process",
    "data_store": "data_store",
    "queue": "managed_service",
    "external_entity": "external_entity",
    "infrastructure": "managed_service",
}


async def _verify_threat_model(
    db: AsyncSession,
    threat_model_id: UUID,
    user: User | None = None,
    *,
    permission: str = "write",
) -> None:
    """Raise 404 if threat model does not exist. Raise 403 if not owned by user."""
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    if user is not None:
        require_model_permission(threat_model, user, permission)  # type: ignore[arg-type]


def _dedupe_node_ids(node_ids: Iterable[UUID]) -> list[UUID]:
    return list(dict.fromkeys(node_ids))


def _ensure_no_boundary_parent_cycles(
    parent_lookup: dict[UUID, UUID | None],
    *,
    detail: str,
) -> None:
    visiting: set[UUID] = set()
    visited: set[UUID] = set()

    def visit(boundary_id: UUID) -> None:
        if boundary_id in visited:
            return
        if boundary_id in visiting:
            raise HTTPException(status_code=400, detail=detail)

        visiting.add(boundary_id)
        parent_id = parent_lookup.get(boundary_id)
        if parent_id is not None:
            visit(parent_id)
        visiting.remove(boundary_id)
        visited.add(boundary_id)

    for boundary_id in parent_lookup:
        visit(boundary_id)


def _add_node_to_boundary(boundary: TrustBoundary, node_id: UUID) -> None:
    node_ids = list(boundary.node_ids or [])
    if node_id not in node_ids:
        boundary.node_ids = [*node_ids, node_id]


def _remove_node_from_boundary(boundary: TrustBoundary, node_id: UUID) -> None:
    node_ids = [existing_id for existing_id in list(boundary.node_ids or []) if existing_id != node_id]
    boundary.node_ids = node_ids


async def _load_boundaries(
    db: AsyncSession,
    threat_model_id: UUID,
    boundary_ids: Iterable[UUID],
) -> dict[UUID, TrustBoundary]:
    unique_boundary_ids = _dedupe_node_ids(boundary_ids)
    if not unique_boundary_ids:
        return {}

    result = await db.execute(
        select(TrustBoundary).where(
            TrustBoundary.threat_model_id == threat_model_id,
            TrustBoundary.id.in_(unique_boundary_ids),
        )
    )
    boundaries = result.scalars().all()
    return {boundary.id: boundary for boundary in boundaries}


async def _sync_node_boundary_membership(
    db: AsyncSession,
    threat_model_id: UUID,
    node: DFDNode,
    new_boundary_id: UUID | None,
) -> None:
    current_boundary_id = node.trust_boundary_id
    boundary_ids = [
        boundary_id
        for boundary_id in (current_boundary_id, new_boundary_id)
        if boundary_id is not None
    ]
    boundaries_by_id = await _load_boundaries(db, threat_model_id, boundary_ids)

    if new_boundary_id is not None and new_boundary_id not in boundaries_by_id:
        raise HTTPException(status_code=400, detail=INVALID_BOUNDARY_REFERENCE)

    if current_boundary_id is not None and current_boundary_id in boundaries_by_id:
        _remove_node_from_boundary(boundaries_by_id[current_boundary_id], node.id)

    node.trust_boundary_id = new_boundary_id

    if new_boundary_id is not None:
        _add_node_to_boundary(boundaries_by_id[new_boundary_id], node.id)


def _derive_boundary_geometry_from_positions(
    node_positions: Iterable[tuple[float, float]]
) -> tuple[float, float, float, float] | None:
    positions = list(node_positions)
    if not positions:
        return None

    min_x = min(position_x for position_x, _ in positions)
    min_y = min(position_y for _, position_y in positions)
    max_x = max(position_x + BOUNDARY_NODE_WIDTH for position_x, _ in positions)
    max_y = max(position_y + BOUNDARY_NODE_HEIGHT for _, position_y in positions)
    return (
        min_x - BOUNDARY_PADDING,
        min_y - BOUNDARY_PADDING,
        max_x - min_x + BOUNDARY_PADDING * 2,
        max_y - min_y + BOUNDARY_PADDING * 2,
    )


def _resolve_boundary_geometry(
    *,
    position_x: float | None,
    position_y: float | None,
    width: float | None,
    height: float | None,
    node_positions: Iterable[tuple[float, float]],
) -> tuple[float, float, float, float]:
    derived_geometry = _derive_boundary_geometry_from_positions(node_positions)
    if derived_geometry is None:
        derived_geometry = (
            0.0,
            0.0,
            DEFAULT_BOUNDARY_WIDTH,
            DEFAULT_BOUNDARY_HEIGHT,
        )

    return (
        derived_geometry[0] if position_x is None else position_x,
        derived_geometry[1] if position_y is None else position_y,
        derived_geometry[2] if width is None else width,
        derived_geometry[3] if height is None else height,
    )


def _normalize_node_properties(raw_properties: object | None, *, node_type: str | None = None) -> dict:
    if raw_properties is None:
        properties: dict = {}
    elif hasattr(raw_properties, "model_dump"):
        properties = raw_properties.model_dump(exclude_none=True)
    elif isinstance(raw_properties, dict):
        properties = dict(raw_properties)
    else:
        properties = {}

    uses_auth = infer_select_presence(properties.get("authentication_type"))
    if uses_auth is not None:
        properties["uses_auth"] = uses_auth
        properties["authenticated"] = uses_auth

    validates_input = infer_select_presence(properties.get("input_validation"))
    if validates_input is not None:
        properties["validates_input"] = validates_input

    encrypted_at_rest = infer_select_presence(properties.get("encryption_at_rest"))
    if encrypted_at_rest is not None:
        properties["encrypted_at_rest"] = encrypted_at_rest

    has_backup = infer_select_presence(properties.get("backup_strategy"))
    if has_backup is not None:
        properties["has_backup"] = has_backup

    internet_facing = infer_internet_facing_exposure(properties.get("network_exposure"))
    if internet_facing is not None:
        properties["internet_facing"] = internet_facing

    trusted = infer_trusted_boundary(properties.get("trust_level"))
    if trusted is not None:
        properties["trusted"] = trusted

    if node_type == "human_actor":
        properties["entity_kind"] = "human"

    if infer_handles_sensitive_data(properties) is True:
        properties["handles_sensitive_data"] = True

    return properties


def _mark_json_field_dirty(instance: object, field_name: str) -> None:
    if hasattr(instance, "_sa_instance_state"):
        flag_modified(instance, field_name)


def _normalize_edge_properties(raw_properties: object | None) -> dict:
    if raw_properties is None:
        return {}
    if hasattr(raw_properties, "model_dump"):
        return raw_properties.model_dump(exclude_none=True)
    if isinstance(raw_properties, dict):
        return dict(raw_properties)
    return {}


def _normalize_seed_label(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _repository_seed_properties(suggestion: RepositoryDfdSeedSuggestion) -> dict:
    properties: dict[str, object] = {
        "component_label": suggestion.label,
        "component_description": suggestion.rationale,
        "repository_seed_id": suggestion.id,
        "repository_seed_confidence": suggestion.confidence,
        "repository_seed_source_refs": suggestion.source_refs,
    }
    if suggestion.node_type == "queue":
        properties.update(
            {
                "component_shape": "queue",
                "service_name": suggestion.label,
                "responsibility": "shared",
            }
        )
    elif suggestion.node_type == "infrastructure":
        properties.update(
            {
                "component_shape": "cloud",
                "service_name": suggestion.label,
                "responsibility": "shared",
            }
        )
    elif suggestion.node_type == "external_entity":
        properties.update(
            {
                "entity_scope": "external",
                "entity_kind": "saas",
                "trust_level": "semi_trusted",
            }
        )
    elif suggestion.node_type == "data_store":
        properties.update(
            {
                "store_type": suggestion.label,
                "encrypted_at_rest": None,
            }
        )
    else:
        properties.update({"runtime_type": "service"})
    return properties


def _repository_seed_preview(
    suggestion: RepositoryDfdSeedSuggestion,
    *,
    existing_nodes_by_name: dict[str, DFDNodeResponse | DFDNode],
    index: int,
) -> DFDRepositorySeedPreview:
    node_type = REPOSITORY_SEED_NODE_TYPES[suggestion.node_type]
    matched_node = existing_nodes_by_name.get(_normalize_seed_label(suggestion.label))
    proposed_node = DFDNodeCreate(
        node_type=node_type,  # type: ignore[arg-type]
        name=suggestion.label,
        position_x=160 + (index % 3) * 260,
        position_y=120 + (index // 3) * 150,
        properties=_repository_seed_properties(suggestion),
    )
    return DFDRepositorySeedPreview(
        suggestion_id=suggestion.id,
        label=suggestion.label,
        node_type=node_type,  # type: ignore[arg-type]
        rationale=suggestion.rationale,
        source_refs=suggestion.source_refs,
        confidence=suggestion.confidence,
        match_status="matched_existing" if matched_node else "new",
        matched_node_id=matched_node.id if matched_node else None,
        matched_node_name=matched_node.name if matched_node else None,
        proposed_node=proposed_node,
    )


def _build_repository_seed_previews(
    repository_evidence: RepositoryEvidence,
    existing_nodes: list[DFDNodeResponse | DFDNode],
) -> list[DFDRepositorySeedPreview]:
    existing_nodes_by_name = {
        _normalize_seed_label(node.name): node
        for node in existing_nodes
        if _normalize_seed_label(node.name)
    }
    return [
        _repository_seed_preview(
            suggestion,
            existing_nodes_by_name=existing_nodes_by_name,
            index=index,
        )
        for index, suggestion in enumerate(repository_evidence.dfd_seed_suggestions)
    ]


def _load_repository_evidence_for_dfd(threat_model) -> RepositoryEvidence:
    if not threat_model.repository_evidence:
        raise HTTPException(status_code=400, detail="No repository evidence is available for DFD seed suggestions.")
    try:
        return RepositoryEvidence.model_validate(threat_model.repository_evidence)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Saved repository evidence cannot be used for DFD seed suggestions because it is invalid.",
        ) from exc


def _select_primary_repository_seed_node(nodes: list[DFDNode]) -> DFDNode | None:
    for preferred_name in ("API layer", "Application service"):
        normalized = _normalize_seed_label(preferred_name)
        for node in nodes:
            if _normalize_seed_label(node.name) == normalized:
                return node
    for node in nodes:
        if node.node_type in {"process", "api_gateway"}:
            return node
    return nodes[0] if nodes else None


def _repository_seed_edge_label(node: DFDNode) -> str:
    if node.node_type == "data_store":
        return "stores and retrieves data"
    if node.node_type == "external_entity":
        return "calls external system"
    if node.properties.get("component_shape") == "queue":
        return "publishes or consumes events"
    if node.node_type == "managed_service":
        return "runs on or depends on"
    return "connects to"


def _repository_seed_flow_edge_properties(flow: RepositoryDfdSeedFlowSuggestion) -> dict:
    return _normalize_edge_properties(
        {
            "protocol": "Repository evidence",
            "directionality": flow.directionality,
            "transfer_mode": flow.transfer_mode,
            "lifecycle_stage": flow.lifecycle_stage,
            "sequence_note": flow.rationale,
            "repository_seed_flow_id": flow.id,
            "repository_seed_confidence": flow.confidence,
            "repository_seed_source_refs": flow.source_refs,
        }
    )


def _repository_seed_boundary_member_nodes(
    boundary: RepositoryDfdSeedBoundarySuggestion,
    applied_nodes_by_seed_id: dict[str, DFDNode],
) -> list[DFDNode]:
    member_nodes: list[DFDNode] = []
    seen_node_ids: set[UUID] = set()
    for seed_id in boundary.seed_ids:
        node = applied_nodes_by_seed_id.get(seed_id)
        if node is None or node.trust_boundary_id is not None or node.id in seen_node_ids:
            continue
        member_nodes.append(node)
        seen_node_ids.add(node.id)
    return member_nodes


def _build_dfd_response(
    nodes: list[DFDNode],
    edges: list[DFDEdge],
    boundaries: list[TrustBoundary],
) -> DFDResponse:
    return DFDResponse(
        nodes=[DFDNodeResponse.model_validate(node) for node in nodes],
        edges=[DFDEdgeResponse.model_validate(edge) for edge in edges],
        trust_boundaries=[
            TrustBoundaryResponse.model_validate(boundary) for boundary in boundaries
        ],
    )


async def _load_dfd_response(db: AsyncSession, threat_model_id: UUID) -> DFDResponse:
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    nodes = nodes_result.scalars().all()
    edges = edges_result.scalars().all()
    boundaries = boundaries_result.scalars().all()
    return _build_dfd_response(nodes, edges, boundaries)


async def _persist_root_dfd(
    db: AsyncSession,
    threat_model_id: UUID,
    materialized_dfd: DFDResponse,
) -> DFDResponse:
    node_payloads = [
        {
            "id": node.id,
            "node_type": node.node_type,
            "name": node.name,
            "position_x": node.position_x,
            "position_y": node.position_y,
            "trust_boundary_id": node.trust_boundary_id,
            "scan_target_url": node.scan_target_url,
            "scan_target_ports": node.scan_target_ports,
            "properties": node.properties,
        }
        for node in materialized_dfd.nodes
    ]
    boundary_payloads = [
        {
            "id": boundary.id,
            "name": boundary.name,
            "node_ids": list(boundary.node_ids),
            "position_x": boundary.position_x,
            "position_y": boundary.position_y,
            "width": boundary.width,
            "height": boundary.height,
            "boundary_type": boundary.boundary_type,
            "parent_boundary_id": boundary.parent_boundary_id,
        }
        for boundary in materialized_dfd.trust_boundaries
    ]
    edge_payloads = [
        {
            "id": edge.id,
            "source_node_id": edge.source_node_id,
            "target_node_id": edge.target_node_id,
            "label": edge.label,
            "properties": _normalize_edge_properties(edge.properties),
        }
        for edge in materialized_dfd.edges
    ]

    await db.execute(delete(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id))
    await db.execute(delete(DFDNode).where(DFDNode.threat_model_id == threat_model_id))
    await db.execute(delete(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id))

    db_boundaries: list[TrustBoundary] = []
    for boundary_payload in boundary_payloads:
        boundary = TrustBoundary(
            id=boundary_payload["id"],
            threat_model_id=threat_model_id,
            name=boundary_payload["name"],
            node_ids=boundary_payload["node_ids"],
            position_x=boundary_payload["position_x"],
            position_y=boundary_payload["position_y"],
            width=boundary_payload["width"],
            height=boundary_payload["height"],
            boundary_type=boundary_payload["boundary_type"],
            parent_boundary_id=boundary_payload["parent_boundary_id"],
        )
        db.add(boundary)
        db_boundaries.append(boundary)
    await db.flush()

    db_nodes: list[DFDNode] = []
    for node_payload in node_payloads:
        node = DFDNode(
            id=node_payload["id"],
            threat_model_id=threat_model_id,
            node_type=node_payload["node_type"],
            name=node_payload["name"],
            position_x=node_payload["position_x"],
            position_y=node_payload["position_y"],
            trust_boundary_id=node_payload["trust_boundary_id"],
            scan_target_url=node_payload["scan_target_url"],
            scan_target_ports=node_payload["scan_target_ports"],
            properties=node_payload["properties"],
        )
        db.add(node)
        db_nodes.append(node)
    await db.flush()

    db_edges: list[DFDEdge] = []
    for edge_payload in edge_payloads:
        edge = DFDEdge(
            id=edge_payload["id"],
            threat_model_id=threat_model_id,
            source_node_id=edge_payload["source_node_id"],
            target_node_id=edge_payload["target_node_id"],
            label=edge_payload["label"],
            properties=edge_payload["properties"],
        )
        db.add(edge)
        db_edges.append(edge)

    dfd_response = _build_dfd_response(db_nodes, db_edges, db_boundaries)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is not None:
        threat_model.dfd_views = sync_default_views(
            getattr(threat_model, "dfd_views", None),
            dfd_response,
        )
        _mark_json_field_dirty(threat_model, "dfd_views")

    await db.commit()

    for node in db_nodes:
        await db.refresh(node)
    for edge in db_edges:
        await db.refresh(edge)
    for boundary in db_boundaries:
        await db.refresh(boundary)

    return dfd_response


async def _sync_persisted_views(
    db: AsyncSession,
    threat_model,
    dfd: DFDResponse,
) -> list[DFDViewResponse]:
    current_raw_views = getattr(threat_model, "dfd_views", None)
    next_raw_views = sync_default_views(current_raw_views, dfd)
    if current_raw_views != next_raw_views:
        threat_model.dfd_views = next_raw_views
        _mark_json_field_dirty(threat_model, "dfd_views")
        await db.commit()
        await db.refresh(threat_model)
    return load_view_responses(threat_model.dfd_views or next_raw_views)


async def _load_threat_model_views_and_root_dfd(
    db: AsyncSession,
    threat_model_id: UUID,
):
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    root_dfd = await _load_dfd_response(db, threat_model_id)
    views = await _sync_persisted_views(db, threat_model, root_dfd)
    return threat_model, root_dfd, views


def _resolve_requested_view(
    views: list[DFDViewResponse],
    view_id: UUID | None,
) -> DFDViewResponse | None:
    if view_id is None:
        return None
    view = find_view_response(views, view_id)
    if view is None:
        raise HTTPException(status_code=404, detail="DFD view not found")
    return view


async def _load_editable_view_context(
    db: AsyncSession,
    threat_model_id: UUID,
    view_id: UUID | None,
):
    threat_model, root_dfd, views = await _load_threat_model_views_and_root_dfd(db, threat_model_id)
    selected_view = _resolve_requested_view(views, view_id)
    if selected_view is not None and not is_editable_view(selected_view):
        raise HTTPException(status_code=400, detail="This DFD view is read only")
    return threat_model, root_dfd, views, selected_view


def _get_graph_for_view(
    root_dfd: DFDResponse,
    view: DFDViewResponse | None,
) -> DFDResponse:
    if not is_custom_graph_view(view):
        return root_dfd
    return get_view_graph(view)


def _build_default_workspace_name(views: list[DFDViewResponse]) -> str:
    existing_names = {view.name.strip().casefold() for view in views}
    counter = 1
    while True:
        candidate = f"DFD Workspace {counter}"
        if candidate.casefold() not in existing_names:
            return candidate
        counter += 1


def _find_node_in_dfd(dfd: DFDResponse, node_id: UUID) -> DFDNodeResponse | None:
    return next((node for node in dfd.nodes if node.id == node_id), None)


def _find_edge_in_dfd(dfd: DFDResponse, edge_id: UUID) -> DFDEdgeResponse | None:
    return next((edge for edge in dfd.edges if edge.id == edge_id), None)


def _find_boundary_in_dfd(dfd: DFDResponse, boundary_id: UUID) -> TrustBoundaryResponse | None:
    return next((boundary for boundary in dfd.trust_boundaries if boundary.id == boundary_id), None)


def _sync_node_boundary_membership_in_dfd(
    dfd: DFDResponse,
    node: DFDNodeResponse,
    new_boundary_id: UUID | None,
) -> None:
    if new_boundary_id is not None and _find_boundary_in_dfd(dfd, new_boundary_id) is None:
        raise HTTPException(status_code=400, detail=INVALID_BOUNDARY_REFERENCE)

    for boundary in dfd.trust_boundaries:
        boundary.node_ids = [existing_id for existing_id in boundary.node_ids if existing_id != node.id]

    node.trust_boundary_id = new_boundary_id

    if new_boundary_id is not None:
        boundary = _find_boundary_in_dfd(dfd, new_boundary_id)
        if boundary is None:
            raise HTTPException(status_code=400, detail=INVALID_BOUNDARY_REFERENCE)
        if node.id not in boundary.node_ids:
            boundary.node_ids = [*boundary.node_ids, node.id]


def _materialize_dfd_response_from_bulk_save(data: DFDBulkSave) -> DFDResponse:
    node_payloads = [
        {
            "id": node_data.id or uuid4(),
            "node_type": node_data.node_type,
            "name": node_data.name,
            "position_x": node_data.position_x,
            "position_y": node_data.position_y,
            "trust_boundary_id": node_data.trust_boundary_id,
            "scan_target_url": node_data.scan_target_url,
            "scan_target_ports": node_data.scan_target_ports,
            "properties": _normalize_node_properties(node_data.properties, node_type=node_data.node_type),
        }
        for node_data in data.nodes
    ]
    node_payloads_by_id = {payload["id"]: payload for payload in node_payloads}
    boundary_payloads = [
        {
            "id": boundary_data.id or uuid4(),
            "name": boundary_data.name,
            "node_ids": list(boundary_data.node_ids),
            "position_x": boundary_data.position_x,
            "position_y": boundary_data.position_y,
            "width": boundary_data.width,
            "height": boundary_data.height,
            "boundary_type": boundary_data.boundary_type,
            "parent_boundary_id": boundary_data.parent_boundary_id,
        }
        for boundary_data in data.trust_boundaries
    ]
    edge_payloads = [
        {
            "id": edge_data.id or uuid4(),
            "source_node_id": edge_data.source_node_id,
            "target_node_id": edge_data.target_node_id,
            "label": edge_data.label,
            "properties": _normalize_edge_properties(edge_data.properties),
        }
        for edge_data in data.edges
    ]

    node_ids = {payload["id"] for payload in node_payloads}
    boundary_ids = {payload["id"] for payload in boundary_payloads}
    edge_ids = {payload["id"] for payload in edge_payloads}

    if len(node_ids) != len(node_payloads):
        raise HTTPException(status_code=400, detail="DFD payload contains duplicate node IDs")
    if len(boundary_ids) != len(boundary_payloads):
        raise HTTPException(status_code=400, detail="DFD payload contains duplicate boundary IDs")
    if len(edge_ids) != len(edge_payloads):
        raise HTTPException(status_code=400, detail="DFD payload contains duplicate edge IDs")

    node_payloads_by_id = {payload["id"]: payload for payload in node_payloads}
    invalid_boundary_refs = {
        payload["trust_boundary_id"]
        for payload in node_payloads
        if payload["trust_boundary_id"] is not None
        and payload["trust_boundary_id"] not in boundary_ids
    }
    if invalid_boundary_refs:
        raise HTTPException(status_code=400, detail="DFD payload contains invalid trust boundary references")

    invalid_edge_refs = [
        payload
        for payload in edge_payloads
        if payload["source_node_id"] not in node_ids
        or payload["target_node_id"] not in node_ids
    ]
    if invalid_edge_refs:
        raise HTTPException(status_code=400, detail="DFD payload contains invalid edge node references")

    invalid_boundary_nodes = [
        payload
        for payload in boundary_payloads
        if any(node_id not in node_ids for node_id in payload["node_ids"])
    ]
    if invalid_boundary_nodes:
        raise HTTPException(status_code=400, detail="DFD payload contains invalid boundary node references")

    invalid_parent_boundary_refs = [
        payload
        for payload in boundary_payloads
        if payload["parent_boundary_id"] is not None
        and payload["parent_boundary_id"] not in boundary_ids
    ]
    if invalid_parent_boundary_refs:
        raise HTTPException(status_code=400, detail="DFD payload contains invalid parent boundary references")

    self_parent_refs = [
        payload
        for payload in boundary_payloads
        if payload["parent_boundary_id"] is not None
        and payload["parent_boundary_id"] == payload["id"]
    ]
    if self_parent_refs:
        raise HTTPException(status_code=400, detail="DFD payload contains self-referential parent boundary references")

    _ensure_no_boundary_parent_cycles(
        {
            payload["id"]: payload["parent_boundary_id"]
            for payload in boundary_payloads
        },
        detail="DFD payload contains cyclic parent boundary references",
    )

    for boundary_payload in boundary_payloads:
        geometry = _resolve_boundary_geometry(
            position_x=boundary_payload["position_x"],
            position_y=boundary_payload["position_y"],
            width=boundary_payload["width"],
            height=boundary_payload["height"],
            node_positions=(
                (
                    node_payloads_by_id[node_id]["position_x"],
                    node_payloads_by_id[node_id]["position_y"],
                )
                for node_id in boundary_payload["node_ids"]
                if node_id in node_payloads_by_id
            ),
        )
        (
            boundary_payload["position_x"],
            boundary_payload["position_y"],
            boundary_payload["width"],
            boundary_payload["height"],
        ) = geometry

    return DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=payload["id"],
                node_type=payload["node_type"],
                name=payload["name"],
                position_x=payload["position_x"],
                position_y=payload["position_y"],
                trust_boundary_id=payload["trust_boundary_id"],
                scan_target_url=payload["scan_target_url"],
                scan_target_ports=payload["scan_target_ports"],
                properties=payload["properties"],
            )
            for payload in node_payloads
        ],
        edges=[
            DFDEdgeResponse(
                id=payload["id"],
                source_node_id=payload["source_node_id"],
                target_node_id=payload["target_node_id"],
                label=payload["label"],
                properties=payload["properties"],
            )
            for payload in edge_payloads
        ],
        trust_boundaries=[
            TrustBoundaryResponse(
                id=payload["id"],
                name=payload["name"],
                node_ids=payload["node_ids"],
                position_x=payload["position_x"],
                position_y=payload["position_y"],
                width=payload["width"],
                height=payload["height"],
                boundary_type=payload["boundary_type"],
                parent_boundary_id=payload["parent_boundary_id"],
            )
            for payload in boundary_payloads
        ],
    )


def _build_decomposition_seed_graph(
    parent_node: DFDNodeResponse,
    parent_graph: DFDResponse,
) -> DFDResponse:
    if parent_node.node_type == "container":
        return _build_container_decomposition_seed_graph(parent_node, parent_graph)

    center_node_id = uuid4()
    connected_edges = [
        edge
        for edge in parent_graph.edges
        if edge.source_node_id == parent_node.id or edge.target_node_id == parent_node.id
    ]
    counterpart_nodes = {}
    incoming_counterparts: list[DFDNodeResponse] = []
    outgoing_counterparts: list[DFDNodeResponse] = []

    for edge in connected_edges:
        counterpart_id = edge.target_node_id if edge.source_node_id == parent_node.id else edge.source_node_id
        counterpart = _find_node_in_dfd(parent_graph, counterpart_id)
        if counterpart is None:
            continue
        counterpart_nodes[counterpart.id] = counterpart
        if edge.source_node_id == counterpart.id:
            incoming_counterparts.append(counterpart)
        else:
            outgoing_counterparts.append(counterpart)

    unique_incoming = list(dict.fromkeys(node.id for node in incoming_counterparts))
    unique_outgoing = list(dict.fromkeys(node.id for node in outgoing_counterparts))
    clone_id_by_parent_id: dict[UUID, UUID] = {}
    seeded_nodes: list[DFDNodeResponse] = [
        DFDNodeResponse(
            id=center_node_id,
            node_type=parent_node.node_type,
            name=f"{parent_node.name} Internal",
            position_x=280,
            position_y=180,
            trust_boundary_id=None,
            properties=parent_node.properties,
        )
    ]

    for index, counterpart_id in enumerate(unique_incoming):
        counterpart = counterpart_nodes[counterpart_id]
        clone_id = uuid4()
        clone_id_by_parent_id[counterpart.id] = clone_id
        seeded_nodes.append(
            DFDNodeResponse(
                id=clone_id,
                node_type=counterpart.node_type,
                name=counterpart.name,
                position_x=40,
                position_y=60 + index * 110,
                trust_boundary_id=None,
                properties=counterpart.properties,
            )
        )

    for index, counterpart_id in enumerate(unique_outgoing):
        counterpart = counterpart_nodes[counterpart_id]
        if counterpart.id in clone_id_by_parent_id:
            continue
        clone_id = uuid4()
        clone_id_by_parent_id[counterpart.id] = clone_id
        seeded_nodes.append(
            DFDNodeResponse(
                id=clone_id,
                node_type=counterpart.node_type,
                name=counterpart.name,
                position_x=520,
                position_y=60 + index * 110,
                trust_boundary_id=None,
                properties=counterpart.properties,
            )
        )

    seeded_edges: list[DFDEdgeResponse] = []
    for edge in connected_edges:
        counterpart_id = edge.target_node_id if edge.source_node_id == parent_node.id else edge.source_node_id
        clone_id = clone_id_by_parent_id.get(counterpart_id)
        if clone_id is None:
            continue
        seeded_edges.append(
            DFDEdgeResponse(
                id=uuid4(),
                source_node_id=center_node_id if edge.source_node_id == parent_node.id else clone_id,
                target_node_id=clone_id if edge.source_node_id == parent_node.id else center_node_id,
                label=edge.label,
                properties=edge.properties,
            )
        )

    return DFDResponse(nodes=seeded_nodes, edges=seeded_edges, trust_boundaries=[])


def _build_container_decomposition_seed_graph(
    parent_node: DFDNodeResponse,
    parent_graph: DFDResponse,
) -> DFDResponse:
    runtime_boundary_id = uuid4()
    workload_node_id = uuid4()
    sidecar_node_id = uuid4()
    secrets_node_id = uuid4()

    connected_edges = [
        edge
        for edge in parent_graph.edges
        if edge.source_node_id == parent_node.id or edge.target_node_id == parent_node.id
    ]
    counterpart_nodes: dict[UUID, DFDNodeResponse] = {}
    incoming_counterparts: list[DFDNodeResponse] = []
    outgoing_counterparts: list[DFDNodeResponse] = []

    for edge in connected_edges:
        counterpart_id = (
            edge.target_node_id
            if edge.source_node_id == parent_node.id
            else edge.source_node_id
        )
        counterpart = _find_node_in_dfd(parent_graph, counterpart_id)
        if counterpart is None:
            continue
        counterpart_nodes[counterpart.id] = counterpart
        if edge.source_node_id == counterpart.id:
            incoming_counterparts.append(counterpart)
        else:
            outgoing_counterparts.append(counterpart)

    unique_incoming = list(dict.fromkeys(node.id for node in incoming_counterparts))
    unique_outgoing = list(dict.fromkeys(node.id for node in outgoing_counterparts))
    clone_id_by_parent_id: dict[UUID, UUID] = {}

    seeded_nodes: list[DFDNodeResponse] = [
        DFDNodeResponse(
            id=workload_node_id,
            node_type="process",
            name=f"{parent_node.name} Workload",
            position_x=260,
            position_y=150,
            trust_boundary_id=runtime_boundary_id,
            properties={
                **(parent_node.properties or {}),
                "runtime_type": "container",
                "isolation_boundary": (
                    (parent_node.properties or {}).get("isolation_boundary")
                    or "container"
                ),
            },
        ),
        DFDNodeResponse(
            id=sidecar_node_id,
            node_type="process",
            name="Telemetry / Policy Sidecar",
            position_x=260,
            position_y=270,
            trust_boundary_id=runtime_boundary_id,
            properties={
                "runtime_type": "worker",
                "logging_level": "audit",
                "network_exposure": "internal",
            },
        ),
        DFDNodeResponse(
            id=secrets_node_id,
            node_type="managed_service",
            name="Secrets / Config",
            position_x=520,
            position_y=210,
            trust_boundary_id=None,
            properties={
                "service_name": "Secrets Store",
                "stores_secrets": True,
                "responsibility": "provider",
                "network_exposure": "internal",
            },
        ),
    ]

    for index, counterpart_id in enumerate(unique_incoming):
        counterpart = counterpart_nodes[counterpart_id]
        clone_id = uuid4()
        clone_id_by_parent_id[counterpart.id] = clone_id
        seeded_nodes.append(
            DFDNodeResponse(
                id=clone_id,
                node_type=counterpart.node_type,
                name=counterpart.name,
                position_x=40,
                position_y=60 + index * 110,
                trust_boundary_id=None,
                properties=counterpart.properties,
            )
        )

    for index, counterpart_id in enumerate(unique_outgoing):
        counterpart = counterpart_nodes[counterpart_id]
        if counterpart.id in clone_id_by_parent_id:
            continue
        clone_id = uuid4()
        clone_id_by_parent_id[counterpart.id] = clone_id
        seeded_nodes.append(
            DFDNodeResponse(
                id=clone_id,
                node_type=counterpart.node_type,
                name=counterpart.name,
                position_x=760,
                position_y=60 + index * 110,
                trust_boundary_id=None,
                properties=counterpart.properties,
            )
        )

    seeded_edges: list[DFDEdgeResponse] = [
        DFDEdgeResponse(
            id=uuid4(),
            source_node_id=workload_node_id,
            target_node_id=sidecar_node_id,
            label="policy + telemetry",
            properties={"protocol": "localhost"},
        ),
        DFDEdgeResponse(
            id=uuid4(),
            source_node_id=workload_node_id,
            target_node_id=secrets_node_id,
            label="load secrets / config",
            properties={"protocol": "TLS", "carries_secrets": True},
        ),
    ]

    for edge in connected_edges:
        counterpart_id = (
            edge.target_node_id
            if edge.source_node_id == parent_node.id
            else edge.source_node_id
        )
        clone_id = clone_id_by_parent_id.get(counterpart_id)
        if clone_id is None:
            continue
        seeded_edges.append(
            DFDEdgeResponse(
                id=uuid4(),
                source_node_id=(
                    workload_node_id
                    if edge.source_node_id == parent_node.id
                    else clone_id
                ),
                target_node_id=(
                    clone_id
                    if edge.source_node_id == parent_node.id
                    else workload_node_id
                ),
                label=edge.label,
                properties=edge.properties,
            )
        )

    return DFDResponse(
        nodes=seeded_nodes,
        edges=seeded_edges,
        trust_boundaries=[
            TrustBoundaryResponse(
                id=runtime_boundary_id,
                name=f"{parent_node.name} Runtime Boundary",
                node_ids=[workload_node_id, sidecar_node_id],
                position_x=210,
                position_y=110,
                width=320,
                height=260,
                boundary_type="cloud",
                parent_boundary_id=None,
            )
        ],
    )


async def _persist_custom_views(
    db: AsyncSession,
    *,
    threat_model,
    root_dfd: DFDResponse,
    views: list[DFDViewResponse],
) -> list[DFDViewResponse]:
    threat_model.dfd_views = sync_default_views(serialize_view_responses(views), root_dfd)
    _mark_json_field_dirty(threat_model, "dfd_views")
    await db.commit()
    await db.refresh(threat_model)
    return load_view_responses(threat_model.dfd_views)


# ─── GET DFD ───────────────────────────────────────────────────────────


@router.get("", response_model=DFDResponse)
async def get_dfd(
    threat_model_id: UUID,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDResponse:
    """Get the DFD for a threat model. Returns empty lists if no DFD data exists."""
    await _verify_threat_model(db, threat_model_id, current_user, permission="read")
    if view_id is None:
        return await _load_dfd_response(db, threat_model_id)
    threat_model, root_dfd, views = await _load_threat_model_views_and_root_dfd(db, threat_model_id)
    _ = threat_model
    selected_view = _resolve_requested_view(views, view_id)
    return _get_graph_for_view(root_dfd, selected_view)


@router.get("/views", response_model=list[DFDViewResponse])
async def get_dfd_views(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DFDViewResponse]:
    await _verify_threat_model(db, threat_model_id, current_user, permission="read")
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    dfd = await _load_dfd_response(db, threat_model_id)
    return await _sync_persisted_views(db, threat_model, dfd)


@router.post("/views/regenerate", response_model=list[DFDViewResponse])
async def regenerate_dfd_views(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DFDViewResponse]:
    await _verify_threat_model(db, threat_model_id, current_user, permission="read")
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    dfd = await _load_dfd_response(db, threat_model_id)
    return await _sync_persisted_views(db, threat_model, dfd)


@router.patch("/views/{view_id}", response_model=DFDViewResponse)
async def update_dfd_view(
    threat_model_id: UUID,
    view_id: UUID,
    data: DFDViewUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDViewResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    views = load_view_responses(threat_model.dfd_views)
    updated_view: DFDViewResponse | None = None
    next_views: list[dict] = []
    for view in views:
        if view.id != view_id:
            next_views.append(view.model_dump(mode="json"))
            continue
        updated_view = DFDViewResponse(
            id=view.id,
            view_type=view.view_type,
            name=data.name.strip() if data.name is not None and data.name.strip() else view.name,
            node_ids=view.node_ids,
            edge_ids=view.edge_ids,
            boundary_ids=view.boundary_ids,
            layout_snapshot=data.layout_snapshot or view.layout_snapshot,
            parent_view_id=view.parent_view_id,
            parent_node_id=view.parent_node_id,
            graph=view.graph,
            is_auto_generated=view.is_auto_generated,
        )
        next_views.append(updated_view.model_dump(mode="json"))

    if updated_view is None:
        raise HTTPException(status_code=404, detail="DFD view not found")

    threat_model.dfd_views = next_views
    _mark_json_field_dirty(threat_model, "dfd_views")
    await db.commit()
    await db.refresh(threat_model)
    return updated_view


@router.post("/views/decompositions", response_model=DFDViewResponse, status_code=201)
async def create_decomposition_view(
    threat_model_id: UUID,
    data: DFDDecompositionViewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDViewResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model, root_dfd, views = await _load_threat_model_views_and_root_dfd(db, threat_model_id)

    parent_view = _resolve_requested_view(views, data.parent_view_id)
    if not is_editable_view(parent_view):
        raise HTTPException(status_code=400, detail="Decomposition can only be created from an editable DFD view")

    parent_graph = _get_graph_for_view(root_dfd, parent_view)
    parent_node = _find_node_in_dfd(parent_graph, data.parent_node_id)
    if parent_node is None:
        raise HTTPException(status_code=404, detail="Parent node not found in the selected DFD view")
    if not is_decomposable_node_type(parent_node.node_type):
        raise HTTPException(status_code=400, detail="Only process-like nodes can be decomposed")

    existing_view = next(
        (
            view
            for view in views
            if view.view_type == "decomposition"
            and view.parent_view_id == (parent_view.id if parent_view is not None else None)
            and view.parent_node_id == parent_node.id
        ),
        None,
    )
    if existing_view is not None:
        return existing_view

    decomposition_view = DFDViewResponse(
        id=uuid4(),
        view_type="decomposition",
        name=data.name.strip() if data.name and data.name.strip() else f"{parent_node.name} Decomposition",
        node_ids=[],
        edge_ids=[],
        boundary_ids=[],
        layout_snapshot=DFDViewLayoutSnapshot(),
        parent_view_id=parent_view.id if parent_view is not None else None,
        parent_node_id=parent_node.id,
        graph=_build_decomposition_seed_graph(parent_node, parent_graph),
        is_auto_generated=False,
    )

    next_views = [*views, decomposition_view]
    persisted_views = await _persist_custom_views(
        db,
        threat_model=threat_model,
        root_dfd=root_dfd,
        views=next_views,
    )
    created_view = find_view_response(persisted_views, decomposition_view.id)
    if created_view is None:
        raise HTTPException(status_code=500, detail="Failed to persist decomposition view")
    return created_view


@router.post("/views/workspaces", response_model=DFDViewResponse, status_code=201)
async def create_workspace_view(
    threat_model_id: UUID,
    data: DFDWorkspaceViewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDViewResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model, root_dfd, views = await _load_threat_model_views_and_root_dfd(db, threat_model_id)

    source_view = _resolve_requested_view(views, data.source_view_id)
    workspace_graph = (
        clone_dfd_response(_get_graph_for_view(root_dfd, source_view))
        if source_view is not None
        else empty_dfd_response()
    )
    workspace_view = DFDViewResponse(
        id=uuid4(),
        view_type="workspace",
        name=data.name.strip() or _build_default_workspace_name(views),
        node_ids=[],
        edge_ids=[],
        boundary_ids=[],
        layout_snapshot=DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=workspace_graph,
        is_auto_generated=False,
    )

    persisted_views = await _persist_custom_views(
        db,
        threat_model=threat_model,
        root_dfd=root_dfd,
        views=[*views, workspace_view],
    )
    created_view = find_view_response(persisted_views, workspace_view.id)
    if created_view is None:
        raise HTTPException(status_code=500, detail="Failed to persist workspace view")
    return created_view


@router.get("/quality-gates", response_model=DFDQualityGateSummary)
async def get_dfd_quality_gates(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDQualityGateSummary:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    dfd = await _load_dfd_response(db, threat_model_id)
    views = await _sync_persisted_views(db, threat_model, dfd)
    return evaluate_quality_gates(dfd, views)

@router.get("/component-templates", response_model=list[DFDComponentTemplateResponse])
async def get_component_templates(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DFDComponentTemplateResponse]:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    return list_component_templates(threat_model.dfd_component_templates)
    return list_component_templates(threat_model.dfd_component_templates)


@router.post(
    "/component-templates",
    response_model=DFDComponentTemplateResponse,
    status_code=201,
)
async def create_dfd_component_template(
    threat_model_id: UUID,
    data: DFDComponentTemplateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDComponentTemplateResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    try:
        template, next_templates = create_component_template(
            threat_model.dfd_component_templates,
            data,
        )
    except ValueError as exc:
        detail = str(exc)
        status_code = 409 if "already exists" in detail.lower() else 400
        raise HTTPException(status_code=status_code, detail=detail) from exc

    threat_model.dfd_component_templates = next_templates
    _mark_json_field_dirty(threat_model, "dfd_component_templates")
    await db.commit()
    await db.refresh(threat_model)
    return template


@router.post(
    "/component-templates/suggest",
    response_model=DFDComponentTemplateSuggestResponse,
)
async def suggest_dfd_component_template(
    threat_model_id: UUID,
    data: DFDComponentTemplateSuggestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDComponentTemplateSuggestResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    return suggest_component_template(
        user_id=current_user.id,
        prompt=data.prompt,
        threat_model_name=threat_model.system_name,
        threat_model_description=threat_model.description or "",
        raw_templates=threat_model.dfd_component_templates,
    )


@router.delete("/component-templates/{template_id}", status_code=204)
async def delete_dfd_component_template(
    threat_model_id: UUID,
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    try:
        deleted, next_templates = delete_component_template(
            threat_model.dfd_component_templates,
            template_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not deleted:
        raise HTTPException(status_code=404, detail="Component template not found")

    threat_model.dfd_component_templates = next_templates or None
    _mark_json_field_dirty(threat_model, "dfd_component_templates")
    await db.commit()
    return Response(status_code=204)


@router.get("/property-options", response_model=list[DFDPropertyOptionResponse])
async def get_dfd_property_options(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DFDPropertyOptionResponse]:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    return list_property_options(threat_model.dfd_property_options)


@router.post(
    "/property-options",
    response_model=DFDPropertyOptionResponse,
    status_code=201,
)
async def create_dfd_property_option(
    threat_model_id: UUID,
    data: DFDPropertyOptionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDPropertyOptionResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    try:
        option, next_options = create_property_option(
            threat_model.dfd_property_options,
            data,
        )
    except ValueError as exc:
        detail = str(exc)
        status_code = 409 if "already exists" in detail.lower() else 400
        raise HTTPException(status_code=status_code, detail=detail) from exc

    threat_model.dfd_property_options = next_options
    _mark_json_field_dirty(threat_model, "dfd_property_options")
    await db.commit()
    await db.refresh(threat_model)
    return option


@router.post(
    "/property-options/suggest",
    response_model=DFDPropertyOptionSuggestResponse,
)
async def suggest_dfd_property_option(
    threat_model_id: UUID,
    data: DFDPropertyOptionSuggestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDPropertyOptionSuggestResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    return suggest_property_option(
        user_id=current_user.id,
        field=data.field,
        prompt=data.prompt,
        threat_model_name=threat_model.system_name,
        threat_model_description=threat_model.description or "",
        raw_options=threat_model.dfd_property_options,
    )


@router.delete("/property-options/{option_id}", status_code=204)
async def delete_dfd_property_option(
    threat_model_id: UUID,
    option_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    deleted, next_options = delete_property_option(
        threat_model.dfd_property_options,
        option_id,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Property option not found")

    threat_model.dfd_property_options = next_options or None
    _mark_json_field_dirty(threat_model, "dfd_property_options")
    await db.commit()
    return Response(status_code=204)


@router.post("/import-iac", response_model=DFDIacImportResponse)
async def import_iac_into_dfd(
    threat_model_id: UUID,
    data: DFDIacImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDIacImportResponse:
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    if not getattr(threat_model, "iac_evidence", None):
        raise HTTPException(status_code=400, detail="No IaC evidence available to import")

    iac_evidence = IacEvidence.model_validate(threat_model.iac_evidence)
    current_dfd = await _load_dfd_response(db, threat_model_id)
    if data.mode == "merge":
        existing_nodes = list(current_dfd.nodes)
        x_offset = (
            max((node.position_x for node in existing_nodes), default=0.0) + 280.0
            if existing_nodes
            else 0.0
        )
        draft = build_iac_import_draft(iac_evidence, x_offset=x_offset)
        if draft.semantic_resource_count == 0:
            raise HTTPException(status_code=400, detail="IaC evidence did not produce any importable DFD components")
        merged_dfd, summary = merge_iac_import_into_dfd(current_dfd, draft)
        persisted = await _persist_root_dfd(db, threat_model_id, merged_dfd)
        response_summary = summary
    else:
        draft = build_iac_import_draft(iac_evidence)
        if draft.semantic_resource_count == 0:
            raise HTTPException(status_code=400, detail="IaC evidence did not produce any importable DFD components")
        persisted = await _persist_root_dfd(db, threat_model_id, draft.dfd)
        response_summary = ServiceDFDIacImportSummary(
            mode="replace",
            imported_resource_count=draft.imported_resource_count,
            semantic_resource_count=draft.semantic_resource_count,
            matched_existing_nodes=0,
            created_nodes=len(draft.dfd.nodes),
            updated_nodes=0,
            created_edges=len(draft.dfd.edges),
            created_boundaries=len(draft.dfd.trust_boundaries),
            warnings=draft.warnings,
        )

    return DFDIacImportResponse(
        dfd=persisted,
        summary=DFDIacImportSummary(
            mode=response_summary.mode,
            imported_resource_count=response_summary.imported_resource_count,
            semantic_resource_count=response_summary.semantic_resource_count,
            matched_existing_nodes=response_summary.matched_existing_nodes,
            created_nodes=response_summary.created_nodes,
            updated_nodes=response_summary.updated_nodes,
            created_edges=response_summary.created_edges,
            created_boundaries=response_summary.created_boundaries,
            warnings=response_summary.warnings,
        ),
    )


@router.get("/repository-suggestions", response_model=DFDRepositorySeedPreviewResponse)
async def preview_repository_dfd_suggestions(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDRepositorySeedPreviewResponse:
    """Preview repository-derived DFD nodes without changing the diagram."""
    await _verify_threat_model(db, threat_model_id, current_user, permission="read")
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    repository_evidence = _load_repository_evidence_for_dfd(threat_model)
    current_dfd = await _load_dfd_response(db, threat_model_id)
    suggestions = _build_repository_seed_previews(repository_evidence, current_dfd.nodes)
    return DFDRepositorySeedPreviewResponse(
        suggestions=suggestions,
        existing_node_count=len(current_dfd.nodes),
        unmatched_suggestion_count=sum(
            1 for suggestion in suggestions if suggestion.match_status == "new"
        ),
        inferred_flow_count=len(repository_evidence.dfd_seed_flow_suggestions),
        inferred_boundary_count=len(repository_evidence.dfd_seed_boundary_suggestions),
    )


@router.post("/repository-suggestions/apply", response_model=DFDRepositorySeedApplyResponse)
async def apply_repository_dfd_suggestions(
    threat_model_id: UUID,
    data: DFDRepositorySeedApplyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDRepositorySeedApplyResponse:
    """Apply selected repository-derived DFD seed suggestions in one transaction."""
    await _verify_threat_model(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    repository_evidence = _load_repository_evidence_for_dfd(threat_model)

    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    nodes = list(nodes_result.scalars().all())
    edges = list(edges_result.scalars().all())
    boundaries = list(boundaries_result.scalars().all())
    previews = _build_repository_seed_previews(repository_evidence, nodes)
    previews_by_id = {preview.suggestion_id: preview for preview in previews}
    applied_nodes_by_seed_id: dict[str, DFDNode] = {}
    for preview in previews:
        if preview.match_status != "matched_existing" or preview.matched_node_id is None:
            continue
        matched_node = next((node for node in nodes if node.id == preview.matched_node_id), None)
        if matched_node is not None:
            applied_nodes_by_seed_id[preview.suggestion_id] = matched_node
    requested_ids = data.suggestion_ids or [
        preview.suggestion_id for preview in previews if preview.match_status == "new"
    ]
    requested_id_set = set(requested_ids)
    skipped_suggestions = [
        suggestion_id
        for suggestion_id in requested_ids
        if suggestion_id not in previews_by_id
    ]

    matched_existing_nodes = 0
    created_nodes: list[DFDNode] = []
    for preview in previews:
        if preview.suggestion_id not in requested_id_set:
            continue
        if preview.match_status == "matched_existing":
            matched_existing_nodes += 1
            continue
        node = DFDNode(
            id=uuid4(),
            threat_model_id=threat_model_id,
            node_type=preview.proposed_node.node_type,
            name=preview.proposed_node.name,
            position_x=preview.proposed_node.position_x,
            position_y=preview.proposed_node.position_y,
            trust_boundary_id=None,
            scan_target_url=preview.proposed_node.scan_target_url,
            scan_target_ports=preview.proposed_node.scan_target_ports,
            properties=_normalize_node_properties(
                preview.proposed_node.properties,
                node_type=preview.proposed_node.node_type,
            ),
        )
        db.add(node)
        nodes.append(node)
        created_nodes.append(node)
        applied_nodes_by_seed_id[preview.suggestion_id] = node

    primary_node = _select_primary_repository_seed_node(nodes)
    existing_edge_pairs = {(edge.source_node_id, edge.target_node_id) for edge in edges}
    created_edges = 0
    for flow in repository_evidence.dfd_seed_flow_suggestions:
        source_node = applied_nodes_by_seed_id.get(flow.source_seed_id)
        target_node = applied_nodes_by_seed_id.get(flow.target_seed_id)
        if source_node is None or target_node is None:
            continue
        pair = (source_node.id, target_node.id)
        if pair in existing_edge_pairs:
            continue
        edge = DFDEdge(
            id=uuid4(),
            threat_model_id=threat_model_id,
            source_node_id=source_node.id,
            target_node_id=target_node.id,
            label=flow.label,
            properties=_repository_seed_flow_edge_properties(flow),
        )
        db.add(edge)
        edges.append(edge)
        existing_edge_pairs.add(pair)
        created_edges += 1

    if created_edges == 0 and primary_node is not None:
        for node in created_nodes:
            if node.id == primary_node.id or node.node_type == "process":
                continue
            pair = (primary_node.id, node.id)
            if pair in existing_edge_pairs:
                continue
            edge = DFDEdge(
                id=uuid4(),
                threat_model_id=threat_model_id,
                source_node_id=primary_node.id,
                target_node_id=node.id,
                label=_repository_seed_edge_label(node),
                properties=_normalize_edge_properties(
                    {
                        "protocol": "Repository evidence",
                        "directionality": "request",
                        "transfer_mode": "synchronous",
                        "sequence_note": "Created from repository DFD seed suggestion.",
                    }
                ),
            )
            db.add(edge)
            edges.append(edge)
            existing_edge_pairs.add(pair)
            created_edges += 1

    existing_boundary_names = {
        _normalize_seed_label(boundary.name) for boundary in boundaries if boundary.name
    }
    created_boundaries = 0
    boundary_warnings: list[str] = []
    for boundary_suggestion in repository_evidence.dfd_seed_boundary_suggestions:
        normalized_boundary_name = _normalize_seed_label(boundary_suggestion.name)
        if not normalized_boundary_name or normalized_boundary_name in existing_boundary_names:
            continue
        member_nodes = _repository_seed_boundary_member_nodes(
            boundary_suggestion,
            applied_nodes_by_seed_id,
        )
        if not member_nodes:
            continue
        position_x, position_y, width, height = _resolve_boundary_geometry(
            position_x=None,
            position_y=None,
            width=None,
            height=None,
            node_positions=[
                (node.position_x or 0.0, node.position_y or 0.0)
                for node in member_nodes
            ],
        )
        boundary = TrustBoundary(
            id=uuid4(),
            threat_model_id=threat_model_id,
            name=boundary_suggestion.name,
            node_ids=[node.id for node in member_nodes],
            position_x=position_x,
            position_y=position_y,
            width=width,
            height=height,
            boundary_type=boundary_suggestion.boundary_type,
            parent_boundary_id=None,
        )
        db.add(boundary)
        await db.flush()
        boundaries.append(boundary)
        existing_boundary_names.add(normalized_boundary_name)
        for node in member_nodes:
            node.trust_boundary_id = boundary.id
        created_boundaries += 1

        skipped_member_count = len(boundary_suggestion.seed_ids) - len(member_nodes)
        if skipped_member_count > 0:
            boundary_warnings.append(
                f"{boundary_suggestion.name} skipped {skipped_member_count} member(s) that were not applied or already had a boundary."
            )

    await db.commit()
    return DFDRepositorySeedApplyResponse(
        dfd=_build_dfd_response(nodes, edges, boundaries),
        summary=DFDRepositorySeedApplySummary(
            requested_suggestion_count=len(requested_ids),
            matched_existing_nodes=matched_existing_nodes,
            created_nodes=len(created_nodes),
            created_edges=created_edges,
            created_boundaries=created_boundaries,
            skipped_suggestions=skipped_suggestions,
            warnings=boundary_warnings,
        ),
    )
# ─── Block 1: Node CRUD ───────────────────────────────────────────────


@router.post("/nodes", response_model=DFDNodeResponse, status_code=201)
async def create_node(
    threat_model_id: UUID,
    data: DFDNodeCreate,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDNodeResponse:
    """Create a new DFD node."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            node = DFDNodeResponse(
                id=data.id or uuid4(),
                node_type=data.node_type,
                name=data.name,
                position_x=data.position_x,
                position_y=data.position_y,
                trust_boundary_id=None,
                scan_target_url=data.scan_target_url,
                scan_target_ports=data.scan_target_ports,
                properties=_normalize_node_properties(data.properties, node_type=data.node_type),
            )
            _sync_node_boundary_membership_in_dfd(graph, node, data.trust_boundary_id)
            graph.nodes.append(node)
            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return node

    node = DFDNode(
        id=data.id,
        threat_model_id=threat_model_id,
        node_type=data.node_type,
        name=data.name,
        position_x=data.position_x,
        position_y=data.position_y,
        trust_boundary_id=None,
        scan_target_url=data.scan_target_url,
        scan_target_ports=data.scan_target_ports,
        properties=_normalize_node_properties(data.properties, node_type=data.node_type),
    )

    try:
        db.add(node)
        await db.flush()
        await _sync_node_boundary_membership(db, threat_model_id, node, data.trust_boundary_id)
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise

    await db.refresh(node)
    return DFDNodeResponse.model_validate(node)


@router.patch("/nodes/{node_id}", response_model=DFDNodeResponse)
async def update_node(
    threat_model_id: UUID,
    node_id: UUID,
    data: DFDNodeUpdate,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDNodeResponse:
    """Update a DFD node (partial update)."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            node = _find_node_in_dfd(graph, node_id)
            if node is None:
                raise HTTPException(status_code=404, detail="Node not found")

            update_data = data.model_dump(exclude_unset=True)
            next_node_type = update_data.get("node_type", node.node_type)
            if "name" in update_data:
                node.name = update_data["name"]
            if "node_type" in update_data:
                node.node_type = update_data["node_type"]
            if "position_x" in update_data:
                node.position_x = update_data["position_x"]
            if "position_y" in update_data:
                node.position_y = update_data["position_y"]
            if "scan_target_url" in update_data:
                node.scan_target_url = update_data["scan_target_url"]
            if "scan_target_ports" in update_data:
                node.scan_target_ports = update_data["scan_target_ports"]
            if "properties" in update_data and data.properties is not None:
                node.properties = _normalize_node_properties(data.properties, node_type=next_node_type)
            if "trust_boundary_id" in data.model_fields_set:
                _sync_node_boundary_membership_in_dfd(graph, node, data.trust_boundary_id)

            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return node

    result = await db.execute(
        select(DFDNode).where(
            DFDNode.id == node_id,
            DFDNode.threat_model_id == threat_model_id,
        )
    )
    node = result.scalar_one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")

    update_data = data.model_dump(exclude_unset=True)
    trust_boundary_id = update_data.pop("trust_boundary_id", None) if "trust_boundary_id" in update_data else None
    trust_boundary_was_updated = "trust_boundary_id" in data.model_fields_set
    try:
        updated_node_type = update_data.get("node_type", node.node_type)
        for field, value in update_data.items():
            if field == "properties" and value is not None:
                node.properties = _normalize_node_properties(data.properties, node_type=updated_node_type)
                node.properties = _normalize_node_properties(data.properties, node_type=updated_node_type)
                flag_modified(node, "properties")
            else:
                setattr(node, field, value)

        if trust_boundary_was_updated:
            await _sync_node_boundary_membership(db, threat_model_id, node, trust_boundary_id)

        await db.commit()
    except HTTPException:
        await db.rollback()
        raise

    await db.refresh(node)
    return DFDNodeResponse.model_validate(node)


@router.delete("/nodes/{node_id}", status_code=204)
async def delete_node(
    threat_model_id: UUID,
    node_id: UUID,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Delete a DFD node and cascade to connected edges."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            node = _find_node_in_dfd(graph, node_id)
            if node is None:
                raise HTTPException(status_code=404, detail="Node not found")

            _sync_node_boundary_membership_in_dfd(graph, node, None)
            graph.nodes = [existing_node for existing_node in graph.nodes if existing_node.id != node_id]
            graph.edges = [
                edge
                for edge in graph.edges
                if edge.source_node_id != node_id and edge.target_node_id != node_id
            ]

            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return Response(status_code=204)

    result = await db.execute(
        select(DFDNode).where(
            DFDNode.id == node_id,
            DFDNode.threat_model_id == threat_model_id,
        )
    )
    node = result.scalar_one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")

    await _sync_node_boundary_membership(db, threat_model_id, node, None)

    # Delete connected edges (cascade from DB FK, but explicit for clarity)
    await db.execute(
        delete(DFDEdge).where(
            (DFDEdge.source_node_id == node_id) | (DFDEdge.target_node_id == node_id)
        )
    )
    await db.delete(node)
    await db.commit()
    return Response(status_code=204)


# ─── Block 2: Edge CRUD ───────────────────────────────────────────────


@router.post("/edges", response_model=DFDEdgeResponse, status_code=201)
async def create_edge(
    threat_model_id: UUID,
    data: DFDEdgeCreate,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDEdgeResponse:
    """Create a new DFD edge."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            if _find_node_in_dfd(graph, data.source_node_id) is None or _find_node_in_dfd(graph, data.target_node_id) is None:
                raise HTTPException(status_code=400, detail="Invalid edge node references")
            edge = DFDEdgeResponse(
                id=data.id or uuid4(),
                source_node_id=data.source_node_id,
                target_node_id=data.target_node_id,
                label=data.label,
                properties=_normalize_edge_properties(data.properties),
            )
            graph.edges.append(edge)
            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return edge

    edge = DFDEdge(
        id=data.id,
        threat_model_id=threat_model_id,
        source_node_id=data.source_node_id,
        target_node_id=data.target_node_id,
        label=data.label,
        properties=_normalize_edge_properties(data.properties),
    )
    db.add(edge)
    await db.commit()
    await db.refresh(edge)
    return DFDEdgeResponse.model_validate(edge)


@router.patch("/edges/{edge_id}", response_model=DFDEdgeResponse)
async def update_edge(
    threat_model_id: UUID,
    edge_id: UUID,
    data: DFDEdgeUpdate,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDEdgeResponse:
    """Update a DFD edge (partial update)."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            edge = _find_edge_in_dfd(graph, edge_id)
            if edge is None:
                raise HTTPException(status_code=404, detail="Edge not found")

            update_data = data.model_dump(exclude_unset=True)
            if "label" in update_data:
                edge.label = update_data["label"]
            if "properties" in update_data and data.properties is not None:
                edge.properties = _normalize_edge_properties(data.properties)

            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return edge

    result = await db.execute(
        select(DFDEdge).where(
            DFDEdge.id == edge_id,
            DFDEdge.threat_model_id == threat_model_id,
        )
    )
    edge = result.scalar_one_or_none()
    if edge is None:
        raise HTTPException(status_code=404, detail="Edge not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "properties" and value is not None:
            edge.properties = _normalize_edge_properties(data.properties)
            flag_modified(edge, "properties")
        else:
            setattr(edge, field, value)

    await db.commit()
    await db.refresh(edge)
    return DFDEdgeResponse.model_validate(edge)


@router.delete("/edges/{edge_id}", status_code=204)
async def delete_edge(
    threat_model_id: UUID,
    edge_id: UUID,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Delete a DFD edge."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            edge = _find_edge_in_dfd(graph, edge_id)
            if edge is None:
                raise HTTPException(status_code=404, detail="Edge not found")
            graph.edges = [existing_edge for existing_edge in graph.edges if existing_edge.id != edge_id]
            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return Response(status_code=204)

    result = await db.execute(
        select(DFDEdge).where(
            DFDEdge.id == edge_id,
            DFDEdge.threat_model_id == threat_model_id,
        )
    )
    edge = result.scalar_one_or_none()
    if edge is None:
        raise HTTPException(status_code=404, detail="Edge not found")

    await db.delete(edge)
    await db.commit()
    return Response(status_code=204)


@router.post("/quick-add", response_model=DFDQuickAddResponse, status_code=201)
async def quick_add_node(
    threat_model_id: UUID,
    data: DFDQuickAddRequest,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDQuickAddResponse:
    """Create a node and connecting edge atomically for the DFD quick-add UX."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            origin_node = _find_node_in_dfd(graph, data.origin_node_id)
            if origin_node is None:
                raise HTTPException(status_code=404, detail="Origin node not found")

            node = DFDNodeResponse(
                id=data.node.id or uuid4(),
                node_type=data.node.node_type,
                name=data.node.name,
                position_x=data.node.position_x,
                position_y=data.node.position_y,
                trust_boundary_id=None,
                scan_target_url=data.node.scan_target_url,
                scan_target_ports=data.node.scan_target_ports,
                properties=_normalize_node_properties(data.node.properties, node_type=data.node.node_type),
            )
            _sync_node_boundary_membership_in_dfd(graph, node, data.node.trust_boundary_id)
            graph.nodes.append(node)

            edge = DFDEdgeResponse(
                id=uuid4(),
                source_node_id=origin_node.id if data.origin_handle == "source" else node.id,
                target_node_id=node.id if data.origin_handle == "source" else origin_node.id,
                label=data.edge.label,
                properties=_normalize_edge_properties(data.edge.properties),
            )
            graph.edges.append(edge)

            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return DFDQuickAddResponse(node=node, edge=edge)

    origin_result = await db.execute(
        select(DFDNode).where(
            DFDNode.id == data.origin_node_id,
            DFDNode.threat_model_id == threat_model_id,
        )
    )
    origin_node = origin_result.scalar_one_or_none()
    if origin_node is None:
        raise HTTPException(status_code=404, detail="Origin node not found")

    node = DFDNode(
        id=data.node.id,
        threat_model_id=threat_model_id,
        node_type=data.node.node_type,
        name=data.node.name,
        position_x=data.node.position_x,
        position_y=data.node.position_y,
        trust_boundary_id=None,
        scan_target_url=data.node.scan_target_url,
        scan_target_ports=data.node.scan_target_ports,
        properties=_normalize_node_properties(data.node.properties, node_type=data.node.node_type),
    )

    try:
        db.add(node)
        await db.flush()
        await _sync_node_boundary_membership(db, threat_model_id, node, data.node.trust_boundary_id)

        edge = DFDEdge(
            threat_model_id=threat_model_id,
            source_node_id=origin_node.id if data.origin_handle == "source" else node.id,
            target_node_id=node.id if data.origin_handle == "source" else origin_node.id,
            label=data.edge.label,
            properties=_normalize_edge_properties(data.edge.properties),
        )
        db.add(edge)
        await db.flush()

        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to quick add node") from exc

    await db.refresh(node)
    await db.refresh(edge)
    return DFDQuickAddResponse(
        node=DFDNodeResponse.model_validate(node),
        edge=DFDEdgeResponse.model_validate(edge),
    )


# ─── Block 3: Trust Boundary CRUD ─────────────────────────────────────


@router.post("/boundaries", response_model=TrustBoundaryResponse, status_code=201)
async def create_boundary(
    threat_model_id: UUID,
    data: TrustBoundaryCreate,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TrustBoundaryResponse:
    """Create a new trust boundary."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            node_ids = _dedupe_node_ids(data.node_ids)
            nodes = [_find_node_in_dfd(graph, node_id) for node_id in node_ids]
            if any(node is None for node in nodes):
                raise HTTPException(status_code=400, detail=INVALID_BOUNDARY_NODE_REFERENCE)

            valid_nodes = [node for node in nodes if node is not None]
            position_x, position_y, width, height = _resolve_boundary_geometry(
                position_x=data.position_x,
                position_y=data.position_y,
                width=data.width,
                height=data.height,
                node_positions=((node.position_x, node.position_y) for node in valid_nodes),
            )
            boundary = TrustBoundaryResponse(
                id=data.id or uuid4(),
                name=data.name,
                node_ids=[],
                position_x=position_x,
                position_y=position_y,
                width=width,
                height=height,
            )
            graph.trust_boundaries.append(boundary)
            for node in valid_nodes:
                _sync_node_boundary_membership_in_dfd(graph, node, boundary.id)

            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return boundary

    node_ids = _dedupe_node_ids(data.node_ids)
    nodes: list[DFDNode] = []
    if node_ids:
        nodes_result = await db.execute(
            select(DFDNode).where(
                DFDNode.threat_model_id == threat_model_id,
                DFDNode.id.in_(node_ids),
            )
        )
        nodes = nodes_result.scalars().all()
        if len(nodes) != len(node_ids):
            raise HTTPException(status_code=400, detail=INVALID_BOUNDARY_NODE_REFERENCE)

    previous_boundary_ids = [
        node.trust_boundary_id for node in nodes if node.trust_boundary_id is not None
    ]
    boundary_lookup_ids = [
        *previous_boundary_ids,
        *([data.parent_boundary_id] if data.parent_boundary_id is not None else []),
    ]
    previous_boundaries = await _load_boundaries(db, threat_model_id, boundary_lookup_ids)
    if data.parent_boundary_id is not None and data.parent_boundary_id not in previous_boundaries:
        raise HTTPException(status_code=400, detail=INVALID_BOUNDARY_REFERENCE)
    if data.id is not None and data.parent_boundary_id == data.id:
        raise HTTPException(status_code=400, detail="Trust boundary cannot be its own parent")
    position_x, position_y, width, height = _resolve_boundary_geometry(
        position_x=data.position_x,
        position_y=data.position_y,
        width=data.width,
        height=data.height,
        node_positions=((node.position_x, node.position_y) for node in nodes),
    )

    boundary = TrustBoundary(
        id=data.id,
        threat_model_id=threat_model_id,
        name=data.name,
        node_ids=[],
        position_x=position_x,
        position_y=position_y,
        width=width,
        height=height,
        boundary_type=data.boundary_type,
        parent_boundary_id=data.parent_boundary_id,
    )
    db.add(boundary)
    await db.flush()

    for node in nodes:
        if node.trust_boundary_id is not None and node.trust_boundary_id in previous_boundaries:
            _remove_node_from_boundary(previous_boundaries[node.trust_boundary_id], node.id)
        node.trust_boundary_id = boundary.id

    boundary.node_ids = node_ids
    await db.commit()
    await db.refresh(boundary)
    return TrustBoundaryResponse.model_validate(boundary)


@router.delete("/boundaries/{boundary_id}", status_code=204)
async def delete_boundary(
    threat_model_id: UUID,
    boundary_id: UUID,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Delete a trust boundary."""
    await _verify_threat_model(db, threat_model_id, current_user)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            graph = _get_graph_for_view(root_dfd, selected_view)
            boundary = _find_boundary_in_dfd(graph, boundary_id)
            if boundary is None:
                raise HTTPException(status_code=404, detail="Trust boundary not found")
            for node in graph.nodes:
                if node.trust_boundary_id == boundary_id:
                    node.trust_boundary_id = None
            graph.trust_boundaries = [
                existing_boundary
                for existing_boundary in graph.trust_boundaries
                if existing_boundary.id != boundary_id
            ]
            updated_view = selected_view.model_copy(update={"graph": graph})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return Response(status_code=204)

    result = await db.execute(
        select(TrustBoundary).where(
            TrustBoundary.id == boundary_id,
            TrustBoundary.threat_model_id == threat_model_id,
        )
    )
    boundary = result.scalar_one_or_none()
    if boundary is None:
        raise HTTPException(status_code=404, detail="Trust boundary not found")

    nodes_result = await db.execute(
        select(DFDNode).where(
            DFDNode.threat_model_id == threat_model_id,
            DFDNode.trust_boundary_id == boundary_id,
        )
    )
    nodes = nodes_result.scalars().all()
    for node in nodes:
        node.trust_boundary_id = None

    await db.delete(boundary)
    await db.commit()
    return Response(status_code=204)


# ─── Block 4: Bulk Save ───────────────────────────────────────────────


@router.put("", response_model=DFDResponse)
async def bulk_save_dfd(
    threat_model_id: UUID,
    data: DFDBulkSave,
    view_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DFDResponse:
    """Replace the entire DFD state (delete-then-create)."""
    await _verify_threat_model(db, threat_model_id, current_user)

    materialized_dfd = _materialize_dfd_response_from_bulk_save(data)

    if view_id is not None:
        threat_model, root_dfd, views, selected_view = await _load_editable_view_context(
            db,
            threat_model_id,
            view_id,
        )
        if is_custom_graph_view(selected_view):
            updated_view = selected_view.model_copy(update={"graph": materialized_dfd})
            await _persist_custom_views(
                db,
                threat_model=threat_model,
                root_dfd=root_dfd,
                views=[updated_view if view.id == selected_view.id else view for view in views],
            )
            return materialized_dfd

    return await _persist_root_dfd(db, threat_model_id, materialized_dfd)
