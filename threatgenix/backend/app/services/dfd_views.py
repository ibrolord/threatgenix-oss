from __future__ import annotations

import uuid
from typing import Any

from app.schemas.dfd import (
    DFDResponse,
    DFDViewLayoutSnapshot,
    DFDViewResponse,
    DFDViewType,
    DFDEdgeResponse,
)
from app.services.dfd_semantics import infer_internet_facing_exposure, is_sensitive_classification

DECOMPOSABLE_NODE_TYPES = {"process", "api_gateway", "container", "serverless", "managed_service"}
EDITABLE_VIEW_TYPES = {DFDViewType.container, DFDViewType.decomposition, DFDViewType.workspace}
CUSTOM_GRAPH_VIEW_TYPES = {DFDViewType.decomposition, DFDViewType.workspace}
SYSTEM_VIEW_NAME = "System View"


def _edge_props(edge: DFDEdgeResponse) -> dict[str, Any]:
    if edge.properties is None:
        return {}
    if hasattr(edge.properties, "model_dump"):
        return edge.properties.model_dump(exclude_none=True)
    if isinstance(edge.properties, dict):
        return edge.properties
    return {}


def _node_props(node: Any) -> dict[str, Any]:
    properties = getattr(node, "properties", None)
    if properties is None:
        return {}
    if hasattr(properties, "model_dump"):
        return properties.model_dump(exclude_none=True)
    if isinstance(properties, dict):
        return properties
    return {}


def _normalize_layout_snapshot(value: Any) -> DFDViewLayoutSnapshot:
    if not value:
        return DFDViewLayoutSnapshot()
    return DFDViewLayoutSnapshot.model_validate(value)


def empty_dfd_response() -> DFDResponse:
    return DFDResponse(nodes=[], edges=[], trust_boundaries=[])


def clone_dfd_response(dfd: DFDResponse | None) -> DFDResponse:
    if dfd is None:
        return empty_dfd_response()
    return DFDResponse.model_validate(dfd.model_dump(mode="json"))


def load_view_responses(raw_views: list[dict[str, Any]] | None) -> list[DFDViewResponse]:
    if not raw_views:
        return []
    return [DFDViewResponse.model_validate(view) for view in raw_views]


def serialize_view_responses(views: list[DFDViewResponse]) -> list[dict[str, Any]]:
    return [view.model_dump(mode="json") for view in views]


def find_view_response(
    raw_views_or_views: list[dict[str, Any]] | list[DFDViewResponse] | None,
    view_id: uuid.UUID,
) -> DFDViewResponse | None:
    views = (
        raw_views_or_views
        if raw_views_or_views and isinstance(raw_views_or_views[0], DFDViewResponse)
        else load_view_responses(raw_views_or_views)  # type: ignore[arg-type,index]
    )
    for view in views:
        if view.id == view_id:
            return view
    return None


def is_editable_view(view: DFDViewResponse | None) -> bool:
    return view is None or view.view_type in EDITABLE_VIEW_TYPES


def is_custom_graph_view(view: DFDViewResponse | None) -> bool:
    return view is not None and view.view_type in CUSTOM_GRAPH_VIEW_TYPES


def is_decomposable_node_type(node_type: str) -> bool:
    return node_type in DECOMPOSABLE_NODE_TYPES


def get_view_graph(view: DFDViewResponse) -> DFDResponse:
    return clone_dfd_response(view.graph)


def _build_node_boundary_map(dfd: DFDResponse) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for node in dfd.nodes:
        if node.trust_boundary_id is not None:
            mapping[str(node.id)] = str(node.trust_boundary_id)
    for boundary in dfd.trust_boundaries:
        for node_id in boundary.node_ids:
            mapping[str(node_id)] = str(boundary.id)
    return mapping


def _is_external_like(node_type: str) -> bool:
    return node_type in {"external_entity", "human_actor"}


def _is_boundary_crossing(edge: DFDEdgeResponse, node_boundary_map: dict[str, str]) -> bool:
    return node_boundary_map.get(str(edge.source_node_id)) != node_boundary_map.get(str(edge.target_node_id))


def _serialize_view(view: DFDViewResponse) -> dict[str, Any]:
    return view.model_dump(mode="json")


def _boundary_ids_for_nodes(dfd: DFDResponse, node_ids: set[str]) -> list[uuid.UUID]:
    boundary_ids: list[uuid.UUID] = []
    for boundary in dfd.trust_boundaries:
        if any(str(node_id) in node_ids for node_id in boundary.node_ids):
            boundary_ids.append(boundary.id)
    return boundary_ids


def _build_container_view(dfd: DFDResponse, existing: DFDViewResponse | None) -> DFDViewResponse:
    view_name = SYSTEM_VIEW_NAME
    if existing and existing.name and existing.name != "Container View":
        view_name = existing.name
    return DFDViewResponse(
        id=existing.id if existing else uuid.uuid4(),
        view_type=DFDViewType.container,
        name=view_name,
        node_ids=[node.id for node in dfd.nodes],
        edge_ids=[edge.id for edge in dfd.edges],
        boundary_ids=[boundary.id for boundary in dfd.trust_boundaries],
        layout_snapshot=existing.layout_snapshot if existing else DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=None,
        is_auto_generated=True,
    )


def _build_context_view(dfd: DFDResponse, existing: DFDViewResponse | None) -> DFDViewResponse:
    node_boundary_map = _build_node_boundary_map(dfd)
    included_node_ids: set[str] = set()

    for node in dfd.nodes:
        properties = _node_props(node)
        if _is_external_like(node.node_type):
            included_node_ids.add(str(node.id))
        if properties.get("internet_facing") is True:
            included_node_ids.add(str(node.id))
        if infer_internet_facing_exposure(properties.get("network_exposure")) is True:
            included_node_ids.add(str(node.id))
        if node.node_type in {"api_gateway", "iam_role"}:
            included_node_ids.add(str(node.id))

    for edge in dfd.edges:
        source_id = str(edge.source_node_id)
        target_id = str(edge.target_node_id)
        source = next((node for node in dfd.nodes if str(node.id) == source_id), None)
        target = next((node for node in dfd.nodes if str(node.id) == target_id), None)
        if source and target and (
            _is_external_like(source.node_type)
            or _is_external_like(target.node_type)
            or _is_boundary_crossing(edge, node_boundary_map)
        ):
            included_node_ids.add(source_id)
            included_node_ids.add(target_id)

    if not included_node_ids:
        included_node_ids = {str(node.id) for node in dfd.nodes[: min(len(dfd.nodes), 8)]}

    edge_ids = [
        edge.id
        for edge in dfd.edges
        if str(edge.source_node_id) in included_node_ids and str(edge.target_node_id) in included_node_ids
    ]

    return DFDViewResponse(
        id=existing.id if existing else uuid.uuid4(),
        view_type=DFDViewType.context,
        name=existing.name if existing else "Context View",
        node_ids=[uuid.UUID(node_id) for node_id in sorted(included_node_ids)],
        edge_ids=edge_ids,
        boundary_ids=_boundary_ids_for_nodes(dfd, included_node_ids),
        layout_snapshot=existing.layout_snapshot if existing else DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=None,
        is_auto_generated=True,
    )


def _is_sensitive_edge(edge: DFDEdgeResponse, node_boundary_map: dict[str, str]) -> bool:
    properties = _edge_props(edge)
    if _is_boundary_crossing(edge, node_boundary_map):
        return True
    if is_sensitive_classification(properties.get("data_classification")):
        return True
    if any(properties.get(flag) is True for flag in ("carries_credentials", "carries_pii", "carries_secrets")):
        return True
    if properties.get("encryption_in_transit") is False:
        return True
    return False


def _is_sensitive_node(node: Any) -> bool:
    properties = _node_props(node)
    if is_sensitive_classification(properties.get("data_classification")):
        return True
    return any(
        properties.get(flag) is True
        for flag in (
            "handles_sensitive_data",
            "handles_pii",
            "handles_financial_data",
            "stores_credentials",
            "stores_secrets",
        )
    )


def _build_data_lifecycle_view(dfd: DFDResponse, existing: DFDViewResponse | None) -> DFDViewResponse:
    node_boundary_map = _build_node_boundary_map(dfd)
    node_by_id = {str(node.id): node for node in dfd.nodes}
    included_node_ids: set[str] = set()
    included_edge_ids: list[uuid.UUID] = []

    for node in dfd.nodes:
        if _is_sensitive_node(node):
            included_node_ids.add(str(node.id))

    for edge in dfd.edges:
        properties = _edge_props(edge)
        is_lifecycle_edge = bool(properties.get("lifecycle_stage"))
        if not (
            is_lifecycle_edge
            or _is_sensitive_edge(edge, node_boundary_map)
            or _is_sensitive_node(node_by_id.get(str(edge.source_node_id)))
            or _is_sensitive_node(node_by_id.get(str(edge.target_node_id)))
        ):
            continue
        included_edge_ids.append(edge.id)
        included_node_ids.add(str(edge.source_node_id))
        included_node_ids.add(str(edge.target_node_id))

    return DFDViewResponse(
        id=existing.id if existing else uuid.uuid4(),
        view_type=DFDViewType.data_lifecycle,
        name=existing.name if existing else "Sensitive Data",
        node_ids=[uuid.UUID(node_id) for node_id in sorted(included_node_ids)],
        edge_ids=included_edge_ids,
        boundary_ids=_boundary_ids_for_nodes(dfd, included_node_ids),
        layout_snapshot=existing.layout_snapshot if existing else DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=None,
        is_auto_generated=True,
    )


def _build_deep_dive_view(dfd: DFDResponse, existing: DFDViewResponse | None) -> DFDViewResponse:
    node_boundary_map = _build_node_boundary_map(dfd)
    included_edge_ids = [
        edge.id for edge in dfd.edges if _is_sensitive_edge(edge, node_boundary_map)
    ]
    included_node_ids: set[str] = set()
    for edge in dfd.edges:
        if edge.id not in included_edge_ids:
            continue
        included_node_ids.add(str(edge.source_node_id))
        included_node_ids.add(str(edge.target_node_id))

    if not included_edge_ids:
        included_edge_ids = [
            edge.id for edge in dfd.edges if _is_boundary_crossing(edge, node_boundary_map)
        ]
        for edge in dfd.edges:
            if edge.id not in included_edge_ids:
                continue
            included_node_ids.add(str(edge.source_node_id))
            included_node_ids.add(str(edge.target_node_id))

    return DFDViewResponse(
        id=existing.id if existing else uuid.uuid4(),
        view_type=DFDViewType.deep_dive,
        name=existing.name if existing else "Risky Flows",
        node_ids=[uuid.UUID(node_id) for node_id in sorted(included_node_ids)],
        edge_ids=included_edge_ids,
        boundary_ids=_boundary_ids_for_nodes(dfd, included_node_ids),
        layout_snapshot=existing.layout_snapshot if existing else DFDViewLayoutSnapshot(),
        parent_view_id=None,
        parent_node_id=None,
        graph=None,
        is_auto_generated=True,
    )


def build_default_views(
    dfd: DFDResponse,
    existing_views: list[DFDViewResponse] | None = None,
) -> list[DFDViewResponse]:
    existing_by_type = {
        view.view_type: view
        for view in (existing_views or [])
        if view.view_type not in CUSTOM_GRAPH_VIEW_TYPES
    }
    return [
        _build_context_view(dfd, existing_by_type.get(DFDViewType.context)),
        _build_container_view(dfd, existing_by_type.get(DFDViewType.container)),
        _build_deep_dive_view(dfd, existing_by_type.get(DFDViewType.deep_dive)),
        _build_data_lifecycle_view(dfd, existing_by_type.get(DFDViewType.data_lifecycle)),
    ]


def _view_node_ids(dfd: DFDResponse) -> set[uuid.UUID]:
    return {node.id for node in dfd.nodes}


def _resolve_parent_graph(
    *,
    top_level_dfd: DFDResponse,
    default_views_by_id: dict[uuid.UUID, DFDViewResponse],
    kept_custom_views_by_id: dict[uuid.UUID, DFDViewResponse],
    view: DFDViewResponse,
) -> DFDResponse | None:
    parent_view_id = view.parent_view_id
    if parent_view_id is None:
        return top_level_dfd
    parent_view = default_views_by_id.get(parent_view_id)
    if parent_view is not None:
        return top_level_dfd if parent_view.view_type not in CUSTOM_GRAPH_VIEW_TYPES else get_view_graph(parent_view)
    parent_custom_view = kept_custom_views_by_id.get(parent_view_id)
    if parent_custom_view is not None:
        return get_view_graph(parent_custom_view)
    return None


def _filter_custom_views(
    existing_views: list[DFDViewResponse],
    *,
    top_level_dfd: DFDResponse,
    default_views: list[DFDViewResponse],
) -> list[DFDViewResponse]:
    default_views_by_id = {view.id: view for view in default_views}
    kept_custom_views: list[DFDViewResponse] = []
    kept_custom_views_by_id: dict[uuid.UUID, DFDViewResponse] = {}

    for view in existing_views:
        if view.is_auto_generated and view.view_type not in CUSTOM_GRAPH_VIEW_TYPES:
            continue
        if view.view_type == DFDViewType.workspace:
            kept_custom_views.append(view)
            kept_custom_views_by_id[view.id] = view
            continue
        if view.view_type != DFDViewType.decomposition:
            kept_custom_views.append(view)
            kept_custom_views_by_id[view.id] = view
            continue

        parent_graph = _resolve_parent_graph(
            top_level_dfd=top_level_dfd,
            default_views_by_id=default_views_by_id,
            kept_custom_views_by_id=kept_custom_views_by_id,
            view=view,
        )
        if parent_graph is None or view.parent_node_id is None:
            continue
        if view.parent_node_id not in _view_node_ids(parent_graph):
            continue

        kept_view = DFDViewResponse(
            id=view.id,
            view_type=view.view_type,
            name=view.name,
            node_ids=view.node_ids,
            edge_ids=view.edge_ids,
            boundary_ids=view.boundary_ids,
            layout_snapshot=view.layout_snapshot,
            parent_view_id=view.parent_view_id,
            parent_node_id=view.parent_node_id,
            graph=clone_dfd_response(view.graph),
            is_auto_generated=False,
        )
        kept_custom_views.append(kept_view)
        kept_custom_views_by_id[kept_view.id] = kept_view

    return kept_custom_views


def sync_default_views(
    raw_views: list[dict[str, Any]] | None,
    dfd: DFDResponse,
) -> list[dict[str, Any]]:
    existing_views = load_view_responses(raw_views)
    default_views = build_default_views(dfd, existing_views)
    custom_views = _filter_custom_views(existing_views, top_level_dfd=dfd, default_views=default_views)
    return [_serialize_view(view) for view in [*default_views, *custom_views]]
