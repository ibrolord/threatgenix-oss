from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from typing import Any
from uuid import UUID, uuid4

import yaml
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.schemas.dfd import (
    DFDComponentTemplateResponse,
    DFDPropertyOptionResponse,
    DFDResponse,
    DFDViewLayoutSnapshot,
    DFDViewResponse,
    TrustBoundaryResponse,
)
from app.schemas.threat_model import ThreatModelAssumptionResponse
from app.schemas.tmac import (
    TMACBuiltInView,
    TMACBuiltInViewType,
    TMACCollaboration,
    TMACDiffResponse,
    TMACDocument,
    TMACEvidence,
    TMACFormat,
    TMACGovernance,
    TMACImportMode,
    TMACImportResponse,
    TMACMetadata,
    TMACReporting,
    TMACSnapshotRecord,
    TMACSummary,
    TMACThreat,
    TMACValidationResponse,
    TMACViews,
    TMAC_VERSION,
)
from app.services.dfd_views import (
    CUSTOM_GRAPH_VIEW_TYPES,
    load_view_responses,
    serialize_view_responses,
    sync_default_views,
)
from app.services.dfd_layout import compute_layout
from app.services.model_collaboration import (
    normalize_assignments,
    normalize_collaborators,
    normalize_notifications,
)
from app.services.model_governance import (
    load_current_dfd,
    normalize_control_library,
    normalize_review_records,
)
from app.services.report_templates import (
    load_custom_report_templates,
    serialize_custom_report_templates,
)

BUILT_IN_VIEW_ORDER: dict[str, int] = {
    TMACBuiltInViewType.context.value: 0,
    TMACBuiltInViewType.container.value: 1,
    TMACBuiltInViewType.deep_dive.value: 2,
    TMACBuiltInViewType.data_lifecycle.value: 3,
}

IGNORED_OPERATIONAL_STATE_WARNING = (
    "Operational TMAC sections were ignored. Snapshots, reviews, collaborators, assignments, and notifications "
    "were preserved on replace or omitted on create_new unless you explicitly enable operational state import."
)
IGNORED_BINARY_ASSETS_WARNING = (
    "Embedded reporting assets were ignored. Existing report logos and architecture diagram binaries were preserved "
    "on replace or omitted on create_new unless you explicitly enable binary asset import."
)

TMAC_NODE_WIDTH = 180.0
TMAC_NODE_HEIGHT = 64.0
TMAC_BOUNDARY_PADDING = 24.0


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        parsed = float(value)
        if math.isfinite(parsed):
            return parsed
    return None


def _ensure_layout_snapshot_positions(layout_snapshot: Any, graph: Any) -> None:
    if not isinstance(layout_snapshot, dict) or not isinstance(graph, dict):
        return

    node_positions: dict[str, tuple[float, float]] = {}
    for node in graph.get("nodes", []):
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        position_x = _coerce_float(node.get("position_x"))
        position_y = _coerce_float(node.get("position_y"))
        if node_id is None or position_x is None or position_y is None:
            continue
        node_positions[str(node_id)] = (position_x, position_y)

    boundary_positions: dict[str, tuple[float, float, float | None, float | None]] = {}
    for boundary in graph.get("trust_boundaries", []):
        if not isinstance(boundary, dict):
            continue
        boundary_id = boundary.get("id")
        position_x = _coerce_float(boundary.get("position_x"))
        position_y = _coerce_float(boundary.get("position_y"))
        width = _coerce_float(boundary.get("width"))
        height = _coerce_float(boundary.get("height"))
        if boundary_id is None or position_x is None or position_y is None:
            continue
        boundary_positions[str(boundary_id)] = (position_x, position_y, width, height)

    for node in layout_snapshot.get("nodes", []):
        if not isinstance(node, dict):
            continue
        fallback = node_positions.get(str(node.get("id")))
        if fallback is None:
            continue
        if _coerce_float(node.get("position_x")) is None:
            node["position_x"] = fallback[0]
        if _coerce_float(node.get("position_y")) is None:
            node["position_y"] = fallback[1]

    for boundary in layout_snapshot.get("boundaries", []):
        if not isinstance(boundary, dict):
            continue
        fallback = boundary_positions.get(str(boundary.get("id")))
        if fallback is None:
            continue
        if _coerce_float(boundary.get("position_x")) is None:
            boundary["position_x"] = fallback[0]
        if _coerce_float(boundary.get("position_y")) is None:
            boundary["position_y"] = fallback[1]
        if _coerce_float(boundary.get("width")) is None and fallback[2] is not None:
            boundary["width"] = fallback[2]
        if _coerce_float(boundary.get("height")) is None and fallback[3] is not None:
            boundary["height"] = fallback[3]


def _ensure_graph_positions(graph: Any) -> None:
    if not isinstance(graph, dict):
        return

    raw_nodes = graph.get("nodes", [])
    raw_edges = graph.get("edges", [])
    raw_boundaries = graph.get("trust_boundaries", [])
    if not isinstance(raw_nodes, list):
        return

    layoutable_nodes: list[dict[str, Any]] = []
    for node in raw_nodes:
        if isinstance(node, dict) and node.get("id") is not None:
            layoutable_nodes.append(node)

    computed_positions = compute_layout(layoutable_nodes, raw_edges if isinstance(raw_edges, list) else [])
    fallback_index = 0
    for node in layoutable_nodes:
        node.setdefault("properties", {})
        node.setdefault("trust_boundary_id", None)
        node_id = str(node["id"])
        fallback_x, fallback_y = computed_positions.get(
            node_id,
            (float(fallback_index * 220), 0.0),
        )
        if _coerce_float(node.get("position_x")) is None:
            node["position_x"] = fallback_x
        if _coerce_float(node.get("position_y")) is None:
            node["position_y"] = fallback_y
        fallback_index += 1

    node_positions: dict[str, tuple[float, float]] = {}
    for node in layoutable_nodes:
        position_x = _coerce_float(node.get("position_x"))
        position_y = _coerce_float(node.get("position_y"))
        if position_x is None or position_y is None:
            continue
        node_positions[str(node["id"])] = (position_x, position_y)

    if isinstance(raw_boundaries, list):
        for boundary in raw_boundaries:
            if not isinstance(boundary, dict):
                continue
            member_ids = boundary.get("node_ids", [])
            member_positions = [
                node_positions[str(node_id)]
                for node_id in member_ids
                if str(node_id) in node_positions
            ]
            if member_positions:
                min_x = min(position[0] for position in member_positions)
                min_y = min(position[1] for position in member_positions)
                max_x = max(position[0] + TMAC_NODE_WIDTH for position in member_positions)
                max_y = max(position[1] + TMAC_NODE_HEIGHT for position in member_positions)
                if _coerce_float(boundary.get("position_x")) is None:
                    boundary["position_x"] = min_x - TMAC_BOUNDARY_PADDING
                if _coerce_float(boundary.get("position_y")) is None:
                    boundary["position_y"] = min_y - TMAC_BOUNDARY_PADDING
                if _coerce_float(boundary.get("width")) is None:
                    boundary["width"] = max_x - min_x + TMAC_BOUNDARY_PADDING * 2
                if _coerce_float(boundary.get("height")) is None:
                    boundary["height"] = max_y - min_y + TMAC_BOUNDARY_PADDING * 2
            else:
                if _coerce_float(boundary.get("position_x")) is None:
                    boundary["position_x"] = 0.0
                if _coerce_float(boundary.get("position_y")) is None:
                    boundary["position_y"] = 0.0
                if _coerce_float(boundary.get("width")) is None:
                    boundary["width"] = 280.0
                if _coerce_float(boundary.get("height")) is None:
                    boundary["height"] = 180.0

    if isinstance(raw_edges, list):
        for edge in raw_edges:
            if isinstance(edge, dict):
                edge.setdefault("label", "")
                edge.setdefault("properties", {})


def _hydrate_missing_graph_positions(raw: dict[str, Any]) -> None:
    root_graph = raw.get("dfd")
    _ensure_graph_positions(root_graph)

    views = raw.get("views")
    if isinstance(views, dict):
        built_in_views = views.get("built_in_views", [])
        if isinstance(built_in_views, list):
            for view in built_in_views:
                if isinstance(view, dict):
                    _ensure_layout_snapshot_positions(view.get("layout_snapshot"), root_graph)

        custom_views = views.get("custom_views", [])
        if isinstance(custom_views, list):
            for view in custom_views:
                if not isinstance(view, dict):
                    continue
                graph = view.get("graph")
                _ensure_graph_positions(graph)
                _ensure_layout_snapshot_positions(view.get("layout_snapshot"), graph)

    governance = raw.get("governance")
    if isinstance(governance, dict):
        snapshots = governance.get("model_snapshots", [])
        if isinstance(snapshots, list):
            for snapshot in snapshots:
                if isinstance(snapshot, dict):
                    _ensure_graph_positions(snapshot.get("dfd"))


def _raise_tmac_validation_error(errors: Sequence[str]) -> None:
    raise HTTPException(
        status_code=422,
        detail={
            "message": "TMAC validation failed.",
            "errors": list(errors),
        },
    )


def _normalize_float(value: float) -> float:
    if not math.isfinite(value):
        return value
    normalized = round(value, 4)
    if normalized == -0.0:
        return 0.0
    return normalized


def _normalize_value(value: Any) -> Any:
    if isinstance(value, float):
        return _normalize_float(value)
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_value(item) for key, item in value.items()}
    return value


def _sort_dfd_graph(dfd: DFDResponse) -> DFDResponse:
    payload = {
        "nodes": [
            _normalize_value(node.model_dump(mode="json"))
            for node in sorted(dfd.nodes, key=lambda item: ((item.name or "").casefold(), str(item.id)))
        ],
        "edges": [
            _normalize_value(edge.model_dump(mode="json"))
            for edge in sorted(
                dfd.edges,
                key=lambda item: (
                    str(item.source_node_id),
                    str(item.target_node_id),
                    (item.label or "").casefold(),
                    str(item.id),
                ),
            )
        ],
        "trust_boundaries": [
            _normalize_value(boundary.model_dump(mode="json"))
            for boundary in sorted(
                dfd.trust_boundaries,
                key=lambda item: ((item.name or "").casefold(), str(item.id)),
            )
        ],
    }
    return DFDResponse.model_validate(payload)


def _sort_builtin_views(views: Iterable[TMACBuiltInView]) -> list[TMACBuiltInView]:
    return sorted(
        views,
        key=lambda item: (
            BUILT_IN_VIEW_ORDER.get(item.view_type.value, 99),
            (item.name or "").casefold(),
            str(item.id or ""),
        ),
    )


def _sort_custom_views(views: Iterable[DFDViewResponse]) -> list[DFDViewResponse]:
    normalized: list[DFDViewResponse] = []
    for view in views:
        payload = _normalize_value(view.model_dump(mode="json"))
        if view.graph is not None:
            payload["graph"] = _sort_dfd_graph(view.graph).model_dump(mode="json")
        normalized.append(DFDViewResponse.model_validate(payload))
    return sorted(
        normalized,
        key=lambda item: (
            item.view_type.value,
            (item.name or "").casefold(),
            str(item.id),
        ),
    )


def _sort_threats(threats: Iterable[TMACThreat]) -> list[TMACThreat]:
    def sort_key(item: TMACThreat) -> tuple[int, int | str, str]:
        try:
            return (0, int(item.display_id.rsplit("-", 1)[1]), str(item.id))
        except (IndexError, ValueError):
            return (1, item.display_id, str(item.id))

    return sorted(threats, key=sort_key)


def _sort_model_dumpable(items: Iterable[Any], *, key) -> list[Any]:
    return sorted(items, key=key)


def _build_summary(document: TMACDocument) -> TMACSummary:
    return TMACSummary(
        node_count=len(document.dfd.nodes),
        edge_count=len(document.dfd.edges),
        boundary_count=len(document.dfd.trust_boundaries),
        built_in_view_count=len(document.views.built_in_views),
        custom_view_count=len(document.views.custom_views),
        threat_count=len(document.threats),
        assumption_count=len(document.assumptions),
        control_count=len(document.controls),
        component_template_count=len(document.component_templates),
        property_option_count=len(document.property_options),
        snapshot_count=len(document.governance.model_snapshots),
        review_count=len(document.governance.review_records),
        collaborator_count=len(document.collaboration.collaborators),
        assignment_count=len(document.collaboration.assignments),
        notification_count=len(document.collaboration.notifications),
    )


def _parse_tmac_content(content: str) -> tuple[TMACDocument, TMACFormat]:
    stripped = content.lstrip()
    detected_format = TMACFormat.json if stripped.startswith("{") or stripped.startswith("[") else TMACFormat.yaml
    try:
        raw = json.loads(content) if detected_format == TMACFormat.json else yaml.safe_load(content)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse TMAC content: {exc}") from exc

    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="TMAC content must decode to a top-level object.")

    _hydrate_missing_graph_positions(raw)

    try:
        document = TMACDocument.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "TMAC schema validation failed.",
                "errors": exc.errors(),
            },
        ) from exc

    if document.tmac_version != TMAC_VERSION:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported TMAC version `{document.tmac_version}`. Expected `{TMAC_VERSION}`.",
        )

    return _canonicalize_document(document), detected_format


def _boundary_cycle_errors(boundaries: list[TrustBoundaryResponse], prefix: str) -> list[str]:
    errors: list[str] = []
    parent_lookup = {boundary.id: boundary.parent_boundary_id for boundary in boundaries}
    visiting: set[UUID] = set()
    visited: set[UUID] = set()

    def visit(boundary_id: UUID) -> None:
        if boundary_id in visited:
            return
        if boundary_id in visiting:
            errors.append(f"{prefix}: trust boundaries contain a parent cycle at `{boundary_id}`.")
            return

        visiting.add(boundary_id)
        parent_id = parent_lookup.get(boundary_id)
        if parent_id is not None:
            visit(parent_id)
        visiting.remove(boundary_id)
        visited.add(boundary_id)

    for boundary in boundaries:
        visit(boundary.id)

    return errors


def _validate_graph(
    dfd: DFDResponse,
    *,
    prefix: str,
    template_ids: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    node_ids = [node.id for node in dfd.nodes]
    edge_ids = [edge.id for edge in dfd.edges]
    boundary_ids = [boundary.id for boundary in dfd.trust_boundaries]

    if len(node_ids) != len(set(node_ids)):
        errors.append(f"{prefix}: duplicate node ids are not allowed.")
    if len(edge_ids) != len(set(edge_ids)):
        errors.append(f"{prefix}: duplicate edge ids are not allowed.")
    if len(boundary_ids) != len(set(boundary_ids)):
        errors.append(f"{prefix}: duplicate trust boundary ids are not allowed.")

    node_id_set = set(node_ids)
    edge_id_set = set(edge_ids)
    boundary_id_set = set(boundary_ids)

    for node in dfd.nodes:
        if node.trust_boundary_id is not None and node.trust_boundary_id not in boundary_id_set:
            errors.append(
                f"{prefix}: node `{node.name}` references missing trust boundary `{node.trust_boundary_id}`."
            )
        component_template_id = (node.properties or {}).get("component_template_id")
        if component_template_id and template_ids is not None and component_template_id not in template_ids:
            errors.append(
                f"{prefix}: node `{node.name}` references missing component template `{component_template_id}`."
            )

    for edge in dfd.edges:
        if edge.source_node_id not in node_id_set:
            errors.append(f"{prefix}: edge `{edge.id}` references missing source node `{edge.source_node_id}`.")
        if edge.target_node_id not in node_id_set:
            errors.append(f"{prefix}: edge `{edge.id}` references missing target node `{edge.target_node_id}`.")
        if edge.response_to_id is not None and edge.response_to_id not in edge_id_set:
            errors.append(
                f"{prefix}: edge `{edge.id}` references missing response_to edge `{edge.response_to_id}`."
            )

    for boundary in dfd.trust_boundaries:
        missing_node_ids = [node_id for node_id in boundary.node_ids if node_id not in node_id_set]
        if missing_node_ids:
            errors.append(
                f"{prefix}: trust boundary `{boundary.name}` references missing node ids "
                + ", ".join(f"`{node_id}`" for node_id in missing_node_ids)
                + "."
            )
        if boundary.parent_boundary_id is not None and boundary.parent_boundary_id not in boundary_id_set:
            errors.append(
                f"{prefix}: trust boundary `{boundary.name}` references missing parent boundary `{boundary.parent_boundary_id}`."
            )
        if boundary.parent_boundary_id == boundary.id:
            errors.append(f"{prefix}: trust boundary `{boundary.name}` cannot parent itself.")

    errors.extend(_boundary_cycle_errors(dfd.trust_boundaries, prefix))
    return errors


def _validate_layout_snapshot(
    layout_snapshot: DFDViewLayoutSnapshot,
    *,
    node_ids: set[UUID],
    boundary_ids: set[UUID],
    prefix: str,
) -> list[str]:
    errors: list[str] = []
    for node in layout_snapshot.nodes:
        if node.id not in node_ids:
            errors.append(f"{prefix}: layout snapshot references missing node `{node.id}`.")
    for boundary in layout_snapshot.boundaries:
        if boundary.id not in boundary_ids:
            errors.append(f"{prefix}: layout snapshot references missing trust boundary `{boundary.id}`.")
    return errors


def _validate_document(document: TMACDocument) -> list[str]:
    template_ids = {template.id for template in document.component_templates}
    errors = _validate_graph(document.dfd, prefix="dfd", template_ids=template_ids)
    root_node_ids = {node.id for node in document.dfd.nodes}
    root_edge_ids = {edge.id for edge in document.dfd.edges}
    root_boundary_ids = {boundary.id for boundary in document.dfd.trust_boundaries}

    built_in_types: set[TMACBuiltInViewType] = set()
    built_in_view_ids: set[UUID] = set()
    for view in document.views.built_in_views:
        if view.view_type in built_in_types:
            errors.append(f"views.built_in_views: duplicate built-in view type `{view.view_type.value}`.")
        built_in_types.add(view.view_type)
        if view.id is not None:
            if view.id in built_in_view_ids:
                errors.append(f"views.built_in_views: duplicate built-in view id `{view.id}`.")
            built_in_view_ids.add(view.id)
        errors.extend(
            _validate_layout_snapshot(
                view.layout_snapshot,
                node_ids=root_node_ids,
                boundary_ids=root_boundary_ids,
                prefix=f"views.built_in_views[{view.view_type.value}]",
            )
        )

    custom_view_ids: set[UUID] = set()
    custom_view_graphs: dict[UUID, DFDResponse] = {}
    for view in document.views.custom_views:
        if view.id in custom_view_ids:
            errors.append(f"views.custom_views: duplicate custom view id `{view.id}`.")
            continue
        custom_view_ids.add(view.id)
        if view.view_type.value not in {item.value for item in CUSTOM_GRAPH_VIEW_TYPES}:
            errors.append(
                f"views.custom_views: custom view `{view.name}` uses unsupported view type `{view.view_type.value}`."
            )
            continue
        graph = view.graph
        if graph is None:
            errors.append(f"views.custom_views: custom view `{view.name}` is missing its graph.")
            continue
        custom_view_graphs[view.id] = graph
        errors.extend(
            _validate_graph(
                graph,
                prefix=f"views.custom_views[{view.name}]",
                template_ids=template_ids,
            )
        )
        graph_node_ids = {node.id for node in graph.nodes}
        graph_edge_ids = {edge.id for edge in graph.edges}
        graph_boundary_ids = {boundary.id for boundary in graph.trust_boundaries}
        if any(node_id not in graph_node_ids for node_id in view.node_ids):
            errors.append(f"views.custom_views[{view.name}]: node_ids must exist inside the embedded graph.")
        if any(edge_id not in graph_edge_ids for edge_id in view.edge_ids):
            errors.append(f"views.custom_views[{view.name}]: edge_ids must exist inside the embedded graph.")
        if any(boundary_id not in graph_boundary_ids for boundary_id in view.boundary_ids):
            errors.append(
                f"views.custom_views[{view.name}]: boundary_ids must exist inside the embedded graph."
            )
        errors.extend(
            _validate_layout_snapshot(
                view.layout_snapshot,
                node_ids=graph_node_ids,
                boundary_ids=graph_boundary_ids,
                prefix=f"views.custom_views[{view.name}]",
            )
        )

    all_view_ids = set(built_in_view_ids) | custom_view_ids
    for view in document.views.custom_views:
        if view.parent_view_id is not None and view.parent_view_id not in all_view_ids:
            errors.append(
                f"views.custom_views[{view.name}]: parent_view_id `{view.parent_view_id}` does not exist."
            )
        if view.view_type.value == "workspace":
            if view.parent_node_id is not None:
                errors.append(f"views.custom_views[{view.name}]: workspace views cannot define parent_node_id.")
        if view.view_type.value == "decomposition":
            if view.parent_node_id is None:
                errors.append(f"views.custom_views[{view.name}]: decomposition views require parent_node_id.")
                continue
            if view.parent_view_id is None:
                parent_graph = document.dfd
            elif view.parent_view_id in custom_view_graphs:
                parent_graph = custom_view_graphs[view.parent_view_id]
            else:
                parent_graph = document.dfd
            parent_node_ids = {node.id for node in parent_graph.nodes}
            if view.parent_node_id not in parent_node_ids:
                errors.append(
                    f"views.custom_views[{view.name}]: parent_node_id `{view.parent_node_id}` does not exist in its parent graph."
                )

    threat_ids: set[UUID] = set()
    for threat in document.threats:
        if threat.id in threat_ids:
            errors.append(f"threats: duplicate threat id `{threat.id}`.")
        threat_ids.add(threat.id)
        missing_node_ids = [node_id for node_id in threat.affected_node_ids if node_id not in root_node_ids]
        missing_edge_ids = [edge_id for edge_id in threat.affected_edge_ids if edge_id not in root_edge_ids]
        if missing_node_ids:
            errors.append(
                f"threats[{threat.display_id}]: missing affected node ids "
                + ", ".join(f"`{node_id}`" for node_id in missing_node_ids)
                + "."
            )
        if missing_edge_ids:
            errors.append(
                f"threats[{threat.display_id}]: missing affected edge ids "
                + ", ".join(f"`{edge_id}`" for edge_id in missing_edge_ids)
                + "."
            )
        if threat.original_rule_threat_id is not None and threat.original_rule_threat_id not in threat_ids:
            # Self/cross references are evaluated after the pass below.
            pass

    for threat in document.threats:
        if threat.original_rule_threat_id is not None and threat.original_rule_threat_id not in threat_ids:
            errors.append(
                f"threats[{threat.display_id}]: original_rule_threat_id `{threat.original_rule_threat_id}` does not exist in this document."
            )

    assumption_ids: set[UUID] = set()
    for assumption in document.assumptions:
        if assumption.id in assumption_ids:
            errors.append(f"assumptions: duplicate assumption id `{assumption.id}`.")
        assumption_ids.add(assumption.id)
        anchor_exists = (
            (assumption.anchor_kind == "node" and assumption.anchor_id in root_node_ids)
            or (assumption.anchor_kind == "edge" and assumption.anchor_id in root_edge_ids)
            or (assumption.anchor_kind == "boundary" and assumption.anchor_id in root_boundary_ids)
        )
        if not anchor_exists:
            errors.append(
                f"assumptions[{assumption.title}]: anchor `{assumption.anchor_kind}:{assumption.anchor_id}` does not exist."
            )

    control_ids: set[UUID] = set()
    for control in document.controls:
        if control.id in control_ids:
            errors.append(f"controls: duplicate control id `{control.id}`.")
        control_ids.add(control.id)
        missing_mapped = [threat_id for threat_id in control.mapped_threat_ids if threat_id not in threat_ids]
        if missing_mapped:
            errors.append(
                f"controls[{control.title}]: mapped threat ids "
                + ", ".join(f"`{threat_id}`" for threat_id in missing_mapped)
                + " do not exist."
            )

    snapshot_ids: set[UUID] = set()
    for snapshot in document.governance.model_snapshots:
        if snapshot.id in snapshot_ids:
            errors.append(f"governance.model_snapshots: duplicate snapshot id `{snapshot.id}`.")
        snapshot_ids.add(snapshot.id)
        errors.extend(
            _validate_graph(
                snapshot.dfd,
                prefix=f"governance.model_snapshots[{snapshot.name}].dfd",
                template_ids=template_ids,
            )
        )
        snapshot_node_ids = {node.id for node in snapshot.dfd.nodes}
        snapshot_edge_ids = {edge.id for edge in snapshot.dfd.edges}
        for threat in snapshot.threats:
            missing_nodes = [node_id for node_id in threat.affected_node_ids if node_id not in snapshot_node_ids]
            missing_edges = [edge_id for edge_id in threat.affected_edge_ids if edge_id not in snapshot_edge_ids]
            if missing_nodes:
                errors.append(
                    f"governance.model_snapshots[{snapshot.name}].threats[{threat.display_id}]: missing node ids "
                    + ", ".join(f"`{node_id}`" for node_id in missing_nodes)
                    + "."
                )
            if missing_edges:
                errors.append(
                    f"governance.model_snapshots[{snapshot.name}].threats[{threat.display_id}]: missing edge ids "
                    + ", ".join(f"`{edge_id}`" for edge_id in missing_edges)
                    + "."
                )

    review_ids: set[UUID] = set()
    for review in document.governance.review_records:
        if review.id in review_ids:
            errors.append(f"governance.review_records: duplicate review id `{review.id}`.")
        review_ids.add(review.id)
        if review.snapshot_id not in snapshot_ids:
            errors.append(
                f"governance.review_records[{review.title}]: snapshot_id `{review.snapshot_id}` does not exist."
            )

    collaborator_ids: set[UUID] = set()
    for collaborator in document.collaboration.collaborators:
        if collaborator.id in collaborator_ids:
            errors.append(f"collaboration.collaborators: duplicate collaborator id `{collaborator.id}`.")
        collaborator_ids.add(collaborator.id)

    assignment_ids: set[UUID] = set()
    for assignment in document.collaboration.assignments:
        if assignment.id in assignment_ids:
            errors.append(f"collaboration.assignments: duplicate assignment id `{assignment.id}`.")
        assignment_ids.add(assignment.id)
        if assignment.threat_id is not None and assignment.threat_id not in threat_ids:
            errors.append(
                f"collaboration.assignments[{assignment.title}]: threat_id `{assignment.threat_id}` does not exist."
            )
        if assignment.review_id is not None and assignment.review_id not in review_ids:
            errors.append(
                f"collaboration.assignments[{assignment.title}]: review_id `{assignment.review_id}` does not exist."
            )
        if assignment.anchor_kind is not None and assignment.anchor_id is not None:
            anchor_exists = (
                (assignment.anchor_kind == "node" and assignment.anchor_id in root_node_ids)
                or (assignment.anchor_kind == "edge" and assignment.anchor_id in root_edge_ids)
                or (assignment.anchor_kind == "boundary" and assignment.anchor_id in root_boundary_ids)
                or (assignment.anchor_kind == "threat" and assignment.anchor_id in threat_ids)
                or (assignment.anchor_kind == "review" and assignment.anchor_id in review_ids)
            )
            if not anchor_exists:
                errors.append(
                    f"collaboration.assignments[{assignment.title}]: anchor `{assignment.anchor_kind}:{assignment.anchor_id}` does not exist."
                )

    notification_ids: set[UUID] = set()
    for notification in document.collaboration.notifications:
        if notification.id in notification_ids:
            errors.append(f"collaboration.notifications: duplicate notification id `{notification.id}`.")
        notification_ids.add(notification.id)
        if notification.target_id is None:
            continue
        target_exists = (
            (notification.target_kind == "snapshot" and notification.target_id in snapshot_ids)
            or (notification.target_kind == "review" and notification.target_id in review_ids)
            or (notification.target_kind == "assignment" and notification.target_id in assignment_ids)
            or (notification.target_kind == "control" and notification.target_id in control_ids)
            or (notification.target_kind == "threat_model")
        )
        if not target_exists:
            errors.append(
                f"collaboration.notifications[{notification.title}]: target `{notification.target_kind}:{notification.target_id}` does not exist."
            )

    template_ids: set[str] = set()
    for template in document.component_templates:
        if template.id in template_ids:
            errors.append(f"component_templates: duplicate template id `{template.id}`.")
        template_ids.add(template.id)

    property_option_ids: set[str] = set()
    for option in document.property_options:
        if option.id in property_option_ids:
            errors.append(f"property_options: duplicate property option id `{option.id}`.")
        property_option_ids.add(option.id)

    return errors


def validate_tmac_content(content: str) -> tuple[TMACDocument, TMACFormat, list[str]]:
    document, detected_format = _parse_tmac_content(content)
    errors = _validate_document(document)
    if errors:
        _raise_tmac_validation_error(errors)
    warnings: list[str] = []
    return document, detected_format, warnings


def _has_operational_state(document: TMACDocument) -> bool:
    return any(
        (
            document.governance.model_snapshots,
            document.governance.review_records,
            document.collaboration.collaborators,
            document.collaboration.assignments,
            document.collaboration.notifications,
        )
    )


def _has_binary_assets(document: TMACDocument) -> bool:
    return bool(document.reporting.report_logo_base64 or document.reporting.arch_diagrams)


def _scoped_document(
    document: TMACDocument,
    *,
    include_operational_state: bool,
    include_binary_assets: bool,
) -> TMACDocument:
    payload = document.model_dump(mode="json")
    if not include_operational_state:
        payload["governance"] = {
            "model_snapshots": [],
            "review_records": [],
        }
        payload["collaboration"] = {
            "collaborators": [],
            "assignments": [],
            "notifications": [],
        }
    if not include_binary_assets:
        payload.setdefault("reporting", {})
        payload["reporting"]["report_logo_base64"] = None
        payload["reporting"]["arch_diagrams"] = []
    return _canonicalize_document(TMACDocument.model_validate(payload))


def _canonicalize_document(document: TMACDocument) -> TMACDocument:
    built_in_views = _sort_builtin_views(document.views.built_in_views)
    custom_views = _sort_custom_views(document.views.custom_views)
    assumptions = _sort_model_dumpable(
        document.assumptions,
        key=lambda item: ((item.title or "").casefold(), str(item.id)),
    )
    controls = _sort_model_dumpable(
        document.controls,
        key=lambda item: ((item.title or "").casefold(), str(item.id)),
    )
    component_templates = _sort_model_dumpable(
        document.component_templates,
        key=lambda item: ((item.group or "").casefold(), (item.label or "").casefold(), item.id),
    )
    property_options = _sort_model_dumpable(
        document.property_options,
        key=lambda item: (item.field, (item.label or "").casefold(), item.id),
    )
    snapshots = _sort_model_dumpable(
        [
            TMACSnapshotRecord.model_validate(
                {
                    **_normalize_value(snapshot.model_dump(mode="json")),
                    "dfd": _sort_dfd_graph(snapshot.dfd).model_dump(mode="json"),
                    "threats": [
                        _normalize_value(threat.model_dump(mode="json"))
                        for threat in sorted(
                            snapshot.threats,
                            key=lambda item: (item.display_id, str(item.id)),
                        )
                    ],
                }
            )
            for snapshot in document.governance.model_snapshots
        ],
        key=lambda item: (item.created_at, str(item.id)),
    )
    reviews = _sort_model_dumpable(
        document.governance.review_records,
        key=lambda item: (item.created_at, str(item.id)),
    )
    collaborators = _sort_model_dumpable(
        document.collaboration.collaborators,
        key=lambda item: (item.email.casefold(), str(item.id)),
    )
    assignments = _sort_model_dumpable(
        document.collaboration.assignments,
        key=lambda item: ((item.title or "").casefold(), str(item.id)),
    )
    notifications = _sort_model_dumpable(
        document.collaboration.notifications,
        key=lambda item: (item.created_at, str(item.id)),
    )

    payload = _normalize_value(
        {
            "tmac_version": document.tmac_version,
            "metadata": document.metadata.model_dump(mode="json"),
            "evidence": document.evidence.model_dump(mode="json"),
            "reporting": document.reporting.model_dump(mode="json"),
            "dfd": _sort_dfd_graph(document.dfd).model_dump(mode="json"),
            "views": {
                "built_in_views": [view.model_dump(mode="json") for view in built_in_views],
                "custom_views": [view.model_dump(mode="json") for view in custom_views],
            },
            "threats": [threat.model_dump(mode="json") for threat in _sort_threats(document.threats)],
            "assumptions": [item.model_dump(mode="json") for item in assumptions],
            "controls": [item.model_dump(mode="json") for item in controls],
            "component_templates": [item.model_dump(mode="json") for item in component_templates],
            "property_options": [item.model_dump(mode="json") for item in property_options],
            "governance": {
                "model_snapshots": [snapshot.model_dump(mode="json") for snapshot in snapshots],
                "review_records": [review.model_dump(mode="json") for review in reviews],
            },
            "collaboration": {
                "collaborators": [item.model_dump(mode="json") for item in collaborators],
                "assignments": [item.model_dump(mode="json") for item in assignments],
                "notifications": [item.model_dump(mode="json") for item in notifications],
            },
        }
    )
    return TMACDocument.model_validate(payload)


async def build_tmac_document(
    db: AsyncSession,
    threat_model: ThreatModel,
    *,
    include_operational_state: bool = True,
    include_binary_assets: bool = True,
) -> TMACDocument:
    root_dfd = _sort_dfd_graph(await load_current_dfd(db, threat_model.id))
    views = load_view_responses(sync_default_views(getattr(threat_model, "dfd_views", None), root_dfd))

    built_in_views = [
        TMACBuiltInView(
            id=view.id,
            view_type=TMACBuiltInViewType(view.view_type.value),
            name=view.name,
            layout_snapshot=view.layout_snapshot,
        )
        for view in views
        if view.view_type.value in BUILT_IN_VIEW_ORDER
    ]
    custom_views = [view for view in views if view.view_type.value not in BUILT_IN_VIEW_ORDER]

    threats_result = await db.execute(
        select(Threat)
        .where(Threat.threat_model_id == threat_model.id)
        .order_by(Threat.display_id.asc())
    )
    threats = [
        TMACThreat(
            id=threat.id,
            display_id=threat.display_id,
            description=threat.description,
            stride_category=threat.stride_category,
            threat_subtype=threat.threat_subtype,
            severity=threat.severity,
            source=threat.source,
            status=threat.status,
            dismiss_reason=threat.dismiss_reason,
            rule_id=threat.rule_id,
            ai_enhanced=threat.ai_enhanced,
            provider_managed=getattr(threat, "provider_managed", False),
            original_rule_threat_id=threat.original_rule_threat_id,
            affected_node_ids=list(getattr(threat, "affected_node_ids", []) or []),
            affected_edge_ids=list(getattr(threat, "affected_edge_ids", []) or []),
            relevance_rationale=threat.relevance_rationale,
            mitigation_plan=threat.mitigation_plan,
            mitigation_owner=threat.mitigation_owner,
            due_date=threat.due_date,
            mitigation_notes=threat.mitigation_notes,
            control_effectiveness=getattr(threat, "control_effectiveness", "none"),
            residual_risk_level=getattr(threat, "residual_risk_level", None),
            closed_at=threat.closed_at,
            created_at=threat.created_at,
            updated_at=threat.updated_at,
        )
        for threat in threats_result.scalars().all()
    ]

    snapshots = [
        TMACSnapshotRecord.model_validate(snapshot)
        for snapshot in (getattr(threat_model, "model_snapshots", None) or [])
    ]

    document = TMACDocument(
        metadata=TMACMetadata(
            id=threat_model.id,
            system_name=threat_model.system_name,
            description=threat_model.description or "",
            data_classification=threat_model.data_classification,
            regulatory_scope=list(threat_model.regulatory_scope or []),
            deployment_model=threat_model.deployment_model,
            created_at=threat_model.created_at,
            updated_at=threat_model.updated_at,
        ),
        evidence=TMACEvidence(
            repository_evidence=threat_model.repository_evidence,
            cloud_scan_evidence=threat_model.cloud_scan_evidence,
            iac_evidence=threat_model.iac_evidence,
            environment_context_summary=threat_model.environment_context_summary,
        ),
        reporting=TMACReporting(
            report_template=getattr(threat_model, "report_template", "default") or "default",
            report_watermark_text=getattr(threat_model, "report_watermark_text", None),
            report_logo_base64=getattr(threat_model, "report_logo_base64", None),
            arch_diagrams=list(getattr(threat_model, "arch_diagrams", None) or []),
            report_templates=load_custom_report_templates(
                getattr(threat_model, "report_templates", None)
            ),
        ),
        dfd=root_dfd,
        views=TMACViews(
            built_in_views=built_in_views,
            custom_views=custom_views,
        ),
        threats=threats,
        assumptions=[
            ThreatModelAssumptionResponse.model_validate(item)
            for item in (getattr(threat_model, "assumptions", None) or [])
        ],
        controls=normalize_control_library(getattr(threat_model, "control_library", None)),
        component_templates=[
            DFDComponentTemplateResponse.model_validate(item)
            for item in (getattr(threat_model, "dfd_component_templates", None) or [])
        ],
        property_options=[
            DFDPropertyOptionResponse.model_validate(item)
            for item in (getattr(threat_model, "dfd_property_options", None) or [])
        ],
        governance=TMACGovernance(
            model_snapshots=snapshots,
            review_records=normalize_review_records(getattr(threat_model, "review_records", None)),
        ),
        collaboration=TMACCollaboration(
            collaborators=normalize_collaborators(getattr(threat_model, "collaborators", None)),
            assignments=normalize_assignments(getattr(threat_model, "assignments", None)),
            notifications=normalize_notifications(getattr(threat_model, "notifications", None)),
        ),
    )

    return _scoped_document(
        document,
        include_operational_state=include_operational_state,
        include_binary_assets=include_binary_assets,
    )


def serialize_tmac_document(document: TMACDocument, *, format: TMACFormat = TMACFormat.yaml) -> str:
    payload = _canonicalize_document(document).model_dump(mode="json")
    if format == TMACFormat.json:
        return json.dumps(payload, indent=2)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=False)


def build_tmac_validation_response(content: str) -> TMACValidationResponse:
    document, detected_format, warnings = validate_tmac_content(content)
    return TMACValidationResponse(
        format=detected_format,
        summary=_build_summary(document),
        warnings=warnings,
    )


def _build_uuid_map(values: Iterable[UUID | None]) -> dict[UUID, UUID]:
    mapping: dict[UUID, UUID] = {}
    for value in values:
        if value is None or value in mapping:
            continue
        mapping[value] = uuid4()
    return mapping


def _remap_uuid(value: UUID | None, mapping: dict[UUID, UUID], *, fallback: UUID | None = None) -> UUID | None:
    if value is None:
        return fallback
    return mapping.get(value, value)


def _remap_uuid_list(values: Iterable[UUID], mapping: dict[UUID, UUID]) -> list[UUID]:
    return [mapping.get(value, value) for value in values]


def _remap_layout_snapshot(
    snapshot: DFDViewLayoutSnapshot,
    *,
    node_map: dict[UUID, UUID],
    boundary_map: dict[UUID, UUID],
) -> None:
    for node in snapshot.nodes:
        node.id = node_map.get(node.id, node.id)
    for boundary in snapshot.boundaries:
        boundary.id = boundary_map.get(boundary.id, boundary.id)


def _remap_dfd_graph(
    dfd: DFDResponse,
    *,
    node_map: dict[UUID, UUID],
    edge_map: dict[UUID, UUID],
    boundary_map: dict[UUID, UUID],
) -> None:
    for boundary in dfd.trust_boundaries:
        boundary.id = boundary_map.get(boundary.id, boundary.id)
        boundary.node_ids = _remap_uuid_list(boundary.node_ids, node_map)
        boundary.parent_boundary_id = _remap_uuid(boundary.parent_boundary_id, boundary_map)

    for node in dfd.nodes:
        node.id = node_map.get(node.id, node.id)
        node.trust_boundary_id = _remap_uuid(node.trust_boundary_id, boundary_map)

    for edge in dfd.edges:
        edge.id = edge_map.get(edge.id, edge.id)
        edge.source_node_id = node_map.get(edge.source_node_id, edge.source_node_id)
        edge.target_node_id = node_map.get(edge.target_node_id, edge.target_node_id)
        edge.response_to_id = _remap_uuid(edge.response_to_id, edge_map)
        if getattr(edge.properties, "response_to_id", None) is not None:
            edge.properties.response_to_id = _remap_uuid(edge.properties.response_to_id, edge_map)


def _remap_document_for_create_new(document: TMACDocument, *, threat_model_id: UUID) -> TMACDocument:
    remapped = document.model_copy(deep=True)
    remapped.metadata.id = threat_model_id

    node_map = _build_uuid_map(
        [
            *(node.id for node in remapped.dfd.nodes),
            *(
                node.id
                for view in remapped.views.custom_views
                if view.graph is not None
                for node in view.graph.nodes
            ),
            *(
                node.id
                for snapshot in remapped.governance.model_snapshots
                for node in snapshot.dfd.nodes
            ),
        ]
    )
    edge_map = _build_uuid_map(
        [
            *(edge.id for edge in remapped.dfd.edges),
            *(
                edge.id
                for view in remapped.views.custom_views
                if view.graph is not None
                for edge in view.graph.edges
            ),
            *(
                edge.id
                for snapshot in remapped.governance.model_snapshots
                for edge in snapshot.dfd.edges
            ),
        ]
    )
    boundary_map = _build_uuid_map(
        [
            *(boundary.id for boundary in remapped.dfd.trust_boundaries),
            *(
                boundary.id
                for view in remapped.views.custom_views
                if view.graph is not None
                for boundary in view.graph.trust_boundaries
            ),
            *(
                boundary.id
                for snapshot in remapped.governance.model_snapshots
                for boundary in snapshot.dfd.trust_boundaries
            ),
        ]
    )
    threat_map = _build_uuid_map(
        [
            *(threat.id for threat in remapped.threats),
            *(
                threat.id
                for snapshot in remapped.governance.model_snapshots
                for threat in snapshot.threats
            ),
        ]
    )
    assumption_map = _build_uuid_map(assumption.id for assumption in remapped.assumptions)
    control_map = _build_uuid_map(control.id for control in remapped.controls)
    snapshot_map = _build_uuid_map(snapshot.id for snapshot in remapped.governance.model_snapshots)
    review_map = _build_uuid_map(review.id for review in remapped.governance.review_records)
    review_comment_map = _build_uuid_map(
        comment.id
        for review in remapped.governance.review_records
        for comment in review.comments
    )
    collaborator_map = _build_uuid_map(
        collaborator.id for collaborator in remapped.collaboration.collaborators
    )
    assignment_map = _build_uuid_map(
        assignment.id for assignment in remapped.collaboration.assignments
    )
    assignment_comment_map = _build_uuid_map(
        comment.id
        for assignment in remapped.collaboration.assignments
        for comment in assignment.comments
    )
    notification_map = _build_uuid_map(
        notification.id for notification in remapped.collaboration.notifications
    )

    existing_view_ids = [
        *(view.id for view in remapped.views.built_in_views if view.id is not None),
        *(view.id for view in remapped.views.custom_views),
    ]
    view_map = _build_uuid_map(existing_view_ids)

    _remap_dfd_graph(
        remapped.dfd,
        node_map=node_map,
        edge_map=edge_map,
        boundary_map=boundary_map,
    )

    for view in remapped.views.built_in_views:
        view.id = _remap_uuid(view.id, view_map, fallback=uuid4())
        _remap_layout_snapshot(
            view.layout_snapshot,
            node_map=node_map,
            boundary_map=boundary_map,
        )

    for view in remapped.views.custom_views:
        view.id = view_map.get(view.id, view.id)
        view.node_ids = _remap_uuid_list(view.node_ids, node_map)
        view.edge_ids = _remap_uuid_list(view.edge_ids, edge_map)
        view.boundary_ids = _remap_uuid_list(view.boundary_ids, boundary_map)
        view.parent_view_id = _remap_uuid(view.parent_view_id, view_map)
        view.parent_node_id = _remap_uuid(view.parent_node_id, node_map)
        _remap_layout_snapshot(
            view.layout_snapshot,
            node_map=node_map,
            boundary_map=boundary_map,
        )
        if view.graph is not None:
            _remap_dfd_graph(
                view.graph,
                node_map=node_map,
                edge_map=edge_map,
                boundary_map=boundary_map,
            )

    for threat in remapped.threats:
        threat.id = threat_map.get(threat.id, threat.id)
        threat.original_rule_threat_id = _remap_uuid(threat.original_rule_threat_id, threat_map)
        threat.affected_node_ids = _remap_uuid_list(threat.affected_node_ids, node_map)
        threat.affected_edge_ids = _remap_uuid_list(threat.affected_edge_ids, edge_map)

    for assumption in remapped.assumptions:
        assumption.id = assumption_map.get(assumption.id, assumption.id)
        if assumption.anchor_kind == "node":
            assumption.anchor_id = node_map.get(assumption.anchor_id, assumption.anchor_id)
        elif assumption.anchor_kind == "edge":
            assumption.anchor_id = edge_map.get(assumption.anchor_id, assumption.anchor_id)
        else:
            assumption.anchor_id = boundary_map.get(assumption.anchor_id, assumption.anchor_id)

    for control in remapped.controls:
        control.id = control_map.get(control.id, control.id)
        control.mapped_threat_ids = _remap_uuid_list(control.mapped_threat_ids, threat_map)

    for snapshot in remapped.governance.model_snapshots:
        snapshot.id = snapshot_map.get(snapshot.id, snapshot.id)
        _remap_dfd_graph(
            snapshot.dfd,
            node_map=node_map,
            edge_map=edge_map,
            boundary_map=boundary_map,
        )
        for threat in snapshot.threats:
            threat.id = threat_map.get(threat.id, threat.id)
            threat.affected_node_ids = _remap_uuid_list(threat.affected_node_ids, node_map)
            threat.affected_edge_ids = _remap_uuid_list(threat.affected_edge_ids, edge_map)

    for review in remapped.governance.review_records:
        review.id = review_map.get(review.id, review.id)
        review.snapshot_id = _remap_uuid(review.snapshot_id, snapshot_map, fallback=review.snapshot_id)
        for comment in review.comments:
            comment.id = review_comment_map.get(comment.id, comment.id)

    for collaborator in remapped.collaboration.collaborators:
        collaborator.id = collaborator_map.get(collaborator.id, collaborator.id)

    for assignment in remapped.collaboration.assignments:
        assignment.id = assignment_map.get(assignment.id, assignment.id)
        assignment.threat_id = _remap_uuid(assignment.threat_id, threat_map)
        assignment.review_id = _remap_uuid(assignment.review_id, review_map)
        if assignment.anchor_kind == "node":
            assignment.anchor_id = _remap_uuid(assignment.anchor_id, node_map)
        elif assignment.anchor_kind == "edge":
            assignment.anchor_id = _remap_uuid(assignment.anchor_id, edge_map)
        elif assignment.anchor_kind == "boundary":
            assignment.anchor_id = _remap_uuid(assignment.anchor_id, boundary_map)
        elif assignment.anchor_kind == "threat":
            assignment.anchor_id = _remap_uuid(assignment.anchor_id, threat_map)
        elif assignment.anchor_kind == "review":
            assignment.anchor_id = _remap_uuid(assignment.anchor_id, review_map)
        for comment in assignment.comments:
            comment.id = assignment_comment_map.get(comment.id, comment.id)

    for notification in remapped.collaboration.notifications:
        notification.id = notification_map.get(notification.id, notification.id)
        if notification.target_kind == "snapshot":
            notification.target_id = _remap_uuid(notification.target_id, snapshot_map)
        elif notification.target_kind == "review":
            notification.target_id = _remap_uuid(notification.target_id, review_map)
        elif notification.target_kind == "assignment":
            notification.target_id = _remap_uuid(notification.target_id, assignment_map)
        elif notification.target_kind == "control":
            notification.target_id = _remap_uuid(notification.target_id, control_map)
        elif notification.target_kind == "threat_model":
            notification.target_id = threat_model_id

    return remapped


def _mark_json_field_dirty(instance: object, field_name: str) -> None:
    if hasattr(instance, "_sa_instance_state"):
        flag_modified(instance, field_name)


async def _persist_root_dfd(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    dfd: DFDResponse,
) -> None:
    await db.execute(delete(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id))
    await db.execute(delete(DFDNode).where(DFDNode.threat_model_id == threat_model_id))
    await db.execute(delete(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id))

    boundary_parent_ids: dict[UUID, UUID | None] = {}
    for boundary in dfd.trust_boundaries:
        boundary_parent_ids[boundary.id] = boundary.parent_boundary_id
        db.add(
            TrustBoundary(
                id=boundary.id,
                threat_model_id=threat_model_id,
                name=boundary.name,
                node_ids=list(boundary.node_ids),
                position_x=boundary.position_x,
                position_y=boundary.position_y,
                width=boundary.width,
                height=boundary.height,
                boundary_type=boundary.boundary_type,
                parent_boundary_id=None,
            )
        )
    await db.flush()

    boundary_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    for boundary in boundary_result.scalars().all():
        boundary.parent_boundary_id = boundary_parent_ids.get(boundary.id)

    for node in dfd.nodes:
        db.add(
            DFDNode(
                id=node.id,
                threat_model_id=threat_model_id,
                node_type=node.node_type,
                name=node.name,
                position_x=node.position_x,
                position_y=node.position_y,
                trust_boundary_id=node.trust_boundary_id,
                properties=dict(node.properties or {}),
                security_controls=list(node.security_controls or []),
            )
        )
    await db.flush()

    edge_response_refs: dict[UUID, UUID | None] = {}
    for edge in dfd.edges:
        edge_response_refs[edge.id] = edge.response_to_id
        edge_properties = edge.properties.model_dump(exclude_none=True) if hasattr(edge.properties, "model_dump") else dict(edge.properties or {})
        db.add(
            DFDEdge(
                id=edge.id,
                threat_model_id=threat_model_id,
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                label=edge.label,
                properties=edge_properties,
                tls_version=edge.tls_version,
                is_response=bool(edge.is_response),
                response_to_id=None,
                data_objects=list(edge.data_objects or []),
            )
        )
    await db.flush()

    edge_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    for edge in edge_result.scalars().all():
        edge.response_to_id = edge_response_refs.get(edge.id)
    await db.flush()


async def _persist_threats(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    threats: list[TMACThreat],
) -> None:
    await db.execute(delete(Threat).where(Threat.threat_model_id == threat_model_id))
    for threat in threats:
        db.add(
            Threat(
                id=threat.id,
                threat_model_id=threat_model_id,
                display_id=threat.display_id,
                description=threat.description,
                stride_category=threat.stride_category,
                threat_subtype=threat.threat_subtype,
                severity=threat.severity,
                source=threat.source,
                status=threat.status,
                dismiss_reason=threat.dismiss_reason,
                rule_id=threat.rule_id,
                ai_enhanced=threat.ai_enhanced,
                provider_managed=threat.provider_managed,
                original_rule_threat_id=None,
                affected_node_ids=list(threat.affected_node_ids),
                affected_edge_ids=list(threat.affected_edge_ids),
                relevance_rationale=threat.relevance_rationale,
                mitigation_plan=threat.mitigation_plan,
                mitigation_owner=threat.mitigation_owner,
                due_date=threat.due_date,
                mitigation_notes=threat.mitigation_notes,
                control_effectiveness=threat.control_effectiveness,
                residual_risk_level=threat.residual_risk_level,
                closed_at=threat.closed_at,
                created_at=threat.created_at,
                updated_at=threat.updated_at,
            )
        )
    await db.flush()

    for threat in threats:
        if threat.original_rule_threat_id is None:
            continue
        result = await db.execute(
            select(Threat).where(
                Threat.threat_model_id == threat_model_id,
                Threat.id == threat.id,
            )
        )
        persisted = result.scalar_one_or_none()
        if persisted is not None:
            persisted.original_rule_threat_id = threat.original_rule_threat_id


def _built_in_view_to_raw(view: TMACBuiltInView) -> dict[str, Any]:
    return {
        "id": str(view.id or uuid4()),
        "view_type": view.view_type.value,
        "name": view.name,
        "node_ids": [],
        "edge_ids": [],
        "boundary_ids": [],
        "layout_snapshot": view.layout_snapshot.model_dump(mode="json"),
        "parent_view_id": None,
        "parent_node_id": None,
        "graph": None,
        "is_auto_generated": True,
    }


def _apply_document_scope_to_model_record(
    threat_model: ThreatModel,
    document: TMACDocument,
    *,
    apply_operational_state: bool,
    apply_binary_assets: bool,
) -> list[str]:
    warnings: list[str] = []
    threat_model.system_name = document.metadata.system_name
    threat_model.description = document.metadata.description
    threat_model.data_classification = document.metadata.data_classification
    threat_model.regulatory_scope = list(document.metadata.regulatory_scope)
    threat_model.deployment_model = document.metadata.deployment_model
    threat_model.repository_evidence = (
        document.evidence.repository_evidence.model_dump(mode="json")
        if document.evidence.repository_evidence is not None
        else None
    )
    threat_model.cloud_scan_evidence = (
        document.evidence.cloud_scan_evidence.model_dump(mode="json")
        if document.evidence.cloud_scan_evidence is not None
        else None
    )
    threat_model.iac_evidence = (
        document.evidence.iac_evidence.model_dump(mode="json")
        if document.evidence.iac_evidence is not None
        else None
    )
    threat_model.environment_context_summary = document.evidence.environment_context_summary
    threat_model.report_template = document.reporting.report_template
    threat_model.report_watermark_text = document.reporting.report_watermark_text
    threat_model.report_templates = (
        serialize_custom_report_templates(document.reporting.report_templates) or None
    )
    threat_model.assumptions = [item.model_dump(mode="json") for item in document.assumptions] or None
    threat_model.control_library = [item.model_dump(mode="json") for item in document.controls] or None
    threat_model.dfd_component_templates = [item.model_dump(mode="json") for item in document.component_templates] or None
    threat_model.dfd_property_options = [item.model_dump(mode="json") for item in document.property_options] or None
    threat_model.last_analyzed_threats = None

    for field_name in (
        "repository_evidence",
        "cloud_scan_evidence",
        "iac_evidence",
        "report_templates",
        "assumptions",
        "control_library",
        "dfd_component_templates",
        "dfd_property_options",
    ):
        _mark_json_field_dirty(threat_model, field_name)

    if apply_binary_assets:
        threat_model.report_logo_base64 = document.reporting.report_logo_base64
        threat_model.arch_diagrams = (
            [diagram.model_dump(mode="json") for diagram in document.reporting.arch_diagrams] or None
        )
        for field_name in ("arch_diagrams",):
            _mark_json_field_dirty(threat_model, field_name)
    elif _has_binary_assets(document):
        warnings.append(IGNORED_BINARY_ASSETS_WARNING)

    if apply_operational_state:
        threat_model.model_snapshots = [item.model_dump(mode="json") for item in document.governance.model_snapshots] or None
        threat_model.review_records = [item.model_dump(mode="json") for item in document.governance.review_records] or None
        threat_model.collaborators = [item.model_dump(mode="json") for item in document.collaboration.collaborators] or None
        threat_model.assignments = [item.model_dump(mode="json") for item in document.collaboration.assignments] or None
        threat_model.notifications = [item.model_dump(mode="json") for item in document.collaboration.notifications] or None
        for field_name in (
            "model_snapshots",
            "review_records",
            "collaborators",
            "assignments",
            "notifications",
        ):
            _mark_json_field_dirty(threat_model, field_name)
    elif _has_operational_state(document):
        warnings.append(IGNORED_OPERATIONAL_STATE_WARNING)

    return warnings


async def import_tmac_document(
    db: AsyncSession,
    *,
    content: str,
    mode: TMACImportMode,
    current_user_id: UUID,
    target_threat_model: ThreatModel | None = None,
    apply_operational_state: bool = False,
    apply_binary_assets: bool = False,
) -> TMACImportResponse:
    document, _, warnings = validate_tmac_content(content)
    summary = _build_summary(document)

    if mode == TMACImportMode.preview:
        if target_threat_model is not None and document.metadata.id not in {None, target_threat_model.id}:
            warnings.append(
                f"Imported metadata.id `{document.metadata.id}` does not match target model `{target_threat_model.id}`. Replace mode will keep the target id."
            )
        return TMACImportResponse(
            mode=mode,
            threat_model_id=target_threat_model.id if target_threat_model is not None else None,
            system_name=document.metadata.system_name,
            created_new=False,
            applied_operational_state=apply_operational_state,
            applied_binary_assets=apply_binary_assets,
            summary=summary,
            warnings=warnings,
        )

    if mode == TMACImportMode.replace and target_threat_model is None:
        raise HTTPException(status_code=400, detail="Replace mode requires a target threat model.")

    created_new = mode == TMACImportMode.create_new
    if created_new and target_threat_model is not None:
        warnings.append("create_new mode ignores target_threat_model_id and creates a fresh threat model.")
        target_threat_model = None

    threat_model = target_threat_model
    if threat_model is None:
        threat_model = ThreatModel(
            system_name=document.metadata.system_name,
            description=document.metadata.description,
            data_classification=document.metadata.data_classification,
            regulatory_scope=list(document.metadata.regulatory_scope),
            deployment_model=document.metadata.deployment_model,
            owner_id=current_user_id,
        )
        db.add(threat_model)
        await db.flush()
        warnings.append("create_new mode generates a fresh threat model id even if metadata.id is present.")
        document = _remap_document_for_create_new(document, threat_model_id=threat_model.id)

    warnings.extend(
        _apply_document_scope_to_model_record(
            threat_model,
            document,
            apply_operational_state=apply_operational_state,
            apply_binary_assets=apply_binary_assets,
        )
    )
    await _persist_root_dfd(db, threat_model_id=threat_model.id, dfd=document.dfd)
    await _persist_threats(db, threat_model_id=threat_model.id, threats=document.threats)

    raw_views = [
        *_sort_model_dumpable(
            [_built_in_view_to_raw(view) for view in document.views.built_in_views],
            key=lambda item: (
                BUILT_IN_VIEW_ORDER.get(item["view_type"], 99),
                (item["name"] or "").casefold(),
                item.get("id") or "",
            ),
        ),
        *serialize_view_responses(document.views.custom_views),
    ]
    threat_model.dfd_views = sync_default_views(raw_views, document.dfd)
    _mark_json_field_dirty(threat_model, "dfd_views")

    await db.commit()
    await db.refresh(threat_model)

    return TMACImportResponse(
        mode=mode,
        threat_model_id=threat_model.id,
        system_name=threat_model.system_name,
        created_new=created_new,
        applied_operational_state=apply_operational_state,
        applied_binary_assets=apply_binary_assets,
        summary=summary,
        warnings=warnings,
    )


async def diff_tmac_against_model(
    db: AsyncSession,
    *,
    threat_model: ThreatModel,
    content: str,
) -> TMACDiffResponse:
    incoming_document, _, warnings = validate_tmac_content(content)
    current_document = await build_tmac_document(
        db,
        threat_model,
        include_operational_state=_has_operational_state(incoming_document),
        include_binary_assets=_has_binary_assets(incoming_document),
    )

    current_summary = _build_summary(current_document)
    incoming_summary = _build_summary(incoming_document)
    changed_sections: list[str] = []
    for section in (
        "metadata",
        "evidence",
        "reporting",
        "dfd",
        "views",
        "threats",
        "assumptions",
        "controls",
        "component_templates",
        "property_options",
        "governance",
        "collaboration",
    ):
        if getattr(current_document, section) != getattr(incoming_document, section):
            changed_sections.append(section)

    return TMACDiffResponse(
        current_summary=current_summary,
        incoming_summary=incoming_summary,
        changed_sections=changed_sections,
        warnings=warnings,
    )


def build_tmac_scaffold(threat_model: ThreatModel | None = None) -> str:
    system_name = threat_model.system_name if threat_model is not None else "Example System"
    classification = threat_model.data_classification if threat_model is not None else "Internal"
    scaffold = TMACDocument(
        metadata=TMACMetadata(
            system_name=system_name,
            description="Describe the system and its trust assumptions.",
            data_classification=classification,
            regulatory_scope=[],
            deployment_model="cloud",
        ),
        dfd=DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
        views=TMACViews(
            built_in_views=[
                TMACBuiltInView(view_type=TMACBuiltInViewType.context, name="Context View"),
                TMACBuiltInView(view_type=TMACBuiltInViewType.container, name="System View"),
                TMACBuiltInView(view_type=TMACBuiltInViewType.deep_dive, name="Risky Flows"),
                TMACBuiltInView(view_type=TMACBuiltInViewType.data_lifecycle, name="Sensitive Data"),
            ]
        ),
    )
    return serialize_tmac_document(scaffold, format=TMACFormat.yaml)
