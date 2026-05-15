from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal
from uuid import UUID, uuid4

from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.environment_evidence import IacEvidence
from app.services.dfd_generator import normalize_name

ImportMode = Literal["merge", "replace"]

BOUNDARY_PADDING = 24.0
NODE_WIDTH = 180.0
NODE_HEIGHT = 64.0
COLUMN_X = {
    "external": 0.0,
    "ingress": 230.0,
    "runtime": 470.0,
    "iam": 700.0,
    "data": 930.0,
}

EDGE_BOUNDARY_NAME = "IaC Public Edge"
RUNTIME_BOUNDARY_NAME = "IaC Private Runtime"
DATA_BOUNDARY_NAME = "IaC Data Layer"

IGNORED_RESOURCE_KEYWORDS = (
    "security_group",
    "subnet",
    "route_table",
    "network_acl",
    "internet_gateway",
    "nat_gateway",
    "vpc",
    "eip",
    "cluster",
    "namespace",
    "serviceaccount",
    "rolebinding",
    "networkpolicy",
    "listener",
    "targetgroup",
)


@dataclass
class ImportedResource:
    resource_type: str
    full_name: str
    display_name: str
    node_type: str
    internet_facing: bool
    boundary_name: str | None
    properties: dict


@dataclass
class DFDIacImportDraft:
    dfd: DFDResponse
    imported_resource_count: int
    semantic_resource_count: int
    warnings: list[str]


@dataclass
class DFDIacImportSummary:
    mode: ImportMode
    imported_resource_count: int
    semantic_resource_count: int
    matched_existing_nodes: int
    created_nodes: int
    updated_nodes: int
    created_edges: int
    created_boundaries: int
    warnings: list[str]


def _split_resource_identifier(identifier: str) -> tuple[str, str]:
    if ":" in identifier:
        resource_type, resource_name = identifier.split(":", 1)
        return resource_type, resource_name
    if "." in identifier:
        resource_type, resource_name = identifier.split(".", 1)
        return resource_type, resource_name
    return "resource", identifier


def _display_name(resource_name: str) -> str:
    return resource_name.replace("_", "-").strip()


def _resource_signal_matches(resource_name: str, signal: str) -> bool:
    signal_lower = signal.casefold()
    tokens = {
        resource_name.casefold(),
        resource_name.casefold().replace("_", "-"),
        resource_name.casefold().replace("-", "_"),
    }
    if ":" in resource_name:
        tokens.add(resource_name.split(":", 1)[1].casefold())
    if "." in resource_name:
        tokens.add(resource_name.split(".", 1)[1].casefold())
    return any(token and token in signal_lower for token in tokens)


def _should_ignore_resource(resource_type: str) -> bool:
    lowered = resource_type.casefold().replace("::", "_")
    return any(keyword in lowered for keyword in IGNORED_RESOURCE_KEYWORDS)


def _is_data_store(resource_type: str) -> bool:
    lowered = resource_type.casefold()
    return any(
        keyword in lowered
        for keyword in (
            "bucket",
            "db",
            "database",
            "rds",
            "redis",
            "cache",
            "storage",
            "blob",
            "secret",
            "vault",
            "queue",
            "topic",
            "backup",
            "log",
        )
    )


def _is_iam(resource_type: str) -> bool:
    lowered = resource_type.casefold()
    return "iam" in lowered and "rolebinding" not in lowered and "serviceaccount" not in lowered


def _is_serverless(resource_type: str) -> bool:
    lowered = resource_type.casefold()
    return "lambda" in lowered or re.search(r"(^|[:._-])function($|[:._-])", lowered) is not None


def _is_ingress_resource(resource_type: str) -> bool:
    lowered = resource_type.casefold()
    return any(
        keyword in lowered
        for keyword in ("gateway", "ingress", "apigateway", "loadbalancer", "load_balancer")
    )


def _is_runtime_resource(resource_type: str) -> bool:
    lowered = resource_type.casefold()
    return any(
        keyword in lowered
        for keyword in (
            "deployment",
            "container",
            "ecs",
            "pod",
            "statefulset",
            "daemonset",
            "appservice",
            "service",
        )
    )


def _resource_to_node_type(
    resource_type: str,
    *,
    internet_facing: bool,
) -> str | None:
    if _should_ignore_resource(resource_type):
        return None
    if _is_iam(resource_type):
        return "iam_role"
    if _is_serverless(resource_type):
        return "serverless"
    if _is_data_store(resource_type):
        return "data_store"
    if _is_ingress_resource(resource_type):
        return "api_gateway"
    if _is_runtime_resource(resource_type):
        return "api_gateway" if internet_facing else "container"
    return "managed_service"


def _derive_imported_resources(iac: IacEvidence) -> tuple[list[ImportedResource], list[str]]:
    warnings = list(iac.warnings)
    resources: list[ImportedResource] = []
    skipped = 0

    for identifier in iac.resource_names:
        resource_type, resource_name = _split_resource_identifier(identifier)
        internet_facing = any(
            _resource_signal_matches(resource_name, signal)
            for signal in [*iac.public_exposure, *iac.network_paths]
        )
        node_type = _resource_to_node_type(resource_type, internet_facing=internet_facing)
        if node_type is None:
            skipped += 1
            continue

        boundary_name: str | None
        if node_type == "data_store":
            boundary_name = DATA_BOUNDARY_NAME
        elif internet_facing or node_type == "api_gateway":
            boundary_name = EDGE_BOUNDARY_NAME
        else:
            boundary_name = RUNTIME_BOUNDARY_NAME

        properties: dict = {
            "imported_from_iac": True,
            "iac_resource_type": resource_type,
            "iac_resource_name": identifier,
            "network_exposure": "internet" if internet_facing else "internal",
            "internet_facing": internet_facing,
            "responsibility": "shared" if resource_type.startswith("AWS::") else "customer",
        }
        if node_type in {"managed_service", "api_gateway"}:
            properties["service_name"] = resource_type
        if node_type == "serverless":
            properties["function_name"] = _display_name(resource_name)
            properties["runtime_type"] = "function"
        if node_type == "container":
            properties["runtime_type"] = "container"
        if node_type == "api_gateway":
            properties["runtime_type"] = "gateway"
            properties["authentication_type"] = "mtls" if any("tls" in item.casefold() for item in iac.network_paths) else "jwt"
        if node_type == "data_store":
            properties["store_type"] = resource_type
            handles_sensitive = any(
                _resource_signal_matches(resource_name, signal) for signal in iac.secret_refs
            )
            properties["handles_sensitive_data"] = handles_sensitive
            properties["data_classification"] = "Restricted" if handles_sensitive else "Internal"
        if node_type == "iam_role":
            properties["trust_level"] = "privileged"
            properties["privilege_level"] = "privileged"

        resources.append(
            ImportedResource(
                resource_type=resource_type,
                full_name=identifier,
                display_name=_display_name(resource_name),
                node_type=node_type,
                internet_facing=internet_facing,
                boundary_name=boundary_name,
                properties=properties,
            )
        )

    if skipped > 0:
        warnings.append(
            f"Skipped {skipped} low-level IaC resources that do not map cleanly to DFD components."
        )

    return resources, warnings


def _lane_for_resource(resource: ImportedResource) -> str:
    if resource.node_type == "data_store":
        return "data"
    if resource.node_type == "iam_role":
        return "iam"
    if resource.internet_facing or resource.node_type == "api_gateway":
        return "ingress"
    return "runtime"


def _compute_positions(resources: list[ImportedResource], has_external: bool, *, x_offset: float = 0.0) -> dict[str, tuple[float, float]]:
    lanes: dict[str, list[str]] = {key: [] for key in COLUMN_X}
    if has_external:
        lanes["external"].append("internet")
    for resource in resources:
        lanes[_lane_for_resource(resource)].append(resource.full_name)

    positions: dict[str, tuple[float, float]] = {}
    for lane, identifiers in lanes.items():
        total_height = max(0, (len(identifiers) - 1) * 120)
        start_y = -total_height / 2.0
        for index, identifier in enumerate(identifiers):
            positions[identifier] = (COLUMN_X[lane] + x_offset, start_y + index * 120)
    return positions


def _boundary_geometry(nodes: list[DFDNodeResponse]) -> tuple[float, float, float, float]:
    min_x = min(node.position_x for node in nodes)
    min_y = min(node.position_y for node in nodes)
    max_x = max(node.position_x + NODE_WIDTH for node in nodes)
    max_y = max(node.position_y + NODE_HEIGHT for node in nodes)
    return (
        min_x - BOUNDARY_PADDING,
        min_y - BOUNDARY_PADDING,
        max_x - min_x + BOUNDARY_PADDING * 2,
        max_y - min_y + BOUNDARY_PADDING * 2,
    )


def build_iac_import_draft(
    iac_evidence: IacEvidence,
    *,
    x_offset: float = 0.0,
) -> DFDIacImportDraft:
    resources, warnings = _derive_imported_resources(iac_evidence)
    if not resources:
        return DFDIacImportDraft(
            dfd=DFDResponse(nodes=[], edges=[], trust_boundaries=[]),
            imported_resource_count=iac_evidence.resource_count,
            semantic_resource_count=0,
            warnings=warnings,
        )

    has_external = any(resource.internet_facing for resource in resources)
    positions = _compute_positions(resources, has_external, x_offset=x_offset)

    boundary_ids = {
        EDGE_BOUNDARY_NAME: uuid4(),
        RUNTIME_BOUNDARY_NAME: uuid4(),
        DATA_BOUNDARY_NAME: uuid4(),
    }
    nodes: list[DFDNodeResponse] = []
    resource_node_map: dict[str, DFDNodeResponse] = {}

    if has_external:
        internet_node = DFDNodeResponse(
            id=uuid4(),
            node_type="external_entity",
            name="Internet",
            position_x=positions["internet"][0],
            position_y=positions["internet"][1],
            trust_boundary_id=None,
            scan_target_url=None,
            scan_target_ports=None,
            properties={"entity_scope": "external", "entity_kind": "system", "trusted": False},
            security_controls=[],
        )
        nodes.append(internet_node)
        resource_node_map["internet"] = internet_node

    for resource in resources:
        boundary_id = boundary_ids.get(resource.boundary_name) if resource.boundary_name else None
        node = DFDNodeResponse(
            id=uuid4(),
            node_type=resource.node_type,
            name=resource.display_name,
            position_x=positions[resource.full_name][0],
            position_y=positions[resource.full_name][1],
            trust_boundary_id=boundary_id,
            scan_target_url=None,
            scan_target_ports=None,
            properties=resource.properties,
            security_controls=[],
        )
        nodes.append(node)
        resource_node_map[resource.full_name] = node

    ingress_nodes = [
        resource_node_map[resource.full_name]
        for resource in resources
        if _lane_for_resource(resource) == "ingress"
    ]
    runtime_nodes = [
        resource_node_map[resource.full_name]
        for resource in resources
        if _lane_for_resource(resource) == "runtime"
    ]
    iam_nodes = [
        resource_node_map[resource.full_name]
        for resource in resources
        if resource.node_type == "iam_role"
    ]
    data_nodes = [
        resource_node_map[resource.full_name]
        for resource in resources
        if resource.node_type == "data_store"
    ]

    edges: list[DFDEdgeResponse] = []
    seen_edge_keys: set[tuple[UUID, UUID, str]] = set()

    def add_edge(source: DFDNodeResponse, target: DFDNodeResponse, label: str, properties: dict) -> None:
        key = (source.id, target.id, label.casefold())
        if source.id == target.id or key in seen_edge_keys:
            return
        seen_edge_keys.add(key)
        edges.append(
            DFDEdgeResponse(
                id=uuid4(),
                source_node_id=source.id,
                target_node_id=target.id,
                label=label,
                properties=properties,
                tls_version=properties.get("tls_version"),
                is_response=False,
                response_to_id=None,
                data_objects=[],
            )
        )

    internet_node = resource_node_map.get("internet")
    if internet_node is not None:
        for ingress in ingress_nodes:
            add_edge(
                internet_node,
                ingress,
                "Inbound traffic",
                {
                    "protocol": "HTTPS",
                    "data_payload": "External client requests",
                    "data_classification": "Internal",
                    "lifecycle_stage": "ingress",
                    "encryption_in_transit": True,
                    "directionality": "request",
                },
            )

    for ingress in ingress_nodes:
        for runtime in runtime_nodes or data_nodes:
            add_edge(
                ingress,
                runtime,
                "Forward request",
                {
                    "protocol": "HTTPS",
                    "data_payload": "Application request",
                    "data_classification": "Internal",
                    "lifecycle_stage": "processing",
                    "encryption_in_transit": True,
                    "directionality": "request",
                },
            )

    for runtime in runtime_nodes or ingress_nodes:
        for data_node in data_nodes:
            label = "Read / write data"
            if "secret" in data_node.name.casefold():
                label = "Retrieve secret"
            elif "queue" in data_node.name.casefold() or "topic" in data_node.name.casefold():
                label = "Publish / consume messages"
            add_edge(
                runtime,
                data_node,
                label,
                {
                    "protocol": "TLS",
                    "data_payload": "Service data",
                    "data_classification": "Confidential" if data_node.properties.get("handles_sensitive_data") else "Internal",
                    "lifecycle_stage": "storage",
                    "encryption_in_transit": True,
                    "directionality": "request",
                },
            )
        for iam_node in iam_nodes:
            add_edge(
                runtime,
                iam_node,
                "Assume role",
                {
                    "protocol": "IAM",
                    "data_payload": "Temporary credentials",
                    "data_classification": "Restricted",
                    "lifecycle_stage": "processing",
                    "auth_mechanism": "IAM trust policy",
                    "directionality": "request",
                },
            )

    boundaries: list[TrustBoundaryResponse] = []
    for boundary_name in (EDGE_BOUNDARY_NAME, RUNTIME_BOUNDARY_NAME, DATA_BOUNDARY_NAME):
        members = [node for node in nodes if node.trust_boundary_id == boundary_ids[boundary_name]]
        if not members:
            continue
        position_x, position_y, width, height = _boundary_geometry(members)
        boundaries.append(
            TrustBoundaryResponse(
                id=boundary_ids[boundary_name],
                name=boundary_name,
                node_ids=[node.id for node in members],
                position_x=position_x,
                position_y=position_y,
                width=width,
                height=height,
                boundary_type="network",
                parent_boundary_id=None,
            )
        )

    return DFDIacImportDraft(
        dfd=DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries),
        imported_resource_count=iac_evidence.resource_count,
        semantic_resource_count=len(resources),
        warnings=warnings,
    )


def merge_iac_import_into_dfd(
    current_dfd: DFDResponse,
    draft: DFDIacImportDraft,
) -> tuple[DFDResponse, DFDIacImportSummary]:
    imported_dfd = draft.dfd
    current_nodes = [node.model_copy(deep=True) for node in current_dfd.nodes]
    current_edges = [edge.model_copy(deep=True) for edge in current_dfd.edges]
    current_boundaries = [boundary.model_copy(deep=True) for boundary in current_dfd.trust_boundaries]

    by_name = {normalize_name(node.name): node for node in current_nodes}
    replacement_nodes: dict[UUID, DFDNodeResponse] = {node.id: node for node in current_nodes}
    remapped_ids: dict[UUID, UUID] = {}
    imported_node_kept_in_boundary: set[UUID] = set()

    matched_existing_nodes = 0
    updated_nodes = 0
    created_nodes = 0

    for imported_node in imported_dfd.nodes:
        existing = by_name.get(normalize_name(imported_node.name))
        if existing is None:
            current_nodes.append(imported_node)
            replacement_nodes[imported_node.id] = imported_node
            remapped_ids[imported_node.id] = imported_node.id
            created_nodes += 1
            continue

        matched_existing_nodes += 1
        remapped_ids[imported_node.id] = existing.id
        merged_properties = {**existing.properties, **imported_node.properties}
        updated_node = existing.model_copy(
            update={
                "node_type": imported_node.node_type,
                "properties": merged_properties,
                "trust_boundary_id": existing.trust_boundary_id or imported_node.trust_boundary_id,
            }
        )
        replacement_nodes[existing.id] = updated_node
        if existing.trust_boundary_id is None:
            imported_node_kept_in_boundary.add(imported_node.id)
        updated_nodes += 1

    merged_nodes = list(replacement_nodes.values())

    edge_keys = {(edge.source_node_id, edge.target_node_id, edge.label.casefold()) for edge in current_edges}
    created_edges = 0
    for imported_edge in imported_dfd.edges:
        source_id = remapped_ids.get(imported_edge.source_node_id, imported_edge.source_node_id)
        target_id = remapped_ids.get(imported_edge.target_node_id, imported_edge.target_node_id)
        key = (source_id, target_id, imported_edge.label.casefold())
        if source_id == target_id or key in edge_keys:
            continue
        edge_keys.add(key)
        current_edges.append(
            imported_edge.model_copy(
                update={
                    "id": uuid4(),
                    "source_node_id": source_id,
                    "target_node_id": target_id,
                }
            )
        )
        created_edges += 1

    created_boundaries = 0
    current_boundary_by_name = {boundary.name: boundary for boundary in current_boundaries}
    node_lookup = {node.id: node for node in merged_nodes}
    # Track old-boundary-id -> new-boundary-id so we can remap node trust_boundary_id values
    boundary_id_remap: dict[UUID, UUID] = {}
    for imported_boundary in imported_dfd.trust_boundaries:
        remapped_node_ids = [
            remapped_ids[node_id]
            for node_id in imported_boundary.node_ids
            if node_id in remapped_ids and (node_id in imported_node_kept_in_boundary or remapped_ids[node_id] == node_id)
        ]
        if not remapped_node_ids:
            continue
        member_nodes = [node_lookup[node_id] for node_id in remapped_node_ids if node_id in node_lookup]
        if not member_nodes:
            continue
        position_x, position_y, width, height = _boundary_geometry(member_nodes)
        existing_boundary = current_boundary_by_name.get(imported_boundary.name)
        if existing_boundary is None:
            new_boundary_id = uuid4()
            boundary_id_remap[imported_boundary.id] = new_boundary_id
            current_boundaries.append(
                imported_boundary.model_copy(
                    update={
                        "id": new_boundary_id,
                        "node_ids": remapped_node_ids,
                        "position_x": position_x,
                        "position_y": position_y,
                        "width": width,
                        "height": height,
                    }
                )
            )
            created_boundaries += 1
            continue

        # Existing boundary keeps its ID; map the imported ID to the existing one
        boundary_id_remap[imported_boundary.id] = existing_boundary.id
        existing_members = list(dict.fromkeys([*existing_boundary.node_ids, *remapped_node_ids]))
        existing_boundary.node_ids = existing_members
        existing_boundary.position_x = position_x
        existing_boundary.position_y = position_y
        existing_boundary.width = width
        existing_boundary.height = height

    # Remap trust_boundary_id on merged nodes so they reference the final boundary IDs
    if boundary_id_remap:
        for i, node in enumerate(merged_nodes):
            if node.trust_boundary_id and node.trust_boundary_id in boundary_id_remap:
                merged_nodes[i] = node.model_copy(
                    update={"trust_boundary_id": boundary_id_remap[node.trust_boundary_id]}
                )

    return (
        DFDResponse(
            nodes=merged_nodes,
            edges=current_edges,
            trust_boundaries=current_boundaries,
        ),
        DFDIacImportSummary(
            mode="merge",
            imported_resource_count=draft.imported_resource_count,
            semantic_resource_count=draft.semantic_resource_count,
            matched_existing_nodes=matched_existing_nodes,
            created_nodes=created_nodes,
            updated_nodes=updated_nodes,
            created_edges=created_edges,
            created_boundaries=created_boundaries,
            warnings=draft.warnings,
        ),
    )
