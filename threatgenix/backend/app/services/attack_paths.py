from __future__ import annotations

from collections import deque
from uuid import UUID, uuid4

from app.schemas.dfd import DFDResponse
from app.schemas.threat_model import AttackPathResponse, AttackPathStep, AttackPathThreatRef
from app.services.dfd_semantics import infer_internet_facing_exposure, is_sensitive_classification

SEVERITY_SCORE = {
    "Critical": 40,
    "High": 25,
    "Medium": 12,
    "Low": 5,
}


def _is_ingress(node) -> bool:
    node_type = getattr(node, "node_type", "")
    properties = getattr(node, "properties", {}) or {}
    return (
        node_type in {"external_entity", "human_actor"}
        or infer_internet_facing_exposure(properties.get("network_exposure")) is True
        or str(properties.get("internet_facing", "")).lower() == "true"
    )


def _is_target(node) -> bool:
    node_type = getattr(node, "node_type", "")
    properties = getattr(node, "properties", {}) or {}
    return (
        node_type == "data_store"
        or is_sensitive_classification(properties.get("data_classification"))
        or str(properties.get("stores_credentials", "")).lower() == "true"
        or str(properties.get("stores_pii", "")).lower() == "true"
    )


def _build_shortest_path(adjacency: dict[UUID, list[UUID]], source_id: UUID, target_id: UUID) -> list[UUID] | None:
    queue: deque[tuple[UUID, list[UUID]]] = deque([(source_id, [source_id])])
    visited = {source_id}
    while queue:
        node_id, path = queue.popleft()
        if node_id == target_id:
            return path
        for neighbor in adjacency.get(node_id, []):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append((neighbor, [*path, neighbor]))
    return None


def derive_attack_paths(
    dfd: DFDResponse,
    threats: list[dict],
    *,
    limit: int = 5,
) -> list[AttackPathResponse]:
    if not dfd.nodes or not dfd.edges:
        return []

    node_by_id = {node.id: node for node in dfd.nodes}
    adjacency: dict[UUID, list[UUID]] = {}
    edge_lookup: dict[tuple[UUID, UUID], list[str]] = {}
    for edge in dfd.edges:
        adjacency.setdefault(edge.source_node_id, []).append(edge.target_node_id)
        edge_lookup.setdefault((edge.source_node_id, edge.target_node_id), []).append(str(edge.id))

    ingress_nodes = [node for node in dfd.nodes if _is_ingress(node)]
    target_nodes = [node for node in dfd.nodes if _is_target(node)]

    if not ingress_nodes or not target_nodes:
        return []

    candidate_paths: list[AttackPathResponse] = []
    for ingress in ingress_nodes:
        for target in target_nodes:
            if ingress.id == target.id:
                continue
            node_path = _build_shortest_path(adjacency, ingress.id, target.id)
            if not node_path or len(node_path) < 2:
                continue

            path_edge_ids: set[str] = set()
            boundary_crossings = 0
            for index in range(len(node_path) - 1):
                source_id = node_path[index]
                target_id = node_path[index + 1]
                path_edge_ids.update(edge_lookup.get((source_id, target_id), []))
                source_boundary = getattr(node_by_id[source_id], "trust_boundary_id", None)
                target_boundary = getattr(node_by_id[target_id], "trust_boundary_id", None)
                if source_boundary != target_boundary:
                    boundary_crossings += 1

            supporting_threats: list[AttackPathThreatRef] = []
            risk_score = 0
            seen_threat_ids: set[str] = set()
            for threat in threats:
                threat_node_ids = {str(node_id) for node_id in threat.get("affected_node_ids", [])}
                threat_edge_ids = {str(edge_id) for edge_id in threat.get("affected_edge_ids", [])}
                if not (
                    any(str(node_id) in threat_node_ids for node_id in node_path)
                    or bool(path_edge_ids & threat_edge_ids)
                ):
                    continue
                threat_id = str(threat.get("id", ""))
                if threat_id in seen_threat_ids:
                    continue
                seen_threat_ids.add(threat_id)
                severity = str(threat.get("severity", "Medium"))
                risk_score += SEVERITY_SCORE.get(severity, 10)
                supporting_threats.append(
                    AttackPathThreatRef(
                        id=UUID(threat_id),
                        display_id=str(threat.get("display_id", "Threat")),
                        severity=severity,
                        stride_category=str(threat.get("stride_category", "")),
                        description=str(threat.get("description", "")),
                    )
                )

            if not supporting_threats:
                continue

            risk_score += boundary_crossings * 10
            path_steps = [
                AttackPathStep(
                    node_id=node_id,
                    label=node_by_id[node_id].name,
                    node_type=node_by_id[node_id].node_type,
                    trust_boundary_id=node_by_id[node_id].trust_boundary_id,
                )
                for node_id in node_path
            ]
            candidate_paths.append(
                AttackPathResponse(
                    id=uuid4(),
                    title=f"{ingress.name} to {target.name}",
                    summary=(
                        f"Potential attack chain from {ingress.name} to {target.name} across "
                        f"{len(node_path) - 1} flow hop(s) and {boundary_crossings} trust boundary crossing(s)."
                    ),
                    risk_score=risk_score,
                    boundary_crossings=boundary_crossings,
                    path_nodes=path_steps,
                    supporting_threats=sorted(
                        supporting_threats,
                        key=lambda threat: SEVERITY_SCORE.get(threat.severity, 10),
                        reverse=True,
                    )[:6],
                )
            )

    deduped: list[AttackPathResponse] = []
    seen_signatures: set[tuple[str, ...]] = set()
    for path in sorted(candidate_paths, key=lambda item: (item.risk_score, len(item.supporting_threats)), reverse=True):
        signature = tuple(str(step.node_id) for step in path.path_nodes)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        deduped.append(path)
        if len(deduped) >= limit:
            break
    return deduped
