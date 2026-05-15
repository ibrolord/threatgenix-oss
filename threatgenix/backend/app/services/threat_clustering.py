"""Threat clustering service.

Groups related/redundant threats into clusters using a 3-pass deterministic
algorithm. No LLM required. Clusters surface in the UI to reduce cognitive
load when qualifying a large threat list.

Clustering rules (applied in priority order — a threat joins the first cluster
it matches, then is marked as assigned and skipped in later passes):

    Pass 1 — Same primary node + same STRIDE category:
        Threats sharing the same primary node (affected_node_ids[0]) and
        stride_category. Most specific grouping.
        Label: "{stride_category} on {node_name}"

    Pass 2 — Same primary edge:
        Threats sharing the same primary edge (affected_edge_ids[0]) that were
        not assigned in pass 1.
        Label: "Threats on {source_name} → {target_name}"

    Pass 3 — Same subtype + same primary node type:
        Threats with the same threat_subtype affecting nodes of the same
        node_type (primary node), not yet assigned.
        Label: "{subtype} across {node_type}s"

    Minimum cluster size: 2. Singletons remain unassigned (cluster_id = NULL).

Idempotency: Passes process only unassigned threats. Stable representative
selection uses max(auto_score or qualification_score, 0) then alphabetical
display_id as tiebreaker — deterministic across recomputes.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from app.schemas.dfd import DFDResponse


@dataclass
class ThreatClusterResult:
    label: str
    reason: str  # 'same_node_stride' | 'same_edge' | 'same_subtype_node'
    threat_ids: list[uuid.UUID] = field(default_factory=list)
    representative_threat_id: uuid.UUID | None = None


def _node_name(node_id: str, dfd: DFDResponse) -> str:
    for n in dfd.nodes:
        if str(n.id) == node_id:
            for attr in ("name", "label"):
                value = getattr(n, attr, None)
                if isinstance(value, str) and value.strip():
                    return value
            return n.node_type
    return "Unknown"


def _node_type(node_id: str, dfd: DFDResponse) -> str:
    for n in dfd.nodes:
        if str(n.id) == node_id:
            return n.node_type
    return "node"


def _edge_label(edge_id: str, dfd: DFDResponse) -> str:
    for e in dfd.edges:
        if str(e.id) == edge_id:
            src = _node_name(str(e.source_node_id), dfd)
            tgt = _node_name(str(e.target_node_id), dfd)
            return f"{src} → {tgt}"
    return "Unknown Edge"


def _representative(threat_ids: list[uuid.UUID], threats_by_id: dict) -> uuid.UUID | None:
    """Pick the representative threat: highest auto/qualification score, then alphabetical display_id."""
    if not threat_ids:
        return None

    def sort_key(tid: uuid.UUID):
        t = threats_by_id.get(tid)
        if t is None:
            return (0, "")
        score = getattr(t, "auto_score", None) or getattr(t, "qualification_score", None) or 0
        return (-score, getattr(t, "display_id", ""))

    return min(threat_ids, key=sort_key)


def compute_clusters(threats: list, dfd: DFDResponse) -> list[ThreatClusterResult]:
    """Compute cluster assignments for the given threat list.

    Args:
        threats: List of Threat ORM objects (or any object with .id,
                 .affected_node_ids, .affected_edge_ids, .stride_category,
                 .threat_subtype, .auto_score, .qualification_score, .display_id).
        dfd: The DFD for this threat model (used for node/edge labels).

    Returns:
        List of ThreatClusterResult. Each cluster has ≥ 2 members.
        Threats not in any cluster are simply absent from results.
    """
    if not threats:
        return []

    threats_by_id: dict[uuid.UUID, object] = {t.id: t for t in threats}
    assigned: set[uuid.UUID] = set()
    clusters: list[ThreatClusterResult] = []

    # ── Pass 1: Same primary node + same STRIDE ───────────────────────────────
    node_stride_groups: dict[tuple[str, str], list[uuid.UUID]] = defaultdict(list)
    for t in threats:
        node_ids = t.affected_node_ids or []
        if node_ids:
            primary = str(node_ids[0])
            key = (primary, t.stride_category)
            node_stride_groups[key].append(t.id)

    for (node_id, stride), ids in node_stride_groups.items():
        unassigned = [tid for tid in ids if tid not in assigned]
        if len(unassigned) >= 2:
            label = f"{stride} on {_node_name(node_id, dfd)}"
            rep = _representative(unassigned, threats_by_id)
            clusters.append(ThreatClusterResult(
                label=label,
                reason="same_node_stride",
                threat_ids=unassigned,
                representative_threat_id=rep,
            ))
            assigned.update(unassigned)

    # ── Pass 2: Same primary edge ─────────────────────────────────────────────
    edge_groups: dict[str, list[uuid.UUID]] = defaultdict(list)
    for t in threats:
        if t.id in assigned:
            continue
        edge_ids = t.affected_edge_ids or []
        if edge_ids:
            primary_edge = str(edge_ids[0])
            edge_groups[primary_edge].append(t.id)

    for edge_id, ids in edge_groups.items():
        unassigned = [tid for tid in ids if tid not in assigned]
        if len(unassigned) >= 2:
            label = f"Threats on {_edge_label(edge_id, dfd)}"
            rep = _representative(unassigned, threats_by_id)
            clusters.append(ThreatClusterResult(
                label=label,
                reason="same_edge",
                threat_ids=unassigned,
                representative_threat_id=rep,
            ))
            assigned.update(unassigned)

    # ── Pass 3: Same subtype + same primary node type ─────────────────────────
    subtype_nodetype_groups: dict[tuple[str, str], list[uuid.UUID]] = defaultdict(list)
    for t in threats:
        if t.id in assigned:
            continue
        subtype = t.threat_subtype or ""
        if not subtype:
            continue
        node_ids = t.affected_node_ids or []
        if node_ids:
            ntype = _node_type(str(node_ids[0]), dfd)
            key = (subtype, ntype)
            subtype_nodetype_groups[key].append(t.id)

    for (subtype, ntype), ids in subtype_nodetype_groups.items():
        unassigned = [tid for tid in ids if tid not in assigned]
        if len(unassigned) >= 2:
            label = f"{subtype} across {ntype}s"
            rep = _representative(unassigned, threats_by_id)
            clusters.append(ThreatClusterResult(
                label=label,
                reason="same_subtype_node",
                threat_ids=unassigned,
                representative_threat_id=rep,
            ))
            assigned.update(unassigned)

    return clusters
