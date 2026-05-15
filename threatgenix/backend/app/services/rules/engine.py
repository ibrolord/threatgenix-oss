from __future__ import annotations

import time
from typing import Any, NamedTuple

from app.schemas.dfd import DFDResponse, DFDNodeResponse
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.services.rules.boundary import crosses_trust_boundary
from app.services.rules.loader import LoadedRule, load_rules
from app.services.rules.rationale import (
    build_rationale_boundary,
    build_rationale_standalone,
    build_rationale_tuple,
)
from app.services.rules.renderer import build_context, render_description

# ---------------------------------------------------------------------------
# Internal data structure for raw threats before dedup
# ---------------------------------------------------------------------------


class _RawThreat(NamedTuple):
    rule_id: str
    stride_category: str
    threat_subtype: str
    severity: str
    priority: int
    description: str
    node_ids_frozen: frozenset[str]
    node_ids_sorted: list[str]
    edge_ids: list[str]
    relevance_rationale: str
    provider_managed: bool = False
    crosses_trust_boundary: bool = False


def _is_provider_managed(node: DFDNodeResponse) -> bool:
    return (node.properties or {}).get("responsibility") == "provider"


# ---------------------------------------------------------------------------
# STRIDE category sort order
# ---------------------------------------------------------------------------
_STRIDE_ORDER: dict[str, int] = {
    "Spoofing": 0,
    "Tampering": 1,
    "Repudiation": 2,
    "Information Disclosure": 3,
    "Denial of Service": 4,
    "Elevation of Privilege": 5,
}
_SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

# ---------------------------------------------------------------------------
# Module-level cached rules
# ---------------------------------------------------------------------------
_CACHED_RULES: list[LoadedRule] | None = None


def _get_rules() -> list[LoadedRule]:
    global _CACHED_RULES
    if _CACHED_RULES is None:
        _CACHED_RULES = load_rules()
    return _CACHED_RULES


def _base_threat_sort_key(threat: dict[str, Any]) -> tuple[Any, ...]:
    """Preserve the original deterministic order before diversity weighting."""
    return (
        _SEVERITY_ORDER.get(threat["severity"], 99),
        threat["priority"],
        _STRIDE_ORDER.get(threat["stride_category"], 99),
        threat["rule_id"],
        threat["node_ids_sorted"],
    )


def _diversify_rule_order(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Surface unique rule families before later repeats of the same rule.

    The engine should still preserve the base severity/priority ordering, but
    repeated variants of one rule family should not crowd out the first
    occurrence of other high-value themes. We therefore sort in deterministic
    rounds: first occurrence of each rule, then second occurrence, then third.
    """
    base_sorted = sorted(threats, key=_base_threat_sort_key)
    seen_counts: dict[str, int] = {}
    slotted: list[dict[str, Any]] = []

    for threat in base_sorted:
        occurrence_index = seen_counts.get(threat["rule_id"], 0)
        seen_counts[threat["rule_id"]] = occurrence_index + 1
        slotted.append({
            **threat,
            "_occurrence_index": occurrence_index,
        })

    return sorted(
        slotted,
        key=lambda threat: (
            threat["_occurrence_index"],
            *_base_threat_sort_key(threat),
        ),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_rules(dfd: DFDResponse) -> RuleEngineOutput:
    """Evaluate all STRIDE rules against a DFD. Returns deterministic results."""
    start = time.perf_counter()

    rules = _get_rules()
    rules_sorted = sorted(rules, key=lambda r: r.rule_id)

    # Step 2: build lookup maps, sort nodes by ID
    node_map: dict[str, DFDNodeResponse] = {str(n.id): n for n in dfd.nodes}
    sorted_nodes = sorted(dfd.nodes, key=lambda n: str(n.id))
    sorted_edges = sorted(dfd.edges, key=lambda e: str(e.id))
    sorted_boundaries = sorted(dfd.trust_boundaries, key=lambda b: str(b.id))

    # Step 3: extract tuples from edges
    edge_tuples: list[tuple[DFDNodeResponse, Any, DFDNodeResponse, bool, str | None]] = []
    warnings: list[str] = []
    for edge in sorted_edges:
        source = node_map.get(str(edge.source_node_id))
        target = node_map.get(str(edge.target_node_id))
        if source is None or target is None:
            missing_refs: list[str] = []
            if source is None:
                missing_refs.append(f"source node {edge.source_node_id}")
            if target is None:
                missing_refs.append(f"target node {edge.target_node_id}")
            warnings.append(
                f"Skipped edge {edge.id}: missing {' and '.join(missing_refs)}."
            )
            continue
        crosses, boundary_name = crosses_trust_boundary(
            str(edge.source_node_id),
            str(edge.target_node_id),
            dfd.trust_boundaries,
        )
        edge_tuples.append((source, edge, target, crosses, boundary_name))

    # Separate rules by condition_type
    tuple_rules = [r for r in rules_sorted if r.condition_type == "tuple"]
    standalone_rules = [r for r in rules_sorted if r.condition_type == "standalone"]
    boundary_rules = [r for r in rules_sorted if r.condition_type == "boundary"]

    # Collect raw threats before dedup
    raw_threats: list[_RawThreat] = []
    rules_evaluated = 0
    fired_rule_ids: set[str] = set()

    # Step 4: tuple-based rules
    for source, edge, target, crosses, boundary_name in edge_tuples:
        for rule in tuple_rules:
            rules_evaluated += 1
            if rule.requires_boundary_crossing and not crosses:
                continue
            if rule.condition_function(source, edge, target, crosses):
                ctx = build_context(
                    source=source,
                    edge=edge,
                    target=target,
                    boundary_name=boundary_name,
                )
                description = render_description(rule.description_template, ctx)
                rationale = build_rationale_tuple(
                    rule.rule_id, source, edge, target, crosses, boundary_name,
                )
                node_ids_frozen = frozenset([str(source.id), str(target.id)])
                raw_threats.append(_RawThreat(
                    rule_id=rule.rule_id,
                    stride_category=rule.stride_category,
                    threat_subtype=rule.threat_subtype,
                    severity=rule.severity,
                    priority=rule.priority,
                    description=description,
                    node_ids_frozen=node_ids_frozen,
                    node_ids_sorted=sorted(node_ids_frozen),
                    edge_ids=[str(edge.id)],
                    relevance_rationale=rationale,
                    provider_managed=_is_provider_managed(source) or _is_provider_managed(target),
                    crosses_trust_boundary=crosses,
                ))
                fired_rule_ids.add(rule.rule_id)

    # Step 5: standalone rules
    for node in sorted_nodes:
        for rule in standalone_rules:
            rules_evaluated += 1
            context = {
                "all_nodes": dfd.nodes,
                "all_edges": dfd.edges,
                "boundaries": dfd.trust_boundaries,
            }
            if rule.condition_function(node, context):
                ctx = build_context(node=node)
                description = render_description(rule.description_template, ctx)
                rationale = build_rationale_standalone(
                    rule.rule_id, node, context,
                )
                node_ids_frozen = frozenset([str(node.id)])
                raw_threats.append(_RawThreat(
                    rule_id=rule.rule_id,
                    stride_category=rule.stride_category,
                    threat_subtype=rule.threat_subtype,
                    severity=rule.severity,
                    priority=rule.priority,
                    description=description,
                    node_ids_frozen=node_ids_frozen,
                    node_ids_sorted=sorted(node_ids_frozen),
                    edge_ids=[],
                    relevance_rationale=rationale,
                    provider_managed=_is_provider_managed(node),
                    crosses_trust_boundary=False,
                ))
                fired_rule_ids.add(rule.rule_id)

    # Step 6: boundary rules
    for boundary in sorted_boundaries:
        boundary_node_ids_set = {str(nid) for nid in boundary.node_ids}
        # Count entry points: edges from outside the boundary into the boundary
        entry_count = 0
        for edge in sorted_edges:
            src_id = str(edge.source_node_id)
            tgt_id = str(edge.target_node_id)
            if tgt_id in boundary_node_ids_set and src_id not in boundary_node_ids_set:
                entry_count += 1

        for rule in boundary_rules:
            rules_evaluated += 1
            if rule.condition_function(boundary, entry_count):
                ctx = build_context(
                    boundary_name=boundary.name,
                    extra={"entry_count": str(entry_count)},
                )
                description = render_description(rule.description_template, ctx)
                rationale = build_rationale_boundary(
                    rule.rule_id, boundary.name, entry_count, len(boundary.node_ids),
                )
                node_ids_frozen = frozenset(str(nid) for nid in boundary.node_ids)
                boundary_nodes = [
                    n for n in dfd.nodes if str(n.id) in node_ids_frozen
                ]
                raw_threats.append(_RawThreat(
                    rule_id=rule.rule_id,
                    stride_category=rule.stride_category,
                    threat_subtype=rule.threat_subtype,
                    severity=rule.severity,
                    priority=rule.priority,
                    description=description,
                    node_ids_frozen=node_ids_frozen,
                    node_ids_sorted=sorted(node_ids_frozen),
                    edge_ids=[],
                    relevance_rationale=rationale,
                    provider_managed=any(_is_provider_managed(n) for n in boundary_nodes),
                    crosses_trust_boundary=True,
                ))
                fired_rule_ids.add(rule.rule_id)

    # Step 7: deduplicate by the same identity used by threat diff:
    # (rule_id, affected_node_ids). This keeps separate findings distinct while
    # still merging duplicate edges between the same components.
    merged: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    for threat in raw_threats:
        key = (threat.rule_id, tuple(threat.node_ids_sorted))
        if key not in merged:
            merged[key] = {
                "rule_id": threat.rule_id,
                "stride_category": threat.stride_category,
                "threat_subtype": threat.threat_subtype,
                "severity": threat.severity,
                "priority": threat.priority,
                "description": threat.description,
                "node_ids_frozen": threat.node_ids_frozen,
                "node_ids_sorted": threat.node_ids_sorted,
                "edge_ids": list(threat.edge_ids),
                "relevance_rationale": threat.relevance_rationale,
                "provider_managed": threat.provider_managed,
                "crosses_trust_boundary": threat.crosses_trust_boundary,
            }
        else:
            m = merged[key]
            m["node_ids_frozen"] = m["node_ids_frozen"] | threat.node_ids_frozen
            m["node_ids_sorted"] = sorted(m["node_ids_frozen"])
            m["priority"] = min(m["priority"], threat.priority)
            for eid in threat.edge_ids:
                if eid not in m["edge_ids"]:
                    m["edge_ids"].append(eid)
            # Keep the most specific rationale (longest = most context)
            if len(threat.relevance_rationale) > len(m["relevance_rationale"]):
                m["relevance_rationale"] = threat.relevance_rationale
            # provider_managed is True if ANY matching threat is provider-managed
            if threat.provider_managed:
                m["provider_managed"] = True
            # crosses_trust_boundary is True if ANY variant crosses a boundary
            if threat.crosses_trust_boundary:
                m["crosses_trust_boundary"] = True

    # Step 8: sort and assign display_ids
    deduped = _diversify_rule_order(list(merged.values()))

    threats: list[GeneratedThreat] = []
    for idx, m in enumerate(deduped, start=1):
        threats.append(GeneratedThreat(
            rule_id=m["rule_id"],
            display_id=f"T-{idx:03d}",
            stride_category=m["stride_category"],
            threat_subtype=m["threat_subtype"],
            severity=m["severity"],
            description=m["description"],
            affected_node_ids=m["node_ids_sorted"],
            affected_edge_ids=m["edge_ids"],
            relevance_rationale=m["relevance_rationale"],
            source="Rules",
            provider_managed=m.get("provider_managed", False),
            crosses_trust_boundary=m.get("crosses_trust_boundary", False),
        ))

    elapsed_ms = (time.perf_counter() - start) * 1000.0

    return RuleEngineOutput(
        threats=threats,
        execution_time_ms=elapsed_ms,
        rules_evaluated=rules_evaluated,
        rules_fired=len(fired_rule_ids),
        warnings=warnings,
    )
