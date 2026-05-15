from __future__ import annotations

import re
from typing import Any

from app.schemas.dfd import (
    DFDQualityGateResult,
    DFDQualityGateSummary,
    DFDResponse,
    DFDViewResponse,
    DFDViewType,
    DFDEdgeResponse,
    DFDNodeResponse,
)
from app.services.dfd_semantics import (
    infer_internet_facing_exposure,
    infer_select_presence,
    is_sensitive_classification,
)

_GENERIC_FLOW_LABEL_RE = re.compile(r"^(request|response|payload|data|event|message|call|api call)$", re.IGNORECASE)
_GENERIC_NODE_NAME_RE = re.compile(
    r"^(backend|service|system|component|module|database layer|db layer|app|application|processor)$",
    re.IGNORECASE,
)


def _node_props(node: DFDNodeResponse) -> dict[str, Any]:
    if node.properties is None:
        return {}
    if hasattr(node.properties, "model_dump"):
        return node.properties.model_dump(exclude_none=True)
    if isinstance(node.properties, dict):
        return node.properties
    return {}


def _edge_props(edge: DFDEdgeResponse) -> dict[str, Any]:
    if edge.properties is None:
        return {}
    if hasattr(edge.properties, "model_dump"):
        return edge.properties.model_dump(exclude_none=True)
    if isinstance(edge.properties, dict):
        return edge.properties
    return {}


def _build_node_boundary_map(dfd: DFDResponse) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for node in dfd.nodes:
        if node.trust_boundary_id is not None:
            mapping[str(node.id)] = str(node.trust_boundary_id)
    for boundary in dfd.trust_boundaries:
        for node_id in boundary.node_ids:
            mapping[str(node_id)] = str(boundary.id)
    return mapping


def _is_boundary_crossing(edge: DFDEdgeResponse, node_boundary_map: dict[str, str]) -> bool:
    return node_boundary_map.get(str(edge.source_node_id)) != node_boundary_map.get(str(edge.target_node_id))


def _required_metadata_fields(node: DFDNodeResponse) -> list[str]:
    common = ["data_classification", "authentication_type", "network_exposure", "privilege_level"]
    if node.node_type in {"process", "api_gateway", "container", "serverless", "managed_service"}:
        return [*common, "runtime_type", "input_validation", "logging_level"]
    if node.node_type == "data_store":
        return [*common, "store_type", "store_purpose", "encryption_at_rest", "backup_strategy"]
    if node.node_type in {"external_entity", "human_actor", "iam_role"}:
        return [*common, "entity_scope", "entity_kind", "trust_level"]
    return common


def _missing_required_metadata(node: DFDNodeResponse) -> list[str]:
    properties = _node_props(node)
    return [field for field in _required_metadata_fields(node) if not properties.get(field)]


def _is_sensitive_node(node: DFDNodeResponse) -> bool:
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


def _is_sensitive_edge(edge: DFDEdgeResponse) -> bool:
    properties = _edge_props(edge)
    if is_sensitive_classification(properties.get("data_classification")):
        return True
    return any(
        properties.get(flag) is True
        for flag in ("carries_credentials", "carries_pii", "carries_secrets")
    )


def evaluate_quality_gates(
    dfd: DFDResponse,
    views: list[DFDViewResponse] | None = None,
) -> DFDQualityGateSummary:
    results: list[DFDQualityGateResult] = []
    if not dfd.nodes and not dfd.edges and not dfd.trust_boundaries:
        results.append(
            DFDQualityGateResult(
                gate_id="missing_dfd",
                title="DFD Required",
                severity="block",
                message="Build or import a DFD before relying on this model for semantic threat review, validation binding, or formal report export.",
            )
        )

    node_boundary_map = _build_node_boundary_map(dfd)
    node_by_id = {str(node.id): node for node in dfd.nodes}

    unlabeled_edge_ids = [
        edge.id
        for edge in dfd.edges
        if not edge.label.strip() and not _edge_props(edge).get("data_payload")
    ]
    if unlabeled_edge_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="unlabeled_flows",
                title="Unlabeled Data Flows",
                severity="block",
                message="Every data flow must be labeled with the real data being moved, not left blank.",
                affected_edge_ids=unlabeled_edge_ids,
            )
        )

    generic_flow_label_ids = [
        edge.id for edge in dfd.edges if edge.label.strip() and _GENERIC_FLOW_LABEL_RE.match(edge.label.strip())
    ]
    if generic_flow_label_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="generic_flow_labels",
                title="Generic Flow Labels",
                severity="warn",
                message="Replace generic flow labels like request or payload with the actual data being moved.",
                affected_edge_ids=generic_flow_label_ids,
            )
        )

    unclassified_store_ids = [
        node.id
        for node in dfd.nodes
        if node.node_type == "data_store" and not _node_props(node).get("data_classification")
    ]
    if unclassified_store_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="unclassified_data_stores",
                title="Unclassified Data Stores",
                severity="block",
                message="Every data store must declare a data classification so downstream threats can be ranked correctly.",
                affected_node_ids=unclassified_store_ids,
            )
        )

    unclassified_sensitive_flow_ids = []
    for edge in dfd.edges:
        properties = _edge_props(edge)
        if (
            _is_sensitive_edge(edge)
            or properties.get("data_payload")
        ) and not properties.get("data_classification"):
            unclassified_sensitive_flow_ids.append(edge.id)
    if unclassified_sensitive_flow_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="unclassified_sensitive_flows",
                title="Unclassified Sensitive Flows",
                severity="warn",
                message="Sensitive flows should declare a data classification so downstream risks can be ranked correctly.",
                affected_edge_ids=unclassified_sensitive_flow_ids,
            )
        )

    orphan_node_ids = []
    for node in dfd.nodes:
        if not any(
            edge.source_node_id == node.id or edge.target_node_id == node.id for edge in dfd.edges
        ):
            orphan_node_ids.append(node.id)
    if orphan_node_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="orphan_nodes",
                title="Disconnected Nodes",
                severity="block",
                message="Each modeled node must participate in at least one data flow.",
                affected_node_ids=orphan_node_ids,
            )
        )

    if not views or not any(view.view_type == DFDViewType.context for view in views):
        results.append(
            DFDQualityGateResult(
                gate_id="missing_context_view",
                title="Missing Context View",
                severity="block",
                message="A world-class DFD needs a context view that shows the system boundary and its external interactions.",
            )
        )

    if any(_is_sensitive_node(node) for node in dfd.nodes) or any(_is_sensitive_edge(edge) for edge in dfd.edges):
        if not views or not any(view.view_type == DFDViewType.data_lifecycle for view in views):
            results.append(
                DFDQualityGateResult(
                    gate_id="missing_data_lifecycle_view",
                    title="Missing Sensitive Data View",
                    severity="warn",
                    message="Sensitive systems should expose a dedicated source-to-processing-to-sink view for regulated data paths.",
                )
            )

    sensitive_flow_missing_stage_ids = [
        edge.id
        for edge in dfd.edges
        if _is_sensitive_edge(edge) and not _edge_props(edge).get("lifecycle_stage")
    ]
    if sensitive_flow_missing_stage_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="sensitive_flows_missing_lifecycle_stage",
                title="Sensitive Flows Missing Lifecycle Stage",
                severity="warn",
                message="Mark whether each sensitive flow is ingress, processing, storage, egress, replication, backup, analytics, or notification.",
                affected_edge_ids=sensitive_flow_missing_stage_ids,
            )
        )

    if len(dfd.nodes) >= 6 and not dfd.trust_boundaries:
        results.append(
            DFDQualityGateResult(
                gate_id="missing_trust_boundaries",
                title="Missing Trust Boundaries",
                severity="warn",
                message="Complex systems should model explicit trust boundaries so cross-zone attack paths can be reasoned about.",
            )
        )

    metadata_gap_ids = [
        node.id for node in dfd.nodes if _missing_required_metadata(node)
    ]
    if metadata_gap_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="missing_security_metadata",
                title="Missing Security Metadata",
                severity="warn",
                message="Some nodes are missing mandatory security metadata for their type.",
                affected_node_ids=metadata_gap_ids,
            )
        )

    direct_store_to_store_ids = [
        edge.id
        for edge in dfd.edges
        if node_by_id.get(str(edge.source_node_id), None)
        and node_by_id.get(str(edge.target_node_id), None)
        and node_by_id[str(edge.source_node_id)].node_type == "data_store"
        and node_by_id[str(edge.target_node_id)].node_type == "data_store"
    ]
    if direct_store_to_store_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="store_to_store_flows",
                title="Store-to-Store Flows",
                severity="warn",
                message="A direct data store to data store flow usually means a missing process or transform stage in the model.",
                affected_edge_ids=direct_store_to_store_ids,
            )
        )

    vague_node_ids = [
        node.id for node in dfd.nodes if _GENERIC_NODE_NAME_RE.match(node.name.strip())
    ]
    if vague_node_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="vague_node_names",
                title="Vague Node Names",
                severity="warn",
                message="Replace generic node names like backend or service with the actual security-relevant component name.",
                affected_node_ids=vague_node_ids,
            )
        )

    internet_process_without_auth_ids = []
    for node in dfd.nodes:
        if node.node_type not in {"process", "api_gateway", "container", "serverless"}:
            continue
        properties = _node_props(node)
        if (
            infer_internet_facing_exposure(properties.get("network_exposure")) is True
            and infer_select_presence(properties.get("authentication_type")) is not True
        ):
            internet_process_without_auth_ids.append(node.id)
    if internet_process_without_auth_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="internet_process_without_auth",
                title="Internet-Facing Process Without Authentication",
                severity="warn",
                message="Internet-facing processes should usually declare an authentication control.",
                affected_node_ids=internet_process_without_auth_ids,
            )
        )

    unencrypted_crossing_edge_ids = [
        edge.id
        for edge in dfd.edges
        if _is_boundary_crossing(edge, node_boundary_map)
        and _edge_props(edge).get("encryption_in_transit") is False
    ]
    if unencrypted_crossing_edge_ids:
        results.append(
            DFDQualityGateResult(
                gate_id="unencrypted_boundary_crossings",
                title="Unencrypted Trust-Boundary Crossings",
                severity="warn",
                message="Boundary-crossing flows should declare protection in transit.",
                affected_edge_ids=unencrypted_crossing_edge_ids,
            )
        )

    # Gate: internet-facing nodes must be inside a trust boundary
    internet_nodes_without_boundary = [
        node for node in dfd.nodes
        if _node_props(node).get("internet_facing") is True
        and node.trust_boundary_id is None
        and str(node.id) not in node_boundary_map
    ]
    if internet_nodes_without_boundary:
        results.append(DFDQualityGateResult(
            gate_id="missing_external_boundary",
            title="Internet-Facing Node Outside Trust Boundary",
            severity="warn",
            message="Internet-facing nodes must be inside a trust boundary (e.g. DMZ or External Network). Without a boundary, no boundary-crossing STRIDE rules fire for inbound traffic.",
            affected_node_ids=[n.id for n in internet_nodes_without_boundary],
        ))

    # Gate: if sensitive nodes exist, at least one audit/logging node must exist with an incoming edge
    sensitive_nodes = [n for n in dfd.nodes if _is_sensitive_node(n)]
    if sensitive_nodes:
        log_node_ids = {
            str(n.id) for n in dfd.nodes
            if any(kw in n.name.lower() for kw in ("log", "audit", "siem", "monitor", "splunk", "elk", "cloudwatch"))
        }
        has_log_edge = any(
            str(edge.target_node_id) in log_node_ids
            for edge in dfd.edges
        )
        if not log_node_ids or not has_log_edge:
            results.append(DFDQualityGateResult(
                gate_id="no_logging_path",
                title="No Audit Logging Path Modeled",
                severity="warn",
                message="The DFD contains sensitive nodes but no identifiable log/audit destination with an incoming data flow. OSFI B-13 Section 3.5 and PCI DSS Requirement 10 require active logging of access to sensitive systems.",
                affected_node_ids=[n.id for n in sensitive_nodes[:5]],
            ))

    # Gate: financial data nodes need a CDE boundary
    financial_nodes = [
        n for n in dfd.nodes
        if _node_props(n).get("handles_financial_data") is True
        or _node_props(n).get("stores_credentials") is True
    ]
    if financial_nodes:
        boundary_names_lower = {b.name.lower() for b in dfd.trust_boundaries}
        has_cde_boundary = any(
            kw in name for name in boundary_names_lower
            for kw in ("cde", "pci", "cardholder", "payment")
        )
        if not has_cde_boundary:
            results.append(DFDQualityGateResult(
                gate_id="cde_isolation",
                title="No CDE Trust Boundary Defined",
                severity="warn",
                message="Nodes that handle financial data or store credentials require a clearly named CDE (Cardholder Data Environment) trust boundary per PCI DSS 4.0 Requirement 1.2.4.",
                affected_node_ids=[n.id for n in financial_nodes[:5]],
            ))

    # Gate: external service (non-human) nodes should have their own trust boundary
    external_services = [
        n for n in dfd.nodes
        if n.node_type in ("external_entity",)
        and not any(kw in n.name.lower() for kw in ("user", "customer", "browser", "mobile", "web", "client", "portal"))
        and n.trust_boundary_id is None
        and str(n.id) not in node_boundary_map
    ]
    if external_services:
        results.append(DFDQualityGateResult(
            gate_id="third_party_boundary",
            title="Third-Party Service Without Dedicated Trust Boundary",
            severity="warn",
            message="External service integrations (APIs, payment processors, identity providers) should be in a dedicated 'Third-Party' trust boundary per OSFI B-13 Section 2.2.2. This enables explicit third-party risk rules.",
            affected_node_ids=[n.id for n in external_services[:5]],
        ))

    # Gate: secrets/key stores must not share a boundary with the data they protect
    secret_stores = [
        n for n in dfd.nodes
        if _node_props(n).get("stores_secrets") is True
        or (n.node_type in ("data_store",) and any(kw in n.name.lower() for kw in ("secret", "key", "kms", "vault", "hsm")))
    ]
    sensitive_stores = [
        n for n in dfd.nodes
        if n.node_type == "data_store"
        and (_node_props(n).get("handles_pii") is True or _node_props(n).get("handles_financial_data") is True)
        and n not in secret_stores
    ]
    colocated_pairs = []
    for ss in secret_stores:
        ss_boundary = node_boundary_map.get(str(ss.id)) or ss.trust_boundary_id
        for ds in sensitive_stores:
            ds_boundary = node_boundary_map.get(str(ds.id)) or ds.trust_boundary_id
            if ss_boundary and ds_boundary and str(ss_boundary) == str(ds_boundary):
                colocated_pairs.append(ss.id)
    if colocated_pairs:
        results.append(DFDQualityGateResult(
            gate_id="key_colocation",
            title="Encryption Keys Co-Located with Protected Data",
            severity="warn",
            message="Secrets/key stores (KMS, Vault, HSM) are in the same trust boundary as the sensitive data they protect. Compromising the boundary exposes both data and keys simultaneously. Keys must be in a separate boundary.",
            affected_node_ids=list(set(colocated_pairs))[:5],
        ))

    # Gate: admin/system privilege nodes should be in a distinct boundary or have clearly marked admin flows
    admin_nodes = [
        n for n in dfd.nodes
        if _node_props(n).get("privilege_level") in ("admin", "system", "privileged")
    ]
    if admin_nodes:
        boundary_names_lower = {b.name.lower() for b in dfd.trust_boundaries}
        has_admin_boundary = any(
            kw in name for name in boundary_names_lower
            for kw in ("admin", "management", "mgmt", "privileged", "break-glass", "ops")
        )
        if not has_admin_boundary:
            results.append(DFDQualityGateResult(
                gate_id="admin_path_unmarked",
                title="Privileged Access Nodes Without Admin Boundary",
                severity="warn",
                message="Nodes with admin/system privilege level should be in a dedicated management boundary (e.g. 'Admin / Management Plane'). Without this, privileged access paths are invisible to reviewers and auditors.",
                affected_node_ids=[n.id for n in admin_nodes[:5]],
            ))

    warning_count = sum(1 for result in results if result.severity == "warn")
    blocking_count = sum(1 for result in results if result.severity == "block")
    return DFDQualityGateSummary(
        blocking_count=blocking_count,
        warning_count=warning_count,
        results=results,
    )
