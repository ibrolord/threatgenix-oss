from __future__ import annotations

import re

from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, TrustBoundaryResponse
from app.services.dfd_semantics import (
    infer_handles_sensitive_data,
    infer_internet_facing_exposure,
    infer_select_presence,
    infer_trusted_boundary,
    is_deprecated_tls_value,
    is_no_tls_value,
    is_tls_1_0_value,
    is_tls_1_1_value,
)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

SENSITIVE_KEYWORDS: tuple[str, ...] = (
    "password",
    "credential",
    "token",
    "secret",
    "key",
    "auth",
    "ssn",
    "sin",
    "account",
)

_FINANCIAL_FLOW_RE = re.compile(
    r"\b(payment|transaction|transfer|posting|balance|callback|wire|fund|approval)\b",
    re.IGNORECASE,
)
_PRIVILEGED_FLOW_RE = re.compile(
    r"\b(privileged|override|repair|approval|approved|admin|operator|diagnostic|time-boxed)\b",
    re.IGNORECASE,
)
_SWIFT_FLOW_RE = re.compile(r"\bswift\b", re.IGNORECASE)
_TOKEN_FLOW_RE = re.compile(r"\b(token|tokenization|detoken|pan)\b", re.IGNORECASE)
_LEDGER_FLOW_RE = re.compile(
    r"\b(posting|balance|ledger|replay|reconcile)\b",
    re.IGNORECASE,
)
_SCREENING_FLOW_RE = re.compile(
    r"\b(fraud|aml|screening|sanctions|investigation|scoring)\b",
    re.IGNORECASE,
)
_BREAK_GLASS_FLOW_RE = re.compile(
    r"\b(break[- ]glass|emergency|override|repair|replay|resubmit)\b",
    re.IGNORECASE,
)

_OPERATOR_NODE_RE = re.compile(
    r"\b(treasury|operator|portal user|admin|analyst)\b",
    re.IGNORECASE,
)
_PAYMENT_NODE_RE = re.compile(
    # NOTE: intentionally excludes bare "api" — too generic; matches any node named "X API".
    # Use "payment gateway", "api gateway", or "orchestrator" for specificity.
    r"\b(payment|payments|payment gateway|payment orchestrator|api gateway)\b",
    re.IGNORECASE,
)
_SWIFT_NODE_RE = re.compile(r"\bswift\b", re.IGNORECASE)
_TOKEN_NODE_RE = re.compile(
    r"\b(token vault|card token|network token|tokenization|detoken|pan)\b",
    re.IGNORECASE,
)
_LEDGER_NODE_RE = re.compile(r"\b(ledger|core banking|reconcile)\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Cloud-native node type mapping
# ---------------------------------------------------------------------------

_CLOUD_BASE_TYPE: dict[str, str] = {
    "human_actor": "external_entity",
    "iam_role": "external_entity",
    "managed_service": "data_store",
    "api_gateway": "process",
    "container": "process",
    "serverless": "process",
}


def _base_type(node_type: str) -> str:
    """Map cloud node types to their STRIDE base type.

    Classic types pass through unchanged. Cloud types map to the base type
    that the existing 41 rules understand, so no rule changes are needed.
    """
    return _CLOUD_BASE_TYPE.get(node_type, node_type)


def _is_cloud_type(node_type: str) -> bool:
    return node_type in _CLOUD_BASE_TYPE


def _prop(node: DFDNodeResponse, key: str) -> bool:
    """Return True only if the property key is explicitly True in the node's properties dict.

    Missing keys, None values, and non-bool values all return False.
    """
    properties = node.properties or {}
    value = properties.get(key)
    if value is None:
        if key == "uses_auth":
            inferred = infer_select_presence(properties.get("authentication_type"))
            if inferred is not None:
                return inferred
        if key == "validates_input":
            inferred = infer_select_presence(properties.get("input_validation"))
            if inferred is not None:
                return inferred
        if key == "encrypted_at_rest":
            inferred = infer_select_presence(properties.get("encryption_at_rest"))
            if inferred is not None:
                return inferred
        if key == "has_backup":
            inferred = infer_select_presence(properties.get("backup_strategy"))
            if inferred is not None:
                return inferred
        if key == "internet_facing":
            inferred = infer_internet_facing_exposure(properties.get("network_exposure"))
            if inferred is not None:
                return inferred
        if key == "trusted":
            inferred = infer_trusted_boundary(properties.get("trust_level"))
            if inferred is not None:
                return inferred
        if key == "authenticated":
            inferred = infer_select_presence(properties.get("authentication_type"))
            if inferred is not None:
                return inferred
        if key == "handles_sensitive_data":
            inferred = infer_handles_sensitive_data(properties)
            if inferred is not None:
                return inferred
    if value is True:
        return True
    return False


def _is_true(node: DFDNodeResponse, key: str) -> bool:
    return _prop(node, key) is True


def _is_false(node: DFDNodeResponse, key: str) -> bool:
    return _prop(node, key) is False


def _matches(pattern: re.Pattern[str], value: str | None) -> bool:
    return bool(value and pattern.search(value))


def _node_text(node: DFDNodeResponse) -> str:
    description = (node.properties or {}).get("description")
    if isinstance(description, str) and description.strip():
        return f"{node.name} {description}"
    return node.name


def _label(edge: DFDEdgeResponse) -> str:
    return edge.label or ""


def _flow_matches(edge: DFDEdgeResponse, *patterns: re.Pattern[str]) -> bool:
    label = _label(edge)
    return any(_matches(pattern, label) for pattern in patterns)


def _node_matches(node: DFDNodeResponse, *patterns: re.Pattern[str]) -> bool:
    text = _node_text(node)
    return any(_matches(pattern, text) for pattern in patterns)


def _node_name_matches(node: DFDNodeResponse, *patterns: re.Pattern[str]) -> bool:
    return any(_matches(pattern, node.name) for pattern in patterns)


def _degree(node: DFDNodeResponse, context: dict) -> int:
    node_id = str(node.id)
    all_edges: list[DFDEdgeResponse] = context.get("all_edges", [])
    return sum(
        1
        for edge in all_edges
        if str(edge.source_node_id) == node_id or str(edge.target_node_id) == node_id
    )


def _connected_edges(node: DFDNodeResponse, context: dict) -> list[DFDEdgeResponse]:
    node_id = str(node.id)
    all_edges: list[DFDEdgeResponse] = context.get("all_edges", [])
    return [
        edge
        for edge in all_edges
        if str(edge.source_node_id) == node_id or str(edge.target_node_id) == node_id
    ]


def _connected_nodes(node: DFDNodeResponse, context: dict) -> list[DFDNodeResponse]:
    node_id = str(node.id)
    all_nodes: list[DFDNodeResponse] = context.get("all_nodes", [])
    node_map = {str(candidate.id): candidate for candidate in all_nodes}
    neighbors: list[DFDNodeResponse] = []
    seen_ids: set[str] = set()
    for edge in _connected_edges(node, context):
        neighbor_id = (
            str(edge.target_node_id)
            if str(edge.source_node_id) == node_id
            else str(edge.source_node_id)
        )
        neighbor = node_map.get(neighbor_id)
        if neighbor and neighbor_id not in seen_ids:
            neighbors.append(neighbor)
            seen_ids.add(neighbor_id)
    return neighbors


def _boundary_names_for_node(node: DFDNodeResponse, context: dict) -> list[str]:
    node_id = str(node.id)
    boundaries: list[TrustBoundaryResponse] = context.get("boundaries", [])
    return [
        boundary.name
        for boundary in boundaries
        if node_id in {str(candidate_id) for candidate_id in boundary.node_ids}
    ]


def _node_in_boundary_matching(
    node: DFDNodeResponse,
    context: dict,
    *patterns: re.Pattern[str],
) -> bool:
    return any(
        _matches(pattern, boundary_name)
        for boundary_name in _boundary_names_for_node(node, context)
        for pattern in patterns
    )


def _connected_to_pattern(
    node: DFDNodeResponse,
    context: dict,
    *patterns: re.Pattern[str],
) -> bool:
    return any(_flow_matches(edge, *patterns) for edge in _connected_edges(node, context))


def _connected_to_node_pattern(
    node: DFDNodeResponse,
    context: dict,
    *patterns: re.Pattern[str],
) -> bool:
    return any(_node_matches(neighbor, *patterns) for neighbor in _connected_nodes(node, context))


def _is_partial_model(context: dict) -> bool:
    all_nodes: list[DFDNodeResponse] = context.get("all_nodes", [])
    all_edges: list[DFDEdgeResponse] = context.get("all_edges", [])
    return len(all_nodes) >= 2 and len(all_edges) <= 1


def _is_high_value_flow(edge: DFDEdgeResponse) -> bool:
    return _flow_matches(
        edge,
        _FINANCIAL_FLOW_RE,
        _PRIVILEGED_FLOW_RE,
        _SWIFT_FLOW_RE,
        _TOKEN_FLOW_RE,
        _LEDGER_FLOW_RE,
        _SCREENING_FLOW_RE,
    )


def _tls_version(edge: DFDEdgeResponse) -> str | None:
    """Return tls_version from edge fields, or None."""
    if edge.tls_version:
        return edge.tls_version
    props = edge.properties if isinstance(edge.properties, dict) else (edge.properties.model_dump() if edge.properties else {})
    return props.get("tls_version")


def _is_deprecated_tls(edge: DFDEdgeResponse) -> bool:
    """True if edge explicitly declares a deprecated TLS version (1.0 or 1.1)."""
    return is_deprecated_tls_value(_tls_version(edge))


def _is_no_tls(edge: DFDEdgeResponse) -> bool:
    """True if edge explicitly declares no TLS."""
    return is_no_tls_value(_tls_version(edge))


def _edge_prop_true(edge: DFDEdgeResponse, key: str) -> bool:
    """Return True only if the given edge property key is explicitly True."""
    props = edge.properties if isinstance(edge.properties, dict) else (edge.properties.model_dump() if edge.properties else {})
    return props.get(key) is True


def _has_security_control(node: DFDNodeResponse, control_type: str) -> bool:
    """True if node has a named security control of the given type (case-insensitive)."""
    props = node.properties if isinstance(node.properties, dict) else (node.properties.model_dump() if node.properties else {})
    controls = props.get("security_controls") or []
    ct_lower = control_type.lower()
    return any(c.get("control_type", "").lower() == ct_lower for c in controls if isinstance(c, dict))


def _is_token_store(node: DFDNodeResponse) -> bool:
    return _base_type(node.node_type) == "data_store" and _node_matches(node, _TOKEN_NODE_RE)


def _is_ledger_store(node: DFDNodeResponse) -> bool:
    return _base_type(node.node_type) == "data_store" and _node_matches(node, _LEDGER_NODE_RE)


def condition_s01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """External entity sends data to a process across a trust boundary."""
    if not (crosses_boundary and _base_type(source.node_type) == "external_entity" and _base_type(target.node_type) == "process"):
        return False
    if _is_true(source, "authenticated"):
        return False
    return True


def condition_s02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Any flow crosses a trust boundary (general spoofing risk)."""
    if not crosses_boundary:
        return False
    if _is_true(target, "uses_auth"):
        return False
    return True


def condition_s03(node: DFDNodeResponse, context: dict) -> bool:
    """High-value external actor without identity assurance.

    Fires only for external entities that participate in financial, privileged,
    or sensitive workflows — not for every unauthenticated external entity
    (which is already covered by S-01/S-04/S-05 on specific edges/boundaries).
    """
    if _base_type(node.node_type) != "external_entity":
        return False
    if _is_true(node, "authenticated"):
        return False
    # Must be a named high-value actor (treasury, operator, admin, analyst portal)
    # OR be connected to financial/privileged-labelled flows.
    return _node_matches(node, _OPERATOR_NODE_RE, _PAYMENT_NODE_RE, _SWIFT_NODE_RE) or (
        _connected_to_pattern(node, context, _FINANCIAL_FLOW_RE, _PRIVILEGED_FLOW_RE, _SWIFT_FLOW_RE)
    )


# ===========================================================================
# Tampering (T)
# ===========================================================================


def condition_t01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Data flow crosses trust boundary (data in transit risk)."""
    if not crosses_boundary:
        return False
    if _is_true(source, "uses_encryption") or _is_true(target, "uses_encryption"):
        return False
    return True


def condition_t02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """External entity writes to a data store."""
    return (
        _base_type(source.node_type) == "external_entity"
        and _base_type(target.node_type) == "data_store"
    )


def condition_t03(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Flow targets a data store (write integrity risk)."""
    if _base_type(target.node_type) != "data_store":
        return False
    if _is_true(target, "encrypted_at_rest"):
        return False
    return True


def condition_t04(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Flow crosses boundary AND targets data store."""
    return crosses_boundary and _base_type(target.node_type) == "data_store"


# ===========================================================================
# Repudiation (R)
# ===========================================================================


def condition_r01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """External entity interacts with system (no audit trail assumed)."""
    return (
        _base_type(source.node_type) == "external_entity"
        or _base_type(target.node_type) == "external_entity"
    )


def condition_r02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Weak auditability on a critical/privileged workflow.

    Fires only when the edge is part of a high-value control path — financial
    transactions, privileged overrides, or sensitive-data handling.  Generic
    process→process flows are covered by R-03/R-04 on the node level.
    """
    # At least one endpoint must be a process
    if not (_base_type(source.node_type) == "process" or _base_type(target.node_type) == "process"):
        return False
    # Flow label must indicate a critical/privileged/financial operation
    if _flow_matches(edge, _FINANCIAL_FLOW_RE, _PRIVILEGED_FLOW_RE, _SWIFT_FLOW_RE, _BREAK_GLASS_FLOW_RE):
        return True
    # Alternatively, either node must explicitly handle sensitive data
    return _is_true(source, "handles_sensitive_data") or _is_true(target, "handles_sensitive_data")


def condition_r03(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Process writes to data store (modification without audit)."""
    return (
        _base_type(source.node_type) == "process"
        and _base_type(target.node_type) == "data_store"
    )


# ===========================================================================
# Information Disclosure (I)
# ===========================================================================


def condition_i01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Data flow crosses trust boundary (exposure in transit)."""
    if not crosses_boundary:
        return False
    if _is_true(source, "uses_encryption") or _is_true(target, "uses_encryption"):
        return False
    return True


def condition_i02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Data store is read by external entity."""
    return (
        _base_type(source.node_type) == "data_store"
        and _base_type(target.node_type) == "external_entity"
    )


def condition_i03(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Flow from data store crosses boundary."""
    return crosses_boundary and _base_type(source.node_type) == "data_store"


def condition_i04(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Flow label contains sensitive keywords."""
    label_lower = _label(edge).lower()
    if not label_lower:
        return False
    if not any(keyword in label_lower for keyword in SENSITIVE_KEYWORDS):
        return False
    if _is_true(source, "uses_encryption"):
        return False
    return True


# ===========================================================================
# Denial of Service (D)
# ===========================================================================


def condition_d01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """External entity sends to a process (potential flood)."""
    if not (_base_type(source.node_type) == "external_entity" and _base_type(target.node_type) == "process"):
        return False
    if _is_true(target, "validates_input"):
        return False
    return True


def condition_d02(node: DFDNodeResponse, context: dict) -> bool:
    """Critical workflow process exhaustion.

    Fires only for processes that are internet-facing or have high connectivity
    (degree >= 3), making them realistic exhaustion targets in a banking context.
    Generic internal processes are not surface area for this threat.
    """
    if _base_type(node.node_type) != "process":
        return False
    # Internet-facing processes are directly reachable and the primary DoS surface
    if _is_true(node, "internet_facing"):
        return True
    # Processes connected to 2+ nodes are non-trivial dependencies — exhausting
    # them cascades (e.g. a payment service with one inbound + one core-banking link)
    return _degree(node, context) >= 2


def condition_d03(node: DFDNodeResponse, context: dict) -> bool:
    """Node is a single point of failure — has high connectivity (degree >= 4)."""
    return _degree(node, context) >= 4


# ===========================================================================
# Elevation of Privilege (E)
# ===========================================================================


def condition_e01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """External entity accesses a process across boundary."""
    if not (crosses_boundary and _base_type(source.node_type) == "external_entity" and _base_type(target.node_type) == "process"):
        return False
    if _is_true(source, "authenticated") and _is_true(target, "uses_auth"):
        return False
    return True


def condition_e02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Flow crosses trust boundary without authentication/encryption (privilege escalation vector)."""
    if not crosses_boundary:
        return False
    # Suppress when the source authenticates and the edge uses encryption in transit.
    # edge.properties may be a Pydantic model or a plain dict (raw/partial DFD data) — handle both.
    if edge.properties is None:
        _edge_props: dict = {}
    elif isinstance(edge.properties, dict):
        _edge_props = edge.properties
    else:
        _edge_props = edge.properties.model_dump()
    edge_encrypted = _edge_props.get("encryption_in_transit") is True
    if _is_true(source, "uses_auth") and edge_encrypted:
        return False
    # Also suppress when both ends explicitly mark the flow as authenticated
    if _is_true(source, "authenticated") and _is_true(target, "uses_auth"):
        return False
    return True


def condition_e03(boundary: TrustBoundaryResponse, entry_count: int) -> bool:
    """Trust boundary has multiple entry points (>= 2 inbound flows from outside)."""
    return entry_count >= 2


# ===========================================================================
# Property-Dependent Rules (F-07+)
# ===========================================================================

# --- Spoofing (S-04 to S-06) ---


def condition_s04(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Process without auth receives cross-boundary flow."""
    return (
        crosses_boundary
        and _base_type(target.node_type) == "process"
        and _is_false(target, "uses_auth")
    )


def condition_s05(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Unauthenticated external entity sends to data store."""
    return (
        _base_type(source.node_type) == "external_entity"
        and _base_type(target.node_type) == "data_store"
        and _is_false(source, "authenticated")
    )


def condition_s06(node: DFDNodeResponse, context: dict) -> bool:
    """Internet-facing process without authentication."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "internet_facing")
        and _is_false(node, "uses_auth")
    )


# --- Tampering (T-05 to T-08) ---


def condition_t05(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Process without input validation receives external input."""
    return (
        _base_type(source.node_type) == "external_entity"
        and _base_type(target.node_type) == "process"
        and _is_false(target, "validates_input")
    )


def condition_t06(node: DFDNodeResponse, context: dict) -> bool:
    """Data store without encryption at rest."""
    return (
        _base_type(node.node_type) == "data_store"
        and _is_false(node, "encrypted_at_rest")
    )


def condition_t07(node: DFDNodeResponse, context: dict) -> bool:
    """Internet-facing process without encryption."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "internet_facing")
        and _is_false(node, "uses_encryption")
    )


def condition_t08(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Privileged and payment-messaging flows are tampering targets."""
    if _base_type(target.node_type) != "process":
        return False
    if _flow_matches(edge, _SWIFT_FLOW_RE):
        return False
    if _flow_matches(edge, _PRIVILEGED_FLOW_RE, _BREAK_GLASS_FLOW_RE) and _node_matches(
        source, _OPERATOR_NODE_RE
    ):
        return False
    if _flow_matches(edge, _PRIVILEGED_FLOW_RE):
        return True
    return _is_high_value_flow(edge) and (
        _node_matches(source, _OPERATOR_NODE_RE)
        or _node_matches(target, _SWIFT_NODE_RE, _PAYMENT_NODE_RE)
    )


# --- Repudiation (R-04 to R-06) ---


def condition_r04(node: DFDNodeResponse, context: dict) -> bool:
    """Process handling sensitive data (audit gap risk)."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "handles_sensitive_data")
    )


def condition_r05(node: DFDNodeResponse, context: dict) -> bool:
    """Data store with credentials but no backup."""
    return (
        _base_type(node.node_type) == "data_store"
        and _is_true(node, "stores_credentials")
        and _is_false(node, "has_backup")
    )


def condition_r06(node: DFDNodeResponse, context: dict) -> bool:
    """Internet-facing process (unlogged actions risk)."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "internet_facing")
    )


# --- Information Disclosure (I-05 to I-08) ---


def condition_i05(node: DFDNodeResponse, context: dict) -> bool:
    """Data store with credentials but no encryption at rest."""
    return (
        _base_type(node.node_type) == "data_store"
        and _is_true(node, "stores_credentials")
        and _is_false(node, "encrypted_at_rest")
    )


def condition_i06(node: DFDNodeResponse, context: dict) -> bool:
    """Process handles sensitive data without encryption."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "handles_sensitive_data")
        and _is_false(node, "uses_encryption")
    )


def condition_i07(node: DFDNodeResponse, context: dict) -> bool:
    """Tokenization and detokenization stores are high-value disclosure targets."""
    return _is_token_store(node) and (
        _is_true(node, "stores_credentials")
        or _connected_to_pattern(node, context, _TOKEN_FLOW_RE, _FINANCIAL_FLOW_RE)
        or _degree(node, context) > 0
    )


def condition_i08(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Untrusted external entity reads from process."""
    return (
        _base_type(source.node_type) == "process"
        and _base_type(target.node_type) == "external_entity"
        and _is_false(target, "trusted")
    )


# --- Denial of Service (D-04 to D-06) ---


def condition_d04(node: DFDNodeResponse, context: dict) -> bool:
    """Internet-facing process without input validation."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "internet_facing")
        and _is_false(node, "validates_input")
    )


def condition_d05(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Internet-facing external entity targets process."""
    return (
        _base_type(source.node_type) == "external_entity"
        and _base_type(target.node_type) == "process"
        and _is_true(source, "internet_facing")
        and _is_high_value_flow(edge)
    )


def condition_d06(node: DFDNodeResponse, context: dict) -> bool:
    """Core ledger stores are availability-critical even when backed up."""
    return _is_ledger_store(node) and (
        _connected_to_pattern(node, context, _LEDGER_FLOW_RE, _FINANCIAL_FLOW_RE)
        or _connected_to_node_pattern(node, context, _PAYMENT_NODE_RE)
        or _matches(_LEDGER_FLOW_RE, _node_text(node))
    )


# --- Elevation of Privilege (E-04 to E-07) ---


def condition_e04(node: DFDNodeResponse, context: dict) -> bool:
    """Internet-facing process without authentication."""
    return (
        _base_type(node.node_type) == "process"
        and _is_true(node, "internet_facing")
        and _is_false(node, "uses_auth")
    )


def condition_e05(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Unauthenticated external entity accesses data store across boundary."""
    return (
        crosses_boundary
        and _base_type(source.node_type) == "external_entity"
        and _base_type(target.node_type) == "data_store"
        and _is_false(source, "authenticated")
    )


def condition_e06(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Process without input validation receives cross-boundary flow."""
    return (
        crosses_boundary
        and _base_type(target.node_type) == "process"
        and _is_false(target, "validates_input")
    )


def condition_e07(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Untrusted unauthenticated external entity with direct data store access."""
    return (
        _base_type(source.node_type) == "external_entity"
        and _base_type(target.node_type) == "data_store"
        and _is_false(source, "trusted")
        and _is_false(source, "authenticated")
    )


def condition_c01(node: DFDNodeResponse, context: dict) -> bool:
    """Managed service without encryption at rest (Information Disclosure)."""
    return (
        node.node_type == "managed_service"
        and _is_false(node, "encrypted_at_rest")
    )


def condition_c02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Serverless function crossing a trust boundary without authentication (Elevation of Privilege).

    Matches regardless of edge direction: outbound (serverless → X) or
    inbound (caller → serverless), which is the more common invocation pattern.
    """
    serverless_node = (
        source if source.node_type == "serverless"
        else target if target.node_type == "serverless"
        else None
    )
    return (
        crosses_boundary
        and serverless_node is not None
        and _is_false(serverless_node, "uses_auth")
    )


def condition_c03(node: DFDNodeResponse, context: dict) -> bool:
    """IAM role / identity provider not marked as authenticated — MFA not enforced (Spoofing)."""
    return (
        node.node_type == "iam_role"
        and _is_false(node, "authenticated")
    )


def condition_c04(node: DFDNodeResponse, context: dict) -> bool:
    """API gateway without input validation — accepts unvalidated input (Tampering)."""
    return (
        node.node_type == "api_gateway"
        and _is_false(node, "validates_input")
    )


def condition_c05(node: DFDNodeResponse, context: dict) -> bool:
    """Internet-facing container without encryption — unverified image source risk (Tampering)."""
    return (
        node.node_type == "container"
        and _is_true(node, "internet_facing")
        and _is_false(node, "uses_encryption")
    )


# ===========================================================================
# TLS Version Rules (T-TLS-01, T-TLS-02, I-TLS-01)
# ===========================================================================


def condition_t_tls_01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Data flow uses deprecated TLS 1.0 (Tampering — PCI DSS 4.0 Req 4.2.1)."""
    return _is_deprecated_tls(edge) and is_tls_1_0_value(_tls_version(edge))


def condition_t_tls_02(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Data flow uses deprecated TLS 1.1 (Tampering — PCI DSS 4.0 Req 4.2.1)."""
    return _is_deprecated_tls(edge) and is_tls_1_1_value(_tls_version(edge))


def condition_i_tls_01(
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
) -> bool:
    """Data flow carries sensitive data with no TLS (Information Disclosure)."""
    return _is_no_tls(edge) and (
        _edge_prop_true(edge, "carries_pii")
        or _edge_prop_true(edge, "carries_credentials")
        or _edge_prop_true(edge, "carries_financial_data")
        or _edge_prop_true(edge, "carries_secrets")
    )
