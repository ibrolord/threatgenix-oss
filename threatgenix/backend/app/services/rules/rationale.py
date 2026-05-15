"""Contextual relevance rationale generator for rule-based threats.

Generates human-readable explanations of WHY a threat matters for THIS
specific system, based on node properties, data flow labels, boundary
context, and security posture — not just structural pattern matches.
"""

from __future__ import annotations

import re

from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse
from app.services.dfd_semantics import (
    infer_handles_sensitive_data,
    infer_internet_facing_exposure,
    infer_select_presence,
    infer_trusted_boundary,
)
from app.services.rules.conditions import _base_type

# Keywords that indicate high-value data in flow labels.
# Uses word-boundary regex to avoid false positives (e.g., "name" in "filename").
_FINANCIAL_PATTERNS = re.compile(
    r"\b(payment|transaction|transfer|balance|account_?\w*balance|"
    r"card(?:holder)?|debit|credit|wire|fund|deposit|withdraw)\b", re.IGNORECASE
)
_CREDENTIAL_PATTERNS = re.compile(
    r"\b(password|credentials?|token|secret|api[_\s]?key|"
    r"auth(?:entication)?|jwt|session[_\s]?id|oauth|bearer)\b", re.IGNORECASE
)
_PII_PATTERNS = re.compile(
    r"\b(ssn|social[_\s]?insurance|sin[_\s]number|"
    r"(?:full|first|last)[_\s]?name|home[_\s]?address|mailing[_\s]?address|"
    r"email[_\s]?address|email|phone[_\s]?number|"
    r"dob|date[_\s]?of[_\s]?birth)\b", re.IGNORECASE
)


def _classify_data_flow(label: str) -> list[str]:
    """Classify what kind of data a flow carries based on its label."""
    if not label:
        return []
    classes = []
    if _FINANCIAL_PATTERNS.search(label):
        classes.append("financial data")
    if _CREDENTIAL_PATTERNS.search(label):
        classes.append("credentials/secrets")
    if _PII_PATTERNS.search(label):
        classes.append("personally identifiable information")
    return classes


def _prop_state(node: DFDNodeResponse, key: str) -> bool | None:
    """Return tri-state property values instead of treating missing as false."""
    properties = node.properties or {}
    value = properties.get(key)
    if value is None:
        if key == "uses_auth":
            return infer_select_presence(properties.get("authentication_type"))
        if key == "validates_input":
            return infer_select_presence(properties.get("input_validation"))
        if key == "encrypted_at_rest":
            return infer_select_presence(properties.get("encryption_at_rest"))
        if key == "has_backup":
            return infer_select_presence(properties.get("backup_strategy"))
        if key == "internet_facing":
            return infer_internet_facing_exposure(properties.get("network_exposure"))
        if key == "trusted":
            return infer_trusted_boundary(properties.get("trust_level"))
        if key == "authenticated":
            return infer_select_presence(properties.get("authentication_type"))
        if key == "handles_sensitive_data":
            return infer_handles_sensitive_data(properties)
    if value is True:
        return True
    if value is False:
        return False
    return None


def _describe_security_posture(node: DFDNodeResponse) -> list[str]:
    """List explicitly known security gaps on a node."""
    gaps = []
    if _base_type(node.node_type) == "process":
        if _prop_state(node, "internet_facing") is True and _prop_state(node, "uses_auth") is False:
            gaps.append("internet-exposed without authentication")
        elif _prop_state(node, "uses_auth") is False:
            gaps.append("no authentication")
        if _prop_state(node, "validates_input") is False:
            gaps.append("no input validation")
        if _prop_state(node, "uses_encryption") is False:
            gaps.append("no encryption")
        if _prop_state(node, "handles_sensitive_data") is True:
            gaps.append("handles sensitive data")
    elif _base_type(node.node_type) == "data_store":
        if _prop_state(node, "encrypted_at_rest") is False:
            gaps.append("not encrypted at rest")
        if _prop_state(node, "stores_credentials") is True:
            gaps.append("stores credentials")
        if _prop_state(node, "has_backup") is False:
            gaps.append("no backup")
        if _prop_state(node, "internet_facing") is True:
            gaps.append("directly internet-exposed")
    elif _base_type(node.node_type) == "external_entity":
        if _prop_state(node, "trusted") is False:
            gaps.append("untrusted")
        if _prop_state(node, "authenticated") is False:
            gaps.append("unauthenticated")
    return gaps


def build_rationale_tuple(
    rule_id: str,
    source: DFDNodeResponse,
    edge: DFDEdgeResponse,
    target: DFDNodeResponse,
    crosses_boundary: bool,
    boundary_name: str | None,
) -> str:
    """Build contextual rationale for a tuple-based (edge) rule firing."""
    parts = []

    # What data is at stake?
    data_classes = _classify_data_flow(edge.label or "")
    if data_classes:
        parts.append(
            f"This flow carries {', '.join(data_classes)} "
            f"(\"{edge.label}\"), making exploitation high-impact."
        )

    # What's the security posture of the nodes?
    source_gaps = _describe_security_posture(source)
    target_gaps = _describe_security_posture(target)

    if source_gaps:
        parts.append(
            f"{source.name} has these security concerns: {', '.join(source_gaps)} — "
            f"increasing the likelihood of this threat."
        )
    if target_gaps:
        parts.append(
            f"{target.name} has these security concerns: {', '.join(target_gaps)} — "
            f"leaving it vulnerable to this attack."
        )

    # Boundary crossing context
    if crosses_boundary and boundary_name:
        parts.append(
            f"The data crosses the \"{boundary_name}\" trust boundary, "
            f"meaning it transitions between different security domains."
        )

    # If we have nothing specific, at least explain the structural relationship
    if not parts:
        parts.append(
            f"The data flow from {source.name} ({source.node_type}) to "
            f"{target.name} ({target.node_type}) creates an attack surface "
            f"that should be evaluated in context of your system's risk profile."
        )

    return " ".join(parts)


def build_rationale_standalone(
    rule_id: str,
    node: DFDNodeResponse,
    context: dict,
) -> str:
    """Build contextual rationale for a standalone (node) rule firing."""
    parts = []
    gaps = _describe_security_posture(node)

    if gaps:
        parts.append(
            f"{node.name} currently has these security gaps: "
            f"{', '.join(gaps)}."
        )

    # Check what flows into/out of this node to understand impact
    all_edges = context.get("all_edges", [])
    node_id = str(node.id)
    inbound_labels = []
    outbound_labels = []
    for e in all_edges:
        if str(e.target_node_id) == node_id and e.label:
            inbound_labels.append(e.label)
        if str(e.source_node_id) == node_id and e.label:
            outbound_labels.append(e.label)

    # Classify data flowing through this node
    all_labels = inbound_labels + outbound_labels
    all_data_classes = set()
    for label in all_labels:
        all_data_classes.update(_classify_data_flow(label))

    if all_data_classes:
        parts.append(
            f"This component processes {', '.join(sorted(all_data_classes))}, "
            f"so compromise would directly impact sensitive operations."
        )

    if len(inbound_labels) + len(outbound_labels) >= 4:
        parts.append(
            f"It has {len(inbound_labels)} inbound and {len(outbound_labels)} "
            f"outbound data flows, making it a high-connectivity target."
        )

    # Check if it's in a trust boundary
    boundaries = context.get("boundaries", [])
    for b in boundaries:
        if node.id in (b.node_ids or []):
            parts.append(f"Located within the \"{b.name}\" trust boundary.")
            break

    if not parts:
        parts.append(
            f"{node.name} ({node.node_type}) should be evaluated based on "
            f"the sensitivity of data it handles and its role in the system."
        )

    return " ".join(parts)


def build_rationale_boundary(
    rule_id: str,
    boundary_name: str,
    entry_count: int,
    node_count: int,
) -> str:
    """Build contextual rationale for a boundary-based rule firing."""
    return (
        f"The \"{boundary_name}\" boundary has {entry_count} entry points "
        f"protecting {node_count} internal components. Each entry point is "
        f"a potential attack vector that must be individually secured — "
        f"the more entry points, the harder it is to maintain consistent "
        f"security controls across all of them."
    )
