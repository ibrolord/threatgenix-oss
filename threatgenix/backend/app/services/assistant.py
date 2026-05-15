from __future__ import annotations

from collections import Counter, defaultdict, deque
from functools import lru_cache
import re
from typing import Any, Iterable
from uuid import UUID

from pydantic import ValidationError

from app.schemas.assistant import (
    AssistantActionArtifact,
    AssistantAnchor,
    AssistantGuidedStep,
    AssistantProposal,
    AssistantProposalBundle,
    AssistantReference,
    AssistantRequest,
    AssistantResponse,
    AssistantReviewFinding,
)
from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, DFDResponse, TrustBoundaryResponse
from app.schemas.security_review import (
    ReviewArtifactKind,
    SecurityReviewApplicationSummary,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
)
from app.schemas.threat import ThreatResponse
from app.services.security_review_artifacts import build_security_review_artifact
from app.services.llm_client import get_llm_client_for_user
from app.services.rules.loader import load_rules

ASSISTANT_PROMPT_VERSION = "v1.0"

VALID_NODE_TYPES = {
    "process",
    "data_store",
    "external_entity",
    "iam_role",
    "managed_service",
    "api_gateway",
    "container",
    "serverless",
}
PROCESS_LIKE_NODE_TYPES = {
    "process",
    "api_gateway",
    "container",
    "serverless",
    "managed_service",
}
VALID_PROPERTY_KEYS = {
    "component_template_id",
    "component_label",
    "component_shape",
    "component_description",
    "property_display_labels",
    "internet_facing",
    "data_classification",
    "authentication_type",
    "authorization_model",
    "network_exposure",
    "privilege_level",
    "uses_auth",
    "validates_input",
    "uses_encryption",
    "handles_sensitive_data",
    "runtime_type",
    "isolation_boundary",
    "accepted_input",
    "input_validation",
    "logging_level",
    "handles_pii",
    "handles_financial_data",
    "stores_credentials",
    "encrypted_at_rest",
    "has_backup",
    "store_type",
    "store_purpose",
    "read_access_scope",
    "write_access_scope",
    "encryption_at_rest",
    "backup_strategy",
    "integrity_controls",
    "stores_secrets",
    "trusted",
    "authenticated",
    "entity_scope",
    "entity_kind",
    "trust_level",
    "service_name",
    "function_name",
    "responsibility",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
ASSISTANT_TITLE_MAX_LENGTH = 160
ASSISTANT_FINDING_DESCRIPTION_MAX_LENGTH = 1200

ASSISTANT_SYSTEM_MESSAGE = """\
You are ThreatGenix Assistant.

You help users reason about a live threat model. The DFD is a structured security graph, not a picture.

Rules:
- Ground every answer in the provided threat model context.
- Never invent nodes, edges, trust boundaries, or threats that are not present in the context.
- If you propose a graph change, propose only the smallest useful reversible action.
- Use exact IDs from the provided context for references and proposals.
- Do not claim compliance certification. Describe coverage, mappings, or gaps only.
- Keep answers concise and product-facing.
- If the user request is ambiguous, explain what is missing instead of guessing wildly.

You must call the respond_to_user tool with your structured answer.
"""

ASSISTANT_RESPONSE_TOOL: dict[str, Any] = {
    "name": "respond_to_user",
    "description": "Return a grounded ThreatGenix assistant response with optional graph edit proposal.",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["ask", "explain", "review", "build"],
                },
                "answer": {"type": "string"},
                "references": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["node", "edge", "boundary", "threat"],
                            },
                            "id": {"type": "string"},
                            "label": {"type": "string"},
                        },
                        "required": ["kind", "id", "label"],
                    },
                },
                "proposal": {
                    "type": "object",
                    "properties": {
                        "proposal_type": {
                            "type": "string",
                            "enum": [
                                "create_connected_node",
                            "create_node",
                            "create_edge",
                            "create_boundary",
                            "update_node",
                            "create_assumption",
                            ],
                        },
                        "title": {"type": "string"},
                        "summary": {"type": "string"},
                        "anchor_node_id": {"type": "string"},
                        "anchor_handle": {
                            "type": "string",
                            "enum": ["source", "target"],
                        },
                        "node_id": {"type": "string"},
                        "node_type": {"type": "string"},
                        "node_name": {"type": "string"},
                        "position_x": {"type": "number"},
                        "position_y": {"type": "number"},
                        "source_node_id": {"type": "string"},
                        "target_node_id": {"type": "string"},
                        "edge_label": {"type": "string"},
                        "boundary_name": {"type": "string"},
                        "boundary_node_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "name_patch": {"type": "string"},
                        "assumption_title": {"type": "string"},
                        "assumption_description": {"type": "string"},
                        "assumption_status": {
                            "type": "string",
                            "enum": ["open", "validated", "challenged"],
                        },
                        "assumption_anchor_kind": {
                            "type": "string",
                            "enum": ["node", "edge", "boundary"],
                        },
                        "assumption_anchor_id": {"type": "string"},
                        "assumption_anchor_label": {"type": "string"},
                        "properties_patch": {
                            "type": "object",
                            "additionalProperties": True,
                        },
                    },
                    "required": ["proposal_type", "title", "summary"],
                },
                "guided_steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "prompt": {"type": "string"},
                            "status": {
                                "type": "string",
                                "enum": ["done", "current", "up_next"],
                            },
                            "provenance": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                        "required": ["id", "title", "description", "prompt", "status"],
                    },
                },
                "action_artifacts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["remediation_note", "verification_note", "evidence_request"],
                            },
                            "title": {"type": "string"},
                            "summary": {"type": "string"},
                            "body": {"type": "string"},
                            "review_finding_id": {"type": "string"},
                            "source_object_type": {
                                "type": "string",
                                "enum": ["threat", "application_review_finding", "manual"],
                            },
                            "source_object_id": {"type": "string"},
                        },
                        "required": [
                            "kind",
                            "title",
                            "summary",
                            "body",
                            "review_finding_id",
                            "source_object_type",
                            "source_object_id",
                        ],
                    },
                },
                "degraded_reason": {"type": "string"},
            },
            "required": ["mode", "answer", "references"],
        }
    },
}


@lru_cache(maxsize=1)
def _rules_by_id() -> dict[str, Any]:
    return {rule.rule_id: rule for rule in load_rules()}


def _strip_command_prefix(message: str) -> tuple[str, str | None]:
    stripped = message.strip()
    lowered = stripped.lower()
    for command, mode in (
        ("/ask", "ask"),
        ("/build", "build"),
        ("/review", "review"),
        ("/explain", "explain"),
    ):
        if lowered.startswith(command):
            remainder = stripped[len(command):].strip()
            return remainder or stripped, mode
    return stripped, None


def _node_map(dfd: DFDResponse) -> dict[str, DFDNodeResponse]:
    return {str(node.id): node for node in dfd.nodes}


def _edge_map(dfd: DFDResponse) -> dict[str, DFDEdgeResponse]:
    return {str(edge.id): edge for edge in dfd.edges}


def _boundary_map(dfd: DFDResponse) -> dict[str, TrustBoundaryResponse]:
    return {str(boundary.id): boundary for boundary in dfd.trust_boundaries}


def _threat_map(threats: list[ThreatResponse]) -> dict[str, ThreatResponse]:
    return {str(threat.id): threat for threat in threats}


def _normalize_name(value: str) -> str:
    return " ".join(value.split()).strip().casefold()


def _truncate_assistant_text(value: str, max_length: int) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) <= max_length:
        return cleaned
    if max_length <= 3:
        return cleaned[:max_length]
    return f"{cleaned[: max_length - 3].rstrip()}..."


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


def _boundary_name(boundary_id: str | None, boundary_map: dict[str, TrustBoundaryResponse]) -> str | None:
    if boundary_id is None:
        return None
    boundary = boundary_map.get(boundary_id)
    return boundary.name if boundary else None


def _find_named_boundaries(message: str, dfd: DFDResponse) -> list[TrustBoundaryResponse]:
    lowered = message.casefold()
    matches = [
        boundary
        for boundary in dfd.trust_boundaries
        if boundary.name and boundary.name.casefold() in lowered
    ]
    deduped: list[TrustBoundaryResponse] = []
    seen_ids: set[str] = set()
    for boundary in matches:
        boundary_id = str(boundary.id)
        if boundary_id in seen_ids:
            continue
        seen_ids.add(boundary_id)
        deduped.append(boundary)
    return deduped


def _build_reference(kind: str, id_value: UUID | str, label: str) -> AssistantReference:
    return AssistantReference(kind=kind, id=id_value, label=label)


def _assistant_severity_for_priority(priority: str) -> str:
    if priority in {"p0_blocker", "p1_now"}:
        return "high"
    if priority == "p2_sprint":
        return "medium"
    if priority == "p3_backlog":
        return "low"
    return "info"


def _build_review_finding_references(
    finding: SecurityReviewFinding,
    threats: list[ThreatResponse],
) -> list[AssistantReference]:
    references: list[AssistantReference] = []
    if finding.threat_id is not None:
        threat = next((item for item in threats if str(item.id) == finding.threat_id), None)
        if threat is not None:
            references.append(_build_reference("threat", threat.id, threat.display_id))
    return references


def _review_action_text(finding: SecurityReviewFinding) -> str:
    return finding.next_best_action or finding.next_step or "continue the review and assign the next concrete action."


def _default_review_artifact_kind(finding: SecurityReviewFinding) -> ReviewArtifactKind:
    if finding.needs_evidence or finding.queue_bucket == "gather_evidence":
        return "evidence_request"
    if finding.queue_bucket == "verify":
        return "verification_note"
    return "remediation_note"


def _requested_review_artifact_kind(
    message: str,
    finding: SecurityReviewFinding,
) -> ReviewArtifactKind | None:
    lowered = message.casefold()
    if "draft" not in lowered and "note" not in lowered and "artifact" not in lowered:
        return None
    if "evidence request" in lowered:
        return "evidence_request"
    if "verification note" in lowered:
        return "verification_note"
    if "remediation note" in lowered or "fix note" in lowered:
        return "remediation_note"
    if "evidence" in lowered and "request" in lowered:
        return "evidence_request"
    if "verify" in lowered and "note" in lowered:
        return "verification_note"
    if "remediation" in lowered and "note" in lowered:
        return "remediation_note"
    if "next step" in lowered or "draft the next" in lowered or "draft note" in lowered:
        return _default_review_artifact_kind(finding)
    return None


def _build_assistant_action_artifact(
    finding: SecurityReviewFinding,
    *,
    kind: ReviewArtifactKind,
    threats: list[ThreatResponse],
) -> AssistantActionArtifact:
    threat = next((item for item in threats if str(item.id) == finding.threat_id), None)
    artifact = build_security_review_artifact(finding, kind=kind, threat=threat)
    return AssistantActionArtifact(
        kind=artifact.kind,
        title=_truncate_assistant_text(artifact.title, ASSISTANT_TITLE_MAX_LENGTH),
        summary=artifact.summary,
        body=artifact.body,
        review_finding_id=finding.id,
        source_object_type=finding.source_object_type,
        source_object_id=finding.source_object_id,
        references=_build_review_finding_references(finding, threats),
    )


def _build_review_artifact_response(
    finding: SecurityReviewFinding,
    *,
    kind: ReviewArtifactKind,
    threats: list[ThreatResponse],
) -> AssistantResponse:
    artifact = _build_assistant_action_artifact(finding, kind=kind, threats=threats)
    artifact_label = artifact.kind.replace("_", " ")
    return AssistantResponse(
        mode="review",
        answer=(
            f"I drafted a {artifact_label} for `{finding.title}`. "
            f"It stays grounded in the current queue state, why-now rationale, and the next best action: {_review_action_text(finding)}"
        ),
        references=artifact.references,
        findings=[
            AssistantReviewFinding(
                severity=_assistant_severity_for_priority(finding.priority),  # type: ignore[arg-type]
                title=_truncate_assistant_text(finding.title, ASSISTANT_TITLE_MAX_LENGTH),
                description=_truncate_assistant_text(
                    f"{finding.why_now} Next: {_review_action_text(finding)}",
                    ASSISTANT_FINDING_DESCRIPTION_MAX_LENGTH,
                ),
                references=artifact.references,
            )
        ],
        action_artifacts=[artifact],
    )


def _format_properties(properties: dict[str, Any]) -> str:
    interesting = []
    for key in (
        "uses_auth",
        "validates_input",
        "uses_encryption",
        "handles_sensitive_data",
        "encrypted_at_rest",
        "internet_facing",
        "trusted",
        "authenticated",
        "service_name",
        "function_name",
        "responsibility",
    ):
        if key in properties and properties[key] is not None:
            interesting.append(f"{key}={properties[key]}")
    return ", ".join(interesting) if interesting else "no key security properties set"


def _edge_props_dict(edge: DFDEdgeResponse | None) -> dict[str, Any]:
    if edge is None or edge.properties is None:
        return {}
    if hasattr(edge.properties, "model_dump"):
        return edge.properties.model_dump(exclude_none=True)
    if isinstance(edge.properties, dict):
        return edge.properties
    return {}


def _format_edge_semantics(properties: dict[str, Any]) -> str:
    details: list[str] = []
    label = properties.get("protocol")
    if label:
        details.append(f"protocol `{label}`")
    payload = properties.get("data_payload")
    if payload:
        details.append(f"payload `{payload}`")
    classification = properties.get("data_classification")
    if classification:
        details.append(f"classification `{classification}`")
    auth_mechanism = properties.get("auth_mechanism")
    if auth_mechanism:
        details.append(f"auth `{auth_mechanism}`")
    if properties.get("encryption_in_transit") is True:
        details.append("encryption in transit")
    directionality = properties.get("directionality")
    if directionality:
        details.append(f"direction `{directionality}`")
    data_types = properties.get("data_types") or []
    if data_types:
        details.append(f"legacy data types {', '.join(data_types[:3])}")
    return ", ".join(details) if details else "no flow semantics recorded"


def _find_anchor_threat(anchor: AssistantAnchor | None, message: str, threats: list[ThreatResponse]) -> ThreatResponse | None:
    if anchor and anchor.kind == "threat":
        return _threat_map(threats).get(str(anchor.id))

    lowered = message.casefold()
    for threat in threats:
        if threat.display_id.casefold() in lowered:
            return threat
    return None


def _find_named_nodes(message: str, dfd: DFDResponse) -> list[DFDNodeResponse]:
    lowered = message.casefold()
    matches = [
        node
        for node in dfd.nodes
        if node.name and node.name.casefold() in lowered
    ]
    deduped: list[DFDNodeResponse] = []
    seen_ids: set[str] = set()
    for node in matches:
        node_id = str(node.id)
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        deduped.append(node)
    return deduped


def _infer_node_type_from_text(message: str) -> str:
    lowered = message.casefold()
    if "api gateway" in lowered or "gateway" in lowered:
        return "api_gateway"
    if any(token in lowered for token in ("lambda", "serverless", "function")):
        return "serverless"
    if "container" in lowered or "pod" in lowered:
        return "container"
    if "iam role" in lowered:
        return "iam_role"
    if any(token in lowered for token in ("database", "db", "postgres", "mysql", "redis", "cache", "queue", "bucket", "storage", "vault")):
        return "data_store"
    if any(token in lowered for token in ("external", "third party", "partner", "vendor", "customer", "end user", "browser user", "mobile app user")):
        return "external_entity"
    if "managed service" in lowered or any(token in lowered for token in ("s3", "rds", "sqs", "sns")):
        return "managed_service"
    return "process"


def _default_node_name_for_type(node_type: str) -> str:
    return {
        "process": "Process",
        "data_store": "Data Store",
        "external_entity": "External Entity",
        "iam_role": "IAM Role",
        "managed_service": "Managed Service",
        "api_gateway": "API Gateway",
        "container": "Container",
        "serverless": "Function",
    }.get(node_type, "Node")


def _extract_quoted_name(message: str) -> str | None:
    match = re.search(r'"([^"]+)"', message)
    if match:
        return match.group(1).strip() or None
    return None


def _strip_assumption_lead(message: str) -> str:
    cleaned = message.strip()
    patterns = (
        r"^create an assumption(?: on| for)?\s+",
        r"^add an assumption(?: on| for)?\s+",
        r"^capture an assumption(?: on| for)?\s+",
        r"^record an assumption(?: on| for)?\s+",
    )
    for pattern in patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE)
    return cleaned.strip()


def _default_assumption_text_for_anchor(
    anchor_kind: str,
    anchor_label: str,
) -> tuple[str, str]:
    if anchor_kind == "boundary":
        return (
            f"{anchor_label} cleanly separates trust zones",
            f"The `{anchor_label}` trust boundary reflects a real change in trust, privilege, or exposure.",
        )
    if anchor_kind == "edge":
        return (
            f"{anchor_label} carries authenticated and expected traffic",
            f"The `{anchor_label}` flow is assumed to carry the expected traffic with the stated protections in place.",
        )
    return (
        f"{anchor_label} enforces its modeled security controls",
        f"The `{anchor_label}` node is assumed to enforce the controls shown in the model before handling sensitive operations.",
    )


def _build_guided_steps(
    *,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    assumption_count: int,
    environment_context_summary: str | None,
) -> list[AssistantGuidedStep]:
    external_nodes = [node for node in dfd.nodes if node.node_type == "external_entity"]
    process_nodes = [node for node in dfd.nodes if node.node_type in PROCESS_LIKE_NODE_TYPES]
    data_store_nodes = [node for node in dfd.nodes if node.node_type == "data_store"]
    ingress_edges = [
        edge
        for edge in dfd.edges
        if any(str(edge.source_node_id) == str(node.id) for node in external_nodes)
        and any(str(edge.target_node_id) == str(node.id) for node in process_nodes)
    ]
    process_to_store_edges = [
        edge
        for edge in dfd.edges
        if any(str(edge.source_node_id) == str(node.id) for node in process_nodes)
        and any(str(edge.target_node_id) == str(node.id) for node in data_store_nodes)
    ]
    candidate_boundary_nodes = [
        node
        for node in process_nodes
        if (node.properties or {}).get("internet_facing") is True
    ] or process_nodes[:2]

    assumption_anchor = (
        candidate_boundary_nodes[0]
        if candidate_boundary_nodes
        else process_nodes[0]
        if process_nodes
        else external_nodes[0]
        if external_nodes
        else None
    )

    ingress_bundle: AssistantProposalBundle | None = None
    if process_nodes:
        ingress_proposals = [
            AssistantProposal(
                proposal_type="create_connected_node",
                title="Add primary external actor",
                summary=f"Create `Primary User` as an external actor and connect it to `{process_nodes[0].name}`.",
                anchor_node_id=process_nodes[0].id,
                anchor_handle="target",
                node_type="external_entity",
                node_name="Primary User",
                edge_label="submit request",
            )
        ]
        if not dfd.trust_boundaries and process_nodes[0].trust_boundary_id is None:
            ingress_proposals.append(
                AssistantProposal(
                    proposal_type="create_boundary",
                    title="Wrap the entry service in a boundary",
                    summary=f"Create an ingress trust boundary around `{process_nodes[0].name}`.",
                    boundary_name="Ingress Boundary",
                    boundary_node_ids=[process_nodes[0].id],
                )
            )
        ingress_bundle = AssistantProposalBundle(
            title="Apply ingress pass",
            summary="Add the primary actor and make the first entry path explicit.",
            proposals=ingress_proposals,
        )

    if process_nodes:
        ingress_prompt = f'/build add an external entity named "Primary User" before {process_nodes[0].name}'
        ingress_anchor = AssistantAnchor(kind="node", id=process_nodes[0].id)
        ingress_refs = [_build_reference("node", process_nodes[0].id, process_nodes[0].name)]
        ingress_title = "Model the main ingress path"
        ingress_description = (
            "Start with the primary external actor and the first service it reaches. "
            "This gives the model a real entry point to reason about."
        )
    else:
        ingress_prompt = '/build add a service named "Core API Service"'
        ingress_anchor = None
        ingress_refs = []
        ingress_title = "Add the first entry service"
        ingress_description = "Create the first service or gateway that sits on the main system ingress path."
        ingress_bundle = None

    storage_bundle: AssistantProposalBundle | None = None

    if process_nodes and not data_store_nodes:
        storage_prompt = f'/build add a database named "Primary Data Store" behind {process_nodes[0].name}'
        storage_anchor = AssistantAnchor(kind="node", id=process_nodes[0].id)
        storage_refs = [_build_reference("node", process_nodes[0].id, process_nodes[0].name)]
        storage_title = "Add the first data store"
        storage_description = "Threat models are stronger once the first persistence or stateful component is explicit."
        storage_bundle = AssistantProposalBundle(
            title="Apply storage pass",
            summary="Add the first persistence tier behind the primary service.",
            proposals=[
                AssistantProposal(
                    proposal_type="create_connected_node",
                    title="Add primary data store",
                    summary=f"Create `Primary Data Store` behind `{process_nodes[0].name}`.",
                    anchor_node_id=process_nodes[0].id,
                    anchor_handle="source",
                    node_type="data_store",
                    node_name="Primary Data Store",
                    edge_label="store business data",
                )
            ],
        )
    elif process_nodes and data_store_nodes:
        storage_prompt = f"/build connect {process_nodes[0].name} to {data_store_nodes[0].name}"
        storage_anchor = AssistantAnchor(kind="node", id=process_nodes[0].id)
        storage_refs = [
            _build_reference("node", process_nodes[0].id, process_nodes[0].name),
            _build_reference("node", data_store_nodes[0].id, data_store_nodes[0].name),
        ]
        storage_title = "Connect processing to storage"
        storage_description = "Make the core persistence path explicit so downstream disclosure and tampering threats stay grounded."
        storage_bundle = AssistantProposalBundle(
            title="Apply storage pass",
            summary="Connect the primary processing node to the first data store.",
            proposals=[
                AssistantProposal(
                    proposal_type="create_edge",
                    title="Connect processing to storage",
                    summary=f"Create a data flow from `{process_nodes[0].name}` to `{data_store_nodes[0].name}`.",
                    source_node_id=process_nodes[0].id,
                    target_node_id=data_store_nodes[0].id,
                    edge_label="persist data",
                )
            ],
        )
    else:
        storage_prompt = '/build add a database named "Primary Data Store"'
        storage_anchor = None
        storage_refs = []
        storage_title = "Add the first data store"
        storage_description = "Expose the first persistence tier so the model has somewhere to store or retrieve critical state."
        storage_bundle = None

    boundary_names = ", ".join(node.name for node in candidate_boundary_nodes[:3]) if candidate_boundary_nodes else "Core API Service"
    boundary_bundle: AssistantProposalBundle | None = None
    if candidate_boundary_nodes:
        boundary_proposals = [
            AssistantProposal(
                proposal_type="create_boundary",
                title="Create ingress boundary",
                summary="Create a trust boundary around the first application-facing nodes.",
                boundary_name="DMZ",
                boundary_node_ids=[node.id for node in candidate_boundary_nodes[:3]],
            )
        ]
        if assumption_anchor is not None and assumption_count == 0:
            boundary_proposals.append(
                AssistantProposal(
                    proposal_type="create_assumption",
                    title=f"Capture assumption for {assumption_anchor.name}",
                    summary=f"Record the first explicit assumption on `{assumption_anchor.name}`.",
                    assumption_title=f"{assumption_anchor.name} enforces authentication before business logic",
                    assumption_description=(
                        f"The model currently assumes that `{assumption_anchor.name}` "
                        "enforces authentication before business logic."
                    ),
                    assumption_status="open",
                    assumption_anchor_kind="node",
                    assumption_anchor_id=assumption_anchor.id,
                    assumption_anchor_label=assumption_anchor.name,
                )
            )
        boundary_bundle = AssistantProposalBundle(
            title="Apply boundary pass",
            summary="Make the first trust change explicit and capture the first reviewable assumption.",
            proposals=boundary_proposals,
        )

    assumption_bundle: AssistantProposalBundle | None = None
    if assumption_anchor is not None:
        assumption_bundle = AssistantProposalBundle(
            title="Capture first assumption",
            summary="Anchor the first explicit modeling assumption so reviewers can challenge it later.",
            proposals=[
                AssistantProposal(
                    proposal_type="create_assumption",
                    title=f"Capture assumption for {assumption_anchor.name}",
                    summary=f"Add a reviewable assumption anchored to `{assumption_anchor.name}`.",
                    assumption_title=f"{assumption_anchor.name} enforces authentication before business logic",
                    assumption_description=(
                        f"The model currently assumes that `{assumption_anchor.name}` "
                        "enforces authentication before business logic."
                    ),
                    assumption_status="open",
                    assumption_anchor_kind="node",
                    assumption_anchor_id=assumption_anchor.id,
                    assumption_anchor_label=assumption_anchor.name,
                )
            ],
        )

    ingress_provenance: list[str] = []
    if process_nodes:
        ingress_provenance.append(
            f"Selected `{process_nodes[0].name}` because it is the first process-like node in the current model."
        )
    if not external_nodes:
        ingress_provenance.append("No explicit external actor exists yet, so the main ingress path is still implicit.")
    elif not ingress_edges:
        ingress_provenance.append("External actors exist, but none currently reach an internal service through an explicit ingress flow.")

    storage_provenance: list[str] = []
    if process_nodes:
        storage_provenance.append(
            f"Used `{process_nodes[0].name}` as the anchor because it appears to be the primary processing service."
        )
    if not data_store_nodes:
        storage_provenance.append("No data store is modeled yet, so persistence threats still lack a grounded target.")
    elif not process_to_store_edges:
        storage_provenance.append("A data store exists, but no explicit process-to-store flow is modeled yet.")

    boundary_provenance: list[str] = []
    if candidate_boundary_nodes:
        boundary_provenance.append(
            "Selected "
            + ", ".join(f"`{node.name}`" for node in candidate_boundary_nodes[:3])
            + " because they are the first application-facing process nodes without a clear trust boundary."
        )
    if not dfd.trust_boundaries:
        boundary_provenance.append("The current model has no trust boundaries, so trust changes are still implicit.")

    assumption_provenance: list[str] = []
    if assumption_anchor is not None:
        assumption_provenance.append(
            f"Anchored the first assumption to `{assumption_anchor.name}` because decisions there affect multiple downstream threats."
        )
    if assumption_count == 0:
        assumption_provenance.append("No explicit assumptions are recorded yet, so reviewers cannot challenge hidden design expectations.")

    review_provenance: list[str] = []
    if threats:
        review_provenance.append("Threats already exist, so this review step checks whether the structure still supports them cleanly.")
    else:
        review_provenance.append("Threat generation is more useful after the structure is coherent enough to review.")
    if environment_context_summary:
        review_provenance.append("Environment evidence is available, so the next review can compare the diagram to discovered system context.")

    step_templates: list[dict[str, Any]] = [
        {
            "id": "main-ingress",
            "title": ingress_title,
            "description": ingress_description,
            "prompt": ingress_prompt,
            "anchor": ingress_anchor,
            "references": ingress_refs,
            "provenance": ingress_provenance,
            "proposal_bundle": ingress_bundle,
            "completed": bool(ingress_edges),
        },
        {
            "id": "storage-tier",
            "title": storage_title,
            "description": storage_description,
            "prompt": storage_prompt,
            "anchor": storage_anchor,
            "references": storage_refs,
            "provenance": storage_provenance,
            "proposal_bundle": storage_bundle,
            "completed": bool(data_store_nodes and process_to_store_edges),
        },
        {
            "id": "trust-boundaries",
            "title": "Add the first trust boundary",
            "description": "Make the first trust change explicit. Boundaries are where Shostack-style models become useful.",
            "prompt": f'/build create a trust boundary named "DMZ" around {boundary_names}',
            "anchor": AssistantAnchor(kind="node", id=candidate_boundary_nodes[0].id) if candidate_boundary_nodes else None,
            "references": [
                _build_reference("node", node.id, node.name)
                for node in candidate_boundary_nodes[:3]
            ],
            "provenance": boundary_provenance,
            "proposal_bundle": boundary_bundle,
            "completed": bool(dfd.trust_boundaries),
        },
        {
            "id": "assumptions",
            "title": "Record the first modeling assumption",
            "description": "Capture one concrete assumption the design relies on so reviewers can challenge it later.",
            "prompt": (
                f"/build create an assumption on {assumption_anchor.name} "
                "that authentication is enforced before business logic"
            )
            if assumption_anchor is not None
            else "/build create an assumption on the core ingress service that authentication is enforced before business logic",
            "anchor": AssistantAnchor(kind="node", id=assumption_anchor.id) if assumption_anchor is not None else None,
            "references": [_build_reference("node", assumption_anchor.id, assumption_anchor.name)] if assumption_anchor is not None else [],
            "provenance": assumption_provenance,
            "proposal_bundle": assumption_bundle,
            "completed": assumption_count > 0,
        },
        {
            "id": "first-review",
            "title": "Review the structure before the first threat pass",
            "description": (
                "Do a structural pass first so the first threat generation run is based on a coherent model."
            )
            + (
                " I also see attached environment evidence, so keep using it to validate what changed."
                if environment_context_summary
                else ""
            ),
            "prompt": "/review review this threat model and tell me what to fix first",
            "anchor": None,
            "references": [],
            "provenance": review_provenance,
            "completed": bool(threats),
        },
    ]

    incomplete_indexes = [
        index for index, step in enumerate(step_templates) if not step["completed"]
    ]
    current_index = incomplete_indexes[0] if incomplete_indexes else None

    guided_steps: list[AssistantGuidedStep] = []
    for index, step in enumerate(step_templates):
        status = "done" if step["completed"] else "current" if index == current_index else "up_next"
        guided_steps.append(
            AssistantGuidedStep(
                id=step["id"],
                title=step["title"],
                description=step["description"],
                prompt=step["prompt"],
                status=status,
                anchor=step["anchor"],
                references=step["references"],
                provenance=step.get("provenance", []),
                proposal_bundle=step.get("proposal_bundle"),
            )
        )
    return guided_steps


def _attach_guided_steps(
    response: AssistantResponse,
    *,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    assumption_count: int,
    environment_context_summary: str | None,
) -> AssistantResponse:
    if response.mode != "build":
        return response
    if response.guided_steps:
        return response
    response.guided_steps = _build_guided_steps(
        dfd=dfd,
        threats=threats,
        assumption_count=assumption_count,
        environment_context_summary=environment_context_summary,
    )
    return response



def _strip_anchor_name_from_message(message: str, anchor_node: DFDNodeResponse | None) -> str:
    if anchor_node is None or not anchor_node.name.strip():
        return message
    pattern = re.compile(re.escape(anchor_node.name), re.IGNORECASE)
    return pattern.sub("", message)


def _build_heuristic_response(
    cleaned_message: str,
    request: AssistantRequest,
    dfd: DFDResponse,
) -> AssistantResponse | None:
    lowered = cleaned_message.casefold()
    named_nodes = _find_named_nodes(cleaned_message, dfd)
    named_boundaries = _find_named_boundaries(cleaned_message, dfd)
    anchor_node: DFDNodeResponse | None = None
    anchor_boundary: TrustBoundaryResponse | None = None

    if request.anchor and request.anchor.kind == "node":
        anchor_node = _node_map(dfd).get(str(request.anchor.id))
    if request.anchor and request.anchor.kind == "boundary":
        anchor_boundary = _boundary_map(dfd).get(str(request.anchor.id))
    if anchor_node is None and named_nodes:
        anchor_node = named_nodes[0]
    if anchor_boundary is None and named_boundaries:
        anchor_boundary = named_boundaries[0]

    if "assumption" in lowered or lowered.startswith("assume "):
        anchor_kind = None
        anchor_id = None
        anchor_label = None
        references: list[AssistantReference] = []
        if anchor_boundary is not None:
            anchor_kind = "boundary"
            anchor_id = anchor_boundary.id
            anchor_label = anchor_boundary.name
            references = [_build_reference("boundary", anchor_boundary.id, anchor_boundary.name)]
        elif anchor_node is not None:
            anchor_kind = "node"
            anchor_id = anchor_node.id
            anchor_label = anchor_node.name
            references = [_build_reference("node", anchor_node.id, anchor_node.name)]

        if anchor_kind is None or anchor_id is None or not anchor_label:
            return AssistantResponse(
                mode="build",
                answer=(
                    "I can capture an assumption, but I need the exact node or trust boundary it belongs to. "
                    "Anchor the request to a graph object or name it explicitly."
                ),
                references=[],
            )

        assumption_body = _strip_assumption_lead(cleaned_message)
        assumption_body = re.sub(
            rf"^{re.escape(anchor_label)}\s+that\s+",
            "",
            assumption_body,
            flags=re.IGNORECASE,
        )
        assumption_body = re.sub(
            r"^that\s+",
            "",
            assumption_body,
            flags=re.IGNORECASE,
        ).strip(" .")
        default_title, default_description = _default_assumption_text_for_anchor(anchor_kind, anchor_label)
        assumption_title = (
            f"{anchor_label} {assumption_body}"
            if assumption_body
            else default_title
        )
        assumption_description = (
            f"The model currently assumes that {anchor_label} {assumption_body}."
            if assumption_body
            else default_description
        )

        return AssistantResponse(
            mode="build",
            answer=f"I can capture that assumption on `{anchor_label}` and keep it tied to the model.",
            references=references,
            proposal=AssistantProposal(
                proposal_type="create_assumption",
                title=f"Capture assumption for {anchor_label}",
                summary=f"Add a new assumption anchored to `{anchor_label}`.",
                assumption_title=assumption_title[:160],
                assumption_description=assumption_description[:2000],
                assumption_status="open",
                assumption_anchor_kind=anchor_kind,
                assumption_anchor_id=anchor_id,
                assumption_anchor_label=anchor_label,
            ),
        )

    property_aliases = {
        "uses_auth": ("uses_auth", "authentication", "auth"),
        "validates_input": ("validates_input", "validate input", "validation"),
        "uses_encryption": ("uses_encryption", "encryption", "encrypted"),
        "handles_sensitive_data": ("handles_sensitive_data", "sensitive data"),
        "encrypted_at_rest": ("encrypted_at_rest", "encrypted at rest"),
        "internet_facing": ("internet_facing", "internet facing"),
        "trusted": ("trusted",),
        "authenticated": ("authenticated",),
    }
    if any(token in lowered for token in ("set ", "mark ", "update ", "rename ")):
        if anchor_node is not None:
            for property_key, aliases in property_aliases.items():
                if any(alias in lowered for alias in aliases):
                    value = not any(token in lowered for token in ("false", "disable", "disabled", "off"))
                    current_value = (anchor_node.properties or {}).get(property_key)
                    if current_value == value:
                        return AssistantResponse(
                            mode="build",
                            answer=(
                                f"`{anchor_node.name}` already has `{property_key}={value}`. "
                                "There is no graph change to apply yet."
                            ),
                            references=[_build_reference("node", anchor_node.id, anchor_node.name)],
                        )
                    return AssistantResponse(
                        mode="build",
                        answer=f"I can update `{anchor_node.name}` to reflect that control.",
                        references=[_build_reference("node", anchor_node.id, anchor_node.name)],
                        proposal=AssistantProposal(
                            proposal_type="update_node",
                            title=f"Update {anchor_node.name}",
                            summary=f"Set `{property_key}` on `{anchor_node.name}` to `{value}`.",
                            node_id=anchor_node.id,
                            properties_patch={property_key: value},
                        ),
                    )
            if "rename" in lowered:
                new_name = _extract_quoted_name(cleaned_message)
                if new_name:
                    if _normalize_name(new_name) == _normalize_name(anchor_node.name):
                        return AssistantResponse(
                            mode="build",
                            answer=(
                                f"`{anchor_node.name}` is already named `{new_name}`. "
                                "There is no graph change to apply yet."
                            ),
                            references=[_build_reference("node", anchor_node.id, anchor_node.name)],
                        )
                    return AssistantResponse(
                        mode="build",
                        answer=f"I can rename `{anchor_node.name}` to `{new_name}`.",
                        references=[_build_reference("node", anchor_node.id, anchor_node.name)],
                        proposal=AssistantProposal(
                            proposal_type="update_node",
                            title=f"Rename {anchor_node.name}",
                            summary=f"Rename `{anchor_node.name}` to `{new_name}`.",
                            node_id=anchor_node.id,
                            name_patch=new_name,
                        ),
                    )

    if "connect" in lowered and len(named_nodes) >= 2:
        source_node = named_nodes[0]
        target_node = named_nodes[1]
        existing_edge = next(
            (
                edge
                for edge in dfd.edges
                if str(edge.source_node_id) == str(source_node.id)
                and str(edge.target_node_id) == str(target_node.id)
            ),
            None,
        )
        if existing_edge is not None:
            return AssistantResponse(
                mode="build",
                answer=(
                    f"`{source_node.name}` is already connected to `{target_node.name}`"
                    + (f" via `{existing_edge.label}`." if existing_edge.label else ".")
                ),
                references=[
                    _build_reference("node", source_node.id, source_node.name),
                    _build_reference("node", target_node.id, target_node.name),
                    _build_reference(
                        "edge",
                        existing_edge.id,
                        existing_edge.label or f"{source_node.name} -> {target_node.name}",
                    ),
                ],
            )
        return AssistantResponse(
            mode="build",
            answer=f"I can connect `{source_node.name}` to `{target_node.name}`.",
            references=[
                _build_reference("node", source_node.id, source_node.name),
                _build_reference("node", target_node.id, target_node.name),
            ],
            proposal=AssistantProposal(
                proposal_type="create_edge",
                title=f"Connect {source_node.name} to {target_node.name}",
                summary=f"Create a data flow from `{source_node.name}` to `{target_node.name}`.",
                source_node_id=source_node.id,
                target_node_id=target_node.id,
            ),
        )

    if "boundary" in lowered:
        boundary_nodes = named_nodes[:6]
        return AssistantResponse(
            mode="build",
            answer=(
                "I can create a trust boundary"
                + (
                    f" around {', '.join(f'`{node.name}`' for node in boundary_nodes)}."
                    if boundary_nodes
                    else "."
                )
            ),
            references=[_build_reference("node", node.id, node.name) for node in boundary_nodes],
            proposal=AssistantProposal(
                proposal_type="create_boundary",
                title="Create trust boundary",
                summary=(
                    "Create a trust boundary around the selected nodes."
                    if boundary_nodes
                    else "Create an empty trust boundary."
                ),
                boundary_name=_extract_quoted_name(cleaned_message) or "Trust Boundary",
                boundary_node_ids=[node.id for node in boundary_nodes],
            ),
        )

    if any(token in lowered for token in ("add ", "create ")) and any(
        token in lowered
        for token in (
            "process",
            "database",
            "db",
            "cache",
            "queue",
            "external",
            "gateway",
            "function",
            "serverless",
            "container",
            "service",
        )
    ):
        node_type = _infer_node_type_from_text(
            _strip_anchor_name_from_message(cleaned_message, anchor_node)
        )
        node_name = _extract_quoted_name(cleaned_message) or _default_node_name_for_type(node_type)
        anchor_handle = "source"
        if any(token in lowered for token in ("before", "upstream", "in front of")):
            anchor_handle = "target"

        if anchor_node is not None:
            return AssistantResponse(
                mode="build",
                answer=f"I can add `{node_name}` and connect it to `{anchor_node.name}`.",
                references=[_build_reference("node", anchor_node.id, anchor_node.name)],
                proposal=AssistantProposal(
                    proposal_type="create_connected_node",
                    title=f"Add {node_name}",
                    summary=f"Create `{node_name}` as a `{node_type}` and connect it to `{anchor_node.name}`.",
                    anchor_node_id=anchor_node.id,
                    anchor_handle=anchor_handle,
                    node_type=node_type,
                    node_name=node_name,
                ),
            )

        return AssistantResponse(
            mode="build",
            answer=f"I can add `{node_name}` as a new DFD node.",
            references=[],
            proposal=AssistantProposal(
                proposal_type="create_node",
                title=f"Add {node_name}",
                summary=f"Create a new `{node_type}` node named `{node_name}`.",
                node_type=node_type,
                node_name=node_name,
            ),
        )

    return None


def _build_object_summary_response(
    message: str,
    anchor: AssistantAnchor,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
) -> AssistantResponse | None:
    node_map = _node_map(dfd)
    edge_map = _edge_map(dfd)
    boundary_map = _boundary_map(dfd)
    node_boundary_map = _build_node_boundary_map(dfd)

    if anchor.kind == "node":
        node = node_map.get(str(anchor.id))
        if node is None:
            return None
        incoming = [edge for edge in dfd.edges if str(edge.target_node_id) == str(node.id)]
        outgoing = [edge for edge in dfd.edges if str(edge.source_node_id) == str(node.id)]
        related_threats = [
            threat for threat in threats if str(node.id) in {str(item) for item in threat.affected_node_ids}
        ]
        boundary_name = _boundary_name(node_boundary_map.get(str(node.id)), boundary_map)
        next_steps: list[str] = []
        properties = node.properties or {}
        if node.node_type in PROCESS_LIKE_NODE_TYPES and properties.get("uses_auth") is not True:
            next_steps.append("set `uses_auth` if this service already enforces authentication")
        if node.node_type in PROCESS_LIKE_NODE_TYPES and properties.get("validates_input") is not True:
            next_steps.append("mark `validates_input` if request validation exists")
        if node.node_type == "data_store" and properties.get("encrypted_at_rest") is not True:
            next_steps.append("mark `encrypted_at_rest` if storage encryption is enabled")

        answer_parts = [
            f"`{node.name}` is a `{node.node_type}` node"
            + (f" inside the `{boundary_name}` trust boundary." if boundary_name else "."),
            f"It currently has {len(incoming)} inbound flow(s) and {len(outgoing)} outbound flow(s).",
            f"Security properties: {_format_properties(properties)}.",
        ]
        if related_threats:
            top = ", ".join(threat.display_id for threat in related_threats[:3])
            answer_parts.append(
                f"It is referenced by {len(related_threats)} threat(s), including {top}."
            )
        if next_steps:
            answer_parts.append(f"Highest-value next step: {next_steps[0]}.")
        return AssistantResponse(
            mode="ask",
            answer=" ".join(answer_parts),
            references=[
                _build_reference("node", node.id, node.name),
                *[
                    _build_reference("threat", threat.id, threat.display_id)
                    for threat in related_threats[:3]
                ],
            ],
        )

    if anchor.kind == "edge":
        edge = edge_map.get(str(anchor.id))
        if edge is None:
            return None
        source = node_map.get(str(edge.source_node_id))
        target = node_map.get(str(edge.target_node_id))
        if source is None or target is None:
            return None
        related_threats = [
            threat for threat in threats if str(edge.id) in {str(item) for item in threat.affected_edge_ids}
        ]
        crossing = _is_boundary_crossing(edge, node_boundary_map)
        edge_properties = _edge_props_dict(edge)
        answer_parts = [
            f"This flow connects `{source.name}` to `{target.name}`"
            + (f" with label `{edge.label}`." if edge.label else "."),
            "It crosses a trust boundary." if crossing else "It stays within the same trust zone.",
            f"Flow semantics: {_format_edge_semantics(edge_properties)}.",
        ]
        if target.node_type in PROCESS_LIKE_NODE_TYPES and (target.properties or {}).get("uses_auth") is not True and crossing:
            answer_parts.append(
                f"`{target.name}` does not currently show `uses_auth`, so this ingress path is worth validating."
            )
        if related_threats:
            top = ", ".join(threat.display_id for threat in related_threats[:3])
            answer_parts.append(
                f"This edge is referenced by {len(related_threats)} threat(s), including {top}."
            )
        return AssistantResponse(
            mode="ask",
            answer=" ".join(answer_parts),
            references=[
                _build_reference("edge", edge.id, edge.label or f"{source.name} -> {target.name}"),
                _build_reference("node", source.id, source.name),
                _build_reference("node", target.id, target.name),
                *[
                    _build_reference("threat", threat.id, threat.display_id)
                    for threat in related_threats[:2]
                ],
            ],
        )

    if anchor.kind == "boundary":
        boundary = boundary_map.get(str(anchor.id))
        if boundary is None:
            return None
        member_nodes = [node for node in dfd.nodes if str(node.id) in {str(node_id) for node_id in boundary.node_ids}]
        crossing_edges = [edge for edge in dfd.edges if _is_boundary_crossing(edge, node_boundary_map)]
        related_threats = [
            threat
            for threat in threats
            if any(str(node_id) in {str(item) for item in threat.affected_node_ids} for node_id in boundary.node_ids)
        ]
        answer = (
            f"`{boundary.name}` contains {len(member_nodes)} node(s): "
            + ", ".join(node.name for node in member_nodes[:5])
            + (", ..." if len(member_nodes) > 5 else "")
            + f". I see {len(crossing_edges)} boundary-crossing flow(s) in the current DFD and "
            + f"{len(related_threats)} related threat(s) tied to nodes inside this boundary."
        )
        return AssistantResponse(
            mode="ask",
            answer=answer,
            references=[
                _build_reference("boundary", boundary.id, boundary.name),
                *[
                    _build_reference("node", node.id, node.name)
                    for node in member_nodes[:4]
                ],
            ],
        )

    return None


def _build_review_response(
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    *,
    cleaned_message: str | None = None,
    review_summary: SecurityReviewApplicationSummary | None = None,
    review_findings: SecurityReviewFindingListResponse | None = None,
    selected_review_finding_id: str | None = None,
) -> AssistantResponse:
    if review_summary is not None and review_findings is not None and review_findings.findings:
        active_findings = [
            finding
            for finding in review_findings.findings
            if finding.review_status in {"open", "in_progress"}
        ]
        selected_finding = (
            next(
                (
                    finding
                    for finding in review_findings.findings
                    if finding.id == selected_review_finding_id
                ),
                None,
            )
            if selected_review_finding_id
            else None
        )
        if selected_finding is not None and cleaned_message:
            requested_artifact_kind = _requested_review_artifact_kind(
                cleaned_message,
                selected_finding,
            )
            if requested_artifact_kind is not None:
                return _build_review_artifact_response(
                    selected_finding,
                    kind=requested_artifact_kind,
                    threats=threats,
                )
        lead_finding = (
            selected_finding
            or next(
                (
                    finding
                    for finding in active_findings
                    if finding.queue_bucket in {"fix_now", "verify", "gather_evidence"}
                ),
                None,
            )
            or review_findings.findings[0]
        )
        top_findings = active_findings[:4] if active_findings else review_findings.findings[:4]
        if selected_finding is not None:
            answer = (
                f"`{selected_finding.title}` is currently in "
                f"`{selected_finding.queue_bucket or 'review'}` because {selected_finding.why_now} "
                f"It is {'real' if selected_finding.is_real else 'still contextual'}, "
                f"{'urgent' if selected_finding.is_urgent else 'not yet urgent'}, and "
                f"{'exploitable in this architecture' if selected_finding.is_exploitable_in_context else 'not yet shown as directly exploitable in context'}. "
                f"Next best action: {_review_action_text(selected_finding)}"
            )
        else:
            answer = (
                f"The review queue is currently led by `{lead_finding.title}`. "
                f"{review_summary.focus_statement} "
                f"Start with the items in `Fix Now`, then move to `Verify` and `Gather Evidence` so the team separates engineering change from missing proof."
            )
        references: list[AssistantReference] = []
        seen_reference_keys: set[tuple[str, str]] = set()
        assistant_findings: list[AssistantReviewFinding] = []
        for finding in top_findings:
            finding_refs = _build_review_finding_references(finding, threats)
            for reference in finding_refs:
                key = (reference.kind, str(reference.id))
                if key in seen_reference_keys:
                    continue
                seen_reference_keys.add(key)
                references.append(reference)
            assistant_findings.append(
                AssistantReviewFinding(
                    severity=_assistant_severity_for_priority(finding.priority),  # type: ignore[arg-type]
                    title=_truncate_assistant_text(finding.title, ASSISTANT_TITLE_MAX_LENGTH),
                    description=_truncate_assistant_text(
                        f"{finding.why_now} "
                        f"Next: {_review_action_text(finding)}",
                        ASSISTANT_FINDING_DESCRIPTION_MAX_LENGTH,
                    ),
                    references=finding_refs,
                )
            )
        return AssistantResponse(
            mode="review",
            answer=answer,
            references=references[:8],
            findings=assistant_findings,
        )

    node_map = _node_map(dfd)
    node_boundary_map = _build_node_boundary_map(dfd)

    if len(dfd.nodes) < 3 or len(dfd.edges) < 2:
        answer = (
            "This DFD is still too minimal for a meaningful structural review. "
            f"I currently see {len(dfd.nodes)} node(s), {len(dfd.edges)} flow(s), and "
            f"{len(dfd.trust_boundaries)} trust boundary(ies). Add the main actors, flows, and trust zones first."
        )
        return AssistantResponse(
            mode="review",
            answer=answer,
            findings=[
                AssistantReviewFinding(
                    severity="high",
                    title="DFD is too incomplete for deep review",
                    description="The model is still missing enough structure that most review findings would just be noise.",
                    references=[],
                )
            ],
        )

    findings: list[AssistantReviewFinding] = []

    edge_count_by_node_id: Counter[str] = Counter()
    for edge in dfd.edges:
        edge_count_by_node_id[str(edge.source_node_id)] += 1
        edge_count_by_node_id[str(edge.target_node_id)] += 1

    orphan_nodes = [node for node in dfd.nodes if edge_count_by_node_id[str(node.id)] == 0]
    if orphan_nodes:
        findings.append(
            AssistantReviewFinding(
                severity="high" if len(orphan_nodes) <= 2 else "medium",
                title="Orphan nodes with no data flows",
                description=(
                    f"{len(orphan_nodes)} node(s) are disconnected from the rest of the DFD."
                ),
                references=[_build_reference("node", node.id, node.name) for node in orphan_nodes[:4]],
            )
        )

    name_counts = Counter(_normalize_name(node.name) for node in dfd.nodes if node.name.strip())
    duplicate_names = {
        normalized
        for normalized, count in name_counts.items()
        if count > 1
    }
    if duplicate_names:
        dupe_nodes = [node for node in dfd.nodes if _normalize_name(node.name) in duplicate_names]
        findings.append(
            AssistantReviewFinding(
                severity="medium",
                title="Duplicate node names make the graph ambiguous",
                description="At least two nodes share the same name, which makes threat references and assistant actions harder to trust.",
                references=[_build_reference("node", node.id, node.name) for node in dupe_nodes[:4]],
            )
        )

    has_external_entities = any(node.node_type == "external_entity" for node in dfd.nodes)
    if not dfd.trust_boundaries and (len(dfd.nodes) >= 6 or has_external_entities):
        findings.append(
            AssistantReviewFinding(
                severity="high" if has_external_entities else "medium",
                title="Model lacks trust boundaries",
                description="The current graph has enough externally relevant structure that missing trust boundaries will hide ingress and crossing risks.",
                references=[],
            )
        )

    unlabeled_boundary_crossings: list[AssistantReference] = []
    missing_protocol_crossings: list[AssistantReference] = []
    missing_classification_crossings: list[AssistantReference] = []
    unauthenticated_ingress: list[AssistantReference] = []
    unvalidated_ingress: list[AssistantReference] = []

    for edge in dfd.edges:
        if not _is_boundary_crossing(edge, node_boundary_map):
            continue

        source = node_map.get(str(edge.source_node_id))
        target = node_map.get(str(edge.target_node_id))
        if source is None or target is None:
            continue

        edge_label = edge.label or f"{source.name} -> {target.name}"
        edge_properties = _edge_props_dict(edge)
        if not edge.label.strip():
            unlabeled_boundary_crossings.append(_build_reference("edge", edge.id, edge_label))
        if not edge_properties.get("protocol"):
            missing_protocol_crossings.append(_build_reference("edge", edge.id, edge_label))
        if not edge_properties.get("data_classification"):
            missing_classification_crossings.append(_build_reference("edge", edge.id, edge_label))

        target_props = target.properties or {}
        if source.node_type == "external_entity" and target.node_type in PROCESS_LIKE_NODE_TYPES:
            if target_props.get("uses_auth") is not True:
                unauthenticated_ingress.append(_build_reference("edge", edge.id, edge_label))
            if target_props.get("validates_input") is not True:
                unvalidated_ingress.append(_build_reference("edge", edge.id, edge_label))

    if unlabeled_boundary_crossings:
        findings.append(
            AssistantReviewFinding(
                severity="medium",
                title="Boundary-crossing flows are unlabeled",
                description="Cross-boundary edges should say what is moving so reviews and threat explanations stay concrete.",
                references=unlabeled_boundary_crossings[:4],
            )
        )

    if missing_protocol_crossings:
        findings.append(
            AssistantReviewFinding(
                severity="medium",
                title="Boundary-crossing flows do not show protocol",
                description="Cross-boundary edges should record the transport or protocol so network-facing threats stay grounded in real flow behavior.",
                references=missing_protocol_crossings[:4],
            )
        )

    if missing_classification_crossings:
        findings.append(
            AssistantReviewFinding(
                severity="low",
                title="Boundary-crossing flows are missing data classification",
                description="Flow classification helps explain impact and prioritize disclosure risks when data moves between trust zones.",
                references=missing_classification_crossings[:4],
            )
        )

    if unauthenticated_ingress:
        findings.append(
            AssistantReviewFinding(
                severity="high",
                title="External ingress paths do not show authentication",
                description="At least one external-to-process boundary crossing targets a node that does not currently show `uses_auth`.",
                references=unauthenticated_ingress[:4],
            )
        )

    if unvalidated_ingress:
        findings.append(
            AssistantReviewFinding(
                severity="medium",
                title="External ingress paths do not show request validation",
                description="At least one external-to-process boundary crossing targets a node that does not currently show `validates_input`.",
                references=unvalidated_ingress[:4],
            )
        )

    low_information_nodes = [
        node
        for node in dfd.nodes
        if node.node_type in PROCESS_LIKE_NODE_TYPES
        and not any(
            (node.properties or {}).get(key) is not None
            for key in ("uses_auth", "validates_input", "uses_encryption", "handles_sensitive_data")
        )
    ]
    if low_information_nodes:
        findings.append(
            AssistantReviewFinding(
                severity="low",
                title="Several process nodes still lack useful security properties",
                description="These nodes have enough structure to model but not enough properties to explain or suppress threats confidently.",
                references=[_build_reference("node", node.id, node.name) for node in low_information_nodes[:4]],
            )
        )

    empty_boundaries = [boundary for boundary in dfd.trust_boundaries if not boundary.node_ids]
    if empty_boundaries:
        findings.append(
            AssistantReviewFinding(
                severity="low",
                title="Empty trust boundaries need members or cleanup",
                description="These boundaries exist in the model but do not currently contain any nodes.",
                references=[_build_reference("boundary", boundary.id, boundary.name) for boundary in empty_boundaries[:4]],
            )
        )

    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in dfd.edges:
        source_id = str(edge.source_node_id)
        target_id = str(edge.target_node_id)
        adjacency[source_id].add(target_id)
        adjacency[target_id].add(source_id)

    visited: set[str] = set()
    components = 0
    for node in dfd.nodes:
        node_id = str(node.id)
        if node_id in visited:
            continue
        components += 1
        queue = deque([node_id])
        visited.add(node_id)
        while queue:
            current = queue.popleft()
            for neighbor in adjacency[current]:
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                queue.append(neighbor)
    if components > 1:
        findings.append(
            AssistantReviewFinding(
                severity="low",
                title="DFD has disconnected subgraphs",
                description=f"The current graph breaks into {components} separate components. That may be fine, but it often indicates missing flows.",
                references=[],
            )
        )

    findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.title))
    top_findings = findings[:8]

    if not top_findings:
        answer = (
            f"I did not find any obvious structural issues in the current DFD. "
            f"The graph has {len(dfd.nodes)} nodes, {len(dfd.edges)} flows, "
            f"{len(dfd.trust_boundaries)} trust boundaries, and {len(threats)} tracked threats."
        )
    else:
        answer = (
            f"I found {len(top_findings)} structural review finding(s). "
            f"Start with `{top_findings[0].title}` because it carries the highest risk or the biggest model-quality impact."
        )

    references: list[AssistantReference] = []
    seen_reference_ids: set[tuple[str, str]] = set()
    for finding in top_findings:
        for reference in finding.references:
            key = (reference.kind, str(reference.id))
            if key in seen_reference_ids:
                continue
            seen_reference_ids.add(key)
            references.append(reference)

    return AssistantResponse(
        mode="review",
        answer=answer,
        references=references[:8],
        findings=top_findings,
    )


def _suppression_suggestions(threat: ThreatResponse, dfd: DFDResponse) -> list[str]:
    node_map = _node_map(dfd)
    suggestions: list[str] = []
    for node_id in threat.affected_node_ids:
        node = node_map.get(str(node_id))
        if node is None:
            continue
        props = node.properties or {}
        if node.node_type in PROCESS_LIKE_NODE_TYPES and props.get("uses_auth") is not True:
            suggestions.append(f"set `uses_auth=true` on `{node.name}` if authentication is enforced there")
        if node.node_type in PROCESS_LIKE_NODE_TYPES and props.get("validates_input") is not True:
            suggestions.append(f"set `validates_input=true` on `{node.name}` if request validation is implemented")
        if node.node_type == "data_store" and props.get("encrypted_at_rest") is not True:
            suggestions.append(f"set `encrypted_at_rest=true` on `{node.name}` if storage encryption is enabled")
        if node.node_type == "external_entity" and props.get("authenticated") is not True:
            suggestions.append(f"mark `{node.name}` as authenticated if the external party is already verified")
    deduped: list[str] = []
    for suggestion in suggestions:
        if suggestion not in deduped:
            deduped.append(suggestion)
    return deduped[:3]


def _build_threat_explain_response(threat: ThreatResponse, dfd: DFDResponse) -> AssistantResponse:
    node_map = _node_map(dfd)
    edge_map = _edge_map(dfd)
    rule = _rules_by_id().get(threat.rule_id or "")
    missing_nodes = [node_id for node_id in threat.affected_node_ids if str(node_id) not in node_map]
    missing_edges = [edge_id for edge_id in threat.affected_edge_ids if str(edge_id) not in edge_map]

    if missing_nodes or missing_edges:
        answer = (
            f"`{threat.display_id}` is stale relative to the current DFD. "
            "It still references graph objects that are no longer present, so it should clear on the next analysis run."
        )
        return AssistantResponse(
            mode="explain",
            answer=answer,
            references=[_build_reference("threat", threat.id, threat.display_id)],
            degraded_reason="Threat references stale graph objects.",
        )

    node_refs = [_build_reference("node", node.id, node.name) for node in (node_map[str(node_id)] for node_id in threat.affected_node_ids)]
    edge_refs = []
    for edge_id in threat.affected_edge_ids:
        edge = edge_map[str(edge_id)]
        source = node_map.get(str(edge.source_node_id))
        target = node_map.get(str(edge.target_node_id))
        edge_refs.append(
            _build_reference(
                "edge",
                edge.id,
                edge.label or f"{source.name if source else edge.source_node_id} -> {target.name if target else edge.target_node_id}",
            )
        )

    parts = [
        f"`{threat.display_id}` is a `{threat.stride_category}` threat with `{threat.severity}` severity.",
    ]
    if threat.rule_id:
        parts.append(f"It comes from rule `{threat.rule_id}`.")
    if rule is not None:
        parts.append(f"Rule subtype: {rule.threat_subtype}.")
    if node_refs:
        parts.append("Affected nodes: " + ", ".join(f"`{ref.label}`" for ref in node_refs) + ".")
    if edge_refs:
        parts.append("Affected flows: " + ", ".join(f"`{ref.label}`" for ref in edge_refs) + ".")
    if threat.relevance_rationale:
        parts.append(f"Why it fired: {threat.relevance_rationale}")

    suggestions = _suppression_suggestions(threat, dfd)
    if suggestions:
        parts.append("Likely next step: " + suggestions[0] + ".")
    if threat.compliance_controls:
        control_summary = ", ".join(
            f"{control.framework} {control.control_id}" for control in threat.compliance_controls[:3]
        )
        parts.append(f"Mapped controls include {control_summary}.")

    return AssistantResponse(
        mode="explain",
        answer=" ".join(parts),
        references=[_build_reference("threat", threat.id, threat.display_id), *node_refs[:4], *edge_refs[:3]],
    )


def _infer_mode(
    request: AssistantRequest,
    cleaned_message: str,
    command_mode: str | None,
) -> str:
    if request.mode_hint:
        return request.mode_hint
    if command_mode:
        return command_mode
    if request.anchor and request.anchor.kind == "threat":
        return "explain"

    lowered = cleaned_message.casefold()
    if "review" in lowered or "what is wrong" in lowered or "what should i fix" in lowered:
        return "review"
    if any(keyword in lowered for keyword in ("add ", "create ", "connect ", "set ", "update ", "rename ", "wrap ", "boundary")):
        return "build"
    return "ask"


def _build_context_payload(
    cleaned_message: str,
    request: AssistantRequest,
    threat_model_name: str,
    description: str,
    data_classification: str,
    regulatory_scope: Iterable[str],
    deployment_model: str | None,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    environment_context_summary: str | None,
    review_summary: SecurityReviewApplicationSummary | None,
    review_findings: SecurityReviewFindingListResponse | None,
) -> str:
    node_map = _node_map(dfd)
    boundary_map = _boundary_map(dfd)
    node_boundary_map = _build_node_boundary_map(dfd)
    threat_lines = []
    for threat in threats[:40]:
        threat_lines.append(
            f"- id={threat.id} display_id={threat.display_id} stride={threat.stride_category} "
            f"severity={threat.severity} status={threat.status} rule_id={threat.rule_id or ''} "
            f"nodes={[str(node_id) for node_id in threat.affected_node_ids]}"
        )

    edge_lines = []
    for edge in dfd.edges:
        source = node_map.get(str(edge.source_node_id))
        target = node_map.get(str(edge.target_node_id))
        boundary_crossing = _is_boundary_crossing(edge, node_boundary_map)
        edge_properties = _edge_props_dict(edge)
        edge_lines.append(
            f"- id={edge.id} source={edge.source_node_id}({source.name if source else 'unknown'}) "
            f"target={edge.target_node_id}({target.name if target else 'unknown'}) "
            f"label={edge.label!r} crossing={boundary_crossing} properties={edge_properties}"
        )

    node_lines = []
    for node in dfd.nodes:
        boundary_name = _boundary_name(node_boundary_map.get(str(node.id)), boundary_map)
        node_lines.append(
            f"- id={node.id} name={node.name!r} type={node.node_type} "
            f"boundary={boundary_name or 'none'} properties={node.properties or {}}"
        )

    boundary_lines = [
        f"- id={boundary.id} name={boundary.name!r} node_ids={[str(node_id) for node_id in boundary.node_ids]}"
        for boundary in dfd.trust_boundaries
    ]

    anchor_block = "none"
    if request.anchor is not None:
        anchor_block = f"{request.anchor.kind}:{request.anchor.id}"

    regulatory = ", ".join(regulatory_scope) if regulatory_scope else "None"
    review_lines = ["- none"]
    selected_review_finding = None
    if review_findings is not None:
        if request.review_finding_id:
            selected_review_finding = next(
                (
                    finding
                    for finding in review_findings.findings
                    if finding.id == request.review_finding_id
                ),
                None,
            )
        active_findings = [
            finding
            for finding in review_findings.findings
            if finding.review_status in {"open", "in_progress"}
        ]
        review_lines = [
            (
                f"- id={finding.id} queue={finding.queue_bucket or 'none'} status={finding.review_status} "
                f"priority={finding.priority} real={finding.is_real} urgent={finding.is_urgent} "
                f"exploitability={finding.exploitability or 'unknown'} needs_engineering={finding.needs_engineering_change} "
                f"needs_evidence={finding.needs_evidence} title={finding.title!r} "
                f"next_best_action={_review_action_text(finding)!r}"
            )
            for finding in active_findings[:12]
        ] or ["- none"]
    selected_review_block = (
        (
            f"id={selected_review_finding.id} queue={selected_review_finding.queue_bucket or 'none'} "
            f"status={selected_review_finding.review_status} title={selected_review_finding.title!r} "
            f"why_now={selected_review_finding.why_now!r} "
            f"next_best_action={_review_action_text(selected_review_finding)!r}"
        )
        if selected_review_finding is not None
        else "none"
    )

    return "\n".join(
        [
            f"User message: {cleaned_message}",
            f"Anchor: {anchor_block}",
            f"Threat model: {threat_model_name}",
            f"Description: {description}",
            f"Data classification: {data_classification}",
            f"Regulatory scope: {regulatory}",
            f"Deployment model: {deployment_model or 'unknown'}",
            "Nodes:",
            *node_lines,
            "Edges:",
            *edge_lines,
            "Trust boundaries:",
            *(boundary_lines or ["- none"]),
            "Threats:",
            *(threat_lines or ["- none"]),
            "Environment evidence summary:",
            environment_context_summary or "none",
            "Security review summary:",
            (
                f"- overall_priority={review_summary.overall_priority} "
                f"focus_statement={review_summary.focus_statement!r}"
                if review_summary is not None
                else "- none"
            ),
            "Selected review finding:",
            selected_review_block,
            "Active review queue:",
            *review_lines,
        ]
    )


def _validate_references(
    references: Iterable[AssistantReference],
    dfd: DFDResponse,
    threats: list[ThreatResponse],
) -> list[AssistantReference]:
    node_ids = set(_node_map(dfd))
    edge_ids = set(_edge_map(dfd))
    boundary_ids = set(_boundary_map(dfd))
    threat_ids = set(_threat_map(threats))

    validated: list[AssistantReference] = []
    seen: set[tuple[str, str]] = set()
    for reference in references:
        ref_id = str(reference.id)
        is_valid = (
            (reference.kind == "node" and ref_id in node_ids)
            or (reference.kind == "edge" and ref_id in edge_ids)
            or (reference.kind == "boundary" and ref_id in boundary_ids)
            or (reference.kind == "threat" and ref_id in threat_ids)
        )
        if not is_valid:
            continue
        key = (reference.kind, ref_id)
        if key in seen:
            continue
        seen.add(key)
        validated.append(reference)
    return validated


def _validate_and_normalize_proposal(
    proposal: AssistantProposal | None,
    dfd: DFDResponse,
) -> AssistantProposal | None:
    if proposal is None:
        return None

    node_ids = set(_node_map(dfd))
    safe_edge_properties = proposal.edge_properties if isinstance(proposal.edge_properties, dict) else {}
    safe_properties_patch = (
        {
            key: value
            for key, value in proposal.properties_patch.items()
            if key in VALID_PROPERTY_KEYS
            and (isinstance(value, (str, bool, int, float)) or value is None)
        }
        if isinstance(proposal.properties_patch, dict)
        else {}
    )

    if proposal.proposal_type == "create_connected_node":
        if (
            proposal.anchor_node_id is None
            or str(proposal.anchor_node_id) not in node_ids
            or proposal.anchor_handle not in {"source", "target"}
            or proposal.node_type not in VALID_NODE_TYPES
            or not proposal.node_name
        ):
            return None
        proposal.edge_properties = safe_edge_properties
        return proposal

    if proposal.proposal_type == "create_node":
        if proposal.node_type not in VALID_NODE_TYPES or not proposal.node_name:
            return None
        return proposal

    if proposal.proposal_type == "create_edge":
        if (
            proposal.source_node_id is None
            or proposal.target_node_id is None
            or str(proposal.source_node_id) not in node_ids
            or str(proposal.target_node_id) not in node_ids
            or proposal.source_node_id == proposal.target_node_id
        ):
            return None
        proposal.edge_properties = safe_edge_properties
        return proposal

    if proposal.proposal_type == "create_boundary":
        if any(str(node_id) not in node_ids for node_id in proposal.boundary_node_ids):
            return None
        if not proposal.boundary_name:
            proposal.boundary_name = "Trust Boundary"
        return proposal

    if proposal.proposal_type == "update_node":
        if proposal.node_id is None or str(proposal.node_id) not in node_ids:
            return None
        if not proposal.name_patch and not safe_properties_patch:
            return None
        proposal.properties_patch = safe_properties_patch
        return proposal

    if proposal.proposal_type == "create_assumption":
        if (
            proposal.assumption_anchor_kind not in {"node", "edge", "boundary"}
            or proposal.assumption_anchor_id is None
            or not proposal.assumption_title
            or not proposal.assumption_anchor_label
        ):
            return None
        if proposal.assumption_anchor_kind == "node" and str(proposal.assumption_anchor_id) not in node_ids:
            return None
        if proposal.assumption_anchor_kind == "edge" and str(proposal.assumption_anchor_id) not in _edge_map(dfd):
            return None
        if proposal.assumption_anchor_kind == "boundary" and str(proposal.assumption_anchor_id) not in _boundary_map(dfd):
            return None
        proposal.assumption_status = proposal.assumption_status or "open"
        proposal.assumption_description = proposal.assumption_description or ""
        return proposal

    return None


def _fallback_ask_response(
    cleaned_message: str,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    review_summary: SecurityReviewApplicationSummary | None = None,
    review_findings: SecurityReviewFindingListResponse | None = None,
) -> AssistantResponse:
    answer = (
        "I could not use the LLM path for that request, so I am falling back to grounded product context only. "
        f"The current model has {len(dfd.nodes)} node(s), {len(dfd.edges)} flow(s), "
        f"{len(dfd.trust_boundaries)} trust boundary(ies), and {len(threats)} threat(s). "
    )
    if review_summary is not None and review_findings is not None:
        active_findings = [
            finding
            for finding in review_findings.findings
            if finding.review_status in {"open", "in_progress"}
        ]
        answer += (
            f"The active review queue currently has {len(active_findings)} item(s), led by "
            f"`{review_findings.default_finding_id or 'the current top finding'}`. "
            "Try `/review`, ask why an item is in Fix Now, ask what evidence moves it to Verify, "
            "or ask for a remediation note."
        )
    else:
        answer += (
            "Try `/review`, ask about a specific threat, or make a smaller build request like "
            "`add a database behind the API Gateway`."
        )
    return AssistantResponse(mode="ask", answer=answer, references=[])


def _validated_assistant_items(model: type[Any], raw_items: Any) -> list[Any]:
    if not isinstance(raw_items, list):
        return []
    parsed_items: list[Any] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        try:
            parsed_items.append(model.model_validate(item))
        except ValidationError:
            continue
    return parsed_items


def _coerce_assistant_tool_output(tool_output: dict[str, Any]) -> AssistantResponse:
    raw_answer = tool_output.get("answer")
    if not isinstance(raw_answer, str) or not raw_answer.strip():
        raise ValueError("assistant_llm_missing_answer")

    raw_mode = tool_output.get("mode")
    mode = raw_mode if raw_mode in {"ask", "build", "explain", "review"} else "ask"
    degraded_reason = tool_output.get("degraded_reason")

    proposal = None
    raw_proposal = tool_output.get("proposal")
    if isinstance(raw_proposal, dict):
        try:
            proposal = AssistantProposal.model_validate(raw_proposal)
        except ValidationError:
            proposal = None

    return AssistantResponse(
        mode=mode,
        answer=raw_answer,
        references=_validated_assistant_items(
            AssistantReference,
            tool_output.get("references"),
        ),
        findings=_validated_assistant_items(
            AssistantReviewFinding,
            tool_output.get("findings"),
        ),
        action_artifacts=_validated_assistant_items(
            AssistantActionArtifact,
            tool_output.get("action_artifacts"),
        ),
        guided_steps=_validated_assistant_items(
            AssistantGuidedStep,
            tool_output.get("guided_steps"),
        ),
        proposal=proposal,
        degraded_reason=degraded_reason if isinstance(degraded_reason, str) else None,
    )


def _fallback_build_response(
    *,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    assumption_count: int,
    environment_context_summary: str | None,
) -> AssistantResponse:
    return AssistantResponse(
        mode="build",
        answer=(
            "I could not use the LLM path for that build request, so I am falling back to a grounded build sequence. "
            "Work through the current step first, then continue down the list."
        ),
        references=[],
        guided_steps=_build_guided_steps(
            dfd=dfd,
            threats=threats,
            assumption_count=assumption_count,
            environment_context_summary=environment_context_summary,
        ),
    )


def _call_llm_for_assistant_response(
    *,
    user_id: UUID,
    cleaned_message: str,
    request: AssistantRequest,
    threat_model_name: str,
    description: str,
    data_classification: str,
    regulatory_scope: Iterable[str],
    deployment_model: str | None,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    environment_context_summary: str | None,
    review_summary: SecurityReviewApplicationSummary | None,
    review_findings: SecurityReviewFindingListResponse | None,
) -> AssistantResponse:
    client = get_llm_client_for_user(user_id)
    tool_output = client.call_with_tools(
        system_message=ASSISTANT_SYSTEM_MESSAGE,
        user_message=_build_context_payload(
            cleaned_message=cleaned_message,
            request=request,
            threat_model_name=threat_model_name,
            description=description,
            data_classification=data_classification,
            regulatory_scope=regulatory_scope,
            deployment_model=deployment_model,
            dfd=dfd,
            threats=threats,
            environment_context_summary=environment_context_summary,
            review_summary=review_summary,
            review_findings=review_findings,
        ),
        tools=[ASSISTANT_RESPONSE_TOOL],
        max_tokens=3000,
        prompt_version=ASSISTANT_PROMPT_VERSION,
    )
    if not tool_output:
        raise RuntimeError("assistant_llm_empty_response")

    parsed = _coerce_assistant_tool_output(tool_output)
    validated_refs = _validate_references(parsed.references, dfd, threats)
    validated_proposal = _validate_and_normalize_proposal(parsed.proposal, dfd)
    degraded_reason = parsed.degraded_reason
    if parsed.proposal is not None and validated_proposal is None:
        degraded_reason = (
            (degraded_reason + " " if degraded_reason else "")
            + "Filtered an invalid assistant proposal."
        )

    return AssistantResponse(
        mode=parsed.mode if parsed.mode in {"ask", "build", "explain", "review"} else "ask",
        answer=parsed.answer,
        references=validated_refs,
        findings=parsed.findings,
        action_artifacts=parsed.action_artifacts,
        guided_steps=parsed.guided_steps,
        proposal=validated_proposal,
        degraded_reason=degraded_reason,
    )


def respond_to_assistant_request(
    *,
    request: AssistantRequest,
    user_id: UUID,
    threat_model_name: str,
    description: str,
    data_classification: str,
    regulatory_scope: Iterable[str],
    deployment_model: str | None,
    dfd: DFDResponse,
    threats: list[ThreatResponse],
    environment_context_summary: str | None,
    assumption_count: int = 0,
    review_summary: SecurityReviewApplicationSummary | None = None,
    review_findings: SecurityReviewFindingListResponse | None = None,
) -> AssistantResponse:
    cleaned_message, command_mode = _strip_command_prefix(request.message)
    resolved_mode = _infer_mode(request, cleaned_message, command_mode)

    anchor_threat = _find_anchor_threat(request.anchor, cleaned_message, threats)
    if resolved_mode == "explain" and anchor_threat is not None:
        return _build_threat_explain_response(anchor_threat, dfd)

    if resolved_mode == "review":
        return _build_review_response(
            dfd,
            threats,
            cleaned_message=cleaned_message,
            review_summary=review_summary,
            review_findings=review_findings,
            selected_review_finding_id=request.review_finding_id,
        )

    if request.anchor is not None and request.anchor.kind in {"node", "edge", "boundary"} and resolved_mode in {"ask", "explain"}:
        object_response = _build_object_summary_response(cleaned_message, request.anchor, dfd, threats)
        if object_response is not None:
            return object_response

    if resolved_mode == "build":
        heuristic_response = _build_heuristic_response(cleaned_message, request, dfd)
        if heuristic_response is not None:
            return _attach_guided_steps(
                heuristic_response,
                dfd=dfd,
                threats=threats,
                assumption_count=assumption_count,
                environment_context_summary=environment_context_summary,
            )

    try:
        response = _call_llm_for_assistant_response(
            user_id=user_id,
            cleaned_message=cleaned_message,
            request=request,
            threat_model_name=threat_model_name,
            description=description,
            data_classification=data_classification,
            regulatory_scope=regulatory_scope,
            deployment_model=deployment_model,
            dfd=dfd,
            threats=threats,
            environment_context_summary=environment_context_summary,
            review_summary=review_summary,
            review_findings=review_findings,
        )
        return _attach_guided_steps(
            response,
            dfd=dfd,
            threats=threats,
            assumption_count=assumption_count,
            environment_context_summary=environment_context_summary,
        )
    except Exception as exc:
        if resolved_mode == "build":
            response = _fallback_build_response(
                dfd=dfd,
                threats=threats,
                assumption_count=assumption_count,
                environment_context_summary=environment_context_summary,
            )
        else:
            response = _fallback_ask_response(
                cleaned_message,
                dfd,
                threats,
                review_summary=review_summary,
                review_findings=review_findings,
            )
        response.degraded_reason = f"Assistant fell back to deterministic mode: {type(exc).__name__}"
        return response
