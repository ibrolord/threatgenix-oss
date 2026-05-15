"""Adapters from persisted threat-model state into security-review contexts."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import re
from typing import Mapping, Sequence

from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.schemas.environment_evidence import (
    CloudFinding,
    CloudScanEvidence,
    CodeControlSignal,
    CodeRiskSignal,
    CodeSurface,
    FindingCodeLink,
    IacEvidence,
    RepositoryEvidence,
)
from app.schemas.security_review import (
    QueueBucket,
    SecurityReviewApplicationSummary,
    SecurityReviewBucketCount,
    SecurityReviewCoverageSummary,
    SecurityReviewEvidenceAnchor,
    SecurityReviewFinding,
    PriorityBand,
    ReviewConfidence,
    ReviewDisplayKind,
    ReviewPrimaryMode,
    SecurityReviewFindingListResponse,
    SecurityReviewStateRecord,
    SecurityReviewContext,
    SecurityReviewDecision,
    SecurityReviewDeltaSummary,
    SecurityReviewFindingSummary,
    SecurityReviewRiskAcceptance,
    SecurityReviewRiskAcceptanceSummary,
)
from app.schemas.threat import ThreatIntelResponse
from app.services.security_review_engine import evaluate_security_review_contexts

_CLASSIFICATION_RANK = {
    "Public": 0,
    "Internal": 1,
    "Confidential": 2,
    "Restricted": 3,
}
_QUALIFICATION_PRIORITY: dict[str, PriorityBand] = {
    "Priority": "p1_now",
    "Investigate": "p2_sprint",
    "Review": "p3_backlog",
    "Low Signal": "p4_monitor",
}
_PRIVILEGE_LEVELS = {"privileged", "admin", "system"}
_EDGE_FACING_EXPOSURES = {"internet", "dmz"}
_EXTERNAL_NODE_TYPES = {"external_entity", "human_actor"}
_SENSITIVE_NODE_TYPES = {"data_store", "managed_service"}
_CONTROL_PLANE_NODE_TYPES = {"iam_role", "api_gateway"}
_ACTIVE_THREAT_STATUSES = {"Open", "In Progress", "Accepted", "Mitigated"}
_HIGH_SIGNAL_SEVERITIES = {"Critical", "High"}
_COUNT_LABELS = {
    "priority": {
        "p0_blocker": "P0 blocker",
        "p1_now": "P1 now",
        "p2_sprint": "P2 sprint",
        "p3_backlog": "P3 backlog",
        "p4_monitor": "P4 monitor",
    },
    "action_bucket": {
        "bright_red_line": "Bright red line",
        "engineer_now": "Engineer now",
        "verify_control": "Verify control",
        "fill_evidence_gap": "Fill evidence gap",
        "planned_hardening": "Planned hardening",
        "monitor": "Monitor",
    },
    "truth_status": {
        "validated": "Validated",
        "strongly_indicated": "Strongly indicated",
        "contextual": "Contextual",
        "theoretical": "Theoretical",
    },
    "noise_disposition": {
        "focus": "Focus",
        "queue": "Queue",
        "background": "Background",
        "suppress": "Suppress",
    },
}
_COUNT_ORDER = {
    "priority": ["p0_blocker", "p1_now", "p2_sprint", "p3_backlog", "p4_monitor"],
    "action_bucket": [
        "bright_red_line",
        "engineer_now",
        "verify_control",
        "fill_evidence_gap",
        "planned_hardening",
        "monitor",
    ],
    "truth_status": ["validated", "strongly_indicated", "contextual", "theoretical"],
    "noise_disposition": ["focus", "queue", "background", "suppress"],
}
_PRIORITY_RANK = {
    "p0_blocker": 0,
    "p1_now": 1,
    "p2_sprint": 2,
    "p3_backlog": 3,
    "p4_monitor": 4,
}
_QUEUE_BUCKET_ORDER: list[QueueBucket] = [
    "fix_now",
    "verify",
    "gather_evidence",
    "backlog",
]
_QUEUE_BUCKET_LABELS: dict[str, str] = {
    "fix_now": "Fix now",
    "verify": "Verify",
    "gather_evidence": "Gather evidence",
    "backlog": "Backlog",
}
_REVIEW_STATUS_ORDER = ["open", "in_progress", "accepted", "mitigated", "dismissed"]
_REVIEW_STATUS_LABELS = {
    "open": "Open",
    "in_progress": "In progress",
    "accepted": "Accepted",
    "mitigated": "Mitigated",
    "dismissed": "Dismissed",
}


def _as_string(value: object | None) -> str | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        candidate = getattr(value, "value")
        return str(candidate) if candidate is not None else None
    return str(value)


def _evidence_source_out_of_scope(threat_model: object, source: str) -> bool:
    statement = (
        _as_string(getattr(threat_model, "out_of_scope_statement", None)) or ""
    ).casefold()
    if not statement:
        return False
    if "out of scope" not in statement and "not in scope" not in statement:
        return False
    if source == "cloud":
        return "cloud" in statement or "deployment evidence" in statement
    if source == "iac":
        return any(
            token in statement
            for token in (
                "iac",
                "infrastructure-as-code",
                "infrastructure as code",
                "terraform",
                "cloudformation",
                "kubernetes",
                "deployment evidence",
            )
        )
    return False


def _parse_optional_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _coerce_repository_evidence(value: object | None) -> RepositoryEvidence | None:
    if value is None:
        return None
    if isinstance(value, RepositoryEvidence):
        return value
    try:
        return RepositoryEvidence.model_validate(value)
    except Exception:
        return None


def _coerce_cloud_scan_evidence(value: object | None) -> CloudScanEvidence | None:
    if value is None:
        return None
    if isinstance(value, CloudScanEvidence):
        return value
    try:
        return CloudScanEvidence.model_validate(value)
    except Exception:
        return None


def _coerce_iac_evidence(value: object | None) -> IacEvidence | None:
    if value is None:
        return None
    if isinstance(value, IacEvidence):
        return value
    try:
        return IacEvidence.model_validate(value)
    except Exception:
        return None


def _evidence_object_id(*parts: object | None) -> str:
    raw = ":".join(
        str(part).strip()
        for part in parts
        if part is not None and str(part).strip()
    )
    if not raw:
        return "unknown"
    normalized = re.sub(r"[^A-Za-z0-9_.:/-]+", "-", raw).strip("-")
    return normalized[:180] or "unknown"


def _tokenize_code_match_text(*values: object | None) -> set[str]:
    stop_words = {
        "this",
        "that",
        "with",
        "from",
        "into",
        "without",
        "through",
        "route",
        "surface",
        "threat",
        "finding",
        "service",
        "system",
        "public",
        "internal",
    }
    tokens: set[str] = set()
    for value in values:
        if value is None:
            continue
        for token in re.findall(r"[A-Za-z0-9_/-]+", str(value).casefold()):
            for part in re.split(r"[^a-z0-9]+", token):
                if not part or part in stop_words:
                    continue
                if len(part) >= 4 or part in {"api", "jwt", "s3"}:
                    tokens.add(part)
    return tokens


def _code_surface_tokens(surface: CodeSurface) -> set[str]:
    return _tokenize_code_match_text(
        surface.name,
        surface.path,
        surface.source_file,
        *surface.auth_guards,
        *surface.sensitive_data_signals,
        *surface.validation_signals,
        *surface.outbound_call_signals,
        *surface.risk_flags,
    )


def _as_string_values(value: object | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        candidate = value.strip()
        return [candidate] if candidate else []
    if isinstance(value, Mapping):
        return [
            item
            for nested in value.values()
            for item in _as_string_values(nested)
        ]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [
            item
            for nested in value
            for item in _as_string_values(nested)
        ]
    candidate = str(value).strip()
    return [candidate] if candidate else []


def _normalized_mapping_ref(value: object | None) -> str:
    if value is None:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", str(value).casefold()).strip()


def _dfd_code_mapping_values(
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
    keys: Sequence[str],
) -> set[str]:
    values: set[str] = set()
    for item in [*nodes, *edges]:
        properties = getattr(item, "properties", None)
        if not isinstance(properties, Mapping):
            continue
        for key in keys:
            values.update(_as_string_values(properties.get(key)))
    return {value for value in values if value}


def _dfd_mapped_code_surface_ids(
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
) -> set[str]:
    return _dfd_code_mapping_values(
        nodes,
        edges,
        ("mapped_code_surface_ids", "code_surface_ids"),
    )


def _dfd_mapped_code_source_refs(
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
) -> set[str]:
    return _dfd_code_mapping_values(
        nodes,
        edges,
        (
            "mapped_code_source_refs",
            "code_source_refs",
            "repository_seed_source_refs",
            "code_mapping_evidence",
        ),
    )


def _code_surface_has_dfd_mapping(
    surface: CodeSurface,
    *,
    mapped_surface_ids: set[str],
    mapped_source_refs: set[str],
) -> bool:
    if surface.id in mapped_surface_ids:
        return True

    source_file = _as_string(surface.source_file)
    source_line = _as_string(surface.line_number)
    surface_ref = (
        f"{source_file}:{source_line}"
        if source_file and source_line
        else source_file
    )
    normalized_surface_ref = _normalized_mapping_ref(surface_ref)
    normalized_source_file = _normalized_mapping_ref(source_file)
    normalized_surface_name = _normalized_mapping_ref(surface.name)

    for ref in mapped_source_refs:
        normalized_ref = _normalized_mapping_ref(ref)
        if not normalized_ref:
            continue
        if normalized_surface_ref and normalized_surface_ref in normalized_ref:
            return True
        if (
            normalized_source_file
            and normalized_surface_name
            and normalized_source_file in normalized_ref
            and normalized_surface_name in normalized_ref
        ):
            return True
    return False


def _relationship_for_code_link(
    risk_signals: Sequence[CodeRiskSignal],
    control_signals: Sequence[CodeControlSignal],
) -> str:
    if risk_signals:
        return "confirms_missing_control"
    if control_signals:
        return "shows_compensating_control"
    return "needs_evidence"


def _code_link_summary(
    surface: CodeSurface,
    risk_signals: Sequence[CodeRiskSignal],
    control_signals: Sequence[CodeControlSignal],
) -> str:
    if risk_signals:
        return "; ".join(signal.evidence for signal in risk_signals[:2])
    if control_signals:
        controls = ", ".join(
            signal.control_type.replace("_", " ") for signal in control_signals[:3]
        )
        return f"Detected {controls} control evidence on {surface.name}."
    return f"Code surface {surface.name} is relevant but still needs review evidence."


def _build_code_links_for_tokens(
    repository: RepositoryEvidence | None,
    *,
    finding_key: str | None,
    match_tokens: set[str],
) -> list[FindingCodeLink]:
    if repository is None or not repository.code_surfaces:
        return []

    controls_by_surface: dict[str, list[CodeControlSignal]] = {}
    for signal in repository.code_control_signals:
        controls_by_surface.setdefault(signal.surface_id, []).append(signal)
    risks_by_surface: dict[str, list[CodeRiskSignal]] = {}
    for signal in repository.code_risk_signals:
        risks_by_surface.setdefault(signal.surface_id, []).append(signal)

    scored_surfaces: list[tuple[int, CodeSurface]] = []
    for surface in repository.code_surfaces:
        surface_tokens = _code_surface_tokens(surface)
        overlap = match_tokens & surface_tokens
        risk_weight = len(risks_by_surface.get(surface.id, [])) * 2
        control_weight = len(controls_by_surface.get(surface.id, []))
        if overlap:
            scored_surfaces.append(
                (len(overlap) * 5 + risk_weight + control_weight, surface)
            )

    if not scored_surfaces and match_tokens & {
        "admin",
        "auth",
        "authentication",
        "authorization",
        "callback",
        "charge",
        "payment",
        "payments",
        "token",
        "webhook",
    }:
        for surface in repository.code_surfaces:
            if risks_by_surface.get(surface.id):
                scored_surfaces.append((len(risks_by_surface[surface.id]) * 3, surface))

    links: list[FindingCodeLink] = []
    for _, surface in sorted(
        scored_surfaces, key=lambda item: (-item[0], item[1].name)
    )[:4]:
        control_signals = controls_by_surface.get(surface.id, [])
        risk_signals = risks_by_surface.get(surface.id, [])
        links.append(
            FindingCodeLink(
                finding_key=finding_key,
                surface_id=surface.id,
                surface_name=surface.name,
                source_file=surface.source_file,
                line_number=surface.line_number,
                relationship=_relationship_for_code_link(risk_signals, control_signals),  # type: ignore[arg-type]
                summary=_code_link_summary(surface, risk_signals, control_signals),
                control_signal_ids=[signal.id for signal in control_signals],
                risk_signal_ids=[signal.id for signal in risk_signals],
            )
        )
    return links


def _stronger_evidence_strength(current: str, candidate: str) -> str:
    rank = {"missing": 0, "weak": 1, "partial": 2, "strong": 3}
    return candidate if rank[candidate] > rank[current] else current


def _node_property(node: DFDNode, key: str) -> object | None:
    properties = getattr(node, "properties", None)
    if not isinstance(properties, dict):
        return None
    return properties.get(key)


def _normalize_data_classification(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    normalized = candidate.casefold()
    if normalized == "restricted":
        return "Restricted"
    if normalized == "confidential":
        return "Confidential"
    if normalized == "internal":
        return "Internal"
    if normalized == "public":
        return "Public"
    return candidate


def _max_data_classification(values: Sequence[str], fallback: str) -> str:
    if not values:
        return fallback
    normalized = [
        item
        for item in (_normalize_data_classification(value) for value in values)
        if item
    ]
    if not normalized:
        return fallback
    return max(normalized, key=lambda item: _CLASSIFICATION_RANK.get(item, -1))


def _select_edge_nodes(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> tuple[list[DFDNode], list[DFDNode]]:
    source_nodes: list[DFDNode] = []
    target_nodes: list[DFDNode] = []
    for edge_id in threat.affected_edge_ids or []:
        edge = edges_by_id.get(str(edge_id))
        if edge is None:
            continue
        source = nodes_by_id.get(str(edge.source_node_id))
        target = nodes_by_id.get(str(edge.target_node_id))
        if source is not None:
            source_nodes.append(source)
        if target is not None:
            target_nodes.append(target)
    return source_nodes, target_nodes


def _is_node_public(node: DFDNode) -> bool:
    if node.node_type in _EXTERNAL_NODE_TYPES:
        return True
    if _node_property(node, "internet_facing") is True:
        return True
    exposure = _as_string(_node_property(node, "network_exposure"))
    return bool(exposure and exposure.casefold() in _EDGE_FACING_EXPOSURES)


def _is_node_sensitive(node: DFDNode) -> bool:
    classification = _normalize_data_classification(
        _as_string(_node_property(node, "data_classification"))
    )
    if classification in {"Restricted", "Confidential"}:
        return True
    if node.node_type in _SENSITIVE_NODE_TYPES:
        return True
    if _node_property(node, "handles_sensitive_data") is True:
        return True
    privilege = _as_string(_node_property(node, "privilege_level"))
    return bool(privilege and privilege.casefold() in _PRIVILEGE_LEVELS)


def _is_control_plane_node(node: DFDNode) -> bool:
    if node.node_type in _CONTROL_PLANE_NODE_TYPES:
        return True
    if _node_property(node, "stores_credentials") is True:
        return True
    service_name = (_as_string(_node_property(node, "service_name")) or "").casefold()
    return any(
        token in service_name for token in ("iam", "auth", "identity", "secrets")
    )


def _edge_crosses_boundary(
    edge: DFDEdge,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> bool:
    del edges_by_id  # kept for signature consistency with other edge helpers
    source = nodes_by_id.get(str(edge.source_node_id))
    target = nodes_by_id.get(str(edge.target_node_id))
    if source is None or target is None:
        return False
    return str(source.trust_boundary_id or "") != str(target.trust_boundary_id or "")


def _infer_entry_point(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> str | None:
    affected_nodes = [
        node
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    ]
    public_nodes = [node for node in affected_nodes if _is_node_public(node)]
    if public_nodes:
        return public_nodes[0].name

    source_nodes, _ = _select_edge_nodes(threat, nodes_by_id, edges_by_id)
    public_sources = [node for node in source_nodes if _is_node_public(node)]
    if public_sources:
        return public_sources[0].name
    if source_nodes:
        return source_nodes[0].name
    if affected_nodes:
        return affected_nodes[0].name
    return None


def _infer_target_asset(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> str | None:
    affected_nodes = [
        node
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    ]
    sensitive_nodes = [node for node in affected_nodes if _is_node_sensitive(node)]
    if sensitive_nodes:
        return sensitive_nodes[-1].name

    _, target_nodes = _select_edge_nodes(threat, nodes_by_id, edges_by_id)
    sensitive_targets = [node for node in target_nodes if _is_node_sensitive(node)]
    if sensitive_targets:
        return sensitive_targets[-1].name
    if target_nodes:
        return target_nodes[-1].name
    if affected_nodes:
        return affected_nodes[-1].name
    return None


def _infer_public_exposure(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> bool:
    if any(
        _is_node_public(node)
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    ):
        return True
    source_nodes, target_nodes = _select_edge_nodes(threat, nodes_by_id, edges_by_id)
    return any(_is_node_public(node) for node in [*source_nodes, *target_nodes])


def _infer_boundary_crossing(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> bool:
    for edge_id in threat.affected_edge_ids or []:
        edge = edges_by_id.get(str(edge_id))
        if edge is None:
            continue
        if _edge_crosses_boundary(edge, nodes_by_id, edges_by_id):
            return True
    source_nodes, target_nodes = _select_edge_nodes(threat, nodes_by_id, edges_by_id)
    return any(
        str(source.trust_boundary_id or "") != str(target.trust_boundary_id or "")
        for source in source_nodes
        for target in target_nodes
    )


def _infer_privileged_access(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
) -> bool:
    for node_id in threat.affected_node_ids or []:
        node = nodes_by_id.get(str(node_id))
        if node is None:
            continue
        if node.node_type == "iam_role":
            return True
        privilege = _as_string(_node_property(node, "privilege_level"))
        if privilege and privilege.casefold() in _PRIVILEGE_LEVELS:
            return True
    return False


def _infer_control_plane_asset(
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
) -> bool:
    for node_id in threat.affected_node_ids or []:
        node = nodes_by_id.get(str(node_id))
        if node is None:
            continue
        if _is_control_plane_node(node):
            return True
    return False


def _infer_business_criticality(
    threat_model: ThreatModel,
    threat: Threat,
    nodes_by_id: Mapping[str, DFDNode],
) -> str:
    affected_classifications = [
        _as_string(_node_property(node, "data_classification"))
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    ]
    highest_classification = _max_data_classification(
        [value for value in affected_classifications if value],
        threat_model.data_classification,
    )
    has_crown_jewel = any(
        _node_property(node, "crown_jewel") is True
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    )
    if has_crown_jewel or (
        highest_classification == "Restricted"
        or threat.severity == "Critical"
        or (
            threat_model.regulatory_scope
            and (
                highest_classification == "Confidential" or threat.status == "Accepted"
            )
        )
    ):
        return "mission_critical"
    if (
        highest_classification == "Confidential"
        or threat.severity == "High"
        or bool(threat_model.regulatory_scope)
    ):
        return "high"
    if _infer_public_exposure(threat, nodes_by_id, {}):
        return "moderate"
    return "low"


def _infer_evidence_strength(
    threat: Threat,
    intel: ThreatIntelResponse | None,
    scan_status: str | None,
) -> str:
    if scan_status == "confirmed":
        return "strong"
    if intel is not None and (
        intel.kev_entries
        or any(item.match_type == "exact" for item in intel.attack_techniques)
        or any(item.match_type == "exact" for item in intel.attack_patterns)
        or intel.scan_cve_ids
    ):
        return "strong"
    if scan_status in {"mitigated", "unverifiable"}:
        return "partial"
    if intel is not None and (
        intel.attack_techniques or intel.attack_patterns or intel.severity_signals
    ):
        return "partial"
    if threat.relevance_rationale or threat.mitigation_notes or threat.mitigation_plan:
        return "weak"
    return "missing"


def _infer_finding_kind(
    threat: Threat,
    intel: ThreatIntelResponse | None,
    scan_status: str | None,
) -> str:
    del intel, scan_status
    if threat.status == "Accepted" and threat.false_positive_reason == "accepted_risk":
        return "control_gap"
    return "threat"


def _infer_previous_priority(threat: Threat) -> PriorityBand | None:
    qualification_label = getattr(threat, "qualification_label", None)
    if qualification_label is None:
        score = getattr(threat, "qualification_score", None)
        if score is None:
            return None
        if score >= 70:
            qualification_label = "Priority"
        elif score >= 45:
            qualification_label = "Investigate"
        elif score >= 20:
            qualification_label = "Review"
        else:
            qualification_label = "Low Signal"

    if qualification_label is None:
        return None
    return _QUALIFICATION_PRIORITY.get(qualification_label)


def _days_since(timestamp: datetime | None) -> int | None:
    if timestamp is None:
        return None
    current = datetime.now(UTC)
    reference = (
        timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=UTC)
    )
    return max((current - reference).days, 0)


def _build_risk_acceptance(threat: Threat) -> SecurityReviewRiskAcceptance | None:
    if (
        threat.status != "Accepted"
        and threat.false_positive_reason != "accepted_risk"
    ):
        return None
    accepted_at = threat.closed_at or threat.qualification_completed_at
    reopened = (
        threat.status != "Accepted"
        and threat.false_positive_reason == "accepted_risk"
    )
    return SecurityReviewRiskAcceptance(
        finding_title=f"{threat.display_id}: {threat.description}",
        status="reopened" if reopened else "active",
        accepted_by=threat.mitigation_owner,
        accepted_at=accepted_at.isoformat() if accepted_at is not None else None,
        expires_at=threat.due_date.isoformat() if threat.due_date else None,
        acceptance_rationale=threat.dismiss_reason
        or threat.mitigation_notes
        or threat.mitigation_plan,
        compensating_control=threat.mitigation_plan,
        reopen_triggers=["threat reopened by reviewer"] if reopened else [],
    )


def _build_context_evidence_anchors(
    context: SecurityReviewContext,
    nodes_by_id: Mapping[str, DFDNode],
    edges_by_id: Mapping[str, DFDEdge],
) -> list[SecurityReviewEvidenceAnchor]:
    anchors: list[SecurityReviewEvidenceAnchor] = list(context.evidence_anchors)
    validated = context.evidence_strength in {"strong", "partial"}

    for node_id in context.affected_node_ids[:6]:
        node = nodes_by_id.get(node_id)
        node_label = node.name if node is not None else node_id
        anchors.append(
            SecurityReviewEvidenceAnchor(
                type="dfd",
                reference=f"dfd_node:{node_id}",
                claim=f"DFD node {node_label} is affected by this finding.",
                validated=validated,
                source_object_type="dfd_node",
                source_object_id=node_id,
                location=f"dfd_node:{node_id}",
                relationship="affected_component",
                strength=context.evidence_strength,
            )
        )

    for edge_id in context.affected_edge_ids[:6]:
        edge = edges_by_id.get(edge_id)
        source = nodes_by_id.get(str(edge.source_node_id)) if edge is not None else None
        target = nodes_by_id.get(str(edge.target_node_id)) if edge is not None else None
        edge_label = getattr(edge, "label", None)
        flow_label = (
            edge_label
            if edge is not None and edge_label
            else (
                f"{source.name if source is not None else 'source'} -> "
                f"{target.name if target is not None else 'target'}"
            )
        )
        anchors.append(
            SecurityReviewEvidenceAnchor(
                type="dfd",
                reference=f"dfd_edge:{edge_id}",
                claim=f"DFD flow {flow_label} is affected by this finding.",
                validated=validated,
                source_object_type="dfd_edge",
                source_object_id=edge_id,
                location=f"dfd_edge:{edge_id}",
                relationship="affected_flow",
                strength=context.evidence_strength,
            )
        )

    return anchors


def _cloud_finding_anchor(
    cloud: CloudScanEvidence,
    finding: CloudFinding,
    index: int,
) -> SecurityReviewEvidenceAnchor:
    object_id = finding.source_finding_id or _evidence_object_id(
        cloud.provider,
        finding.category,
        finding.service,
        finding.resource,
        index,
    )
    locator = f"cloud_finding:{object_id}"
    label = " / ".join(
        part for part in (finding.service, finding.resource) if part
    ) or finding.category
    source_note = (
        f" Scanner finding `{finding.source_finding_id}`."
        if finding.source_finding_id
        else ""
    )
    return SecurityReviewEvidenceAnchor(
        type="cloud",
        reference=locator,
        claim=(
            f"{cloud.provider} reported {finding.severity} "
            f"{finding.category.replace('_', ' ')} on {label}: {finding.detail}"
            f"{source_note}"
        ),
        validated=True,
        source_object_type="cloud_finding",
        source_object_id=object_id,
        location=locator,
        relationship="supports_cloud_risk",
        strength="strong" if finding.severity in {"Critical", "High"} else "partial",
    )


def _build_cloud_scan_evidence_anchors(
    cloud: CloudScanEvidence,
) -> list[SecurityReviewEvidenceAnchor]:
    return [
        _cloud_finding_anchor(cloud, finding, index)
        for index, finding in enumerate(cloud.high_signal_findings[:8], start=1)
    ]


def _build_iac_evidence_anchors(iac: IacEvidence) -> list[SecurityReviewEvidenceAnchor]:
    anchors: list[SecurityReviewEvidenceAnchor] = []
    for resource_name in iac.resource_names[:8]:
        object_id = _evidence_object_id(iac.reference, resource_name)
        anchors.append(
            SecurityReviewEvidenceAnchor(
                type="iac",
                reference=f"iac_resource:{object_id}",
                claim=f"IaC evidence includes resource {resource_name}.",
                validated=True,
                source_object_type="iac_resource",
                source_object_id=object_id,
                location=f"iac_resource:{object_id}",
                relationship="defines_runtime_object",
                strength="partial",
            )
        )

    signal_groups = (
        ("public_exposure", iac.public_exposure, "shows_public_exposure"),
        ("iam_binding", iac.iam_bindings, "shows_identity_scope"),
        ("network_path", iac.network_paths, "shows_network_path"),
        ("secret_ref", iac.secret_refs, "shows_secret_dependency"),
    )
    for signal_type, values, relationship in signal_groups:
        for value in values[:4]:
            object_id = _evidence_object_id(iac.reference, signal_type, value)
            anchors.append(
                SecurityReviewEvidenceAnchor(
                    type="iac",
                    reference=f"iac_{signal_type}:{object_id}",
                    claim=f"IaC evidence includes {signal_type.replace('_', ' ')}: {value}.",
                    validated=True,
                    source_object_type=f"iac_{signal_type}",
                    source_object_id=object_id,
                    location=f"iac_{signal_type}:{object_id}",
                    relationship=relationship,
                    strength="strong" if signal_type in {"public_exposure", "iam_binding"} else "partial",
                )
            )
    return anchors[:12]


def _build_document_excerpt_anchors(
    threat_model: ThreatModel,
) -> list[SecurityReviewEvidenceAnchor]:
    anchors: list[SecurityReviewEvidenceAnchor] = []
    for document in list(getattr(threat_model, "documents", None) or [])[:3]:
        document_id = str(getattr(document, "id", "") or getattr(document, "filename", "document"))
        filename = str(getattr(document, "filename", "") or document_id)
        raw_text = str(getattr(document, "raw_text", "") or "")
        parsed_components = getattr(document, "parsed_components", None)
        if not raw_text and isinstance(parsed_components, Mapping):
            raw_text = str(parsed_components.get("raw_text_excerpt") or "")
        excerpt = re.sub(r"\s+", " ", raw_text).strip()[:220]
        if not excerpt:
            continue
        locator = f"document_excerpt:{document_id}"
        anchors.append(
            SecurityReviewEvidenceAnchor(
                type="document",
                reference=locator,
                claim=f"Document {filename} excerpt supports architecture context: {excerpt}",
                validated=True,
                source_object_type="document_excerpt",
                source_object_id=document_id,
                location=locator,
                relationship="supports_architecture_context",
                strength="partial",
            )
        )
    return anchors


def build_security_review_context(
    threat_model: ThreatModel,
    threat: Threat,
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
    *,
    intel: ThreatIntelResponse | None = None,
    scan_status: str | None = None,
) -> SecurityReviewContext:
    """Map one persisted threat into a deterministic review context."""

    nodes_by_id = {str(node.id): node for node in nodes}
    edges_by_id = {str(edge.id): edge for edge in edges}
    affected_classifications = [
        _as_string(_node_property(node, "data_classification"))
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    ]
    highest_classification = _max_data_classification(
        [value for value in affected_classifications if value],
        threat_model.data_classification,
    )
    selected_scan_status = scan_status or None
    evidence_strength = _infer_evidence_strength(threat, intel, selected_scan_status)
    public_exposure = _infer_public_exposure(threat, nodes_by_id, edges_by_id)
    crosses_trust_boundary = _infer_boundary_crossing(threat, nodes_by_id, edges_by_id)
    privileged_access = _infer_privileged_access(threat, nodes_by_id)
    control_plane_asset = _infer_control_plane_asset(threat, nodes_by_id)
    finding_title = f"{threat.display_id}: {threat.description}"
    entry_point = _infer_entry_point(threat, nodes_by_id, edges_by_id)
    target_asset = _infer_target_asset(threat, nodes_by_id, edges_by_id)
    crown_jewel = any(
        _node_property(node, "crown_jewel") is True
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    )
    repository_evidence = _coerce_repository_evidence(
        getattr(threat_model, "repository_evidence", None)
    )
    document_anchors = _build_document_excerpt_anchors(threat_model)
    affected_node_names = [
        node.name
        for node_id in threat.affected_node_ids or []
        if (node := nodes_by_id.get(str(node_id))) is not None
    ]
    code_links = _build_code_links_for_tokens(
        repository_evidence,
        finding_key=str(threat.id),
        match_tokens=_tokenize_code_match_text(
            threat.display_id,
            threat.description,
            threat.stride_category,
            threat.threat_subtype,
            entry_point,
            target_asset,
            *affected_node_names,
        ),
    )
    has_code_risk = any(link.risk_signal_ids for link in code_links)
    has_code_control = any(link.control_signal_ids for link in code_links)
    if has_code_risk or has_code_control:
        evidence_strength = _stronger_evidence_strength(evidence_strength, "partial")
    control_effectiveness = threat.control_effectiveness
    compensating_controls_present = threat.control_effectiveness in {
        "substantial",
        "full",
    } or threat.status in {"Mitigated", "Accepted"}
    if has_code_control and not has_code_risk:
        control_effectiveness = (
            "full"
            if len(
                {
                    signal_id
                    for link in code_links
                    for signal_id in link.control_signal_ids
                }
            )
            >= 2
            else "substantial"
        )
        compensating_controls_present = True
    if has_code_risk:
        public_exposure = True
        control_effectiveness = "none"
        compensating_controls_present = False
    finding_sources = (
        ["scan", "threat_intel", "dfd"]
        if selected_scan_status and intel is not None
        else (
            ["scan", "dfd"]
            if selected_scan_status
            else ["threat_intel", "dfd"]
            if intel is not None
            else ["dfd"]
        )
    )
    if code_links and "repository" not in finding_sources:
        finding_sources.append("repository")

    return SecurityReviewContext(
        finding_kind=_infer_finding_kind(threat, intel, selected_scan_status),  # type: ignore[arg-type]
        finding_key=str(threat.id),
        title=finding_title,
        description=threat.description,
        finding_sources=finding_sources,  # type: ignore[arg-type]
        affected_node_ids=[str(node_id) for node_id in threat.affected_node_ids or []],
        affected_edge_ids=[str(edge_id) for edge_id in threat.affected_edge_ids or []],
        entry_point=entry_point,
        target_asset=target_asset,
        threat_severity=threat.severity,  # type: ignore[arg-type]
        residual_risk_level=threat.residual_risk_level,  # type: ignore[arg-type]
        control_effectiveness=control_effectiveness,  # type: ignore[arg-type]
        scan_status=selected_scan_status,  # type: ignore[arg-type]
        has_known_exploited_vulnerability=bool(intel and intel.kev_entries),
        has_exact_threat_intel=bool(
            intel
            and (
                any(item.match_type == "exact" for item in intel.attack_techniques)
                or any(item.match_type == "exact" for item in intel.attack_patterns)
            )
        ),
        has_semantic_threat_intel=bool(
            intel
            and (
                intel.semantic_matches_inferred
                or any(
                    item.match_type == "semantic" for item in intel.attack_techniques
                )
                or any(item.match_type == "semantic" for item in intel.attack_patterns)
            )
        ),
        internet_facing=public_exposure,
        public_exposure=public_exposure,
        privileged_access=privileged_access,
        crosses_trust_boundary=crosses_trust_boundary,
        control_plane_asset=control_plane_asset,
        crown_jewel=crown_jewel,
        data_classification=highest_classification,  # type: ignore[arg-type]
        regulatory_scope=list(threat_model.regulatory_scope or []),
        business_criticality=_infer_business_criticality(
            threat_model, threat, nodes_by_id
        ),  # type: ignore[arg-type]
        business_capability=threat_model.system_name,
        evidence_strength=evidence_strength,  # type: ignore[arg-type]
        change_surface="code"
        if code_links or threat.source in {"AI", "AI+Rules"}
        else "design",
        active_change_window=False,
        compensating_controls_present=compensating_controls_present,
        owner_known=bool(threat.mitigation_owner),
        remediation_exists=bool(threat.mitigation_plan or threat.mitigation_notes),
        existing_risk_acceptance=_build_risk_acceptance(threat),
        previous_priority=_infer_previous_priority(threat),
        days_since_last_review=_days_since(
            threat.qualification_completed_at or threat.closed_at or threat.created_at
        ),
        code_links=code_links,
        evidence_anchors=document_anchors,
    )


def evaluate_threat_security_reviews(
    threat_model: ThreatModel,
    threats: Sequence[Threat],
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
    *,
    intel_by_threat_id: Mapping[str, ThreatIntelResponse] | None = None,
    scan_status_by_threat_id: Mapping[str, str] | None = None,
) -> dict[str, SecurityReviewDecision]:
    """Evaluate all threat decisions for a model in one pass."""

    contexts = [
        build_security_review_context(
            threat_model,
            threat,
            nodes,
            edges,
            intel=(intel_by_threat_id or {}).get(str(threat.id)),
            scan_status=(scan_status_by_threat_id or {}).get(str(threat.id)),
        )
        for threat in threats
    ]
    decisions = evaluate_security_review_contexts(contexts)
    return {
        str(threat.id): decision
        for threat, decision in zip(threats, decisions, strict=True)
    }


def _infer_model_business_criticality(
    threat_model: ThreatModel,
    nodes: Sequence[DFDNode],
) -> str:
    classification = _normalize_data_classification(
        _as_string(getattr(threat_model, "data_classification", None))
    )
    if classification == "Restricted" or bool(
        getattr(threat_model, "regulatory_scope", None)
    ):
        return "mission_critical"
    if classification == "Confidential" or any(_is_node_public(node) for node in nodes):
        return "high"
    if nodes:
        return "moderate"
    return "low"


def _build_systemic_review_contexts(
    threat_model: ThreatModel,
    threats: Sequence[Threat],
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
    boundaries: Sequence[TrustBoundary],
) -> list[SecurityReviewContext]:
    contexts: list[SecurityReviewContext] = []
    regulatory_scope = list(getattr(threat_model, "regulatory_scope", None) or [])
    data_classification = (
        _normalize_data_classification(
            _as_string(getattr(threat_model, "data_classification", None))
        )
        or "Internal"
    )
    business_criticality = _infer_model_business_criticality(threat_model, nodes)
    deployment_model = (
        _as_string(getattr(threat_model, "deployment_model", None)) or ""
    ).casefold()
    owner_known = bool(getattr(threat_model, "owner_id", None))
    public_nodes = [node for node in nodes if _is_node_public(node)]
    sensitive_nodes = [node for node in nodes if _is_node_sensitive(node)]
    repository_evidence = _coerce_repository_evidence(
        getattr(threat_model, "repository_evidence", None)
    )
    cloud_scan_evidence = _coerce_cloud_scan_evidence(
        getattr(threat_model, "cloud_scan_evidence", None)
    )
    iac_evidence = _coerce_iac_evidence(getattr(threat_model, "iac_evidence", None))
    document_anchors = _build_document_excerpt_anchors(threat_model)

    if not nodes and not edges:
        contexts.append(
            SecurityReviewContext(
                finding_kind="evidence_gap",
                finding_key="model:dfd-coverage",
                title="Threat model lacks DFD coverage",
                description="No nodes or flows are present, so the application review cannot prove architecture coverage.",
                finding_sources=["dfd"],
                threat_severity="High",
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="missing",
                change_surface="design",
                owner_known=owner_known,
            )
        )

    if repository_evidence is not None and repository_evidence.code_risk_signals:
        surfaces_by_id = {
            surface.id: surface for surface in repository_evidence.code_surfaces
        }
        high_signal_risks = [
            signal
            for signal in repository_evidence.code_risk_signals
            if signal.risk_type in {"missing_authentication", "missing_validation"}
            and signal.surface_id in surfaces_by_id
        ]
        if high_signal_risks:
            links: list[FindingCodeLink] = []
            for signal in high_signal_risks[:4]:
                surface = surfaces_by_id[signal.surface_id]
                links.append(
                    FindingCodeLink(
                        finding_key="model:code-unprotected-sensitive-surface",
                        surface_id=surface.id,
                        surface_name=surface.name,
                        source_file=surface.source_file,
                        line_number=surface.line_number,
                        relationship="confirms_missing_control",
                        summary=signal.evidence,
                        risk_signal_ids=[signal.id],
                    )
                )
            contexts.append(
                SecurityReviewContext(
                    finding_kind="control_gap",
                    finding_key="model:code-unprotected-sensitive-surface",
                    title="Code evidence found unprotected sensitive routes",
                    description="Repository evidence found route handlers that touch sensitive data without enough detected control evidence.",
                    finding_sources=["repository"],
                    threat_severity="High",
                    public_exposure=True,
                    internet_facing=True,
                    data_classification=data_classification,  # type: ignore[arg-type]
                    regulatory_scope=regulatory_scope,
                    business_criticality=business_criticality,  # type: ignore[arg-type]
                    evidence_strength="strong",
                    change_surface="code",
                    owner_known=owner_known,
                    code_links=links,
                )
            )

    if repository_evidence is not None and repository_evidence.code_surfaces and nodes:
        modeled_tokens = _tokenize_code_match_text(*(node.name for node in nodes))
        mapped_surface_ids = _dfd_mapped_code_surface_ids(nodes, edges)
        mapped_source_refs = _dfd_mapped_code_source_refs(nodes, edges)
        unmatched_surfaces = [
            surface
            for surface in repository_evidence.code_surfaces
            if not (_code_surface_tokens(surface) & modeled_tokens)
            and not _code_surface_has_dfd_mapping(
                surface,
                mapped_surface_ids=mapped_surface_ids,
                mapped_source_refs=mapped_source_refs,
            )
        ]
        if unmatched_surfaces:
            links = [
                FindingCodeLink(
                    finding_key="model:code-evidence-mapping",
                    surface_id=surface.id,
                    surface_name=surface.name,
                    source_file=surface.source_file,
                    line_number=surface.line_number,
                    relationship="unmodeled_surface",
                    summary="This code surface is present in repository evidence but is not clearly mapped to a DFD node.",
                )
                for surface in unmatched_surfaces[:4]
            ]
            contexts.append(
                SecurityReviewContext(
                    finding_kind="evidence_gap",
                    finding_key="model:code-evidence-mapping",
                    title="Code surfaces need DFD mapping evidence",
                    description="Repository scanning found routes or handlers that are not clearly represented in the current DFD.",
                    finding_sources=["repository", "dfd"],
                    threat_severity="Medium",
                    public_exposure=True,
                    internet_facing=True,
                    data_classification=data_classification,  # type: ignore[arg-type]
                    regulatory_scope=regulatory_scope,
                    business_criticality=business_criticality,  # type: ignore[arg-type]
                    evidence_strength="missing",
                    change_surface="code",
                    owner_known=owner_known,
                    code_links=links,
                )
            )

    if getattr(threat_model, "repository_evidence", None) is None:
        contexts.append(
            SecurityReviewContext(
                finding_kind="evidence_gap",
                finding_key="model:repository-evidence",
                title="Repository evidence is missing for this application review",
                description="Without code or repository evidence, the review cannot separate real implementation risk from design-only assumptions.",
                finding_sources=["repository"],
                threat_severity="Medium",
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="missing",
                change_surface="code",
                owner_known=owner_known,
            )
        )

    cloud_evidence_out_of_scope = _evidence_source_out_of_scope(threat_model, "cloud")
    iac_evidence_out_of_scope = _evidence_source_out_of_scope(threat_model, "iac")

    if (
        deployment_model in {"cloud", "hybrid"}
        and getattr(threat_model, "cloud_scan_evidence", None) is None
        and not cloud_evidence_out_of_scope
    ):
        contexts.append(
            SecurityReviewContext(
                finding_kind="evidence_gap",
                finding_key="model:cloud-evidence",
                title="Cloud configuration evidence is missing for an in-scope deployment",
                description="The application is deployed in cloud or hybrid infrastructure, but there is no attached cloud configuration evidence.",
                finding_sources=["cloud", "compliance"],
                threat_severity="High",
                public_exposure=bool(public_nodes),
                internet_facing=bool(public_nodes),
                crosses_trust_boundary=bool(boundaries),
                control_plane_asset=any(_is_control_plane_node(node) for node in nodes),
                crown_jewel=business_criticality == "mission_critical",
                entry_point=public_nodes[0].name if public_nodes else None,
                target_asset=sensitive_nodes[0].name if sensitive_nodes else None,
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="missing",
                change_surface="deployment",
                owner_known=owner_known,
            )
        )

    if cloud_scan_evidence is not None and cloud_scan_evidence.high_signal_findings:
        cloud_anchors = _build_cloud_scan_evidence_anchors(cloud_scan_evidence)
        exposed = any(
            finding.category in {"public_storage", "internet_exposure"}
            for finding in cloud_scan_evidence.high_signal_findings
        )
        identity_risk = any(
            finding.category in {"broad_iam", "cross_account_trust", "mfa_gap"}
            for finding in cloud_scan_evidence.high_signal_findings
        )
        contexts.append(
            SecurityReviewContext(
                finding_kind="control_gap",
                finding_key="model:cloud-scan-high-signal",
                title=(
                    "Cloud scan evidence contains high-signal configuration findings"
                ),
                description=(
                    "Attached cloud posture evidence contains findings that should "
                    "be resolved or explicitly accepted before this review is treated "
                    "as deployment-ready."
                ),
                finding_sources=["cloud", "scan"],
                threat_severity="High",
                public_exposure=exposed,
                internet_facing=exposed,
                privileged_access=identity_risk,
                control_plane_asset=identity_risk,
                crown_jewel=business_criticality == "mission_critical",
                entry_point=cloud_scan_evidence.exposed_services[0]
                if cloud_scan_evidence.exposed_services
                else None,
                target_asset=(
                    cloud_scan_evidence.identity_risks[0]
                    if cloud_scan_evidence.identity_risks
                    else cloud_scan_evidence.encryption_gaps[0]
                    if cloud_scan_evidence.encryption_gaps
                    else None
                ),
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="strong",
                change_surface="deployment",
                owner_known=owner_known,
                evidence_anchors=[*cloud_anchors, *document_anchors[:1]],
            )
        )

    if (
        deployment_model in {"cloud", "hybrid"}
        and getattr(threat_model, "iac_evidence", None) is None
        and not iac_evidence_out_of_scope
    ):
        contexts.append(
            SecurityReviewContext(
                finding_kind="evidence_gap",
                finding_key="model:iac-evidence",
                title="Infrastructure-as-code evidence is missing for an in-scope deployment",
                description="Without IaC evidence, the review cannot prove whether exposure, identity, and network controls match the intended design.",
                finding_sources=["iac", "compliance"],
                threat_severity="High",
                public_exposure=bool(public_nodes),
                internet_facing=bool(public_nodes),
                crosses_trust_boundary=bool(boundaries),
                control_plane_asset=any(_is_control_plane_node(node) for node in nodes),
                crown_jewel=business_criticality == "mission_critical",
                entry_point=public_nodes[0].name if public_nodes else None,
                target_asset=sensitive_nodes[0].name if sensitive_nodes else None,
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="missing",
                change_surface="deployment",
                owner_known=owner_known,
            )
        )

    if iac_evidence is not None and (
        iac_evidence.public_exposure
        or iac_evidence.iam_bindings
        or iac_evidence.network_paths
        or iac_evidence.secret_refs
    ):
        iac_anchors = _build_iac_evidence_anchors(iac_evidence)
        contexts.append(
            SecurityReviewContext(
                finding_kind="control_gap",
                finding_key="model:iac-object-risk",
                title="IaC evidence contains deployment objects that need review",
                description=(
                    "Attached infrastructure-as-code evidence contains exposure, "
                    "identity, network, or secret-reference signals that should be "
                    "mapped to controls before this review is treated as deployment-ready."
                ),
                finding_sources=["iac"],
                threat_severity="High",
                public_exposure=bool(iac_evidence.public_exposure),
                internet_facing=bool(iac_evidence.public_exposure),
                privileged_access=bool(iac_evidence.iam_bindings),
                crosses_trust_boundary=bool(iac_evidence.network_paths),
                control_plane_asset=bool(iac_evidence.iam_bindings),
                crown_jewel=business_criticality == "mission_critical",
                entry_point=iac_evidence.public_exposure[0]
                if iac_evidence.public_exposure
                else None,
                target_asset=iac_evidence.resource_names[0]
                if iac_evidence.resource_names
                else None,
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="strong",
                change_surface="deployment",
                owner_known=owner_known,
                evidence_anchors=[*iac_anchors, *document_anchors[:1]],
            )
        )

    if regulatory_scope and not getattr(
        threat_model, "environment_context_summary", None
    ):
        contexts.append(
            SecurityReviewContext(
                finding_kind="evidence_gap",
                finding_key="model:environment-context",
                title="Environment context summary is missing for a regulated model",
                description="The application is in regulatory scope, but the review is missing the synthesized environment context needed to connect evidence to controls.",
                finding_sources=["cloud", "iac", "repository", "compliance"],
                threat_severity="Medium",
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="missing",
                change_surface="unknown",
                owner_known=owner_known,
            )
        )

    if public_nodes and not boundaries:
        contexts.append(
            SecurityReviewContext(
                finding_kind="control_gap",
                finding_key="model:trust-boundary-gap",
                title="Externally reachable surfaces lack trust-boundary segmentation",
                description="The DFD shows externally reachable surfaces, but the model does not currently establish trust boundaries around them.",
                finding_sources=["dfd"],
                threat_severity="High",
                public_exposure=True,
                internet_facing=True,
                crosses_trust_boundary=False,
                control_plane_asset=any(_is_control_plane_node(node) for node in nodes),
                crown_jewel=business_criticality == "mission_critical",
                entry_point=public_nodes[0].name,
                target_asset=sensitive_nodes[0].name if sensitive_nodes else None,
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="partial",
                change_surface="design",
                owner_known=owner_known,
            )
        )

    unowned_high_risk = [
        threat
        for threat in threats
        if threat.status in {"Open", "In Progress"}
        and threat.severity in _HIGH_SIGNAL_SEVERITIES
        and not getattr(threat, "mitigation_owner", None)
    ]
    if unowned_high_risk:
        contexts.append(
            SecurityReviewContext(
                finding_kind="control_gap",
                finding_key="model:owner-gap",
                title=f"{len(unowned_high_risk)} active high-risk findings have no owner",
                description="High-signal findings are still unowned, which means the review cannot reliably translate into delivery work.",
                finding_sources=["manual"],
                threat_severity="High",
                data_classification=data_classification,  # type: ignore[arg-type]
                regulatory_scope=regulatory_scope,
                business_criticality=business_criticality,  # type: ignore[arg-type]
                evidence_strength="partial",
                change_surface="code",
                owner_known=False,
            )
        )

    return contexts


def _build_bucket_counts(
    category: str, counter: Counter[str]
) -> list[SecurityReviewBucketCount]:
    labels = _COUNT_LABELS[category]
    return [
        SecurityReviewBucketCount(
            key=key,
            label=labels[key],
            count=counter.get(key, 0),
        )
        for key in _COUNT_ORDER[category]
    ]


def _build_finding_summary(
    context: SecurityReviewContext,
    decision: SecurityReviewDecision,
    *,
    threat: Threat | None,
) -> SecurityReviewFindingSummary:
    return SecurityReviewFindingSummary(
        finding_key=context.finding_key,
        threat_id=str(threat.id) if threat is not None else None,
        display_id=threat.display_id if threat is not None else None,
        finding_kind=context.finding_kind,
        title=context.title,
        priority=decision.priority,
        action_bucket=decision.action_bucket,
        truth_status=decision.truth_status,
        urgency=decision.urgency,
        noise_disposition=decision.noise_disposition,
        numeric_score=decision.numeric_score,
        entry_point=context.entry_point,
        target_asset=context.target_asset,
        rationale_excerpt=decision.rationale[0] if decision.rationale else None,
        next_step=decision.next_steps[0] if decision.next_steps else None,
        related_attack_path_count=len(decision.related_attack_paths),
        evidence_adjustment_count=len(decision.evidence_adjustments),
        systemic=threat is None,
    )


def _finding_sort_key(summary: SecurityReviewFindingSummary) -> tuple[int, int, str]:
    return (
        _PRIORITY_RANK[summary.priority],
        -summary.numeric_score,
        summary.title.casefold(),
    )


def _dedupe_attack_paths(
    decisions: Sequence[SecurityReviewDecision],
) -> list:
    by_id = {}
    for decision in decisions:
        for path in decision.related_attack_paths:
            existing = by_id.get(path.path_id)
            if existing is None or (
                _PRIORITY_RANK[path.composite_priority],
                -path.hop_count,
                path.chain_description.casefold(),
            ) < (
                _PRIORITY_RANK[existing.composite_priority],
                -existing.hop_count,
                existing.chain_description.casefold(),
            ):
                by_id[path.path_id] = path
    return sorted(
        by_id.values(),
        key=lambda path: (
            _PRIORITY_RANK[path.composite_priority],
            -path.hop_count,
            path.chain_description.casefold(),
        ),
    )


def build_application_security_review(
    threat_model: ThreatModel,
    threats: Sequence[Threat],
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
    boundaries: Sequence[TrustBoundary],
    *,
    intel_by_threat_id: Mapping[str, ThreatIntelResponse] | None = None,
    scan_status_by_threat_id: Mapping[str, str] | None = None,
) -> SecurityReviewApplicationSummary:
    """Build an application-wide deterministic security review summary."""

    reviewable_threats = [
        threat for threat in threats if threat.status in _ACTIVE_THREAT_STATUSES
    ]
    threat_context_entries = [
        (
            build_security_review_context(
                threat_model,
                threat,
                nodes,
                edges,
                intel=(intel_by_threat_id or {}).get(str(threat.id)),
                scan_status=(scan_status_by_threat_id or {}).get(str(threat.id)),
            ),
            threat,
        )
        for threat in reviewable_threats
    ]
    systemic_context_entries = [
        (context, None)
        for context in _build_systemic_review_contexts(
            threat_model,
            reviewable_threats,
            nodes,
            edges,
            boundaries,
        )
    ]
    context_entries = [*threat_context_entries, *systemic_context_entries]
    decisions = (
        evaluate_security_review_contexts([context for context, _ in context_entries])
        if context_entries
        else []
    )
    finding_summaries = [
        _build_finding_summary(context, decision, threat=threat)
        for (context, threat), decision in zip(context_entries, decisions, strict=True)
    ]
    sorted_findings = sorted(finding_summaries, key=_finding_sort_key)
    attack_paths = _dedupe_attack_paths(decisions)
    priority_counts = _build_bucket_counts(
        "priority", Counter(decision.priority for decision in decisions)
    )
    action_bucket_counts = _build_bucket_counts(
        "action_bucket", Counter(decision.action_bucket for decision in decisions)
    )
    truth_status_counts = _build_bucket_counts(
        "truth_status", Counter(decision.truth_status for decision in decisions)
    )
    noise_counts = _build_bucket_counts(
        "noise_disposition",
        Counter(decision.noise_disposition for decision in decisions),
    )

    risk_acceptance_summary = SecurityReviewRiskAcceptanceSummary(
        active=sum(
            1
            for decision in decisions
            if decision.risk_acceptance is not None
            and decision.risk_acceptance.status == "active"
        ),
        reopened=sum(
            1
            for decision in decisions
            if decision.risk_acceptance is not None
            and decision.risk_acceptance.status == "reopened"
        ),
        expired=sum(
            1
            for decision in decisions
            if decision.risk_acceptance is not None
            and decision.risk_acceptance.status == "expired"
        ),
    )
    review_delta_summary = SecurityReviewDeltaSummary(
        new_findings=sum(
            (decision.review_delta.new_findings_count if decision.review_delta else 0)
            for decision in decisions
        ),
        resolved_findings=sum(
            (decision.review_delta.resolved_count if decision.review_delta else 0)
            for decision in decisions
        ),
        reopened_findings=sum(
            (decision.review_delta.reopened_count if decision.review_delta else 0)
            for decision in decisions
        ),
        escalated_findings=sum(
            (decision.review_delta.escalated_count if decision.review_delta else 0)
            for decision in decisions
        ),
        deescalated_findings=sum(
            1
            for decision in decisions
            if decision.review_delta is not None
            and decision.review_delta.disposition == "deescalated"
        ),
    )

    deployment_model = (
        _as_string(getattr(threat_model, "deployment_model", None)) or ""
    ).casefold()
    cloud_evidence_out_of_scope = _evidence_source_out_of_scope(threat_model, "cloud")
    iac_evidence_out_of_scope = _evidence_source_out_of_scope(threat_model, "iac")
    expected_evidence_sources = 1
    if deployment_model in {"cloud", "hybrid"}:
        if not cloud_evidence_out_of_scope:
            expected_evidence_sources += 1
        if not iac_evidence_out_of_scope:
            expected_evidence_sources += 1
    if bool(getattr(threat_model, "regulatory_scope", None)) or any(
        getattr(threat_model, field, None) is not None
        for field in ("repository_evidence", "cloud_scan_evidence", "iac_evidence")
    ):
        expected_evidence_sources += 1

    attached_evidence_sources = sum(
        1
        for field in (
            "repository_evidence",
            "cloud_scan_evidence",
            "iac_evidence",
            "environment_context_summary",
        )
        if getattr(threat_model, field, None)
    )
    coverage = SecurityReviewCoverageSummary(
        total_findings=len(finding_summaries),
        threat_findings=len(threat_context_entries),
        systemic_findings=len(systemic_context_entries),
        open_threats=sum(
            1 for threat in threats if threat.status in {"Open", "In Progress"}
        ),
        public_entry_points=sum(1 for node in nodes if _is_node_public(node)),
        privileged_surfaces=sum(
            1
            for node in nodes
            if node.node_type == "iam_role"
            or (
                (_as_string(_node_property(node, "privilege_level")) or "").casefold()
                in _PRIVILEGE_LEVELS
            )
        ),
        restricted_assets=sum(1 for node in nodes if _is_node_sensitive(node)),
        attack_paths=len(attack_paths),
        attached_evidence_sources=attached_evidence_sources,
        missing_evidence_sources=max(
            expected_evidence_sources - attached_evidence_sources, 0
        ),
    )

    top_findings = sorted_findings[:6]
    blind_spots = [summary for summary in sorted_findings if summary.systemic][:4]
    overall = top_findings[0] if top_findings else None

    if overall is None:
        focus_statement = "No immediate blockers are currently inferred for this application. Keep the model and evidence current so the next review stays grounded in reality."
        rationale = [
            "The current application review did not find a deterministic blocker across threats, evidence, or control posture.",
            "Keep architecture and evidence aligned so the review queue stays about real work instead of model noise.",
        ]
        next_steps = [
            "Keep repository, cloud, and IaC evidence attached so the next review run stays grounded in the actual system.",
            "Re-run the application review after meaningful architecture, deployment, or control changes.",
        ]
        overall_priority: PriorityBand = "p4_monitor"
        overall_action_bucket = "monitor"
    else:
        focus_statement = (
            f"This application is currently led by {overall.priority.replace('_', ' ')} work: {overall.title}."
            if not blind_spots
            else f"This application has immediate work in both active findings and systemic blind spots, led by {overall.title}."
        )
        rationale = [
            f"{sum(item.count for item in priority_counts[:2])} findings are in the interruption queue across the current application review.",
            (
                f"{len(blind_spots)} systemic blind spots are still weakening review confidence."
                if blind_spots
                else "The review confidence is being driven mostly by concrete findings rather than missing evidence."
            ),
            (
                f"{len(attack_paths)} multi-step attack path(s) connect exposed entry points to sensitive assets."
                if attack_paths
                else "No multi-step attack paths were synthesized across the current finding set."
            ),
        ]
        next_steps = []
        for summary in [*top_findings, *blind_spots]:
            if summary.next_step and summary.next_step not in next_steps:
                next_steps.append(summary.next_step)
            if len(next_steps) == 5:
                break
        overall_priority = overall.priority
        overall_action_bucket = overall.action_bucket

    return SecurityReviewApplicationSummary(
        generated_at=datetime.now(UTC).isoformat(),
        system_name=threat_model.system_name,
        overall_priority=overall_priority,
        overall_action_bucket=overall_action_bucket,
        focus_statement=focus_statement,
        rationale=rationale,
        next_steps=next_steps,
        coverage=coverage,
        priority_counts=priority_counts,
        action_bucket_counts=action_bucket_counts,
        truth_status_counts=truth_status_counts,
        noise_counts=noise_counts,
        top_findings=top_findings,
        blind_spots=blind_spots,
        attack_paths=attack_paths[:4],
        risk_acceptance_summary=risk_acceptance_summary,
        review_delta_summary=review_delta_summary,
    )


def _queue_bucket_from_action_bucket(action_bucket: str | None) -> QueueBucket:
    if action_bucket in {"bright_red_line", "engineer_now"}:
        return "fix_now"
    if action_bucket == "verify_control":
        return "verify"
    if action_bucket == "fill_evidence_gap":
        return "gather_evidence"
    return "backlog"


def _repository_only_code_signal(context: SecurityReviewContext) -> bool:
    return (
        context.scan_status is None
        and "repository" in context.finding_sources
        and any(link.risk_signal_ids for link in context.code_links)
    )


def _queue_bucket_from_priority(priority: str | None) -> QueueBucket:
    if priority in {"p0_blocker", "p1_now"}:
        return "fix_now"
    if priority == "p2_sprint":
        return "verify"
    return "backlog"


def _queue_bucket_from_severity(severity: str | None) -> QueueBucket:
    if severity in {"Critical", "High"}:
        return "fix_now"
    if severity == "Medium":
        return "verify"
    return "backlog"


def _confidence_from_truth_status(truth_status: str | None) -> ReviewConfidence:
    if truth_status in {"validated", "strongly_indicated"}:
        return "high"
    if truth_status == "contextual":
        return "medium"
    return "low"


def _primary_mode_for_display_kind(
    display_kind: ReviewDisplayKind,
) -> ReviewPrimaryMode:
    if display_kind in {"compliance_gap", "control_gap", "evidence_gap"}:
        return "compliance"
    if display_kind in {
        "threat",
        "hardening",
        "misconfiguration",
        "pr_risk",
        "incident_signal",
    }:
        return "findings"
    return "review"


def _source_provenance_for_systemic(
    finding_kind: str,
) -> str:
    if finding_kind in {"compliance_gap", "control_gap"}:
        return "framework_seed"
    return "app_review_projection"


def _string_timestamp(value: object | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        normalized = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return normalized.isoformat()
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)


def _build_bucket_count_list(
    labels: Mapping[str, str],
    order: Sequence[str],
    values: Sequence[str],
) -> list[SecurityReviewBucketCount]:
    counts = Counter(values)
    return [
        SecurityReviewBucketCount(key=key, label=labels[key], count=counts.get(key, 0))
        for key in order
    ]


def _normalized_threat_review_status(
    threat: Threat,
    *,
    scan_status: str | None,
    computed_queue_bucket: QueueBucket,
) -> tuple[str, QueueBucket | None, QueueBucket | None]:
    status = (threat.status or "Open").strip()
    if status == "Accepted":
        return "accepted", None, computed_queue_bucket
    if status == "Dismissed":
        return "dismissed", None, computed_queue_bucket
    if status == "Mitigated":
        if scan_status == "mitigated":
            return "mitigated", None, computed_queue_bucket
        return "open", "verify", computed_queue_bucket
    if status == "In Progress":
        return "in_progress", computed_queue_bucket, None
    return "open", computed_queue_bucket, None


def _merge_persisted_review_state(
    base: SecurityReviewFinding,
    persisted: SecurityReviewStateRecord | None,
    *,
    allow_review_status_override: bool,
) -> SecurityReviewFinding:
    review_status = base.review_status
    if (
        allow_review_status_override
        and persisted is not None
        and persisted.review_status is not None
    ):
        review_status = persisted.review_status

    queue_bucket = (
        None
        if review_status in {"accepted", "mitigated", "dismissed"}
        else base.queue_bucket
    )
    if (
        queue_bucket is not None
        and persisted is not None
        and persisted.queue_bucket is not None
    ):
        queue_bucket = persisted.queue_bucket

    last_non_terminal_bucket = (
        persisted.last_non_terminal_bucket
        if persisted is not None and persisted.last_non_terminal_bucket is not None
        else base.last_non_terminal_bucket
    )
    computed_recommendation_changed = bool(
        persisted is not None
        and persisted.queue_bucket is not None
        and base.computed_queue_bucket is not None
        and persisted.queue_bucket != base.computed_queue_bucket
        and review_status in {"open", "in_progress"}
    )
    risk_acceptance = (
        persisted.risk_acceptance
        if persisted is not None and persisted.risk_acceptance is not None
        else base.risk_acceptance
    )
    if risk_acceptance is not None and risk_acceptance.status == "active":
        expires_at = _parse_optional_iso_datetime(risk_acceptance.expires_at)
        if expires_at is not None and expires_at <= datetime.now(UTC):
            risk_acceptance = risk_acceptance.model_copy(
                update={
                    "status": "expired",
                    "reopen_triggers": sorted(
                        {
                            *risk_acceptance.reopen_triggers,
                            "risk acceptance expired",
                        }
                    ),
                }
            )

    return base.model_copy(
        update={
            "queue_bucket": queue_bucket,
            "review_status": review_status,
            "last_non_terminal_bucket": last_non_terminal_bucket,
            "owner": persisted.owner
            if persisted is not None and persisted.owner is not None
            else base.owner,
            "due_at": persisted.due_at
            if persisted is not None and persisted.due_at is not None
            else base.due_at,
            "note": persisted.note
            if persisted is not None and persisted.note is not None
            else base.note,
            "artifacts": persisted.artifacts
            if persisted is not None
            else base.artifacts,
            "risk_acceptance": risk_acceptance,
            "computed_recommendation_changed": computed_recommendation_changed,
        }
    )


def _review_finding_sort_key(
    finding: SecurityReviewFinding,
) -> tuple[int, int, int, int, int, int, int, str]:
    queue_rank = (
        _QUEUE_BUCKET_ORDER.index(finding.queue_bucket)
        if finding.queue_bucket
        else len(_QUEUE_BUCKET_ORDER)
    )
    return (
        queue_rank,
        _PRIORITY_RANK[finding.priority],
        0 if finding.is_real else 1,
        0 if finding.is_urgent else 1,
        0 if finding.needs_evidence else 1,
        -finding.numeric_score,
        _COUNT_ORDER["noise_disposition"].index(finding.noise_disposition),
        finding.title.casefold(),
    )


def build_security_review_findings(
    threat_model: ThreatModel,
    threats: Sequence[Threat],
    nodes: Sequence[DFDNode],
    edges: Sequence[DFDEdge],
    boundaries: Sequence[TrustBoundary],
    *,
    review_state: Sequence[SecurityReviewStateRecord] | None = None,
    intel_by_threat_id: Mapping[str, ThreatIntelResponse] | None = None,
    scan_status_by_threat_id: Mapping[str, str] | None = None,
) -> SecurityReviewFindingListResponse:
    nodes_by_id = {str(node.id): node for node in nodes}
    edges_by_id = {str(edge.id): edge for edge in edges}
    review_state_map = {
        (item.source_object_type, item.source_object_id): item
        for item in (review_state or [])
    }

    threat_context_entries = [
        (
            build_security_review_context(
                threat_model,
                threat,
                nodes,
                edges,
                intel=(intel_by_threat_id or {}).get(str(threat.id)),
                scan_status=(scan_status_by_threat_id or {}).get(str(threat.id)),
            ),
            threat,
        )
        for threat in threats
    ]
    threat_decisions = evaluate_security_review_contexts(
        [context for context, _ in threat_context_entries]
    )

    findings: list[SecurityReviewFinding] = []
    for (context, threat), decision in zip(
        threat_context_entries, threat_decisions, strict=True
    ):
        repository_only_signal = _repository_only_code_signal(context)
        action_bucket = (
            "fill_evidence_gap" if repository_only_signal else decision.action_bucket
        )
        truth_status = "contextual" if repository_only_signal else decision.truth_status
        exploitability = "low" if repository_only_signal else decision.exploitability
        priority = "p3_backlog" if repository_only_signal else decision.priority
        numeric_score = (
            min(decision.numeric_score, 45)
            if repository_only_signal
            else decision.numeric_score
        )
        wire_kind = (
            "hardening"
            if action_bucket in {"planned_hardening", "monitor"}
            else "threat"
        )
        computed_queue_bucket = _queue_bucket_from_action_bucket(action_bucket)
        review_status, normalized_queue_bucket, last_non_terminal_bucket = (
            _normalized_threat_review_status(
                threat,
                scan_status=(scan_status_by_threat_id or {}).get(str(threat.id)),
                computed_queue_bucket=computed_queue_bucket,
            )
        )
        why_now = (
            "Repository parser evidence is contextual; validate the affected path before treating this as confirmed."
            if repository_only_signal
            else decision.rationale[0]
            if decision.rationale
            else context.description or context.title
        )
        base = SecurityReviewFinding(
            id=f"threat:{threat.id}",
            source_object_type="threat",
            source_object_id=str(threat.id),
            threat_id=str(threat.id),
            display_id=threat.display_id,
            wire_kind=wire_kind,
            display_kind=wire_kind,
            source_provenance="manual" if threat.source == "Manual" else "rules_engine",
            title=context.title,
            priority=priority,
            numeric_score=numeric_score,
            wire_action_bucket=action_bucket,
            queue_bucket=normalized_queue_bucket,
            computed_queue_bucket=computed_queue_bucket,
            truth_status=truth_status,
            exploitability=exploitability,
            urgency=decision.urgency,
            business_impact=decision.business_impact,
            regulatory_pressure=decision.regulatory_pressure,
            confidence=_confidence_from_truth_status(truth_status),
            is_real=truth_status in {"validated", "strongly_indicated"},
            is_urgent=decision.urgency in {"immediate", "current_cycle"},
            is_exploitable_in_context=exploitability in {"proven", "high"},
            is_regulatory_or_control_relevant=(
                decision.regulatory_pressure != "low"
                or context.finding_kind
                in {"compliance_gap", "control_gap", "evidence_gap"}
            ),
            needs_engineering_change=action_bucket
            in {"bright_red_line", "engineer_now", "planned_hardening"},
            needs_evidence=action_bucket in {"verify_control", "fill_evidence_gap"},
            why_now=why_now,
            impacted_assets=[item for item in [context.target_asset] if item],
            entry_point=context.entry_point,
            evidence_refs=[str(source) for source in context.finding_sources],
            linked_threat_ids=[str(threat.id)],
            code_links=context.code_links,
            evidence_anchors=_build_context_evidence_anchors(
                context,
                nodes_by_id,
                edges_by_id,
            ),
            owner=getattr(threat, "mitigation_owner", None),
            due_at=_string_timestamp(getattr(threat, "due_date", None)),
            note=getattr(threat, "mitigation_notes", None),
            risk_acceptance=decision.risk_acceptance,
            review_status=review_status,  # type: ignore[arg-type]
            last_non_terminal_bucket=last_non_terminal_bucket,
            primary_mode="findings",
            noise_disposition=decision.noise_disposition,
            systemic=False,
            next_best_action=decision.next_steps[0] if decision.next_steps else None,
            next_step=decision.next_steps[0] if decision.next_steps else None,
            rationale_excerpt=decision.rationale[0] if decision.rationale else None,
        )
        persisted = review_state_map.get(("threat", str(threat.id)))
        findings.append(
            _merge_persisted_review_state(
                base,
                persisted,
                allow_review_status_override=False,
            )
        )

    systemic_contexts = _build_systemic_review_contexts(
        threat_model,
        [threat for threat in threats if threat.status != "Dismissed"],
        nodes,
        edges,
        boundaries,
    )
    systemic_decisions = (
        evaluate_security_review_contexts(systemic_contexts)
        if systemic_contexts
        else []
    )
    for context, decision in zip(systemic_contexts, systemic_decisions, strict=True):
        computed_queue_bucket = (
            "gather_evidence"
            if context.finding_kind == "evidence_gap"
            else _queue_bucket_from_action_bucket(decision.action_bucket)
        )
        display_kind: ReviewDisplayKind = (
            "evidence_gap"
            if context.finding_kind == "evidence_gap"
            else "compliance_gap"
            if context.finding_kind == "compliance_gap"
            else "control_gap"
            if context.finding_kind == "control_gap"
            else "hardening"
        )
        finding_id = context.finding_key or context.title.casefold().replace(" ", "-")
        base = SecurityReviewFinding(
            id=f"application_review_finding:{finding_id}",
            source_object_type="application_review_finding",
            source_object_id=finding_id,
            wire_kind=context.finding_kind,  # type: ignore[arg-type]
            display_kind=display_kind,
            source_provenance=_source_provenance_for_systemic(context.finding_kind),  # type: ignore[arg-type]
            title=context.title,
            priority=decision.priority,
            numeric_score=decision.numeric_score,
            wire_action_bucket=decision.action_bucket,
            queue_bucket=computed_queue_bucket,
            computed_queue_bucket=computed_queue_bucket,
            truth_status=decision.truth_status,
            exploitability=decision.exploitability,
            urgency=decision.urgency,
            business_impact=decision.business_impact,
            regulatory_pressure=decision.regulatory_pressure,
            confidence=_confidence_from_truth_status(decision.truth_status),
            is_real=decision.truth_status in {"validated", "strongly_indicated"},
            is_urgent=decision.urgency in {"immediate", "current_cycle"},
            is_exploitable_in_context=decision.exploitability in {"proven", "high"},
            is_regulatory_or_control_relevant=(
                decision.regulatory_pressure != "low"
                or context.finding_kind
                in {"compliance_gap", "control_gap", "evidence_gap"}
            ),
            needs_engineering_change=decision.action_bucket
            in {"bright_red_line", "engineer_now", "planned_hardening"},
            needs_evidence=decision.action_bucket
            in {"verify_control", "fill_evidence_gap"},
            why_now=decision.rationale[0]
            if decision.rationale
            else context.description or context.title,
            impacted_assets=[item for item in [context.target_asset] if item],
            entry_point=context.entry_point,
            evidence_refs=[str(source) for source in context.finding_sources],
            code_links=context.code_links,
            evidence_anchors=_build_context_evidence_anchors(
                context,
                nodes_by_id,
                edges_by_id,
            ),
            review_status="open",
            last_non_terminal_bucket=None,
            primary_mode=_primary_mode_for_display_kind(display_kind),
            noise_disposition=decision.noise_disposition,
            systemic=True,
            next_best_action=decision.next_steps[0] if decision.next_steps else None,
            next_step=decision.next_steps[0] if decision.next_steps else None,
            rationale_excerpt=decision.rationale[0] if decision.rationale else None,
        )
        persisted = review_state_map.get(("application_review_finding", finding_id))
        findings.append(
            _merge_persisted_review_state(
                base,
                persisted,
                allow_review_status_override=True,
            )
        )

    sorted_findings = sorted(findings, key=_review_finding_sort_key)
    queue_counts = _build_bucket_count_list(
        _QUEUE_BUCKET_LABELS,
        _QUEUE_BUCKET_ORDER,
        [
            finding.queue_bucket
            for finding in sorted_findings
            if finding.queue_bucket is not None
        ],
    )
    review_status_counts = _build_bucket_count_list(
        _REVIEW_STATUS_LABELS,
        _REVIEW_STATUS_ORDER,
        [finding.review_status for finding in sorted_findings],
    )
    default_finding = next(
        (
            finding.id
            for finding in sorted_findings
            if finding.review_status in {"open", "in_progress"}
            and finding.noise_disposition in {"focus", "queue"}
        ),
        sorted_findings[0].id if sorted_findings else None,
    )
    return SecurityReviewFindingListResponse(
        generated_at=datetime.now(UTC).isoformat(),
        system_name=threat_model.system_name,
        queue_counts=queue_counts,
        review_status_counts=review_status_counts,
        default_finding_id=default_finding,
        findings=sorted_findings,
    )
