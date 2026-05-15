from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.scan import ScanJob, ScanThreatResult
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, DFDResponse, TrustBoundaryResponse
from app.schemas.threat_model import (
    ArchitectureValidationSummary,
    ThreatModelAssumptionResponse,
    ThreatModelControlResponse,
    ThreatModelCoverageSummary,
    ThreatModelElementCoverageSummary,
    ThreatModelReviewFreshnessSummary,
    ThreatModelReviewResponse,
    ThreatModelVersionDiffResponse,
    ThreatModelVersionResponse,
)

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_token(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def normalize_model_snapshots(raw_snapshots: list[dict] | None) -> list[ThreatModelVersionResponse]:
    normalized: list[ThreatModelVersionResponse] = []
    for item in raw_snapshots or []:
        try:
            normalized.append(ThreatModelVersionResponse.model_validate(item))
        except Exception:
            continue
    return sorted(normalized, key=lambda item: item.created_at, reverse=True)


def normalize_review_records(raw_reviews: list[dict] | None) -> list[ThreatModelReviewResponse]:
    normalized: list[ThreatModelReviewResponse] = []
    for item in raw_reviews or []:
        try:
            normalized.append(ThreatModelReviewResponse.model_validate(item))
        except Exception:
            continue
    return sorted(normalized, key=lambda item: item.updated_at, reverse=True)


def normalize_control_library(raw_controls: list[dict] | None) -> list[ThreatModelControlResponse]:
    normalized: list[ThreatModelControlResponse] = []
    for item in raw_controls or []:
        try:
            normalized.append(ThreatModelControlResponse.model_validate(item))
        except Exception:
            continue
    return sorted(normalized, key=lambda item: item.updated_at, reverse=True)


async def load_current_dfd(db: AsyncSession, threat_model_id: UUID) -> DFDResponse:
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    return DFDResponse(
        nodes=[DFDNodeResponse.model_validate(node) for node in nodes_result.scalars().all()],
        edges=[DFDEdgeResponse.model_validate(edge) for edge in edges_result.scalars().all()],
        trust_boundaries=[
            TrustBoundaryResponse.model_validate(boundary)
            for boundary in boundaries_result.scalars().all()
        ],
    )


async def load_current_threat_snapshot(db: AsyncSession, threat_model_id: UUID) -> list[dict[str, Any]]:
    result = await db.execute(
        select(Threat)
        .where(Threat.threat_model_id == threat_model_id)
        .order_by(Threat.display_id.asc())
    )
    threats = result.scalars().all()
    return [
        {
            "id": str(threat.id),
            "display_id": threat.display_id,
            "description": threat.description,
            "severity": threat.severity,
            "stride_category": threat.stride_category,
            "status": threat.status,
            "mitigation_plan": threat.mitigation_plan,
            "mitigation_owner": threat.mitigation_owner,
            "due_date": threat.due_date.isoformat() if threat.due_date is not None else None,
            "mitigation_notes": threat.mitigation_notes,
            "control_effectiveness": getattr(threat, "control_effectiveness", "none"),
            "residual_risk_level": getattr(threat, "residual_risk_level", None),
            "affected_node_ids": [str(node_id) for node_id in getattr(threat, "affected_node_ids", [])],
            "affected_edge_ids": [str(edge_id) for edge_id in getattr(threat, "affected_edge_ids", [])],
        }
        for threat in threats
    ]


def _build_snapshot_payload(
    *,
    dfd: DFDResponse,
    threats: list[dict[str, Any]],
    name: str,
    description: str,
    created_by: str,
    snapshot_id: UUID | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "id": str(snapshot_id or uuid4()),
        "name": name,
        "description": description,
        "created_at": (created_at or _now()).isoformat(),
        "created_by": created_by,
        "node_count": len(dfd.nodes),
        "edge_count": len(dfd.edges),
        "boundary_count": len(dfd.trust_boundaries),
        "threat_count": len(threats),
        "dfd": dfd.model_dump(mode="json"),
        "threats": threats,
    }


def build_current_snapshot_payload(
    dfd: DFDResponse,
    threats: list[dict[str, Any]],
) -> dict[str, Any]:
    return _build_snapshot_payload(
        dfd=dfd,
        threats=threats,
        name="Current Model",
        description="Unsaved current state",
        created_by="Current session",
    )


async def build_snapshot_record(
    db: AsyncSession,
    threat_model: ThreatModel,
    *,
    name: str,
    description: str,
    created_by: str,
) -> dict[str, Any]:
    dfd = await load_current_dfd(db, threat_model.id)
    threats = await load_current_threat_snapshot(db, threat_model.id)
    return _build_snapshot_payload(
        dfd=dfd,
        threats=threats,
        name=name,
        description=description,
        created_by=created_by,
        snapshot_id=uuid4(),
        created_at=_now(),
    )


async def build_current_snapshot_record(
    db: AsyncSession,
    threat_model: ThreatModel,
) -> dict[str, Any]:
    dfd = await load_current_dfd(db, threat_model.id)
    threats = await load_current_threat_snapshot(db, threat_model.id)
    return build_current_snapshot_payload(dfd, threats)


def _find_snapshot(raw_snapshots: list[dict] | None, snapshot_id: UUID) -> dict[str, Any] | None:
    snapshot_id_str = str(snapshot_id)
    for item in raw_snapshots or []:
        if str(item.get("id")) == snapshot_id_str:
            return item
    return None


def build_snapshot_diff(
    left_snapshot: dict[str, Any],
    right_snapshot: dict[str, Any],
) -> ThreatModelVersionDiffResponse:
    left_nodes = {
        (node.get("name") or "").strip()
        for node in left_snapshot.get("dfd", {}).get("nodes", [])
        if (node.get("name") or "").strip()
    }
    right_nodes = {
        (node.get("name") or "").strip()
        for node in right_snapshot.get("dfd", {}).get("nodes", [])
        if (node.get("name") or "").strip()
    }
    left_threats = {
        (threat.get("display_id") or threat.get("description") or "").strip()
        for threat in left_snapshot.get("threats", [])
        if (threat.get("display_id") or threat.get("description") or "").strip()
    }
    right_threats = {
        (threat.get("display_id") or threat.get("description") or "").strip()
        for threat in right_snapshot.get("threats", [])
        if (threat.get("display_id") or threat.get("description") or "").strip()
    }

    return ThreatModelVersionDiffResponse(
        left_label=left_snapshot.get("name", "Snapshot"),
        right_label=right_snapshot.get("name", "Current Model"),
        node_delta=int(right_snapshot.get("node_count", 0)) - int(left_snapshot.get("node_count", 0)),
        edge_delta=int(right_snapshot.get("edge_count", 0)) - int(left_snapshot.get("edge_count", 0)),
        boundary_delta=int(right_snapshot.get("boundary_count", 0)) - int(left_snapshot.get("boundary_count", 0)),
        threat_delta=int(right_snapshot.get("threat_count", 0)) - int(left_snapshot.get("threat_count", 0)),
        added_nodes=sorted(right_nodes - left_nodes)[:10],
        removed_nodes=sorted(left_nodes - right_nodes)[:10],
        added_threats=sorted(right_threats - left_threats)[:10],
        removed_threats=sorted(left_threats - right_threats)[:10],
    )


def _diff_has_changes(diff: ThreatModelVersionDiffResponse) -> bool:
    return any(
        (
            diff.node_delta,
            diff.edge_delta,
            diff.boundary_delta,
            diff.threat_delta,
            diff.added_nodes,
            diff.removed_nodes,
            diff.added_threats,
            diff.removed_threats,
        )
    )


def _coerce_uuid(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _build_edge_label(
    edge: DFDEdgeResponse,
    node_names: dict[str, str],
) -> str:
    if edge.label.strip():
        return edge.label.strip()
    source = node_names.get(str(edge.source_node_id), "Unknown")
    target = node_names.get(str(edge.target_node_id), "Unknown")
    return f"{source} -> {target}"


def _build_element_coverage_summary(
    *,
    labels: dict[str, str],
    threat_map: dict[str, bool],
    assumption_map: dict[str, bool],
    stride_map: dict[str, set[str]],
) -> ThreatModelElementCoverageSummary:
    total = len(labels)
    with_threats = sum(1 for element_id in labels if threat_map.get(element_id, False))
    with_assumptions = sum(1 for element_id in labels if assumption_map.get(element_id, False))
    with_stride_coverage = sum(1 for element_id in labels if stride_map.get(element_id))
    fully_stride_covered = sum(
        1 for element_id in labels if len(stride_map.get(element_id, set())) == len(STRIDE_CATEGORIES)
    )
    uncovered_labels = [
        label
        for element_id, label in labels.items()
        if not stride_map.get(element_id)
    ][:5]
    average_stride_categories = (
        round(sum(len(stride_map.get(element_id, set())) for element_id in labels) / total, 1)
        if total
        else 0.0
    )
    return ThreatModelElementCoverageSummary(
        total=total,
        with_threats=with_threats,
        with_assumptions=with_assumptions,
        with_stride_coverage=with_stride_coverage,
        without_stride_coverage=max(total - with_stride_coverage, 0),
        fully_stride_covered=fully_stride_covered,
        average_stride_categories=average_stride_categories,
        uncovered_labels=uncovered_labels,
    )


def build_coverage_summary(
    dfd: DFDResponse,
    threats: list[dict[str, Any]],
    assumptions: list[ThreatModelAssumptionResponse],
) -> ThreatModelCoverageSummary:
    node_names = {str(node.id): node.name for node in dfd.nodes}
    node_labels = {
        str(node.id): (node.name or "").strip() or f"Node {str(node.id)[:8]}"
        for node in dfd.nodes
    }
    edge_labels = {
        str(edge.id): _build_edge_label(edge, node_names)
        for edge in dfd.edges
    }
    boundary_labels = {
        str(boundary.id): (boundary.name or "").strip() or f"Boundary {str(boundary.id)[:8]}"
        for boundary in dfd.trust_boundaries
    }

    node_stride = {element_id: set() for element_id in node_labels}
    edge_stride = {element_id: set() for element_id in edge_labels}
    boundary_stride = {element_id: set() for element_id in boundary_labels}
    node_threats = {element_id: False for element_id in node_labels}
    edge_threats = {element_id: False for element_id in edge_labels}
    boundary_threats = {element_id: False for element_id in boundary_labels}
    node_assumptions = {element_id: False for element_id in node_labels}
    edge_assumptions = {element_id: False for element_id in edge_labels}
    boundary_assumptions = {element_id: False for element_id in boundary_labels}

    node_to_boundaries: dict[str, set[str]] = {element_id: set() for element_id in node_labels}
    for node in dfd.nodes:
        if node.trust_boundary_id is not None:
            boundary_id = str(node.trust_boundary_id)
            if boundary_id in boundary_labels:
                node_to_boundaries[str(node.id)].add(boundary_id)
    for boundary in dfd.trust_boundaries:
        boundary_id = str(boundary.id)
        for node_id in boundary.node_ids:
            node_to_boundaries.setdefault(str(node_id), set()).add(boundary_id)

    for threat in threats:
        stride = str(threat.get("stride_category") or "").strip()
        if not stride:
            continue

        for raw_node_id in threat.get("affected_node_ids", []) or []:
            node_id = _coerce_uuid(raw_node_id)
            if node_id is None or node_id not in node_stride:
                continue
            node_threats[node_id] = True
            node_stride[node_id].add(stride)
            for boundary_id in node_to_boundaries.get(node_id, set()):
                if boundary_id in boundary_stride:
                    boundary_threats[boundary_id] = True
                    boundary_stride[boundary_id].add(stride)

        for raw_edge_id in threat.get("affected_edge_ids", []) or []:
            edge_id = _coerce_uuid(raw_edge_id)
            if edge_id is None or edge_id not in edge_stride:
                continue
            edge = next((item for item in dfd.edges if str(item.id) == edge_id), None)
            edge_threats[edge_id] = True
            edge_stride[edge_id].add(stride)
            if edge is None:
                continue
            for endpoint in (edge.source_node_id, edge.target_node_id):
                for boundary_id in node_to_boundaries.get(str(endpoint), set()):
                    if boundary_id in boundary_stride:
                        boundary_threats[boundary_id] = True
                        boundary_stride[boundary_id].add(stride)

    for assumption in assumptions:
        anchor_id = str(assumption.anchor_id)
        if assumption.anchor_kind == "node" and anchor_id in node_assumptions:
            node_assumptions[anchor_id] = True
        elif assumption.anchor_kind == "edge" and anchor_id in edge_assumptions:
            edge_assumptions[anchor_id] = True
        elif assumption.anchor_kind == "boundary" and anchor_id in boundary_assumptions:
            boundary_assumptions[anchor_id] = True

    nodes_summary = _build_element_coverage_summary(
        labels=node_labels,
        threat_map=node_threats,
        assumption_map=node_assumptions,
        stride_map=node_stride,
    )
    edges_summary = _build_element_coverage_summary(
        labels=edge_labels,
        threat_map=edge_threats,
        assumption_map=edge_assumptions,
        stride_map=edge_stride,
    )
    boundaries_summary = _build_element_coverage_summary(
        labels=boundary_labels,
        threat_map=boundary_threats,
        assumption_map=boundary_assumptions,
        stride_map=boundary_stride,
    )

    seen_categories = [
        category
        for category in STRIDE_CATEGORIES
        if any((threat.get("stride_category") or "").strip() == category for threat in threats)
    ]
    total_elements = nodes_summary.total + edges_summary.total + boundaries_summary.total
    covered_elements = (
        nodes_summary.with_stride_coverage
        + edges_summary.with_stride_coverage
        + boundaries_summary.with_stride_coverage
    )
    coverage_score = round((covered_elements / total_elements) * 100) if total_elements else 0

    return ThreatModelCoverageSummary(
        coverage_score=coverage_score,
        total_elements=total_elements,
        covered_elements=covered_elements,
        stride_categories_seen=seen_categories,
        missing_stride_categories=[
            category for category in STRIDE_CATEGORIES if category not in seen_categories
        ],
        nodes=nodes_summary,
        edges=edges_summary,
        boundaries=boundaries_summary,
    )


def build_review_freshness_summary(
    *,
    threat_model: ThreatModel,
    reviews: list[ThreatModelReviewResponse],
    current_snapshot: dict[str, Any],
) -> ThreatModelReviewFreshnessSummary:
    latest_review = reviews[0] if reviews else None
    latest_approved = next((review for review in reviews if review.status == "approved"), None)

    if latest_approved is not None:
        approved_snapshot = _find_snapshot(getattr(threat_model, "model_snapshots", None), latest_approved.snapshot_id)
        reviewed_at = latest_approved.signed_off_at or latest_approved.updated_at
        if approved_snapshot is None:
            return ThreatModelReviewFreshnessSummary(
                status="stale",
                summary="The last approved review references a snapshot that is no longer available, so the current model needs review again.",
                reviewed_snapshot_id=latest_approved.snapshot_id,
                reviewed_snapshot_name=None,
                latest_review_title=latest_review.title if latest_review is not None else latest_approved.title,
                latest_review_status=latest_review.status if latest_review is not None else latest_approved.status,
                reviewed_at=reviewed_at,
                changes_since_review=None,
            )
        diff = build_snapshot_diff(approved_snapshot, current_snapshot)
        if diff is not None and _diff_has_changes(diff):
            return ThreatModelReviewFreshnessSummary(
                status="stale",
                summary="The current model has drifted from the last approved snapshot and needs a fresh review.",
                reviewed_snapshot_id=latest_approved.snapshot_id,
                reviewed_snapshot_name=approved_snapshot.get("name"),
                latest_review_title=latest_review.title if latest_review is not None else latest_approved.title,
                latest_review_status=latest_review.status if latest_review is not None else latest_approved.status,
                reviewed_at=reviewed_at,
                changes_since_review=diff,
            )
        return ThreatModelReviewFreshnessSummary(
            status="current",
            summary="The current model still matches the most recently approved snapshot.",
            reviewed_snapshot_id=latest_approved.snapshot_id,
            reviewed_snapshot_name=approved_snapshot.get("name") if approved_snapshot is not None else None,
            latest_review_title=latest_review.title if latest_review is not None else latest_approved.title,
            latest_review_status=latest_review.status if latest_review is not None else latest_approved.status,
            reviewed_at=reviewed_at,
            changes_since_review=diff,
        )

    if latest_review is not None and latest_review.status == "changes_requested":
        return ThreatModelReviewFreshnessSummary(
            status="changes_requested",
            summary="The latest formal review requested changes, so this model is not yet signed off.",
            latest_review_title=latest_review.title,
            latest_review_status=latest_review.status,
            reviewed_at=latest_review.updated_at,
        )

    if latest_review is not None and latest_review.status == "pending":
        return ThreatModelReviewFreshnessSummary(
            status="pending",
            summary="A formal review is in progress, but there is no approved snapshot for the current model yet.",
            latest_review_title=latest_review.title,
            latest_review_status=latest_review.status,
            reviewed_at=latest_review.updated_at,
        )

    return ThreatModelReviewFreshnessSummary(
        status="unreviewed",
        summary="No approved review snapshot exists yet for this threat model.",
        latest_review_title=latest_review.title if latest_review is not None else None,
        latest_review_status=latest_review.status if latest_review is not None else None,
        reviewed_at=latest_review.updated_at if latest_review is not None else None,
    )


def model_has_drift_signals(threat_model: ThreatModel) -> bool:
    repository = getattr(threat_model, "repository_evidence", None) or {}
    cloud = getattr(threat_model, "cloud_scan_evidence", None) or {}
    return any(
        (
            repository.get("warnings"),
            repository.get("unprotected_routes"),
            repository.get("risky_routes"),
            cloud.get("warnings"),
            cloud.get("exposed_services"),
            cloud.get("identity_risks"),
            cloud.get("encryption_gaps"),
            cloud.get("logging_gaps"),
        )
    )


async def build_architecture_validation_summary(
    db: AsyncSession,
    threat_model: ThreatModel,
) -> ArchitectureValidationSummary:
    dfd = await load_current_dfd(db, threat_model.id)
    latest_scan_result = await db.execute(
        select(ScanJob)
        .where(ScanJob.threat_model_id == threat_model.id)
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )
    latest_scan = latest_scan_result.scalar_one_or_none()

    scan_results_count = 0
    if latest_scan is not None:
        mapped_result = await db.execute(
            select(ScanThreatResult).where(ScanThreatResult.scan_job_id == latest_scan.id)
        )
        scan_results_count = len(mapped_result.scalars().all())

    threats = await load_current_threat_snapshot(db, threat_model.id)

    modeled_names = {
        _normalize_token(node.name)
        for node in dfd.nodes
        if _normalize_token(node.name)
    }
    discovered_repository = [
        *(((getattr(threat_model, "repository_evidence", None) or {}).get("frameworks")) or []),
        *(((getattr(threat_model, "repository_evidence", None) or {}).get("data_stores")) or []),
        *(((getattr(threat_model, "repository_evidence", None) or {}).get("queues")) or []),
        *(((getattr(threat_model, "repository_evidence", None) or {}).get("external_integrations")) or []),
        *(((getattr(threat_model, "repository_evidence", None) or {}).get("infrastructure_resources")) or []),
        *(((getattr(threat_model, "repository_evidence", None) or {}).get("auth_surfaces")) or []),
    ]
    discovered_cloud = [
        *(((getattr(threat_model, "cloud_scan_evidence", None) or {}).get("exposed_services")) or []),
        *[
            finding.get("service", "")
            for finding in ((getattr(threat_model, "cloud_scan_evidence", None) or {}).get("high_signal_findings") or [])
            if finding.get("service")
        ],
    ]
    discovered_iac = [
        *(((getattr(threat_model, "iac_evidence", None) or {}).get("resource_types")) or []),
        *(((getattr(threat_model, "iac_evidence", None) or {}).get("resource_names")) or []),
        *(((getattr(threat_model, "iac_evidence", None) or {}).get("public_exposure")) or []),
        *(((getattr(threat_model, "iac_evidence", None) or {}).get("network_paths")) or []),
    ]

    unmapped_repository = [
        item for item in discovered_repository
        if _normalize_token(item) and _normalize_token(item) not in modeled_names
    ]
    unmapped_cloud = [
        item for item in discovered_cloud
        if _normalize_token(item) and _normalize_token(item) not in modeled_names
    ]
    unmapped_iac = [
        item for item in discovered_iac
        if _normalize_token(item) and _normalize_token(item) not in modeled_names
    ]

    nodes_without_scan_targets = [
        node.name
        for node in dfd.nodes
        if node.node_type in {"process", "api_gateway", "serverless", "container", "managed_service"}
        and not node.scan_target_url
    ]

    threat_scan_statuses: dict[str, str] = {}
    if latest_scan is not None:
        threat_results_result = await db.execute(
            select(ScanThreatResult).where(ScanThreatResult.scan_job_id == latest_scan.id)
        )
        threat_scan_statuses = {
            str(item.threat_id): item.scan_status
            for item in threat_results_result.scalars().all()
        }

    unvalidated_threats = [
        threat["display_id"]
        for threat in threats
        if threat.get("status") in {"Open", "In Progress"}
        and threat_scan_statuses.get(str(threat["id"])) not in {"confirmed", "mitigated"}
    ]

    repository = getattr(threat_model, "repository_evidence", None) or {}
    cloud = getattr(threat_model, "cloud_scan_evidence", None) or {}
    iac = getattr(threat_model, "iac_evidence", None) or {}
    drift_flags = [
        *[f"Repository: {warning}" for warning in (repository.get("warnings") or [])[:4]],
        *[f"Cloud exposure: {item}" for item in (cloud.get("exposed_services") or [])[:4]],
        *[f"IAM: {item}" for item in (cloud.get("identity_risks") or [])[:4]],
        *[f"Encryption: {item}" for item in (cloud.get("encryption_gaps") or [])[:4]],
        *[f"Logging: {item}" for item in (cloud.get("logging_gaps") or [])[:4]],
        *[f"IaC exposure: {item}" for item in (iac.get("public_exposure") or [])[:4]],
        *[f"IaC IAM: {item}" for item in (iac.get("iam_bindings") or [])[:4]],
    ]

    deductions = (
        min(25, len(unmapped_repository) * 5)
        + min(20, len(unmapped_cloud) * 5)
        + min(20, len(unmapped_iac) * 5)
        + min(20, len(nodes_without_scan_targets) * 4)
        + min(20, len(unvalidated_threats) * 3)
        + min(15, len(drift_flags) * 3)
    )
    completeness_score = max(0, 100 - deductions)

    return ArchitectureValidationSummary(
        completeness_score=completeness_score,
        discovered_components=len(discovered_repository) + len(discovered_cloud) + len(discovered_iac),
        discovered_repository_components=len(discovered_repository),
        discovered_cloud_services=len(discovered_cloud),
        modeled_components=len(dfd.nodes),
        mapped_discovered_components=(
            len(discovered_repository)
            + len(discovered_cloud)
            + len(discovered_iac)
            - len(unmapped_repository)
            - len(unmapped_cloud)
            - len(unmapped_iac)
        ),
        latest_scan_status=latest_scan.status if latest_scan is not None else None,
        latest_scan_finding_count=latest_scan.finding_count if latest_scan is not None else 0,
        correlated_scan_results=scan_results_count,
        unmapped_repository_components=[*unmapped_repository[:5], *unmapped_iac[:5]],
        unmapped_cloud_services=unmapped_cloud[:10],
        nodes_without_scan_targets=nodes_without_scan_targets[:10],
        unvalidated_threats=unvalidated_threats[:10],
        drift_flags=drift_flags[:10],
    )
