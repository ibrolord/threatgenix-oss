"""Threats generate, list, and analyze endpoints (Block B19 + B13 + B23)."""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import delete, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.config import settings
from app.database import async_session, get_db
from app.services.entitlement import check_org_entitlement
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.document import Document
from app.models.scan import ScanJob, ScanThreatResult
from app.models.threat import Threat, ThreatCluster
from app.models.threat_model import ThreatModel
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.security_review import (
    AgentCiFailPolicy,
    AgentRemediationConnectorTicketCreateRequest,
    AgentRemediationConnectorTicketCreateResponse,
    AgentRemediationEvidenceWebhookRequest,
    AgentRemediationEvidenceWebhookResponse,
    AgentRemediationProviderWebhookTestRequest,
    AgentRemediationProviderWebhookTestResponse,
    AgentRemediationAction,
    AgentRemediationPlanApplyRequest,
    AgentRemediationPlanApplyResponse,
    AgentRemediationPlanResponse,
    AgentRemediationTicketCreateRequest,
    AgentRemediationTicketCreateResponse,
    AgentSecurityReviewResponse,
    CustomerSecurityPacketResponse,
    SecurityReviewArtifact,
    SecurityReviewArtifactCreate,
    SecurityReviewApplicationSummary,
    SecurityReviewDecision,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
    SecurityReviewRiskAcceptance,
    SecurityReviewRiskAcceptanceRequest,
    SecurityReviewStateUpdate,
)
from app.schemas.rules import RuleEngineOutput
from app.models.audit import ThreatAuditLog
from app.schemas.threat import (
    ThreatClusterResponse,
    QualificationProgressResponse,
    AnalyzeResponse,
    BulkTriageRequest,
    ResidualRiskSummary,
    ThreatAuditEntry,
    ThreatIntelResponse,
    ThreatDiffResponse,
    ThreatResponse,
    ThreatSummary,
    ThreatTriageRequest,
    ThreatQualifyRequest,
)
from app.services.threat_scorer import compute_qualification_score, blend_scores
from app.services.threat_clustering import compute_clusters
from app.services.threat_diff import diff_threat_lists
from app.models.user import User
from app.services.ai_enhancement import enhance_threats
from app.services.ai_threat_merger import build_node_name_map, merge_ai_threats
from app.services.auth import get_current_user
from app.services.compliance_service import lookup_controls_batch
from app.services.llm_client import get_llm_client_for_user_async
from app.services.model_collaboration import require_model_permission
from app.services.residual_risk import (
    build_residual_risk_summary,
    derive_residual_risk_level,
    normalize_control_effectiveness,
)
from app.services.remediation_connectors import (
    RemediationConnectorError,
    attach_remediation_webhook_setups,
    create_remediation_provider_ticket,
    remediation_evidence_callback_payload,
    remediation_evidence_callback_url,
)
from app.services.remediation_webhooks import (
    RemediationWebhookSignatureError,
    normalize_remediation_webhook_event,
    remediation_webhook_required_headers_template,
    remediation_webhook_signature_base_string,
    verify_remediation_webhook_signature_durable,
)
from app.services.remediation_provider_webhooks import (
    RemediationProviderWebhookError,
    parse_remediation_provider_webhook,
)
from app.services.agent_security_review import (
    build_customer_packet_csv,
    build_customer_packet_pdf,
    build_agent_remediation_plan_response,
    build_agent_security_review_response,
    build_customer_packet_source_fingerprints,
    build_customer_security_packet_response,
    customer_packet_sensitive_source_labels,
)
from app.services.rules.engine import evaluate_rules
from app.services.security_review_adapter import (
    build_application_security_review,
    build_security_review_findings,
    evaluate_threat_security_reviews,
)
from app.services.security_review_artifacts import (
    build_security_review_artifact,
    replace_artifact_of_kind,
)
from app.services.security_review_state import (
    find_review_state_record,
    normalize_review_state_records,
    upsert_review_state_record,
)
from app.services.threat_intel.threat_details import build_threat_intel_response
from app.services.threat_model import get_threat_model

logger = logging.getLogger(__name__)

_ANALYZE_COOLDOWN_SECONDS = 60
RESIDUAL_SUMMARY_STATUSES = ("Open", "In Progress", "Mitigated", "Accepted")
SECURITY_REVIEW_INTEL_THREAT_LIMIT = 12
_SEVERITY_SORT_RANK = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}
_SCAN_STATUS_SORT_RANK = {
    "confirmed": 0,
    "mitigated": 1,
    "not_found": 2,
    "unverifiable": 3,
}


def _append_reason(existing: str | None, extra: str | None) -> str | None:
    if not extra:
        return existing
    if not existing:
        return extra
    if extra in existing:
        return existing
    return f"{existing} {extra}"


def _display_id_sort_key(display_id: str) -> tuple[int, int | str]:
    try:
        return (0, int(display_id.rsplit("-", 1)[1]))
    except (IndexError, ValueError):
        return (1, display_id)


def _security_review_intel_candidates(
    threats: list[Threat],
    scan_status_by_threat_id: dict[str, str],
    *,
    limit: int = SECURITY_REVIEW_INTEL_THREAT_LIMIT,
) -> list[Threat]:
    """Return a bounded, priority-sorted set of threats for semantic enrichment."""
    if limit <= 0:
        return []

    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    return sorted(
        reviewable_threats,
        key=lambda threat: (
            _SCAN_STATUS_SORT_RANK.get(
                scan_status_by_threat_id.get(str(threat.id), ""), 4
            ),
            _SEVERITY_SORT_RANK.get(threat.severity, 4),
            _display_id_sort_key(threat.display_id),
        ),
    )[:limit]


def _dfd_quality_warnings(dfd: DFDResponse) -> list[str]:
    warnings: list[str] = []
    if len(dfd.nodes) >= 2 and not dfd.edges:
        warnings.append("The current DFD has components but no data flows.")
    if len(dfd.nodes) >= 6 and not dfd.trust_boundaries:
        warnings.append("The current DFD has many components but no trust boundaries.")
    return warnings


def _document_extraction_warnings(document: Document | None) -> list[str]:
    parsed_components = getattr(document, "parsed_components", None)
    if document is None or not isinstance(parsed_components, dict):
        return []
    payload = parsed_components
    warnings = payload.get("warnings")
    if isinstance(warnings, list):
        return [str(item) for item in warnings if str(item).strip()]
    return []


def _document_context_summary(document: Document | None) -> str:
    parsed_components = getattr(document, "parsed_components", None)
    if document is None or not isinstance(parsed_components, dict):
        return ""

    evidence = parsed_components.get("evidence")
    parse_result = parsed_components.get("parse_result")
    if not isinstance(evidence, dict) or not isinstance(parse_result, dict):
        return ""

    lines: list[str] = []
    detected_doc_type = evidence.get("detected_doc_type")
    if detected_doc_type:
        lines.append(f"Document type: {str(detected_doc_type).replace('_', ' ')}.")

    component_count = int(evidence.get("component_count") or 0)
    flow_count = int(evidence.get("flow_count") or 0)
    boundary_count = int(evidence.get("boundary_count") or 0)
    if component_count or flow_count or boundary_count:
        lines.append(
            f"Extracted architecture evidence: {component_count} components, "
            f"{flow_count} flows, {boundary_count} trust boundaries."
        )

    diagram_pages = evidence.get("diagram_pages")
    if isinstance(diagram_pages, list) and diagram_pages:
        lines.append(
            "Diagram pages detected: "
            + ", ".join(str(page) for page in diagram_pages[:8])
            + "."
        )
    diagram_artifacts = evidence.get("diagram_artifacts")
    if isinstance(diagram_artifacts, list) and diagram_artifacts:
        lines.append(
            "Diagram artifacts detected: "
            + ", ".join(str(artifact) for artifact in diagram_artifacts[:8])
            + "."
        )

    extraction_sources = evidence.get("extraction_sources")
    if isinstance(extraction_sources, list) and extraction_sources:
        lines.append(
            "Extraction sources: "
            + ", ".join(str(source) for source in extraction_sources[:6])
            + "."
        )

    components = parse_result.get("components")
    if isinstance(components, list) and components:
        component_lines: list[str] = []
        for component in components[:8]:
            if not isinstance(component, dict):
                continue
            name = str(component.get("name") or "").strip()
            if not name:
                continue
            component_type = str(component.get("component_type") or "process")
            extraction_source = str(component.get("extraction_source") or "heuristic")
            evidence_page = component.get("evidence_page")
            snippet = str(
                component.get("evidence_snippet") or component.get("description") or ""
            ).strip()
            detail_bits = [component_type, extraction_source]
            if evidence_page is not None:
                detail_bits.append(f"page {evidence_page}")
            detail = ", ".join(detail_bits)
            if snippet:
                component_lines.append(f"- {name} [{detail}]: {snippet[:180]}")
            else:
                component_lines.append(f"- {name} [{detail}]")
        if component_lines:
            lines.append("Document-derived components:\n" + "\n".join(component_lines))

    flows = parse_result.get("flows")
    if isinstance(flows, list) and flows:
        flow_lines: list[str] = []
        for flow in flows[:8]:
            if not isinstance(flow, dict):
                continue
            source = str(flow.get("source") or "").strip()
            target = str(flow.get("target") or "").strip()
            if not source or not target:
                continue
            label = str(flow.get("label") or "unnamed flow").strip()
            provenance = str(flow.get("extraction_source") or "heuristic")
            flow_lines.append(f"- {source} -> {target}: {label} [{provenance}]")
        if flow_lines:
            lines.append("Document-derived flows:\n" + "\n".join(flow_lines))

    return "\n".join(lines)[:3000]


def _customer_packet_scope(threat_model: ThreatModel) -> list[str]:
    scope = [f"System: {threat_model.system_name}."]
    classification = getattr(threat_model, "data_classification", None)
    if classification:
        scope.append(f"Data classification: {classification}.")
    deployment_model = getattr(threat_model, "deployment_model", None)
    if deployment_model:
        scope.append(f"Deployment model: {deployment_model}.")
    regulatory_scope = getattr(threat_model, "regulatory_scope", None) or []
    if regulatory_scope:
        scope.append(f"Regulatory scope: {', '.join(regulatory_scope)}.")
    out_of_scope_statement = getattr(threat_model, "out_of_scope_statement", None)
    if out_of_scope_statement:
        scope.append(f"Out of scope: {str(out_of_scope_statement).rstrip('.')}.")
    if getattr(threat_model, "repository_evidence", None):
        scope.append("Repository evidence is attached to the review.")
    if getattr(threat_model, "cloud_scan_evidence", None):
        scope.append("Cloud evidence is attached to the review.")
    if getattr(threat_model, "iac_evidence", None):
        scope.append("IaC evidence is attached to the review.")
    return scope


def _iso_timestamp(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


async def _load_customer_packet_validation_scan_evidence(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    limit: int = 12,
) -> list[dict[str, object]]:
    result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.threat_model_id == threat_model_id,
            ScanJob.status == "completed",
        )
        .order_by(ScanJob.completed_at.desc().nullslast(), ScanJob.created_at.desc())
        .limit(limit)
    )
    scans = result.scalars().all()
    return [
        {
            "id": str(scan.id),
            "tool_name": scan.tool_name,
            "target_type": scan.target_type,
            "scan_type": scan.scan_type,
            "scope": scan.scope,
            "status": scan.status,
            "finding_count": int(scan.finding_count or 0),
            "created_at": _iso_timestamp(scan.created_at),
            "started_at": _iso_timestamp(scan.started_at),
            "completed_at": _iso_timestamp(scan.completed_at),
        }
        for scan in scans
    ]


def _reviewer_display_name(user: User) -> str:
    for value in (getattr(user, "full_name", None), getattr(user, "email", None)):
        candidate = (value or "").strip()
        if candidate:
            return candidate
    return str(getattr(user, "id", "reviewer"))


def _parse_risk_acceptance_expiry(value: str | None) -> date | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate).date()
    except ValueError:
        try:
            return date.fromisoformat(candidate)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="risk_acceptance.expires_at must be a valid ISO date or timestamp",
            ) from exc


def _expired_acceptance_status(
    acceptance: SecurityReviewRiskAcceptance | None,
) -> SecurityReviewRiskAcceptance | None:
    if acceptance is None or acceptance.status != "active" or not acceptance.expires_at:
        return acceptance
    try:
        expires_at = datetime.fromisoformat(
            acceptance.expires_at.replace("Z", "+00:00")
        )
    except ValueError:
        return acceptance
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at > datetime.now(timezone.utc):
        return acceptance
    return acceptance.model_copy(
        update={
            "status": "expired",
            "reopen_triggers": sorted(
                {*acceptance.reopen_triggers, "risk acceptance expired"}
            ),
        }
    )


def _reopened_acceptance_status(
    acceptance: SecurityReviewRiskAcceptance | None,
) -> SecurityReviewRiskAcceptance | None:
    if acceptance is None or acceptance.status == "reopened":
        return acceptance
    return acceptance.model_copy(
        update={
            "status": "reopened",
            "reopen_triggers": sorted(
                {*acceptance.reopen_triggers, "finding reopened by reviewer"}
            ),
        }
    )


def _hydrate_threat_response(
    threat: Threat,
    controls_map: dict[UUID, list] | None = None,
    scan_status: str | None = None,
) -> ThreatResponse:
    response = ThreatResponse.model_validate(threat)
    response.control_effectiveness = normalize_control_effectiveness(
        getattr(threat, "control_effectiveness", None)
    )
    response.residual_risk_level = getattr(
        threat, "residual_risk_level", None
    ) or derive_residual_risk_level(
        threat.severity,
        response.control_effectiveness,
    )
    response.compliance_controls = (
        controls_map.get(threat.id, []) if controls_map else []
    )
    response.scan_status = scan_status  # type: ignore[assignment]
    return response


async def _latest_scan_status_by_threat_id(
    db: AsyncSession,
    threats: list[Threat],
) -> dict[str, str]:
    if not threats:
        return {}

    scan_rows_result = await db.execute(
        select(ScanThreatResult)
        .where(ScanThreatResult.threat_id.in_([item.id for item in threats]))
        .order_by(
            ScanThreatResult.threat_id,
            ScanThreatResult.updated_at.desc(),
            ScanThreatResult.created_at.desc(),
            ScanThreatResult.id.desc(),
        )
    )
    scan_status_by_threat_id: dict[str, str] = {}
    for row in scan_rows_result.scalars().all():
        threat_id = getattr(row, "threat_id", None)
        scan_status = getattr(row, "scan_status", None)
        if threat_id is None or not scan_status:
            continue
        threat_key = str(threat_id)
        if threat_key not in scan_status_by_threat_id:
            scan_status_by_threat_id[threat_key] = scan_status
    return scan_status_by_threat_id


async def _require_owner(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    """Verify current user can modify the model. Returns user."""
    require_model_permission(
        await get_threat_model(db, threat_model_id), current_user, "write"
    )  # type: ignore[arg-type]
    return current_user


async def _require_read_access(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    require_model_permission(
        await get_threat_model(db, threat_model_id), current_user, "read"
    )  # type: ignore[arg-type]
    return current_user


async def _require_review_access(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    require_model_permission(
        await get_threat_model(db, threat_model_id), current_user, "review"
    )  # type: ignore[arg-type]
    return current_user


async def _load_security_review_inputs(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    include_intel: bool,
) -> tuple[
    ThreatModel,
    list[Threat],
    list[DFDNode],
    list[DFDEdge],
    list[TrustBoundary],
    dict[str, str],
    dict[str, ThreatIntelResponse],
]:
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    if isinstance(threat_model, ThreatModel):
        documents_result = await db.execute(
            select(Document)
            .where(Document.threat_model_id == threat_model_id)
            .order_by(Document.uploaded_at.desc())
            .limit(3)
        )
        set_committed_value(
            threat_model,
            "documents",
            list(documents_result.scalars().all()),
        )

    threats_result = await db.execute(
        select(Threat).where(Threat.threat_model_id == threat_model_id)
    )
    threats = list(threats_result.scalars().all())

    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    nodes = list(nodes_result.scalars().all())
    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    edges = list(edges_result.scalars().all())
    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    boundaries = list(boundaries_result.scalars().all())

    scan_status_by_threat_id: dict[str, str] = {}
    if threats:
        scan_rows_result = await db.execute(
            select(ScanThreatResult)
            .where(ScanThreatResult.threat_id.in_([item.id for item in threats]))
            .order_by(
                ScanThreatResult.threat_id,
                ScanThreatResult.updated_at.desc(),
                ScanThreatResult.created_at.desc(),
            )
        )
        for row in scan_rows_result.scalars().all():
            key = str(row.threat_id)
            if key not in scan_status_by_threat_id:
                scan_status_by_threat_id[key] = row.scan_status

    intel_by_threat_id: dict[str, ThreatIntelResponse] = {}
    if include_intel:
        intel_candidates = _security_review_intel_candidates(
            threats,
            scan_status_by_threat_id,
        )
        for threat in intel_candidates:
            threat_id_str = str(threat.id)
            try:
                intel_by_threat_id[threat_id_str] = await build_threat_intel_response(
                    db,
                    threat,
                    system_name=threat_model.system_name,
                    system_description=threat_model.description or "",
                    include_semantic_retrieval=settings.security_review_semantic_intel_enabled,
                )
            except Exception as exc:
                logger.warning(
                    "security_review_intel_failed threat_id=%s: %s",
                    threat_id_str,
                    exc,
                )
                continue

    return (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    )


async def _recompute_clusters(
    db: AsyncSession,
    threat_model_id: UUID,
    threats: list,
    dfd: "DFDResponse",
) -> None:
    """Delete old clusters for this model and persist newly computed ones."""
    # Delete existing clusters (threats have cluster_id SET NULL via FK cascade)
    await db.execute(
        delete(ThreatCluster).where(ThreatCluster.threat_model_id == threat_model_id)
    )
    await db.flush()

    cluster_results = compute_clusters(threats, dfd)
    threat_map = {t.id: t for t in threats}

    for result in cluster_results:
        cluster = ThreatCluster(
            id=uuid4(),
            threat_model_id=threat_model_id,
            cluster_label=result.label,
            cluster_reason=result.reason,
            representative_threat_id=result.representative_threat_id,
            threat_count=len(result.threat_ids),
        )
        db.add(cluster)
        await db.flush()  # get cluster.id before updating threats

        for tid in result.threat_ids:
            t = threat_map.get(tid)
            if t is not None:
                t.cluster_id = cluster.id

    await db.commit()


router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}",
    tags=["threats"],
)


@router.post("/threats/generate", response_model=RuleEngineOutput)
async def generate_threats(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_owner),
) -> RuleEngineOutput:
    """Run the rules engine against the DFD and persist generated threats."""
    # 1. Verify threat model exists
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # 2. Load DFD from database
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    nodes = nodes_result.scalars().all()

    if not nodes:
        raise HTTPException(
            status_code=400,
            detail="No DFD found. Upload a document first.",
        )

    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    edges = edges_result.scalars().all()

    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    boundaries = boundaries_result.scalars().all()

    dfd_response = DFDResponse(
        nodes=[DFDNodeResponse.model_validate(n) for n in nodes],
        edges=[DFDEdgeResponse.model_validate(e) for e in edges],
        trust_boundaries=[
            TrustBoundaryResponse.model_validate(tb) for tb in boundaries
        ],
    )

    # 3. Call the rules engine
    output = evaluate_rules(dfd_response)

    # 4. Persist generated threats (idempotent: delete existing rules-engine threats first)
    # Advisory lock prevents concurrent generate requests from duplicating threats.
    lock_key = threat_model_id.int % (2**63)
    await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
    await db.execute(
        delete(Threat).where(
            Threat.threat_model_id == threat_model_id,
            Threat.source == "Rules",
        )
    )

    for gt in output.threats:
        # Convert string UUIDs to UUID objects for ARRAY(UUID) columns
        affected_node_ids = [UUID(nid) for nid in gt.affected_node_ids]
        affected_edge_ids = [UUID(eid) for eid in gt.affected_edge_ids]

        threat = Threat(
            threat_model_id=threat_model_id,
            display_id=gt.display_id,
            description=gt.description,
            stride_category=gt.stride_category,
            threat_subtype=gt.threat_subtype,
            severity=gt.severity,
            source="Rules",
            status="Open",
            rule_id=gt.rule_id,
            affected_node_ids=affected_node_ids,
            affected_edge_ids=affected_edge_ids,
            relevance_rationale=gt.relevance_rationale or None,
        )
        db.add(threat)

    await db.commit()

    # 5. Return the rule engine output
    return output


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    threat_model_id: UUID,
    rules_only: bool = Query(False, description="Skip AI enhancement pass"),
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_owner),
) -> AnalyzeResponse:
    """Run the full 3-layer analysis pipeline (rules + optional AI enhancement).

    Layer 1: Rules engine (deterministic STRIDE threats).
    Layer 2: AI enhancement (context-dependent, banking-specific threats).
    Layer 3: Compliance mapping (handled at query time in GET /threats).

    Returns AnalyzeResponse with threats and ai_skipped_reason (null when AI
    enhancement succeeded, string reason when skipped).
    """
    # Billing entitlement gate
    if not await check_org_entitlement(_owner, db, "ai_enhancement"):
        raise HTTPException(
            status_code=403, detail="Your plan does not include this feature"
        )

    # 1. Verify threat model exists
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # Rate limit: one analysis per model per 60 seconds per user.
    # In production this is persisted on the model row so the limit survives
    # app restarts and applies across worker processes.
    from app.config import settings as _settings

    if _settings.app_env not in ("development", "test"):
        now_ts = datetime.now(timezone.utc)
        cutoff = now_ts - timedelta(seconds=_ANALYZE_COOLDOWN_SECONDS)
        claimed = await db.execute(
            update(ThreatModel)
            .where(
                ThreatModel.id == threat_model_id,
                or_(
                    ThreatModel.last_analyze_requested_at.is_(None),
                    ThreatModel.last_analyze_requested_at < cutoff,
                ),
            )
            .values(last_analyze_requested_at=now_ts)
            .returning(ThreatModel.id)
        )
        if claimed.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=429,
                detail="Analysis rate limited — please wait before re-analyzing.",
            )
        threat_model.last_analyze_requested_at = now_ts

    # 2. Load DFD from database
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    nodes = nodes_result.scalars().all()

    if not nodes:
        raise HTTPException(
            status_code=400,
            detail="No DFD found. Upload a document first.",
        )

    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    edges = edges_result.scalars().all()

    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    boundaries = boundaries_result.scalars().all()

    dfd_response = DFDResponse(
        nodes=[DFDNodeResponse.model_validate(n) for n in nodes],
        edges=[DFDEdgeResponse.model_validate(e) for e in edges],
        trust_boundaries=[
            TrustBoundaryResponse.model_validate(tb) for tb in boundaries
        ],
    )

    # 3. Layer 1: Rules engine
    rules_output = evaluate_rules(dfd_response)

    # 4. Layer 2: AI enhancement (optional)
    all_threats = list(rules_output.threats)  # start with rule threats
    ai_skipped_reason: str | None = None
    dfd_quality_warnings = _dfd_quality_warnings(dfd_response)

    doc_result = await db.execute(
        select(Document)
        .where(Document.threat_model_id == threat_model_id)
        .order_by(Document.uploaded_at.desc())
        .limit(1)
    )
    doc = doc_result.scalar_one_or_none()
    doc_excerpt = (doc.raw_text or "")[:4000] if doc else ""
    parsed_payload = getattr(doc, "parsed_components", None)
    if not doc_excerpt and isinstance(parsed_payload, dict):
        evidence = parsed_payload.get("evidence")
        if isinstance(evidence, dict):
            doc_excerpt = str(evidence.get("raw_text_excerpt") or "")[:4000]
    document_warnings = _document_extraction_warnings(doc)
    document_context_summary = _document_context_summary(doc)

    if rules_only:
        ai_skipped_reason = "AI enhancement skipped (rules_only mode)"
    else:
        try:
            llm_client = await get_llm_client_for_user_async(_owner.id, db)
            enhancement_kwargs = dict(
                client=llm_client,
                system_name=threat_model.system_name,
                description=threat_model.description or "",
                data_classification=threat_model.data_classification,
                regulatory_scope=threat_model.regulatory_scope or [],
                deployment_model=threat_model.deployment_model,
                document_context_summary=document_context_summary,
                environment_context_summary=threat_model.environment_context_summary
                or "",
            )

            # Threat-intel retrieval can execute vector SQL that may fail when
            # pgvector or related tables are unavailable. Keep that work on an
            # isolated session so any rollback does not poison the main analyze
            # transaction used for advisory locking and threat persistence.
            if isinstance(db, AsyncSession):
                async with async_session() as enhancement_db:
                    ai_output, ai_skipped_reason = await enhance_threats(
                        dfd_response,
                        rules_output,
                        doc_excerpt,
                        db=enhancement_db,
                        **enhancement_kwargs,
                    )
            else:
                ai_output, ai_skipped_reason = await enhance_threats(
                    dfd_response,
                    rules_output,
                    doc_excerpt,
                    db=db,
                    **enhancement_kwargs,
                )
            if ai_output.threats:
                node_name_map = build_node_name_map(dfd_response.nodes)
                node_pm_map = {
                    str(n.id): (n.properties or {}).get("responsibility") == "provider"
                    for n in dfd_response.nodes
                }
                all_threats = merge_ai_threats(
                    rules_output,
                    ai_output,
                    node_name_map,
                    {boundary.name for boundary in dfd_response.trust_boundaries},
                    node_pm_map,
                )
        except RuntimeError as exc:
            ai_skipped_reason = "AI enhancement is currently unavailable"
            logger.warning("ai_enhancement_unavailable in analyze: %s", exc)
        except Exception as exc:
            ai_skipped_reason = "AI enhancement encountered an error"
            logger.warning("ai_enhancement_error in analyze: %s", exc)
            # Graceful degradation: return rules-only results

    quality_warnings = []
    seen_warning_text: set[str] = set()
    for warning in [*document_warnings, *dfd_quality_warnings]:
        if warning not in seen_warning_text:
            quality_warnings.append(warning)
            seen_warning_text.add(warning)

    if quality_warnings:
        ai_skipped_reason = _append_reason(
            ai_skipped_reason,
            "Analysis completed on an incomplete DFD. " + " ".join(quality_warnings),
        )

    # 5. Load existing threats to preserve triage decisions (status, dismiss_reason)
    # Advisory lock prevents concurrent analyze requests from duplicating threats
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": threat_model_id.int % (2**63)},
    )

    existing_result = await db.execute(
        select(Threat).where(Threat.threat_model_id == threat_model_id)
    )
    existing_threats = list(existing_result.scalars().all())

    # Build lookup by the same identity used by threat diff:
    # (rule_id, sorted affected_node_ids). This preserves triage on unchanged
    # findings while allowing one rule to fire on multiple distinct node pairs.
    def _threat_identity(
        rule_id: str | None, node_ids: list[UUID] | list[str]
    ) -> tuple[str, tuple[str, ...]]:
        return (
            rule_id or "",
            tuple(sorted(str(node_id) for node_id in node_ids)),
        )

    generated_existing = [t for t in existing_threats if t.source != "Manual"]
    manual_existing = [t for t in existing_threats if t.source == "Manual"]
    manual_responses = [
        ThreatResponse.model_validate(threat) for threat in manual_existing
    ]

    existing_by_identity: dict[tuple[str, tuple[str, ...]], list[Threat]] = {}
    for et in generated_existing:
        key = _threat_identity(et.rule_id, et.affected_node_ids or [])
        existing_by_identity.setdefault(key, []).append(et)
    # Track which existing threats have been matched
    matched_existing_ids: set = set()

    # 6. Sync threats: update matching, delete removed, add new.
    #    This preserves threat IDs and audit trail for unchanged threats.
    responses: list[ThreatResponse] = []
    now = datetime.now(timezone.utc)

    for gt in all_threats:
        affected_node_ids = [
            UUID(nid) if isinstance(nid, str) else nid for nid in gt.affected_node_ids
        ]
        affected_edge_ids = [
            UUID(eid) if isinstance(eid, str) else eid for eid in gt.affected_edge_ids
        ]

        # Find matching existing threat by stable threat identity.
        prev = None
        identity = _threat_identity(gt.rule_id, affected_node_ids)
        for candidate in existing_by_identity.get(identity, []):
            if candidate.id not in matched_existing_ids:
                prev = candidate
                matched_existing_ids.add(candidate.id)
                break

        score = compute_qualification_score(
            gt, threat_model.data_classification, dfd_response
        )

        if prev:
            # Invalidate stale cluster and AI likelihood cache on re-analyze
            prev.cluster_id = None
            prev.ai_likelihood_assessment = None
            prev.ai_likelihood_score = None
            prev.ai_likelihood_generated_at = None
            # Update existing threat in place — preserve ID, status, dismiss_reason
            previous_severity = prev.severity
            prev.display_id = gt.display_id
            prev.description = gt.description
            prev.stride_category = gt.stride_category
            prev.threat_subtype = gt.threat_subtype
            prev.severity = gt.severity
            prev.source = gt.source
            prev.rule_id = gt.rule_id
            prev.ai_enhanced = gt.source in ("AI", "AI+Rules")
            prev.provider_managed = getattr(gt, "provider_managed", False)
            prev.affected_node_ids = affected_node_ids
            prev.affected_edge_ids = affected_edge_ids
            prev.relevance_rationale = gt.relevance_rationale or None
            prev.auto_score = score
            # Blend with analyst score if one exists, otherwise use auto score
            if prev.analyst_score is not None:
                prev.qualification_score = blend_scores(score, prev.analyst_score)
            else:
                prev.qualification_score = score
            if previous_severity != gt.severity or not prev.residual_risk_level:
                prev.residual_risk_level = derive_residual_risk_level(
                    gt.severity,
                    prev.control_effectiveness,
                )
            threat_id = prev.id
            preserved_status = prev.status
            preserved_reason = prev.dismiss_reason
            preserved_note = prev.qualification_note
            created_at = prev.created_at
            control_effectiveness = prev.control_effectiveness
            residual_risk_level = prev.residual_risk_level
        else:
            # New threat
            threat_id = uuid4()
            preserved_status = "Open"
            preserved_reason = None
            preserved_note = None
            created_at = now
            control_effectiveness = "none"
            residual_risk_level = derive_residual_risk_level(
                gt.severity, control_effectiveness
            )
            threat = Threat(
                id=threat_id,
                threat_model_id=threat_model_id,
                display_id=gt.display_id,
                description=gt.description,
                stride_category=gt.stride_category,
                threat_subtype=gt.threat_subtype,
                severity=gt.severity,
                source=gt.source,
                status="Open",
                rule_id=gt.rule_id,
                ai_enhanced=gt.source in ("AI", "AI+Rules"),
                provider_managed=getattr(gt, "provider_managed", False),
                affected_node_ids=affected_node_ids,
                affected_edge_ids=affected_edge_ids,
                relevance_rationale=gt.relevance_rationale or None,
                control_effectiveness=control_effectiveness,
                residual_risk_level=residual_risk_level,
                qualification_score=score,
                auto_score=score,
            )
            db.add(threat)

        responses.append(
            ThreatResponse(
                id=threat_id,
                display_id=gt.display_id,
                description=gt.description,
                stride_category=gt.stride_category,
                threat_subtype=gt.threat_subtype,
                severity=gt.severity,
                source=gt.source,
                status=preserved_status,
                dismiss_reason=preserved_reason,
                rule_id=gt.rule_id,
                ai_enhanced=gt.source in ("AI", "AI+Rules"),
                provider_managed=getattr(gt, "provider_managed", False),
                original_rule_threat_id=None,
                affected_node_ids=affected_node_ids,
                affected_edge_ids=affected_edge_ids,
                relevance_rationale=gt.relevance_rationale or None,
                control_effectiveness=control_effectiveness,
                residual_risk_level=residual_risk_level,
                qualification_score=score,
                qualification_note=preserved_note,
                created_at=created_at,
            )
        )

    # Delete threats that were not matched (no longer exist in new analysis)
    for et in generated_existing:
        if et.id not in matched_existing_ids:
            await db.delete(et)

    # 7. Snapshot rules-engine threats only for future diff comparisons.
    #    The diff endpoint runs rules-only (no AI), so we store only rules
    #    threats to avoid false "removed" entries for AI-generated threats.
    threat_model.last_analyzed_threats = [
        {
            "rule_id": gt.rule_id,
            "stride_category": gt.stride_category,
            "threat_subtype": gt.threat_subtype,
            "severity": gt.severity,
            "description": gt.description,
            "affected_node_ids": [
                str(nid) if not isinstance(nid, str) else nid
                for nid in gt.affected_node_ids
            ],
            "affected_edge_ids": [
                str(eid) if not isinstance(eid, str) else eid
                for eid in gt.affected_edge_ids
            ],
        }
        for gt in rules_output.threats
    ]

    await db.commit()

    # 8. Recompute threat clusters for this model (post-commit, async-safe).
    #    Deletes old clusters first, then persists new ones.
    all_persisted = await db.execute(
        select(Threat).where(Threat.threat_model_id == threat_model_id)
    )
    persisted_threats = all_persisted.scalars().all()
    await _recompute_clusters(db, threat_model_id, persisted_threats, dfd_response)

    responses.extend(manual_responses)

    responses.sort(key=lambda item: _display_id_sort_key(item.display_id))

    # 9. Return AnalyzeResponse with threats and AI skip reason
    return AnalyzeResponse(threats=responses, ai_skipped_reason=ai_skipped_reason)


@router.get("/threats", response_model=list[ThreatResponse])
async def list_threats(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_read_access),
    stride_category: Optional[str] = Query(
        None, description="Filter by STRIDE category"
    ),
    severity: Optional[str] = Query(
        None, description="Filter by severity (Critical, High, Medium, Low)"
    ),
    status: Optional[str] = Query(
        None,
        description="Filter by status (Open, In Progress, Mitigated, Accepted, Dismissed)",
    ),
    search: Optional[str] = Query(
        None, description="Keyword search in threat description (case-insensitive)"
    ),
    frameworks: Optional[list[str]] = Query(
        None, description="Filter compliance controls by framework(s)"
    ),
    control: Optional[str] = Query(
        None,
        description="Filter threats by compliance control ID (e.g. PCI-DSS-Req-1.3)",
    ),
    limit: Optional[int] = Query(
        None, ge=1, le=500, description="Max threats to return"
    ),
    offset: int = Query(0, ge=0, description="Number of threats to skip"),
) -> list[ThreatResponse]:
    """List all threats for a threat model, ordered by display_id."""
    # 1. Verify threat model exists
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # 2. Query threats ordered by display_id, with optional filters
    stmt = select(Threat).where(Threat.threat_model_id == threat_model_id)
    if stride_category is not None:
        stmt = stmt.where(Threat.stride_category == stride_category)
    if severity is not None:
        stmt = stmt.where(Threat.severity == severity)
    if status is not None:
        stmt = stmt.where(Threat.status == status)
    if search is not None:
        stmt = stmt.where(Threat.description.ilike(f"%{search}%"))
    stmt = stmt.order_by(Threat.display_id)
    if offset:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    threats = result.scalars().all()

    # 3. Populate compliance controls
    controls_map = await lookup_controls_batch(db, threats, frameworks=frameworks)

    scan_status_by_threat_id = await _latest_scan_status_by_threat_id(db, threats)

    # 4. Return threat responses with compliance controls and scan verdicts attached
    responses = []
    for t in threats:
        responses.append(
            _hydrate_threat_response(
                t,
                controls_map,
                scan_status=scan_status_by_threat_id.get(str(t.id)),
            )
        )

    # 5. Post-filter by compliance control ID if requested
    if control is not None:
        control_lower = control.lower()
        responses = [
            r
            for r in responses
            if any(c.control_id.lower() == control_lower for c in r.compliance_controls)
        ]

    return responses


@router.get("/threats/export.csv")
async def export_threats_csv(
    threat_model_id: UUID,
    _owner: User = Depends(_require_read_access),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Export all threats as CSV for integration with external tools."""
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    result = await db.execute(
        select(Threat)
        .where(Threat.threat_model_id == threat_model_id)
        .order_by(Threat.display_id)
    )
    threats = result.scalars().all()
    controls_map = await lookup_controls_batch(db, threats)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "ID",
            "Description",
            "STRIDE Category",
            "Severity",
            "Status",
            "Control Effectiveness",
            "Residual Risk",
            "Source",
            "Rule ID",
            "Dismiss Reason",
            "Mitigation Plan",
            "Mitigation Owner",
            "Due Date",
            "Relevance Rationale",
            "Compliance Controls",
            "Created At",
            "Closed At",
            "AI Enhanced",
        ]
    )
    for t in threats:
        controls = controls_map.get(t.id, [])
        controls_str = (
            "; ".join(f"{c.control_id} ({c.framework})" for c in controls)
            if controls
            else ""
        )
        writer.writerow(
            [
                t.display_id,
                t.description,
                t.stride_category,
                t.severity,
                t.status,
                normalize_control_effectiveness(
                    getattr(t, "control_effectiveness", None)
                ),
                getattr(t, "residual_risk_level", None)
                or derive_residual_risk_level(
                    t.severity,
                    getattr(t, "control_effectiveness", None),
                ),
                t.source,
                t.rule_id or "",
                t.dismiss_reason or "",
                getattr(t, "mitigation_plan", None) or "",
                getattr(t, "mitigation_owner", None) or "",
                str(getattr(t, "due_date", None) or ""),
                getattr(t, "relevance_rationale", None) or "",
                controls_str,
                t.created_at.isoformat() if t.created_at else "",
                t.closed_at.isoformat() if t.closed_at else "",
                "Yes" if t.ai_enhanced else "No",
            ]
        )

    buf.seek(0)
    filename = f"threats-{threat_model_id}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/threats/summary", response_model=ThreatSummary)
async def get_threats_summary(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_read_access),
) -> ThreatSummary:
    """Return threat counts grouped by STRIDE category, severity, and status."""
    # 1. Verify threat model exists
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # 2. Load all threats for this model
    result = await db.execute(
        select(Threat).where(Threat.threat_model_id == threat_model_id)
    )
    threats = result.scalars().all()

    # 3. Count by category, severity, and status
    by_stride: dict[str, int] = dict(Counter(t.stride_category for t in threats))
    by_severity: dict[str, int] = dict(Counter(t.severity for t in threats))
    by_status: dict[str, int] = dict(Counter(t.status for t in threats))

    return ThreatSummary(
        total=len(threats),
        by_stride=by_stride,
        by_severity=by_severity,
        by_status=by_status,
    )


@router.get("/threats/residual-summary", response_model=ResidualRiskSummary)
async def get_residual_risk_summary(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_read_access),
) -> ResidualRiskSummary:
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    result = await db.execute(
        select(Threat).where(
            Threat.threat_model_id == threat_model_id,
            Threat.status.in_(RESIDUAL_SUMMARY_STATUSES),
        )
    )
    threats = result.scalars().all()
    summary = build_residual_risk_summary(
        [
            getattr(threat, "residual_risk_level", None)
            or derive_residual_risk_level(
                threat.severity,
                getattr(threat, "control_effectiveness", None),
            )
            for threat in threats
        ]
    )
    return ResidualRiskSummary(total=len(threats), by_level=summary)


@router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_model_id: UUID,
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_read_access),
) -> ThreatResponse:
    """Return a single threat with compliance controls attached."""
    result = await db.execute(
        select(Threat).where(
            Threat.id == threat_id,
            Threat.threat_model_id == threat_model_id,
        )
    )
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    controls_map = await lookup_controls_batch(db, [threat])
    return _hydrate_threat_response(threat, controls_map)


@router.get("/threats/{threat_id}/intel", response_model=ThreatIntelResponse)
async def get_threat_intel(
    threat_model_id: UUID,
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_owner),
) -> ThreatIntelResponse:
    """Return threat-intel enrichment for a single threat.

    The payload combines exact cited references, scan-derived CVEs, and semantic
    matches from the local intel store. Failures degrade to an unavailable
    payload instead of failing the whole threat detail page.
    """
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    result = await db.execute(
        select(Threat).where(
            Threat.id == threat_id,
            Threat.threat_model_id == threat_model_id,
        )
    )
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    local_severity = threat.severity
    try:
        return await build_threat_intel_response(
            db,
            threat,
            system_name=threat_model.system_name,
            system_description=threat_model.description or "",
        )
    except Exception as exc:
        logger.warning("threat_intel_detail_failed threat_id=%s: %s", threat_id, exc)
        return ThreatIntelResponse(
            local_severity=local_severity,
            unavailable_reason="Threat intelligence temporarily unavailable.",
        )


@router.get("/threats/{threat_id}/review", response_model=SecurityReviewDecision)
async def get_threat_review(
    threat_model_id: UUID,
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> SecurityReviewDecision:
    """Return a deterministic security-review decision for one threat."""

    (
        threat_model,
        threats,
        nodes,
        edges,
        _boundaries,
        scan_status_by_threat_id,
        _intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=False)
    if not threats:
        raise HTTPException(status_code=404, detail="No threats found for this model")

    selected_threat = next((item for item in threats if item.id == threat_id), None)
    if selected_threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    intel_by_threat_id: dict[str, ThreatIntelResponse] = {}
    try:
        intel_by_threat_id[str(selected_threat.id)] = await build_threat_intel_response(
            db,
            selected_threat,
            system_name=threat_model.system_name,
            system_description=threat_model.description or "",
        )
    except Exception as exc:
        logger.warning("threat_review_intel_failed threat_id=%s: %s", threat_id, exc)

    decisions = evaluate_threat_security_reviews(
        threat_model,
        threats,
        nodes,
        edges,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    decision = decisions.get(str(threat_id))
    if decision is None:
        raise HTTPException(status_code=404, detail="Threat review not found")
    return decision


@router.get("/review", response_model=SecurityReviewApplicationSummary)
async def get_application_review(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> SecurityReviewApplicationSummary:
    """Return a deterministic application-wide security review summary."""

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]

    return build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )


@router.get("/review-findings", response_model=SecurityReviewFindingListResponse)
async def get_security_review_findings(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> SecurityReviewFindingListResponse:
    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    return build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )


@router.get("/agent/release-decision", response_model=AgentSecurityReviewResponse)
async def get_agent_release_decision(
    threat_model_id: UUID,
    ci_fail_policy: AgentCiFailPolicy = Query(
        default="block_only",
        description=(
            "CI exit policy for the response contract. The endpoint returns HTTP 200 "
            "when the review can be computed; callers should use ci.exit_code."
        ),
    ),
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentSecurityReviewResponse:
    """Return the release decision contract intended for coding agents and CI."""

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    return build_agent_security_review_response(
        summary,
        findings,
        ci_fail_policy=ci_fail_policy,
    )


@router.get(
    "/agent/remediation-plan",
    response_model=AgentRemediationPlanResponse,
)
async def get_agent_remediation_plan(
    threat_model_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentRemediationPlanResponse:
    """Return ordered agent remediation actions for the current decision."""

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    plan = build_agent_remediation_plan_response(summary, agent_response, findings)
    return _attach_remediation_webhook_setups(
        plan, base_url=str(request.base_url), threat_model_id=threat_model_id
    )


def _attach_remediation_webhook_setups(
    plan: AgentRemediationPlanResponse,
    *,
    base_url: str,
    threat_model_id: UUID,
) -> AgentRemediationPlanResponse:
    return attach_remediation_webhook_setups(
        plan,
        base_url=base_url,
        threat_model_id=threat_model_id,
    )


def _find_remediation_action(
    plan: AgentRemediationPlanResponse, action_id: str
) -> AgentRemediationAction:
    action = next((item for item in plan.actions if item.action_id == action_id), None)
    if action is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    return action


def _find_security_review_finding(
    findings: SecurityReviewFindingListResponse,
    *,
    source_object_type: str,
    source_object_id: str,
) -> SecurityReviewFinding:
    finding = next(
        (
            item
            for item in findings.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")
    return finding


def _external_ticket_artifact(
    action: AgentRemediationAction,
    body: AgentRemediationTicketCreateRequest,
) -> SecurityReviewArtifact:
    now = datetime.now(timezone.utc).isoformat()
    ticket_id = body.external_ticket_id or f"{body.provider}:{action.finding_id}"
    ticket_url = body.external_ticket_url or "not supplied"
    created_by = body.created_by or "confirmed reviewer"
    return SecurityReviewArtifact(
        id=str(uuid4()),
        kind=action.artifact_kind,
        title=f"External ticket handoff · {action.title}",
        summary=(
            "Confirmed external ticket handoff for the remediation loop; "
            "the finding still needs implementation proof before clearance."
        ),
        body="\n".join(
            [
                "External ticket handoff",
                f"- Provider: {body.provider}",
                f"- Ticket id: {ticket_id}",
                f"- Ticket URL: {ticket_url}",
                f"- Confirmed by: {created_by}",
                f"- Confirmed at: {now}",
                "",
                "Ticket draft",
                f"- Title: {action.ticket_draft.title}",
                f"- Labels: {', '.join(action.ticket_draft.labels) or 'none'}",
                "",
                "Required next proof",
                f"- {action.instruction}",
                "- Attach PR, validation output, or reviewer evidence before rerunning the release decision.",
            ]
        ),
        created_at=now,
    )


def _inbound_evidence_artifact(
    action: AgentRemediationAction,
    body: AgentRemediationEvidenceWebhookRequest,
    *,
    normalized_provider_event: str = "manual_evidence",
) -> SecurityReviewArtifact:
    now = body.received_at or datetime.now(timezone.utc).isoformat()
    return SecurityReviewArtifact(
        id=str(uuid4()),
        kind="verification_note",
        title=f"Inbound remediation evidence · {action.title}",
        summary=(
            "External remediation evidence was ingested and the finding is "
            "ready for the next review rerun or verification checkpoint."
        ),
        body="\n".join(
            [
                "Inbound evidence webhook",
                f"- Provider: {body.provider}",
                f"- Normalized event: {normalized_provider_event}",
                f"- Ticket id: {body.external_ticket_id or 'not supplied'}",
                f"- Pull request: {body.pull_request_url or 'not supplied'}",
                f"- Commit: {body.commit_sha or 'not supplied'}",
                f"- Evidence URL: {body.evidence_url or 'not supplied'}",
                f"- Received at: {now}",
                "",
                "Evidence summary",
                f"- {body.evidence_summary}",
                "",
                "Review rerun",
                "- Rerun the agent release decision and keep block/fix-now findings at verify until the named proof is validated.",
            ]
        ),
        created_at=now,
    )


@router.post(
    "/agent/remediation-plan/apply",
    response_model=AgentRemediationPlanApplyResponse,
)
async def apply_agent_remediation_plan(
    threat_model_id: UUID,
    request: Request,
    body: AgentRemediationPlanApplyRequest = AgentRemediationPlanApplyRequest(),
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentRemediationPlanApplyResponse:
    """Create local review artifacts for the current agent remediation plan."""

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    plan = build_agent_remediation_plan_response(summary, agent_response, findings)

    selected_ids = set(body.action_ids or [])
    selected_actions = [
        action
        for action in plan.actions
        if not selected_ids or action.action_id in selected_ids
    ][: body.max_actions]
    findings_by_source = {
        (finding.source_object_type, finding.source_object_id): finding
        for finding in findings.findings
    }
    created_count = 0
    updated_finding_ids: list[str] = []

    for action in selected_actions:
        current_finding = findings_by_source.get(
            (action.source_object_type, action.source_object_id)
        )
        if current_finding is None:
            continue
        related_threat = (
            next(
                (item for item in threats if str(item.id) == current_finding.threat_id),
                None,
            )
            if current_finding.threat_id is not None
            else None
        )
        artifact = build_security_review_artifact(
            current_finding,
            kind=action.artifact_kind,
            threat=_hydrate_threat_response(related_threat)
            if related_threat is not None
            else None,
        )
        current_record = find_review_state_record(
            getattr(threat_model, "review_state", None),
            source_object_type=action.source_object_type,
            source_object_id=action.source_object_id,
        )
        next_artifacts = replace_artifact_of_kind(
            current_record.artifacts
            if current_record is not None
            else current_finding.artifacts,
            artifact,
        )
        threat_model.review_state = upsert_review_state_record(
            getattr(threat_model, "review_state", None),
            source_object_type=action.source_object_type,
            source_object_id=action.source_object_id,
            update=SecurityReviewStateUpdate(artifacts=next_artifacts),
            current_record=current_record,
        )
        created_count += 1
        updated_finding_ids.append(action.finding_id)

    if created_count:
        await db.commit()

    refreshed_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    refreshed_agent_response = build_agent_security_review_response(
        summary, refreshed_findings
    )
    refreshed_plan = build_agent_remediation_plan_response(
        summary, refreshed_agent_response, refreshed_findings
    )
    refreshed_plan = _attach_remediation_webhook_setups(
        refreshed_plan, base_url=str(request.base_url), threat_model_id=threat_model_id
    )
    return AgentRemediationPlanApplyResponse(
        generated_at=refreshed_plan.generated_at,
        system_name=refreshed_plan.system_name,
        created_artifact_count=created_count,
        updated_finding_ids=updated_finding_ids,
        plan=refreshed_plan,
    )


@router.post(
    "/agent/remediation-plan/tickets",
    response_model=AgentRemediationTicketCreateResponse,
)
async def create_agent_remediation_ticket(
    threat_model_id: UUID,
    body: AgentRemediationTicketCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentRemediationTicketCreateResponse:
    """Record a confirmed external ticket handoff for a remediation action."""

    if not body.confirmed:
        raise HTTPException(
            status_code=400,
            detail="External ticket creation requires explicit confirmation",
        )

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    plan = build_agent_remediation_plan_response(summary, agent_response, findings)
    action = _find_remediation_action(plan, body.action_id)
    current_finding = _find_security_review_finding(
        findings,
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
    )

    current_record = find_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
    )
    ticket_artifact = _external_ticket_artifact(action, body)
    next_artifacts = replace_artifact_of_kind(
        current_record.artifacts
        if current_record is not None
        else current_finding.artifacts,
        ticket_artifact,
    )
    threat_model.review_state = upsert_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
        update=SecurityReviewStateUpdate(artifacts=next_artifacts),
        current_record=current_record,
    )
    await db.commit()

    refreshed_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    refreshed_agent_response = build_agent_security_review_response(
        summary, refreshed_findings
    )
    refreshed_plan = build_agent_remediation_plan_response(
        summary, refreshed_agent_response, refreshed_findings
    )
    refreshed_plan = _attach_remediation_webhook_setups(
        refreshed_plan, base_url=str(request.base_url), threat_model_id=threat_model_id
    )
    return AgentRemediationTicketCreateResponse(
        generated_at=refreshed_plan.generated_at,
        system_name=refreshed_plan.system_name,
        created_ticket_count=1,
        updated_finding_ids=[action.finding_id],
        plan=refreshed_plan,
    )


@router.post(
    "/agent/remediation-plan/tickets/connectors",
    response_model=AgentRemediationConnectorTicketCreateResponse,
)
async def create_agent_remediation_ticket_with_connector(
    threat_model_id: UUID,
    body: AgentRemediationConnectorTicketCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentRemediationConnectorTicketCreateResponse:
    """Create a provider ticket with a customer-owned credential after confirmation."""

    if not body.confirmed:
        raise HTTPException(
            status_code=400,
            detail="Provider ticket creation requires explicit confirmation",
        )
    if body.access_token is None:
        raise HTTPException(
            status_code=400,
            detail="Provider ticket creation requires a customer-owned access token",
        )

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    plan = build_agent_remediation_plan_response(summary, agent_response, findings)
    action = _find_remediation_action(plan, body.action_id)
    current_finding = _find_security_review_finding(
        findings,
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
    )

    try:
        provider_result = await create_remediation_provider_ticket(
            body=body,
            action=action,
        )
    except RemediationConnectorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    ticket_body = AgentRemediationTicketCreateRequest(
        action_id=body.action_id,
        provider=body.provider,
        confirmed=True,
        external_ticket_id=provider_result.external_ticket_id,
        external_ticket_url=provider_result.external_ticket_url,
        created_by=body.created_by or "provider connector",
    )
    current_record = find_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
    )
    ticket_artifact = _external_ticket_artifact(action, ticket_body)
    next_artifacts = replace_artifact_of_kind(
        current_record.artifacts
        if current_record is not None
        else current_finding.artifacts,
        ticket_artifact,
    )
    threat_model.review_state = upsert_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
        update=SecurityReviewStateUpdate(artifacts=next_artifacts),
        current_record=current_record,
    )
    await db.commit()

    refreshed_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    refreshed_agent_response = build_agent_security_review_response(
        summary, refreshed_findings
    )
    refreshed_plan = build_agent_remediation_plan_response(
        summary, refreshed_agent_response, refreshed_findings
    )
    refreshed_plan = _attach_remediation_webhook_setups(
        refreshed_plan, base_url=str(request.base_url), threat_model_id=threat_model_id
    )
    callback_url = remediation_evidence_callback_url(
        str(request.base_url), threat_model_id
    )
    callback_payload = remediation_evidence_callback_payload(
        action,
        provider=body.provider,
        result=provider_result,
    )
    return AgentRemediationConnectorTicketCreateResponse(
        generated_at=refreshed_plan.generated_at,
        system_name=refreshed_plan.system_name,
        provider=body.provider,
        created_ticket_count=1,
        updated_finding_ids=[action.finding_id],
        external_ticket_id=provider_result.external_ticket_id,
        external_ticket_url=provider_result.external_ticket_url,
        callback_url=callback_url,
        callback_payload_template=callback_payload,
        callback_required_headers=remediation_webhook_required_headers_template(),
        callback_signature_base_string=remediation_webhook_signature_base_string(),
        plan=refreshed_plan,
    )


@router.post(
    "/agent/remediation-plan/webhooks/evidence",
    response_model=AgentRemediationEvidenceWebhookResponse,
)
async def ingest_agent_remediation_evidence_webhook(
    threat_model_id: UUID,
    body: AgentRemediationEvidenceWebhookRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentRemediationEvidenceWebhookResponse:
    """Attach external PR or evidence webhook proof to the remediation loop."""

    raw_body = await request.body()
    try:
        await verify_remediation_webhook_signature_durable(
            headers=request.headers,
            raw_body=raw_body,
            scope=str(threat_model_id),
            db=db,
            provider=body.provider,
        )
    except RemediationWebhookSignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    normalized_provider_event = normalize_remediation_webhook_event(body)
    return await _ingest_agent_remediation_evidence(
        threat_model_id=threat_model_id,
        body=body,
        db=db,
        normalized_provider_event=normalized_provider_event,
        base_url=str(request.base_url),
    )


@router.post(
    "/agent/remediation-plan/webhooks/providers/{provider}/evidence",
    response_model=AgentRemediationEvidenceWebhookResponse,
)
async def ingest_agent_remediation_provider_evidence_webhook(
    threat_model_id: UUID,
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AgentRemediationEvidenceWebhookResponse:
    """Attach signed provider-native webhook evidence without a user session."""

    raw_body = await request.body()
    try:
        await verify_remediation_webhook_signature_durable(
            headers=request.headers,
            raw_body=raw_body,
            scope=f"{threat_model_id}:{provider.casefold()}",
            db=db,
            provider=provider,
        )
        payload = await request.json()
        if not isinstance(payload, dict):
            raise RemediationProviderWebhookError(
                "Provider webhook payload must be a JSON object."
            )
        body = parse_remediation_provider_webhook(provider=provider, payload=payload)
    except RemediationWebhookSignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except (RemediationProviderWebhookError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    normalized_provider_event = normalize_remediation_webhook_event(body)
    return await _ingest_agent_remediation_evidence(
        threat_model_id=threat_model_id,
        body=body,
        db=db,
        normalized_provider_event=normalized_provider_event,
        base_url=str(request.base_url),
    )


@router.post(
    "/agent/remediation-plan/webhooks/providers/{provider}/test",
    response_model=AgentRemediationProviderWebhookTestResponse,
)
async def test_agent_remediation_provider_evidence_webhook(
    threat_model_id: UUID,
    provider: str,
    body: AgentRemediationProviderWebhookTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> AgentRemediationProviderWebhookTestResponse:
    """Dry-run a signed provider-native callback without attaching evidence."""

    normalized_provider = provider.casefold().strip()
    if normalized_provider not in {"github", "linear", "jira"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported remediation provider: {provider}.",
        )
    if body.provider != normalized_provider:
        raise HTTPException(
            status_code=400,
            detail="Provider path and body provider must match.",
        )

    raw_body = body.payload_text.encode("utf-8")
    try:
        await verify_remediation_webhook_signature_durable(
            headers=body.headers,
            raw_body=raw_body,
            scope=f"{threat_model_id}:{normalized_provider}:test",
            db=db,
            provider=f"{normalized_provider}:test",
        )
        payload = json.loads(body.payload_text)
        if not isinstance(payload, dict):
            raise RemediationProviderWebhookError(
                "Provider webhook payload must be a JSON object."
            )
        parsed = parse_remediation_provider_webhook(
            provider=normalized_provider,
            payload=payload,
        )
    except RemediationWebhookSignatureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Provider webhook payload must be valid JSON.",
        ) from exc
    except (RemediationProviderWebhookError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    plan = build_agent_remediation_plan_response(summary, agent_response, findings)
    if parsed.action_id is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    action = _find_remediation_action(plan, parsed.action_id)
    plan = _attach_remediation_webhook_setups(
        plan, base_url=str(request.base_url), threat_model_id=threat_model_id
    )
    await db.commit()

    return AgentRemediationProviderWebhookTestResponse(
        generated_at=plan.generated_at,
        system_name=plan.system_name,
        provider=body.provider,
        normalized_provider_event=normalize_remediation_webhook_event(parsed),
        action_id=action.action_id,
        finding_id=action.finding_id,
        action_title=action.title,
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
        external_ticket_id=parsed.external_ticket_id,
        pull_request_url=parsed.pull_request_url,
        commit_sha=parsed.commit_sha,
        evidence_url=parsed.evidence_url,
        evidence_summary=parsed.evidence_summary,
        plan=plan,
    )


async def _ingest_agent_remediation_evidence(
    *,
    threat_model_id: UUID,
    body: AgentRemediationEvidenceWebhookRequest,
    db: AsyncSession,
    normalized_provider_event: str,
    base_url: str,
) -> AgentRemediationEvidenceWebhookResponse:
    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    plan = build_agent_remediation_plan_response(summary, agent_response, findings)

    action = (
        _find_remediation_action(plan, body.action_id)
        if body.action_id is not None
        else next(
            (
                item
                for item in plan.actions
                if item.source_object_type == body.source_object_type
                and item.source_object_id == body.source_object_id
            ),
            None,
        )
    )
    if action is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    current_finding = _find_security_review_finding(
        findings,
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
    )
    current_record = find_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
    )
    evidence_artifact = _inbound_evidence_artifact(
        action,
        body,
        normalized_provider_event=normalized_provider_event,
    )
    next_artifacts = replace_artifact_of_kind(
        current_record.artifacts
        if current_record is not None
        else current_finding.artifacts,
        evidence_artifact,
    )
    threat_model.review_state = upsert_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=action.source_object_type,
        source_object_id=action.source_object_id,
        update=SecurityReviewStateUpdate(artifacts=next_artifacts),
        current_record=current_record,
    )
    await db.commit()

    refreshed_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    refreshed_agent_response = build_agent_security_review_response(
        summary, refreshed_findings
    )
    refreshed_plan = build_agent_remediation_plan_response(
        summary, refreshed_agent_response, refreshed_findings
    )
    refreshed_plan = _attach_remediation_webhook_setups(
        refreshed_plan, base_url=base_url, threat_model_id=threat_model_id
    )
    return AgentRemediationEvidenceWebhookResponse(
        generated_at=refreshed_plan.generated_at,
        system_name=refreshed_plan.system_name,
        ingested_artifact_count=1,
        updated_finding_ids=[action.finding_id],
        callback_security_status="verified",
        normalized_provider_event=normalized_provider_event,
        plan=refreshed_plan,
    )


async def _build_customer_security_packet(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> CustomerSecurityPacketResponse:
    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)
    reviewable_threats = [threat for threat in threats if threat.status != "Dismissed"]
    summary = build_application_security_review(
        threat_model,
        reviewable_threats,
        nodes,
        edges,
        boundaries,
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    agent_response = build_agent_security_review_response(summary, findings)
    validation_scan_evidence = await _load_customer_packet_validation_scan_evidence(
        db, threat_model_id
    )
    return build_customer_security_packet_response(
        summary,
        findings,
        agent_response,
        scope=_customer_packet_scope(threat_model),
        source_fingerprints=build_customer_packet_source_fingerprints(
            summary=summary,
            findings_response=findings,
            agent_response=agent_response,
            repository_evidence=getattr(threat_model, "repository_evidence", None),
            validation_scan_evidence=validation_scan_evidence,
            cloud_scan_evidence=getattr(threat_model, "cloud_scan_evidence", None),
            iac_evidence=getattr(threat_model, "iac_evidence", None),
        ),
    )


def _assert_customer_packet_export_approval(
    packet: CustomerSecurityPacketResponse,
    *,
    include_source_labels: bool,
    approved_sensitive_labels: bool,
) -> None:
    sensitive_labels = customer_packet_sensitive_source_labels(packet)
    if include_source_labels and sensitive_labels and not approved_sensitive_labels:
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Exporting source labels requires reviewer approval because "
                    "the packet includes repository, PR, cloud, or IaC labels."
                ),
                "sensitive_source_label_count": len(sensitive_labels),
            },
        )


@router.get(
    "/customer-packet",
    response_model=CustomerSecurityPacketResponse,
)
async def get_customer_security_packet(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> CustomerSecurityPacketResponse:
    """Return a customer-safe security review packet for external reviewers."""

    return await _build_customer_security_packet(threat_model_id, db)


@router.get("/customer-packet/export.csv")
async def export_customer_security_packet_csv(
    threat_model_id: UUID,
    include_source_labels: bool = Query(default=False),
    approved_sensitive_labels: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> StreamingResponse:
    """Export the customer-safe security packet as CSV."""

    packet = await _build_customer_security_packet(threat_model_id, db)
    _assert_customer_packet_export_approval(
        packet,
        include_source_labels=include_source_labels,
        approved_sensitive_labels=approved_sensitive_labels,
    )
    filename = f"customer-security-packet-{threat_model_id}.csv"
    return StreamingResponse(
        iter(
            [
                build_customer_packet_csv(
                    packet, include_source_labels=include_source_labels
                )
            ]
        ),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/customer-packet/export.pdf")
async def export_customer_security_packet_pdf(
    threat_model_id: UUID,
    include_source_labels: bool = Query(default=False),
    approved_sensitive_labels: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> Response:
    """Export the customer-safe security packet as PDF."""

    packet = await _build_customer_security_packet(threat_model_id, db)
    _assert_customer_packet_export_approval(
        packet,
        include_source_labels=include_source_labels,
        approved_sensitive_labels=approved_sensitive_labels,
    )
    filename = f"customer-security-packet-{threat_model_id}.pdf"
    return Response(
        content=build_customer_packet_pdf(
            packet, include_source_labels=include_source_labels
        ),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch(
    "/review-findings/{source_object_type}/{source_object_id}",
    response_model=SecurityReviewFinding,
)
async def update_security_review_finding_state(
    threat_model_id: UUID,
    source_object_type: str,
    source_object_id: str,
    body: SecurityReviewStateUpdate,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> SecurityReviewFinding:
    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)

    current_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    current_finding = next(
        (
            item
            for item in current_findings.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if current_finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")

    if source_object_type not in {"threat", "application_review_finding", "manual"}:
        raise HTTPException(status_code=404, detail="Review finding not found")

    if source_object_type == "threat":
        threat = next(
            (item for item in threats if str(item.id) == source_object_id), None
        )
        if threat is None:
            raise HTTPException(status_code=404, detail="Review finding not found")
        if "review_status" in body.model_fields_set:
            raise HTTPException(
                status_code=400,
                detail="Threat lifecycle state must be updated through threat triage.",
            )
        if "owner" in body.model_fields_set:
            threat.mitigation_owner = (body.owner or "").strip() or None
        if "due_at" in body.model_fields_set:
            threat.due_date = (
                datetime.fromisoformat(body.due_at).date() if body.due_at else None
            )
        if "note" in body.model_fields_set:
            threat.mitigation_notes = (body.note or "").strip() or None

    terminal_statuses = {"accepted", "mitigated", "dismissed"}
    current_is_terminal = current_finding.review_status in terminal_statuses

    patch_data = body.model_dump(exclude_unset=True)
    next_status = patch_data.get("review_status")
    if (
        "queue_bucket" in patch_data
        and current_is_terminal
        and next_status not in {"open", "in_progress"}
    ):
        raise HTTPException(
            status_code=400,
            detail="Terminal findings must be reopened before changing queue bucket.",
        )
    if (
        next_status in terminal_statuses
        and current_is_terminal
        and next_status != current_finding.review_status
    ):
        raise HTTPException(
            status_code=400,
            detail="Terminal findings must be reopened before changing terminal state.",
        )

    if next_status in terminal_statuses:
        patch_data["queue_bucket"] = None
        patch_data["last_non_terminal_bucket"] = (
            current_finding.queue_bucket
            or current_finding.last_non_terminal_bucket
            or current_finding.computed_queue_bucket
            or "verify"
        )
    elif next_status in {"open", "in_progress"} and current_is_terminal:
        patch_data["queue_bucket"] = (
            patch_data.get("queue_bucket")
            or current_finding.last_non_terminal_bucket
            or current_finding.computed_queue_bucket
            or "verify"
        )
        reopened_acceptance = _reopened_acceptance_status(
            _expired_acceptance_status(current_finding.risk_acceptance)
        )
        if reopened_acceptance is not None:
            patch_data["risk_acceptance"] = reopened_acceptance

    current_record = find_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
    )
    threat_model.review_state = upsert_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
        update=SecurityReviewStateUpdate(**patch_data),
        current_record=current_record,
    )
    await db.commit()

    findings_response = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    finding = next(
        (
            item
            for item in findings_response.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")
    return finding


@router.post(
    "/review-findings/{source_object_type}/{source_object_id}/risk-acceptance",
    response_model=SecurityReviewFinding,
)
async def accept_security_review_finding_risk(
    threat_model_id: UUID,
    source_object_type: str,
    source_object_id: str,
    body: SecurityReviewRiskAcceptanceRequest,
    db: AsyncSession = Depends(get_db),
    owner: User = Depends(_require_review_access),
) -> SecurityReviewFinding:
    """Persist governed accepted-risk state for a review finding."""

    if source_object_type == "threat":
        raise HTTPException(
            status_code=400,
            detail="Threat risk acceptance must be handled through threat triage.",
        )
    if source_object_type not in {"application_review_finding", "manual"}:
        raise HTTPException(status_code=404, detail="Review finding not found")

    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)

    current_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    current_finding = next(
        (
            item
            for item in current_findings.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if current_finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")

    accepted_by = body.accepted_by or _reviewer_display_name(owner)
    acceptance = SecurityReviewRiskAcceptance(
        finding_title=current_finding.title,
        status="active",
        accepted_by=accepted_by,
        accepted_at=datetime.now(timezone.utc).isoformat(),
        expires_at=body.expires_at,
        acceptance_rationale=body.acceptance_rationale,
        compensating_control=body.compensating_control,
    )
    last_non_terminal_bucket = (
        current_finding.queue_bucket
        or current_finding.last_non_terminal_bucket
        or current_finding.computed_queue_bucket
        or "verify"
    )
    current_record = find_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
    )
    threat_model.review_state = upsert_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
        update=SecurityReviewStateUpdate(
            review_status="accepted",
            queue_bucket=None,
            last_non_terminal_bucket=last_non_terminal_bucket,
            owner=accepted_by,
            note=body.acceptance_rationale,
            risk_acceptance=acceptance,
        ),
        current_record=current_record,
    )
    await db.commit()

    findings_response = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    finding = next(
        (
            item
            for item in findings_response.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")
    return finding


@router.post(
    "/review-findings/{source_object_type}/{source_object_id}/artifacts",
    response_model=SecurityReviewFinding,
)
async def create_security_review_artifact(
    threat_model_id: UUID,
    source_object_type: str,
    source_object_id: str,
    body: SecurityReviewArtifactCreate,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_review_access),
) -> SecurityReviewFinding:
    (
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        scan_status_by_threat_id,
        intel_by_threat_id,
    ) = await _load_security_review_inputs(db, threat_model_id, include_intel=True)

    findings_response = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    current_finding = next(
        (
            item
            for item in findings_response.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if current_finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")

    related_threat = (
        next(
            (item for item in threats if str(item.id) == current_finding.threat_id),
            None,
        )
        if current_finding.threat_id is not None
        else None
    )
    artifact = build_security_review_artifact(
        current_finding,
        kind=body.kind,
        threat=_hydrate_threat_response(related_threat)
        if related_threat is not None
        else None,
    )

    current_record = find_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
    )
    next_artifacts = replace_artifact_of_kind(
        current_record.artifacts
        if current_record is not None
        else current_finding.artifacts,
        artifact,
    )
    threat_model.review_state = upsert_review_state_record(
        getattr(threat_model, "review_state", None),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
        update=SecurityReviewStateUpdate(artifacts=next_artifacts),
        current_record=current_record,
    )
    await db.commit()

    refreshed_findings = build_security_review_findings(
        threat_model,
        threats,
        nodes,
        edges,
        boundaries,
        review_state=normalize_review_state_records(
            getattr(threat_model, "review_state", None)
        ),
        intel_by_threat_id=intel_by_threat_id,
        scan_status_by_threat_id=scan_status_by_threat_id,
    )
    finding = next(
        (
            item
            for item in refreshed_findings.findings
            if item.source_object_type == source_object_type
            and item.source_object_id == source_object_id
        ),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Review finding not found")
    return finding


@router.patch("/threats/{threat_id}/triage", response_model=ThreatResponse)
async def triage_threat(
    threat_model_id: UUID,
    threat_id: UUID,
    body: ThreatTriageRequest,
    _owner: User = Depends(_require_review_access),
    db: AsyncSession = Depends(get_db),
) -> ThreatResponse:
    """Accept or dismiss a threat (triage)."""
    # 1. Verify threat model exists
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # 2. Load the threat by ID + threat_model_id
    result = await db.execute(
        select(Threat).where(
            Threat.id == threat_id,
            Threat.threat_model_id == threat_model_id,
        )
    )
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    # 3. Validate: if Dismissed, dismiss_reason is required
    if body.status == "Dismissed" and not body.dismiss_reason:
        raise HTTPException(
            status_code=400,
            detail="dismiss_reason is required when status is Dismissed",
        )
    if body.risk_acceptance is not None and body.status != "Accepted":
        raise HTTPException(
            status_code=400,
            detail="risk_acceptance can only be submitted with Accepted status",
        )
    triage_reason = (
        body.risk_acceptance.acceptance_rationale
        if body.risk_acceptance is not None
        else body.dismiss_reason
        or body.mitigation_notes
        or f"Status changed to {body.status}"
    )

    # 4. Capture old values before updating
    old_status = threat.status
    old_severity = threat.severity
    old_mitigation_owner = threat.mitigation_owner
    old_control_effectiveness = normalize_control_effectiveness(
        getattr(threat, "control_effectiveness", None)
    )

    # 5. Update status and dismiss_reason
    threat.status = body.status
    if body.severity is not None:
        threat.severity = body.severity
    if body.status == "Accepted":
        threat.dismiss_reason = None
    else:
        threat.dismiss_reason = body.dismiss_reason

    # 6. Update mitigation fields if provided
    if body.mitigation_plan is not None:
        threat.mitigation_plan = body.mitigation_plan
    if body.mitigation_owner is not None:
        threat.mitigation_owner = body.mitigation_owner
    if body.due_date is not None:
        threat.due_date = body.due_date
    if body.mitigation_notes is not None:
        threat.mitigation_notes = body.mitigation_notes
    if body.control_effectiveness is not None:
        threat.control_effectiveness = body.control_effectiveness
    if body.risk_acceptance is not None:
        accepted_by = body.risk_acceptance.accepted_by or _reviewer_display_name(_owner)
        threat.dismiss_reason = body.risk_acceptance.acceptance_rationale
        threat.false_positive_reason = "accepted_risk"
        threat.mitigation_owner = accepted_by
        threat.due_date = _parse_risk_acceptance_expiry(body.risk_acceptance.expires_at)
        threat.mitigation_notes = body.risk_acceptance.acceptance_rationale
        if body.risk_acceptance.compensating_control is not None:
            threat.mitigation_plan = body.risk_acceptance.compensating_control
    current_control_effectiveness = getattr(threat, "control_effectiveness", None)
    current_residual_risk_level = getattr(threat, "residual_risk_level", None)
    if body.residual_risk_level is not None:
        threat.residual_risk_level = body.residual_risk_level
    elif (
        body.control_effectiveness is not None
        or body.severity is not None
        or not current_residual_risk_level
    ):
        threat.residual_risk_level = derive_residual_risk_level(
            threat.severity,
            current_control_effectiveness,
        )

    # 7. Auto-manage closed_at based on status
    now = datetime.now(timezone.utc)
    if body.status in ("Mitigated", "Accepted", "Dismissed"):
        threat.closed_at = now
    elif body.status in ("Open", "In Progress"):
        threat.closed_at = None

    # 8. Create audit log entry in the same transaction
    audit_entry = ThreatAuditLog(
        threat_id=threat_id,
        threat_model_id=threat_model_id,
        user_id=_owner.id,
        action="triaged",
        old_status=old_status,
        new_status=body.status,
        reason=triage_reason,
    )
    db.add(audit_entry)

    # 9. Audit log for mitigation_owner assignment changes
    if (
        body.mitigation_owner is not None
        and body.mitigation_owner != old_mitigation_owner
    ):
        owner_audit = ThreatAuditLog(
            threat_id=threat_id,
            threat_model_id=threat_model_id,
            user_id=_owner.id,
            action="mitigation_assigned",
            old_status=old_status,
            new_status=body.status,
            reason=f"Assigned to: {body.mitigation_owner}",
        )
        db.add(owner_audit)

    if (
        body.control_effectiveness is not None
        and body.control_effectiveness != old_control_effectiveness
    ):
        control_audit = ThreatAuditLog(
            threat_id=threat_id,
            threat_model_id=threat_model_id,
            user_id=_owner.id,
            action="control_effectiveness_updated",
            old_status=old_status,
            new_status=body.status,
            reason=f"{old_control_effectiveness} -> {body.control_effectiveness}",
        )
        db.add(control_audit)

    if body.severity is not None and body.severity != old_severity:
        severity_audit = ThreatAuditLog(
            threat_id=threat_id,
            threat_model_id=threat_model_id,
            user_id=_owner.id,
            action="severity_updated",
            old_status=old_severity,
            new_status=body.severity,
            reason=f"{old_severity} -> {body.severity}",
        )
        db.add(severity_audit)

    await db.commit()
    await db.refresh(threat)

    # 7. Populate compliance controls and return
    controls_map = await lookup_controls_batch(db, [threat])
    return _hydrate_threat_response(threat, controls_map)


@router.post("/threats/bulk-triage", response_model=list[ThreatResponse])
async def bulk_triage_threats(
    threat_model_id: UUID,
    body: BulkTriageRequest,
    _owner: User = Depends(_require_review_access),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatResponse]:
    """Bulk accept or dismiss multiple threats at once."""
    if not body.threat_ids:
        raise HTTPException(status_code=400, detail="threat_ids must not be empty")

    if body.status == "Dismissed" and not body.dismiss_reason:
        raise HTTPException(
            status_code=400,
            detail="dismiss_reason is required when status is Dismissed",
        )
    triage_reason = body.dismiss_reason or f"Status changed to {body.status}"

    # Advisory lock: prevent race with concurrent analyze (which deletes+recreates threats)
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": threat_model_id.int % (2**63)},
    )

    # Load all threats in one query
    result = await db.execute(
        select(Threat).where(
            Threat.id.in_(body.threat_ids),
            Threat.threat_model_id == threat_model_id,
        )
    )
    threats = result.scalars().all()

    if len(threats) != len(body.threat_ids):
        raise HTTPException(status_code=404, detail="One or more threats not found")

    _TERMINAL_STATUSES = {"Mitigated", "Accepted", "Dismissed"}
    now = datetime.now(timezone.utc)

    # Update all and create audit entries
    for threat in threats:
        old_status = threat.status
        threat.status = body.status
        threat.dismiss_reason = (
            body.dismiss_reason if body.status == "Dismissed" else None
        )
        if body.status in _TERMINAL_STATUSES:
            if threat.closed_at is None:
                threat.closed_at = now
        else:
            threat.closed_at = None

        audit_entry = ThreatAuditLog(
            threat_id=threat.id,
            threat_model_id=threat_model_id,
            user_id=_owner.id,
            action="triaged",
            old_status=old_status,
            new_status=body.status,
            reason=triage_reason,
        )
        db.add(audit_entry)

    await db.commit()

    # Refresh and build response
    responses: list[ThreatResponse] = []
    controls_map = await lookup_controls_batch(db, threats)
    for threat in threats:
        await db.refresh(threat)
        responses.append(_hydrate_threat_response(threat, controls_map))

    return responses


@router.get("/threats/{threat_id}/history", response_model=list[ThreatAuditEntry])
async def get_threat_history(
    threat_model_id: UUID,
    threat_id: UUID,
    _owner: User = Depends(_require_read_access),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatAuditEntry]:
    """Return audit trail for a specific threat, ordered by most recent first."""
    # Verify threat exists and belongs to this threat model
    threat_result = await db.execute(
        select(Threat).where(
            Threat.id == threat_id,
            Threat.threat_model_id == threat_model_id,
        )
    )
    if threat_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Query audit logs joined with User for email
    result = await db.execute(
        select(ThreatAuditLog)
        .where(
            ThreatAuditLog.threat_id == threat_id,
            ThreatAuditLog.threat_model_id == threat_model_id,
        )
        .order_by(ThreatAuditLog.created_at.desc())
    )
    logs = result.scalars().all()

    return [
        ThreatAuditEntry(
            id=log.id,
            action=log.action,
            old_status=log.old_status,
            new_status=log.new_status,
            reason=log.reason,
            changed_by=log.user.email,
            changed_at=log.created_at,
        )
        for log in logs
    ]


@router.patch("/threats/{threat_id}/qualify", response_model=ThreatResponse)
async def qualify_threat(
    threat_model_id: UUID,
    threat_id: UUID,
    body: ThreatQualifyRequest,
    current_user: User = Depends(_require_review_access),
    db: AsyncSession = Depends(get_db),
) -> ThreatResponse:
    """Atomic qualification: set analyst score, action, and optional note in one transaction."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": threat_model_id.int % (2**63)},
    )

    result = await db.execute(
        select(Threat).where(
            Threat.id == threat_id,
            Threat.threat_model_id == threat_model_id,
        )
    )
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Record analyst assessment
    threat.analyst_score = body.analyst_score
    threat.analyst_score_rationale = body.analyst_score_rationale
    if body.qualification_note is not None:
        threat.qualification_note = body.qualification_note or None

    # Blend scores: auto 40% / analyst 60%
    auto = (
        threat.auto_score
        if threat.auto_score is not None
        else (threat.qualification_score or 0)
    )
    threat.qualification_score = blend_scores(auto, body.analyst_score)

    # Apply action atomically
    from datetime import timezone as _tz

    now = datetime.now(_tz.utc)
    previous_status = threat.status  # capture before any mutation
    if body.action == "dismiss":
        threat.status = "Dismissed"
        threat.false_positive_reason = body.false_positive_reason
        threat.dismiss_reason = body.analyst_score_rationale
        threat.closed_at = now
        threat.qualification_completed_at = now
    elif body.action == "confirm":
        # Keep existing status (Open → In Progress is a triage action, not qualify)
        threat.qualification_completed_at = now
    # 'defer' leaves status unchanged and does NOT stamp qualification_completed_at
    # so the threat remains in the queue for a future session

    # Audit log
    audit_reason = body.analyst_score_rationale or (
        f"False-positive reason: {body.false_positive_reason}"
        if body.action == "dismiss" and body.false_positive_reason
        else f"Qualification action: {body.action}"
    )
    db.add(
        ThreatAuditLog(
            threat_id=threat.id,
            threat_model_id=threat_model_id,
            user_id=current_user.id,
            action="qualified",
            old_status=previous_status,
            new_status=threat.status,
            reason=audit_reason,
        )
    )

    await db.commit()
    await db.refresh(threat)

    controls_map = await lookup_controls_batch(db, [threat])
    return _hydrate_threat_response(threat, controls_map)


@router.post("/clusters/compute", response_model=list[ThreatClusterResponse])
async def recompute_clusters(
    threat_model_id: UUID,
    _owner: User = Depends(_require_review_access),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatClusterResponse]:
    """Recompute threat clusters for this model on demand."""
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # Build DFD response
    from app.api.dfd import _load_dfd_response

    dfd_response = await _load_dfd_response(db, threat_model_id)

    threats_result = await db.execute(
        select(Threat).where(Threat.threat_model_id == threat_model_id)
    )
    threats = threats_result.scalars().all()

    await _recompute_clusters(db, threat_model_id, threats, dfd_response)

    clusters_result = await db.execute(
        select(ThreatCluster).where(ThreatCluster.threat_model_id == threat_model_id)
    )
    return [
        ThreatClusterResponse.model_validate(c) for c in clusters_result.scalars().all()
    ]


@router.get("/clusters", response_model=list[ThreatClusterResponse])
async def list_clusters(
    threat_model_id: UUID,
    _owner: User = Depends(_require_read_access),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatClusterResponse]:
    """List all clusters for this threat model."""
    result = await db.execute(
        select(ThreatCluster).where(ThreatCluster.threat_model_id == threat_model_id)
    )
    return [ThreatClusterResponse.model_validate(c) for c in result.scalars().all()]


@router.get("/qualification/progress", response_model=QualificationProgressResponse)
async def qualification_progress(
    threat_model_id: UUID,
    _owner: User = Depends(_require_read_access),
    db: AsyncSession = Depends(get_db),
) -> QualificationProgressResponse:
    """Return qualification progress computed from threat state (no session table)."""
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # Only count threats that are in the qualification queue (Open/In Progress).
    # Threats dismissed via old triage (no qualification_completed_at) are excluded
    # so they don't inflate total without being counted as qualified.
    threats_result = await db.execute(
        select(Threat).where(
            Threat.threat_model_id == threat_model_id,
            Threat.status.in_(["Open", "In Progress"]),
        )
    )
    threats = threats_result.scalars().all()

    qualified = sum(1 for t in threats if t.qualification_completed_at is not None)
    total = len(threats)
    progress_pct = round(qualified / total * 100, 1) if total > 0 else 0.0

    clusters_result = await db.execute(
        select(ThreatCluster).where(ThreatCluster.threat_model_id == threat_model_id)
    )
    clusters = clusters_result.scalars().all()

    # A cluster is "resolved" if its representative has been qualified
    threat_map = {t.id: t for t in threats}
    clusters_resolved = sum(
        1
        for c in clusters
        if c.representative_threat_id
        and threat_map.get(c.representative_threat_id) is not None
        and threat_map[c.representative_threat_id].qualification_completed_at
        is not None
    )

    return QualificationProgressResponse(
        threat_model_id=threat_model_id,
        total_open=total,
        qualified=qualified,
        unqualified=total - qualified,
        progress_pct=progress_pct,
        cluster_count=len(clusters),
        clusters_resolved=clusters_resolved,
    )


@router.get("/qualification/next", response_model=ThreatResponse | None)
async def qualification_next(
    threat_model_id: UUID,
    _owner: User = Depends(_require_review_access),
    db: AsyncSession = Depends(get_db),
) -> ThreatResponse | None:
    """Return the next unqualified threat in triage queue order.

    Queue ordering:
    1. Unqualified (qualification_completed_at IS NULL)
    2. Unclustered threats first (cluster_id IS NULL) — must be reviewed individually
    3. Within group: highest qualification_score descending
    4. Stable secondary: display_id ascending

    Advisory lock ensures concurrent analysts don't race on the same threat.
    """
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": threat_model_id.int % (2**63)},
    )

    result = await db.execute(
        select(Threat).where(
            Threat.threat_model_id == threat_model_id,
            Threat.status.in_(["Open", "In Progress"]),
            Threat.qualification_completed_at.is_(None),
        )
    )
    candidates = result.scalars().all()
    if not candidates:
        return None

    # Sort: unclustered first, then by score desc, then display_id asc
    def _sort_key(t: Threat):
        is_clustered = 0 if t.cluster_id is None else 1
        score = -(t.qualification_score or 0)
        return (is_clustered, score, t.display_id)

    candidates.sort(key=_sort_key)
    threat = candidates[0]

    controls_map = await lookup_controls_batch(db, [threat])
    return _hydrate_threat_response(threat, controls_map)


@router.post("/threat-diff", response_model=ThreatDiffResponse)
async def threat_diff(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_read_access),
) -> ThreatDiffResponse:
    """Compare the last analyzed threats snapshot to current DFD state.

    Runs the rules engine (no AI) against the current DFD and diffs
    against the stored snapshot from the last /analyze run.
    """
    from app.schemas.threat import ThreatDiffSummary

    # 1. Load the threat model
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    baseline = threat_model.last_analyzed_threats

    # 2. If no baseline, return empty diff with has_baseline=False
    if baseline is None:
        return ThreatDiffResponse(
            added=[],
            removed=[],
            counts={"added": 0, "removed": 0, "total_before": 0, "total_after": 0},
            has_baseline=False,
        )

    # 3. Load current DFD
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    nodes = nodes_result.scalars().all()

    if not nodes:
        # No DFD means no current threats — everything in baseline is "removed"
        diff_result = diff_threat_lists(baseline, [])
        return ThreatDiffResponse(
            added=[
                ThreatDiffSummary(
                    rule_id=s["rule_id"],
                    stride_category=s["stride_category"],
                    severity=s["severity"],
                    description=s["description_snippet"],
                )
                for s in diff_result["added"]
            ],
            removed=[
                ThreatDiffSummary(
                    rule_id=s["rule_id"],
                    stride_category=s["stride_category"],
                    severity=s["severity"],
                    description=s["description_snippet"],
                )
                for s in diff_result["removed"]
            ],
            counts=diff_result["counts"],
            has_baseline=True,
        )

    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    edges = edges_result.scalars().all()

    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    boundaries = boundaries_result.scalars().all()

    dfd_response = DFDResponse(
        nodes=[DFDNodeResponse.model_validate(n) for n in nodes],
        edges=[DFDEdgeResponse.model_validate(e) for e in edges],
        trust_boundaries=[
            TrustBoundaryResponse.model_validate(tb) for tb in boundaries
        ],
    )

    # 4. Run rules engine (deterministic, no AI)
    rules_output = evaluate_rules(dfd_response)

    # 5. Serialize current threats to dicts for comparison
    current_threats = [
        {
            "rule_id": gt.rule_id,
            "stride_category": gt.stride_category,
            "threat_subtype": gt.threat_subtype,
            "severity": gt.severity,
            "description": gt.description,
            "affected_node_ids": [str(nid) for nid in gt.affected_node_ids],
            "affected_edge_ids": [str(eid) for eid in gt.affected_edge_ids],
        }
        for gt in rules_output.threats
    ]

    # 6. Diff
    diff_result = diff_threat_lists(baseline, current_threats)

    return ThreatDiffResponse(
        added=[
            ThreatDiffSummary(
                rule_id=s["rule_id"],
                stride_category=s["stride_category"],
                severity=s["severity"],
                description=s["description_snippet"],
            )
            for s in diff_result["added"]
        ],
        removed=[
            ThreatDiffSummary(
                rule_id=s["rule_id"],
                stride_category=s["stride_category"],
                severity=s["severity"],
                description=s["description_snippet"],
            )
            for s in diff_result["removed"]
        ],
        counts=diff_result["counts"],
        has_baseline=True,
    )
