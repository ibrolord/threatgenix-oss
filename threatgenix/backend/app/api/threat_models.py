import base64 as _b64
import hashlib
import json
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDQualityGateSummary,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.report import ReportConfigUpdate, ReportRequest
from app.schemas.threat_model import (
    AttackPathResponse,
    ArchitectureValidationSummary,
    ThreatModelAssignmentCreate,
    ThreatModelAssignmentResponse,
    ThreatModelAssignmentUpdate,
    ThreatModelAssumptionSummary,
    ThreatModelControlCreate,
    ThreatModelControlResponse,
    ThreatModelCoverageSummary,
    ThreatModelControlSummary,
    ThreatModelControlUpdate,
    ThreatModelCollaboratorCreate,
    ThreatModelCollaboratorResponse,
    ThreatModelCollaboratorUpdate,
    ThreatModelCollaborationSummary,
    ThreatModelAssumptionCreate,
    ThreatModelAssumptionResponse,
    ThreatModelAssumptionUpdate,
    ThreatModelCreate,
    ThreatModelListItem,
    ThreatModelNotificationResponse,
    ThreatModelNotificationUpdate,
    ThreatModelMitigationSummary,
    ThreatModelReviewCommentResponse,
    ThreatModelReviewCreate,
    ThreatModelReviewFreshnessSummary,
    ThreatModelReviewResponse,
    ThreatModelReviewSummary,
    ThreatModelReviewUpdate,
    ThreatModelResponse,
    ThreatModelScorecardResponse,
    ThreatModelVersionCreate,
    ThreatModelVersionDiffRequest,
    ThreatModelVersionDiffResponse,
    ThreatModelVersionResponse,
)
from app.schemas.tmac import (
    TMACContentRequest,
    TMACDiffRequest,
    TMACDiffResponse,
    TMACFormat,
    TMACImportRequest,
    TMACImportMode,
    TMACImportResponse,
    TMACValidationResponse,
)
from app.services.attack_paths import derive_attack_paths
from app.services.auth import get_current_user
from app.services.dfd_quality_gates import evaluate_quality_gates
from app.services.dfd_views import load_view_responses, sync_default_views
from app.services.entitlement import check_org_entitlement
from app.services.model_collaboration import (
    build_assignment_comment,
    build_collaboration_summary,
    create_notification,
    normalize_assignments,
    normalize_collaborators,
    normalize_notifications,
    require_model_permission,
)
from app.services.model_governance import (
    build_architecture_validation_summary,
    build_coverage_summary,
    build_current_snapshot_record,
    build_current_snapshot_payload,
    build_review_freshness_summary,
    build_snapshot_diff,
    build_snapshot_record,
    load_current_dfd,
    load_current_threat_snapshot,
    normalize_control_library,
    normalize_model_snapshots,
    normalize_review_records,
)
from app.services.pdf_report import generate_report
from app.services.report_templates import (
    get_report_template,
    list_report_templates,
    serialize_custom_report_templates,
)
from app.services.residual_risk import build_residual_risk_summary
from app.services.tmac import (
    build_tmac_document,
    build_tmac_scaffold,
    build_tmac_validation_response,
    diff_tmac_against_model,
    import_tmac_document,
    serialize_tmac_document,
)
from app.services.threat_model import (
    create_threat_model,
    get_threat_model,
    list_threat_models,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threat-models", tags=["threat-models"])


def _serialize_threat_model_response(threat_model: ThreatModel) -> ThreatModelResponse:
    if getattr(threat_model, "report_templates", None) is None:
        threat_model.report_templates = []
    response = ThreatModelResponse.model_validate(threat_model)
    return response.model_copy(
        update={
            "organization_name": getattr(getattr(threat_model, "organization", None), "name", None)
            or getattr(getattr(getattr(threat_model, "owner", None), "organization", None), "name", None),
            "report_templates": list_report_templates(
                getattr(threat_model, "report_templates", None)
            )
        }
    )


async def _verify_ownership(
    db: AsyncSession, threat_model_id: UUID, user: User
) -> None:
    """Backward-compatible write check for model routes."""
    await _require_model_permission(db, threat_model_id, user, "write")


async def _require_model_permission(
    db: AsyncSession,
    threat_model_id: UUID,
    user: User,
    permission: str,
) -> ThreatModel:
    tm = await get_threat_model(db, threat_model_id)
    return require_model_permission(tm, user, permission)  # type: ignore[arg-type]


def _normalize_assumptions(raw_assumptions: list[dict] | None) -> list[ThreatModelAssumptionResponse]:
    normalized: list[ThreatModelAssumptionResponse] = []
    for item in raw_assumptions or []:
        try:
            normalized.append(ThreatModelAssumptionResponse.model_validate(item))
        except Exception:
            continue
    return sorted(normalized, key=lambda item: item.updated_at, reverse=True)


def _build_assumption_summary(
    assumptions: list[ThreatModelAssumptionResponse],
) -> ThreatModelAssumptionSummary:
    return ThreatModelAssumptionSummary(
        total=len(assumptions),
        open=sum(1 for item in assumptions if item.status == "open"),
        validated=sum(1 for item in assumptions if item.status == "validated"),
        challenged=sum(1 for item in assumptions if item.status == "challenged"),
    )


def _build_mitigation_summary(threats: list[dict]) -> ThreatModelMitigationSummary:
    active_statuses = {"Open", "In Progress"}
    active_threats = [threat for threat in threats if threat.get("status") in active_statuses]
    return ThreatModelMitigationSummary(
        total=len(threats),
        active=len(active_threats),
        mitigated=sum(1 for threat in threats if threat.get("status") == "Mitigated"),
        accepted=sum(1 for threat in threats if threat.get("status") == "Accepted"),
        dismissed=sum(1 for threat in threats if threat.get("status") == "Dismissed"),
        with_plan=sum(1 for threat in active_threats if threat.get("mitigation_plan")),
        with_owner=sum(1 for threat in active_threats if threat.get("mitigation_owner")),
        with_due_date=sum(1 for threat in active_threats if threat.get("due_date")),
        with_residual_risk=sum(1 for threat in threats if threat.get("residual_risk_level")),
    )


def _build_control_summary(
    controls: list[ThreatModelControlResponse],
) -> ThreatModelControlSummary:
    return ThreatModelControlSummary(
        total=len(controls),
        planned=sum(1 for control in controls if control.status == "planned"),
        implemented=sum(1 for control in controls if control.status == "implemented"),
        partial=sum(1 for control in controls if control.status == "partial"),
        deferred=sum(1 for control in controls if control.status == "deferred"),
        with_evidence=sum(1 for control in controls if control.evidence),
        mapped_to_threats=sum(1 for control in controls if control.mapped_threat_ids),
        with_owner=sum(1 for control in controls if control.owner),
    )


def _build_review_summary(
    reviews: list[ThreatModelReviewResponse],
) -> ThreatModelReviewSummary:
    latest = reviews[0] if reviews else None
    return ThreatModelReviewSummary(
        total=len(reviews),
        pending=sum(1 for review in reviews if review.status == "pending"),
        approved=sum(1 for review in reviews if review.status == "approved"),
        changes_requested=sum(1 for review in reviews if review.status == "changes_requested"),
        latest_status=latest.status if latest is not None else None,
        latest_title=latest.title if latest is not None else None,
        latest_updated_at=latest.updated_at if latest is not None else None,
    )


def _build_scorecard_actions(
    *,
    validation: ArchitectureValidationSummary,
    coverage: ThreatModelCoverageSummary,
    quality: DFDQualityGateSummary,
    assumptions: ThreatModelAssumptionSummary,
    mitigations: ThreatModelMitigationSummary,
    controls: ThreatModelControlSummary,
    reviews: ThreatModelReviewSummary,
    review_freshness: ThreatModelReviewFreshnessSummary,
    collaboration: ThreatModelCollaborationSummary,
) -> list[str]:
    actions: list[str] = []

    unmapped_components = len(validation.unmapped_repository_components) + len(validation.unmapped_cloud_services)
    unresolved_assumptions = assumptions.open + assumptions.challenged
    active_without_plan = max(mitigations.active - mitigations.with_plan, 0)
    active_without_owner = max(mitigations.active - mitigations.with_owner, 0)
    uncovered_nodes = coverage.nodes.without_stride_coverage
    uncovered_edges = coverage.edges.without_stride_coverage
    uncovered_boundaries = coverage.boundaries.without_stride_coverage

    if quality.blocking_count > 0:
        actions.append(f"Resolve {quality.blocking_count} blocking DFD quality gate(s).")
    if active_without_plan > 0:
        actions.append(f"Add mitigation plans for {active_without_plan} active threat(s).")
    if active_without_owner > 0:
        actions.append(f"Assign owners to {active_without_owner} active threat(s).")
    if review_freshness.status == "stale":
        actions.append("The current model changed after the last approved snapshot. Save a fresh snapshot and rerun review.")
    elif review_freshness.status == "changes_requested":
        actions.append("Address review feedback before treating this model as signed off.")
    elif review_freshness.status == "pending":
        actions.append(f"Close {reviews.pending} pending review(s).")
    elif review_freshness.status == "unreviewed":
        actions.append("Create a snapshot and run a formal review before publishing this model.")
    if quality.warning_count > 0:
        actions.append(f"Work through {quality.warning_count} warning-level DFD quality gate(s).")
    if unmapped_components > 0:
        actions.append(f"Map {unmapped_components} discovered component(s) that are still missing from the model.")
    if validation.nodes_without_scan_targets:
        actions.append(
            f"Add scan targets or validation evidence for {len(validation.nodes_without_scan_targets)} modeled runtime node(s)."
        )
    if validation.unvalidated_threats:
        actions.append(f"Validate or close {len(validation.unvalidated_threats)} threat(s) still lacking evidence.")
    if unresolved_assumptions > 0:
        actions.append(f"Review {unresolved_assumptions} unresolved assumption(s).")
    if uncovered_nodes > 0:
        actions.append(f"Add STRIDE coverage to {uncovered_nodes} node(s) that still have no mapped threats.")
    if uncovered_edges > 0:
        actions.append(f"Add STRIDE coverage to {uncovered_edges} flow(s) that still have no mapped threats.")
    if uncovered_boundaries > 0:
        actions.append(f"Review {uncovered_boundaries} trust boundary/boundaries with no mapped STRIDE coverage yet.")
    if coverage.missing_stride_categories:
        preview = ", ".join(coverage.missing_stride_categories[:3])
        suffix = "..." if len(coverage.missing_stride_categories) > 3 else ""
        actions.append(
            f"Check whether the model still needs coverage for missing STRIDE categories: {preview}{suffix}."
        )
    if controls.total > 0 and controls.with_evidence < controls.total:
        actions.append(f"Attach evidence to {controls.total - controls.with_evidence} control(s).")
    if collaboration.open_assignments > 0:
        actions.append(f"Close or re-scope {collaboration.open_assignments} open collaboration assignment(s).")
    if collaboration.unread_notifications > 0:
        actions.append(f"Review {collaboration.unread_notifications} unread notification(s) in the collaboration feed.")

    deduped: list[str] = []
    for action in actions:
        if action not in deduped:
            deduped.append(action)
    return deduped


def _derive_scorecard_status(
    *,
    validation: ArchitectureValidationSummary,
    coverage: ThreatModelCoverageSummary,
    quality: DFDQualityGateSummary,
    assumptions: ThreatModelAssumptionSummary,
    mitigations: ThreatModelMitigationSummary,
    reviews: ThreatModelReviewSummary,
    review_freshness: ThreatModelReviewFreshnessSummary,
) -> tuple[str, str]:
    unresolved_assumptions = assumptions.open + assumptions.challenged
    active_without_plan = max(mitigations.active - mitigations.with_plan, 0)
    uncovered_elements = (
        coverage.nodes.without_stride_coverage
        + coverage.edges.without_stride_coverage
        + coverage.boundaries.without_stride_coverage
    )
    materially_uncovered = (
        coverage.total_elements > 0
        and uncovered_elements >= max(3, (coverage.total_elements + 1) // 2)
    )

    if review_freshness.status == "stale":
        return (
            "action_required",
            "The current model no longer matches the last approved review snapshot. Re-review it before treating it as signed off.",
        )

    if review_freshness.status == "changes_requested":
        return (
            "action_required",
            "The latest formal review requested changes. Resolve them before relying on this model as complete.",
        )

    if (
        quality.blocking_count > 0
        or validation.completeness_score < 60
        or active_without_plan > 0
        or materially_uncovered
    ):
        return (
            "action_required",
            "The model is not review-ready yet. Clear the blockers below before relying on it as a signed-off artifact.",
        )

    if (
        quality.warning_count > 0
        or validation.completeness_score < 80
        or unresolved_assumptions > 0
        or reviews.pending > 0
        or mitigations.active > 0
        or uncovered_elements > 0
        or bool(coverage.missing_stride_categories)
        or review_freshness.status in {"pending", "unreviewed"}
    ):
        return (
            "attention",
            "The model is useful, but important coverage or review evidence is still incomplete.",
        )

    return (
        "good",
        "The model is in strong shape. Keep the evidence current as the design changes.",
    )


async def _ensure_anchor_exists(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    anchor_kind: str,
    anchor_id: UUID,
) -> None:
    if anchor_kind == "node":
        result = await db.execute(
            select(DFDNode.id).where(
                DFDNode.id == anchor_id,
                DFDNode.threat_model_id == threat_model_id,
            )
        )
    elif anchor_kind == "edge":
        result = await db.execute(
            select(DFDEdge.id).where(
                DFDEdge.id == anchor_id,
                DFDEdge.threat_model_id == threat_model_id,
            )
        )
    elif anchor_kind == "boundary":
        result = await db.execute(
            select(TrustBoundary.id).where(
                TrustBoundary.id == anchor_id,
                TrustBoundary.threat_model_id == threat_model_id,
            )
        )
    else:
        raise HTTPException(status_code=422, detail="Unsupported assumption anchor kind")

    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=404,
            detail=f"{anchor_kind.title()} anchor not found for this threat model",
        )


def _fallback_anchor_label(anchor_kind: str, anchor_id: UUID) -> str:
    return f"{anchor_kind.title()} {str(anchor_id)[:8]}"


def _replace_json_record(items: list[dict], record_id: UUID, replacement: dict) -> list[dict]:
    return [
        replacement if str(item.get("id")) == str(record_id) else item
        for item in items
    ]


def _snapshot_dict_or_404(raw_snapshots: list[dict] | None, snapshot_id: UUID) -> dict:
    for item in raw_snapshots or []:
        if str(item.get("id")) == str(snapshot_id):
            return item
    raise HTTPException(status_code=404, detail="Snapshot not found")


def _control_dict_or_404(raw_controls: list[dict] | None, control_id: UUID) -> dict:
    for item in raw_controls or []:
        if str(item.get("id")) == str(control_id):
            return item
    raise HTTPException(status_code=404, detail="Control not found")


def _review_dict_or_404(raw_reviews: list[dict] | None, review_id: UUID) -> dict:
    for item in raw_reviews or []:
        if str(item.get("id")) == str(review_id):
            return item
    raise HTTPException(status_code=404, detail="Review not found")


def _collaborator_dict_or_404(raw_collaborators: list[dict] | None, collaborator_id: UUID) -> dict:
    for item in raw_collaborators or []:
        if str(item.get("id")) == str(collaborator_id):
            return item
    raise HTTPException(status_code=404, detail="Collaborator not found")


def _assignment_dict_or_404(raw_assignments: list[dict] | None, assignment_id: UUID) -> dict:
    for item in raw_assignments or []:
        if str(item.get("id")) == str(assignment_id):
            return item
    raise HTTPException(status_code=404, detail="Assignment not found")


def _notification_dict_or_404(raw_notifications: list[dict] | None, notification_id: UUID) -> dict:
    for item in raw_notifications or []:
        if str(item.get("id")) == str(notification_id):
            return item
    raise HTTPException(status_code=404, detail="Notification not found")


def _serialize_threat_model_response(threat_model: ThreatModel) -> ThreatModelResponse:
    if getattr(threat_model, "report_templates", None) is None:
        threat_model.report_templates = []
    response = ThreatModelResponse.model_validate(threat_model)
    return response.model_copy(
        update={
            "report_templates": list_report_templates(
                getattr(threat_model, "report_templates", None)
            )
        }
    )


@router.post("", response_model=ThreatModelResponse, status_code=201)
async def create_threat_model_endpoint(
    data: ThreatModelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelResponse:
    threat_model = await create_threat_model(
        db,
        data,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )
    return _serialize_threat_model_response(threat_model)


@router.get("", response_model=list[ThreatModelListItem])
async def list_threat_models_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelListItem]:
    return await list_threat_models(
        db,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
    )


@router.get("/{threat_model_id}", response_model=ThreatModelResponse)
async def get_threat_model_endpoint(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return _serialize_threat_model_response(threat_model)


@router.patch("/{threat_model_id}/archive", response_model=ThreatModelResponse)
async def archive_threat_model_endpoint(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "write")
    if threat_model.archived_at is None:
        threat_model.archived_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(threat_model)
    return _serialize_threat_model_response(threat_model)


@router.get("/{threat_model_id}/tmac")
async def export_threat_model_as_code(
    threat_model_id: UUID,
    format: TMACFormat = TMACFormat.yaml,
    include_operational_state: bool = False,
    include_binary_assets: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    document = await build_tmac_document(
        db,
        threat_model,
        include_operational_state=include_operational_state,
        include_binary_assets=include_binary_assets,
    )
    filename_suffix = "yaml" if format == TMACFormat.yaml else "json"
    media_type = "application/x-yaml" if format == TMACFormat.yaml else "application/json"
    return Response(
        content=serialize_tmac_document(document, format=format),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="threat-model-{threat_model_id}.tmac.{filename_suffix}"',
        },
    )


@router.post("/tmac/validate", response_model=TMACValidationResponse)
async def validate_threat_model_as_code(
    request: TMACContentRequest,
    current_user: User = Depends(get_current_user),
) -> TMACValidationResponse:
    _ = current_user
    return build_tmac_validation_response(request.content)


@router.get("/tmac/scaffold")
async def scaffold_threat_model_as_code(
    current_user: User = Depends(get_current_user),
) -> Response:
    _ = current_user
    return Response(
        content=build_tmac_scaffold(),
        media_type="application/x-yaml",
        headers={"Content-Disposition": 'attachment; filename="threat-model-scaffold.tmac.yaml"'},
    )


@router.post("/tmac/import", response_model=TMACImportResponse)
async def import_threat_model_as_code(
    request: TMACImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TMACImportResponse:
    if request.mode == TMACImportMode.create_new and request.target_threat_model_id is not None:
        raise HTTPException(
            status_code=400,
            detail="create_new mode must not include target_threat_model_id.",
        )

    target_threat_model = None
    if request.target_threat_model_id is not None:
        target_threat_model = await _require_model_permission(
            db,
            request.target_threat_model_id,
            current_user,
            "write",
        )
    if request.mode == TMACImportMode.replace and target_threat_model is None:
        raise HTTPException(status_code=400, detail="Replace mode requires target_threat_model_id.")
    return await import_tmac_document(
        db,
        content=request.content,
        mode=request.mode,
        current_user_id=current_user.id,
        target_threat_model=target_threat_model,
        apply_operational_state=request.apply_operational_state,
        apply_binary_assets=request.apply_binary_assets,
    )


@router.post("/{threat_model_id}/tmac/diff", response_model=TMACDiffResponse)
async def diff_threat_model_as_code(
    threat_model_id: UUID,
    request: TMACDiffRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TMACDiffResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return await diff_tmac_against_model(db, threat_model=threat_model, content=request.content)


@router.post("/{threat_model_id}/report")
async def get_report(
    threat_model_id: UUID,
    body: ReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """F-14: Generate and return a PDF report for this threat model."""
    await _require_model_permission(db, threat_model_id, current_user, "read")
    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    dfd = DFDResponse(
        nodes=[DFDNodeResponse.model_validate(node) for node in nodes_result.scalars().all()],
        edges=[DFDEdgeResponse.model_validate(edge) for edge in edges_result.scalars().all()],
        trust_boundaries=[
            TrustBoundaryResponse.model_validate(boundary)
            for boundary in boundaries_result.scalars().all()
        ],
    )
    threat_model = await get_threat_model(db, threat_model_id)
    synced_views = sync_default_views(
        getattr(threat_model, "dfd_views", None) if threat_model is not None else None,
        dfd,
    )
    quality = evaluate_quality_gates(
        dfd,
        load_view_responses(synced_views),
    )
    if quality.blocking_count > 0:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Report export is blocked until the DFD quality gates are resolved.",
                "gates": [result.model_dump(mode="json") for result in quality.results if result.severity == "block"],
            },
        )
    # Billing entitlement gate after deterministic validation failures so users
    # get actionable quality feedback before plan gating blocks PDF generation.
    if not await check_org_entitlement(current_user, db, "pdf_export"):
        raise HTTPException(status_code=403, detail="Your plan does not include this feature")
    # Validate DFD image base64 — pass empty string if invalid to avoid WeasyPrint errors
    dfd_integrity_sha256 = hashlib.sha256(
        json.dumps(
            dfd.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    safe_dfd_image = ""
    if body.dfd_image_base64:
        try:
            _b64.b64decode(body.dfd_image_base64, validate=True)
            safe_dfd_image = body.dfd_image_base64
        except Exception:
            logger.warning("generate_report: invalid dfd_image_base64 — omitting DFD image")
    pdf_bytes = await generate_report(
        db,
        threat_model_id,
        dfd_image_base64=safe_dfd_image,
        dfd_integrity_sha256=dfd_integrity_sha256,
        sections=body.sections,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="threatmodel-{threat_model_id}.pdf"',
        },
    )


@router.put("/{threat_model_id}/report-config", response_model=ThreatModelResponse)
async def update_report_config(
    threat_model_id: UUID,
    body: ReportConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelResponse:
    """Update report customization settings (template, logo, watermark)."""
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    next_custom_report_templates = getattr(threat_model, "report_templates", None)
    if body.report_templates is not None:
        try:
            next_custom_report_templates = (
                serialize_custom_report_templates(body.report_templates) or None
            )
            threat_model.report_templates = next_custom_report_templates
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if body.report_template is not None:
        resolved = get_report_template(next_custom_report_templates, body.report_template)
        threat_model.report_template = resolved.id
    if body.report_watermark_text is not None:
        threat_model.report_watermark_text = body.report_watermark_text or None
    if body.report_logo_base64 is not None:
        threat_model.report_logo_base64 = body.report_logo_base64 or None
    if body.arch_diagrams is not None:
        threat_model.arch_diagrams = (
            [d.model_dump() for d in body.arch_diagrams] if body.arch_diagrams else None
        )
    if body.analyst_name is not None:
        threat_model.analyst_name = body.analyst_name or None
    if body.analyst_attestation is not None:
        threat_model.analyst_attestation = body.analyst_attestation or None
    if body.next_review_date is not None:
        threat_model.next_review_date = body.next_review_date
    if body.out_of_scope_statement is not None:
        threat_model.out_of_scope_statement = body.out_of_scope_statement or None

    await db.commit()
    await db.refresh(threat_model)
    return _serialize_threat_model_response(threat_model)


@router.get(
    "/{threat_model_id}/assumptions",
    response_model=list[ThreatModelAssumptionResponse],
)
async def list_assumptions(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelAssumptionResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return _normalize_assumptions(threat_model.assumptions)


@router.post(
    "/{threat_model_id}/assumptions",
    response_model=ThreatModelAssumptionResponse,
    status_code=201,
)
async def create_assumption(
    threat_model_id: UUID,
    body: ThreatModelAssumptionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelAssumptionResponse:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    await _ensure_anchor_exists(
        db,
        threat_model_id,
        anchor_kind=body.anchor_kind,
        anchor_id=body.anchor_id,
    )

    now = datetime.now(timezone.utc)
    assumption = ThreatModelAssumptionResponse(
        id=uuid4(),
        title=body.title.strip(),
        description=body.description.strip(),
        status=body.status,
        anchor_kind=body.anchor_kind,
        anchor_id=body.anchor_id,
        anchor_label=(body.anchor_label or "").strip() or _fallback_anchor_label(body.anchor_kind, body.anchor_id),
        created_at=now,
        updated_at=now,
    )
    existing = _normalize_assumptions(threat_model.assumptions)
    threat_model.assumptions = [
        *(item.model_dump(mode="json") for item in existing),
        assumption.model_dump(mode="json"),
    ]
    await db.commit()
    return assumption


@router.patch(
    "/{threat_model_id}/assumptions/{assumption_id}",
    response_model=ThreatModelAssumptionResponse,
)
async def update_assumption(
    threat_model_id: UUID,
    assumption_id: UUID,
    body: ThreatModelAssumptionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelAssumptionResponse:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    assumptions = _normalize_assumptions(threat_model.assumptions)
    target = next((item for item in assumptions if item.id == assumption_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Assumption not found")

    next_anchor_kind = body.anchor_kind or target.anchor_kind
    next_anchor_id = body.anchor_id or target.anchor_id
    if body.anchor_kind is not None or body.anchor_id is not None:
        await _ensure_anchor_exists(
            db,
            threat_model_id,
            anchor_kind=next_anchor_kind,
            anchor_id=next_anchor_id,
        )

    updated = ThreatModelAssumptionResponse(
        id=target.id,
        title=body.title.strip() if body.title is not None else target.title,
        description=body.description.strip() if body.description is not None else target.description,
        status=body.status or target.status,
        anchor_kind=next_anchor_kind,
        anchor_id=next_anchor_id,
        anchor_label=(
            body.anchor_label.strip()
            if body.anchor_label is not None
            else target.anchor_label
        ) or _fallback_anchor_label(next_anchor_kind, next_anchor_id),
        created_at=target.created_at,
        updated_at=datetime.now(timezone.utc),
    )

    threat_model.assumptions = [
        updated.model_dump(mode="json") if item.id == assumption_id else item.model_dump(mode="json")
        for item in assumptions
    ]
    await db.commit()
    return updated


@router.delete("/{threat_model_id}/assumptions/{assumption_id}", status_code=204)
async def delete_assumption(
    threat_model_id: UUID,
    assumption_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    assumptions = _normalize_assumptions(threat_model.assumptions)
    remaining = [item for item in assumptions if item.id != assumption_id]
    if len(remaining) == len(assumptions):
        raise HTTPException(status_code=404, detail="Assumption not found")

    threat_model.assumptions = [item.model_dump(mode="json") for item in remaining] or None
    await db.commit()
    return Response(status_code=204)


@router.get(
    "/{threat_model_id}/versions",
    response_model=list[ThreatModelVersionResponse],
)
async def list_model_versions(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelVersionResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return normalize_model_snapshots(threat_model.model_snapshots)


@router.post(
    "/{threat_model_id}/versions",
    response_model=ThreatModelVersionResponse,
    status_code=201,
)
async def create_model_version(
    threat_model_id: UUID,
    body: ThreatModelVersionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelVersionResponse:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    snapshot = await build_snapshot_record(
        db,
        threat_model,
        name=body.name.strip(),
        description=body.description.strip(),
        created_by=current_user.email,
    )
    existing = list(threat_model.model_snapshots or [])
    threat_model.model_snapshots = [*existing, snapshot]
    create_notification(
        threat_model,
        notification_type="snapshot_created",
        title="Snapshot saved",
        message=f"{body.name.strip()} captured the current model state.",
        actor=current_user.email,
        target_kind="snapshot",
        target_id=UUID(str(snapshot["id"])),
    )
    await db.commit()
    return ThreatModelVersionResponse.model_validate(snapshot)


@router.post(
    "/{threat_model_id}/versions/diff",
    response_model=ThreatModelVersionDiffResponse,
)
async def diff_model_versions(
    threat_model_id: UUID,
    body: ThreatModelVersionDiffRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelVersionDiffResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")

    left_snapshot = _snapshot_dict_or_404(threat_model.model_snapshots, body.left_snapshot_id)
    if body.right_snapshot_id is not None:
        right_snapshot = _snapshot_dict_or_404(threat_model.model_snapshots, body.right_snapshot_id)
    else:
        right_snapshot = await build_current_snapshot_record(db, threat_model)
    return build_snapshot_diff(left_snapshot, right_snapshot)


@router.get(
    "/{threat_model_id}/reviews",
    response_model=list[ThreatModelReviewResponse],
)
async def list_model_reviews(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelReviewResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return normalize_review_records(threat_model.review_records)


@router.post(
    "/{threat_model_id}/reviews",
    response_model=ThreatModelReviewResponse,
    status_code=201,
)
async def create_model_review(
    threat_model_id: UUID,
    body: ThreatModelReviewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelReviewResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "review")

    _snapshot_dict_or_404(threat_model.model_snapshots, body.snapshot_id)
    now = datetime.now(timezone.utc)
    review = ThreatModelReviewResponse(
        id=uuid4(),
        snapshot_id=body.snapshot_id,
        title=body.title.strip(),
        status="pending",
        assignee=(body.assignee or "").strip() or None,
        created_by=current_user.email,
        created_at=now,
        updated_at=now,
        signed_off_at=None,
        comments=[],
    )
    existing = list(threat_model.review_records or [])
    threat_model.review_records = [*existing, review.model_dump(mode="json")]
    create_notification(
        threat_model,
        notification_type="review_requested",
        title="Review opened",
        message=f"{review.title} is pending{f' for {review.assignee}' if review.assignee else ''}.",
        actor=current_user.email,
        target_kind="review",
        target_id=review.id,
    )
    await db.commit()
    return review


@router.patch(
    "/{threat_model_id}/reviews/{review_id}",
    response_model=ThreatModelReviewResponse,
)
async def update_model_review(
    threat_model_id: UUID,
    review_id: UUID,
    body: ThreatModelReviewUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelReviewResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "review")

    review_dict = _review_dict_or_404(threat_model.review_records, review_id)
    review = ThreatModelReviewResponse.model_validate(review_dict)
    comments = list(review.comments)
    if body.comment:
        comments.append(
            ThreatModelReviewCommentResponse(
                id=uuid4(),
                author=current_user.email,
                comment=body.comment.strip(),
                created_at=datetime.now(timezone.utc),
            )
        )

    next_status = body.status or review.status
    updated = ThreatModelReviewResponse(
        id=review.id,
        snapshot_id=review.snapshot_id,
        title=review.title,
        status=next_status,
        assignee=(body.assignee.strip() if body.assignee is not None else review.assignee) or None,
        created_by=review.created_by,
        created_at=review.created_at,
        updated_at=datetime.now(timezone.utc),
        signed_off_at=(
            datetime.now(timezone.utc)
            if next_status == "approved"
            else review.signed_off_at
        ),
        comments=comments,
    )
    existing = list(threat_model.review_records or [])
    threat_model.review_records = _replace_json_record(
        existing,
        review_id,
        updated.model_dump(mode="json"),
    )
    create_notification(
        threat_model,
        notification_type="review_updated",
        title="Review updated",
        message=f"{updated.title} is now {updated.status.replace('_', ' ')}.",
        actor=current_user.email,
        target_kind="review",
        target_id=updated.id,
    )
    await db.commit()
    return updated


@router.get(
    "/{threat_model_id}/controls",
    response_model=list[ThreatModelControlResponse],
)
async def list_control_library(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelControlResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return normalize_control_library(threat_model.control_library)


@router.post(
    "/{threat_model_id}/controls",
    response_model=ThreatModelControlResponse,
    status_code=201,
)
async def create_control_library_entry(
    threat_model_id: UUID,
    body: ThreatModelControlCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelControlResponse:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    control = ThreatModelControlResponse(
        id=uuid4(),
        title=body.title.strip(),
        description=body.description.strip(),
        category=body.category,
        status=body.status,
        owner=(body.owner or "").strip() or None,
        evidence=(body.evidence or "").strip() or None,
        mapped_threat_ids=body.mapped_threat_ids,
        updated_at=datetime.now(timezone.utc),
    )
    existing = list(threat_model.control_library or [])
    threat_model.control_library = [*existing, control.model_dump(mode="json")]
    create_notification(
        threat_model,
        notification_type="control_updated",
        title="Control added",
        message=f"{control.title} was added to the control library.",
        actor=current_user.email,
        target_kind="control",
        target_id=control.id,
    )
    await db.commit()
    return control


@router.patch(
    "/{threat_model_id}/controls/{control_id}",
    response_model=ThreatModelControlResponse,
)
async def update_control_library_entry(
    threat_model_id: UUID,
    control_id: UUID,
    body: ThreatModelControlUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelControlResponse:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    control_dict = _control_dict_or_404(threat_model.control_library, control_id)
    control = ThreatModelControlResponse.model_validate(control_dict)
    updated = ThreatModelControlResponse(
        id=control.id,
        title=body.title.strip() if body.title is not None else control.title,
        description=body.description.strip() if body.description is not None else control.description,
        category=body.category or control.category,
        status=body.status or control.status,
        owner=(body.owner.strip() if body.owner is not None else control.owner) or None,
        evidence=(body.evidence.strip() if body.evidence is not None else control.evidence) or None,
        mapped_threat_ids=body.mapped_threat_ids if body.mapped_threat_ids is not None else control.mapped_threat_ids,
        updated_at=datetime.now(timezone.utc),
    )
    existing = list(threat_model.control_library or [])
    threat_model.control_library = _replace_json_record(
        existing,
        control_id,
        updated.model_dump(mode="json"),
    )
    create_notification(
        threat_model,
        notification_type="control_updated",
        title="Control updated",
        message=f"{updated.title} is now {updated.status}.",
        actor=current_user.email,
        target_kind="control",
        target_id=updated.id,
    )
    await db.commit()
    return updated


@router.delete("/{threat_model_id}/controls/{control_id}", status_code=204)
async def delete_control_library_entry(
    threat_model_id: UUID,
    control_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await _verify_ownership(db, threat_model_id, current_user)
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    controls = normalize_control_library(threat_model.control_library)
    remaining = [item for item in controls if item.id != control_id]
    if len(remaining) == len(controls):
        raise HTTPException(status_code=404, detail="Control not found")

    threat_model.control_library = [item.model_dump(mode="json") for item in remaining] or None
    create_notification(
        threat_model,
        notification_type="control_updated",
        title="Control removed",
        message=f"{next((item.title for item in controls if item.id == control_id), 'Control')} was removed from the library.",
        actor=current_user.email,
        target_kind="control",
        target_id=control_id,
    )
    await db.commit()
    return Response(status_code=204)


@router.get(
    "/{threat_model_id}/collaborators",
    response_model=list[ThreatModelCollaboratorResponse],
)
async def list_collaborators(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelCollaboratorResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    collaborators = normalize_collaborators(threat_model.collaborators)
    owner = ThreatModelCollaboratorResponse(
        id=current_user.id if threat_model.owner_id == current_user.id else threat_model.owner_id,
        email=current_user.email if threat_model.owner_id == current_user.id else "Owner",
        role="owner",
        status="active",
        invited_by=current_user.email if threat_model.owner_id == current_user.id else "Owner",
        invited_at=threat_model.created_at,
        updated_at=threat_model.updated_at,
    )
    return [owner, *collaborators]


@router.post(
    "/{threat_model_id}/collaborators",
    response_model=ThreatModelCollaboratorResponse,
    status_code=201,
)
async def create_collaborator(
    threat_model_id: UUID,
    body: ThreatModelCollaboratorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelCollaboratorResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "admin")
    normalized_email = body.email.strip().casefold()
    if normalized_email == current_user.email.casefold():
        raise HTTPException(status_code=400, detail="Owner already has access")

    collaborators = normalize_collaborators(threat_model.collaborators)
    for collaborator in collaborators:
        if collaborator.email.casefold() == normalized_email:
            raise HTTPException(status_code=409, detail="Collaborator already exists")

    now = datetime.now(timezone.utc)
    collaborator = ThreatModelCollaboratorResponse(
        id=uuid4(),
        email=body.email.strip(),
        role=body.role,
        status="active",
        invited_by=current_user.email,
        invited_at=now,
        updated_at=now,
    )
    threat_model.collaborators = [
        collaborator.model_dump(mode="json"),
        *[item.model_dump(mode="json") for item in collaborators],
    ]
    create_notification(
        threat_model,
        notification_type="assignment_updated",
        title="Collaborator added",
        message=f"{collaborator.email} now has {collaborator.role} access to {threat_model.system_name}.",
        actor=current_user.email,
        target_kind="threat_model",
        target_id=threat_model.id,
    )
    await db.commit()
    return collaborator


@router.patch(
    "/{threat_model_id}/collaborators/{collaborator_id}",
    response_model=ThreatModelCollaboratorResponse,
)
async def update_collaborator(
    threat_model_id: UUID,
    collaborator_id: UUID,
    body: ThreatModelCollaboratorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelCollaboratorResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "admin")
    collaborator_dict = _collaborator_dict_or_404(threat_model.collaborators, collaborator_id)
    collaborator = ThreatModelCollaboratorResponse.model_validate(collaborator_dict)
    updated = ThreatModelCollaboratorResponse(
        id=collaborator.id,
        email=collaborator.email,
        role=body.role or collaborator.role,
        status=body.status or collaborator.status,
        invited_by=collaborator.invited_by,
        invited_at=collaborator.invited_at,
        updated_at=datetime.now(timezone.utc),
    )
    threat_model.collaborators = _replace_json_record(
        list(threat_model.collaborators or []),
        collaborator_id,
        updated.model_dump(mode="json"),
    )
    create_notification(
        threat_model,
        notification_type="assignment_updated",
        title="Collaborator updated",
        message=f"{updated.email} is now {updated.role} ({updated.status}).",
        actor=current_user.email,
        target_kind="threat_model",
        target_id=threat_model.id,
    )
    await db.commit()
    return updated


@router.get(
    "/{threat_model_id}/assignments",
    response_model=list[ThreatModelAssignmentResponse],
)
async def list_assignments(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelAssignmentResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return normalize_assignments(threat_model.assignments)


@router.post(
    "/{threat_model_id}/assignments",
    response_model=ThreatModelAssignmentResponse,
    status_code=201,
)
async def create_assignment(
    threat_model_id: UUID,
    body: ThreatModelAssignmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelAssignmentResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "review")
    now = datetime.now(timezone.utc)
    assignment = ThreatModelAssignmentResponse(
        id=uuid4(),
        title=body.title.strip(),
        description=body.description.strip(),
        assignee=body.assignee.strip(),
        priority=body.priority,
        status="open",
        due_date=body.due_date,
        threat_id=body.threat_id,
        review_id=body.review_id,
        anchor_kind=body.anchor_kind,
        anchor_id=body.anchor_id,
        anchor_label=(body.anchor_label or "").strip() or None,
        created_by=current_user.email,
        created_at=now,
        updated_at=now,
        comments=[],
    )
    threat_model.assignments = [
        assignment.model_dump(mode="json"),
        *[item.model_dump(mode="json") for item in normalize_assignments(threat_model.assignments)],
    ]
    create_notification(
        threat_model,
        notification_type="assignment_created",
        title="Assignment created",
        message=f"{assignment.title} assigned to {assignment.assignee}.",
        actor=current_user.email,
        target_kind="assignment",
        target_id=assignment.id,
    )
    await db.commit()
    return assignment


@router.patch(
    "/{threat_model_id}/assignments/{assignment_id}",
    response_model=ThreatModelAssignmentResponse,
)
async def update_assignment(
    threat_model_id: UUID,
    assignment_id: UUID,
    body: ThreatModelAssignmentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelAssignmentResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "review")
    assignment_dict = _assignment_dict_or_404(threat_model.assignments, assignment_id)
    assignment = ThreatModelAssignmentResponse.model_validate(assignment_dict)
    comments = list(assignment.comments)
    if body.comment and body.comment.strip():
        comments.append(build_assignment_comment(current_user.email, body.comment))
    updated = ThreatModelAssignmentResponse(
        id=assignment.id,
        title=body.title.strip() if body.title is not None else assignment.title,
        description=body.description.strip() if body.description is not None else assignment.description,
        assignee=body.assignee.strip() if body.assignee is not None else assignment.assignee,
        priority=body.priority or assignment.priority,
        status=body.status or assignment.status,
        due_date=body.due_date if body.due_date is not None else assignment.due_date,
        threat_id=assignment.threat_id,
        review_id=assignment.review_id,
        anchor_kind=assignment.anchor_kind,
        anchor_id=assignment.anchor_id,
        anchor_label=assignment.anchor_label,
        created_by=assignment.created_by,
        created_at=assignment.created_at,
        updated_at=datetime.now(timezone.utc),
        comments=comments,
    )
    threat_model.assignments = _replace_json_record(
        list(threat_model.assignments or []),
        assignment_id,
        updated.model_dump(mode="json"),
    )
    create_notification(
        threat_model,
        notification_type="assignment_updated",
        title="Assignment updated",
        message=f"{updated.title} is now {updated.status.replace('_', ' ')}.",
        actor=current_user.email,
        target_kind="assignment",
        target_id=updated.id,
    )
    await db.commit()
    return updated


@router.get(
    "/{threat_model_id}/notifications",
    response_model=list[ThreatModelNotificationResponse],
)
async def list_notifications(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatModelNotificationResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return normalize_notifications(threat_model.notifications)


@router.patch(
    "/{threat_model_id}/notifications/{notification_id}",
    response_model=ThreatModelNotificationResponse,
)
async def update_notification(
    threat_model_id: UUID,
    notification_id: UUID,
    body: ThreatModelNotificationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelNotificationResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    notification_dict = _notification_dict_or_404(threat_model.notifications, notification_id)
    notification = ThreatModelNotificationResponse.model_validate(notification_dict)
    updated = ThreatModelNotificationResponse(
        **{
            **notification.model_dump(mode="python"),
            "status": body.status,
        }
    )
    threat_model.notifications = _replace_json_record(
        list(threat_model.notifications or []),
        notification_id,
        updated.model_dump(mode="json"),
    )
    await db.commit()
    return updated


@router.get(
    "/{threat_model_id}/attack-paths",
    response_model=list[AttackPathResponse],
)
async def list_attack_paths(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AttackPathResponse]:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    dfd = await load_current_dfd(db, threat_model.id)
    threats = await load_current_threat_snapshot(db, threat_model.id)
    return derive_attack_paths(dfd, threats)


@router.get(
    "/{threat_model_id}/scorecard",
    response_model=ThreatModelScorecardResponse,
)
async def get_model_scorecard(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatModelScorecardResponse:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")

    dfd = await load_current_dfd(db, threat_model.id)
    synced_views = sync_default_views(getattr(threat_model, "dfd_views", None), dfd)
    quality = evaluate_quality_gates(
        dfd,
        load_view_responses(synced_views),
    )
    validation = await build_architecture_validation_summary(db, threat_model)
    assumptions = _normalize_assumptions(threat_model.assumptions)
    controls = normalize_control_library(threat_model.control_library)
    reviews = normalize_review_records(threat_model.review_records)
    threats = await load_current_threat_snapshot(db, threat_model.id)
    current_snapshot = build_current_snapshot_payload(dfd, threats)

    assumption_summary = _build_assumption_summary(assumptions)
    coverage_summary = build_coverage_summary(dfd, threats, assumptions)
    mitigation_summary = _build_mitigation_summary(threats)
    control_summary = _build_control_summary(controls)
    review_summary = _build_review_summary(reviews)
    review_freshness = build_review_freshness_summary(
        threat_model=threat_model,
        reviews=reviews,
        current_snapshot=current_snapshot,
    )
    collaboration_summary = build_collaboration_summary(threat_model)
    residual_risk_by_level = build_residual_risk_summary(
        [threat.get("residual_risk_level") for threat in threats]
    )
    overall_status, overall_summary = _derive_scorecard_status(
        validation=validation,
        coverage=coverage_summary,
        quality=quality,
        assumptions=assumption_summary,
        mitigations=mitigation_summary,
        reviews=review_summary,
        review_freshness=review_freshness,
    )
    top_actions = _build_scorecard_actions(
        validation=validation,
        coverage=coverage_summary,
        quality=quality,
        assumptions=assumption_summary,
        mitigations=mitigation_summary,
        controls=control_summary,
        reviews=review_summary,
        review_freshness=review_freshness,
        collaboration=collaboration_summary,
    )

    return ThreatModelScorecardResponse(
        overall_status=overall_status,
        overall_summary=overall_summary,
        architecture_validation=validation,
        coverage_summary=coverage_summary,
        quality_gates=quality,
        assumption_summary=assumption_summary,
        mitigation_summary=mitigation_summary,
        control_summary=control_summary,
        review_summary=review_summary,
        review_freshness=review_freshness,
        collaboration_summary=collaboration_summary,
        residual_risk_by_level=residual_risk_by_level,
        top_actions=top_actions,
    )


@router.get(
    "/{threat_model_id}/validation-summary",
    response_model=ArchitectureValidationSummary,
)
async def get_validation_summary(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ArchitectureValidationSummary:
    threat_model = await _require_model_permission(db, threat_model_id, current_user, "read")
    return await build_architecture_validation_summary(db, threat_model)
