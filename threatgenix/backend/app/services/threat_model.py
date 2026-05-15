from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.schemas.threat_model import (
    PortfolioSummary,
    PortfolioTrendPoint,
    PortfolioTrendResponse,
    ThreatModelCreate,
    ThreatModelListItem,
)
from app.services.model_collaboration import (
    normalize_assignments,
    normalize_notifications,
)
from app.services.model_governance import model_has_drift_signals
from app.services.residual_risk import build_residual_risk_summary, derive_residual_risk_level


async def create_threat_model(
    db: AsyncSession,
    data: ThreatModelCreate,
    owner_id: UUID,
    organization_id: UUID | None = None,
) -> ThreatModel:
    threat_model = ThreatModel(
        system_name=data.system_name,
        description=data.description,
        data_classification=data.data_classification,
        regulatory_scope=data.regulatory_scope or [],
        deployment_model=data.deployment_model,
        owner_id=owner_id,
        organization_id=organization_id,
    )
    db.add(threat_model)
    await db.commit()
    await db.refresh(threat_model)
    return threat_model


def _apply_tenant_scope(
    statement,
    *,
    owner_id: UUID | None = None,
    organization_id: UUID | None = None,
):
    if organization_id is not None:
        if owner_id is not None:
            return statement.where(
                or_(
                    ThreatModel.organization_id == organization_id,
                    and_(
                        ThreatModel.organization_id.is_(None),
                        ThreatModel.owner_id == owner_id,
                    ),
                )
            )
        return statement.where(ThreatModel.organization_id == organization_id)
    if owner_id is not None:
        return statement.where(ThreatModel.owner_id == owner_id)
    return statement


def tenant_scoped_threat_model_ids(
    *,
    owner_id: UUID | None = None,
    organization_id: UUID | None = None,
):
    statement = _apply_tenant_scope(
        select(ThreatModel.id),
        owner_id=owner_id,
        organization_id=organization_id,
    )
    return statement.where(ThreatModel.archived_at.is_(None))


async def list_threat_models(
    db: AsyncSession,
    owner_id: Optional[UUID] = None,
    organization_id: Optional[UUID] = None,
) -> list[ThreatModelListItem]:
    stmt = (
        select(
            ThreatModel.id,
            ThreatModel.owner_id,
            ThreatModel.organization_id,
            ThreatModel.system_name,
            ThreatModel.data_classification,
            ThreatModel.created_at,
            ThreatModel.updated_at,
            func.count(Threat.id).label("threat_count"),
            func.count(
                case((Threat.status == "Open", Threat.id), else_=None)
            ).label("open_count"),
        )
        .outerjoin(Threat, ThreatModel.id == Threat.threat_model_id)
    )
    stmt = _apply_tenant_scope(stmt, owner_id=owner_id, organization_id=organization_id)
    stmt = stmt.where(ThreatModel.archived_at.is_(None))
    stmt = stmt.group_by(ThreatModel.id).order_by(ThreatModel.updated_at.desc())
    result = await db.execute(stmt)
    rows = result.all()
    items = []
    for row in rows:
        d = row._asdict()
        d["has_been_analyzed"] = d["threat_count"] > 0
        items.append(ThreatModelListItem.model_validate(d))
    return items


async def get_threat_model(db: AsyncSession, threat_model_id: UUID) -> Optional[ThreatModel]:
    stmt = (
        select(ThreatModel)
        .where(ThreatModel.id == threat_model_id)
        .options(
            selectinload(ThreatModel.owner),
            selectinload(ThreatModel.organization),
        )
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_portfolio_summary(
    db: AsyncSession,
    owner_id: Optional[UUID] = None,
    organization_id: Optional[UUID] = None,
) -> PortfolioSummary:
    """Return aggregate portfolio stats for dashboard and leadership rollups."""

    model_stmt = _apply_tenant_scope(
        select(ThreatModel),
        owner_id=owner_id,
        organization_id=organization_id,
    )
    model_stmt = model_stmt.where(ThreatModel.archived_at.is_(None))
    model_stmt = model_stmt.order_by(ThreatModel.updated_at.desc())
    model_result = await db.execute(model_stmt)
    models = list(model_result.scalars().all())

    total_models = len(models)
    models_by_classification: dict[str, int] = {}
    for model in models:
        models_by_classification[model.data_classification] = (
            models_by_classification.get(model.data_classification, 0) + 1
        )

    threat_stmt = select(Threat)
    if organization_id is not None or owner_id is not None:
        threat_stmt = threat_stmt.where(
            Threat.threat_model_id.in_(
                tenant_scoped_threat_model_ids(
                    owner_id=owner_id,
                    organization_id=organization_id,
                )
            )
        )
    threat_result = await db.execute(threat_stmt)
    threats = list(threat_result.scalars().all())

    threats_by_severity: dict[str, int] = {}
    threats_by_status: dict[str, int] = {}
    threats_by_stride: dict[str, int] = {}
    for threat in threats:
        threats_by_severity[threat.severity] = threats_by_severity.get(threat.severity, 0) + 1
        threats_by_status[threat.status] = threats_by_status.get(threat.status, 0) + 1
        threats_by_stride[threat.stride_category] = threats_by_stride.get(threat.stride_category, 0) + 1
    total_threats = len(threats)
    residual_risk_by_level = build_residual_risk_summary(
        [
            getattr(threat, "residual_risk_level", None)
            or derive_residual_risk_level(
                threat.severity,
                getattr(threat, "control_effectiveness", None),
            )
            for threat in threats
        ]
    )

    open_reviews = 0
    models_pending_review = 0
    models_with_drift = 0
    shared_models = 0
    open_assignments = 0
    overdue_assignments = 0
    unread_notifications = 0
    controls_by_status: dict[str, int] = {}
    for model in models:
        review_records = getattr(model, "review_records", None) or []
        review_statuses = {record.get("status", "pending") for record in review_records}
        open_reviews += sum(
            1
            for record in review_records
            if record.get("status") in {"pending", "changes_requested"}
        )
        if any(status in {"pending", "changes_requested"} for status in review_statuses):
            models_pending_review += 1
        if model_has_drift_signals(model):
            models_with_drift += 1
        if getattr(model, "collaborators", None):
            shared_models += 1
        assignments = normalize_assignments(getattr(model, "assignments", None))
        open_assignments += sum(1 for assignment in assignments if assignment.status != "done")
        overdue_assignments += sum(
            1
            for assignment in assignments
            if assignment.status != "done"
            and assignment.due_date is not None
            and assignment.due_date < datetime.now(assignment.due_date.tzinfo or timezone.utc)
        )
        unread_notifications += sum(
            1 for notification in normalize_notifications(getattr(model, "notifications", None))
            if notification.status == "unread"
        )
        for control in getattr(model, "control_library", None) or []:
            status = control.get("status", "planned")
            controls_by_status[status] = controls_by_status.get(status, 0) + 1

    recent_stmt = (
        select(
            ThreatModel.id,
            ThreatModel.owner_id,
            ThreatModel.organization_id,
            ThreatModel.system_name,
            ThreatModel.data_classification,
            ThreatModel.created_at,
            ThreatModel.updated_at,
            func.count(Threat.id).label("threat_count"),
        )
        .outerjoin(Threat, ThreatModel.id == Threat.threat_model_id)
    )
    recent_stmt = _apply_tenant_scope(
        recent_stmt,
        owner_id=owner_id,
        organization_id=organization_id,
    )
    recent_stmt = recent_stmt.where(ThreatModel.archived_at.is_(None))
    recent_stmt = (
        recent_stmt.group_by(ThreatModel.id)
        .order_by(ThreatModel.updated_at.desc())
        .limit(100)
    )
    recent_result = await db.execute(recent_stmt)
    recent_models = [
        ThreatModelListItem.model_validate(row._asdict())
        for row in recent_result.all()
    ]

    return PortfolioSummary(
        total_models=total_models,
        total_threats=total_threats,
        threats_by_severity=threats_by_severity,
        threats_by_status=threats_by_status,
        threats_by_stride=threats_by_stride,
        residual_risk_by_level=residual_risk_by_level,
        models_by_classification=models_by_classification,
        controls_by_status=controls_by_status,
        open_reviews=open_reviews,
        models_pending_review=models_pending_review,
        models_with_drift=models_with_drift,
        shared_models=shared_models,
        open_assignments=open_assignments,
        overdue_assignments=overdue_assignments,
        unread_notifications=unread_notifications,
        recent_models=recent_models,
    )


async def get_portfolio_trends(
    db: AsyncSession,
    owner_id: Optional[UUID] = None,
    organization_id: Optional[UUID] = None,
    *,
    limit_days: int = 14,
) -> PortfolioTrendResponse:
    model_stmt = _apply_tenant_scope(
        select(ThreatModel),
        owner_id=owner_id,
        organization_id=organization_id,
    )
    model_stmt = model_stmt.where(ThreatModel.archived_at.is_(None))
    model_result = await db.execute(model_stmt)
    models = list(model_result.scalars().all())

    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "snapshot_count": 0,
            "threat_count": 0,
            "high_risk_threat_count": 0,
            "review_events": 0,
            "control_events": 0,
        }
    )

    for model in models:
        for snapshot in getattr(model, "model_snapshots", None) or []:
            created_at = snapshot.get("created_at")
            if not created_at:
                continue
            bucket_key = str(created_at)[:10]
            buckets[bucket_key]["snapshot_count"] += 1
            threats = snapshot.get("threats", []) or []
            buckets[bucket_key]["threat_count"] += len(threats)
            buckets[bucket_key]["high_risk_threat_count"] += sum(
                1 for threat in threats if threat.get("severity") in {"Critical", "High"}
            )
        for review in getattr(model, "review_records", None) or []:
            updated_at = review.get("updated_at")
            if updated_at:
                buckets[str(updated_at)[:10]]["review_events"] += 1
        for control in getattr(model, "control_library", None) or []:
            updated_at = control.get("updated_at")
            if updated_at:
                buckets[str(updated_at)[:10]]["control_events"] += 1

    sorted_keys = sorted(buckets.keys(), reverse=True)[:limit_days]
    points = [
        PortfolioTrendPoint(date=key, **buckets[key])
        for key in sorted(sorted_keys)
    ]
    if not points:
        return PortfolioTrendResponse(
            points=[],
            latest_summary="No snapshot or governance activity has been recorded yet.",
        )

    latest = points[-1]
    return PortfolioTrendResponse(
        points=points,
        latest_summary=(
            f"Latest activity on {latest.date}: {latest.snapshot_count} saved version(s), "
            f"{latest.high_risk_threat_count} high-risk threat(s), {latest.review_events} review event(s), "
            f"and {latest.control_events} control update(s)."
        ),
    )
