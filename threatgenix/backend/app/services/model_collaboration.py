from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from fastapi import HTTPException

from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.threat_model import (
    ThreatModelAssignmentCommentResponse,
    ThreatModelAssignmentResponse,
    ThreatModelCollaboratorResponse,
    ThreatModelCollaborationSummary,
    ThreatModelNotificationResponse,
)

ModelPermission = Literal["read", "write", "review", "admin"]

ROLE_PERMISSIONS: dict[str, set[ModelPermission]] = {
    "owner": {"read", "write", "review", "admin"},
    "editor": {"read", "write", "review"},
    "reviewer": {"read", "review"},
    "viewer": {"read"},
}

ORG_ROLE_TO_MODEL_ROLE: dict[str, str] = {
    "admin": "owner",
    "owner": "owner",
    "security_engineer": "editor",
    "engineer": "editor",
    "editor": "editor",
    "reviewer": "reviewer",
    "viewer": "viewer",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_or_none(value: object) -> UUID | None:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            return None
    return None


def normalize_collaborators(raw_collaborators: list[dict] | None) -> list[ThreatModelCollaboratorResponse]:
    normalized: list[ThreatModelCollaboratorResponse] = []
    for item in raw_collaborators or []:
        try:
            normalized.append(ThreatModelCollaboratorResponse.model_validate(item))
        except Exception:
            continue
    return sorted(normalized, key=lambda item: (item.email.casefold(), item.invited_at))


def normalize_assignments(raw_assignments: list[dict] | None) -> list[ThreatModelAssignmentResponse]:
    normalized: list[ThreatModelAssignmentResponse] = []
    for item in raw_assignments or []:
        try:
            normalized.append(ThreatModelAssignmentResponse.model_validate(item))
        except Exception:
            continue
    return sorted(
        normalized,
        key=lambda item: (item.status == "done", -item.updated_at.timestamp()),
    )


def normalize_notifications(raw_notifications: list[dict] | None) -> list[ThreatModelNotificationResponse]:
    normalized: list[ThreatModelNotificationResponse] = []
    for item in raw_notifications or []:
        try:
            normalized.append(ThreatModelNotificationResponse.model_validate(item))
        except Exception:
            continue
    return sorted(normalized, key=lambda item: item.created_at, reverse=True)


def get_model_role(threat_model: ThreatModel, user: User) -> str | None:
    owner_id = getattr(threat_model, "owner_id", None)
    if owner_id is None:
        # owner_id is NOT NULL after migration 047. If this code path is reached
        # it means a pre-migration row leaked through — deny access.
        return None
    if owner_id == user.id:
        return "owner"

    model_org_id = _uuid_or_none(getattr(threat_model, "organization_id", None))
    owner = getattr(threat_model, "owner", None)
    owner_org_id = _uuid_or_none(getattr(owner, "organization_id", None))
    effective_model_org_id = model_org_id or owner_org_id
    user_org_id = _uuid_or_none(getattr(user, "organization_id", None))

    if effective_model_org_id is not None and effective_model_org_id == user_org_id:
        org_role = str(getattr(user, "role", "") or "").strip().casefold()
        mapped_role = ORG_ROLE_TO_MODEL_ROLE.get(org_role)
        if mapped_role is not None:
            return mapped_role

    if effective_model_org_id is not None and effective_model_org_id != user_org_id:
        return None
    if effective_model_org_id is None and user_org_id is not None:
        # If the model owner cannot be tied to the caller's tenant, do not let
        # collaborator JSON alone bridge tenants.
        return None

    user_email = (getattr(user, "email", "") or "").casefold()
    for collaborator in normalize_collaborators(getattr(threat_model, "collaborators", None)):
        if collaborator.status != "active":
            continue
        if collaborator.email.casefold() == user_email:
            return collaborator.role
    return None


def require_model_permission(
    threat_model: ThreatModel | None,
    user: User,
    permission: ModelPermission,
) -> ThreatModel:
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    role = get_model_role(threat_model, user)
    if role is None:
        raise HTTPException(status_code=403, detail="Access denied")
    if permission not in ROLE_PERMISSIONS.get(role, set()):
        raise HTTPException(status_code=403, detail="Insufficient role for this action")
    return threat_model


def build_collaboration_summary(threat_model: ThreatModel) -> ThreatModelCollaborationSummary:
    collaborators = normalize_collaborators(getattr(threat_model, "collaborators", None))
    assignments = normalize_assignments(getattr(threat_model, "assignments", None))
    notifications = normalize_notifications(getattr(threat_model, "notifications", None))
    now = _now()
    return ThreatModelCollaborationSummary(
        collaborators_total=len(collaborators),
        active_collaborators=sum(1 for item in collaborators if item.status == "active"),
        editors=sum(1 for item in collaborators if item.role == "editor" and item.status == "active"),
        reviewers=sum(1 for item in collaborators if item.role == "reviewer" and item.status == "active"),
        viewers=sum(1 for item in collaborators if item.role == "viewer" and item.status == "active"),
        open_assignments=sum(1 for item in assignments if item.status != "done"),
        overdue_assignments=sum(
            1
            for item in assignments
            if item.status != "done" and item.due_date is not None and item.due_date < now
        ),
        unread_notifications=sum(1 for item in notifications if item.status == "unread"),
    )


def create_notification(
    threat_model: ThreatModel,
    *,
    notification_type: Literal[
        "review_requested",
        "review_updated",
        "assignment_created",
        "assignment_updated",
        "snapshot_created",
        "control_updated",
    ],
    title: str,
    message: str,
    actor: str,
    target_kind: Literal["snapshot", "review", "assignment", "control", "threat_model"] | None = None,
    target_id: UUID | None = None,
) -> ThreatModelNotificationResponse:
    notification = ThreatModelNotificationResponse(
        id=uuid4(),
        type=notification_type,
        title=title,
        message=message,
        status="unread",
        actor=actor,
        target_kind=target_kind,
        target_id=target_id,
        created_at=_now(),
    )
    existing = list(getattr(threat_model, "notifications", None) or [])
    threat_model.notifications = [notification.model_dump(mode="json"), *existing][:100]
    return notification


def build_assignment_comment(author: str, comment: str) -> ThreatModelAssignmentCommentResponse:
    return ThreatModelAssignmentCommentResponse(
        id=uuid4(),
        author=author,
        comment=comment.strip(),
        created_at=_now(),
    )
