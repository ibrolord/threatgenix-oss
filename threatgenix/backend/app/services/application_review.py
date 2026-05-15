"""Service layer for tenant-scoped application security reviews."""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application_review import ApplicationSecurityReview
from app.models.user import User
from app.schemas.application_review import (
    ApplicationReviewCreate,
    ApplicationReviewResponse,
    REVIEW_LIFECYCLE_STATUSES,
    ReviewStatus,
    canonical_json,
    fingerprint_scope,
)
from app.schemas.review_intake import IntakeValidationRequest
from app.services.review_intake import validate_intake_answers


class ReviewIdempotencyConflict(ValueError):
    """Raised when an idempotency key is reused for a different review request."""


class ReviewValidationError(ValueError):
    """Raised when a review request fails deterministic validation."""


REVIEW_STATE_TRANSITIONS: dict[str, set[str]] = {
    "created": {
        "intake_required",
        "bundle_required",
        "bundle_received",
        "indexing",
        "cancelled",
        "failed_retryable",
    },
    "intake_required": {"bundle_required", "bundle_received", "indexing", "cancelled", "failed_retryable"},
    "bundle_required": {"bundle_received", "indexing", "cancelled", "failed_retryable"},
    "bundle_received": {"scanning", "indexing", "extracting_context", "cancelled", "failed_retryable"},
    "scanning": {
        "extracting_context",
        "indexing",
        "blocked_by_permission",
        "cancelled",
        "failed_retryable",
        "failed_terminal",
    },
    "extracting_context": {"indexing", "cancelled", "failed_retryable", "failed_terminal"},
    "indexing": {"building_graph", "deciding", "cancelled", "failed_retryable", "failed_terminal"},
    "building_graph": {"deciding", "cancelled", "failed_retryable", "failed_terminal"},
    "deciding": {
        "explaining",
        "completed",
        "blocked_by_policy",
        "cancelled",
        "failed_retryable",
        "failed_terminal",
    },
    "explaining": {"completed", "failed_retryable", "failed_terminal"},
    "failed_retryable": {"bundle_received", "scanning", "extracting_context", "indexing", "deciding", "cancelled"},
    "completed": set(),
    "blocked_by_policy": set(),
    "blocked_by_permission": set(),
    "failed_terminal": set(),
    "cancelled": set(),
}


def transition_application_review_status(
    review: ApplicationSecurityReview,
    next_status: ReviewStatus,
    *,
    result_summary: str | None = None,
    error_message: str | None = None,
) -> ApplicationSecurityReview:
    if next_status not in REVIEW_LIFECYCLE_STATUSES:
        raise ReviewValidationError(f"Unsupported review status: {next_status}")
    current_status = review.status or "created"
    if current_status == next_status:
        return review
    allowed = REVIEW_STATE_TRANSITIONS.get(current_status)
    if allowed is None:
        raise ReviewValidationError(f"Unsupported current review status: {current_status}")
    if next_status not in allowed:
        raise ReviewValidationError(
            f"Invalid review status transition: {current_status} -> {next_status}"
        )
    review.status = next_status
    if result_summary is not None:
        review.result_summary = result_summary
    if error_message is not None:
        review.error_message = error_message
    return review


def tenant_key_for_user(user: User) -> str:
    organization_id = getattr(user, "organization_id", None)
    if organization_id is not None:
        return f"org:{organization_id}"
    return f"user:{user.id}"


def normalized_intake_answers_for_request(request: ApplicationReviewCreate) -> dict[str, object]:
    result = validate_intake_answers(
        IntakeValidationRequest(
            version=request.intake_version,
            review_type=request.input_kind,
            answers=request.intake_answers,
        )
    )
    if not result.valid:
        return request.intake_answers
    return result.normalized_answers


def review_fingerprint_payload(request: ApplicationReviewCreate) -> dict[str, object]:
    scope_fingerprint = fingerprint_scope(request.scope)
    return {
        "app_name": request.app_name,
        "threat_model_id": str(request.threat_model_id) if request.threat_model_id else None,
        "invocation_surface": request.invocation_surface,
        "input_kind": request.input_kind,
        "commit_sha": request.commit_sha,
        "bundle_hash": request.bundle_hash,
        "scope_fingerprint": scope_fingerprint,
        "requested_tools": request.requested_tools,
        "policy": request.policy,
        "intake_answers": normalized_intake_answers_for_request(request),
    }


def generated_idempotency_key(tenant_key: str, request: ApplicationReviewCreate) -> str:
    payload = {
        "tenant_key": tenant_key,
        **review_fingerprint_payload(request),
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"auto:{digest}"


def ensure_idempotent_review_matches(
    existing: ApplicationSecurityReview,
    request: ApplicationReviewCreate,
) -> None:
    expected = review_fingerprint_payload(request)
    actual = {
        "app_name": existing.app_name,
        "threat_model_id": str(existing.threat_model_id) if existing.threat_model_id else None,
        "invocation_surface": existing.invocation_surface,
        "input_kind": existing.input_kind,
        "commit_sha": existing.commit_sha,
        "bundle_hash": existing.bundle_hash,
        "scope_fingerprint": existing.scope_fingerprint,
        "requested_tools": existing.requested_tools or [],
        "policy": existing.policy or {},
        "intake_answers": (existing.context or {}).get("intake", {}).get("answers", {}),
    }
    if canonical_json(actual) != canonical_json(expected):
        raise ReviewIdempotencyConflict(
            "Idempotency key was already used for a different review request."
        )


def serialize_application_review(
    review: ApplicationSecurityReview,
) -> ApplicationReviewResponse:
    return ApplicationReviewResponse(
        id=review.id,
        tenant_key=review.tenant_key,
        owner_id=review.owner_id,
        organization_id=review.organization_id,
        threat_model_id=review.threat_model_id,
        parent_review_id=review.parent_review_id,
        review_lineage_id=review.review_lineage_id,
        app_name=review.app_name,
        invocation_surface=review.invocation_surface,
        input_kind=review.input_kind,
        status=review.status,
        decision=review.decision,
        commit_sha=review.commit_sha,
        bundle_hash=review.bundle_hash,
        scope_fingerprint=review.scope_fingerprint,
        idempotency_key=review.idempotency_key,
        requested_tools=review.requested_tools or [],
        scope=review.scope or {},
        context=review.context or {},
        policy=review.policy or {},
        result_summary=review.result_summary,
        error_message=review.error_message,
        created_at=review.created_at,
        updated_at=review.updated_at,
    )


async def get_application_review_by_idempotency_key(
    db: AsyncSession,
    *,
    tenant_key: str,
    idempotency_key: str,
) -> ApplicationSecurityReview | None:
    result = await db.execute(
        select(ApplicationSecurityReview)
        .where(
            ApplicationSecurityReview.tenant_key == tenant_key,
            ApplicationSecurityReview.idempotency_key == idempotency_key,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_application_review(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
) -> ApplicationSecurityReview | None:
    result = await db.execute(
        select(ApplicationSecurityReview)
        .where(
            ApplicationSecurityReview.tenant_key == tenant_key,
            ApplicationSecurityReview.id == review_id,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def list_application_reviews(
    db: AsyncSession,
    *,
    tenant_key: str,
    limit: int = 100,
) -> list[ApplicationSecurityReview]:
    result = await db.execute(
        select(ApplicationSecurityReview)
        .where(ApplicationSecurityReview.tenant_key == tenant_key)
        .order_by(ApplicationSecurityReview.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def create_application_review(
    db: AsyncSession,
    *,
    current_user: User,
    request: ApplicationReviewCreate,
) -> ApplicationSecurityReview:
    tenant_key = tenant_key_for_user(current_user)
    intake_result = validate_intake_answers(
        IntakeValidationRequest(
            version=request.intake_version,
            review_type=request.input_kind,
            answers=request.intake_answers,
        )
    )
    if not intake_result.valid:
        details = [*intake_result.missing_required, *intake_result.errors]
        raise ReviewValidationError("Invalid intake answers: " + ", ".join(details))

    idempotency_key = request.idempotency_key or generated_idempotency_key(tenant_key, request)
    existing = await get_application_review_by_idempotency_key(
        db,
        tenant_key=tenant_key,
        idempotency_key=idempotency_key,
    )
    if existing is not None:
        ensure_idempotent_review_matches(existing, request)
        return existing

    parent_review = None
    if request.parent_review_id is not None:
        parent_review = await get_application_review(
            db,
            tenant_key=tenant_key,
            review_id=request.parent_review_id,
        )
        if parent_review is None:
            raise ValueError("Parent review was not found for this tenant.")

    review_id = uuid4()
    context = dict(request.context)
    context["intake"] = {
        "version": intake_result.version,
        "review_type": intake_result.review_type,
        "answers": intake_result.normalized_answers,
        "evidence_gaps": intake_result.evidence_gaps,
        "adaptive_followups": [question.id for question in intake_result.adaptive_followups],
    }
    review = ApplicationSecurityReview(
        id=review_id,
        tenant_key=tenant_key,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        threat_model_id=request.threat_model_id,
        parent_review_id=request.parent_review_id,
        review_lineage_id=(
            parent_review.review_lineage_id if parent_review is not None else review_id
        ),
        app_name=request.app_name,
        invocation_surface=request.invocation_surface,
        input_kind=request.input_kind,
        commit_sha=request.commit_sha,
        bundle_hash=request.bundle_hash,
        scope_fingerprint=fingerprint_scope(request.scope),
        idempotency_key=idempotency_key,
        requested_tools=request.requested_tools,
        scope=request.scope,
        context=context,
        policy=request.policy,
        status="created",
    )
    db.add(review)
    await db.flush()
    return review
