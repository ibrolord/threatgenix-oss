"""Deterministic orchestration for invoke-anywhere review runs."""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.application_review_orchestration import (
    ApplicationReviewOrchestrationRequest,
    ApplicationReviewOrchestrationResponse,
    ReviewOrchestrationStep,
    StepStatus,
)
from app.schemas.review_scanners import EnqueueReviewScannersRequest
from app.schemas.scan import ScanJobResponse
from app.services.application_review import (
    ReviewIdempotencyConflict,
    ReviewValidationError,
    create_application_review,
    ensure_idempotent_review_matches,
    generated_idempotency_key,
    get_application_review_by_idempotency_key,
    serialize_application_review,
    tenant_key_for_user,
)
from app.services.application_review_bundles import (
    ReviewBundleValidationError,
    create_review_bundle,
    serialize_application_review_bundle,
)
from app.services.application_review_context import (
    ApplicationReviewContextError,
    rebuild_review_context_index,
)
from app.services.application_review_decision import evaluate_application_review_decision
from app.services.model_collaboration import require_model_permission
from app.services.review_scanner_enqueue import (
    ReviewScannerEnqueueError,
    enqueue_review_scanner_jobs,
)
from app.services.threat_model import create_threat_model, get_threat_model


class ReviewOrchestrationError(ValueError):
    """Raised when an orchestration request is invalid before execution."""


async def orchestrate_application_review(
    db: AsyncSession,
    *,
    current_user: User,
    request: ApplicationReviewOrchestrationRequest,
    public_web_base_url: str | None = None,
) -> ApplicationReviewOrchestrationResponse:
    steps: list[ReviewOrchestrationStep] = []
    threat_model_id = request.review.threat_model_id
    review_response = None
    bundle_response = None
    scanner_jobs = []
    indexed_entry_count = None
    decision = None

    try:
        if request.threat_model is not None:
            threat_model = await create_threat_model(
                db,
                request.threat_model,
                owner_id=current_user.id,
                organization_id=getattr(current_user, "organization_id", None),
            )
            threat_model_id = threat_model.id
            request.review.threat_model_id = threat_model.id
            steps.append(_step("threat_model", "pass", f"created {threat_model.id}"))
        elif threat_model_id is not None:
            threat_model = await get_threat_model(db, threat_model_id)
            require_model_permission(threat_model, current_user, "write")  # type: ignore[arg-type]
            steps.append(_step("threat_model", "pass", f"linked {threat_model_id}"))
        else:
            steps.append(_step("threat_model", "skip", "no threat model requested"))

        review = await _create_review(db, current_user=current_user, request=request)
        review_response = serialize_application_review(review)
        steps.append(_step("review", "pass", f"created {review.id}"))

        if request.bundle is not None:
            bundle = await create_review_bundle(
                db,
                current_user=current_user,
                review_id=review.id,
                request=request.bundle,
            )
            await db.commit()
            bundle_response = serialize_application_review_bundle(bundle)
            steps.append(_step("bundle", "pass", f"created {bundle.id}"))
        else:
            steps.append(_step("bundle", "skip", "no bundle requested"))

        if request.scanner_tools:
            if bundle_response is None:
                raise ReviewOrchestrationError("scanner enqueue requires a bundle")
            jobs = await enqueue_review_scanner_jobs(
                db,
                current_user=current_user,
                review_id=review.id,
                request=EnqueueReviewScannersRequest(
                    bundle_id=bundle_response.id,
                    tools=request.scanner_tools,
                    external_active_authorized=request.external_active_authorized,
                    external_targets=request.external_targets,
                ),
            )
            await db.commit()
            scanner_jobs = [ScanJobResponse.model_validate(job) for job in jobs]
            steps.append(_step("scanner_enqueue", "pass", f"enqueued {len(jobs)} job(s)"))
        else:
            steps.append(_step("scanner_enqueue", "skip", "no scanner tools requested"))

        if request.rebuild_context:
            entries = await rebuild_review_context_index(
                db,
                current_user=current_user,
                review_id=review.id,
            )
            await db.commit()
            indexed_entry_count = len(entries)
            steps.append(_step("context_rebuild", "pass", f"indexed {len(entries)} entry(s)"))
        else:
            steps.append(_step("context_rebuild", "skip", "not requested"))

        if request.evaluate_decision:
            decision = await evaluate_application_review_decision(
                db,
                current_user=current_user,
                review_id=review.id,
            )
            await db.commit()
            steps.append(_step("decision", "pass", decision.decision))
        else:
            steps.append(_step("decision", "skip", "not requested"))

        return ApplicationReviewOrchestrationResponse(
            status="completed",
            steps=steps,
            threat_model_id=threat_model_id,
            review=review_response,
            bundle=bundle_response,
            scanner_jobs=scanner_jobs,
            indexed_entry_count=indexed_entry_count,
            decision=decision,
            web_url=_web_url(public_web_base_url, review_response.id if review_response else None),
        )
    except (
        ReviewIdempotencyConflict,
        ReviewValidationError,
        ReviewBundleValidationError,
        ReviewScannerEnqueueError,
        ApplicationReviewContextError,
        ReviewOrchestrationError,
        ValueError,
    ) as exc:
        await db.rollback()
        steps.append(_step(_failure_stage(steps), "fail", str(exc)))
        return ApplicationReviewOrchestrationResponse(
            status="failed",
            steps=steps,
            failure_reason=str(exc),
            threat_model_id=threat_model_id,
            review=review_response,
            bundle=bundle_response,
            scanner_jobs=scanner_jobs,
            indexed_entry_count=indexed_entry_count,
            decision=decision,
            web_url=_web_url(public_web_base_url, review_response.id if review_response else None),
        )


async def _create_review(
    db: AsyncSession,
    *,
    current_user: User,
    request: ApplicationReviewOrchestrationRequest,
):
    try:
        review = await create_application_review(
            db,
            current_user=current_user,
            request=request.review,
        )
        await db.commit()
        return review
    except IntegrityError:
        await db.rollback()
        tenant_key = tenant_key_for_user(current_user)
        idempotency_key = request.review.idempotency_key or generated_idempotency_key(
            tenant_key,
            request.review,
        )
        review = await get_application_review_by_idempotency_key(
            db,
            tenant_key=tenant_key,
            idempotency_key=idempotency_key,
        )
        if review is None:
            raise
        ensure_idempotent_review_matches(review, request.review)
        return review


def _step(name: str, status: StepStatus, detail: str) -> ReviewOrchestrationStep:
    return ReviewOrchestrationStep(name=name, status=status, detail=detail)


def _failure_stage(steps: list[ReviewOrchestrationStep]) -> str:
    passed = {step.name for step in steps if step.status == "pass"}
    for name in ("threat_model", "review", "bundle", "scanner_enqueue", "context_rebuild", "decision"):
        if name not in passed:
            return name
    return "orchestration"


def _web_url(base_url: str | None, review_id) -> str | None:
    if not base_url or review_id is None:
        return None
    return f"{base_url.rstrip('/')}/reviews/{review_id}"
