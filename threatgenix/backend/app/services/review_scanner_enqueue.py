"""Plan and enqueue managed scanner jobs for review bundles."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanJob
from app.models.user import User
from app.schemas.review_scanners import EnqueueReviewScannersRequest
from app.services.application_review import (
    get_application_review,
    tenant_key_for_user,
    transition_application_review_status,
)
from app.services.application_review_bundles import get_review_bundle

REVIEW_BUNDLE_TARGET_SCHEME = "tgx-review-bundle://"
SUPPORTED_REVIEW_SCANNER_TOOLS = {
    "semgrep",
    "osv-scanner",
    "trivy",
    "checkov",
    "trufflehog",
    "nuclei",
}


class ReviewScannerEnqueueError(ValueError):
    """Raised when scanner jobs cannot be safely enqueued."""


async def enqueue_review_scanner_jobs(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
    request: EnqueueReviewScannersRequest,
) -> list[ScanJob]:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise ReviewScannerEnqueueError("Review was not found for this tenant.")
    if review.threat_model_id is None:
        raise ReviewScannerEnqueueError(
            "Review scanner enqueue requires a review linked to a threat model."
        )
    bundle = await get_review_bundle(
        db,
        tenant_key=tenant_key,
        review_id=review_id,
        bundle_id=request.bundle_id,
    )
    if bundle is None:
        raise ReviewScannerEnqueueError("Review bundle was not found for this tenant.")
    if bundle.status != "ready":
        raise ReviewScannerEnqueueError("Review bundle is not ready.")

    tools = list(dict.fromkeys(request.tools or review.requested_tools or []))
    if not tools:
        raise ReviewScannerEnqueueError("No requested scanner tools were provided.")
    unsupported = [tool for tool in tools if tool not in SUPPORTED_REVIEW_SCANNER_TOOLS]
    if unsupported:
        raise ReviewScannerEnqueueError(f"Unsupported review scanner tool: {unsupported[0]}")
    if "nuclei" in tools and not request.external_active_authorized:
        raise ReviewScannerEnqueueError(
            "Active external scanning with nuclei requires explicit authorization."
        )

    jobs: list[ScanJob] = []
    for tool_name in tools:
        plan = _plan_scan_job(tool_name, bundle, request)
        existing = await _get_existing_review_scan_job(
            db,
            threat_model_id=review.threat_model_id,
            owner_id=current_user.id,
            tool_name=tool_name,
            target_type=plan["target_type"],
            targets=plan["targets"],
        )
        if existing is not None:
            jobs.append(existing)
            continue
        job = ScanJob(
            threat_model_id=review.threat_model_id,
            owner_id=current_user.id,
            status="pending",
            scan_type="unauthenticated",
            scope=plan["scope"],
            tool_name=tool_name,
            target_type=plan["target_type"],
            targets=plan["targets"],
            nuclei_templates=[],
            finding_count=0,
            credential_id=None,
        )
        db.add(job)
        jobs.append(job)

    if jobs:
        transition_application_review_status(review, "scanning")
        await db.flush()
    return jobs


async def _get_existing_review_scan_job(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    owner_id: UUID,
    tool_name: str,
    target_type: str,
    targets: dict[str, str],
) -> ScanJob | None:
    result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.threat_model_id == threat_model_id,
            ScanJob.owner_id == owner_id,
            ScanJob.tool_name == tool_name,
            ScanJob.target_type == target_type,
            ScanJob.targets == targets,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


def _plan_scan_job(tool_name: str, bundle, request: EnqueueReviewScannersRequest) -> dict[str, object]:
    if tool_name == "nuclei":
        if not request.external_targets:
            raise ReviewScannerEnqueueError("nuclei requires at least one external target.")
        return {
            "target_type": "url",
            "scope": "external",
            "targets": {
                f"external:{index}": target
                for index, target in enumerate(request.external_targets)
            },
        }

    manifest_kinds = {str(item.get("file_kind") or "other") for item in bundle.manifest or []}
    if tool_name == "osv-scanner" and "dependency_lock" not in manifest_kinds:
        raise ReviewScannerEnqueueError("osv-scanner requires a dependency_lock file in the bundle.")
    if tool_name == "checkov" and "iac" not in manifest_kinds:
        raise ReviewScannerEnqueueError("checkov requires an iac file in the bundle.")

    target_type = {
        "semgrep": "repository_path",
        "osv-scanner": "lockfile",
        "trivy": "repository_path",
        "checkov": "iac_directory",
        "trufflehog": "repository_path",
    }[tool_name]
    return {
        "target_type": target_type,
        "scope": "internal",
        "targets": {
            "bundle": f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}",
        },
    }
