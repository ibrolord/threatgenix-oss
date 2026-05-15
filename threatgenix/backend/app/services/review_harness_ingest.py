"""Persist trusted managed scanner harness output for application reviews."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanExecutionArtifact, ScanFinding, ScanJob
from app.models.user import User
from app.schemas.review_harness_ingest import (
    IngestHarnessOutputRequest,
    IngestHarnessOutputResponse,
)
from app.services.application_review import get_application_review, tenant_key_for_user
from app.services.application_review_bundles import canonical_json, get_review_bundle
from app.services.review_scanner_enqueue import REVIEW_BUNDLE_TARGET_SCHEME
from app.services.tool_harness import (
    ToolHarnessValidationError,
    normalize_tool_output_against_bundle,
)

HARNESS_VALIDATION_ORIGIN = "review_harness"


class ReviewHarnessIngestionError(ValueError):
    """Raised when managed scanner harness output cannot be safely persisted."""


async def ingest_review_harness_output(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
    scan_job_id: UUID,
    request: IngestHarnessOutputRequest,
) -> IngestHarnessOutputResponse:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise ReviewHarnessIngestionError("Review was not found for this tenant.")
    if review.threat_model_id is None:
        raise ReviewHarnessIngestionError(
            "Harness ingestion requires a review linked to a threat model."
        )

    bundle = await get_review_bundle(
        db,
        tenant_key=tenant_key,
        review_id=review_id,
        bundle_id=request.bundle_id,
    )
    if bundle is None:
        raise ReviewHarnessIngestionError("Review bundle was not found for this tenant.")

    scan_job = await _get_review_scan_job(
        db,
        scan_job_id=scan_job_id,
        owner_id=current_user.id,
        threat_model_id=review.threat_model_id,
    )
    if scan_job is None:
        raise ReviewHarnessIngestionError("Scan job was not found for this review.")
    if scan_job.tool_name != request.output.tool_name:
        raise ReviewHarnessIngestionError("Harness output tool_name does not match scan job.")
    if scan_job.targets.get("bundle") != f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}":
        raise ReviewHarnessIngestionError("Scan job is not scoped to this review bundle.")

    try:
        normalized = normalize_tool_output_against_bundle(request.output, bundle)
    except ToolHarnessValidationError as exc:
        raise ReviewHarnessIngestionError(str(exc)) from exc

    now = datetime.now(timezone.utc)
    finding_keys: list[str] = []
    if normalized.status == "completed":
        existing_keys = await _existing_harness_finding_keys(db, scan_job_id=scan_job.id)
        created_count = 0
        for finding in normalized.findings:
            finding_keys.append(finding.finding_key)
            if finding.finding_key in existing_keys:
                continue
            db.add(
                ScanFinding(
                    scan_job_id=scan_job.id,
                    template_id=finding.rule_id,
                    template_name=finding.title,
                    severity=finding.severity.lower(),
                    matched_at=_matched_at(finding.path, finding.start_line),
                    extracted_results=finding.evidence_snippet_sha256,
                    cve_ids=[],
                    tags=[
                        finding.source_type,
                        "threatgenix-harness",
                        finding.finding_key,
                    ],
                    cvss_score=None,
                    raw_output=_raw_finding_output(
                        review_id=review.id,
                        bundle_id=bundle.id,
                        normalized=normalized,
                        finding=finding,
                    ),
                )
            )
            existing_keys.add(finding.finding_key)
            created_count += 1
        scan_job.status = "completed"
        scan_job.completed_at = now
        scan_job.error_message = None
        scan_job.failure_code = None
        scan_job.finding_count = len(existing_keys)
    else:
        scan_job.status = "failed"
        scan_job.completed_at = now
        scan_job.failure_code = f"harness_{normalized.status}"
        scan_job.error_message = f"Managed scanner harness output was {normalized.status}."
        scan_job.finding_count = 0

    db.add(_execution_artifact(scan_job=scan_job, bundle_id=bundle.id, normalized=normalized, at=now))
    await db.flush()

    return IngestHarnessOutputResponse(
        review_id=review.id,
        bundle_id=bundle.id,
        scan_job_id=scan_job.id,
        status=scan_job.status,
        finding_count=scan_job.finding_count or 0,
        finding_keys=finding_keys,
    )


async def _get_review_scan_job(
    db: AsyncSession,
    *,
    scan_job_id: UUID,
    owner_id: UUID,
    threat_model_id: UUID,
) -> ScanJob | None:
    result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.id == scan_job_id,
            ScanJob.owner_id == owner_id,
            ScanJob.threat_model_id == threat_model_id,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _existing_harness_finding_keys(db: AsyncSession, *, scan_job_id: UUID) -> set[str]:
    result = await db.execute(select(ScanFinding).where(ScanFinding.scan_job_id == scan_job_id))
    keys: set[str] = set()
    for finding in result.scalars().all():
        raw_output = finding.raw_output or {}
        harness = raw_output.get("threatgenix_harness") if isinstance(raw_output, dict) else None
        if isinstance(harness, dict) and harness.get("finding_key"):
            keys.add(str(harness["finding_key"]))
    return keys


def _matched_at(path: str, start_line: int) -> str:
    return f"{path}:{start_line}"


def _raw_finding_output(*, review_id: UUID, bundle_id: UUID, normalized, finding) -> dict:
    return {
        "threatgenix_harness": {
            "finding_key": finding.finding_key,
            "review_id": str(review_id),
            "bundle_id": str(bundle_id),
            "scanner_run_id": normalized.scanner_run_id,
            "ruleset_version": normalized.ruleset_version,
            "provenance": normalized.provenance.model_dump(mode="json"),
            "raw_artifact_refs": normalized.raw_artifact_refs,
            "evidence_snippet_sha256": finding.evidence_snippet_sha256,
            "confidence": finding.confidence,
            "source_type": finding.source_type,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
        },
        "threatgenix_validation": {
            "tool_name": normalized.tool_name,
            "tool_version": normalized.tool_version,
            "target": f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle_id}",
            "deterministic": True,
            "evidence_origin": HARNESS_VALIDATION_ORIGIN,
            "synthetic": False,
        },
    }


def _execution_artifact(*, scan_job: ScanJob, bundle_id: UUID, normalized, at: datetime) -> ScanExecutionArtifact:
    payload = canonical_json(normalized.model_dump(mode="json"))
    payload_bytes = payload.encode("utf-8")
    provenance = normalized.provenance
    return ScanExecutionArtifact(
        scan_job_id=scan_job.id,
        source="ingest",
        tool_name=normalized.tool_name,
        target_type=scan_job.target_type,
        target=f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle_id}",
        resolved_target=f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle_id}",
        status="completed" if normalized.status == "completed" else normalized.status,
        deterministic=True,
        sandboxed=True,
        sandbox_mode="managed_harness",
        container_image=provenance.scanner_image,
        resource_limits={},
        policy_decision="managed scanner harness output accepted",
        command=[],
        command_redacted=True,
        returncode=0 if normalized.status == "completed" else 1,
        timed_out=False,
        output_limit_exceeded=False,
        stdout_bytes=len(payload_bytes),
        output_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        stderr_summary=None if normalized.status == "completed" else f"harness_{normalized.status}",
        network_mode="none",
        max_runtime_seconds=None,
        max_output_bytes=None,
        started_at=at,
        completed_at=at,
        duration_ms=0,
    )
