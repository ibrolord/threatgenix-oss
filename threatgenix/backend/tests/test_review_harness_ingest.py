from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.scan import ScanFinding, ScanJob
from app.schemas.review_harness_ingest import IngestHarnessOutputRequest
from app.schemas.tool_harness import ToolHarnessFinding, ToolHarnessOutput
from app.services.application_review import tenant_key_for_user
from app.services.application_review_bundles import build_bundle_integrity, compute_bundle_hash
from app.services.review_harness_ingest import (
    HARNESS_VALIDATION_ORIGIN,
    ReviewHarnessIngestionError,
    ingest_review_harness_output,
)
from app.services.review_scanner_enqueue import REVIEW_BUNDLE_TARGET_SCHEME
from app.services.tool_harness import TRUSTED_HARNESS_ISSUER


class _Result:
    def __init__(self, item: object | list[object] | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item if not isinstance(self.item, list) else None

    def scalars(self):
        return self

    def all(self):
        return self.item if isinstance(self.item, list) else []


class _FakeSession:
    def __init__(self, execute_results: list[object | list[object] | None]) -> None:
        self.execute_results = list(execute_results)
        self.added: list[object] = []
        self.flush_count = 0

    async def execute(self, statement: object):
        del statement
        return _Result(self.execute_results.pop(0) if self.execute_results else None)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


def _user():
    return SimpleNamespace(id=uuid.uuid4(), organization_id=None, email="owner@example.com")


def _review(user, *, threat_model_id=None) -> ApplicationSecurityReview:
    now = datetime.now(timezone.utc)
    return ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        owner_id=user.id,
        organization_id=None,
        threat_model_id=threat_model_id or uuid.uuid4(),
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="running",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy={},
        created_at=now,
        updated_at=now,
    )


def _bundle(user, review_id: uuid.UUID) -> ApplicationReviewBundle:
    now = datetime.now(timezone.utc)
    manifest = [
        {
            "path": "apps/api/users.py",
            "file_kind": "source",
            "sha256": "a" * 64,
            "byte_size": 120,
            "source": "cli",
        }
    ]
    content_hash = compute_bundle_hash("diff", manifest)
    return ApplicationReviewBundle(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        review_id=review_id,
        owner_id=user.id,
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=manifest,
        redaction_report={},
        integrity=build_bundle_integrity(
            bundle_kind="diff",
            manifest=manifest,
            content_hash=content_hash,
            byte_size=120,
            file_count=1,
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=120,
        file_count=1,
        legal_hold=False,
        created_at=now,
        updated_at=now,
    )


def _scan_job(user, review: ApplicationSecurityReview, bundle: ApplicationReviewBundle) -> ScanJob:
    return ScanJob(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        owner_id=user.id,
        status="running",
        scan_type="unauthenticated",
        scope="internal",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"bundle": f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}"},
        nuclei_templates=[],
        finding_count=0,
    )


def _finding(**overrides) -> ToolHarnessFinding:
    payload = {
        "rule_id": "python.fastapi.missing-authz",
        "title": "Sensitive export route is missing authorization",
        "severity": "High",
        "path": "apps/api/users.py",
        "start_line": 42,
        "end_line": 45,
        "evidence_snippet_sha256": "c" * 64,
        "confidence": "high",
        "source_type": "sast",
    }
    payload.update(overrides)
    return ToolHarnessFinding(**payload)


def _output(bundle: ApplicationReviewBundle, **overrides) -> ToolHarnessOutput:
    payload = {
        "tool_name": "semgrep",
        "tool_version": "1.2.3",
        "ruleset_version": "rules-2026-05-01",
        "scanner_run_id": "run-123",
        "bundle_id": bundle.id,
        "status": "completed",
        "findings": [_finding()],
        "raw_artifact_refs": ["artifact://semgrep/run-123"],
        "provenance": {
            "issuer": TRUSTED_HARNESS_ISSUER,
            "tool_name": "semgrep",
            "scanner_run_id": "run-123",
            "bundle_id": bundle.id,
            "output_format": "threatgenix-harness-v1",
        },
    }
    payload.update(overrides)
    return ToolHarnessOutput(**payload)


@pytest.mark.asyncio
async def test_ingest_valid_harness_output_creates_scan_finding_with_provenance():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    job = _scan_job(user, review, bundle)
    db = _FakeSession([review, bundle, job, []])

    response = await ingest_review_harness_output(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        scan_job_id=job.id,
        request=IngestHarnessOutputRequest(bundle_id=bundle.id, output=_output(bundle)),
    )

    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert len(findings) == 1
    assert response.status == "completed"
    assert response.finding_count == 1
    assert response.finding_keys == findings[0].tags[-1:]
    assert job.status == "completed"
    assert findings[0].severity == "high"
    assert findings[0].matched_at == "apps/api/users.py:42"
    assert findings[0].tool_name == "semgrep"
    assert findings[0].evidence_origin == HARNESS_VALIDATION_ORIGIN
    assert findings[0].synthetic is False
    assert findings[0].raw_output["threatgenix_harness"]["bundle_id"] == str(bundle.id)
    assert findings[0].raw_output["threatgenix_harness"]["scanner_run_id"] == "run-123"


@pytest.mark.asyncio
async def test_ingest_failed_output_marks_job_failed_without_findings():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    job = _scan_job(user, review, bundle)
    db = _FakeSession([review, bundle, job])

    response = await ingest_review_harness_output(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        scan_job_id=job.id,
        request=IngestHarnessOutputRequest(
            bundle_id=bundle.id,
            output=_output(bundle, status="failed", findings=[]),
        ),
    )

    assert response.status == "failed"
    assert response.finding_count == 0
    assert response.finding_keys == []
    assert job.failure_code == "harness_failed"
    assert not any(isinstance(item, ScanFinding) for item in db.added)


@pytest.mark.asyncio
async def test_ingest_rejects_scan_job_tool_mismatch():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    job = _scan_job(user, review, bundle)
    job.tool_name = "trufflehog"
    db = _FakeSession([review, bundle, job])

    with pytest.raises(ReviewHarnessIngestionError, match="tool_name"):
        await ingest_review_harness_output(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            scan_job_id=job.id,
            request=IngestHarnessOutputRequest(bundle_id=bundle.id, output=_output(bundle)),
        )


@pytest.mark.asyncio
async def test_ingest_rejects_scan_job_not_scoped_to_bundle():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    job = _scan_job(user, review, bundle)
    job.targets = {"bundle": f"{REVIEW_BUNDLE_TARGET_SCHEME}{uuid.uuid4()}"}
    db = _FakeSession([review, bundle, job])

    with pytest.raises(ReviewHarnessIngestionError, match="review bundle"):
        await ingest_review_harness_output(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            scan_job_id=job.id,
            request=IngestHarnessOutputRequest(bundle_id=bundle.id, output=_output(bundle)),
        )


@pytest.mark.asyncio
async def test_ingest_rejects_cross_tenant_missing_review():
    user = _user()
    db = _FakeSession([None])

    with pytest.raises(ReviewHarnessIngestionError, match="Review"):
        await ingest_review_harness_output(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=uuid.uuid4(),
            scan_job_id=uuid.uuid4(),
            request=IngestHarnessOutputRequest(
                bundle_id=uuid.uuid4(),
                output=_output(_bundle(user, uuid.uuid4())),
            ),
        )


@pytest.mark.asyncio
async def test_ingest_rejects_finding_path_not_in_manifest():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    job = _scan_job(user, review, bundle)
    db = _FakeSession([review, bundle, job])

    with pytest.raises(ReviewHarnessIngestionError, match="not present"):
        await ingest_review_harness_output(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            scan_job_id=job.id,
            request=IngestHarnessOutputRequest(
                bundle_id=bundle.id,
                output=_output(bundle, findings=[_finding(path="apps/api/admin.py")]),
            ),
        )
