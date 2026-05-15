from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.scan import ScanJob
from app.schemas.review_scanners import EnqueueReviewScannersRequest
from app.services.application_review import tenant_key_for_user
from app.services.application_review_bundles import build_bundle_integrity, compute_bundle_hash
from app.services.review_scanner_enqueue import (
    REVIEW_BUNDLE_TARGET_SCHEME,
    ReviewScannerEnqueueError,
    enqueue_review_scanner_jobs,
)


class _Result:
    def __init__(self, item: object | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item


class _FakeSession:
    def __init__(self, execute_results: list[object | None] | None = None) -> None:
        self.execute_results = list(execute_results or [])
        self.added: list[object] = []
        self.flush_count = 0

    async def execute(self, statement: object):
        del statement
        item = self.execute_results.pop(0) if self.execute_results else None
        return _Result(item)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


def _user():
    return SimpleNamespace(id=uuid.uuid4(), organization_id=None, email="owner@example.com")


def _review(user, *, requested_tools=None, threat_model_id=None) -> ApplicationSecurityReview:
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
        status="bundle_received",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=requested_tools or ["semgrep"],
        scope={},
        context={},
        policy={},
        created_at=now,
        updated_at=now,
    )


def _bundle(user, review_id: uuid.UUID, *, status: str = "ready", manifest=None) -> ApplicationReviewBundle:
    now = datetime.now(timezone.utc)
    normalized_manifest = manifest or [
        {
            "path": "apps/api/users.py",
            "file_kind": "source",
            "sha256": "a" * 64,
            "byte_size": 120,
            "source": "cli",
        }
    ]
    content_hash = compute_bundle_hash("diff", normalized_manifest)
    byte_size = sum(item["byte_size"] for item in normalized_manifest)
    return ApplicationReviewBundle(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        review_id=review_id,
        owner_id=user.id,
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status=status,
        manifest=normalized_manifest,
        redaction_report={},
        integrity=build_bundle_integrity(
            bundle_kind="diff",
            manifest=normalized_manifest,
            content_hash=content_hash,
            byte_size=byte_size,
            file_count=len(normalized_manifest),
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=byte_size,
        file_count=len(normalized_manifest),
        legal_hold=False,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_enqueue_semgrep_creates_one_pending_scan_and_marks_review_scanning():
    user = _user()
    review = _review(user, requested_tools=["semgrep"])
    bundle = _bundle(user, review.id)
    db = _FakeSession([review, bundle, None])

    jobs = await enqueue_review_scanner_jobs(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        request=EnqueueReviewScannersRequest(bundle_id=bundle.id),
    )

    assert len(jobs) == 1
    assert jobs[0] in db.added
    assert jobs[0].tool_name == "semgrep"
    assert jobs[0].target_type == "repository_path"
    assert jobs[0].targets == {"bundle": f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}"}
    assert review.status == "scanning"
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_enqueue_duplicate_review_bundle_tool_reuses_existing_job():
    user = _user()
    review = _review(user, requested_tools=["semgrep"])
    bundle = _bundle(user, review.id)
    existing = ScanJob(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        owner_id=user.id,
        status="pending",
        scan_type="unauthenticated",
        scope="internal",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"bundle": f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}"},
        nuclei_templates=[],
        finding_count=0,
    )
    db = _FakeSession([review, bundle, existing])

    jobs = await enqueue_review_scanner_jobs(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        request=EnqueueReviewScannersRequest(bundle_id=bundle.id),
    )

    assert jobs == [existing]
    assert db.added == []
    assert review.status == "scanning"


@pytest.mark.asyncio
async def test_enqueue_rejects_review_without_threat_model():
    user = _user()
    review = _review(user, threat_model_id=None)
    review.threat_model_id = None
    db = _FakeSession([review])

    with pytest.raises(ReviewScannerEnqueueError, match="linked to a threat model"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(bundle_id=uuid.uuid4()),
        )


@pytest.mark.asyncio
async def test_enqueue_rejects_cross_tenant_missing_bundle():
    user = _user()
    review = _review(user)
    db = _FakeSession([review, None])

    with pytest.raises(ReviewScannerEnqueueError, match="bundle"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(bundle_id=uuid.uuid4()),
        )


@pytest.mark.asyncio
async def test_enqueue_rejects_deleted_bundle():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id, status="deleted")
    db = _FakeSession([review, bundle])

    with pytest.raises(ReviewScannerEnqueueError, match="not ready"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(bundle_id=bundle.id),
        )


@pytest.mark.asyncio
async def test_enqueue_rejects_unsupported_requested_tool():
    user = _user()
    review = _review(user, requested_tools=["security-review"])
    bundle = _bundle(user, review.id)
    db = _FakeSession([review, bundle])

    with pytest.raises(ReviewScannerEnqueueError, match="Unsupported"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(bundle_id=bundle.id),
        )


@pytest.mark.asyncio
async def test_enqueue_blocks_nuclei_without_explicit_external_authorization():
    user = _user()
    review = _review(user, requested_tools=["nuclei"])
    bundle = _bundle(user, review.id)
    db = _FakeSession([review, bundle])

    with pytest.raises(ReviewScannerEnqueueError, match="requires explicit authorization"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(bundle_id=bundle.id),
        )


@pytest.mark.asyncio
async def test_enqueue_nuclei_requires_external_target_when_authorized():
    user = _user()
    review = _review(user, requested_tools=["nuclei"])
    bundle = _bundle(user, review.id)
    db = _FakeSession([review, bundle])

    with pytest.raises(ReviewScannerEnqueueError, match="external target"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(
                bundle_id=bundle.id,
                external_active_authorized=True,
            ),
        )


@pytest.mark.asyncio
async def test_enqueue_osv_requires_dependency_lock_manifest():
    user = _user()
    review = _review(user, requested_tools=["osv-scanner"])
    bundle = _bundle(user, review.id)
    db = _FakeSession([review, bundle])

    with pytest.raises(ReviewScannerEnqueueError, match="dependency_lock"):
        await enqueue_review_scanner_jobs(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=EnqueueReviewScannersRequest(bundle_id=bundle.id),
        )
