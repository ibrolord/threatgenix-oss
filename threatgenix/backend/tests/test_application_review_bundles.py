from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.schemas.application_review_bundle import (
    ApplicationReviewBundleCreate,
    ApplicationReviewBundleManifestItem,
)
from app.services.application_review import tenant_key_for_user
from app.services.application_review_bundles import (
    ReviewBundleValidationError,
    build_bundle_integrity,
    bundle_id_for_content,
    compute_bundle_hash,
    create_review_bundle,
    normalize_manifest,
    safe_manifest_path,
    verify_bundle_integrity,
)


class _Result:
    def __init__(self, item: object | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item

    def scalars(self):
        items = self.item if isinstance(self.item, list) else ([] if self.item is None else [self.item])
        return SimpleNamespace(all=lambda: items)


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


def _user(*, organization_id: uuid.UUID | None = None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        email="owner@example.com",
    )


def _review(user, *, review_id: uuid.UUID | None = None) -> ApplicationSecurityReview:
    now = datetime.now(timezone.utc)
    return ApplicationSecurityReview(
        id=review_id or uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        owner_id=user.id,
        organization_id=user.organization_id,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
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


def _item(path: str, *, size: int = 120, sha: str | None = None) -> ApplicationReviewBundleManifestItem:
    return ApplicationReviewBundleManifestItem(
        path=path,
        file_kind="source",
        sha256=sha or "a" * 64,
        byte_size=size,
        source="cli",
    )


def _request(*items: ApplicationReviewBundleManifestItem) -> ApplicationReviewBundleCreate:
    return ApplicationReviewBundleCreate(
        bundle_kind="diff",
        source="cli",
        manifest=list(items) or [_item("apps/api/users.py")],
    )


def test_manifest_hash_is_order_independent_and_changes_with_content():
    manifest_a, _ = normalize_manifest(
        [_item("b.py", sha="b" * 64), _item("a.py", sha="a" * 64)]
    )
    manifest_b, _ = normalize_manifest(
        [_item("a.py", sha="a" * 64), _item("b.py", sha="b" * 64)]
    )
    manifest_c, _ = normalize_manifest(
        [_item("a.py", sha="c" * 64), _item("b.py", sha="b" * 64)]
    )

    assert manifest_a == manifest_b
    assert compute_bundle_hash("diff", manifest_a) == compute_bundle_hash("diff", manifest_b)
    assert compute_bundle_hash("diff", manifest_a) != compute_bundle_hash("diff", manifest_c)


def test_bundle_id_is_deterministic_from_tenant_review_and_content():
    review_id = uuid.uuid4()
    content_hash = "a" * 64

    assert bundle_id_for_content(
        tenant_key="org:test",
        review_id=review_id,
        content_hash=content_hash,
    ) == bundle_id_for_content(
        tenant_key="org:test",
        review_id=review_id,
        content_hash=content_hash,
    )
    assert bundle_id_for_content(
        tenant_key="org:other",
        review_id=review_id,
        content_hash=content_hash,
    ) != bundle_id_for_content(
        tenant_key="org:test",
        review_id=review_id,
        content_hash=content_hash,
    )


@pytest.mark.parametrize("bad_path", ["../secret.py", "/tmp/secret.py", "apps/../secret.py", "apps\\secret.py", "bad\x00path"])
def test_safe_manifest_path_rejects_escape_paths(bad_path: str):
    with pytest.raises(ReviewBundleValidationError):
        safe_manifest_path(bad_path)


def test_normalize_manifest_rejects_duplicate_paths():
    with pytest.raises(ReviewBundleValidationError, match="Duplicate"):
        normalize_manifest([_item("apps/api/users.py"), _item("apps/api/users.py", sha="b" * 64)])


def test_normalize_manifest_rejects_oversized_total(monkeypatch):
    monkeypatch.setenv("APPLICATION_REVIEW_BUNDLE_MAX_BYTES", "10")

    with pytest.raises(ReviewBundleValidationError, match="too large"):
        normalize_manifest([_item("apps/api/users.py", size=11)])


@pytest.mark.asyncio
async def test_create_review_bundle_attaches_to_tenant_review():
    user = _user(organization_id=uuid.uuid4())
    review = _review(user)
    db = _FakeSession([review, None, []])

    bundle = await create_review_bundle(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        request=_request(),
    )

    assert bundle in db.added
    assert bundle.tenant_key == review.tenant_key
    assert bundle.review_id == review.id
    assert bundle.owner_id == user.id
    assert bundle.organization_id == user.organization_id
    assert bundle.file_count == 1
    assert bundle.byte_size == 120
    assert bundle.manifest[0]["path"] == "apps/api/users.py"
    assert bundle.id == bundle_id_for_content(
        tenant_key=review.tenant_key,
        review_id=review.id,
        content_hash=bundle.content_hash,
    )
    assert bundle.storage_backend == "database_manifest"
    assert bundle.encryption_status == "metadata_only"
    assert bundle.integrity["content_hash"] == bundle.content_hash
    verify_bundle_integrity(bundle)
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_create_review_bundle_reuses_duplicate_manifest():
    user = _user()
    review = _review(user)
    manifest, total_bytes = normalize_manifest(_request().manifest)
    content_hash = compute_bundle_hash("diff", manifest)
    existing = ApplicationReviewBundle(
        id=bundle_id_for_content(
            tenant_key=review.tenant_key,
            review_id=review.id,
            content_hash=content_hash,
        ),
        tenant_key=review.tenant_key,
        review_id=review.id,
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
            byte_size=total_bytes,
            file_count=len(manifest),
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=total_bytes,
        file_count=len(manifest),
        legal_hold=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db = _FakeSession([review, existing])

    bundle = await create_review_bundle(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        request=_request(),
    )

    assert bundle is existing
    assert db.added == []
    assert db.flush_count == 0


@pytest.mark.asyncio
async def test_create_review_bundle_supersedes_prior_ready_bundle():
    user = _user()
    review = _review(user)
    prior_manifest, prior_total_bytes = normalize_manifest([_item("apps/api/old.py")])
    prior_hash = compute_bundle_hash("diff", prior_manifest)
    prior = ApplicationReviewBundle(
        id=bundle_id_for_content(
            tenant_key=review.tenant_key,
            review_id=review.id,
            content_hash=prior_hash,
        ),
        tenant_key=review.tenant_key,
        review_id=review.id,
        owner_id=user.id,
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=prior_manifest,
        redaction_report={},
        integrity=build_bundle_integrity(
            bundle_kind="diff",
            manifest=prior_manifest,
            content_hash=prior_hash,
            byte_size=prior_total_bytes,
            file_count=len(prior_manifest),
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=prior_hash,
        byte_size=prior_total_bytes,
        file_count=len(prior_manifest),
        legal_hold=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db = _FakeSession([review, None, [prior]])

    bundle = await create_review_bundle(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        request=_request(_item("apps/api/new.py", sha="b" * 64)),
    )

    assert bundle.status == "ready"
    assert prior.status == "superseded"


def test_verify_bundle_integrity_fails_closed_on_tampered_manifest():
    manifest, total_bytes = normalize_manifest([_item("apps/api/users.py")])
    content_hash = compute_bundle_hash("diff", manifest)
    bundle = ApplicationReviewBundle(
        id=uuid.uuid4(),
        tenant_key="org:test",
        review_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=[{**manifest[0], "sha256": "b" * 64}],
        redaction_report={},
        integrity=build_bundle_integrity(
            bundle_kind="diff",
            manifest=manifest,
            content_hash=content_hash,
            byte_size=total_bytes,
            file_count=len(manifest),
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=total_bytes,
        file_count=len(manifest),
        legal_hold=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    with pytest.raises(ReviewBundleValidationError, match="content hash"):
        verify_bundle_integrity(bundle)


@pytest.mark.asyncio
async def test_create_review_bundle_rejects_cross_tenant_review():
    user = _user()
    db = _FakeSession([None])

    with pytest.raises(ReviewBundleValidationError, match="not found"):
        await create_review_bundle(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=uuid.uuid4(),
            request=_request(),
        )
