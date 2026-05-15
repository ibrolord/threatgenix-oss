from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.schemas.application_review import ApplicationReviewCreate, fingerprint_scope
from app.services.application_review import (
    ReviewIdempotencyConflict,
    ReviewValidationError,
    create_application_review,
    ensure_idempotent_review_matches,
    generated_idempotency_key,
    tenant_key_for_user,
    transition_application_review_status,
)


class _Result:
    def __init__(self, item: object | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item


class _ScalarResult:
    def __init__(self, items: list[object]) -> None:
        self.items = items

    def all(self):
        return self.items


class _ListResult:
    def __init__(self, items: list[object]) -> None:
        self.items = items

    def scalars(self):
        return _ScalarResult(self.items)


class _FakeSession:
    def __init__(self, execute_results: list[object | None] | None = None) -> None:
        self.execute_results = list(execute_results or [])
        self.added: list[object] = []
        self.flush_count = 0

    async def execute(self, statement: object):
        del statement
        item = self.execute_results.pop(0) if self.execute_results else None
        if isinstance(item, list):
            return _ListResult(item)
        return _Result(item)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


def _user(*, user_id: uuid.UUID | None = None, organization_id: uuid.UUID | None = None):
    return SimpleNamespace(
        id=user_id or uuid.uuid4(),
        organization_id=organization_id,
        email="owner@example.com",
    )


def _review_request(**overrides) -> ApplicationReviewCreate:
    payload = {
        "app_name": "ExampleApp",
        "invocation_surface": "cli",
        "input_kind": "diff",
        "commit_sha": "abc123",
        "scope": {"paths": ["apps/api/users.py"], "risk": "pii-export"},
        "requested_tools": ["semgrep", "trufflehog"],
        "policy": {"block_on": ["critical"]},
        "intake_answers": {
            "business_purpose": "Exports customer data for support operations.",
            "data_classification": "restricted",
            "sensitive_data_types": ["pii"],
            "changed_security_surface": ["sensitive_data", "authz"],
            "scanner_permissions": ["static_code", "dependencies", "secrets"],
            "upload_permission": True,
            "out_of_scope": ["production database contents"],
        },
    }
    payload.update(overrides)
    return ApplicationReviewCreate(**payload)


@pytest.mark.asyncio
async def test_create_application_review_generates_tenant_scoped_idempotency_key():
    user = _user(organization_id=uuid.uuid4())
    request = _review_request()
    db = _FakeSession()

    review = await create_application_review(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        request=request,
    )

    assert review in db.added
    assert review.tenant_key == f"org:{user.organization_id}"
    assert review.owner_id == user.id
    assert review.organization_id == user.organization_id
    assert review.review_lineage_id == review.id
    assert review.status == "created"
    assert review.scope_fingerprint == fingerprint_scope(request.scope)
    assert review.context["intake"]["answers"]["data_classification"] == "restricted"
    assert review.idempotency_key == generated_idempotency_key(review.tenant_key, request)
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_create_application_review_reuses_matching_idempotent_request():
    user = _user()
    request = _review_request(idempotency_key="review-key-1")
    existing = ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),  # type: ignore[arg-type]
        owner_id=user.id,
        organization_id=None,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name=request.app_name,
        invocation_surface=request.invocation_surface,
        input_kind=request.input_kind,
        commit_sha=request.commit_sha,
        bundle_hash=request.bundle_hash,
        scope_fingerprint=fingerprint_scope(request.scope),
        idempotency_key=request.idempotency_key,
        requested_tools=request.requested_tools,
        scope=request.scope,
        context={
            "intake": {
                "version": request.intake_version,
                "review_type": request.input_kind,
                "answers": request.intake_answers,
            }
        },
        policy=request.policy,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db = _FakeSession([existing])

    review = await create_application_review(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        request=request,
    )

    assert review is existing
    assert db.added == []
    assert db.flush_count == 0


def test_idempotent_review_rejects_request_drift():
    request = _review_request(idempotency_key="review-key-1")
    existing = ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key="user:owner",
        owner_id=uuid.uuid4(),
        organization_id=None,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name=request.app_name,
        invocation_surface=request.invocation_surface,
        input_kind=request.input_kind,
        commit_sha="different-sha",
        bundle_hash=request.bundle_hash,
        scope_fingerprint=fingerprint_scope(request.scope),
        idempotency_key=request.idempotency_key,
        requested_tools=request.requested_tools,
        scope=request.scope,
        context={
            "intake": {
                "version": request.intake_version,
                "review_type": request.input_kind,
                "answers": request.intake_answers,
            }
        },
        policy=request.policy,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    with pytest.raises(ReviewIdempotencyConflict):
        ensure_idempotent_review_matches(existing, request)


@pytest.mark.asyncio
async def test_child_review_inherits_parent_lineage_inside_same_tenant():
    user = _user()
    parent = ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),  # type: ignore[arg-type]
        owner_id=user.id,
        organization_id=None,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint=fingerprint_scope({"paths": ["old.py"]}),
        idempotency_key="parent-key",
        requested_tools=["semgrep"],
        scope={"paths": ["old.py"]},
        context={},
        policy={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    request = _review_request(parent_review_id=parent.id, commit_sha="def456")
    db = _FakeSession([None, parent])

    child = await create_application_review(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        request=request,
    )

    assert child.parent_review_id == parent.id
    assert child.review_lineage_id == parent.review_lineage_id


@pytest.mark.asyncio
async def test_child_review_rejects_parent_outside_tenant():
    user = _user()
    request = _review_request(parent_review_id=uuid.uuid4())
    db = _FakeSession([None, None])

    with pytest.raises(ValueError, match="Parent review"):
        await create_application_review(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            request=request,
        )


def test_review_status_state_machine_allows_planned_lifecycle_path():
    user = _user()
    review = ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),  # type: ignore[arg-type]
        owner_id=user.id,
        organization_id=None,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="created",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    for next_status in ("bundle_received", "scanning", "indexing", "deciding", "completed"):
        transition_application_review_status(review, next_status)  # type: ignore[arg-type]

    assert review.status == "completed"


def test_review_status_state_machine_rejects_terminal_mutation():
    user = _user()
    review = ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),  # type: ignore[arg-type]
        owner_id=user.id,
        organization_id=None,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="completed",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    with pytest.raises(ReviewValidationError, match="Invalid review status transition"):
        transition_application_review_status(review, "scanning")
