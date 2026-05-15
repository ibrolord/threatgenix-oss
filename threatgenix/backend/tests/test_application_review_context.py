from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.application_risk_acceptance import ApplicationRiskAcceptance
from app.models.scan import ScanFinding
from app.services.application_review import tenant_key_for_user
from app.services.application_review_bundles import build_bundle_integrity, compute_bundle_hash
from app.services.application_review_context import (
    ApplicationReviewContextError,
    rebuild_review_context_index,
    search_review_context_index,
)


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


def _review(user) -> ApplicationSecurityReview:
    now = datetime.now(timezone.utc)
    return ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        owner_id=user.id,
        organization_id=None,
        threat_model_id=uuid.uuid4(),
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="scanning",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={"paths": ["apps/api/users.py"]},
        context={"intake": {"business_purpose": "Export customer data"}},
        policy={"block_on_high": True},
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


def _scan_finding(bundle_id: uuid.UUID) -> ScanFinding:
    return ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="python.fastapi.missing-authz",
        template_name="Sensitive export route is missing authorization",
        severity="high",
        matched_at="apps/api/users.py:42",
        extracted_results="c" * 64,
        cve_ids=[],
        tags=["sast", "threatgenix-harness", "harness:semgrep:key"],
        raw_output={
            "threatgenix_harness": {
                "bundle_id": str(bundle_id),
                "finding_key": "harness:semgrep:key",
                "confidence": "high",
                "source_type": "sast",
            },
            "threatgenix_validation": {
                "tool_name": "semgrep",
                "tool_version": "1.2.3",
                "target": f"tgx-review-bundle://{bundle_id}",
                "deterministic": True,
                "evidence_origin": "review_harness",
                "synthetic": False,
            },
        },
        created_at=datetime.now(timezone.utc),
    )


def _context_entry(user, review_id: uuid.UUID, *, title: str, body: str) -> ApplicationReviewContextEntry:
    now = datetime.now(timezone.utc)
    return ApplicationReviewContextEntry(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        review_id=review_id,
        owner_id=user.id,
        organization_id=None,
        source_type="scan_finding",
        source_object_id=uuid.uuid4(),
        item_type="scanner_finding",
        title=title,
        body=body,
        keywords=body.casefold().split(),
        source_refs=[{"type": "path", "path": "apps/api/users.py:42"}],
        content_hash="d" * 64,
        status="active",
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_rebuild_context_index_projects_review_bundle_and_scanner_finding_entries():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    finding = _scan_finding(bundle.id)
    stale_entry = _context_entry(user, review.id, title="old", body="old")
    db = _FakeSession([review, [stale_entry], [], [bundle], [finding]])

    entries = await rebuild_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert stale_entry.status == "stale"
    assert len(entries) == 5
    assert {entry.item_type for entry in entries} == {
        "app_profile",
        "review_scope",
        "policy",
        "bundle_file",
        "scanner_finding",
    }
    scanner_entry = next(entry for entry in entries if entry.item_type == "scanner_finding")
    assert scanner_entry.tenant_key == tenant_key_for_user(user)
    assert "missing authorization" in scanner_entry.body
    assert any(ref["type"] == "finding_key" for ref in scanner_entry.source_refs)
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_rebuild_context_index_projects_scoped_risk_acceptance_entries():
    user = _user()
    review = _review(user)
    now = datetime.now(timezone.utc)
    acceptance = ApplicationRiskAcceptance(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        app_name=review.app_name,
        review_id=review.id,
        finding_stable_id=None,
        scope_type="route",
        scope_value="apps/api/users.py:42",
        justification="Legacy export route has temporary business approval.",
        compensating_control="Alert on anomalous export volume.",
        approver_id=user.id,
        approved_at=now,
        expires_at=now + timedelta(days=14),
        status="active",
        audit_events=[],
        created_at=now,
        updated_at=now,
    )
    db = _FakeSession([review, [], [acceptance], [], []])

    entries = await rebuild_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    risk_entry = next(entry for entry in entries if entry.item_type == "accepted_risk")
    assert risk_entry.source_type == "manual"
    assert risk_entry.facets["acceptance_state"] == "active"
    assert risk_entry.facets["scope_type"] == "route"
    assert risk_entry.facets["scope_value"] == "apps/api/users.py:42"
    assert risk_entry.facets["compensating_control_present"] is True


@pytest.mark.asyncio
async def test_search_context_index_is_tenant_scoped_and_ranks_keyword_matches():
    user = _user()
    review = _review(user)
    matching = _context_entry(
        user,
        review.id,
        title="Sensitive export route is missing authorization",
        body="sensitive export missing authorization pii",
    )
    unrelated = _context_entry(
        user,
        review.id,
        title="Bundle file",
        body="frontend package manifest",
    )
    db = _FakeSession([review, [unrelated, matching]])

    results = await search_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        query="missing authorization export",
    )

    assert [entry.title for entry in results] == [matching.title]


@pytest.mark.asyncio
async def test_search_context_index_rejects_cross_tenant_missing_review():
    user = _user()
    db = _FakeSession([None])

    with pytest.raises(ApplicationReviewContextError, match="Review"):
        await search_review_context_index(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=uuid.uuid4(),
            query="anything",
        )
