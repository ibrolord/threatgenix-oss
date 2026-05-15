from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.evidence import EvidenceEntity, EvidenceFinding, EvidenceItem, EvidenceRelationship
from app.models.scan import ScanFinding
from app.models.threat import Threat
from app.services.application_review import tenant_key_for_user
from app.services.application_review_bundles import build_bundle_integrity, compute_bundle_hash
from app.services.application_review_context import (
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
        return _Result(self.execute_results.pop(0) if self.execute_results else [])

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


def _user():
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="owner@example.com",
    )


def _review(user, *, decision: str | None = None) -> ApplicationSecurityReview:
    now = datetime.now(timezone.utc)
    return ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        owner_id=user.id,
        organization_id=user.organization_id,
        threat_model_id=uuid.uuid4(),
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="scanning",
        decision=decision,
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep", "checkov"],
        scope={"paths": ["apps/api/users.py"], "targets": ["api.example-app.test"]},
        context={
            "intake": {"business_purpose": "Export customer data"},
            "org_profile": {"industry": "fintech", "data_classes": ["pii"]},
            "controls": [{"name": "RBAC", "status": "required"}],
            "docs": [{"title": "Security overview", "summary": "Customers export PII"}],
            "code_summaries": [{"path": "apps/api/users.py", "summary": "User export route"}],
            "accepted_risks": [{"title": "Legacy export exception", "expires": "2026-06-01"}],
        },
        policy={"block_on_high": True},
        result_summary="High severity finding fixed",
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
        organization_id=user.organization_id,
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
        tags=["sast", "threatgenix-harness"],
        raw_output={
            "threatgenix_harness": {
                "bundle_id": str(bundle_id),
                "finding_key": "harness:semgrep:key",
                "confidence": "high",
                "source_type": "sast",
            }
        },
        created_at=datetime.now(timezone.utc),
    )


def _context_entry(
    user,
    review_id: uuid.UUID,
    *,
    item_type: str,
    source_type: str = "manual",
    title: str = "Context",
    body: str = "customer export authorization",
    status: str = "active",
    facets: dict | None = None,
) -> ApplicationReviewContextEntry:
    now = datetime.now(timezone.utc)
    return ApplicationReviewContextEntry(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        review_id=review_id,
        owner_id=user.id,
        organization_id=user.organization_id,
        source_type=source_type,
        source_object_id=uuid.uuid4(),
        item_type=item_type,
        title=title,
        body=body,
        keywords=body.casefold().split(),
        facets=facets or {"category": item_type},
        retrieval_text=f"{title} {body}",
        source_refs=[{"type": "review", "id": str(review_id)}],
        content_hash="d" * 64,
        status=status,
        stale_reason="superseded" if status == "stale" else None,
        created_at=now,
        updated_at=now,
    )


def _evidence_objects(review: ApplicationSecurityReview):
    source_id = uuid.uuid4()
    entity_a = EvidenceEntity(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        entity_type="api_route",
        canonical_key="route:/v2/users/export",
        display_name="/v2/users/export",
        source_object_type="code",
        source_object_id="apps/api/users.py",
        properties={"method": "GET"},
        status="active",
    )
    entity_b = EvidenceEntity(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        entity_type="data_store",
        canonical_key="store:users",
        display_name="Users table",
        properties={"data": "pii"},
        status="active",
    )
    item = EvidenceItem(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        source_id=source_id,
        stable_key="code-summary:users-export",
        item_type="code_summary",
        title="Users export code summary",
        summary="Route exports restricted customer data",
        raw_ref="apps/api/users.py",
        raw_payload={},
        content_sha256="e" * 64,
        confidence_score=80.0,
        confidence_label="verified",
        freshness_status="fresh",
    )
    relationship = EvidenceRelationship(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        stable_key="route-to-store",
        from_entity_id=entity_a.id,
        to_entity_id=entity_b.id,
        relationship_type="reads_sensitive_data",
        evidence_item_id=item.id,
        confidence_score=75.0,
        confidence_label="verified",
        rationale="Export route reads from users table",
        properties={},
    )
    finding = EvidenceFinding(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        finding_key="missing-authz",
        finding_kind="authorization",
        title="Missing authorization on export",
        description="The export route lacks object authorization",
        severity="High",
        status="accepted",
        source_id=source_id,
        primary_evidence_item_id=item.id,
        confidence_score=85.0,
        confidence_label="verified",
        freshness_status="fresh",
    )
    return item, [entity_a, entity_b], relationship, finding


def _accepted_threat(review: ApplicationSecurityReview) -> Threat:
    return Threat(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        display_id="T-1",
        description="Legacy export endpoint remains open during migration",
        stride_category="Information Disclosure",
        severity="High",
        source="Manual",
        status="Accepted",
        false_positive_reason="accepted_risk",
    )


@pytest.mark.asyncio
async def test_rebuild_security_context_index_projects_foundation_sources():
    user = _user()
    review = _review(user)
    prior = _review(user, decision="fix")
    prior.id = uuid.uuid4()
    prior.review_lineage_id = review.review_lineage_id
    bundle = _bundle(user, review.id)
    scan_finding = _scan_finding(bundle.id)
    stale_entry = _context_entry(user, review.id, item_type="note", status="active")
    evidence_item, entities, relationship, evidence_finding = _evidence_objects(review)
    threat = _accepted_threat(review)
    db = _FakeSession(
        [
            review,
            [stale_entry],
            [],
            [bundle],
            [scan_finding],
            [evidence_item],
            entities,
            [relationship],
            [evidence_finding],
            [threat],
            [prior],
        ]
    )

    entries = await rebuild_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert stale_entry.status == "stale"
    assert stale_entry.stale_reason == "superseded_by_rebuild"
    item_types = {entry.item_type for entry in entries}
    assert {
        "app_profile",
        "org_profile",
        "review_scope",
        "policy",
        "control",
        "doc",
        "code_summary",
        "bundle_file",
        "scanner_finding",
        "evidence_item",
        "evidence_entity",
        "evidence_relationship",
        "accepted_risk",
        "prior_review_decision",
    } <= item_types
    assert all(entry.source_refs for entry in entries)
    assert all(entry.facets for entry in entries)
    assert all(entry.retrieval_text for entry in entries)
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_search_security_context_index_filters_status_and_falls_back_from_vector():
    user = _user()
    review = _review(user)
    active = _context_entry(
        user,
        review.id,
        item_type="scanner_finding",
        source_type="scan_finding",
        title="Sensitive export route is missing authorization",
        body="sensitive export missing authorization pii",
    )
    stale = _context_entry(
        user,
        review.id,
        item_type="doc",
        source_type="document",
        title="Stale design doc",
        body="old export authorization design",
        status="stale",
    )
    deleted = _context_entry(
        user,
        review.id,
        item_type="doc",
        source_type="document",
        title="Deleted design doc",
        body="deleted export authorization design",
        status="deleted",
    )
    db = _FakeSession([review, [active, stale, deleted]])

    results = await search_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        query="missing authorization export",
        mode="vector",
    )

    assert results == [active]

    db = _FakeSession([review, [active, stale, deleted]])
    structured = await search_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        query="",
        mode="structured",
        item_types={"doc"},
        include_stale=True,
    )

    assert structured == [stale]


@pytest.mark.asyncio
async def test_graph_neighborhood_retrieval_uses_entity_facets_and_source_refs():
    user = _user()
    review = _review(user)
    entity_id = uuid.uuid4()
    entity = _context_entry(
        user,
        review.id,
        item_type="evidence_entity",
        source_type="evidence_entity",
        title="Export route",
        facets={"entity_id": str(entity_id), "entity_type": "api_route"},
    )
    relationship = _context_entry(
        user,
        review.id,
        item_type="evidence_relationship",
        source_type="evidence_relationship",
        title="Route reads users",
        facets={"from_entity_id": str(entity_id), "to_entity_id": str(uuid.uuid4())},
    )
    unrelated = _context_entry(
        user,
        review.id,
        item_type="evidence_entity",
        source_type="evidence_entity",
        title="Billing route",
        facets={"entity_id": str(uuid.uuid4()), "entity_type": "api_route"},
    )
    db = _FakeSession([review, [unrelated, relationship, entity]])

    results = await search_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        query="route",
        mode="graph_neighborhood",
        graph_entity_id=entity_id,
    )

    assert results == [entity, relationship]
