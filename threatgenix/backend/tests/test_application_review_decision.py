from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_context import ApplicationReviewContextEntry
from app.services.application_review import tenant_key_for_user
from app.services.application_review_decision import (
    DETERMINISTIC_DECISION_ENGINE_VERSION,
    build_decision_evidence_snapshot,
    evaluate_application_review_decision,
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
        self.flush_count = 0

    async def execute(self, statement: object):
        del statement
        return _Result(self.execute_results.pop(0) if self.execute_results else None)

    async def flush(self) -> None:
        self.flush_count += 1


def _user():
    return SimpleNamespace(id=uuid.uuid4(), organization_id=None, email="owner@example.com")


def _review(user, *, policy=None) -> ApplicationSecurityReview:
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
        status="indexing",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy=policy or {},
        created_at=now,
        updated_at=now,
    )


def _entry(
    user,
    review_id: uuid.UUID,
    *,
    item_type: str,
    body: str,
    title: str = "Sensitive export route is missing authorization",
    content_hash: str = "d" * 64,
    facets: dict | None = None,
) -> ApplicationReviewContextEntry:
    now = datetime.now(timezone.utc)
    return ApplicationReviewContextEntry(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        review_id=review_id,
        owner_id=user.id,
        organization_id=None,
        source_type=(
            "scan_finding"
            if item_type == "scanner_finding"
            else "code_context"
            if item_type == "code_context"
            else "bundle"
        ),
        source_object_id=uuid.uuid4(),
        item_type=item_type,
        title=title,
        body=body,
        keywords=body.casefold().split(),
        source_refs=[{"type": "path", "path": "apps/api/users.py:42"}],
        content_hash=content_hash,
        facets=facets or {"category": item_type},
        status="active",
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_decision_requires_gather_evidence_when_index_is_empty():
    user = _user()
    review = _review(user)
    db = _FakeSession([review, review, []])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "gather_evidence"
    assert review.decision == "gather_evidence"
    assert review.status == "completed"
    assert decision.evidence_snapshot_hash
    assert decision.decision_engine_version == DETERMINISTIC_DECISION_ENGINE_VERSION
    assert decision.decision_trace == ["no_active_context_entries"]
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_decision_does_not_block_on_scanner_only_high_finding_by_default():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high missing authorization sensitive customer export",
    )
    db = _FakeSession([review, review, [scanner]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "verify"
    assert decision.scanner_only is True
    assert decision.replayed is False
    assert "scanner_only_high_requires_verification" in decision.decision_trace
    assert review.decision == "verify"


@pytest.mark.asyncio
async def test_decision_blocks_when_high_finding_has_supporting_context():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high missing authorization sensitive customer export",
    )
    bundle = _entry(
        user,
        review.id,
        item_type="bundle_file",
        body="Bundle file apps/api/users.py kind=source",
        title="apps/api/users.py",
    )
    db = _FakeSession([review, review, [scanner, bundle]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "block"
    assert decision.scanner_only is False
    assert review.result_summary.startswith("High-severity")


@pytest.mark.asyncio
async def test_decision_monitors_high_finding_when_active_acceptance_scope_matches():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high missing authorization sensitive customer export",
        facets={
            "category": "scanner_finding",
            "severity": "high",
            "template_id": "python.fastapi.missing-authz",
        },
    )
    bundle = _entry(
        user,
        review.id,
        item_type="bundle_file",
        body="Bundle file apps/api/users.py kind=source",
        title="apps/api/users.py",
    )
    accepted_risk = _entry(
        user,
        review.id,
        item_type="accepted_risk",
        title="Risk acceptance python.fastapi.missing-authz",
        body="Accepted risk is active with export anomaly monitoring.",
        facets={
            "category": "accepted_risk",
            "acceptance_state": "active",
            "scope_type": "rule",
            "scope_value": "python.fastapi.missing-authz",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "compensating_control_present": True,
        },
    )
    db = _FakeSession([review, review, [scanner, bundle, accepted_risk]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "verify"
    assert decision.scanner_only is False
    assert "active_risk_acceptance_scope_matches_all_high_findings" in decision.decision_trace


@pytest.mark.asyncio
async def test_decision_reopens_when_acceptance_scope_does_not_match_high_finding():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high missing authorization sensitive customer export",
        facets={
            "category": "scanner_finding",
            "severity": "high",
            "template_id": "python.fastapi.missing-authz",
        },
    )
    bundle = _entry(
        user,
        review.id,
        item_type="bundle_file",
        body="Bundle file apps/api/users.py kind=source",
        title="apps/api/users.py",
    )
    accepted_risk = _entry(
        user,
        review.id,
        item_type="accepted_risk",
        title="Risk acceptance unrelated route",
        body="Accepted risk is active for a different admin route.",
        facets={
            "category": "accepted_risk",
            "acceptance_state": "active",
            "scope_type": "route",
            "scope_value": "apps/api/admin.py:1",
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
    )
    db = _FakeSession([review, review, [scanner, bundle, accepted_risk]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "block"
    assert "high_scanner_supported_by_context" in decision.decision_trace


@pytest.mark.asyncio
async def test_decision_reopens_when_acceptance_is_expired():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high missing authorization sensitive customer export",
        facets={
            "category": "scanner_finding",
            "severity": "high",
            "template_id": "python.fastapi.missing-authz",
        },
    )
    bundle = _entry(
        user,
        review.id,
        item_type="bundle_file",
        body="Bundle file apps/api/users.py kind=source",
        title="apps/api/users.py",
    )
    accepted_risk = _entry(
        user,
        review.id,
        item_type="accepted_risk",
        title="Expired risk acceptance",
        body="Accepted risk expired yesterday.",
        facets={
            "category": "accepted_risk",
            "acceptance_state": "expired",
            "scope_type": "rule",
            "scope_value": "python.fastapi.missing-authz",
            "expires_at": "2026-01-01T00:00:00+00:00",
        },
    )
    db = _FakeSession([review, review, [scanner, bundle, accepted_risk]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "block"
    assert "active_risk_acceptance_scope_matches_all_high_findings" not in decision.decision_trace


@pytest.mark.asyncio
async def test_decision_blocks_when_code_context_confirms_sensitive_authz_gap():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high possible missing authz",
        content_hash="a" * 64,
    )
    code_context = _entry(
        user,
        review.id,
        item_type="code_context",
        title="GET /v2/users/export",
        body=(
            "code_context route_path=/v2/users/export sensitive_signals=['email', 'customer'] "
            "uncertainty=['sensitive_route_auth_present_but_authz_not_identified'] "
            "missing authorization"
        ),
        content_hash="b" * 64,
        facets={"category": "code_context", "has_sensitive_signals": True, "has_authz": False},
    )
    db = _FakeSession([review, review, [code_context, scanner]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "block"
    assert decision.scanner_only is False
    assert "material_sensitive_authz_signal:True" in decision.decision_trace


@pytest.mark.asyncio
async def test_decision_can_block_scanner_only_when_policy_allows_it():
    user = _user()
    review = _review(user, policy={"block_on_high_scanner_only": True})
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=critical remote command execution",
    )
    db = _FakeSession([review, review, [scanner]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "block"
    assert decision.scanner_only is True


def test_decision_evidence_snapshot_is_order_independent_and_source_referenced():
    user = _user()
    review_id = uuid.uuid4()
    scanner = _entry(
        user,
        review_id,
        item_type="scanner_finding",
        body="severity=high missing authorization",
        content_hash="a" * 64,
    )
    code_context = _entry(
        user,
        review_id,
        item_type="code_context",
        body="GET /v2/users/export customer pii",
        content_hash="b" * 64,
    )

    first = build_decision_evidence_snapshot([scanner, code_context])
    second = build_decision_evidence_snapshot([code_context, scanner])

    assert first["hash"] == second["hash"]
    assert first["entries"][0]["content_hash"] == "b" * 64
    assert first["entries"][0]["source_refs"] == [{"type": "path", "path": "apps/api/users.py:42"}]


@pytest.mark.asyncio
async def test_decision_replay_returns_existing_decision_for_same_engine_and_snapshot():
    user = _user()
    review = _review(user)
    scanner = _entry(
        user,
        review.id,
        item_type="scanner_finding",
        body="severity=high missing authorization sensitive customer export",
        content_hash="a" * 64,
    )
    snapshot = build_decision_evidence_snapshot([scanner])
    review.context = {
        "deterministic_decision_replay": {
            "decision": "verify",
            "reason": "Previous deterministic decision.",
            "evidence_hashes": ["a" * 64],
            "scanner_only": True,
            "evidence_snapshot_hash": snapshot["hash"],
            "decision_engine_version": DETERMINISTIC_DECISION_ENGINE_VERSION,
            "decision_trace": ["previous_trace"],
            "evidence_snapshot": snapshot,
        }
    }
    review.decision = "verify"
    review.status = "completed"
    db = _FakeSession([review, review, [scanner]])

    decision = await evaluate_application_review_decision(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert decision.decision == "verify"
    assert decision.replayed is True
    assert decision.evidence_snapshot_hash == snapshot["hash"]
    assert "replayed_existing_decision" in decision.decision_trace
    assert db.flush_count == 0
