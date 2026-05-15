from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_context import ApplicationReviewContextEntry
from app.schemas.review_context_packet import GroundedAIReviewOutput, GroundedFixPlanStep
from app.services.application_review import tenant_key_for_user
from app.services.review_context_packet import (
    UNTRUSTED_BEGIN,
    UNTRUSTED_END,
    build_grounded_ai_explanation,
    build_review_context_packet,
    validate_grounded_ai_output,
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

    async def execute(self, statement: object):
        del statement
        return _Result(self.execute_results.pop(0) if self.execute_results else None)


def _user():
    return SimpleNamespace(id=uuid.uuid4(), organization_id=None, email="owner@example.com")


def _review(user, *, decision: str | None = "fix") -> ApplicationSecurityReview:
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
        status="running",
        decision=decision,
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy={"block_on_high": True},
        created_at=now,
        updated_at=now,
    )


def _entry(user, review_id: uuid.UUID, *, body: str, content_hash: str = "d" * 64):
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
        title="Sensitive export route is missing authorization",
        body=body,
        keywords=body.casefold().split(),
        source_refs=[{"type": "path", "path": "apps/api/users.py:42"}],
        content_hash=content_hash,
        status="active",
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_context_packet_redacts_secrets_and_delimits_untrusted_text():
    user = _user()
    review = _review(user)
    entry = _entry(
        user,
        review.id,
        body="missing authorization on export route api_key=sk_live_123",
    )
    db = _FakeSession([review, review, [entry]])

    packet = await build_review_context_packet(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        query="missing authorization",
    )

    assert packet.review_id == review.id
    assert packet.commit_sha == "abc123"
    assert packet.deterministic_decision == "fix"
    assert packet.entries[0].untrusted_text.startswith(UNTRUSTED_BEGIN)
    assert packet.entries[0].untrusted_text.endswith(UNTRUSTED_END)
    assert "sk_live_123" not in packet.entries[0].untrusted_text
    assert "api_key=[REDACTED]" in packet.entries[0].untrusted_text
    assert packet.evidence_snapshot_hash


def test_grounded_ai_output_validation_rejects_hallucinated_citations():
    user = _user()
    review = _review(user)
    packet = _packet_for_validation(user, review, content_hash="d" * 64)
    output = GroundedAIReviewOutput(
        summary="Fix the missing authorization.",
        proposed_decision="fix",
        cited_content_hashes=["e" * 64],
        fix_plan=[
            GroundedFixPlanStep(
                title="Add authorization",
                remediation="Check the current user's export permission.",
                cited_content_hashes=["e" * 64],
            )
        ],
    )

    result = validate_grounded_ai_output(output, packet)

    assert result.valid is False
    assert any("not in the context packet" in error for error in result.errors)
    assert any("outside the packet" in error for error in result.errors)


def test_grounded_ai_output_validation_rejects_decision_escalation_and_secret_leak():
    user = _user()
    review = _review(user, decision="fix")
    packet = _packet_for_validation(user, review, content_hash="d" * 64)
    output = GroundedAIReviewOutput(
        summary="Block it because token=abc123 leaked.",
        proposed_decision="block",
        cited_content_hashes=["d" * 64],
    )

    result = validate_grounded_ai_output(output, packet)

    assert result.valid is False
    assert any("cannot change" in error for error in result.errors)
    assert any("secret-shaped" in error for error in result.errors)


def test_grounded_ai_output_validation_accepts_cited_fix_plan():
    user = _user()
    review = _review(user)
    packet = _packet_for_validation(user, review, content_hash="d" * 64)
    output = GroundedAIReviewOutput(
        summary="The export route needs authorization.",
        proposed_decision="fix",
        cited_content_hashes=["d" * 64],
        fix_plan=[
            GroundedFixPlanStep(
                title="Add permission check",
                remediation="Require export permission before returning user data.",
                cited_content_hashes=["d" * 64],
            )
        ],
    )

    assert validate_grounded_ai_output(output, packet).valid is True


@pytest.mark.asyncio
async def test_build_grounded_ai_explanation_preserves_decision_and_cites_packet_evidence():
    user = _user()
    review = _review(user, decision="verify")
    entry = _entry(
        user,
        review.id,
        body="severity=high missing authorization sensitive customer export token=abc123",
    )
    db = _FakeSession([review, review, [entry]])

    response = await build_grounded_ai_explanation(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        query="missing authorization",
    )

    assert response.explanation_status == "ready"
    assert response.validation.valid is True
    assert response.output is not None
    assert response.output.proposed_decision == "verify"
    assert response.output.cited_content_hashes == ["d" * 64]
    assert response.output.fix_plan[0].cited_content_hashes == ["d" * 64]
    assert "abc123" not in response.packet.entries[0].untrusted_text
    assert "abc123" not in response.output.summary
    assert response.prompt_contract


@pytest.mark.asyncio
async def test_build_grounded_ai_explanation_requires_packet_evidence():
    user = _user()
    review = _review(user, decision="gather_evidence")
    db = _FakeSession([review, review, []])

    response = await build_grounded_ai_explanation(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    assert response.explanation_status == "missing_evidence"
    assert response.output is None
    assert response.validation.valid is False
    assert "requires at least one" in response.validation.errors[0]


def _packet_for_validation(user, review: ApplicationSecurityReview, *, content_hash: str):
    entry = _entry(user, review.id, body="missing authorization", content_hash=content_hash)
    from app.schemas.review_context_packet import ReviewContextPacket, ReviewContextPacketEntry

    return ReviewContextPacket(
        review_id=review.id,
        app_name=review.app_name,
        commit_sha=review.commit_sha,
        deterministic_decision=review.decision,
        policy=review.policy,
        evidence_snapshot_hash="f" * 64,
        entries=[
            ReviewContextPacketEntry(
                entry_id=entry.id,
                item_type=entry.item_type,
                title=entry.title,
                untrusted_text=entry.body,
                source_refs=entry.source_refs,
                content_hash=entry.content_hash,
            )
        ],
    )
