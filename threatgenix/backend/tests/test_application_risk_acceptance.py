from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_risk_acceptance import ApplicationRiskAcceptance
from app.schemas.application_risk_acceptance import ApplicationRiskAcceptanceCreate
from app.services.application_review import tenant_key_for_user
from app.services.application_risk_acceptance import (
    RiskAcceptanceError,
    create_application_risk_acceptance,
    expire_application_risk_acceptances,
    require_risk_acceptance_approver,
    revoke_application_risk_acceptance,
    risk_acceptance_matches_entry,
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


def _user(*, role: str = "accept_risk_approver"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="approver@example.com",
        organization_id=None,
        role=role,
    )


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
        status="indexing",
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


def _acceptance(
    user,
    review: ApplicationSecurityReview,
    *,
    scope_type: str = "route",
    scope_value: str = "apps/api/users.py:42",
    status: str = "active",
    expires_at: datetime | None = None,
) -> ApplicationRiskAcceptance:
    now = datetime.now(timezone.utc)
    return ApplicationRiskAcceptance(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        app_name=review.app_name,
        review_id=review.id,
        finding_stable_id=None,
        scope_type=scope_type,
        scope_value=scope_value,
        justification="Known legacy route covered by compensating monitoring.",
        compensating_control="Alert on export volume anomalies.",
        approver_id=user.id,
        approved_at=now,
        expires_at=expires_at or now + timedelta(days=30),
        status=status,
        audit_events=[],
        created_at=now,
        updated_at=now,
    )


def test_only_accept_risk_approver_can_grant_acceptance():
    with pytest.raises(RiskAcceptanceError, match="accept_risk_approver"):
        require_risk_acceptance_approver(_user(role="admin"))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_create_acceptance_is_tenant_scoped_requires_future_expiry_and_audits():
    user = _user()
    review = _review(user)
    db = _FakeSession([review])
    request = ApplicationRiskAcceptanceCreate(
        scope_type="rule",
        scope_value="python.fastapi.missing-authz",
        justification="Legacy route has customer approval and monitoring during migration.",
        compensating_control="Daily export anomaly monitoring.",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )

    acceptance = await create_application_risk_acceptance(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        request=request,
    )

    assert acceptance.tenant_key == tenant_key_for_user(user)
    assert acceptance.review_id == review.id
    assert acceptance.app_name == "ExampleApp"
    assert acceptance.status == "active"
    assert acceptance.audit_events[0]["action"] == "granted"
    assert db.added == [acceptance]
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_create_acceptance_rejects_expired_window():
    user = _user()
    review = _review(user)
    db = _FakeSession([review])
    request = ApplicationRiskAcceptanceCreate(
        scope_type="app",
        scope_value="ExampleApp",
        justification="This should fail because the expiry is already elapsed.",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )

    with pytest.raises(RiskAcceptanceError, match="future"):
        await create_application_risk_acceptance(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            review_id=review.id,
            request=request,
        )


@pytest.mark.asyncio
async def test_revoke_acceptance_enforces_review_scope_and_audits():
    user = _user()
    review = _review(user)
    acceptance = _acceptance(user, review)
    db = _FakeSession([acceptance])

    revoked = await revoke_application_risk_acceptance(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        acceptance_id=acceptance.id,
        review_id=review.id,
        reason="Migration finished and the exception is no longer needed.",
    )

    assert revoked.status == "revoked"
    assert revoked.revoked_by_id == user.id
    assert revoked.audit_events[-1]["action"] == "revoked"
    assert db.flush_count == 1


@pytest.mark.asyncio
async def test_revoke_acceptance_rejects_wrong_review_route():
    user = _user()
    review = _review(user)
    acceptance = _acceptance(user, review)
    db = _FakeSession([acceptance])

    with pytest.raises(RiskAcceptanceError, match="review"):
        await revoke_application_risk_acceptance(
            db,  # type: ignore[arg-type]
            current_user=user,  # type: ignore[arg-type]
            acceptance_id=acceptance.id,
            review_id=uuid.uuid4(),
            reason="Wrong review route should not revoke this risk.",
        )


@pytest.mark.asyncio
async def test_expire_acceptances_reopens_elapsed_active_risks():
    user = _user()
    review = _review(user)
    elapsed = _acceptance(
        user,
        review,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    db = _FakeSession([[elapsed]])

    expired = await expire_application_risk_acceptances(
        db,  # type: ignore[arg-type]
        tenant_key=tenant_key_for_user(user),
    )

    assert expired == [elapsed]
    assert elapsed.status == "expired"
    assert elapsed.audit_events[-1]["action"] == "expired"
    assert db.flush_count == 1


def test_risk_acceptance_matches_only_explicit_scope():
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    finding = {
        "severity": "high",
        "template_id": "python.fastapi.missing-authz",
        "finding_key": "export-authz",
    }
    refs = [{"type": "path", "path": "apps/api/users.py:42"}]

    assert risk_acceptance_matches_entry(
        {
            "acceptance_state": "active",
            "scope_type": "rule",
            "scope_value": "python.fastapi.missing-authz",
            "expires_at": future,
        },
        app_name="ExampleApp",
        entry_facets=finding,
        entry_source_refs=refs,
        entry_content_hash="a" * 64,
    )
    assert risk_acceptance_matches_entry(
        {
            "status": "active",
            "scope_type": "route",
            "scope_value": "apps/api/users.py:42",
            "expires_at": future,
        },
        app_name="ExampleApp",
        entry_facets=finding,
        entry_source_refs=refs,
        entry_content_hash="a" * 64,
    )
    assert not risk_acceptance_matches_entry(
        {
            "status": "active",
            "scope_type": "route",
            "scope_value": "apps/api/admin.py:1",
            "expires_at": future,
        },
        app_name="ExampleApp",
        entry_facets=finding,
        entry_source_refs=refs,
        entry_content_hash="a" * 64,
    )
    assert not risk_acceptance_matches_entry(
        {
            "status": "expired",
            "scope_type": "rule",
            "scope_value": "python.fastapi.missing-authz",
            "expires_at": future,
        },
        app_name="ExampleApp",
        entry_facets=finding,
        entry_source_refs=refs,
        entry_content_hash="a" * 64,
    )


@pytest.mark.asyncio
async def test_expiry_cli_commits_elapsed_risk_acceptances(monkeypatch, capsys):
    from app.cli import expire_risk_acceptances as cli

    class _Session:
        commit_count = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            del exc_type, exc, tb

        async def commit(self):
            self.commit_count += 1

    session = _Session()

    class _SessionFactory:
        def __call__(self):
            return session

    async def fake_expire(db):
        assert db is session
        return [object(), object()]

    monkeypatch.setattr(cli, "async_session", _SessionFactory())
    monkeypatch.setattr(cli, "expire_application_risk_acceptances", fake_expire)

    expired_count = await cli.main()

    assert expired_count == 2
    assert session.commit_count == 1
    assert "expired 2 risk acceptance(s)" in capsys.readouterr().out
