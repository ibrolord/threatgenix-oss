from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import httpx
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.database import get_db
from app.main import app
from app.models.application_review import ApplicationSecurityReview
from app.models.github_integration import GitHubRepositoryLink, GitHubReviewDispatch
from app.schemas.application_review import ApplicationReviewResponse
from app.schemas.application_review_orchestration import ApplicationReviewOrchestrationRequest
from app.services.github_pr_integration import (
    GitHubWebhookError,
    build_pr_orchestration_request,
    choose_pr_comment_upsert,
    dispatch_github_pr_review_update,
    enqueue_github_pr_review_dispatch,
    github_status_state,
    process_github_review_dispatch,
    render_github_pr_comment,
    sign_github_webhook_body,
    verify_github_webhook_signature,
)


def _github_pr_payload() -> dict:
    return {
        "action": "opened",
        "installation": {"id": 12345},
        "repository": {"id": 999, "full_name": "acme/example-app", "private": True},
        "pull_request": {
            "number": 42,
            "title": "Add export endpoint",
            "body": "Adds CSV export",
            "html_url": "https://github.com/acme/example-app/pull/42",
            "diff_url": "https://github.com/acme/example-app/pull/42.diff",
            "head": {"sha": "abc123", "ref": "feature/export"},
            "base": {"sha": "def456", "ref": "main"},
        },
    }


def _review_response(review_id: uuid.UUID, owner_id: uuid.UUID) -> ApplicationReviewResponse:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    return ApplicationReviewResponse(
        id=review_id,
        tenant_key=f"user:{owner_id}",
        owner_id=owner_id,
        organization_id=None,
        threat_model_id=None,
        parent_review_id=None,
        review_lineage_id=review_id,
        app_name="acme/example-app",
        invocation_surface="pr",
        input_kind="diff",
        status="completed",
        decision="pass",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="github-pr:999:42:abc123",
        requested_tools=["semgrep"],
        scope={"github": {"repository_id": "999", "pull_request_number": 42}},
        context={},
        policy={},
        result_summary="Looks good.",
        error_message=None,
        created_at=now,
        updated_at=now,
    )


def _review_model(owner_id: uuid.UUID, *, tenant_key: str | None = None) -> ApplicationSecurityReview:
    review_id = uuid.uuid4()
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    return ApplicationSecurityReview(
        id=review_id,
        tenant_key=tenant_key or f"user:{owner_id}",
        owner_id=owner_id,
        organization_id=None,
        threat_model_id=None,
        parent_review_id=None,
        review_lineage_id=review_id,
        app_name="acme/example-app",
        invocation_surface="pr",
        input_kind="diff",
        status="completed",
        decision="pass",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="github-pr:999:42:abc123",
        requested_tools=["semgrep"],
        scope={
            "github": {
                "installation_id": "12345",
                "repository_id": "999",
                "repository_full_name": "untrusted/repo-name",
                "pull_request_number": 42,
                "head_sha": "abc123",
            }
        },
        context={},
        policy={},
        result_summary="Looks good.",
        error_message=None,
        created_at=now,
        updated_at=now,
    )


class _Result:
    def __init__(self, item: object | list[object] | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item if not isinstance(self.item, list) else None

    def scalars(self):
        return self

    def first(self):
        return self.item[0] if isinstance(self.item, list) and self.item else self.item


class _FakeSession:
    def __init__(self, execute_results: list[object | list[object] | None] | None = None) -> None:
        self.execute_results = list(execute_results or [])
        self.added: list[object] = []
        self.flushed = 0
        self.get_results: dict[tuple[type, object], object] = {}

    async def execute(self, statement: object):
        del statement
        return _Result(self.execute_results.pop(0) if self.execute_results else None)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flushed += 1

    async def get(self, model: type, item_id: object):
        return self.get_results.get((model, item_id))


def _active_link(review: ApplicationSecurityReview, *, tenant_key: str | None = None) -> SimpleNamespace:
    github_scope = review.scope["github"]
    return SimpleNamespace(
        tenant_key=tenant_key or review.tenant_key,
        installation_id=github_scope["installation_id"],
        repository_id=github_scope["repository_id"],
        repository_full_name="acme/example-app",
        status="active",
    )


def test_github_webhook_signature_requires_hmac(monkeypatch):
    monkeypatch.setattr(settings, "github_webhook_secret", "webhook-secret")
    raw_body = json.dumps(_github_pr_payload(), separators=(",", ":")).encode()
    signature = sign_github_webhook_body(raw_body=raw_body, secret="webhook-secret")

    verify_github_webhook_signature(
        headers={"X-Hub-Signature-256": signature},
        raw_body=raw_body,
    )
    with pytest.raises(GitHubWebhookError):
        verify_github_webhook_signature(
            headers={"X-Hub-Signature-256": "sha256=bad"},
            raw_body=raw_body,
        )


@pytest.mark.asyncio
async def test_build_pr_orchestration_request_uses_idempotent_pr_key():
    link = SimpleNamespace(
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        threat_model_id=None,
        requested_tools=["semgrep"],
        tenant_key="user:owner",
    )
    with patch(
        "app.services.github_pr_integration.latest_github_pr_review",
        new_callable=AsyncMock,
        return_value=None,
    ):
        request = await build_pr_orchestration_request(
            AsyncMock(),
            link=link,
            payload=_github_pr_payload(),
        )

    assert request.review.invocation_surface == "pr"
    assert request.review.idempotency_key == "github-pr:999:42:abc123"
    assert request.review.scope["github"]["pull_request_url"].endswith("/pull/42")
    assert request.review.intake_answers["github_permission"] is True


def test_github_pr_comment_rendering_is_idempotent_by_stable_pr_marker():
    review_id = uuid.uuid4()
    body = render_github_pr_comment(
        review_id=review_id,
        decision="fix",
        status="completed",
        web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
        repository_id="999",
        pull_request_number=42,
    )

    assert "<!-- threatgenix-pr-review:999:42 -->" in body
    assert f"<!-- threatgenix-review:{review_id} -->" in body
    assert "ThreatGenix Security Review" in body
    assert "Required check" in body
    assert choose_pr_comment_upsert(existing_comments=[], review_id=review_id, body=body)["action"] == "create"
    assert (
        choose_pr_comment_upsert(
            existing_comments=[{"id": 10, "body": body}],
            review_id=review_id,
            body=body,
            repository_id="999",
            pull_request_number=42,
        )["action"]
        == "edit"
    )


@pytest.mark.asyncio
async def test_completed_pr_review_enqueues_one_dispatch_outbox_row():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    link = GitHubRepositoryLink(
        tenant_key=review.tenant_key,
        owner_id=owner_id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        private=True,
        requested_tools=["semgrep"],
        status="active",
    )
    db = _FakeSession([link, None, link, None])

    dispatch = await enqueue_github_pr_review_dispatch(db=db, review=review)  # type: ignore[arg-type]
    db.execute_results[1] = dispatch
    duplicate = await enqueue_github_pr_review_dispatch(db=db, review=review)  # type: ignore[arg-type]

    assert isinstance(dispatch, GitHubReviewDispatch)
    assert dispatch.repository_full_name == "acme/example-app"
    assert dispatch.pull_request_number == 42
    assert dispatch.head_sha == "abc123"
    assert dispatch.review_status == "completed"
    assert dispatch.review_decision == "pass"
    assert dispatch.status == "queued"
    assert duplicate is dispatch
    assert db.added == [dispatch]


@pytest.mark.asyncio
async def test_completed_pr_review_requeues_existing_dispatch_when_decision_changes():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    link = GitHubRepositoryLink(
        tenant_key=review.tenant_key,
        owner_id=owner_id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        private=True,
        requested_tools=["semgrep"],
        status="active",
    )
    existing = GitHubReviewDispatch(
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="fix",
        status="dispatched",
        attempt_count=1,
        last_error="old error",
    )
    db = _FakeSession([link, existing])

    dispatch = await enqueue_github_pr_review_dispatch(db=db, review=review)  # type: ignore[arg-type]

    assert dispatch is existing
    assert existing.status == "queued"
    assert existing.review_decision == "pass"
    assert existing.last_error is None
    assert db.added == []


@pytest.mark.asyncio
async def test_pr_review_enqueue_requires_matching_tenant_and_head_sha():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    mismatched_link = GitHubRepositoryLink(
        tenant_key="user:other",
        owner_id=uuid.uuid4(),
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        private=True,
        requested_tools=["semgrep"],
        status="active",
    )

    assert await enqueue_github_pr_review_dispatch(  # type: ignore[arg-type]
        db=_FakeSession([mismatched_link]),
        review=review,
    ) is None

    review.commit_sha = "different"
    assert await enqueue_github_pr_review_dispatch(  # type: ignore[arg-type]
        db=_FakeSession([mismatched_link]),
        review=review,
    ) is None


@pytest.mark.asyncio
async def test_github_dispatch_processor_records_retryable_failure():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, _active_link(review)])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(500, json={"message": "github is unavailable"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        outcome = await process_github_review_dispatch(
            db=db,  # type: ignore[arg-type]
            dispatch_id=dispatch.id,
            access_token="ghs_installation_token",
            web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
            http_client=client,
        )

    assert outcome.status == "failed"
    assert dispatch.status == "retryable_failed"
    assert "HTTP 500" in (dispatch.last_error or "")
    assert dispatch.attempt_count == 1


@pytest.mark.asyncio
async def test_github_dispatch_processor_skips_unclaimable_dispatch():
    dispatch_id = uuid.uuid4()
    db = _FakeSession(execute_results=[None])

    outcome = await process_github_review_dispatch(
        db=db,  # type: ignore[arg-type]
        dispatch_id=dispatch_id,
        access_token="ghs_installation_token",
        web_url="https://threatgenix.vercel.app/reviews/1",
    )

    assert outcome.status == "skipped"
    assert outcome.reason == "dispatch not claimable"
    assert db.flushed == 0


@pytest.mark.asyncio
async def test_github_dispatch_processor_records_missing_token_failure():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, _active_link(review)])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review

    outcome = await process_github_review_dispatch(
        db=db,  # type: ignore[arg-type]
        dispatch_id=dispatch.id,
        access_token=None,
        web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
    )

    assert outcome.status == "failed"
    assert dispatch.status == "terminal_failed"
    assert dispatch.last_error == "missing GitHub App credentials for installation token minting"
    assert dispatch.attempt_count == 1


@pytest.mark.asyncio
async def test_github_dispatch_processor_mints_installation_token_at_dispatch_time():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, _active_link(review)])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review
    calls: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.headers.get("Authorization", "")))
        if request.method == "POST" and request.url.path.endswith("/app/installations/12345/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "ghs_installation_token",
                    "expires_at": "2099-05-02T23:59:59Z",
                    "permissions": {"statuses": "write", "issues": "write"},
                },
            )
        if request.method == "GET" and request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(200, json=[])
        if request.method == "POST" and request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(201, json={"id": 99})
        if request.method == "POST" and request.url.path.endswith("/statuses/abc123"):
            return httpx.Response(201, json={"id": 101})
        return httpx.Response(404, json={"message": "not found"})

    with patch("app.services.github_pr_integration.create_github_app_jwt", return_value="app.jwt"):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            outcome = await process_github_review_dispatch(
                db=db,  # type: ignore[arg-type]
                dispatch_id=dispatch.id,
                access_token=None,
                web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
                http_client=client,
            )

    assert outcome.status == "dispatched"
    assert dispatch.status == "dispatched"
    assert dispatch.comment_id == 99
    assert calls[0] == ("POST", "/app/installations/12345/access_tokens", "Bearer app.jwt")
    assert all(call[2] == "Bearer ghs_installation_token" for call in calls[1:])


@pytest.mark.asyncio
async def test_github_dispatch_processor_blocks_installation_token_missing_permissions():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, _active_link(review)])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            201,
            json={
                "token": "ghs_installation_token",
                "expires_at": "2099-05-02T23:59:59Z",
                "permissions": {"statuses": "read", "issues": "write"},
            },
        )

    with patch("app.services.github_pr_integration.create_github_app_jwt", return_value="app.jwt"):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            outcome = await process_github_review_dispatch(
                db=db,  # type: ignore[arg-type]
                dispatch_id=dispatch.id,
                access_token=None,
                web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
                http_client=client,
            )

    assert outcome.status == "failed"
    assert dispatch.status == "terminal_failed"
    assert "missing required GitHub App permissions" in (dispatch.last_error or "")


@pytest.mark.asyncio
async def test_github_dispatch_processor_blocks_expired_installation_token():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, _active_link(review)])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            201,
            json={
                "token": "ghs_installation_token",
                "expires_at": "2020-01-01T00:00:00Z",
                "permissions": {"statuses": "write", "issues": "write"},
            },
        )

    with patch("app.services.github_pr_integration.create_github_app_jwt", return_value="app.jwt"):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            outcome = await process_github_review_dispatch(
                db=db,  # type: ignore[arg-type]
                dispatch_id=dispatch.id,
                access_token=None,
                web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
                http_client=client,
            )

    assert outcome.status == "failed"
    assert dispatch.status == "terminal_failed"
    assert dispatch.last_error == "expired GitHub installation access token"


@pytest.mark.asyncio
async def test_github_dispatch_processor_blocks_revoked_installation_token_mint():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, _active_link(review)])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(404, json={"message": "installation not found"})

    with patch("app.services.github_pr_integration.create_github_app_jwt", return_value="app.jwt"):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            outcome = await process_github_review_dispatch(
                db=db,  # type: ignore[arg-type]
                dispatch_id=dispatch.id,
                access_token=None,
                web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
                http_client=client,
            )

    assert outcome.status == "failed"
    assert dispatch.status == "terminal_failed"
    assert "HTTP 404" in (dispatch.last_error or "")


@pytest.mark.asyncio
async def test_github_dispatch_processor_blocks_inactive_repository_link():
    owner_id = uuid.uuid4()
    review = _review_model(owner_id)
    dispatch = GitHubReviewDispatch(
        id=uuid.uuid4(),
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id="12345",
        repository_id="999",
        repository_full_name="acme/example-app",
        pull_request_number=42,
        head_sha="abc123",
        status_context="ThreatGenix Security Review",
        review_status="completed",
        review_decision="pass",
    )
    db = _FakeSession(execute_results=[dispatch.id, None])
    db.get_results[(GitHubReviewDispatch, dispatch.id)] = dispatch
    db.get_results[(ApplicationSecurityReview, review.id)] = review

    outcome = await process_github_review_dispatch(
        db=db,  # type: ignore[arg-type]
        dispatch_id=dispatch.id,
        access_token="ghs_installation_token",
        web_url=f"https://threatgenix.vercel.app/reviews/{review.id}",
    )

    assert outcome.status == "failed"
    assert dispatch.status == "terminal_failed"
    assert dispatch.last_error == "GitHub repository link is not active for dispatch tenant"
    assert dispatch.attempt_count == 1


@pytest.mark.asyncio
async def test_github_outbound_dispatch_edits_comment_and_posts_success_status():
    review_id = uuid.uuid4()
    calls: list[tuple[str, str, dict | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else None
        calls.append((request.method, request.url.path, payload))
        if request.method == "GET" and request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 99,
                        "body": f"old body <!-- threatgenix-review:{review_id} -->",
                    }
                ],
            )
        if request.method == "PATCH" and request.url.path.endswith("/issues/comments/99"):
            return httpx.Response(200, json={"id": 99})
        if request.method == "POST" and request.url.path.endswith("/statuses/abc123"):
            return httpx.Response(201, json={"id": 123})
        return httpx.Response(404, json={"message": "not found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await dispatch_github_pr_review_update(
            access_token="ghs_installation_token",
            repository_full_name="acme/example-app",
            pull_request_number=42,
            head_sha="abc123",
            review_id=review_id,
            decision="pass",
            status="completed",
            web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
            http_client=client,
        )

    assert result.comment_action == "edit"
    assert result.comment_id == 99
    assert result.status_state == "success"
    assert calls[1][0] == "PATCH"
    assert "ThreatGenix Security Review" in calls[1][2]["body"]
    assert calls[2][2]["state"] == "success"
    assert calls[2][2]["context"] == "ThreatGenix Security Review"


@pytest.mark.asyncio
async def test_github_outbound_dispatch_updates_stable_pr_comment_for_new_sha():
    old_review_id = uuid.uuid4()
    new_review_id = uuid.uuid4()
    calls: list[tuple[str, str, dict | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else None
        calls.append((request.method, request.url.path, payload))
        if request.method == "GET" and request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 99,
                        "body": (
                            "<!-- threatgenix-pr-review:999:42 -->\n"
                            f"<!-- threatgenix-review:{old_review_id} -->"
                        ),
                    }
                ],
            )
        if request.method == "PATCH" and request.url.path.endswith("/issues/comments/99"):
            return httpx.Response(200, json={"id": 99})
        if request.method == "POST" and request.url.path.endswith("/statuses/newsha"):
            return httpx.Response(201, json={"id": 125})
        return httpx.Response(404, json={"message": "not found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await dispatch_github_pr_review_update(
            access_token="ghs_installation_token",
            repository_full_name="acme/example-app",
            pull_request_number=42,
            head_sha="newsha",
            review_id=new_review_id,
            decision="verify",
            status="completed",
            web_url=f"https://threatgenix.vercel.app/reviews/{new_review_id}",
            repository_id="999",
            http_client=client,
        )

    assert result.comment_action == "edit"
    assert calls[1][0] == "PATCH"
    assert f"threatgenix-review:{new_review_id}" in calls[1][2]["body"]
    assert calls[2][1].endswith("/statuses/newsha")
    assert calls[2][2]["state"] == "pending"


@pytest.mark.asyncio
async def test_github_outbound_dispatch_creates_comment_and_failure_status_for_fix():
    review_id = uuid.uuid4()
    calls: list[tuple[str, str, dict | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else None
        calls.append((request.method, request.url.path, payload))
        if request.method == "GET" and request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(200, json=[])
        if request.method == "POST" and request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(201, json={"id": 100})
        if request.method == "POST" and request.url.path.endswith("/statuses/abc123"):
            return httpx.Response(201, json={"id": 124})
        return httpx.Response(404, json={"message": "not found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await dispatch_github_pr_review_update(
            access_token="ghs_installation_token",
            repository_full_name="https://github.com/acme/example-app",
            pull_request_number=42,
            head_sha="abc123",
            review_id=review_id,
            decision="fix",
            status="completed",
            web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
            http_client=client,
        )

    assert result.comment_action == "create"
    assert result.comment_id == 100
    assert result.status_state == "failure"
    assert calls[1][0] == "POST"
    assert calls[2][2]["state"] == "failure"
    assert "must be fixed" in calls[2][2]["description"]


def test_github_status_state_blocks_merge_only_for_terminal_fix_or_block():
    assert github_status_state(decision="pass", status="completed") == "success"
    assert github_status_state(decision="fix", status="completed") == "failure"
    assert github_status_state(decision="block", status="completed") == "failure"
    assert github_status_state(decision="verify", status="completed") == "pending"
    assert github_status_state(decision=None, status="scanning") == "pending"
    assert github_status_state(decision="pass", status="failed_terminal") == "error"
    assert github_status_state(decision="pass", status="blocked_by_permission") == "failure"


@pytest.mark.asyncio
async def test_github_webhook_ignores_unlinked_repository(monkeypatch):
    monkeypatch.setattr(settings, "github_webhook_secret", "webhook-secret")
    raw_body = json.dumps(_github_pr_payload(), separators=(",", ":")).encode()
    signature = sign_github_webhook_body(raw_body=raw_body, secret="webhook-secret")

    async def override_get_db():
        yield AsyncMock()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with (
            patch("app.api.github_integration.consume_github_delivery_once", new_callable=AsyncMock),
            patch("app.api.github_integration.get_active_github_repository_link", new_callable=AsyncMock, return_value=None),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/integrations/github/webhook",
                    headers={
                        "X-Hub-Signature-256": signature,
                        "X-GitHub-Event": "pull_request",
                        "X-GitHub-Delivery": "delivery-1",
                    },
                    content=raw_body,
                )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert response.json()["ignored_reason"] == "repository is not linked to a ThreatGenix tenant"


@pytest.mark.asyncio
async def test_github_webhook_orchestrates_linked_pr_review(monkeypatch):
    monkeypatch.setattr(settings, "github_webhook_secret", "webhook-secret")
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    raw_body = json.dumps(_github_pr_payload(), separators=(",", ":")).encode()
    signature = sign_github_webhook_body(raw_body=raw_body, secret="webhook-secret")
    link = SimpleNamespace(
        owner_id=owner_id,
        tenant_key=f"user:{owner_id}",
        installation_id="12345",
        status="active",
    )
    db = AsyncMock()
    db.get.return_value = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    orchestration_request = ApplicationReviewOrchestrationRequest(
        review={
            "app_name": "acme/example-app",
            "invocation_surface": "pr",
            "input_kind": "diff",
            "commit_sha": "abc123",
            "requested_tools": ["semgrep"],
            "intake_answers": {
                "business_purpose": "Review GitHub PR",
                "data_classification": "internal",
                "sensitive_data_types": ["none"],
                "changed_security_surface": ["unknown"],
                "scanner_permissions": ["static_code"],
                "upload_permission": True,
                "github_permission": True,
                "out_of_scope": ["production data access"],
            },
        }
    )
    orchestration = SimpleNamespace(
        review=_review_response(review_id, owner_id),
        web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
    )
    dispatch = SimpleNamespace(
        id=uuid.uuid4(),
        repository_id="999",
        pull_request_number=42,
    )

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with (
            patch("app.api.github_integration.consume_github_delivery_once", new_callable=AsyncMock),
            patch("app.api.github_integration.get_active_github_repository_link", new_callable=AsyncMock, return_value=link),
            patch(
                "app.api.github_integration.build_pr_orchestration_request",
                new_callable=AsyncMock,
                return_value=orchestration_request,
            ),
            patch(
                "app.api.github_integration.orchestrate_application_review",
                new_callable=AsyncMock,
                return_value=orchestration,
            ) as orchestrate,
            patch(
                "app.api.github_integration.latest_github_review_dispatch",
                new_callable=AsyncMock,
                return_value=dispatch,
            ),
            patch("app.api.github_integration.process_github_review_dispatch", new_callable=AsyncMock) as process_dispatch,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/integrations/github/webhook",
                    headers={
                        "X-Hub-Signature-256": signature,
                        "X-GitHub-Event": "pull_request",
                        "X-GitHub-Delivery": "delivery-2",
                    },
                    content=raw_body,
                )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert body["review_id"] == str(review_id)
    assert "ThreatGenix Security Review" in body["comment_body"]
    assert "<!-- threatgenix-pr-review:999:42 -->" in body["comment_body"]
    orchestrate.assert_awaited_once()
    process_dispatch.assert_awaited_once()
    assert process_dispatch.await_args.kwargs["access_token"] is None
