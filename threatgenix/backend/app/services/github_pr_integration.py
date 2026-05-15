"""GitHub PR webhook verification, review mapping, and comment rendering."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from jose import jwt as jose_jwt
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.application_review import ApplicationSecurityReview
from app.models.github_integration import GitHubRepositoryLink, GitHubReviewDispatch
from app.models.remediation_webhook import RemediationWebhookNonce
from app.models.user import User
from app.schemas.application_review import ApplicationReviewCreate, ReviewTool
from app.schemas.application_review_orchestration import ApplicationReviewOrchestrationRequest
from app.schemas.github_integration import GitHubRepositoryLinkCreate
from app.services.application_review import list_application_reviews, tenant_key_for_user

GITHUB_SIGNATURE_HEADER = "x-hub-signature-256"
GITHUB_EVENT_HEADER = "x-github-event"
GITHUB_DELIVERY_HEADER = "x-github-delivery"
GITHUB_SIGNATURE_PREFIX = "sha256="
GITHUB_REPLAY_TTL_SECONDS = 600
GITHUB_REQUIRED_CHECK_NAME = "ThreatGenix Security Review"
GITHUB_INSTALLATION_TOKEN_EXPIRY_SKEW_SECONDS = 60
PR_REVIEW_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}
TERMINAL_REVIEW_STATUSES = {
    "completed",
    "blocked_by_policy",
    "blocked_by_permission",
    "failed_terminal",
    "cancelled",
}


class GitHubWebhookError(ValueError):
    """Raised when a GitHub webhook cannot be trusted or mapped."""


class GitHubOutboundDispatchError(RuntimeError):
    """Raised when ThreatGenix cannot publish a PR review update to GitHub."""


@dataclass(frozen=True)
class GitHubOutboundDispatchResult:
    comment_action: Literal["create", "edit"]
    comment_id: int | None
    status_state: Literal["success", "failure", "pending", "error"]
    status_context: str
    target_url: str | None


@dataclass(frozen=True)
class GitHubReviewDispatchOutcome:
    status: Literal["dispatched", "failed", "skipped"]
    reason: str | None = None
    result: GitHubOutboundDispatchResult | None = None
    dispatch: GitHubReviewDispatch | None = None


def sign_github_webhook_body(*, raw_body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"{GITHUB_SIGNATURE_PREFIX}{digest}"


def verify_github_webhook_signature(*, headers: Mapping[str, str], raw_body: bytes) -> None:
    secret = settings.github_webhook_secret
    if not secret:
        raise GitHubWebhookError("GitHub webhook secret is not configured.")
    normalized = {key.casefold(): value.strip() for key, value in headers.items()}
    observed = normalized.get(GITHUB_SIGNATURE_HEADER)
    if not observed:
        raise GitHubWebhookError("Missing GitHub webhook signature.")
    expected = sign_github_webhook_body(raw_body=raw_body, secret=secret)
    if not hmac.compare_digest(observed, expected):
        raise GitHubWebhookError("Invalid GitHub webhook signature.")


async def consume_github_delivery_once(
    *,
    db: AsyncSession,
    delivery_id: str,
    installation_id: str,
    now: datetime | None = None,
) -> None:
    observed = now or datetime.now(tz=UTC)
    await db.execute(
        delete(RemediationWebhookNonce).where(
            RemediationWebhookNonce.expires_at <= observed,
            RemediationWebhookNonce.scope.like("github:%"),
        )
    )
    db.add(
        RemediationWebhookNonce(
            scope=f"github:{installation_id}",
            nonce_hash=hashlib.sha256(delivery_id.encode("utf-8")).hexdigest(),
            provider="github",
            expires_at=observed + timedelta(seconds=GITHUB_REPLAY_TTL_SECONDS),
        )
    )
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise GitHubWebhookError("GitHub webhook delivery has already been processed.") from exc


async def create_or_update_github_repository_link(
    db: AsyncSession,
    *,
    current_user: User,
    request: GitHubRepositoryLinkCreate,
) -> GitHubRepositoryLink:
    tenant_key = tenant_key_for_user(current_user)
    result = await db.execute(
        select(GitHubRepositoryLink).where(
            GitHubRepositoryLink.installation_id == request.installation_id,
            GitHubRepositoryLink.repository_id == request.repository_id,
        )
    )
    link = result.scalar_one_or_none()
    if link is None:
        link = GitHubRepositoryLink(
            tenant_key=tenant_key,
            owner_id=current_user.id,
            organization_id=getattr(current_user, "organization_id", None),
            installation_id=request.installation_id,
            repository_id=request.repository_id,
            repository_full_name=request.repository_full_name,
        )
        db.add(link)
    link.tenant_key = tenant_key
    link.owner_id = current_user.id
    link.organization_id = getattr(current_user, "organization_id", None)
    link.threat_model_id = request.threat_model_id
    link.repository_full_name = request.repository_full_name
    link.private = request.private
    link.requested_tools = list(dict.fromkeys(request.requested_tools))
    link.status = "active"
    await db.flush()
    return link


async def get_active_github_repository_link(
    db: AsyncSession,
    *,
    installation_id: str,
    repository_id: str,
) -> GitHubRepositoryLink | None:
    result = await db.execute(
        select(GitHubRepositoryLink).where(
            GitHubRepositoryLink.installation_id == installation_id,
            GitHubRepositoryLink.repository_id == repository_id,
            GitHubRepositoryLink.status == "active",
        )
    )
    return result.scalar_one_or_none()


async def mark_github_installation_status(
    db: AsyncSession,
    *,
    installation_id: str,
    status: Literal["suspended", "uninstalled", "active"],
) -> int:
    result = await db.execute(
        update(GitHubRepositoryLink)
        .where(GitHubRepositoryLink.installation_id == installation_id)
        .values(status=status)
    )
    return int(result.rowcount or 0)


async def block_inflight_github_reviews(
    db: AsyncSession,
    *,
    tenant_key: str,
    installation_id: str,
) -> int:
    reviews = await list_application_reviews(db, tenant_key=tenant_key, limit=500)
    blocked = 0
    for review in reviews:
        github_scope = _mapping(review.scope.get("github"))
        if str(github_scope.get("installation_id")) != installation_id:
            continue
        if review.status in TERMINAL_REVIEW_STATUSES:
            continue
        review.status = "blocked_by_permission"
        review.error_message = "GitHub App installation is suspended or uninstalled."
        blocked += 1
    if blocked:
        await db.flush()
    return blocked


async def latest_github_pr_review(
    db: AsyncSession,
    *,
    tenant_key: str,
    repository_id: str,
    pull_request_number: int,
) -> ApplicationSecurityReview | None:
    reviews = await list_application_reviews(db, tenant_key=tenant_key, limit=500)
    for review in reviews:
        github_scope = _mapping(review.scope.get("github"))
        if str(github_scope.get("repository_id")) != repository_id:
            continue
        if int(github_scope.get("pull_request_number") or 0) == pull_request_number:
            return review
    return None


def parse_github_webhook_payload(
    *,
    event: str,
    raw_body: bytes,
) -> Mapping[str, Any]:
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubWebhookError("GitHub webhook payload is not valid JSON.") from exc
    if not isinstance(payload, Mapping):
        raise GitHubWebhookError("GitHub webhook payload must be a JSON object.")
    if event == "pull_request" and not _mapping(payload.get("pull_request")):
        raise GitHubWebhookError("GitHub pull_request webhook missing pull_request object.")
    return payload


def github_installation_id(payload: Mapping[str, Any]) -> str:
    installation_id = _mapping(payload.get("installation")).get("id")
    if installation_id is None:
        raise GitHubWebhookError("GitHub webhook missing installation.id.")
    return str(installation_id)


def github_repository_id(payload: Mapping[str, Any]) -> str:
    repository_id = _mapping(payload.get("repository")).get("id")
    if repository_id is None:
        raise GitHubWebhookError("GitHub webhook missing repository.id.")
    return str(repository_id)


def github_repository_full_name(payload: Mapping[str, Any]) -> str | None:
    return _string(_mapping(payload.get("repository")).get("full_name"))


async def build_pr_orchestration_request(
    db: AsyncSession,
    *,
    link: GitHubRepositoryLink,
    payload: Mapping[str, Any],
) -> ApplicationReviewOrchestrationRequest:
    pull_request = _mapping(payload.get("pull_request"))
    head = _mapping(pull_request.get("head"))
    base = _mapping(pull_request.get("base"))
    pr_number = int(pull_request.get("number") or payload.get("number") or 0)
    head_sha = _string(head.get("sha"))
    if not pr_number or not head_sha:
        raise GitHubWebhookError("GitHub pull_request webhook missing PR number or head SHA.")
    tenant_key = link.tenant_key
    parent = await latest_github_pr_review(
        db,
        tenant_key=tenant_key,
        repository_id=link.repository_id,
        pull_request_number=pr_number,
    )
    scope = {
        "github": {
            "installation_id": link.installation_id,
            "repository_id": link.repository_id,
            "repository_full_name": link.repository_full_name,
            "pull_request_number": pr_number,
            "pull_request_url": _string(pull_request.get("html_url")),
            "head_sha": head_sha,
            "base_sha": _string(base.get("sha")),
            "diff_url": _string(pull_request.get("diff_url")),
        }
    }
    review = ApplicationReviewCreate(
        app_name=link.repository_full_name,
        threat_model_id=link.threat_model_id,
        parent_review_id=parent.id if parent is not None else None,
        invocation_surface="pr",
        input_kind="diff",
        commit_sha=head_sha,
        requested_tools=[tool for tool in link.requested_tools if tool in _review_tools()],
        scope=scope,
        context={
            "github": {
                "title": _string(pull_request.get("title")),
                "body": _string(pull_request.get("body")),
                "base_ref": _string(base.get("ref")),
                "head_ref": _string(head.get("ref")),
            }
        },
        intake_answers=_github_pr_intake_answers(payload),
        idempotency_key=f"github-pr:{link.repository_id}:{pr_number}:{head_sha}",
    )
    return ApplicationReviewOrchestrationRequest(
        review=review,
        rebuild_context=True,
        evaluate_decision=True,
    )


def render_github_pr_comment(
    *,
    review_id: Any,
    decision: str | None,
    status: str,
    web_url: str | None,
    repository_id: str | None = None,
    pull_request_number: int | None = None,
) -> str:
    outcome = decision or "pending"
    review_link = web_url or "Review URL unavailable"
    markers = []
    if repository_id and pull_request_number:
        markers.append(f"<!-- threatgenix-pr-review:{repository_id}:{pull_request_number} -->")
    markers.append(f"<!-- threatgenix-review:{review_id} -->")
    return "\n".join(
        [
            *markers,
            "### ThreatGenix Security Review",
            "",
            f"- Status: `{status}`",
            f"- Decision: `{outcome}`",
            f"- Required check: `{GITHUB_REQUIRED_CHECK_NAME}`",
            f"- Review: {review_link}",
            "",
            "Evidence-backed findings and rerun history live in the linked review artifact.",
        ]
    )


def choose_pr_comment_upsert(
    *,
    existing_comments: Sequence[Mapping[str, Any]],
    review_id: Any,
    body: str,
    repository_id: str | None = None,
    pull_request_number: int | None = None,
) -> dict[str, Any]:
    stable_marker = (
        f"<!-- threatgenix-pr-review:{repository_id}:{pull_request_number} -->"
        if repository_id and pull_request_number
        else None
    )
    marker = f"<!-- threatgenix-review:{review_id} -->"
    for comment in existing_comments:
        comment_body = _string(comment.get("body")) or ""
        if (stable_marker and stable_marker in comment_body) or marker in comment_body:
            return {"action": "edit", "comment_id": comment.get("id"), "body": body}
    return {"action": "create", "comment_id": None, "body": body}


async def dispatch_github_pr_review_update(
    *,
    access_token: str,
    repository_full_name: str,
    pull_request_number: int,
    head_sha: str,
    review_id: Any,
    decision: str | None,
    status: str,
    web_url: str | None,
    repository_id: str | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> GitHubOutboundDispatchResult:
    """Publish the ThreatGenix PR comment and required commit status to GitHub."""

    token = access_token.strip()
    if not token:
        raise GitHubOutboundDispatchError("GitHub outbound dispatch requires an access token.")
    repository = _normalize_repository_full_name(repository_full_name)
    if pull_request_number <= 0:
        raise GitHubOutboundDispatchError("GitHub outbound dispatch requires a pull request number.")
    clean_head_sha = _string(head_sha)
    if not clean_head_sha:
        raise GitHubOutboundDispatchError("GitHub outbound dispatch requires a head SHA.")

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(20.0))
    try:
        comments = await _github_request_json(
            client,
            "GET",
            f"/repos/{repository}/issues/{pull_request_number}/comments",
            access_token=token,
        )
        existing_comments = comments if isinstance(comments, list) else []
        body = render_github_pr_comment(
            review_id=review_id,
            decision=decision,
            status=status,
            web_url=web_url,
            repository_id=repository_id,
            pull_request_number=pull_request_number,
        )
        upsert = choose_pr_comment_upsert(
            existing_comments=existing_comments,
            review_id=review_id,
            body=body,
            repository_id=repository_id,
            pull_request_number=pull_request_number,
        )
        if upsert["action"] == "edit":
            comment_id = upsert.get("comment_id")
            if comment_id is None:
                raise GitHubOutboundDispatchError("GitHub comment edit was missing comment id.")
            await _github_request_json(
                client,
                "PATCH",
                f"/repos/{repository}/issues/comments/{comment_id}",
                access_token=token,
                json_body={"body": body},
            )
        else:
            created = await _github_request_json(
                client,
                "POST",
                f"/repos/{repository}/issues/{pull_request_number}/comments",
                access_token=token,
                json_body={"body": body},
            )
            comment_id = int(created.get("id")) if isinstance(created, Mapping) and created.get("id") else None

        state = github_status_state(decision=decision, status=status)
        await _github_request_json(
            client,
            "POST",
            f"/repos/{repository}/statuses/{clean_head_sha}",
            access_token=token,
            json_body={
                "state": state,
                "context": GITHUB_REQUIRED_CHECK_NAME,
                "target_url": web_url,
                "description": _github_status_description(decision=decision, status=status),
            },
        )
        return GitHubOutboundDispatchResult(
            comment_action=upsert["action"],
            comment_id=comment_id,
            status_state=state,
            status_context=GITHUB_REQUIRED_CHECK_NAME,
            target_url=web_url,
        )
    finally:
        if owns_client:
            await client.aclose()


async def enqueue_github_pr_review_dispatch(
    *,
    db: AsyncSession,
    review: ApplicationSecurityReview,
) -> GitHubReviewDispatch | None:
    """Queue one GitHub outbound dispatch for a terminal PR-backed review."""

    if review.invocation_surface != "pr" or review.status not in TERMINAL_REVIEW_STATUSES:
        return None
    github_scope = _mapping((review.scope or {}).get("github"))
    installation_id = _string(github_scope.get("installation_id"))
    repository_id = _string(github_scope.get("repository_id"))
    pull_request_number = int(github_scope.get("pull_request_number") or 0)
    head_sha = _string(github_scope.get("head_sha"))
    if not installation_id or not repository_id or pull_request_number <= 0 or not head_sha:
        return None
    if review.commit_sha and review.commit_sha != head_sha:
        return None

    link = await get_active_github_repository_link(
        db,
        installation_id=installation_id,
        repository_id=repository_id,
    )
    if link is None or link.tenant_key != review.tenant_key:
        return None

    existing = await _get_review_dispatch(
        db,
        tenant_key=review.tenant_key,
        review_id=review.id,
        repository_id=repository_id,
        pull_request_number=pull_request_number,
        head_sha=head_sha,
        status_context=GITHUB_REQUIRED_CHECK_NAME,
    )
    if existing is not None:
        if existing.review_status != review.status or existing.review_decision != review.decision:
            existing.review_status = review.status
            existing.review_decision = review.decision
            existing.status = "queued"
            existing.last_error = None
            await db.flush()
        return existing

    dispatch = GitHubReviewDispatch(
        tenant_key=review.tenant_key,
        review_id=review.id,
        installation_id=installation_id,
        repository_id=repository_id,
        repository_full_name=link.repository_full_name,
        pull_request_number=pull_request_number,
        head_sha=head_sha,
        status_context=GITHUB_REQUIRED_CHECK_NAME,
        review_status=review.status,
        review_decision=review.decision,
        status="queued",
        attempt_count=0,
    )
    db.add(dispatch)
    await db.flush()
    return dispatch


async def process_github_review_dispatch(
    *,
    db: AsyncSession,
    dispatch_id: Any,
    access_token: str | None,
    web_url: str | None,
    http_client: httpx.AsyncClient | None = None,
) -> GitHubReviewDispatchOutcome:
    """Send one queued GitHub dispatch and record success or failure on the row."""

    dispatch = await _claim_github_review_dispatch(db, dispatch_id=dispatch_id)
    if dispatch is None:
        return GitHubReviewDispatchOutcome(status="skipped", reason="dispatch not claimable")
    review = await db.get(ApplicationSecurityReview, dispatch.review_id)
    if review is None or review.tenant_key != dispatch.tenant_key:
        dispatch.status = "terminal_failed"
        dispatch.last_error = "review not found for dispatch tenant"
        await db.flush()
        return GitHubReviewDispatchOutcome(status="failed", reason=dispatch.last_error, dispatch=dispatch)

    link = await get_active_github_repository_link(
        db,
        installation_id=dispatch.installation_id,
        repository_id=dispatch.repository_id,
    )
    if link is None or link.tenant_key != dispatch.tenant_key:
        dispatch.status = "terminal_failed"
        dispatch.last_error = "GitHub repository link is not active for dispatch tenant"
        await db.flush()
        return GitHubReviewDispatchOutcome(status="failed", reason=dispatch.last_error, dispatch=dispatch)

    try:
        token = (access_token or "").strip() or await mint_github_installation_access_token(
            installation_id=dispatch.installation_id,
            http_client=http_client,
        )
    except GitHubOutboundDispatchError as exc:
        dispatch.status = _github_dispatch_failure_status(str(exc))
        dispatch.last_error = str(exc)
        await db.flush()
        return GitHubReviewDispatchOutcome(status="failed", reason=str(exc), dispatch=dispatch)

    try:
        result = await dispatch_github_pr_review_update(
            access_token=token,
            repository_full_name=link.repository_full_name,
            pull_request_number=dispatch.pull_request_number,
            head_sha=dispatch.head_sha,
            review_id=review.id,
            decision=review.decision,
            status=review.status,
            web_url=web_url,
            repository_id=dispatch.repository_id,
            http_client=http_client,
        )
    except GitHubOutboundDispatchError as exc:
        dispatch.status = _github_dispatch_failure_status(str(exc))
        dispatch.last_error = str(exc)
        await db.flush()
        return GitHubReviewDispatchOutcome(status="failed", reason=str(exc), dispatch=dispatch)

    dispatch.status = "dispatched"
    dispatch.last_error = None
    dispatch.comment_id = result.comment_id
    dispatch.status_state = result.status_state
    dispatch.target_url = result.target_url
    dispatch.dispatched_at = datetime.now(tz=UTC)
    await db.flush()
    return GitHubReviewDispatchOutcome(status="dispatched", result=result, dispatch=dispatch)


async def latest_github_review_dispatch(
    db: AsyncSession,
    *,
    review_id: Any,
) -> GitHubReviewDispatch | None:
    result = await db.execute(
        select(GitHubReviewDispatch)
        .where(GitHubReviewDispatch.review_id == review_id)
        .order_by(GitHubReviewDispatch.queued_at.desc())
    )
    return result.scalars().first()


async def mint_github_installation_access_token(
    *,
    installation_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> str:
    """Mint a short-lived GitHub App installation token for one dispatch."""

    app_jwt = create_github_app_jwt()
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(20.0))
    try:
        response = await _github_request_json(
            client,
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            access_token=app_jwt,
        )
    finally:
        if owns_client:
            await client.aclose()
    if not isinstance(response, Mapping):
        raise GitHubOutboundDispatchError("GitHub installation token response was invalid.")
    token = _string(response.get("token"))
    if not token:
        raise GitHubOutboundDispatchError("GitHub installation token response omitted token.")
    _validate_github_installation_token_expiry(_string(response.get("expires_at")))
    _require_github_installation_permissions(_mapping(response.get("permissions")))
    return token


def create_github_app_jwt(*, now: datetime | None = None) -> str:
    app_id = _string(settings.github_app_id)
    private_key = _github_app_private_key()
    if not app_id or not private_key:
        raise GitHubOutboundDispatchError("missing GitHub App credentials for installation token minting")
    observed = now or datetime.now(tz=UTC)
    payload = {
        "iat": int((observed - timedelta(seconds=60)).timestamp()),
        "exp": int((observed + timedelta(minutes=9)).timestamp()),
        "iss": app_id,
    }
    return jose_jwt.encode(payload, private_key, algorithm="RS256")


def github_status_state(
    *,
    decision: str | None,
    status: str,
) -> Literal["success", "failure", "pending", "error"]:
    if status in {"failed_retryable", "failed_terminal", "blocked_by_permission", "blocked_by_policy"}:
        return "error" if status.startswith("failed") else "failure"
    if status not in TERMINAL_REVIEW_STATUSES:
        return "pending"
    if decision in {"block", "fix"}:
        return "failure"
    if decision in {"pass", "accepted"}:
        return "success"
    if decision in {"verify", "gather_evidence", None}:
        return "pending"
    return "error"


def _github_pr_intake_answers(payload: Mapping[str, Any]) -> dict[str, object]:
    pull_request = _mapping(payload.get("pull_request"))
    title = _string(pull_request.get("title")) or "GitHub pull request"
    return {
        "business_purpose": f"Review GitHub PR: {title}",
        "data_classification": "internal",
        "sensitive_data_types": ["none"],
        "changed_security_surface": ["unknown"],
        "scanner_permissions": ["static_code"],
        "upload_permission": True,
        "github_permission": True,
        "out_of_scope": ["production data access", "active external scanning"],
    }


def _review_tools() -> set[ReviewTool]:
    return {"semgrep", "osv-scanner", "trivy", "checkov", "trufflehog", "nuclei", "evidence", "security-review"}


async def _github_request_json(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    access_token: str,
    json_body: Mapping[str, Any] | None = None,
) -> Any:
    url = f"https://api.github.com{path}"
    try:
        response = await client.request(
            method,
            url,
            json=dict(json_body) if json_body is not None else None,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "threatgenix-github-pr-dispatch/1.0",
            },
        )
    except httpx.HTTPError as exc:
        raise GitHubOutboundDispatchError("GitHub outbound dispatch request failed.") from exc
    if response.status_code not in {200, 201}:
        raise GitHubOutboundDispatchError(
            f"GitHub outbound dispatch returned HTTP {response.status_code}."
        )
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise GitHubOutboundDispatchError("GitHub outbound dispatch returned invalid JSON.") from exc


def _github_app_private_key() -> str | None:
    raw_private_key = _string(settings.github_app_private_key)
    if not raw_private_key:
        encoded = _string(settings.github_app_private_key_base64)
        if encoded:
            try:
                raw_private_key = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as exc:
                raise GitHubOutboundDispatchError("GitHub App private key base64 is invalid.") from exc
    if not raw_private_key:
        return None
    return raw_private_key.replace("\\n", "\n")


def _validate_github_installation_token_expiry(expires_at: str | None) -> None:
    if not expires_at:
        raise GitHubOutboundDispatchError("GitHub installation token response omitted expiry.")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubOutboundDispatchError("GitHub installation token expiry was invalid.") from exc
    if expiry <= datetime.now(tz=UTC) + timedelta(seconds=GITHUB_INSTALLATION_TOKEN_EXPIRY_SKEW_SECONDS):
        raise GitHubOutboundDispatchError("expired GitHub installation access token")


def _require_github_installation_permissions(permissions: Mapping[str, Any]) -> None:
    status_permission = _string(permissions.get("statuses"))
    comment_permission = _string(permissions.get("issues")) or _string(permissions.get("pull_requests"))
    if status_permission != "write" or comment_permission != "write":
        raise GitHubOutboundDispatchError(
            "missing required GitHub App permissions: statuses:write and issues:write or pull_requests:write"
        )


def _github_status_description(*, decision: str | None, status: str) -> str:
    if status not in TERMINAL_REVIEW_STATUSES:
        return "ThreatGenix review is still running."
    if decision in {"block", "fix"}:
        return "ThreatGenix found security issues that must be fixed before merge."
    if decision == "pass":
        return "ThreatGenix review passed."
    if decision in {"verify", "gather_evidence"}:
        return "ThreatGenix needs verification before merge."
    if decision == "accepted":
        return "ThreatGenix review is covered by an accepted risk."
    return "ThreatGenix review needs attention."


def _normalize_repository_full_name(repository_full_name: str) -> str:
    candidate = repository_full_name.strip().removesuffix(".git")
    if candidate.startswith("https://github.com/"):
        candidate = candidate.removeprefix("https://github.com/")
    parts = [part for part in candidate.strip("/").split("/") if part]
    if len(parts) != 2:
        raise GitHubOutboundDispatchError("GitHub repository must be in owner/repo form.")
    return f"{parts[0]}/{parts[1]}"


async def _get_review_dispatch(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: Any,
    repository_id: str,
    pull_request_number: int,
    head_sha: str,
    status_context: str,
) -> GitHubReviewDispatch | None:
    result = await db.execute(
        select(GitHubReviewDispatch).where(
            GitHubReviewDispatch.tenant_key == tenant_key,
            GitHubReviewDispatch.review_id == review_id,
            GitHubReviewDispatch.repository_id == repository_id,
            GitHubReviewDispatch.pull_request_number == pull_request_number,
            GitHubReviewDispatch.head_sha == head_sha,
            GitHubReviewDispatch.status_context == status_context,
        )
    )
    return result.scalar_one_or_none()


async def _claim_github_review_dispatch(
    db: AsyncSession,
    *,
    dispatch_id: Any,
) -> GitHubReviewDispatch | None:
    result = await db.execute(
        update(GitHubReviewDispatch)
        .where(
            GitHubReviewDispatch.id == dispatch_id,
            GitHubReviewDispatch.status.in_(("queued", "retryable_failed")),
        )
        .values(
            status="dispatching",
            attempt_count=GitHubReviewDispatch.attempt_count + 1,
            last_error=None,
            updated_at=datetime.now(tz=UTC),
        )
        .returning(GitHubReviewDispatch.id)
    )
    claimed_id = result.scalar_one_or_none()
    if claimed_id is None:
        return None
    dispatch = await db.get(GitHubReviewDispatch, claimed_id)
    if dispatch is not None and dispatch.status != "dispatching":
        dispatch.status = "dispatching"
        dispatch.attempt_count = int(dispatch.attempt_count or 0) + 1
        dispatch.last_error = None
    await db.flush()
    return dispatch


def _github_dispatch_failure_status(error: str) -> Literal["retryable_failed", "terminal_failed"]:
    terminal_markers = (
        "HTTP 401",
        "HTTP 403",
        "HTTP 404",
        "GitHub App credentials",
        "GitHub App private key",
        "GitHub installation token",
        "expired GitHub installation access token",
        "missing required GitHub App permissions",
    )
    if any(marker in error for marker in terminal_markers):
        return "terminal_failed"
    return "retryable_failed"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    return candidate or None
