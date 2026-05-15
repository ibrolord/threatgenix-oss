"""GitHub App integration endpoints for PR-triggered reviews."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.github_integration import (
    GitHubRepositoryLinkCreate,
    GitHubRepositoryLinkResponse,
    GitHubWebhookResponse,
)
from app.services.application_review_orchestration import orchestrate_application_review
from app.services.auth import get_current_user
from app.services.github_pr_integration import (
    GITHUB_REQUIRED_CHECK_NAME,
    GitHubWebhookError,
    block_inflight_github_reviews,
    build_pr_orchestration_request,
    consume_github_delivery_once,
    create_or_update_github_repository_link,
    get_active_github_repository_link,
    github_installation_id,
    github_repository_full_name,
    github_repository_id,
    latest_github_review_dispatch,
    mark_github_installation_status,
    parse_github_webhook_payload,
    process_github_review_dispatch,
    render_github_pr_comment,
    verify_github_webhook_signature,
)

router = APIRouter(prefix="/api/integrations/github", tags=["github-integration"])


@router.post("/repos", response_model=GitHubRepositoryLinkResponse)
async def link_github_repository(
    request: GitHubRepositoryLinkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GitHubRepositoryLinkResponse:
    link = await create_or_update_github_repository_link(
        db,
        current_user=current_user,
        request=request,
    )
    await db.commit()
    return GitHubRepositoryLinkResponse.model_validate(link, from_attributes=True)


@router.post("/webhook", response_model=GitHubWebhookResponse)
async def handle_github_webhook(
    request: Request,
    x_github_event: str = Header(default="", alias="X-GitHub-Event"),
    x_github_delivery: str = Header(default="", alias="X-GitHub-Delivery"),
    db: AsyncSession = Depends(get_db),
) -> GitHubWebhookResponse:
    raw_body = await request.body()
    try:
        verify_github_webhook_signature(headers=request.headers, raw_body=raw_body)
        payload = parse_github_webhook_payload(event=x_github_event, raw_body=raw_body)
        installation_id = github_installation_id(payload)
        await consume_github_delivery_once(
            db=db,
            delivery_id=_required_delivery(x_github_delivery),
            installation_id=installation_id,
        )
    except GitHubWebhookError as exc:
        await db.rollback()
        raise HTTPException(status_code=401 if "signature" in str(exc).lower() else 409, detail=str(exc))

    action = str(payload.get("action") or "")
    repository_full_name = github_repository_full_name(payload)
    if x_github_event == "ping":
        await db.commit()
        return GitHubWebhookResponse(
            status="accepted",
            event=x_github_event,
            action=action,
            delivery_id=x_github_delivery,
            repository_full_name=repository_full_name,
            ignored_reason="ping acknowledged",
        )
    if x_github_event == "installation" and action in {"deleted", "suspend", "unsuspend"}:
        status = "active" if action == "unsuspend" else "suspended" if action == "suspend" else "uninstalled"
        changed = await mark_github_installation_status(db, installation_id=installation_id, status=status)
        await db.commit()
        return GitHubWebhookResponse(
            status="accepted",
            event=x_github_event,
            action=action,
            delivery_id=x_github_delivery,
            repository_full_name=repository_full_name,
            ignored_reason=f"updated {changed} repository links to {status}",
        )
    if x_github_event != "pull_request" or action not in {
        "opened",
        "reopened",
        "synchronize",
        "ready_for_review",
    }:
        await db.commit()
        return GitHubWebhookResponse(
            status="ignored",
            event=x_github_event,
            action=action,
            delivery_id=x_github_delivery,
            repository_full_name=repository_full_name,
            ignored_reason="event is not a PR review trigger",
        )

    repository_id = github_repository_id(payload)
    link = await get_active_github_repository_link(
        db,
        installation_id=installation_id,
        repository_id=repository_id,
    )
    if link is None:
        await db.commit()
        return GitHubWebhookResponse(
            status="ignored",
            event=x_github_event,
            action=action,
            delivery_id=x_github_delivery,
            repository_full_name=repository_full_name,
            pull_request_number=_pull_request_number(payload),
            ignored_reason="repository is not linked to a ThreatGenix tenant",
        )

    owner = await db.get(User, link.owner_id)
    if owner is None:
        await db.rollback()
        raise HTTPException(status_code=410, detail="Linked GitHub repository owner no longer exists.")
    if link.status != "active":
        blocked = await block_inflight_github_reviews(
            db,
            tenant_key=link.tenant_key,
            installation_id=link.installation_id,
        )
        await db.commit()
        return GitHubWebhookResponse(
            status="rejected",
            event=x_github_event,
            action=action,
            delivery_id=x_github_delivery,
            repository_full_name=repository_full_name,
            pull_request_number=_pull_request_number(payload),
            ignored_reason=f"GitHub repository link is {link.status}; blocked {blocked} in-flight reviews",
        )

    orchestration_request = await build_pr_orchestration_request(db, link=link, payload=payload)
    orchestration = await orchestrate_application_review(
        db,
        current_user=owner,
        request=orchestration_request,
        public_web_base_url=str(_public_base_url(request)).rstrip("/"),
    )
    review = orchestration.review
    web_url = orchestration.web_url
    if review is not None and web_url is None:
        web_url = str(_public_base_url(request).replace(path=f"reviews/{review.id}", query=""))
    await db.commit()
    comment_body = None
    dispatch = None
    if review is not None:
        dispatch = await latest_github_review_dispatch(db, review_id=review.id)
        if dispatch is not None:
            await process_github_review_dispatch(
                db=db,
                dispatch_id=dispatch.id,
                access_token=None,
                web_url=web_url,
            )
            await db.commit()
        comment_body = render_github_pr_comment(
            review_id=review.id,
            decision=review.decision,
            status=review.status,
            web_url=web_url,
            repository_id=dispatch.repository_id if dispatch is not None else None,
            pull_request_number=dispatch.pull_request_number if dispatch is not None else None,
        )
    return GitHubWebhookResponse(
        status="accepted",
        event=x_github_event,
        action=action,
        delivery_id=x_github_delivery,
        repository_full_name=repository_full_name,
        pull_request_number=_pull_request_number(payload),
        review_id=review.id if review is not None else None,
        review_lineage_id=review.review_lineage_id if review is not None else None,
        web_url=web_url,
        check_name=GITHUB_REQUIRED_CHECK_NAME,
        comment_body=comment_body,
    )


def _required_delivery(delivery_id: str) -> str:
    candidate = delivery_id.strip()
    if not candidate:
        raise GitHubWebhookError("Missing GitHub delivery id.")
    return candidate


def _pull_request_number(payload: dict | object) -> int | None:
    if not isinstance(payload, dict):
        return None
    pull_request = payload.get("pull_request")
    if isinstance(pull_request, dict):
        number = pull_request.get("number")
        return int(number) if number is not None else None
    number = payload.get("number")
    return int(number) if number is not None else None


def _public_base_url(request: Request):
    forwarded_host = request.headers.get("x-forwarded-host")
    host = forwarded_host or request.headers.get("host")
    if not host:
        return request.base_url
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return request.base_url.replace(scheme=proto, netloc=host, path="/", query="")
