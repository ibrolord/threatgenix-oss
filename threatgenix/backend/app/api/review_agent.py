"""Agent/API access layer for invoke-anywhere security reviews."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.application_review_context import ApplicationReviewContextEntryResponse
from app.schemas.application_review_orchestration import ApplicationReviewOrchestrationRequest
from app.schemas.review_agent import (
    AgentEvidenceChainResponse,
    AgentOpenReviewResponse,
    AgentReviewOrchestrationResponse,
    AgentReviewFindingsResponse,
    AgentReviewStatusResponse,
    AgentRerunReviewResponse,
)
from app.services.application_review import (
    get_application_review,
    serialize_application_review,
    tenant_key_for_user,
)
from app.services.application_review_context import (
    ApplicationReviewContextError,
    rebuild_review_context_index,
    search_review_context_index,
)
from app.services.application_review_decision import evaluate_application_review_decision
from app.services.application_review_orchestration import orchestrate_application_review
from app.services.agent_access_limits import (
    AgentAccessDecision,
    AgentAccessLimitExceeded,
    AgentAccessUsage,
    enforce_agent_access_limits,
    token_fingerprint_for_request,
)
from app.services.auth import get_current_user

router = APIRouter(prefix="/api/agent/reviews", tags=["agent-reviews"])


@router.post("/orchestrations", response_model=AgentReviewOrchestrationResponse)
async def orchestrate_agent_review(
    orchestration: ApplicationReviewOrchestrationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentReviewOrchestrationResponse:
    access = _enforce_agent_access(
        request,
        current_user=current_user,
        usage=_orchestration_usage(orchestration),
    )
    response = await orchestrate_application_review(
        db,
        current_user=current_user,
        request=orchestration,
        public_web_base_url=str(_public_base_url(request)).rstrip("/"),
    )
    review_id = response.review.id if response.review is not None else None
    return AgentReviewOrchestrationResponse(
        orchestration=response,
        agent_tools=_agent_tools(request, review_id),
        access=_access_metadata(access),
    )


@router.get("/{review_id}/status", response_model=AgentReviewStatusResponse)
async def get_agent_review_status(
    review_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentReviewStatusResponse:
    access = _enforce_agent_access(request, current_user=current_user)
    review = await _get_review_or_404(db, current_user=current_user, review_id=review_id)
    return AgentReviewStatusResponse(
        review=serialize_application_review(review),
        web_url=_review_web_url(request, review_id),
        api_status_url=_agent_api_url(request, review_id, "/status"),
        terminal_commands=_terminal_commands(request, review_id),
        agent_tools=_agent_tools(request, review_id),
        access=_access_metadata(access),
    )


@router.get("/{review_id}/findings", response_model=AgentReviewFindingsResponse)
async def get_agent_review_findings(
    review_id: UUID,
    request: Request,
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentReviewFindingsResponse:
    access = _enforce_agent_access(request, current_user=current_user)
    entries = await _search_or_http(
        db,
        current_user=current_user,
        review_id=review_id,
        query="scanner_finding severity",
        limit=limit,
    )
    findings = [entry for entry in entries if entry.item_type == "scanner_finding"]
    return AgentReviewFindingsResponse(
        review_id=review_id,
        findings=[ApplicationReviewContextEntryResponse.model_validate(entry) for entry in findings],
        access=_access_metadata(access),
    )


@router.get(
    "/{review_id}/findings/{finding_id}/evidence-chain",
    response_model=AgentEvidenceChainResponse,
)
async def get_agent_evidence_chain(
    review_id: UUID,
    finding_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentEvidenceChainResponse:
    access = _enforce_agent_access(request, current_user=current_user)
    entries = await _search_or_http(
        db,
        current_user=current_user,
        review_id=review_id,
        query="",
        limit=50,
    )
    for entry in entries:
        if entry.id == finding_id:
            return AgentEvidenceChainResponse(
                review_id=review_id,
                finding_id=finding_id,
                source_refs=entry.source_refs or [],
                content_hash=entry.content_hash,
                access=_access_metadata(access),
            )
    raise HTTPException(status_code=404, detail="Finding was not found for this review.")


@router.get("/{review_id}/ship-decision", response_model=AgentReviewStatusResponse)
async def get_agent_ship_decision(
    review_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentReviewStatusResponse:
    return await get_agent_review_status(review_id, request, db, current_user)


def _enforce_agent_access(
    request: Request,
    *,
    current_user: User,
    usage: AgentAccessUsage | None = None,
) -> AgentAccessDecision:
    tenant_key = tenant_key_for_user(current_user)
    fallback = f"{tenant_key}:{getattr(current_user, 'id', '') or getattr(current_user, 'email', '')}"
    token_fingerprint = token_fingerprint_for_request(request, fallback=fallback)
    try:
        return enforce_agent_access_limits(
            tenant_key=tenant_key,
            token_fingerprint=token_fingerprint,
            usage=usage or AgentAccessUsage(),
        )
    except AgentAccessLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.detail,
            headers={
                "Retry-After": str(exc.retry_after_seconds),
                "X-ThreatGenix-Limit-Type": exc.limit_type,
                "X-ThreatGenix-Limit-Metric": exc.metric,
            },
        ) from exc


def _access_metadata(access: AgentAccessDecision) -> dict[str, object]:
    return {
        "rate_limit": access.rate_limit,
        "quotas": access.quotas,
    }


def _orchestration_usage(orchestration: ApplicationReviewOrchestrationRequest) -> AgentAccessUsage:
    scanner_count = len(orchestration.scanner_tools or [])
    manifest_bytes = 0
    if orchestration.bundle is not None:
        manifest_bytes = sum(item.byte_size for item in orchestration.bundle.manifest)
    return AgentAccessUsage(
        scan_minutes=scanner_count * 2,
        ai_tokens=1_000 if orchestration.evaluate_decision else 0,
        bundle_storage_bytes=manifest_bytes,
    )


@router.get("/{review_id}/open", response_model=AgentOpenReviewResponse)
async def open_agent_review(
    review_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentOpenReviewResponse:
    access = _enforce_agent_access(request, current_user=current_user)
    await _get_review_or_404(db, current_user=current_user, review_id=review_id)
    return AgentOpenReviewResponse(
        review_id=review_id,
        web_url=_review_web_url(request, review_id),
        access=_access_metadata(access),
    )


@router.post("/{review_id}/rerun", response_model=AgentRerunReviewResponse)
async def rerun_agent_review(
    review_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentRerunReviewResponse:
    access = _enforce_agent_access(
        request,
        current_user=current_user,
        usage=AgentAccessUsage(ai_tokens=1_000),
    )
    try:
        entries = await rebuild_review_context_index(
            db,
            current_user=current_user,
            review_id=review_id,
        )
        decision = await evaluate_application_review_decision(
            db,
            current_user=current_user,
            review_id=review_id,
        )
        await db.commit()
    except ApplicationReviewContextError as exc:
        await db.rollback()
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)
    return AgentRerunReviewResponse(
        review_id=review_id,
        indexed_entry_count=len(entries),
        decision=decision,
        access=_access_metadata(access),
    )


async def _get_review_or_404(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
):
    review = await get_application_review(
        db,
        tenant_key=tenant_key_for_user(current_user),
        review_id=review_id,
    )
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    return review


async def _search_or_http(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
    query: str,
    limit: int,
):
    try:
        return await search_review_context_index(
            db,
            current_user=current_user,
            review_id=review_id,
            query=query,
            limit=limit,
        )
    except ApplicationReviewContextError as exc:
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)


def _review_web_url(request: Request, review_id: UUID) -> str:
    return str(_public_base_url(request).replace(path=f"reviews/{review_id}", query=""))


def _agent_api_url(request: Request, review_id: UUID, suffix: str) -> str:
    path = f"api/agent/reviews/{review_id}{suffix}"
    return str(_public_base_url(request).replace(path=path, query=""))


def _public_base_url(request: Request):
    forwarded_host = request.headers.get("x-forwarded-host")
    host = forwarded_host or request.headers.get("host")
    if not host:
        return request.base_url
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return request.base_url.replace(scheme=proto, netloc=host, path="/", query="")


def _terminal_commands(request: Request, review_id: UUID) -> list[dict[str, str]]:
    status_url = _agent_api_url(request, review_id, "/status")
    rerun_url = _agent_api_url(request, review_id, "/rerun")
    return [
        {
            "label": "Check review status",
            "command": (
                "curl -sS -H \"Authorization: Bearer $THREATGENIX_TOKEN\" "
                f"\"{status_url}\""
            ),
            "description": "Reads the tenant-scoped review, decision, web URL, and agent command contract.",
        },
        {
            "label": "Rebuild context and re-evaluate",
            "command": (
                "curl -sS -X POST -H \"Authorization: Bearer $THREATGENIX_TOKEN\" "
                f"\"{rerun_url}\""
            ),
            "description": "Rebuilds the indexed context packet and reruns the deterministic merge decision.",
        },
    ]


def _agent_orchestration_url(request: Request) -> str:
    return str(_public_base_url(request).replace(path="api/agent/reviews/orchestrations", query=""))


def _agent_tools(request: Request, review_id: UUID | None) -> list[dict[str, object]]:
    orchestration_tool = {
        "name": "threatgenix.review.orchestrate",
        "method": "POST",
        "endpoint": _agent_orchestration_url(request),
        "description": "Run the tenant-scoped review orchestration workflow from app profile, intake, bundle manifest, and scanner approvals.",
        "input_schema": {
            "type": "object",
            "required": ["review"],
            "properties": {
                "threat_model": {"type": ["object", "null"]},
                "review": {"type": "object"},
                "bundle": {"type": ["object", "null"]},
                "scanner_tools": {"type": ["array", "null"], "items": {"type": "string"}},
                "external_active_authorized": {"type": "boolean"},
                "external_targets": {"type": "array", "items": {"type": "string"}},
                "rebuild_context": {"type": "boolean"},
                "evaluate_decision": {"type": "boolean"},
            },
        },
        "output_schema": {
            "type": "object",
            "required": ["contract_version", "orchestration", "agent_tools", "access"],
        },
        "rate_limit": _agent_rate_limit_hint(),
        "quota_cost": _agent_quota_cost_hint("orchestrate"),
    }
    if review_id is None:
        return [orchestration_tool]
    tools: list[dict[str, object]] = [
        {
            "name": "threatgenix.review.status",
            "method": "GET",
            "endpoint": _agent_api_url(request, review_id, "/status"),
            "description": "Return review status, decision, web URL, and terminal command hints.",
            "input_schema": {"type": "object", "required": ["review_id"]},
            "output_schema": {"type": "object", "required": ["contract_version", "review", "web_url", "access"]},
            "rate_limit": _agent_rate_limit_hint(),
            "quota_cost": _agent_quota_cost_hint("read"),
        },
        {
            "name": "threatgenix.review.findings",
            "method": "GET",
            "endpoint": _agent_api_url(request, review_id, "/findings"),
            "description": "Return scanner findings from the tenant-scoped context index.",
            "input_schema": {"type": "object", "required": ["review_id"]},
            "output_schema": {"type": "object", "required": ["contract_version", "review_id", "findings", "access"]},
            "rate_limit": _agent_rate_limit_hint(),
            "quota_cost": _agent_quota_cost_hint("read"),
        },
        {
            "name": "threatgenix.review.rerun",
            "method": "POST",
            "endpoint": _agent_api_url(request, review_id, "/rerun"),
            "description": "Rebuild context and evaluate the current ship decision.",
            "input_schema": {"type": "object", "required": ["review_id"]},
            "output_schema": {"type": "object", "required": ["contract_version", "review_id", "decision", "access"]},
            "rate_limit": _agent_rate_limit_hint(),
            "quota_cost": _agent_quota_cost_hint("rerun"),
        },
        {
            "name": "threatgenix.review.open",
            "method": "GET",
            "endpoint": _agent_api_url(request, review_id, "/open"),
            "description": "Return the public web review URL for humans.",
            "input_schema": {"type": "object", "required": ["review_id"]},
            "output_schema": {"type": "object", "required": ["contract_version", "review_id", "web_url", "access"]},
            "rate_limit": _agent_rate_limit_hint(),
            "quota_cost": _agent_quota_cost_hint("read"),
        },
        orchestration_tool,
    ]
    return tools


def _agent_rate_limit_hint() -> dict[str, int | str]:
    return {
        "scope": "tenant_and_token",
        "window_seconds": int(settings.agent_access_window_seconds),
        "token_limit": int(settings.agent_token_rate_limit),
        "tenant_limit": int(settings.agent_tenant_rate_limit),
        "retry_after_header": "Retry-After",
    }


def _agent_quota_cost_hint(tool_family: str) -> dict[str, int | str]:
    if tool_family == "orchestrate":
        return {
            "api_calls": 1,
            "scan_minutes": "2 per requested scanner tool",
            "ai_tokens": "1000 when evaluate_decision is true",
            "bundle_storage_bytes": "sum of bundle.manifest[].byte_size",
        }
    if tool_family == "rerun":
        return {
            "api_calls": 1,
            "scan_minutes": 0,
            "ai_tokens": 1000,
            "bundle_storage_bytes": 0,
        }
    return {
        "api_calls": 1,
        "scan_minutes": 0,
        "ai_tokens": 0,
        "bundle_storage_bytes": 0,
    }
