"""Application security review endpoints."""

from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.application_review import ApplicationReviewCreate, ApplicationReviewResponse
from app.schemas.application_review_artifact import (
    ApplicationReviewArtifactFixPlanStep,
    ApplicationReviewArtifactResponse,
    ApplicationReviewEvidenceChain,
    ApplicationReviewEvidenceChainStep,
    ApplicationReviewGraphEdge,
    ApplicationReviewGraphNode,
    ApplicationReviewGraphSlice,
    ApplicationReviewRerunHistoryEntry,
)
from app.schemas.application_review_bundle import (
    ApplicationReviewBundleCreate,
    ApplicationReviewBundleResponse,
)
from app.schemas.application_review_context import (
    ApplicationReviewContextEntryResponse,
    RebuildReviewContextIndexResponse,
    ReviewContextSearchResponse,
)
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.schemas.application_review_orchestration import (
    ApplicationReviewOrchestrationRequest,
    ApplicationReviewOrchestrationResponse,
)
from app.schemas.application_risk_acceptance import (
    ApplicationRiskAcceptanceCreate,
    ApplicationRiskAcceptanceExpireResponse,
    ApplicationRiskAcceptanceResponse,
    ApplicationRiskAcceptanceRevoke,
)
from app.schemas.review_intake import (
    IntakeQuestionBankResponse,
    IntakeValidationRequest,
    IntakeValidationResponse,
    ReviewInputKind,
)
from app.schemas.review_harness_ingest import (
    IngestHarnessOutputRequest,
    IngestHarnessOutputResponse,
)
from app.schemas.review_context_packet import GroundedAIExplanationResponse, ReviewContextPacket
from app.schemas.review_scanners import (
    EnqueueReviewScannersRequest,
    EnqueueReviewScannersResponse,
)
from app.schemas.scan import ScanJobResponse
from app.services.application_review import (
    ReviewIdempotencyConflict,
    ReviewValidationError,
    create_application_review,
    ensure_idempotent_review_matches,
    get_application_review,
    get_application_review_by_idempotency_key,
    generated_idempotency_key,
    list_application_reviews,
    serialize_application_review,
    tenant_key_for_user,
)
from app.services.application_review_bundles import (
    ReviewBundleValidationError,
    create_review_bundle,
    get_review_bundle,
    list_review_bundles,
    serialize_application_review_bundle,
)
from app.services.application_review_context import (
    ApplicationReviewContextError,
    rebuild_review_context_index,
    search_review_context_index,
)
from app.services.application_review_decision import evaluate_application_review_decision
from app.services.application_review_orchestration import orchestrate_application_review
from app.services.application_risk_acceptance import (
    RiskAcceptanceError,
    create_application_risk_acceptance,
    expire_application_risk_acceptances,
    list_application_risk_acceptances,
    revoke_application_risk_acceptance,
)
from app.services.auth import get_current_user
from app.services.model_collaboration import require_model_permission
from app.services.review_intake import get_intake_questions, validate_intake_answers
from app.services.review_context_packet import build_grounded_ai_explanation, build_review_context_packet
from app.services.review_harness_ingest import (
    ReviewHarnessIngestionError,
    ingest_review_harness_output,
)
from app.services.review_scanner_enqueue import (
    ReviewScannerEnqueueError,
    enqueue_review_scanner_jobs,
)
from app.services.threat_model import get_threat_model

router = APIRouter(prefix="/api/reviews", tags=["reviews"])
SENSITIVE_EVIDENCE_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}


@router.get("/intake/questions", response_model=IntakeQuestionBankResponse)
async def get_review_intake_questions(
    review_type: ReviewInputKind = "metadata",
    current_user: User = Depends(get_current_user),
) -> IntakeQuestionBankResponse:
    del current_user
    return get_intake_questions(review_type)


@router.post("/intake/validate", response_model=IntakeValidationResponse)
async def validate_review_intake(
    request: IntakeValidationRequest,
    current_user: User = Depends(get_current_user),
) -> IntakeValidationResponse:
    del current_user
    return validate_intake_answers(request)


@router.get("", response_model=list[ApplicationReviewResponse])
async def list_reviews(
    limit: int = Query(default=100, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ApplicationReviewResponse]:
    tenant_key = tenant_key_for_user(current_user)
    reviews = await list_application_reviews(db, tenant_key=tenant_key, limit=limit)
    return [serialize_application_review(review) for review in reviews]


@router.post("", response_model=ApplicationReviewResponse)
async def create_review(
    request: ApplicationReviewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewResponse:
    if request.threat_model_id is not None:
        threat_model = await get_threat_model(db, request.threat_model_id)
        require_model_permission(threat_model, current_user, "write")  # type: ignore[arg-type]
    try:
        review = await create_application_review(
            db,
            current_user=current_user,
            request=request,
        )
        await db.commit()
    except ReviewIdempotencyConflict as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except ReviewValidationError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc))
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=404, detail=str(exc))
    except IntegrityError:
        await db.rollback()
        tenant_key = tenant_key_for_user(current_user)
        idempotency_key = request.idempotency_key or generated_idempotency_key(
            tenant_key,
            request,
        )
        review = await get_application_review_by_idempotency_key(
            db,
            tenant_key=tenant_key,
            idempotency_key=idempotency_key,
        )
        if review is None:
            raise
        try:
            ensure_idempotent_review_matches(review, request)
        except ReviewIdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    return serialize_application_review(review)


@router.post(
    "/orchestrations",
    response_model=ApplicationReviewOrchestrationResponse,
)
async def orchestrate_review(
    request: Request,
    orchestration: ApplicationReviewOrchestrationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewOrchestrationResponse:
    return await orchestrate_application_review(
        db,
        current_user=current_user,
        request=orchestration,
        public_web_base_url=str(_public_base_url(request)).rstrip("/"),
    )


@router.post(
    "/risk-acceptances/expire",
    response_model=ApplicationRiskAcceptanceExpireResponse,
)
async def expire_risk_acceptances(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationRiskAcceptanceExpireResponse:
    try:
        expired = await expire_application_risk_acceptances(
            db,
            tenant_key=tenant_key_for_user(current_user),
        )
        await db.commit()
    except RiskAcceptanceError as exc:
        await db.rollback()
        raise HTTPException(status_code=403, detail=str(exc))
    return ApplicationRiskAcceptanceExpireResponse(expired_count=len(expired))


@router.get("/{review_id}", response_model=ApplicationReviewResponse)
async def get_review(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewResponse:
    review = await get_application_review(
        db,
        tenant_key=tenant_key_for_user(current_user),
        review_id=review_id,
    )
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    return serialize_application_review(review)


@router.get("/{review_id}/artifact", response_model=ApplicationReviewArtifactResponse)
async def get_review_artifact(
    request: Request,
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewArtifactResponse:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    try:
        entries = await search_review_context_index(
            db,
            current_user=current_user,
            review_id=review_id,
            query="",
            limit=50,
            include_stale=True,
        )
    except ApplicationReviewContextError as exc:
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)
    safe_entries = [_redacted_context_entry(entry) for entry in entries]
    decision_record = _review_decision_record(review.context)
    missing_evidence = []
    if decision_record is None and review.decision is None:
        missing_evidence.append("No deterministic decision has been evaluated yet.")
    if not safe_entries:
        missing_evidence.append("No raw evidence has been indexed for this review.")
    missing_evidence.extend(_decision_missing_evidence(decision_record))
    missing_evidence = _dedupe_strings(missing_evidence)
    evidence_chains = _build_evidence_chains(safe_entries)
    graph_slice = _build_graph_slice(review, safe_entries, missing_evidence)
    return ApplicationReviewArtifactResponse(
        review=serialize_application_review(review),
        web_url=f"{str(_public_base_url(request)).rstrip('/')}/reviews/{review.id}",
        decision_record=_redact_sensitive_value(decision_record) if decision_record else None,
        raw_evidence=safe_entries,
        raw_evidence_count=len(safe_entries),
        has_stale_evidence=any(entry.status == "stale" for entry in safe_entries),
        missing_evidence=missing_evidence,
        source_ref_count=sum(len(entry.source_refs) for entry in safe_entries),
        evidence_chains=evidence_chains,
        graph_slice=graph_slice,
        fix_plan=_build_artifact_fix_plan(review, safe_entries, missing_evidence),
        accepted_risks=[entry for entry in safe_entries if entry.item_type == "accepted_risk"],
        rerun_history=_build_rerun_history(review, decision_record),
        redacted=True,
    )


@router.post("/{review_id}/bundles", response_model=ApplicationReviewBundleResponse)
async def create_bundle(
    review_id: UUID,
    request: ApplicationReviewBundleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewBundleResponse:
    try:
        bundle = await create_review_bundle(
            db,
            current_user=current_user,
            review_id=review_id,
            request=request,
        )
        await db.commit()
    except ReviewBundleValidationError as exc:
        await db.rollback()
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)
    return serialize_application_review_bundle(bundle)


@router.get("/{review_id}/bundles", response_model=list[ApplicationReviewBundleResponse])
async def list_bundles(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ApplicationReviewBundleResponse]:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    bundles = await list_review_bundles(db, tenant_key=tenant_key, review_id=review_id)
    return [serialize_application_review_bundle(bundle) for bundle in bundles]


@router.get("/{review_id}/bundles/{bundle_id}", response_model=ApplicationReviewBundleResponse)
async def get_bundle(
    review_id: UUID,
    bundle_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewBundleResponse:
    bundle = await get_review_bundle(
        db,
        tenant_key=tenant_key_for_user(current_user),
        review_id=review_id,
        bundle_id=bundle_id,
    )
    if bundle is None:
        raise HTTPException(status_code=404, detail="Review bundle not found.")
    return serialize_application_review_bundle(bundle)


@router.post(
    "/{review_id}/risk-acceptances",
    response_model=ApplicationRiskAcceptanceResponse,
)
async def grant_risk_acceptance(
    review_id: UUID,
    request: ApplicationRiskAcceptanceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationRiskAcceptanceResponse:
    try:
        acceptance = await create_application_risk_acceptance(
            db,
            current_user=current_user,
            review_id=review_id,
            request=request,
        )
        await db.commit()
    except RiskAcceptanceError as exc:
        await db.rollback()
        message = str(exc)
        status_code = 403 if "role is required" in message else 422
        if "not found" in message:
            status_code = 404
        raise HTTPException(status_code=status_code, detail=message)
    return ApplicationRiskAcceptanceResponse.model_validate(acceptance)


@router.get(
    "/{review_id}/risk-acceptances",
    response_model=list[ApplicationRiskAcceptanceResponse],
)
async def list_risk_acceptances(
    review_id: UUID,
    include_revoked: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ApplicationRiskAcceptanceResponse]:
    review = await get_application_review(
        db,
        tenant_key=tenant_key_for_user(current_user),
        review_id=review_id,
    )
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    acceptances = await list_application_risk_acceptances(
        db,
        tenant_key=tenant_key_for_user(current_user),
        review_id=review_id,
        include_revoked=include_revoked,
    )
    return [ApplicationRiskAcceptanceResponse.model_validate(acceptance) for acceptance in acceptances]


@router.post(
    "/{review_id}/risk-acceptances/{acceptance_id}/revoke",
    response_model=ApplicationRiskAcceptanceResponse,
)
async def revoke_risk_acceptance(
    review_id: UUID,
    acceptance_id: UUID,
    request: ApplicationRiskAcceptanceRevoke,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationRiskAcceptanceResponse:
    try:
        acceptance = await revoke_application_risk_acceptance(
            db,
            current_user=current_user,
            acceptance_id=acceptance_id,
            review_id=review_id,
            reason=request.reason,
        )
        await db.commit()
    except RiskAcceptanceError as exc:
        await db.rollback()
        message = str(exc)
        status_code = 403 if "role is required" in message else 404
        raise HTTPException(status_code=status_code, detail=message)
    return ApplicationRiskAcceptanceResponse.model_validate(acceptance)


@router.post("/{review_id}/scanner-jobs", response_model=EnqueueReviewScannersResponse)
async def enqueue_scanner_jobs(
    review_id: UUID,
    request: EnqueueReviewScannersRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnqueueReviewScannersResponse:
    try:
        jobs = await enqueue_review_scanner_jobs(
            db,
            current_user=current_user,
            review_id=review_id,
            request=request,
        )
        await db.commit()
    except ReviewScannerEnqueueError as exc:
        await db.rollback()
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)
    return EnqueueReviewScannersResponse(
        review_id=review_id,
        bundle_id=request.bundle_id,
        jobs=[ScanJobResponse.model_validate(job) for job in jobs],
    )


@router.post(
    "/{review_id}/scanner-jobs/{scan_job_id}/harness-output",
    response_model=IngestHarnessOutputResponse,
)
async def ingest_scanner_harness_output(
    review_id: UUID,
    scan_job_id: UUID,
    request: IngestHarnessOutputRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IngestHarnessOutputResponse:
    try:
        response = await ingest_review_harness_output(
            db,
            current_user=current_user,
            review_id=review_id,
            scan_job_id=scan_job_id,
            request=request,
        )
        await db.commit()
    except ReviewHarnessIngestionError as exc:
        await db.rollback()
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)
    return response


def _public_base_url(request: Request):
    forwarded_host = request.headers.get("x-forwarded-host")
    host = forwarded_host or request.headers.get("host")
    if not host:
        return request.base_url
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return request.base_url.replace(scheme=proto, netloc=host, path="/", query="")


def _review_decision_record(context: object) -> dict | None:
    if not isinstance(context, dict):
        return None
    payload = context.get("deterministic_decision_replay")
    return payload if isinstance(payload, dict) else None


def _decision_missing_evidence(decision_record: dict | None) -> list[str]:
    if not isinstance(decision_record, dict):
        return []
    missing: list[str] = []
    for key in ("missing_evidence", "evidence_gaps", "gaps"):
        value = decision_record.get(key)
        if isinstance(value, list):
            missing.extend(str(item) for item in value if str(item).strip())
    return _dedupe_strings(missing)


def _build_evidence_chains(
    entries: list[ApplicationReviewContextEntryResponse],
) -> list[ApplicationReviewEvidenceChain]:
    chains: list[ApplicationReviewEvidenceChain] = []
    for entry in entries:
        steps = [
            ApplicationReviewEvidenceChainStep(
                step_type="context_entry",
                label=f"{entry.item_type}: {entry.title}",
                content_hash=entry.content_hash,
            )
        ]
        for ref in entry.source_refs[:8]:
            steps.append(
                ApplicationReviewEvidenceChainStep(
                    step_type="source_ref",
                    label=_source_ref_label(ref),
                    source_ref=ref,
                    content_hash=entry.content_hash,
                )
            )
        if entry.status == "stale" and entry.stale_reason:
            steps.append(
                ApplicationReviewEvidenceChainStep(
                    step_type="freshness",
                    label=f"Stale: {entry.stale_reason}",
                    content_hash=entry.content_hash,
                )
            )
        chains.append(
            ApplicationReviewEvidenceChain(
                chain_id=f"chain:{entry.content_hash[:16]}",
                title=entry.title,
                item_type=entry.item_type,
                status=entry.status,
                stale_reason=entry.stale_reason,
                content_hash=entry.content_hash,
                source_refs=entry.source_refs,
                steps=steps,
            )
        )
    return chains


def _build_graph_slice(
    review,
    entries: list[ApplicationReviewContextEntryResponse],
    missing_evidence: list[str],
) -> ApplicationReviewGraphSlice:
    nodes: dict[str, ApplicationReviewGraphNode] = {
        f"review:{review.id}": ApplicationReviewGraphNode(
            id=f"review:{review.id}",
            label=getattr(review, "app_name", "Application review"),
            node_type="review",
            evidence_hashes=[],
            status=getattr(review, "status", None),
        )
    }
    edges: list[ApplicationReviewGraphEdge] = []
    for entry in entries[:50]:
        entry_node_id = f"evidence:{entry.content_hash[:16]}"
        nodes[entry_node_id] = ApplicationReviewGraphNode(
            id=entry_node_id,
            label=entry.title,
            node_type=entry.item_type,
            evidence_hashes=[entry.content_hash],
            status=entry.status,
        )
        edges.append(
            ApplicationReviewGraphEdge(
                source=f"review:{review.id}",
                target=entry_node_id,
                relationship="contains_evidence",
                evidence_hashes=[entry.content_hash],
            )
        )
        for ref in entry.source_refs[:8]:
            ref_node_id = f"source:{_stable_ref_key(ref)}"
            if ref_node_id not in nodes:
                nodes[ref_node_id] = ApplicationReviewGraphNode(
                    id=ref_node_id,
                    label=_source_ref_label(ref),
                    node_type="source_ref",
                    evidence_hashes=[entry.content_hash],
                )
            elif entry.content_hash not in nodes[ref_node_id].evidence_hashes:
                nodes[ref_node_id].evidence_hashes.append(entry.content_hash)
            edges.append(
                ApplicationReviewGraphEdge(
                    source=entry_node_id,
                    target=ref_node_id,
                    relationship="supported_by_source_ref",
                    evidence_hashes=[entry.content_hash],
                )
            )
    missing_context = missing_evidence[:10]
    if not entries:
        missing_context = _dedupe_strings(
            [*missing_context, "No graph slice can be built until review evidence is indexed."]
        )
    return ApplicationReviewGraphSlice(
        nodes=list(nodes.values()),
        edges=edges,
        missing_context=missing_context,
    )


def _build_artifact_fix_plan(
    review,
    entries: list[ApplicationReviewContextEntryResponse],
    missing_evidence: list[str],
) -> list[ApplicationReviewArtifactFixPlanStep]:
    steps: list[ApplicationReviewArtifactFixPlanStep] = []
    scanner_findings = [entry for entry in entries if entry.item_type == "scanner_finding"]
    stale_entries = [entry for entry in entries if entry.status == "stale"]
    decision = getattr(review, "decision", None)
    if decision in {"block", "fix", "verify"} and scanner_findings:
        primary = scanner_findings[0]
        steps.append(
            ApplicationReviewArtifactFixPlanStep(
                title="Resolve cited scanner finding",
                action=(
                    "Patch the affected code or configuration shown in the evidence chain, "
                    "or attach proof that the scanner signal is not exploitable in this app."
                ),
                verification="Rerun the review and confirm the deterministic decision no longer depends on this finding.",
                cited_content_hashes=[primary.content_hash],
                source_refs=primary.source_refs,
            )
        )
    if stale_entries:
        primary = stale_entries[0]
        steps.append(
            ApplicationReviewArtifactFixPlanStep(
                title="Refresh stale evidence",
                action="Rebuild the context index or rerun the source scanner so stale evidence is replaced.",
                verification="Confirm the artifact no longer marks the cited evidence chain as stale.",
                cited_content_hashes=[primary.content_hash],
                source_refs=primary.source_refs,
            )
        )
    if missing_evidence:
        cited_hashes = [entry.content_hash for entry in entries[:3]]
        steps.append(
            ApplicationReviewArtifactFixPlanStep(
                title="Attach missing review evidence",
                action="Add the missing code, cloud, scanner, policy, or architecture evidence listed in this artifact.",
                verification="Rebuild context and rerun the decision so the missing-evidence section shrinks or clears.",
                cited_content_hashes=cited_hashes,
                source_refs=[],
            )
        )
    if not steps and entries:
        primary = entries[0]
        steps.append(
            ApplicationReviewArtifactFixPlanStep(
                title="Keep evidence current",
                action="No immediate blocker is visible from indexed evidence. Keep source refs current before relying on the report.",
                verification="Rerun the review after material code, cloud, or policy changes.",
                cited_content_hashes=[primary.content_hash],
                source_refs=primary.source_refs,
            )
        )
    return steps


def _build_rerun_history(review, decision_record: dict | None) -> list[ApplicationReviewRerunHistoryEntry]:
    snapshot = None
    if isinstance(decision_record, dict):
        value = decision_record.get("evidence_snapshot_hash")
        snapshot = value if isinstance(value, str) else None
    return [
        ApplicationReviewRerunHistoryEntry(
            review_id=review.id,
            parent_review_id=review.parent_review_id,
            status=review.status,
            decision=review.decision,
            commit_sha=review.commit_sha,
            evidence_snapshot_hash=snapshot,
            updated_at=review.updated_at,
        )
    ]


def _source_ref_label(ref: dict) -> str:
    ref_type = str(ref.get("type") or "source")
    for key in ("path", "key", "id", "name", "url"):
        value = ref.get(key)
        if isinstance(value, str) and value:
            return f"{ref_type}: {value}"
    return ref_type


def _stable_ref_key(ref: dict) -> str:
    label = _source_ref_label(ref).casefold()
    return re.sub(r"[^a-z0-9_.:-]+", "-", label).strip("-")[:120] or "source"


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _redacted_context_entry(entry) -> ApplicationReviewContextEntryResponse:
    response = ApplicationReviewContextEntryResponse.model_validate(entry)
    data = response.model_dump()
    for key in ("body", "retrieval_text"):
        data[key] = _redact_sensitive_text(str(data.get(key) or ""))
    data["facets"] = _redact_sensitive_value(data.get("facets") or {})
    data["source_refs"] = _redact_sensitive_value(data.get("source_refs") or [])
    return ApplicationReviewContextEntryResponse.model_validate(data)


def _redact_sensitive_value(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            if any(token in key_text.casefold() for token in SENSITIVE_EVIDENCE_KEYS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive_value(item)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_value(item) for item in value]
    if isinstance(value, str):
        return _redact_sensitive_text(value)
    return value


def _redact_sensitive_text(value: str) -> str:
    redacted = value
    for token in SENSITIVE_EVIDENCE_KEYS:
        redacted = re.sub(
            rf"(?i)({re.escape(token)}\s*[:=]\s*)([^\s,;]+)",
            r"\1[REDACTED]",
            redacted,
        )
    return redacted


@router.post(
    "/{review_id}/context-index/rebuild",
    response_model=RebuildReviewContextIndexResponse,
)
async def rebuild_context_index(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RebuildReviewContextIndexResponse:
    try:
        entries = await rebuild_review_context_index(
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
    return RebuildReviewContextIndexResponse(review_id=review_id, entry_count=len(entries))


@router.get(
    "/{review_id}/context-index/search",
    response_model=ReviewContextSearchResponse,
)
async def search_context_index(
    review_id: UUID,
    q: str = Query(default="", max_length=500),
    mode: str = Query(default="keyword", pattern="^(keyword|structured|vector|graph_neighborhood|hybrid)$"),
    item_type: list[str] | None = Query(default=None),
    source_type: list[str] | None = Query(default=None),
    include_stale: bool = Query(default=False),
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReviewContextSearchResponse:
    try:
        entries = await search_review_context_index(
            db,
            current_user=current_user,
            review_id=review_id,
            query=q,
            limit=limit,
            mode=mode,  # type: ignore[arg-type]
            item_types=set(item_type) if item_type else None,
            source_types=set(source_type) if source_type else None,
            include_stale=include_stale,
        )
    except ApplicationReviewContextError as exc:
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)
    return ReviewContextSearchResponse(
        review_id=review_id,
        query=q,
        mode=mode,
        fallback_reason="vector retrieval uses keyword fallback until pgvector entries are available"
        if mode == "vector"
        else None,
        results=[ApplicationReviewContextEntryResponse.model_validate(entry) for entry in entries],
    )


@router.get("/{review_id}/context-packet", response_model=ReviewContextPacket)
async def get_context_packet(
    review_id: UUID,
    q: str = Query(default="", max_length=500),
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReviewContextPacket:
    try:
        return await build_review_context_packet(
            db,
            current_user=current_user,
            review_id=review_id,
            query=q,
            limit=limit,
        )
    except ApplicationReviewContextError as exc:
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)


@router.get("/{review_id}/ai-explanation", response_model=GroundedAIExplanationResponse)
async def get_ai_explanation(
    review_id: UUID,
    q: str = Query(default="", max_length=500),
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GroundedAIExplanationResponse:
    try:
        return await build_grounded_ai_explanation(
            db,
            current_user=current_user,
            review_id=review_id,
            query=q,
            limit=limit,
        )
    except ApplicationReviewContextError as exc:
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=404, detail=message)
        raise HTTPException(status_code=422, detail=message)


@router.post(
    "/{review_id}/decision/evaluate",
    response_model=ApplicationReviewDecisionResponse,
)
async def evaluate_review_decision(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationReviewDecisionResponse:
    try:
        response = await evaluate_application_review_decision(
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
    return response
