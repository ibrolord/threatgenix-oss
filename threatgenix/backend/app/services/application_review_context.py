"""Build and query a tenant-scoped application review retrieval index."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal, Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.application_risk_acceptance import ApplicationRiskAcceptance
from app.models.evidence import EvidenceEntity, EvidenceFinding, EvidenceItem, EvidenceRelationship
from app.models.scan import ScanFinding, ScanJob
from app.models.threat import Threat
from app.models.user import User
from app.services.application_review import (
    get_application_review,
    tenant_key_for_user,
    transition_application_review_status,
)
from app.services.application_review_bundles import canonical_json, list_review_bundles
from app.services.application_risk_acceptance import list_application_risk_acceptances

MAX_CONTEXT_RESULTS = 20
ContextRetrievalMode = Literal["keyword", "structured", "vector", "graph_neighborhood", "hybrid"]
ACTIVE_STATUSES = {"active"}
VISIBLE_STATUSES = {"active", "stale"}
ALL_STATUSES = {"active", "stale", "deleted"}


class ApplicationReviewContextError(ValueError):
    """Raised when a review context index operation cannot be completed."""


async def rebuild_review_context_index(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
) -> list[ApplicationReviewContextEntry]:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise ApplicationReviewContextError("Review was not found for this tenant.")
    if review.status in {"created", "intake_required", "bundle_required", "bundle_received", "scanning"}:
        transition_application_review_status(review, "indexing")

    existing = await _list_active_entries(db, tenant_key=tenant_key, review_id=review_id)
    for entry in existing:
        entry.status = "stale"
        entry.stale_reason = "superseded_by_rebuild"

    entries: list[ApplicationReviewContextEntry] = []
    entries.append(
        _entry(
            tenant_key=tenant_key,
            review_id=review.id,
            owner_id=current_user.id,
            organization_id=getattr(current_user, "organization_id", None),
            source_type="review",
            source_object_id=review.id,
            item_type="app_profile",
            title=f"{review.app_name} application review",
            body=_review_body(review),
            source_refs=[{"type": "review", "id": str(review.id)}],
            facets=_review_facets(review),
        )
    )
    entries.append(
        _entry(
            tenant_key=tenant_key,
            review_id=review.id,
            owner_id=current_user.id,
            organization_id=getattr(current_user, "organization_id", None),
            source_type="review",
            source_object_id=review.id,
            item_type="review_scope",
            title=f"{review.app_name} review scope",
            body=_json_body("scope", review.scope or {}),
            source_refs=[{"type": "review", "id": str(review.id), "field": "scope"}],
            facets={"category": "review_scope", "input_kind": review.input_kind},
        )
    )
    if getattr(current_user, "organization_id", None) is not None or _context_section(review, "org_profile"):
        entries.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=current_user.id,
                organization_id=getattr(current_user, "organization_id", None),
                source_type="organization",
                source_object_id=getattr(current_user, "organization_id", None),
                item_type="org_profile",
                title="Organization security profile",
                body=_json_body("org_profile", _context_section(review, "org_profile")),
                source_refs=[{"type": "review", "id": str(review.id), "field": "context.org_profile"}],
                facets={"category": "org_profile"},
            )
        )
    if review.policy:
        entries.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=current_user.id,
                organization_id=getattr(current_user, "organization_id", None),
                source_type="policy",
                source_object_id=review.id,
                item_type="policy",
                title=f"{review.app_name} review policy",
                body=_json_body("policy", review.policy),
                source_refs=[{"type": "review", "id": str(review.id), "field": "policy"}],
                facets={"category": "policy", "block_on_high": bool(review.policy.get("block_on_high"))},
            )
        )
    entries.extend(
        _context_collection_entries(
            current_user=current_user,
            review=review,
            section="controls",
            source_type="policy",
            item_type="control",
            title_prefix="Control",
        )
    )
    entries.extend(
        _context_collection_entries(
            current_user=current_user,
            review=review,
            section="docs",
            source_type="document",
            item_type="doc",
            title_prefix="Document",
        )
    )
    entries.extend(
        _context_collection_entries(
            current_user=current_user,
            review=review,
            section="code_summaries",
            source_type="code_summary",
            item_type="code_summary",
            title_prefix="Code summary",
        )
    )
    entries.extend(
        _context_collection_entries(
            current_user=current_user,
            review=review,
            section="code_context",
            source_type="code_context",
            item_type="code_context",
            title_prefix="Code context",
        )
    )
    entries.extend(
        _context_collection_entries(
            current_user=current_user,
            review=review,
            section="accepted_risks",
            source_type="manual",
            item_type="accepted_risk",
            title_prefix="Accepted risk",
        )
    )
    for acceptance in await list_application_risk_acceptances(
        db,
        tenant_key=tenant_key,
        review_id=review_id,
    ):
        entries.append(
            _application_risk_acceptance_entry(
                current_user=current_user,
                review=review,
                acceptance=acceptance,
            )
        )

    bundles = await list_review_bundles(db, tenant_key=tenant_key, review_id=review_id)
    for bundle in bundles:
        for manifest_item in bundle.manifest or []:
            path = str(manifest_item.get("path", ""))
            body = (
                f"Bundle file {path} kind={manifest_item.get('file_kind')} "
                f"source={manifest_item.get('source')} sha256={manifest_item.get('sha256')}"
            )
            entries.append(
                _entry(
                    tenant_key=tenant_key,
                    review_id=review.id,
                    owner_id=current_user.id,
                    organization_id=getattr(current_user, "organization_id", None),
                    source_type="bundle",
                    source_object_id=bundle.id,
                    item_type="bundle_file",
                    title=path,
                    body=body,
                    source_refs=[
                        {"type": "bundle", "id": str(bundle.id)},
                        {"type": "path", "path": path},
                    ],
                    facets={
                        "category": "bundle_file",
                        "path": path,
                        "file_kind": manifest_item.get("file_kind"),
                        "source": manifest_item.get("source"),
                    },
                )
            )

    if review.threat_model_id is not None:
        findings = await _list_review_scan_findings(
            db,
            owner_id=current_user.id,
            threat_model_id=review.threat_model_id,
        )
        for finding in findings:
            entries.append(
                _entry(
                    tenant_key=tenant_key,
                    review_id=review.id,
                    owner_id=current_user.id,
                    organization_id=getattr(current_user, "organization_id", None),
                    source_type="scan_finding",
                    source_object_id=finding.id,
                    item_type="scanner_finding",
                    title=finding.template_name,
                    body=_finding_body(finding),
                    source_refs=_finding_source_refs(finding),
                    facets=_finding_facets(finding),
                )
            )
        for entry in await _evidence_graph_entries(
            db,
            current_user=current_user,
            review=review,
        ):
            entries.append(entry)
        for threat in await _list_accepted_risk_threats(
            db,
            threat_model_id=review.threat_model_id,
        ):
            entries.append(_accepted_risk_entry(current_user=current_user, review=review, threat=threat))

    for prior_review in await _list_prior_review_decisions(
        db,
        tenant_key=tenant_key,
        review=review,
    ):
        entries.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=current_user.id,
                organization_id=getattr(current_user, "organization_id", None),
                source_type="decision",
                source_object_id=prior_review.id,
                item_type="prior_review_decision",
                title=f"Prior decision for {prior_review.app_name}",
                body=_prior_decision_body(prior_review),
                source_refs=[{"type": "review", "id": str(prior_review.id)}],
                facets={
                    "category": "prior_decision",
                    "decision": prior_review.decision,
                    "commit_sha": prior_review.commit_sha,
                },
            )
        )

    for entry in entries:
        db.add(entry)
    await db.flush()
    return entries


async def search_review_context_index(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
    query: str,
    limit: int = MAX_CONTEXT_RESULTS,
    mode: ContextRetrievalMode = "keyword",
    item_types: set[str] | None = None,
    source_types: set[str] | None = None,
    statuses: set[str] | None = None,
    include_stale: bool = False,
    include_deleted: bool = False,
    graph_entity_id: UUID | None = None,
) -> list[ApplicationReviewContextEntry]:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise ApplicationReviewContextError("Review was not found for this tenant.")
    selected_statuses = _selected_statuses(
        statuses=statuses,
        include_stale=include_stale,
        include_deleted=include_deleted,
    )
    entries = await _list_entries(
        db,
        tenant_key=tenant_key,
        review_id=review_id,
        statuses=selected_statuses,
    )
    entries = [entry for entry in entries if entry.status in selected_statuses]
    entries = _filter_entries(
        entries,
        item_types=item_types,
        source_types=source_types,
        graph_entity_id=graph_entity_id if mode == "graph_neighborhood" else None,
    )
    if mode == "structured":
        return entries[:limit]
    if mode == "vector" and not await _vector_search_available(db):
        mode = "keyword"
    query_tokens = set(_tokenize(query))
    if not query_tokens:
        return entries[:limit]
    ranked = sorted(
        entries,
        key=lambda entry: (
            -_retrieval_score(query_tokens, entry),
            entry.item_type,
            entry.title,
        ),
    )
    return [entry for entry in ranked if _retrieval_score(query_tokens, entry) > 0][:limit]


async def _list_active_entries(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
) -> list[ApplicationReviewContextEntry]:
    result = await db.execute(
        select(ApplicationReviewContextEntry)
        .where(
            ApplicationReviewContextEntry.tenant_key == tenant_key,
            ApplicationReviewContextEntry.review_id == review_id,
            ApplicationReviewContextEntry.status == "active",
        )
        .order_by(ApplicationReviewContextEntry.created_at.desc())
    )
    return list(result.scalars().all())


async def _list_entries(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
    statuses: set[str],
) -> list[ApplicationReviewContextEntry]:
    result = await db.execute(
        select(ApplicationReviewContextEntry)
        .where(
            ApplicationReviewContextEntry.tenant_key == tenant_key,
            ApplicationReviewContextEntry.review_id == review_id,
            ApplicationReviewContextEntry.status.in_(statuses),
        )
        .order_by(ApplicationReviewContextEntry.status.asc(), ApplicationReviewContextEntry.created_at.desc())
    )
    return list(result.scalars().all())


async def _list_review_scan_findings(
    db: AsyncSession,
    *,
    owner_id: UUID,
    threat_model_id: UUID,
) -> list[ScanFinding]:
    result = await db.execute(
        select(ScanFinding)
        .join(ScanJob, ScanFinding.scan_job_id == ScanJob.id)
        .where(
            ScanJob.owner_id == owner_id,
            ScanJob.threat_model_id == threat_model_id,
        )
    )
    return list(result.scalars().all())


async def _list_prior_review_decisions(
    db: AsyncSession,
    *,
    tenant_key: str,
    review: ApplicationSecurityReview,
) -> list[ApplicationSecurityReview]:
    result = await db.execute(
        select(ApplicationSecurityReview)
        .where(
            ApplicationSecurityReview.tenant_key == tenant_key,
            ApplicationSecurityReview.review_lineage_id == review.review_lineage_id,
            ApplicationSecurityReview.id != review.id,
            ApplicationSecurityReview.decision.is_not(None),
        )
        .order_by(ApplicationSecurityReview.created_at.desc())
        .limit(5)
    )
    return list(result.scalars().all())


async def _list_accepted_risk_threats(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
) -> list[Threat]:
    result = await db.execute(
        select(Threat)
        .where(
            Threat.threat_model_id == threat_model_id,
            (Threat.status == "Accepted") | (Threat.false_positive_reason == "accepted_risk"),
        )
        .limit(20)
    )
    return list(result.scalars().all())


async def _evidence_graph_entries(
    db: AsyncSession,
    *,
    current_user: User,
    review: ApplicationSecurityReview,
) -> list[ApplicationReviewContextEntry]:
    if review.threat_model_id is None:
        return []
    rows: list[ApplicationReviewContextEntry] = []
    owner_id = current_user.id
    organization_id = getattr(current_user, "organization_id", None)
    tenant_key = tenant_key_for_user(current_user)
    result = await db.execute(
        select(EvidenceItem)
        .where(
            EvidenceItem.threat_model_id == review.threat_model_id,
            EvidenceItem.freshness_status != "deleted",
        )
        .limit(30)
    )
    for item in result.scalars().all():
        rows.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=owner_id,
                organization_id=organization_id,
                source_type="evidence_item",
                source_object_id=item.id,
                item_type="evidence_item",
                title=item.title,
                body=_evidence_item_body(item),
                source_refs=[{"type": "evidence_item", "id": str(item.id)}],
                facets={
                    "category": "evidence_item",
                    "item_type": item.item_type,
                    "freshness_status": item.freshness_status,
                    "source_id": str(item.source_id),
                },
                status=_entry_status_from_freshness(item.freshness_status),
                stale_reason=_stale_reason_from_freshness(item.freshness_status),
            )
        )
    result = await db.execute(
        select(EvidenceEntity)
        .where(
            EvidenceEntity.threat_model_id == review.threat_model_id,
            EvidenceEntity.status == "active",
        )
        .limit(50)
    )
    for entity in result.scalars().all():
        rows.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=owner_id,
                organization_id=organization_id,
                source_type="evidence_entity",
                source_object_id=entity.id,
                item_type="evidence_entity",
                title=entity.display_name,
                body=_json_body(
                    "evidence_entity",
                    {
                        "entity_type": entity.entity_type,
                        "canonical_key": entity.canonical_key,
                        "properties": entity.properties or {},
                    },
                ),
                source_refs=[{"type": "evidence_entity", "id": str(entity.id)}],
                facets={
                    "category": "evidence_entity",
                    "entity_id": str(entity.id),
                    "entity_type": entity.entity_type,
                    "canonical_key": entity.canonical_key,
                },
            )
        )
    result = await db.execute(
        select(EvidenceRelationship)
        .where(EvidenceRelationship.threat_model_id == review.threat_model_id)
        .limit(50)
    )
    for relationship in result.scalars().all():
        rows.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=owner_id,
                organization_id=organization_id,
                source_type="evidence_relationship",
                source_object_id=relationship.id,
                item_type="evidence_relationship",
                title=f"Evidence relationship {relationship.relationship_type}",
                body=_json_body(
                    "evidence_relationship",
                    {
                        "relationship_type": relationship.relationship_type,
                        "rationale": relationship.rationale,
                        "properties": relationship.properties or {},
                    },
                ),
                source_refs=[
                    {"type": "evidence_relationship", "id": str(relationship.id)},
                    {"type": "evidence_entity", "id": str(relationship.from_entity_id), "role": "from"},
                    {"type": "evidence_entity", "id": str(relationship.to_entity_id), "role": "to"},
                ],
                facets={
                    "category": "evidence_relationship",
                    "relationship_type": relationship.relationship_type,
                    "from_entity_id": str(relationship.from_entity_id),
                    "to_entity_id": str(relationship.to_entity_id),
                },
            )
        )
    result = await db.execute(
        select(EvidenceFinding)
        .where(EvidenceFinding.threat_model_id == review.threat_model_id)
        .limit(50)
    )
    for finding in result.scalars().all():
        rows.append(
            _entry(
                tenant_key=tenant_key,
                review_id=review.id,
                owner_id=owner_id,
                organization_id=organization_id,
                source_type="evidence_finding",
                source_object_id=finding.id,
                item_type="accepted_risk" if finding.status == "accepted" else "evidence_finding",
                title=finding.title,
                body=_evidence_finding_body(finding),
                source_refs=[{"type": "evidence_finding", "id": str(finding.id)}],
                facets={
                    "category": "evidence_finding",
                    "finding_kind": finding.finding_kind,
                    "severity": finding.severity,
                    "status": finding.status,
                    "freshness_status": finding.freshness_status,
                },
                status=_entry_status_from_freshness(finding.freshness_status),
                stale_reason=_stale_reason_from_freshness(finding.freshness_status),
            )
        )
    return rows


def _entry(
    *,
    tenant_key: str,
    review_id: UUID,
    owner_id: UUID,
    organization_id: UUID | None,
    source_type: str,
    source_object_id: UUID | None,
    item_type: str,
    title: str,
    body: str,
    source_refs: list[dict],
    facets: dict | None = None,
    status: str = "active",
    stale_reason: str | None = None,
) -> ApplicationReviewContextEntry:
    if not source_refs:
        raise ApplicationReviewContextError("Context index entries require source references.")
    facets = facets or {}
    retrieval_text = f"{title}\n{body}\n{canonical_json(source_refs)}\n{canonical_json(facets)}"
    keywords = sorted(set(_tokenize(retrieval_text)))
    content_hash = hashlib.sha256(
        canonical_json(
            {
                "source_type": source_type,
                "source_object_id": str(source_object_id) if source_object_id else None,
                "item_type": item_type,
                "title": title,
                "body": body,
                "source_refs": source_refs,
                "facets": facets,
            }
        ).encode("utf-8")
    ).hexdigest()
    return ApplicationReviewContextEntry(
        tenant_key=tenant_key,
        review_id=review_id,
        owner_id=owner_id,
        organization_id=organization_id,
        source_type=source_type,
        source_object_id=source_object_id,
        item_type=item_type,
        title=title,
        body=body,
        keywords=keywords,
        facets=facets,
        retrieval_text=retrieval_text,
        source_refs=source_refs,
        content_hash=content_hash,
        status=status,
        stale_reason=stale_reason,
    )


def _review_body(review) -> str:
    context = review.context or {}
    intake = context.get("intake") if isinstance(context, dict) else None
    return " ".join(
        [
            f"app_name={review.app_name}",
            f"surface={review.invocation_surface}",
            f"input_kind={review.input_kind}",
            f"status={review.status}",
            f"requested_tools={', '.join(review.requested_tools or [])}",
            f"scope={json.dumps(review.scope or {}, sort_keys=True)}",
            f"policy={json.dumps(review.policy or {}, sort_keys=True)}",
            f"intake={json.dumps(intake or {}, sort_keys=True)}",
        ]
    )


def _review_facets(review: ApplicationSecurityReview) -> dict:
    return {
        "category": "app_profile",
        "app_name": review.app_name,
        "invocation_surface": review.invocation_surface,
        "input_kind": review.input_kind,
        "status": review.status,
        "commit_sha": review.commit_sha,
        "requested_tools": review.requested_tools or [],
    }


def _context_section(review: ApplicationSecurityReview, section: str) -> Any:
    context = review.context or {}
    if isinstance(context, dict):
        return context.get(section)
    return None


def _json_body(label: str, payload: Any) -> str:
    return f"{label}={json.dumps(payload or {}, sort_keys=True, default=str)}"


def _context_collection_entries(
    *,
    current_user: User,
    review: ApplicationSecurityReview,
    section: str,
    source_type: str,
    item_type: str,
    title_prefix: str,
) -> list[ApplicationReviewContextEntry]:
    values = _context_section(review, section)
    if not isinstance(values, list):
        return []
    entries = []
    for index, value in enumerate(values):
        title = _title_from_context_value(value, title_prefix, index)
        source_refs = [
            {
                "type": "review",
                "id": str(review.id),
                "field": f"context.{section}[{index}]",
            }
        ]
        source_refs.extend(_source_refs_from_context_value(value))
        facets = {"category": item_type, "section": section, "index": index}
        facets.update(_facets_from_context_value(value))
        entries.append(
            _entry(
                tenant_key=tenant_key_for_user(current_user),
                review_id=review.id,
                owner_id=current_user.id,
                organization_id=getattr(current_user, "organization_id", None),
                source_type=source_type,
                source_object_id=review.id,
                item_type=item_type,
                title=title,
                body=_json_body(section, value),
                source_refs=source_refs,
                facets=facets,
            )
        )
    return entries


def _source_refs_from_context_value(value: Any) -> list[Any]:
    if not isinstance(value, dict):
        return []
    source_refs = value.get("source_refs")
    if isinstance(source_refs, list):
        return source_refs
    return []


def _facets_from_context_value(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    facets = value.get("facets")
    if not isinstance(facets, dict):
        return {}
    return facets


def _title_from_context_value(value: Any, title_prefix: str, index: int) -> str:
    if isinstance(value, dict):
        for key in ("title", "name", "id", "path"):
            if value.get(key):
                return str(value[key])
    if isinstance(value, str) and value.strip():
        return value.strip()[:500]
    return f"{title_prefix} {index + 1}"


def _finding_body(finding: ScanFinding) -> str:
    harness = {}
    raw_output = finding.raw_output or {}
    if isinstance(raw_output, dict) and isinstance(raw_output.get("threatgenix_harness"), dict):
        harness = raw_output["threatgenix_harness"]
    return " ".join(
        [
            f"scanner_finding={finding.template_name}",
            f"rule={finding.template_id}",
            f"severity={finding.severity}",
            f"matched_at={finding.matched_at}",
            f"tags={', '.join(finding.tags or [])}",
            f"confidence={harness.get('confidence', '')}",
            f"source_type={harness.get('source_type', '')}",
            f"evidence_sha256={finding.extracted_results or ''}",
        ]
    )


def _finding_facets(finding: ScanFinding) -> dict:
    raw_output = finding.raw_output or {}
    harness = raw_output.get("threatgenix_harness") if isinstance(raw_output, dict) else {}
    return {
        "category": "scanner_finding",
        "severity": finding.severity,
        "template_id": finding.template_id,
        "matched_at": finding.matched_at,
        "tags": finding.tags or [],
        "source_type": harness.get("source_type") if isinstance(harness, dict) else None,
        "finding_key": harness.get("finding_key") if isinstance(harness, dict) else None,
    }


def _finding_source_refs(finding: ScanFinding) -> list[dict]:
    refs: list[dict] = [
        {"type": "scan_finding", "id": str(finding.id)},
        {"type": "scan_job", "id": str(finding.scan_job_id)},
        {"type": "path", "path": finding.matched_at},
    ]
    raw_output = finding.raw_output or {}
    harness = raw_output.get("threatgenix_harness") if isinstance(raw_output, dict) else None
    if isinstance(harness, dict):
        if harness.get("bundle_id"):
            refs.append({"type": "bundle", "id": str(harness["bundle_id"])})
        if harness.get("finding_key"):
            refs.append({"type": "finding_key", "key": str(harness["finding_key"])})
    return refs


def _accepted_risk_entry(
    *,
    current_user: User,
    review: ApplicationSecurityReview,
    threat: Threat,
) -> ApplicationReviewContextEntry:
    return _entry(
        tenant_key=tenant_key_for_user(current_user),
        review_id=review.id,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        source_type="threat",
        source_object_id=threat.id,
        item_type="accepted_risk",
        title=f"Accepted risk {threat.display_id}",
        body=_json_body(
            "accepted_risk",
            {
                "display_id": threat.display_id,
                "severity": threat.severity,
                "stride_category": threat.stride_category,
                "description": threat.description,
                "qualification_note": threat.qualification_note,
                "false_positive_reason": threat.false_positive_reason,
            },
        ),
        source_refs=[{"type": "threat", "id": str(threat.id), "display_id": threat.display_id}],
        facets={
            "category": "accepted_risk",
            "severity": threat.severity,
            "stride_category": threat.stride_category,
        },
    )


def _application_risk_acceptance_entry(
    *,
    current_user: User,
    review: ApplicationSecurityReview,
    acceptance: ApplicationRiskAcceptance,
) -> ApplicationReviewContextEntry:
    return _entry(
        tenant_key=tenant_key_for_user(current_user),
        review_id=review.id,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        source_type="manual",
        source_object_id=acceptance.id,
        item_type="accepted_risk",
        title=f"Risk acceptance {acceptance.scope_type}:{acceptance.scope_value}",
        body=_json_body(
            "risk_acceptance",
            {
                "status": acceptance.status,
                "app_name": acceptance.app_name,
                "finding_stable_id": acceptance.finding_stable_id,
                "scope_type": acceptance.scope_type,
                "scope_value": acceptance.scope_value,
                "justification": acceptance.justification,
                "compensating_control": acceptance.compensating_control,
                "approved_at": acceptance.approved_at.isoformat(),
                "expires_at": acceptance.expires_at.isoformat(),
                "revoked_at": acceptance.revoked_at.isoformat() if acceptance.revoked_at else None,
            },
        ),
        source_refs=[
            {"type": "risk_acceptance", "id": str(acceptance.id)},
            {"type": "review", "id": str(review.id)},
        ],
        facets={
            "category": "accepted_risk",
            "acceptance_state": acceptance.status,
            "app_name": acceptance.app_name,
            "finding_stable_id": acceptance.finding_stable_id,
            "scope_type": acceptance.scope_type,
            "scope_value": acceptance.scope_value,
            "expires_at": acceptance.expires_at.isoformat(),
            "compensating_control_present": bool(acceptance.compensating_control),
        },
    )


def _prior_decision_body(review: ApplicationSecurityReview) -> str:
    return " ".join(
        [
            f"decision={review.decision}",
            f"status={review.status}",
            f"commit_sha={review.commit_sha}",
            f"summary={review.result_summary or ''}",
        ]
    )


def _evidence_item_body(item: EvidenceItem) -> str:
    return _json_body(
        "evidence_item",
        {
            "item_type": item.item_type,
            "title": item.title,
            "summary": item.summary,
            "raw_ref": item.raw_ref,
            "freshness_status": item.freshness_status,
            "confidence_label": item.confidence_label,
            "content_sha256": item.content_sha256,
        },
    )


def _evidence_finding_body(finding: EvidenceFinding) -> str:
    return _json_body(
        "evidence_finding",
        {
            "finding_kind": finding.finding_kind,
            "description": finding.description,
            "severity": finding.severity,
            "status": finding.status,
            "freshness_status": finding.freshness_status,
            "confidence_label": finding.confidence_label,
            "source_system": finding.source_system,
        },
    )


def _entry_status_from_freshness(freshness_status: str | None) -> str:
    if freshness_status in {"stale", "expired"}:
        return "stale"
    if freshness_status == "deleted":
        return "deleted"
    return "active"


def _stale_reason_from_freshness(freshness_status: str | None) -> str | None:
    if freshness_status in {"stale", "expired", "deleted"}:
        return f"evidence_freshness_{freshness_status}"
    return None


def _selected_statuses(
    *,
    statuses: set[str] | None,
    include_stale: bool,
    include_deleted: bool,
) -> set[str]:
    selected = set(statuses or ACTIVE_STATUSES)
    if include_stale:
        selected |= VISIBLE_STATUSES
    if include_deleted:
        selected |= ALL_STATUSES
    return selected & ALL_STATUSES


def _filter_entries(
    entries: list[ApplicationReviewContextEntry],
    *,
    item_types: set[str] | None,
    source_types: set[str] | None,
    graph_entity_id: UUID | None,
) -> list[ApplicationReviewContextEntry]:
    filtered = entries
    if item_types:
        filtered = [entry for entry in filtered if entry.item_type in item_types]
    if source_types:
        filtered = [entry for entry in filtered if entry.source_type in source_types]
    if graph_entity_id is not None:
        entity_id = str(graph_entity_id)
        filtered = [
            entry
            for entry in filtered
            if _entry_references_graph_entity(entry, entity_id)
        ]
    return filtered


def _entry_references_graph_entity(entry: ApplicationReviewContextEntry, entity_id: str) -> bool:
    facets = entry.facets or {}
    if entity_id in {
        str(facets.get("entity_id")),
        str(facets.get("from_entity_id")),
        str(facets.get("to_entity_id")),
    }:
        return True
    for ref in entry.source_refs or []:
        if ref.get("type") == "evidence_entity" and str(ref.get("id")) == entity_id:
            return True
    return False


def _tokenize(value: str) -> list[str]:
    return [
        token
        for token in re.findall(r"[a-z0-9_./:-]+", value.casefold())
        if len(token) > 1
    ]


def _keyword_score(query_tokens: set[str], entry: ApplicationReviewContextEntry) -> int:
    keywords = {str(keyword) for keyword in entry.keywords or []}
    return len(query_tokens & keywords)


def _retrieval_score(query_tokens: set[str], entry: ApplicationReviewContextEntry) -> int:
    keyword_score = _keyword_score(query_tokens, entry)
    title_score = len(query_tokens & set(_tokenize(entry.title))) * 2
    body_score = len(query_tokens & set(_tokenize(entry.retrieval_text or entry.body)))
    return keyword_score + title_score + body_score


async def _vector_search_available(db: AsyncSession) -> bool:
    del db
    return False
