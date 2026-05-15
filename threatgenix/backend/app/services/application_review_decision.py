"""Deterministic decision integration for invoke-anywhere application reviews."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.user import User
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.services.application_review import (
    get_application_review,
    tenant_key_for_user,
    transition_application_review_status,
)
from app.services.application_review_bundles import canonical_json
from app.services.application_review_context import (
    ApplicationReviewContextError,
    search_review_context_index,
)
from app.services.application_risk_acceptance import risk_acceptance_matches_entry

DETERMINISTIC_DECISION_ENGINE_VERSION = "appsec-decision-v1.0.0"
DECISION_REPLAY_CONTEXT_KEY = "deterministic_decision_replay"


async def evaluate_application_review_decision(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
) -> ApplicationReviewDecisionResponse:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise ApplicationReviewContextError("Review was not found for this tenant.")
    entries = await search_review_context_index(
        db,
        current_user=current_user,
        review_id=review_id,
        query="",
        limit=50,
    )
    snapshot = build_decision_evidence_snapshot(entries)
    existing_replay = _stored_replay(review.context)
    if (
        existing_replay
        and existing_replay.get("decision_engine_version") == DETERMINISTIC_DECISION_ENGINE_VERSION
        and existing_replay.get("evidence_snapshot_hash") == snapshot["hash"]
    ):
        if review.status == "completed":
            from app.services.github_pr_integration import enqueue_github_pr_review_dispatch

            await enqueue_github_pr_review_dispatch(db=db, review=review)
        return _decision_from_replay(review.id, existing_replay)

    decision = _decide(
        review_id=review.id,
        app_name=review.app_name,
        entries=entries,
        policy=review.policy or {},
        evidence_snapshot_hash=str(snapshot["hash"]),
    )
    review.context = {
        **(review.context or {}),
        DECISION_REPLAY_CONTEXT_KEY: _decision_replay_payload(decision, snapshot),
    }
    review.decision = decision.decision
    if review.status not in {"completed", "deciding"}:
        if review.status != "indexing":
            transition_application_review_status(review, "indexing")
        transition_application_review_status(review, "deciding")
    if review.status == "deciding":
        transition_application_review_status(review, "completed", result_summary=decision.reason)
    else:
        review.result_summary = decision.reason
    if review.status == "completed":
        from app.services.github_pr_integration import enqueue_github_pr_review_dispatch

        await enqueue_github_pr_review_dispatch(db=db, review=review)
    await db.flush()
    return decision


def evaluate_application_review_decision_entries(
    *,
    review_id: UUID,
    entries: list[ApplicationReviewContextEntry],
    policy: dict | None = None,
) -> ApplicationReviewDecisionResponse:
    active_entries = [entry for entry in entries if entry.status == "active"]
    snapshot = build_decision_evidence_snapshot(active_entries)
    return _decide(
        review_id=review_id,
        app_name="",
        entries=active_entries,
        policy=policy or {},
        evidence_snapshot_hash=str(snapshot["hash"]),
    )


def build_decision_evidence_snapshot(entries: list[ApplicationReviewContextEntry]) -> dict[str, Any]:
    normalized_entries = [
        {
            "content_hash": entry.content_hash,
            "facets": entry.facets or {},
            "item_type": entry.item_type,
            "source_refs": entry.source_refs or [],
            "source_type": entry.source_type,
            "status": entry.status,
            "title": entry.title,
        }
        for entry in sorted(
            entries,
            key=lambda entry: (
                entry.item_type,
                entry.source_type,
                entry.content_hash,
                entry.title,
            ),
        )
    ]
    payload = {
        "version": DETERMINISTIC_DECISION_ENGINE_VERSION,
        "entries": normalized_entries,
    }
    return {
        "hash": hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        "entries": normalized_entries,
    }


def _decide(
    *,
    review_id: UUID,
    app_name: str,
    entries: list[ApplicationReviewContextEntry],
    policy: dict,
    evidence_snapshot_hash: str,
) -> ApplicationReviewDecisionResponse:
    if not entries:
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="gather_evidence",
            reason="No active security context evidence is available.",
            evidence_hashes=[],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=["no_active_context_entries"],
        )

    scanner_findings = [
        entry
        for entry in entries
        if entry.item_type == "scanner_finding" and not _is_untrusted_scanner_finding(entry)
    ]
    rejected_scanner_findings = [
        entry for entry in entries if entry.item_type == "scanner_finding" and entry not in scanner_findings
    ]
    high_scanner_findings = [
        entry for entry in scanner_findings if _entry_mentions_high_or_critical(entry)
    ]
    non_scanner_support = [
        entry for entry in entries if entry.item_type != "scanner_finding"
    ]
    evidence_hashes = [entry.content_hash for entry in high_scanner_findings[:10]]
    scanner_only = bool(high_scanner_findings) and not non_scanner_support
    trace = _decision_trace(
        entries=entries,
        scanner_findings=scanner_findings,
        high_scanner_findings=high_scanner_findings,
        scanner_only=scanner_only,
        policy=policy,
        rejected_scanner_findings=rejected_scanner_findings,
    )

    if rejected_scanner_findings and not scanner_findings:
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="verify",
            reason="Scanner evidence was rejected or downgraded because provenance was untrusted.",
            evidence_hashes=[entry.content_hash for entry in rejected_scanner_findings[:10]],
            scanner_only=True,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "untrusted_scanner_evidence_requires_verification"],
        )

    if _has_conflicting_evidence_signal(entries):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="verify",
            reason="Indexed evidence contains conflicting claims that require human verification.",
            evidence_hashes=[entry.content_hash for entry in entries[:10]],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "conflicting_evidence_requires_verification"],
        )

    if _has_public_admin_iac_signal(entries):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="block",
            reason="Infrastructure evidence exposes an administrative service publicly.",
            evidence_hashes=[entry.content_hash for entry in entries[:10]],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "public_admin_iac_blocks_release"],
        )

    if _has_webhook_signature_gap(entries):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="fix",
            reason="Webhook route evidence does not show signature verification.",
            evidence_hashes=[entry.content_hash for entry in entries[:10]],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "webhook_signature_gap_requires_fix"],
        )

    if not scanner_findings and _has_material_sensitive_authz_signal(entries):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="verify",
            reason="Sensitive authorization risk exists, but scanner or exposure evidence is missing.",
            evidence_hashes=[entry.content_hash for entry in entries[:10]],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "sensitive_authz_gap_missing_scanner_or_exposure"],
        )

    if _has_unsupported_framework_signal(entries):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="gather_evidence",
            reason="Unsupported framework evidence prevents a high-confidence pass.",
            evidence_hashes=[entry.content_hash for entry in entries[:10]],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "unsupported_framework_requires_more_evidence"],
        )

    if _is_metadata_only_review(entries):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="gather_evidence",
            reason="Only metadata or intake evidence is available.",
            evidence_hashes=[entry.content_hash for entry in entries[:10]],
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "metadata_only_requires_more_evidence"],
        )

    if high_scanner_findings and scanner_only:
        if policy.get("block_on_high_scanner_only") is True:
            return ApplicationReviewDecisionResponse(
                review_id=review_id,
                decision="block",
                reason="Tenant policy allows high-severity scanner-only evidence to block.",
                evidence_hashes=evidence_hashes,
                scanner_only=True,
                evidence_snapshot_hash=evidence_snapshot_hash,
                decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
                decision_trace=[*trace, "policy:block_on_high_scanner_only"],
            )
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="verify",
            reason="High-severity scanner evidence exists, but no supporting context evidence was indexed.",
            evidence_hashes=evidence_hashes,
            scanner_only=True,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "scanner_only_high_requires_verification"],
        )

    if high_scanner_findings and _all_high_findings_have_active_risk_acceptance(
        entries=entries,
        high_scanner_findings=high_scanner_findings,
        app_name=app_name,
    ):
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="verify",
            reason="High-severity evidence is covered by active accepted risk scope and should be monitored.",
            evidence_hashes=evidence_hashes,
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "active_risk_acceptance_scope_matches_all_high_findings"],
        )

    if high_scanner_findings:
        decision = "block" if _has_material_sensitive_authz_signal(entries) else "fix"
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision=decision,
            reason="High-severity scanner evidence is supported by indexed application context.",
            evidence_hashes=evidence_hashes,
            scanner_only=False,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[
                *trace,
                "high_scanner_supported_by_context",
                f"material_sensitive_authz_signal:{decision == 'block'}",
            ],
        )

    if scanner_findings:
        return ApplicationReviewDecisionResponse(
            review_id=review_id,
            decision="fix",
            reason="Scanner findings exist but none are high-severity blockers.",
            evidence_hashes=[entry.content_hash for entry in scanner_findings[:10]],
            scanner_only=not non_scanner_support,
            evidence_snapshot_hash=evidence_snapshot_hash,
            decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
            decision_trace=[*trace, "non_high_scanner_findings_require_fix"],
        )

    return ApplicationReviewDecisionResponse(
        review_id=review_id,
        decision="pass",
        reason="No blocking scanner or context evidence was found.",
        evidence_hashes=[entry.content_hash for entry in entries[:10]],
        scanner_only=False,
        evidence_snapshot_hash=evidence_snapshot_hash,
        decision_engine_version=DETERMINISTIC_DECISION_ENGINE_VERSION,
        decision_trace=[*trace, "no_scanner_findings_pass"],
    )


def _entry_mentions_high_or_critical(entry: ApplicationReviewContextEntry) -> bool:
    text = _entry_text(entry)
    severity = str((entry.facets or {}).get("severity") or "").casefold()
    return severity in {"high", "critical"} or "severity=high" in text or "severity=critical" in text


def _is_untrusted_scanner_finding(entry: ApplicationReviewContextEntry) -> bool:
    facets = entry.facets or {}
    if facets.get("provenance_trusted") is False:
        return True
    if facets.get("scanner_provenance") in {"untrusted", "spoofed", "unknown"}:
        return True
    text = _entry_text(entry)
    return "malicious sarif spoof" in text or "untrusted provenance" in text


def _has_material_sensitive_authz_signal(entries: list[ApplicationReviewContextEntry]) -> bool:
    text = " ".join(_entry_text(entry) for entry in entries)
    return (
        ("missing authorization" in text or "missing authz" in text)
        and any(token in text for token in ("sensitive", "pii", "customer", "restricted"))
    )


def _has_conflicting_evidence_signal(entries: list[ApplicationReviewContextEntry]) -> bool:
    text = " ".join(_entry_text(entry) for entry in entries)
    return any((entry.facets or {}).get("conflicting_evidence") is True for entry in entries) or (
        "conflicting docs" in text or "conflicts with code" in text
    )


def _has_public_admin_iac_signal(entries: list[ApplicationReviewContextEntry]) -> bool:
    text = " ".join(_entry_text(entry) for entry in entries)
    return any(
        (entry.facets or {}).get("surface") == "admin"
        and (entry.facets or {}).get("public_exposure") is True
        for entry in entries
    ) or ("public admin service" in text and ("iac" in text or "terraform" in text))


def _has_webhook_signature_gap(entries: list[ApplicationReviewContextEntry]) -> bool:
    text = " ".join(_entry_text(entry) for entry in entries)
    return "webhook" in text and (
        "signature verification not identified" in text
        or "webhook_signature_verification_not_identified" in text
    )


def _has_unsupported_framework_signal(entries: list[ApplicationReviewContextEntry]) -> bool:
    text = " ".join(_entry_text(entry) for entry in entries)
    return any((entry.facets or {}).get("unsupported_framework") is True for entry in entries) or (
        "unsupported framework" in text
    )


def _is_metadata_only_review(entries: list[ApplicationReviewContextEntry]) -> bool:
    metadata_types = {"app_profile", "org_profile", "review_scope", "doc", "note", "policy"}
    return bool(entries) and all(entry.item_type in metadata_types for entry in entries)


def _all_high_findings_have_active_risk_acceptance(
    *,
    entries: list[ApplicationReviewContextEntry],
    high_scanner_findings: list[ApplicationReviewContextEntry],
    app_name: str,
) -> bool:
    acceptances = [
        entry
        for entry in entries
        if entry.item_type == "accepted_risk" and (entry.facets or {}).get("acceptance_state") == "active"
    ]
    if not acceptances:
        return False
    for finding in high_scanner_findings:
        if not any(
            risk_acceptance_matches_entry(
                acceptance.facets or {},
                app_name=app_name,
                entry_facets=finding.facets or {},
                entry_source_refs=finding.source_refs or [],
                entry_content_hash=finding.content_hash,
            )
            for acceptance in acceptances
        ):
            return False
    return True


def _entry_text(entry: ApplicationReviewContextEntry) -> str:
    return " ".join(
        [
            entry.title,
            entry.body,
            canonical_json(entry.facets or {}),
            canonical_json(entry.source_refs or []),
        ]
    ).casefold()


def _decision_trace(
    *,
    entries: list[ApplicationReviewContextEntry],
    scanner_findings: list[ApplicationReviewContextEntry],
    high_scanner_findings: list[ApplicationReviewContextEntry],
    scanner_only: bool,
    policy: dict,
    rejected_scanner_findings: list[ApplicationReviewContextEntry],
) -> list[str]:
    item_counts: dict[str, int] = {}
    for entry in entries:
        item_counts[entry.item_type] = item_counts.get(entry.item_type, 0) + 1
    return [
        f"engine:{DETERMINISTIC_DECISION_ENGINE_VERSION}",
        f"entries:{len(entries)}",
        f"item_counts:{canonical_json(item_counts)}",
        f"scanner_findings:{len(scanner_findings)}",
        f"rejected_scanner_findings:{len(rejected_scanner_findings)}",
        f"high_or_critical_scanner_findings:{len(high_scanner_findings)}",
        f"scanner_only:{scanner_only}",
        f"policy_hash:{hashlib.sha256(canonical_json(policy or {}).encode('utf-8')).hexdigest()}",
    ]


def _stored_replay(context: Any) -> dict[str, Any] | None:
    if not isinstance(context, dict):
        return None
    payload = context.get(DECISION_REPLAY_CONTEXT_KEY)
    return payload if isinstance(payload, dict) else None


def _decision_replay_payload(
    decision: ApplicationReviewDecisionResponse,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    return {
        "decision": decision.decision,
        "reason": decision.reason,
        "evidence_hashes": decision.evidence_hashes,
        "scanner_only": decision.scanner_only,
        "evidence_snapshot_hash": decision.evidence_snapshot_hash,
        "decision_engine_version": decision.decision_engine_version,
        "decision_trace": decision.decision_trace,
        "evidence_snapshot": snapshot,
    }


def _decision_from_replay(
    review_id: UUID,
    payload: dict[str, Any],
) -> ApplicationReviewDecisionResponse:
    return ApplicationReviewDecisionResponse(
        review_id=review_id,
        decision=str(payload.get("decision") or "gather_evidence"),
        reason=str(payload.get("reason") or "Replayed deterministic decision."),
        evidence_hashes=[
            str(value)
            for value in payload.get("evidence_hashes", [])
            if isinstance(value, str)
        ],
        scanner_only=bool(payload.get("scanner_only")),
        evidence_snapshot_hash=str(payload["evidence_snapshot_hash"]),
        decision_engine_version=str(payload["decision_engine_version"]),
        replayed=True,
        decision_trace=[
            *[
                str(value)
                for value in payload.get("decision_trace", [])
                if isinstance(value, str)
            ],
            "replayed_existing_decision",
        ],
    )
