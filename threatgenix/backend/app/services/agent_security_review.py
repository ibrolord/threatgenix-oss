"""Agent-facing release decision projection for semantic security reviews."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from collections import Counter
from collections.abc import Mapping
from typing import Any, Literal

from app.schemas.security_review import (
    AgentCiContract,
    AgentCiFailPolicy,
    AgentEvidenceRef,
    AgentEvidenceType,
    AgentFindingVerification,
    AgentRemediationAction,
    AgentRemediationHistoryEntry,
    AgentRemediationPlanResponse,
    AgentRemediationTicketDraft,
    AgentRemediationTransition,
    AgentReleaseDecision,
    AgentSecurityReviewFinding,
    AgentSecurityReviewResponse,
    CustomerSecurityPacketFinding,
    CustomerSecurityPacketResponse,
    CustomerSecurityPacketSourceFingerprint,
    EvidenceStrength,
    SecurityReviewApplicationSummary,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
)

PASS_SEMANTICS = (
    "Ship means no blocking finding based on currently connected evidence; "
    "it does not certify that the application is secure."
)

_DECISION_RANK: dict[AgentReleaseDecision, int] = {
    "block": 0,
    "fix_now": 1,
    "verify": 2,
    "gather_evidence": 3,
    "accept_risk": 4,
    "ship": 5,
}
_EVIDENCE_TYPES: set[AgentEvidenceType] = {
    "code",
    "dfd",
    "document",
    "scan",
    "cloud",
    "iac",
    "control",
    "threat_intel",
    "manual",
    "repository",
    "unknown",
}
_CI_FAIL_DECISIONS: dict[AgentCiFailPolicy, tuple[AgentReleaseDecision, ...]] = {
    "block_only": ("block",),
    "block_or_fix_now": ("block", "fix_now"),
    "block_fix_now_or_verify": ("block", "fix_now", "verify"),
    "never": (),
}


def build_agent_ci_contract(
    decision: AgentReleaseDecision,
    fail_policy: AgentCiFailPolicy = "block_only",
) -> AgentCiContract:
    blocking_decisions = list(_CI_FAIL_DECISIONS[fail_policy])
    should_fail = decision in blocking_decisions
    if should_fail:
        reason = (
            f"CI should fail because decision `{decision}` is included in "
            f"policy `{fail_policy}`."
        )
    else:
        reason = (
            f"CI should continue because decision `{decision}` is not included in "
            f"policy `{fail_policy}`."
        )
    return AgentCiContract(
        fail_policy=fail_policy,
        blocking_decisions=blocking_decisions,
        should_fail=should_fail,
        exit_code=1 if should_fail else 0,
        reason=reason,
    )


def _active_for_release(finding: SecurityReviewFinding) -> bool:
    return finding.review_status in {"open", "in_progress", "accepted"}


def _is_grounded(finding: SecurityReviewFinding) -> bool:
    return bool(finding.evidence_refs or finding.code_links)


def _evidence_type(value: str) -> AgentEvidenceType:
    candidate = value.strip().casefold().replace("-", "_")
    if candidate in _EVIDENCE_TYPES:
        return candidate  # type: ignore[return-value]
    if candidate in {"repo", "git", "github"}:
        return "repository"
    if candidate in {"sast", "dast", "validation"}:
        return "scan"
    if candidate in {"threat_intelligence", "intel"}:
        return "threat_intel"
    return "unknown"


def _code_link_strength(relationship: str) -> EvidenceStrength:
    if relationship in {"confirms_missing_control", "shows_compensating_control"}:
        return "strong"
    if relationship == "unmodeled_surface":
        return "partial"
    return "missing"


def _source_object_type_for_ref(evidence_type: AgentEvidenceType) -> str:
    if evidence_type == "dfd":
        return "dfd_model"
    if evidence_type == "document":
        return "document_excerpt"
    if evidence_type == "repository":
        return "repository_evidence"
    if evidence_type == "scan":
        return "scan_evidence"
    if evidence_type == "cloud":
        return "cloud_evidence"
    if evidence_type == "iac":
        return "iac_evidence"
    if evidence_type == "threat_intel":
        return "threat_intel"
    if evidence_type == "control":
        return "control_evidence"
    if evidence_type == "manual":
        return "human_attestation"
    return "evidence_ref"


def _source_object_id_for_ref(
    evidence_type: AgentEvidenceType,
    raw_ref: str,
    finding: SecurityReviewFinding,
) -> str:
    if evidence_type == "repository":
        return "repository_evidence"
    if evidence_type == "cloud":
        return "cloud_scan_evidence"
    if evidence_type == "iac":
        return "iac_evidence"
    if evidence_type == "scan" and finding.linked_threat_ids:
        return finding.linked_threat_ids[0]
    if evidence_type == "manual":
        return finding.source_object_id
    return raw_ref


def _dedupe_key(ref: AgentEvidenceRef) -> tuple[str, str, str, str]:
    return (
        ref.type,
        ref.source_object_type or "",
        ref.source_object_id or "",
        ref.location or ref.reference,
    )


def _append_evidence_ref(
    refs: list[AgentEvidenceRef],
    seen: set[tuple[str, str, str, str]],
    ref: AgentEvidenceRef,
) -> None:
    key = _dedupe_key(ref)
    if key in seen:
        return
    seen.add(key)
    refs.append(ref)


def _risk_acceptance_evidence_ref(
    finding: SecurityReviewFinding,
) -> AgentEvidenceRef | None:
    acceptance = finding.risk_acceptance
    if acceptance is None:
        return None
    status = acceptance.status
    accepted_by = acceptance.accepted_by or "unknown reviewer"
    expires = acceptance.expires_at or "no expiry recorded"
    control = acceptance.compensating_control or "no compensating control recorded"
    return AgentEvidenceRef(
        type="manual",
        reference=f"risk_acceptance:{status}:{finding.source_object_id}",
        claim=(
            f"Risk acceptance is {status}; accepted by {accepted_by}; "
            f"expires {expires}; compensating control: {control}."
        ),
        validated=status == "active",
        source_object_type="human_attestation",
        source_object_id=finding.source_object_id,
        location=f"risk_acceptance:{status}",
        relationship="accepted_by_reviewer",
        strength="partial" if status == "active" else "weak",
    )


def _agent_decision_for_finding(
    finding: SecurityReviewFinding,
) -> AgentReleaseDecision:
    if finding.review_status == "accepted":
        return "accept_risk"

    proposed: AgentReleaseDecision
    if (
        finding.priority == "p0_blocker"
        or finding.wire_action_bucket == "bright_red_line"
    ):
        proposed = "block"
    elif (
        finding.queue_bucket == "fix_now"
        or finding.wire_action_bucket == "engineer_now"
        or (finding.needs_engineering_change and finding.priority == "p1_now")
    ):
        proposed = "fix_now"
    elif (
        finding.queue_bucket == "verify"
        or finding.wire_action_bucket == "verify_control"
    ):
        proposed = "verify"
    elif (
        finding.queue_bucket == "gather_evidence"
        or finding.wire_action_bucket == "fill_evidence_gap"
        or finding.needs_evidence
    ):
        proposed = "gather_evidence"
    else:
        proposed = "verify"

    if (
        proposed in {"block", "fix_now"}
        and not _is_grounded(finding)
        and finding.truth_status not in {"validated", "strongly_indicated"}
    ):
        return "gather_evidence"
    return proposed


def _risk_path(finding: SecurityReviewFinding) -> list[str]:
    path: list[str] = []
    if finding.entry_point:
        path.append(finding.entry_point)
    path.extend(asset for asset in finding.impacted_assets if asset not in path)
    if not path and finding.code_links:
        first_link = finding.code_links[0]
        path.append(first_link.surface_name or first_link.source_file)
    if finding.title not in path:
        path.append(finding.title)
    return path


def _evidence_refs(finding: SecurityReviewFinding) -> list[AgentEvidenceRef]:
    validated = finding.truth_status in {"validated", "strongly_indicated"}
    refs: list[AgentEvidenceRef] = []
    seen: set[tuple[str, str, str, str]] = set()

    for link in finding.code_links:
        reference = link.source_file
        if link.line_number:
            reference = f"{reference}:{link.line_number}"
        _append_evidence_ref(
            refs,
            seen,
            AgentEvidenceRef(
                type="code",
                reference=reference,
                claim=link.summary,
                validated=link.relationship
                in {"confirms_missing_control", "shows_compensating_control"},
                source_object_type="code_surface",
                source_object_id=link.surface_id,
                location=reference,
                relationship=link.relationship,
                strength=_code_link_strength(link.relationship),
            ),
        )

    for anchor in finding.evidence_anchors:
        _append_evidence_ref(
            refs,
            seen,
            AgentEvidenceRef.model_validate(anchor.model_dump()),
        )

    acceptance_ref = _risk_acceptance_evidence_ref(finding)
    if acceptance_ref is not None:
        _append_evidence_ref(refs, seen, acceptance_ref)

    for raw_ref in finding.evidence_refs:
        evidence_type = _evidence_type(raw_ref)
        _append_evidence_ref(
            refs,
            seen,
            AgentEvidenceRef(
                type=evidence_type,
                reference=raw_ref,
                claim=f"{raw_ref.replace('_', ' ')} evidence supports this review finding.",
                validated=validated,
                source_object_type=_source_object_type_for_ref(evidence_type),
                source_object_id=_source_object_id_for_ref(
                    evidence_type,
                    raw_ref,
                    finding,
                ),
                relationship="supports_review_finding",
                strength="strong" if validated else "partial",
            ),
        )

    return refs


def _fix_instructions(
    finding: SecurityReviewFinding, decision: AgentReleaseDecision
) -> list[str]:
    instructions: list[str] = []
    for candidate in (
        finding.next_best_action,
        finding.next_step,
        finding.rationale_excerpt,
    ):
        if candidate and candidate not in instructions:
            instructions.append(candidate)

    if finding.needs_engineering_change:
        instructions.append(
            "Patch the affected code, configuration, or control path and rerun the review."
        )
    if finding.needs_evidence or decision == "gather_evidence":
        instructions.append(
            "Attach repository, scan, DFD, cloud, or human evidence before promoting this as validated."
        )
    if not finding.owner and decision in {"block", "fix_now", "verify"}:
        instructions.append("Assign an owner for the next review action.")

    deduped: list[str] = []
    for item in instructions:
        normalized = item.strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped


def _verification(
    finding: SecurityReviewFinding, decision: AgentReleaseDecision
) -> AgentFindingVerification:
    evidence_needed: list[str] = []
    if finding.needs_evidence or decision == "gather_evidence":
        evidence_needed.append("grounded evidence chain")
    if not finding.code_links and "repository" in finding.evidence_refs:
        evidence_needed.append("exact code reference")
    if not finding.evidence_refs:
        evidence_needed.append("at least one non-AI evidence reference")

    suggested_test = finding.next_step or finding.next_best_action
    if decision == "block":
        suggested_test = (
            suggested_test
            or "Reproduce the blocked path, apply the fix, then rerun review."
        )
    elif decision == "verify":
        suggested_test = (
            suggested_test or "Collect proof that the compensating control is active."
        )
    elif decision == "gather_evidence":
        suggested_test = (
            suggested_test or "Attach the missing evidence, then rerun the review."
        )

    return AgentFindingVerification(
        required=decision != "ship",
        suggested_test=suggested_test,
        evidence_needed=evidence_needed,
    )


def _overall_decision(
    summary: SecurityReviewApplicationSummary,
    decisions: list[AgentReleaseDecision],
) -> AgentReleaseDecision:
    if "block" in decisions:
        return "block"
    if "fix_now" in decisions:
        return "fix_now"
    if "verify" in decisions:
        return "verify"
    if "gather_evidence" in decisions:
        return "gather_evidence"
    if summary.coverage.missing_evidence_sources > 0:
        return "gather_evidence"
    if "accept_risk" in decisions:
        return "accept_risk"
    return "ship"


def _decision_reason(
    decision: AgentReleaseDecision,
    summary: SecurityReviewApplicationSummary,
    decisions: list[AgentReleaseDecision],
) -> str:
    counts = Counter(decisions)
    if decision == "ship":
        return PASS_SEMANTICS
    if decision == "block":
        return f"{counts['block']} blocking finding(s) are grounded enough to stop release."
    if decision == "fix_now":
        return f"{counts['fix_now']} finding(s) require current-cycle engineering work before confidence is defensible."
    if decision == "verify":
        return f"{counts['verify']} finding(s) need control or implementation verification before release confidence improves."
    if decision == "gather_evidence":
        gaps = counts["gather_evidence"] or summary.coverage.missing_evidence_sources
        return f"{gaps} evidence gap(s) prevent a strong pass or fix decision."
    return "Only accepted-risk items remain active in the release decision set."


def build_agent_security_review_response(
    summary: SecurityReviewApplicationSummary,
    findings_response: SecurityReviewFindingListResponse,
    *,
    ci_fail_policy: AgentCiFailPolicy = "block_only",
) -> AgentSecurityReviewResponse:
    agent_findings: list[AgentSecurityReviewFinding] = []
    evidence_gaps: list[str] = []

    active_findings = [
        finding
        for finding in findings_response.findings
        if _active_for_release(finding)
    ]
    for finding in sorted(
        active_findings,
        key=lambda item: (
            _DECISION_RANK[_agent_decision_for_finding(item)],
            -item.numeric_score,
            item.title,
        ),
    ):
        decision = _agent_decision_for_finding(finding)
        if decision == "gather_evidence":
            evidence_gaps.append(finding.title)
        agent_findings.append(
            AgentSecurityReviewFinding(
                decision=decision,
                finding_id=finding.id,
                source_object_type=finding.source_object_type,
                source_object_id=finding.source_object_id,
                title=finding.title,
                priority=finding.priority,
                confidence=finding.confidence,
                risk_path=_risk_path(finding),
                evidence=_evidence_refs(finding),
                fix_instructions=_fix_instructions(finding, decision),
                verification=_verification(finding, decision),
            )
        )

    decisions = [finding.decision for finding in agent_findings]
    overall = _overall_decision(summary, decisions)
    return AgentSecurityReviewResponse(
        generated_at=findings_response.generated_at,
        system_name=findings_response.system_name,
        decision=overall,
        decision_reason=_decision_reason(overall, summary, decisions),
        pass_semantics=PASS_SEMANTICS,
        ci=build_agent_ci_contract(overall, ci_fail_policy),
        findings=agent_findings,
        evidence_gaps=evidence_gaps,
    )


def _remediation_action_kind(
    finding: AgentSecurityReviewFinding,
) -> tuple[str, str, AgentReleaseDecision]:
    if finding.decision in {"block", "fix_now"}:
        return "patch_guidance", "remediation_note", "verify"
    if finding.decision == "verify":
        return "verification", "verification_note", "ship"
    if finding.decision == "gather_evidence":
        return "evidence_request", "evidence_request", "gather_evidence"
    return "verification", "verification_note", "ship"


def _remediation_instruction(finding: AgentSecurityReviewFinding) -> str:
    if finding.fix_instructions:
        return finding.fix_instructions[0]
    if finding.verification.suggested_test:
        return finding.verification.suggested_test
    if finding.decision == "gather_evidence":
        return "Attach the missing evidence, then rerun the release decision."
    return "Rerun the review and confirm the finding no longer affects release."


def _ticket_draft_body(finding: AgentSecurityReviewFinding, instruction: str) -> str:
    evidence_lines = [
        f"- {item.type}: {item.location or item.reference} ({item.strength or 'unspecified'})"
        for item in finding.evidence[:6]
    ] or ["- No concrete evidence reference is attached yet."]
    evidence_needed = finding.verification.evidence_needed or [
        "implementation proof or reviewer evidence"
    ]
    return "\n".join(
        [
            "## Security remediation",
            "",
            f"Finding: {finding.title}",
            f"Current decision: {finding.decision}",
            f"Priority: {finding.priority}",
            "",
            "## Action",
            f"- {instruction}",
            "",
            "## Evidence references",
            *evidence_lines,
            "",
            "## Evidence needed before closure",
            *[f"- {item}" for item in evidence_needed],
            "",
            "## Verification",
            f"- {finding.verification.suggested_test or 'Rerun the security review and attach proof.'}",
            "",
            "Generated by ThreatGenix. This is a draft; confirm before creating an external ticket.",
        ]
    )


def _ticket_draft(
    finding: AgentSecurityReviewFinding,
    *,
    instruction: str,
    artifacts: list[Any] | None = None,
) -> AgentRemediationTicketDraft:
    provider: Literal["github_issue", "linear", "jira"] = "github_issue"
    external_ticket_id: str | None = None
    external_ticket_url: str | None = None
    for artifact in artifacts or []:
        body = str(getattr(artifact, "body", "") or "")
        if "External ticket handoff" not in body:
            continue
        for line in body.splitlines():
            if line.startswith("- Provider:"):
                parsed_provider = line.split(":", 1)[1].strip()
                if parsed_provider in {"github_issue", "linear", "jira"}:
                    provider = parsed_provider
            elif line.startswith("- Ticket id:"):
                external_ticket_id = line.split(":", 1)[1].strip() or None
            elif line.startswith("- Ticket URL:"):
                external_ticket_url = line.split(":", 1)[1].strip() or None
        break
    return AgentRemediationTicketDraft(
        provider=provider,
        title=f"[Security] {finding.title}",
        body=_ticket_draft_body(finding, instruction),
        labels=[
            "security-review",
            finding.decision.replace("_", "-"),
            finding.priority.replace("_", "-"),
        ],
        priority=finding.priority,
        external_creation_status="created"
        if external_ticket_id or external_ticket_url
        else "draft_only",
        connector_creation_status="created"
        if external_ticket_id or external_ticket_url
        else "available_with_confirmation",
        external_ticket_id=external_ticket_id,
        external_ticket_url=external_ticket_url,
    )


def _transition_status(
    finding: AgentSecurityReviewFinding,
    *,
    artifacts: list[Any],
    expected_next_decision: AgentReleaseDecision,
) -> AgentRemediationTransition:
    latest_artifact_at = max(
        (str(getattr(item, "created_at", "") or "") for item in artifacts),
        default=None,
    )
    artifact_count = len(artifacts)
    evidence_count = len(finding.evidence)
    inbound_evidence_artifact_exists = any(
        "Inbound evidence webhook" in str(getattr(item, "body", "") or "")
        for item in artifacts
    )
    if (
        finding.verification.evidence_needed
        and evidence_count == 0
        and not inbound_evidence_artifact_exists
    ):
        status = "evidence_still_missing"
        rationale = (
            "The action still lacks the named evidence needed before the "
            "decision can improve."
        )
    elif artifact_count > 0 and finding.decision in {"block", "fix_now"}:
        status = "ready_for_verify"
        rationale = (
            "A local remediation artifact exists; attach implementation proof "
            "and rerun the review before moving past verify."
        )
    elif artifact_count > 0 and finding.decision == "verify":
        status = "ready_for_clearance"
        rationale = (
            "Verification guidance exists; attach proof and rerun the release "
            "decision to determine whether this can clear."
        )
    elif artifact_count > 0:
        status = "ready_for_rerun"
        rationale = "A local action artifact exists and the review is ready to rerun."
    else:
        status = "needs_action"
        rationale = (
            "No local remediation, verification, or evidence-request artifact "
            "has been created for this action yet."
        )
    return AgentRemediationTransition(
        status=status,
        current_decision=finding.decision,
        expected_next_decision=expected_next_decision,
        rationale=rationale,
        artifact_count=artifact_count,
        latest_artifact_at=latest_artifact_at,
        evidence_count=evidence_count,
    )


def _artifacts_by_finding(
    findings_response: SecurityReviewFindingListResponse | None,
) -> dict[tuple[str, str], list[Any]]:
    if findings_response is None:
        return {}
    return {
        (finding.source_object_type, finding.source_object_id): finding.artifacts
        for finding in findings_response.findings
    }


def _remediation_plan_markdown(plan: AgentRemediationPlanResponse) -> str:
    lines = [
        f"# {plan.system_name} Agent Remediation Plan",
        "",
        f"Generated: {plan.generated_at}",
        f"Current decision: {plan.current_decision}",
        plan.summary,
        "",
        "## Actions",
    ]
    if not plan.actions:
        lines.append("No remediation actions are required by the current decision.")
    for index, action in enumerate(plan.actions, start=1):
        lines.extend(
            [
                f"{index}. {action.title}",
                f"   - Current decision: {action.current_decision}",
                f"   - Action: {action.action_kind.replace('_', ' ')}",
                f"   - Artifact: {action.artifact_kind}",
                f"   - Instruction: {action.instruction}",
                (
                    "   - Evidence needed: "
                    + (
                        ", ".join(action.evidence_needed)
                        if action.evidence_needed
                        else "No extra evidence named."
                    )
                ),
                f"   - Expected next decision after proof: {action.expected_next_decision}",
                (
                    f"   - Transition: {action.transition.status} "
                    f"({action.transition.rationale})"
                ),
                (
                    "   - Ticket draft: "
                    f"{action.ticket_draft.provider} / {action.ticket_draft.title}"
                ),
            ]
        )
    lines.extend(["", "## Action history"])
    if plan.action_history:
        for item in plan.action_history:
            lines.append(
                f"- {item.created_at}: {item.artifact_kind} for "
                f"{item.finding_id} ({item.transition_status})"
            )
    else:
        lines.append("No local remediation artifacts have been created yet.")
    lines.extend(["", "## Rerun instructions", *plan.rerun_instructions])
    return "\n".join(lines)


def build_agent_remediation_plan_response(
    summary: SecurityReviewApplicationSummary,
    agent_response: AgentSecurityReviewResponse,
    findings_response: SecurityReviewFindingListResponse | None = None,
) -> AgentRemediationPlanResponse:
    """Create agent-readable remediation actions without changing review state."""
    actions: list[AgentRemediationAction] = []
    action_history: list[AgentRemediationHistoryEntry] = []
    artifacts_by_source = _artifacts_by_finding(findings_response)
    for finding in agent_response.findings:
        if finding.decision in {"ship", "accept_risk"}:
            continue
        action_kind, artifact_kind, expected_next_decision = _remediation_action_kind(
            finding
        )
        action_id = (
            f"{finding.source_object_type}:{finding.source_object_id}:{artifact_kind}"
        )
        instruction = _remediation_instruction(finding)
        artifacts = artifacts_by_source.get(
            (finding.source_object_type, finding.source_object_id),
            [],
        )
        transition = _transition_status(
            finding,
            artifacts=artifacts,
            expected_next_decision=expected_next_decision,
        )
        for artifact in artifacts:
            action_history.append(
                AgentRemediationHistoryEntry(
                    action_id=action_id,
                    finding_id=finding.finding_id,
                    artifact_kind=getattr(artifact, "kind", artifact_kind),
                    artifact_title=str(getattr(artifact, "title", "")),
                    created_at=str(getattr(artifact, "created_at", "")),
                    transition_status=transition.status,
                )
            )
        actions.append(
            AgentRemediationAction(
                action_id=action_id,
                finding_id=finding.finding_id,
                source_object_type=finding.source_object_type,
                source_object_id=finding.source_object_id,
                title=finding.title,
                current_decision=finding.decision,
                action_kind=action_kind,
                artifact_kind=artifact_kind,
                priority=finding.priority,
                instruction=instruction,
                verification_required=finding.verification.required,
                evidence_needed=finding.verification.evidence_needed,
                expected_next_decision=expected_next_decision,
                ticket_draft=_ticket_draft(
                    finding, instruction=instruction, artifacts=artifacts
                ),
                transition=transition,
            )
        )

    if actions:
        summary_text = (
            f"{len(actions)} remediation loop action(s) are ready. Applying the "
            "plan creates local review artifacts; it does not clear a finding "
            "until new proof is attached and the release decision is rerun."
        )
        loop_status = "ready"
    else:
        summary_text = (
            "No active agent remediation action is required by the current "
            "release decision."
        )
        loop_status = "no_action_required"

    plan = AgentRemediationPlanResponse(
        generated_at=agent_response.generated_at,
        system_name=agent_response.system_name,
        current_decision=agent_response.decision,
        loop_status=loop_status,
        summary=summary_text,
        actions=actions[:12],
        action_history=sorted(
            action_history,
            key=lambda item: item.created_at,
            reverse=True,
        )[:12],
        rerun_instructions=[
            "Apply the patch, control change, or evidence request named in each action.",
            "Attach implementation proof, validation output, PR link, or reviewer evidence to the finding.",
            "Rerun GET /api/threat-models/{id}/review and GET /api/threat-models/{id}/agent/release-decision.",
            (
                "Do not promote a fix_now/block item past verify until the "
                "verification evidence named by the action is present."
            ),
        ],
        plan_markdown="",
    )
    plan.plan_markdown = _remediation_plan_markdown(plan)
    return plan


def _customer_status_for_agent_finding(
    finding: AgentSecurityReviewFinding,
) -> str:
    if finding.decision == "accept_risk":
        return "accepted_risk"
    if finding.decision == "gather_evidence":
        return "evidence_gap"
    if finding.decision == "verify" or finding.verification.required:
        return "needs_verification"
    return "validated_risk"


def _customer_evidence_summary(finding: AgentSecurityReviewFinding) -> str:
    if not finding.evidence:
        return "No customer-safe supporting evidence is connected yet."
    validated = sum(1 for item in finding.evidence if item.validated)
    evidence_types = sorted(
        {
            item.type.replace("_", " ")
            for item in finding.evidence
            if item.type != "unknown"
        }
    )
    if (
        finding.decision == "gather_evidence" or finding.verification.evidence_needed
    ) and validated == 0:
        return (
            "No customer-safe validation evidence is connected yet."
            f" Expected evidence types: {', '.join(evidence_types) if evidence_types else 'the missing source'}."
        )
    strength_counts = Counter(
        item.strength or "unspecified" for item in finding.evidence
    )
    strength_bits = ", ".join(
        f"{count} {strength}" for strength, count in sorted(strength_counts.items())
    )
    return (
        f"{len(finding.evidence)} evidence reference(s) are connected across "
        f"{', '.join(evidence_types)}; {validated} are marked validated"
        f"{f' ({strength_bits})' if strength_bits else ''}."
    )


def _customer_finding_summary(finding: AgentSecurityReviewFinding) -> str:
    risk_path = " -> ".join(finding.risk_path[:4])
    if risk_path:
        return f"{finding.title} affects the reviewed path {risk_path}."
    return finding.title


def _customer_packet_finding(
    finding: AgentSecurityReviewFinding,
) -> CustomerSecurityPacketFinding:
    return CustomerSecurityPacketFinding(
        title=finding.title,
        release_decision=finding.decision,
        customer_status=_customer_status_for_agent_finding(finding),
        summary=_customer_finding_summary(finding),
        evidence_summary=_customer_evidence_summary(finding),
        next_step=(
            finding.verification.suggested_test
            or (finding.fix_instructions[0] if finding.fix_instructions else None)
        ),
    )


def _evidence_types(
    agent_response: AgentSecurityReviewResponse,
) -> set[AgentEvidenceType]:
    return {
        evidence.type
        for finding in agent_response.findings
        for evidence in finding.evidence
        if evidence.type != "unknown" and evidence.validated
    }


def _connected_customer_packet_evidence_types(
    agent_response: AgentSecurityReviewResponse,
    source_fingerprints: list[CustomerSecurityPacketSourceFingerprint],
) -> set[AgentEvidenceType]:
    evidence_types = set(_evidence_types(agent_response))
    for source in source_fingerprints:
        if source.source_type in {"repository", "pull_request"}:
            evidence_types.add("repository")
        elif source.source_type == "scan":
            evidence_types.add("scan")
        elif source.source_type == "cloud_scan":
            evidence_types.add("cloud")
        elif source.source_type == "iac":
            evidence_types.add("iac")
    return evidence_types


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_jsonable(item) for item in value]
    return value


def _without_volatile_fields(value: Any, volatile_keys: set[str]) -> Any:
    jsonable = _jsonable(value)
    if isinstance(jsonable, Mapping):
        return {
            str(key): _without_volatile_fields(item, volatile_keys)
            for key, item in jsonable.items()
            if str(key) not in volatile_keys
        }
    if isinstance(jsonable, list):
        return [_without_volatile_fields(item, volatile_keys) for item in jsonable]
    return jsonable


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _stable_content_hash(value: Any, *, volatile_keys: set[str] | None = None) -> str:
    encoded = json.dumps(
        _without_volatile_fields(value, volatile_keys or {"generated_at"}),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, Mapping) else None
    return value if isinstance(value, Mapping) else None


def _as_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _scanner_tool_label(tool_name: str) -> str:
    labels = {
        "osv-scanner": "OSV Scanner",
        "semgrep": "Semgrep",
        "trivy": "Trivy",
        "checkov": "Checkov",
        "trufflehog": "TruffleHog",
        "nuclei": "Nuclei",
        "external-report": "External report",
        "pentest-report": "Pentest report",
    }
    return labels.get(tool_name.strip().casefold(), tool_name.replace("-", " ").title())


def _source_label(source_type: str, source_id: str, payload: Mapping[str, Any]) -> str:
    if source_type == "repository":
        connection = _as_mapping(payload.get("connection"))
        repository = connection.get("repository") if connection else None
        filename = payload.get("filename")
        return str(repository or filename or "Repository evidence")
    if source_type == "pull_request":
        pull_request = _as_mapping(payload.get("pull_request")) or payload
        repository = pull_request.get("repository")
        number = pull_request.get("number")
        if repository and number:
            return f"{repository} PR #{number}"
        return str(repository or "Pull request evidence")
    if source_type == "scan":
        tool_name = _scanner_tool_label(str(payload.get("tool_name") or "Scanner"))
        finding_count = payload.get("finding_count")
        if isinstance(finding_count, int):
            suffix = "finding" if finding_count == 1 else "findings"
            return f"{tool_name} validation scan ({finding_count} {suffix})"
        return f"{tool_name} validation scan"
    if source_type == "cloud_scan":
        return str(payload.get("filename") or payload.get("provider") or "Cloud scan")
    if source_type == "iac":
        return str(
            payload.get("filename") or payload.get("reference") or "IaC evidence"
        )
    return source_id


def _collected_at(payload: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return None


def _source_fingerprint(
    source_type: str,
    source_id: str,
    payload: Any,
    *,
    collected_at: str | None = None,
) -> CustomerSecurityPacketSourceFingerprint | None:
    normalized = _as_mapping(payload)
    if normalized is None:
        return None
    return CustomerSecurityPacketSourceFingerprint(
        source_type=source_type,
        source_id=source_id,
        label=_source_label(source_type, source_id, normalized),
        fingerprint=_stable_hash(normalized),
        collected_at=collected_at,
    )


def build_customer_packet_source_fingerprints(
    *,
    summary: SecurityReviewApplicationSummary,
    findings_response: SecurityReviewFindingListResponse,
    agent_response: AgentSecurityReviewResponse,
    repository_evidence: Any = None,
    validation_scan_evidence: Any = None,
    cloud_scan_evidence: Any = None,
    iac_evidence: Any = None,
) -> list[CustomerSecurityPacketSourceFingerprint]:
    """Build customer-safe fingerprints without exposing raw evidence payloads."""
    fingerprints: list[CustomerSecurityPacketSourceFingerprint] = [
        CustomerSecurityPacketSourceFingerprint(
            source_type="review_summary",
            source_id="application_review_summary",
            label="Application review summary",
            fingerprint=_stable_content_hash(summary),
            collected_at=summary.generated_at,
        ),
        CustomerSecurityPacketSourceFingerprint(
            source_type="review_findings",
            source_id="application_review_findings",
            label="Application review findings",
            fingerprint=_stable_content_hash(findings_response),
            collected_at=findings_response.generated_at,
        ),
        CustomerSecurityPacketSourceFingerprint(
            source_type="agent_decision",
            source_id="agent_release_decision",
            label="Agent release decision",
            fingerprint=_stable_content_hash(agent_response),
            collected_at=agent_response.generated_at,
        ),
    ]

    repository_payload = _as_mapping(repository_evidence)
    if repository_payload:
        repository = _source_fingerprint(
            "repository",
            "repository_evidence",
            repository_payload,
            collected_at=_collected_at(repository_payload, "parsed_at"),
        )
        if repository:
            fingerprints.append(repository)

        pull_request_payload = _as_mapping(repository_payload.get("pull_request"))
        if pull_request_payload:
            pull_request = _source_fingerprint(
                "pull_request",
                "repository_pull_request",
                pull_request_payload,
                collected_at=_collected_at(pull_request_payload, "fetched_at"),
            )
            if pull_request:
                fingerprints.append(pull_request)

    scan_payloads = _as_sequence(validation_scan_evidence)
    for index, scan_payload in enumerate(scan_payloads[:12], start=1):
        normalized_scan = _as_mapping(scan_payload)
        if not normalized_scan:
            continue
        scan_id = str(normalized_scan.get("id") or f"validation_scan_{index}")
        scan = _source_fingerprint(
            "scan",
            f"validation_scan:{scan_id}",
            normalized_scan,
            collected_at=_collected_at(
                normalized_scan, "completed_at", "created_at", "started_at"
            ),
        )
        if scan:
            fingerprints.append(scan)

    cloud_payload = _as_mapping(cloud_scan_evidence)
    if cloud_payload:
        cloud = _source_fingerprint(
            "cloud_scan",
            "cloud_scan_evidence",
            cloud_payload,
            collected_at=_collected_at(cloud_payload, "parsed_at"),
        )
        if cloud:
            fingerprints.append(cloud)

    iac_payload = _as_mapping(iac_evidence)
    if iac_payload:
        iac = _source_fingerprint(
            "iac",
            "iac_evidence",
            iac_payload,
            collected_at=_collected_at(iac_payload, "parsed_at"),
        )
        if iac:
            fingerprints.append(iac)

    return fingerprints


def _default_redaction_notes() -> list[str]:
    return [
        (
            "Customer packet omits raw repository contents, secret values, "
            "credentials, and internal evidence payloads."
        ),
        (
            "Packet fingerprints identify the reviewed evidence snapshot without "
            "disclosing the underlying evidence body."
        ),
        (
            "Review file paths, repository names, and source labels against the "
            "recipient sharing policy before external distribution."
        ),
    ]


def _customer_packet_markdown(
    packet: CustomerSecurityPacketResponse,
) -> str:
    def section(title: str, items: list[str]) -> list[str]:
        return [f"## {title}", *(items if items else ["None recorded."]), ""]

    def finding_lines(findings: list[CustomerSecurityPacketFinding]) -> list[str]:
        if not findings:
            return ["None recorded."]
        lines: list[str] = []
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"{index}. {finding.title}",
                    f"   - Status: {finding.customer_status.replace('_', ' ')}",
                    f"   - Evidence: {finding.evidence_summary}",
                    f"   - Next step: {finding.next_step or 'No next step recorded.'}",
                ]
            )
        return lines

    return "\n".join(
        [
            f"# {packet.system_name} Customer Security Review Packet",
            "",
            f"Generated: {packet.generated_at}",
            f"Packet version: {packet.packet_version}",
            f"Packet hash: {packet.packet_hash}",
            f"Redaction profile: {packet.redaction_profile}",
            f"Release decision: {packet.release_decision}",
            packet.decision_summary,
            "",
            *section("Scope", packet.scope),
            *section("What is proven", packet.proven),
            *section("Assumptions", packet.assumptions),
            *section("What remains unknown", packet.unknowns),
            "## Validated risks",
            *finding_lines(packet.validated_risks),
            "",
            "## Accepted risks",
            *finding_lines(packet.accepted_risks),
            "",
            "## Evidence gaps",
            *finding_lines(packet.evidence_gaps),
            "",
            "## Source fingerprints",
            *(
                [
                    (
                        f"- {source.label} ({source.source_type}): "
                        f"{source.fingerprint}"
                        f"{f' collected {source.collected_at}' if source.collected_at else ''}"
                    )
                    for source in packet.source_fingerprints
                ]
                if packet.source_fingerprints
                else ["None recorded."]
            ),
            "",
            *section("External sharing controls", packet.redaction_notes),
        ]
    )


SENSITIVE_CUSTOMER_PACKET_SOURCE_TYPES = {
    "repository",
    "pull_request",
    "scan",
    "cloud_scan",
    "iac",
}


def customer_packet_sensitive_source_labels(
    packet: CustomerSecurityPacketResponse,
) -> list[str]:
    """Return source labels that need reviewer approval before export."""
    return [
        source.label
        for source in packet.source_fingerprints
        if source.source_type in SENSITIVE_CUSTOMER_PACKET_SOURCE_TYPES
    ]


def _customer_packet_export_source_label(
    source: CustomerSecurityPacketSourceFingerprint,
    *,
    include_source_labels: bool,
) -> str:
    return source.label if include_source_labels else "redacted source label"


def build_customer_packet_csv(
    packet: CustomerSecurityPacketResponse,
    *,
    include_source_labels: bool = False,
) -> str:
    """Build a customer-safe CSV export for spreadsheet review workflows."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "item", "status", "summary", "evidence", "next_step"])
    writer.writerow(
        [
            "metadata",
            packet.system_name,
            packet.release_decision,
            packet.decision_summary,
            packet.packet_hash,
            packet.redaction_profile,
        ]
    )
    for item in packet.scope:
        writer.writerow(["scope", item, "", "", "", ""])
    for item in packet.proven:
        writer.writerow(["proven", item, "", "", "", ""])
    for item in packet.assumptions:
        writer.writerow(["assumption", item, "", "", "", ""])
    for item in packet.unknowns:
        writer.writerow(["unknown", item, "", "", "", ""])
    for section, findings in (
        ("validated_risk", packet.validated_risks),
        ("accepted_risk", packet.accepted_risks),
        ("evidence_gap", packet.evidence_gaps),
    ):
        for finding in findings:
            writer.writerow(
                [
                    section,
                    finding.title,
                    finding.customer_status,
                    finding.summary,
                    finding.evidence_summary,
                    finding.next_step or "",
                ]
            )
    for source in packet.source_fingerprints:
        writer.writerow(
            [
                "source_fingerprint",
                _customer_packet_export_source_label(
                    source, include_source_labels=include_source_labels
                ),
                source.source_type,
                source.fingerprint,
                source.collected_at or "",
                "",
            ]
        )
    for item in packet.redaction_notes:
        writer.writerow(["redaction_note", item, "", "", "", ""])
    return output.getvalue()


def _html_list(items: list[str]) -> str:
    if not items:
        return "<p>None recorded.</p>"
    return "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in items) + "</ul>"


def _html_findings(findings: list[CustomerSecurityPacketFinding]) -> str:
    if not findings:
        return "<p>None recorded.</p>"
    blocks: list[str] = []
    for finding in findings:
        blocks.append(
            "\n".join(
                [
                    "<article>",
                    f"<h3>{html.escape(finding.title)}</h3>",
                    f"<p><strong>Status:</strong> {html.escape(finding.customer_status.replace('_', ' '))}</p>",
                    f"<p>{html.escape(finding.summary)}</p>",
                    f"<p><strong>Evidence:</strong> {html.escape(finding.evidence_summary)}</p>",
                    f"<p><strong>Next step:</strong> {html.escape(finding.next_step or 'No next step recorded.')}</p>",
                    "</article>",
                ]
            )
        )
    return "\n".join(blocks)


def build_customer_packet_html(
    packet: CustomerSecurityPacketResponse,
    *,
    include_source_labels: bool = False,
) -> str:
    """Render the customer packet as a compact printable HTML document."""
    source_rows = "\n".join(
        (
            "<tr>"
            f"<td>{html.escape(source.source_type.replace('_', ' '))}</td>"
            f"<td>{html.escape(_customer_packet_export_source_label(source, include_source_labels=include_source_labels))}</td>"
            f"<td>{html.escape(source.fingerprint)}</td>"
            f"<td>{html.escape(source.collected_at or '')}</td>"
            "</tr>"
        )
        for source in packet.source_fingerprints
    )
    if not source_rows:
        source_rows = '<tr><td colspan="4">None recorded.</td></tr>'
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{html.escape(packet.system_name)} Customer Security Review Packet</title>
  <style>
    body {{ color: #0f172a; font-family: Inter, Arial, sans-serif; font-size: 12px; line-height: 1.45; }}
    h1 {{ font-size: 24px; margin: 0 0 8px; }}
    h2 {{ border-bottom: 1px solid #cbd5e1; font-size: 16px; margin-top: 22px; padding-bottom: 4px; }}
    h3 {{ font-size: 13px; margin-bottom: 4px; }}
    .meta {{ color: #475569; margin-bottom: 16px; }}
    article {{ border: 1px solid #e2e8f0; border-radius: 6px; margin: 8px 0; padding: 8px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 6px; text-align: left; vertical-align: top; word-break: break-word; }}
    th {{ background: #f8fafc; }}
  </style>
</head>
<body>
  <h1>{html.escape(packet.system_name)} Customer Security Review Packet</h1>
  <p class="meta">Generated {html.escape(packet.generated_at)} · {html.escape(packet.packet_version)} · {html.escape(packet.packet_hash)} · {html.escape(packet.redaction_profile)}</p>
  <p><strong>Release decision:</strong> {html.escape(packet.release_decision)}</p>
  <p>{html.escape(packet.decision_summary)}</p>
  <h2>Scope</h2>{_html_list(packet.scope)}
  <h2>What is proven</h2>{_html_list(packet.proven)}
  <h2>Assumptions</h2>{_html_list(packet.assumptions)}
  <h2>What remains unknown</h2>{_html_list(packet.unknowns)}
  <h2>Validated risks</h2>{_html_findings(packet.validated_risks)}
  <h2>Accepted risks</h2>{_html_findings(packet.accepted_risks)}
  <h2>Evidence gaps</h2>{_html_findings(packet.evidence_gaps)}
  <h2>Source fingerprints</h2>
  <table>
    <thead><tr><th>Type</th><th>Label</th><th>Fingerprint</th><th>Collected</th></tr></thead>
    <tbody>{source_rows}</tbody>
  </table>
  <h2>External sharing controls</h2>{_html_list(packet.redaction_notes)}
</body>
</html>"""


def build_customer_packet_pdf(
    packet: CustomerSecurityPacketResponse,
    *,
    include_source_labels: bool = False,
) -> bytes:
    """Build a PDF export using the same customer-safe packet content."""
    from weasyprint import HTML

    return HTML(
        string=build_customer_packet_html(
            packet, include_source_labels=include_source_labels
        )
    ).write_pdf()


def build_customer_security_packet_response(
    summary: SecurityReviewApplicationSummary,
    findings_response: SecurityReviewFindingListResponse,
    agent_response: AgentSecurityReviewResponse,
    *,
    scope: list[str] | None = None,
    source_fingerprints: list[CustomerSecurityPacketSourceFingerprint] | None = None,
    redaction_notes: list[str] | None = None,
) -> CustomerSecurityPacketResponse:
    """Build a customer-safe packet without exposing internal-only reasoning."""
    packet_source_fingerprints = source_fingerprints or []
    agent_evidence_types = _evidence_types(agent_response)
    evidence_types = _connected_customer_packet_evidence_types(
        agent_response, packet_source_fingerprints
    )
    customer_findings = [
        _customer_packet_finding(finding) for finding in agent_response.findings
    ]
    validated_risks = [
        finding
        for finding in customer_findings
        if finding.customer_status in {"validated_risk", "needs_verification"}
    ]
    accepted_risks = [
        finding
        for finding in customer_findings
        if finding.customer_status == "accepted_risk"
    ]
    evidence_gaps = [
        finding
        for finding in customer_findings
        if finding.customer_status == "evidence_gap"
    ]

    proven = [
        (
            f"{summary.coverage.attached_evidence_sources} evidence source(s) are "
            "connected to this review."
        ),
        (
            f"{len(validated_risks)} customer-visible risk item(s) have enough "
            "supporting context to discuss with a reviewer."
        ),
    ]
    if evidence_types:
        proven.append(
            "Connected evidence types: "
            + ", ".join(sorted(item.replace("_", " ") for item in evidence_types))
            + "."
        )

    assumptions = [
        PASS_SEMANTICS,
        (
            "This packet summarizes the evidence connected to the review workspace; "
            "it is not a penetration test, SOC 2 report, or legal certification."
        ),
    ]

    unknowns: list[str] = []
    if summary.coverage.missing_evidence_sources > 0:
        unknowns.append(
            f"{summary.coverage.missing_evidence_sources} expected evidence source(s) "
            "are still missing or incomplete."
        )
    if agent_response.evidence_gaps:
        unknowns.extend(
            f"Evidence gap: {title}" for title in agent_response.evidence_gaps[:6]
        )
    if "scan" not in evidence_types:
        unknowns.append("Runtime or scanner validation evidence is not connected.")
    elif "scan" not in agent_evidence_types:
        unknowns.append(
            "Scanner validation evidence is imported but not yet mapped to a "
            "customer-visible reviewed risk."
        )
    if "repository" not in evidence_types and "code" not in evidence_types:
        unknowns.append("Exact repository or code-surface evidence is not connected.")

    if not unknowns:
        unknowns.append(
            "No major missing-evidence category is flagged by the current review."
        )

    packet = CustomerSecurityPacketResponse(
        generated_at=findings_response.generated_at,
        system_name=findings_response.system_name,
        release_decision=agent_response.decision,
        decision_summary=agent_response.decision_reason,
        scope=scope or [summary.focus_statement],
        proven=proven,
        assumptions=assumptions,
        unknowns=unknowns,
        validated_risks=validated_risks[:8],
        accepted_risks=accepted_risks[:8],
        evidence_gaps=evidence_gaps[:8],
        source_fingerprints=packet_source_fingerprints,
        redaction_notes=redaction_notes or _default_redaction_notes(),
        customer_safe_markdown="",
    )
    packet.packet_hash = _stable_content_hash(
        packet.model_dump(exclude={"packet_hash"}),
        volatile_keys={"generated_at", "collected_at"},
    )
    packet.customer_safe_markdown = _customer_packet_markdown(packet)
    packet.packet_hash = _stable_content_hash(
        packet.model_dump(exclude={"packet_hash", "customer_safe_markdown"}),
        volatile_keys={"generated_at", "collected_at"},
    )
    packet.customer_safe_markdown = _customer_packet_markdown(packet)
    return packet
