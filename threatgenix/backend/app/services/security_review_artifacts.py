from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.schemas.security_review import (
    ReviewArtifactKind,
    SecurityReviewArtifact,
    SecurityReviewFinding,
)
from app.schemas.threat import ThreatResponse


def _artifact_context_line(finding: SecurityReviewFinding, threat: ThreatResponse | None) -> str:
    parts = [finding.title]
    if threat is not None:
        parts.append(f"STRIDE: {threat.stride_category}")
        parts.append(f"Severity: {threat.severity}")
    elif finding.display_kind != "threat":
        parts.append(f"Kind: {finding.display_kind.replace('_', ' ')}")
    if finding.entry_point:
        parts.append(f"Entry: {finding.entry_point}")
    if finding.impacted_assets:
        parts.append(f"Asset: {', '.join(finding.impacted_assets[:3])}")
    return " | ".join(parts)


def _artifact_body_sections(
    finding: SecurityReviewFinding,
    *,
    kind: ReviewArtifactKind,
    threat: ThreatResponse | None,
) -> tuple[str, str, str]:
    context_line = _artifact_context_line(finding, threat)
    evidence_line = (
        ", ".join(finding.evidence_refs)
        if finding.evidence_refs
        else "No attached evidence yet."
    )
    next_action = finding.next_best_action or finding.next_step or "Continue the review and assign the next concrete action."

    if kind == "remediation_note":
        title = f"Remediation note · {finding.title}"
        summary = (
            "Concrete engineering change to reduce the current attack path and move the finding out of the active queue."
        )
        body = "\n".join(
            [
                "Objective",
                f"- Reduce or eliminate the current risk described by `{finding.title}`.",
                "",
                "Context",
                f"- {context_line}",
                f"- Why now: {finding.why_now}",
                f"- Current queue: {finding.queue_bucket or 'unassigned'}",
                "",
                "Recommended engineering change",
                f"- {next_action}",
                "- Record the exact component, trust boundary, or control surface being changed.",
                "- Capture the rollback or fail-safe behavior if the change is incomplete.",
                "",
                "Evidence to close",
                f"- Re-run the review against: {evidence_line}",
                "- Attach implementation proof such as config, PR link, test output, or runtime validation.",
                "",
                "Owner handoff",
                f"- Suggested owner: {finding.owner or 'Unassigned'}",
                "- Define the verification checkpoint before marking this mitigated.",
            ]
        )
        return title, summary, body

    if kind == "verification_note":
        title = f"Verification note · {finding.title}"
        summary = (
            "Verification checklist to prove the intended control exists and actually changes the review outcome."
        )
        body = "\n".join(
            [
                "Control to verify",
                f"- {next_action}",
                "",
                "Context",
                f"- {context_line}",
                f"- Why this matters: {finding.why_now}",
                "",
                "Checks to perform",
                "- Confirm the control exists in the live architecture, not just on paper.",
                "- Validate negative and abuse-path behavior, not just the happy path.",
                "- Record exactly which environment, tenant, or workload was checked.",
                "",
                "Evidence to collect",
                f"- Relevant sources: {evidence_line}",
                "- Capture screenshots, config snippets, test output, or audit records.",
                "",
                "Exit criteria",
                "- The reviewer can point to concrete proof and explain why the queue bucket can be reduced or closed.",
            ]
        )
        return title, summary, body

    title = f"Evidence request · {finding.title}"
    summary = "Specific evidence request needed to move the finding from missing proof into a verifiable engineering review."
    body = "\n".join(
        [
            "Requested evidence",
            f"- Provide the proof needed to support `{finding.title}`.",
            "",
            "Context",
            f"- {context_line}",
            f"- Review blocker: {finding.why_now}",
            "",
            "What to provide",
            f"- Current evidence references: {evidence_line}",
            "- Architecture or control screenshots that show the real deployment state.",
            "- Policy, IAM, IaC, or runtime artifacts that prove the control is actually enforced.",
            "- Any exceptions, manual steps, or compensating controls that change the verdict.",
            "",
            "Definition of done",
            "- The reviewer can move this item out of Gather Evidence and explain the remaining action with confidence.",
        ]
    )
    return title, summary, body


def build_security_review_artifact(
    finding: SecurityReviewFinding,
    *,
    kind: ReviewArtifactKind,
    threat: ThreatResponse | None = None,
) -> SecurityReviewArtifact:
    title, summary, body = _artifact_body_sections(finding, kind=kind, threat=threat)
    return SecurityReviewArtifact(
        id=str(uuid4()),
        kind=kind,
        title=title,
        summary=summary,
        body=body,
        created_at=datetime.now(UTC).isoformat(),
    )


def replace_artifact_of_kind(
    artifacts: list[SecurityReviewArtifact] | None,
    replacement: SecurityReviewArtifact,
) -> list[SecurityReviewArtifact]:
    remaining = [item for item in artifacts or [] if item.kind != replacement.kind]
    remaining.append(replacement)
    return sorted(remaining, key=lambda item: item.created_at, reverse=True)
