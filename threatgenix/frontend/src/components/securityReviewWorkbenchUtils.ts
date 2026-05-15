import type {
  ReviewArtifactKind,
  ReviewDisplayKind,
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewFinding,
  SecurityReviewRiskAcceptanceRequest,
  ThreatResponse,
  ThreatTriageRequest,
} from "../types/api";

export const REVIEW_QUEUE_BUCKET_ORDER: ReviewQueueBucket[] = [
  "fix_now",
  "verify",
  "gather_evidence",
  "backlog",
];

export const REVIEW_TERMINAL_STATUS_ORDER: ReviewStatus[] = [
  "accepted",
  "mitigated",
  "dismissed",
];

export function reviewQueueBucketLabel(bucket: ReviewQueueBucket): string {
  switch (bucket) {
    case "fix_now":
      return "Fix Now";
    case "verify":
      return "Verify";
    case "gather_evidence":
      return "Gather Evidence";
    default:
      return "Backlog";
  }
}

export function reviewStatusLabel(status: ReviewStatus): string {
  switch (status) {
    case "in_progress":
      return "In Progress";
    case "accepted":
      return "Accepted";
    case "mitigated":
      return "Mitigated";
    case "dismissed":
      return "Dismissed";
    default:
      return "Open";
  }
}

export function reviewPriorityLabel(priority: SecurityReviewFinding["priority"]): string {
  switch (priority) {
    case "p0_blocker":
      return "P0 blocker";
    case "p1_now":
      return "P1 now";
    case "p2_sprint":
      return "P2 sprint";
    case "p3_backlog":
      return "P3 backlog";
    default:
      return "P4 monitor";
  }
}

export function reviewPriorityTone(priority: SecurityReviewFinding["priority"]): string {
  switch (priority) {
    case "p0_blocker":
      return "security-review-priority-critical";
    case "p1_now":
      return "security-review-priority-high";
    case "p2_sprint":
      return "security-review-priority-medium";
    default:
      return "security-review-priority-low";
  }
}

export function reviewFindingKindLabel(kind: ReviewDisplayKind): string {
  switch (kind) {
    case "control_gap":
      return "Control gap";
    case "compliance_gap":
      return "Compliance gap";
    case "evidence_gap":
      return "Evidence gap";
    case "hardening":
      return "Hardening";
    case "misconfiguration":
      return "Misconfiguration";
    case "pr_risk":
      return "PR risk";
    case "incident_signal":
      return "Incident signal";
    default:
      return "Threat";
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function findingTitle(finding: SecurityReviewFinding): string {
  const title = finding.title?.trim() ?? "";
  if (!finding.display_id) return title;
  const duplicatePrefixPattern = new RegExp(
    `^${escapeRegExp(finding.display_id)}(?:\\s*[·:\\-]\\s*|\\s+)`,
    "i"
  );
  const normalizedTitle = title.replace(duplicatePrefixPattern, "").trim();
  return normalizedTitle ? `${finding.display_id} · ${normalizedTitle}` : finding.display_id;
}

export function isComplianceFinding(finding: SecurityReviewFinding): boolean {
  return ["compliance_gap", "control_gap", "evidence_gap"].includes(finding.display_kind);
}

export function isFindingsModeFinding(finding: SecurityReviewFinding): boolean {
  return !isComplianceFinding(finding);
}

export function reviewArtifactKindLabel(kind: ReviewArtifactKind): string {
  switch (kind) {
    case "verification_note":
      return "Verification Note";
    case "evidence_request":
      return "Evidence Request";
    default:
      return "Remediation Note";
  }
}

export function buildThreatTriagePayload(
  threat: ThreatResponse,
  status: ThreatTriageRequest["status"],
  riskAcceptance?: SecurityReviewRiskAcceptanceRequest | null,
): ThreatTriageRequest {
  return {
    status,
    dismiss_reason:
      status === "Dismissed"
        ? threat.dismiss_reason ?? "Dismissed from the security review."
        : threat.dismiss_reason,
    mitigation_plan: threat.mitigation_plan,
    mitigation_owner: threat.mitigation_owner,
    due_date: threat.due_date,
    mitigation_notes: threat.mitigation_notes,
    control_effectiveness: threat.control_effectiveness,
    residual_risk_level: threat.residual_risk_level,
    risk_acceptance:
      status === "Accepted" && riskAcceptance ? riskAcceptance : undefined,
  };
}
