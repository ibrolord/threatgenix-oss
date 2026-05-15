import type {
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewRiskAcceptanceRequest,
  ThreatResponse,
} from "../types/api";
import { SecurityReviewFindingDetail } from "./SecurityReviewFindingDetail";
import {
  findingTitle,
  isComplianceFinding,
  reviewPriorityLabel,
  reviewPriorityTone,
  reviewQueueBucketLabel,
  reviewStatusLabel,
} from "./securityReviewWorkbenchUtils";

interface SecurityReviewCompliancePanelProps {
  findingsResponse: SecurityReviewFindingListResponse | null;
  threats: ThreatResponse[];
  selectedFindingId: string | null;
  onSelectFinding: (findingId: string) => void;
  onQueueBucketChange: (finding: SecurityReviewFinding, bucket: ReviewQueueBucket) => void;
  onStatusChange: (finding: SecurityReviewFinding, status: ReviewStatus) => void;
  onRiskAcceptanceSubmit?: (
    finding: SecurityReviewFinding,
    payload: SecurityReviewRiskAcceptanceRequest,
  ) => Promise<void> | void;
  queueUpdatingId?: string | null;
  statusUpdatingId?: string | null;
}

export function SecurityReviewCompliancePanel({
  findingsResponse,
  threats,
  selectedFindingId,
  onSelectFinding,
  onQueueBucketChange,
  onStatusChange,
  onRiskAcceptanceSubmit,
  queueUpdatingId = null,
  statusUpdatingId = null,
}: SecurityReviewCompliancePanelProps): JSX.Element {
  if (!findingsResponse) {
    return <div className="application-review-panel-state">Loading compliance workspace…</div>;
  }

  const findings = findingsResponse.findings.filter(isComplianceFinding);
  const readinessBlockers = findings.filter(
    (finding) =>
      finding.review_status !== "accepted" &&
      finding.review_status !== "dismissed" &&
      (finding.queue_bucket === "fix_now" ||
        (finding.display_kind !== "evidence_gap" && finding.needs_engineering_change)),
  );
  const evidenceNeeded = findings.filter(
    (finding) =>
      finding.review_status !== "accepted" &&
      finding.review_status !== "dismissed" &&
      (finding.queue_bucket === "gather_evidence" || finding.needs_evidence),
  );
  const controlFollowThrough = findings.filter(
    (finding) =>
      !readinessBlockers.includes(finding) &&
      !evidenceNeeded.includes(finding) &&
      finding.review_status !== "accepted" &&
      finding.review_status !== "dismissed",
  );
  const resolvedOrAccepted = findings.filter((finding) =>
    ["accepted", "dismissed", "mitigated"].includes(finding.review_status),
  );
  const sectionOrder = [
    ...readinessBlockers,
    ...evidenceNeeded,
    ...controlFollowThrough,
    ...resolvedOrAccepted,
  ];
  const selectedFinding =
    findings.find((item) => item.id === selectedFindingId) ?? sectionOrder[0] ?? null;
  const selectedThreat =
    selectedFinding?.threat_id
      ? threats.find((item) => item.id === selectedFinding.threat_id) ?? null
      : null;

  const sections = [
    {
      key: "blockers",
      title: "Readiness blockers",
      description: "Control or compliance work that blocks a clean review outcome right now.",
      findings: readinessBlockers,
    },
    {
      key: "evidence",
      title: "Evidence needed",
      description: "Items that stay open until the review has concrete proof or validation.",
      findings: evidenceNeeded,
    },
    {
      key: "follow-through",
      title: "Control follow-through",
      description: "Real compliance work that should stay visible, but does not interrupt the team today.",
      findings: controlFollowThrough,
    },
    {
      key: "resolved",
      title: "Accepted or resolved",
      description: "Closed or accepted compliance decisions that still belong in the review record.",
      findings: resolvedOrAccepted,
    },
  ].filter((section) => section.findings.length > 0);

  return (
    <div className="security-review-mode-layout">
      <div className="security-review-mode-list">
        <section className="security-review-compliance-summary">
          <div className="security-review-mode-header">
            <h4>Compliance</h4>
            <span>{findings.length}</span>
          </div>
          <p>
            Turn framework mapping into concrete evidence work, control changes, and readiness blockers.
          </p>
          <div className="security-review-compliance-metrics">
            <div className="security-review-compliance-metric">
              <strong>{readinessBlockers.length}</strong>
              <span>blocker{readinessBlockers.length === 1 ? "" : "s"}</span>
            </div>
            <div className="security-review-compliance-metric">
              <strong>{evidenceNeeded.length}</strong>
              <span>need evidence</span>
            </div>
            <div className="security-review-compliance-metric">
              <strong>{controlFollowThrough.length}</strong>
              <span>follow-through</span>
            </div>
          </div>
        </section>

        {findings.length === 0 ? (
          <div className="security-review-detail-empty">
            <strong>No compliance blockers yet.</strong>
            <p>When the review finds missing evidence, control gaps, or framework-mapped work, it will show up here with the next action.</p>
          </div>
        ) : null}

        {sections.map((section) => (
          <section key={section.key} className="security-review-compliance-section">
            <div className="security-review-mode-header">
              <h4>{section.title}</h4>
              <span>{section.findings.length}</span>
            </div>
            <p className="security-review-compliance-copy">{section.description}</p>
            <div className="security-review-mode-scroll">
              {section.findings.map((finding) => (
                <button
                  key={finding.id}
                  type="button"
                  className={`security-review-mode-item${selectedFinding?.id === finding.id ? " security-review-mode-item-active" : ""}`}
                  onClick={() => onSelectFinding(finding.id)}
                >
                  <div className="security-review-queue-card-topline">
                    <span className={`application-review-priority-chip ${reviewPriorityTone(finding.priority)}`}>
                      {reviewPriorityLabel(finding.priority)}
                    </span>
                    <span className="security-review-detail-tag">
                      Status: {reviewStatusLabel(finding.review_status)}
                    </span>
                  </div>
                  <strong>{findingTitle(finding)}</strong>
                  <p>{finding.next_best_action ?? finding.next_step ?? finding.why_now}</p>
                  <div className="security-review-detail-tags">
                    {finding.queue_bucket ? (
                      <span className="security-review-detail-tag">{reviewQueueBucketLabel(finding.queue_bucket)}</span>
                    ) : null}
                    <span className="security-review-detail-tag">
                      {finding.needs_evidence ? "Evidence gap" : "Control action"}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
      <div className="security-review-mode-detail">
        <SecurityReviewFindingDetail
          finding={selectedFinding}
          threat={selectedThreat}
          queueUpdating={queueUpdatingId === selectedFinding?.id}
          statusUpdating={statusUpdatingId === selectedFinding?.id}
          onQueueBucketChange={
            selectedFinding
              ? (bucket) => onQueueBucketChange(selectedFinding, bucket)
              : undefined
          }
          onStatusChange={
            selectedFinding
              ? (status) => onStatusChange(selectedFinding, status)
              : undefined
          }
          onRiskAcceptanceSubmit={
            selectedFinding && onRiskAcceptanceSubmit
              ? (payload) => onRiskAcceptanceSubmit(selectedFinding, payload)
              : undefined
          }
        />
      </div>
    </div>
  );
}
