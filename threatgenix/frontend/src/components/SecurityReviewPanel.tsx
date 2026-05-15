import type {
  ReviewArtifactKind,
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewApplicationSummary,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewRiskAcceptanceRequest,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";
import { SecurityReviewFindingDetail } from "./SecurityReviewFindingDetail";
import {
  findingTitle,
  REVIEW_QUEUE_BUCKET_ORDER,
  REVIEW_TERMINAL_STATUS_ORDER,
  reviewPriorityLabel,
  reviewPriorityTone,
  reviewQueueBucketLabel,
  reviewStatusLabel,
} from "./securityReviewWorkbenchUtils";

interface SecurityReviewPanelProps {
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  summary: SecurityReviewApplicationSummary | null;
  findingsResponse: SecurityReviewFindingListResponse | null;
  selectedFindingId: string | null;
  onSelectFinding: (findingId: string) => void;
  onOpenWorkspace: (finding: SecurityReviewFinding) => void;
  onQueueBucketChange: (finding: SecurityReviewFinding, bucket: ReviewQueueBucket) => void;
  onStatusChange: (finding: SecurityReviewFinding, status: ReviewStatus) => void;
  onRiskAcceptanceSubmit?: (
    finding: SecurityReviewFinding,
    payload: SecurityReviewRiskAcceptanceRequest,
  ) => Promise<void> | void;
  onCreateArtifact: (finding: SecurityReviewFinding, kind: ReviewArtifactKind) => void;
  queueUpdatingId?: string | null;
  statusUpdatingId?: string | null;
  artifactCreatingId?: string | null;
  artifactCreatingKind?: ReviewArtifactKind | null;
  hasDfdContent?: boolean | null;
}

export function SecurityReviewPanel({
  model,
  threats,
  summary,
  findingsResponse,
  selectedFindingId,
  onSelectFinding,
  onOpenWorkspace,
  onQueueBucketChange,
  onStatusChange,
  onRiskAcceptanceSubmit,
  onCreateArtifact,
  queueUpdatingId = null,
  statusUpdatingId = null,
  artifactCreatingId = null,
  artifactCreatingKind = null,
  hasDfdContent = null,
}: SecurityReviewPanelProps): JSX.Element {
  if (!summary || !findingsResponse) {
    return <div className="application-review-panel-state">Loading security review…</div>;
  }

  const activeFindings = findingsResponse.findings.filter(
    (finding) =>
      finding.review_status === "open" || finding.review_status === "in_progress"
  );
  const selectedFinding =
    findingsResponse.findings.find((item) => item.id === selectedFindingId) ??
    findingsResponse.findings.find((item) => item.id === findingsResponse.default_finding_id) ??
    activeFindings[0] ??
    findingsResponse.findings[0] ??
    null;
  const selectedThreat =
    selectedFinding?.threat_id
      ? threats.find((item) => item.id === selectedFinding.threat_id) ?? null
      : null;

  return (
    <div className="security-review-workbench">
      <section className="application-review-hero">
        <div className="application-review-hero-topline">
          <span className={`application-review-priority-chip ${reviewPriorityTone(summary.overall_priority)}`}>
            {reviewPriorityLabel(summary.overall_priority)}
          </span>
          <span className="application-review-updated">
            {hasDfdContent === false ? "Model readiness review" : "Semantic application review"}
          </span>
        </div>
        <h4>What Matters Now</h4>
        <p>{summary.focus_statement}</p>
        <div className="application-review-context-line">
          <span>{model.data_classification}</span>
          <span>
            {model.regulatory_scope.length > 0
              ? model.regulatory_scope.join(", ")
              : "No regulatory scope attached"}
          </span>
          <span>
            {summary.coverage.open_threats} {hasDfdContent === false ? "generated findings" : "active findings"}
          </span>
          <span>{summary.coverage.attached_evidence_sources} evidence sources attached</span>
          <span>{summary.review_delta_summary.new_findings} new in this review window</span>
        </div>
        <div className="security-review-queue-legend" aria-label="Review queue meaning">
          <span><strong>Fix Now</strong> immediate engineering work</span>
          <span><strong>Verify</strong> control or implementation check</span>
          <span><strong>Gather Evidence</strong> review is blocked on proof</span>
          <span><strong>Backlog</strong> real work that does not interrupt the team today</span>
        </div>
      </section>

      <section className="security-review-queue-layout">
        <div className="security-review-queue-column">
          {REVIEW_QUEUE_BUCKET_ORDER.map((bucket) => {
            const items = activeFindings.filter((finding) => finding.queue_bucket === bucket);
            if (items.length === 0) return null;
            return (
              <section key={bucket} className="security-review-queue-section">
                <div className="security-review-queue-header">
                  <h5>{reviewQueueBucketLabel(bucket)}</h5>
                  <span>{items.length}</span>
                </div>
                <div className="security-review-queue-list">
                  {items.map((finding) => (
                    <button
                      key={finding.id}
                      type="button"
                      className={`security-review-queue-card${selectedFinding?.id === finding.id ? " security-review-queue-card-active" : ""}`}
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
                      <p>{finding.rationale_excerpt ?? finding.why_now}</p>
                    </button>
                  ))}
                </div>
              </section>
            );
          })}

          {REVIEW_TERMINAL_STATUS_ORDER.map((status) => {
            const items = findingsResponse.findings.filter((finding) => finding.review_status === status);
            if (items.length === 0) return null;
            return (
              <section key={status} className="security-review-queue-section security-review-queue-section-secondary">
                <div className="security-review-queue-header">
                  <h5>{reviewStatusLabel(status)}</h5>
                  <span>{items.length}</span>
                </div>
                <div className="security-review-queue-list">
                  {items.map((finding) => (
                    <button
                      key={finding.id}
                      type="button"
                      className={`security-review-queue-card security-review-queue-card-secondary${selectedFinding?.id === finding.id ? " security-review-queue-card-active" : ""}`}
                      onClick={() => onSelectFinding(finding.id)}
                    >
                      <div className="security-review-queue-card-topline">
                        <strong>{findingTitle(finding)}</strong>
                        <span className="security-review-detail-tag">
                          Status: {reviewStatusLabel(finding.review_status)}
                        </span>
                      </div>
                      <p>{finding.next_step ?? finding.why_now}</p>
                    </button>
                  ))}
                </div>
              </section>
            );
          })}
        </div>

        <div className="security-review-detail-column">
          <SecurityReviewFindingDetail
            finding={selectedFinding}
            threat={selectedThreat}
            queueUpdating={queueUpdatingId === selectedFinding?.id}
            statusUpdating={statusUpdatingId === selectedFinding?.id}
            artifactCreatingKind={
              artifactCreatingId === selectedFinding?.id ? artifactCreatingKind : null
            }
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
            onCreateArtifact={
              selectedFinding
                ? (kind) => onCreateArtifact(selectedFinding, kind)
                : undefined
            }
          />

          {selectedFinding ? (
            <button
              type="button"
              className="security-review-open-workspace-btn"
              onClick={() => onOpenWorkspace(selectedFinding)}
            >
              Open In {selectedFinding.primary_mode === "compliance" ? "Compliance" : "Findings"}
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}
