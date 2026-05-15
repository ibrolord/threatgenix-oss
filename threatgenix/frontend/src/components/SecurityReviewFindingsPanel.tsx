import type {
  ReviewArtifactKind,
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewRiskAcceptanceRequest,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";
import { SecurityReviewFindingDetail } from "./SecurityReviewFindingDetail";
import { ThreatDeepDivePanel } from "./ThreatDeepDivePanel";
import {
  findingTitle,
  isFindingsModeFinding,
  reviewPriorityLabel,
  reviewPriorityTone,
} from "./securityReviewWorkbenchUtils";

interface SecurityReviewFindingsPanelProps {
  threatModelId: string;
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  findingsResponse: SecurityReviewFindingListResponse | null;
  selectedFindingId: string | null;
  onSelectFinding: (findingId: string) => void;
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
}

export function SecurityReviewFindingsPanel({
  threatModelId,
  model,
  threats,
  findingsResponse,
  selectedFindingId,
  onSelectFinding,
  onQueueBucketChange,
  onStatusChange,
  onRiskAcceptanceSubmit,
  onCreateArtifact,
  queueUpdatingId = null,
  statusUpdatingId = null,
  artifactCreatingId = null,
  artifactCreatingKind = null,
}: SecurityReviewFindingsPanelProps): JSX.Element {
  if (!findingsResponse) {
    return <div className="application-review-panel-state">Loading findings workspace…</div>;
  }

  const findings = findingsResponse.findings.filter(isFindingsModeFinding);
  const selectedFinding =
    findings.find((item) => item.id === selectedFindingId) ?? findings[0] ?? null;
  const selectedThreat =
    selectedFinding?.threat_id
      ? threats.find((item) => item.id === selectedFinding.threat_id) ?? null
      : null;

  if (findings.length === 0) {
    return (
      <div className="security-review-mode-layout">
        <div className="security-review-mode-list">
          <div className="security-review-mode-header">
            <h4>Findings</h4>
            <span>0</span>
          </div>
          <div className="security-review-detail-empty">
            <strong>No application findings yet.</strong>
            <p>
              This does not mean the application is secure. Connect evidence,
              build the DFD, and run the review before relying on this workspace
              for a release decision.
            </p>
          </div>
        </div>
        <div className="security-review-mode-detail">
          <div className="security-review-detail-empty">
            <strong>Evidence-limited review state.</strong>
            <p>
              Findings will appear here after ThreatGenix has
              enough architecture, repository, scanner, or reviewer evidence to
              separate real work from missing proof.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="security-review-mode-layout">
      <div className="security-review-mode-list">
        <div className="security-review-mode-header">
          <h4>Findings</h4>
          <span>{findings.length}</span>
        </div>
        <div className="security-review-mode-scroll">
          {findings.map((finding) => (
            <button
              key={finding.id}
              type="button"
              className={`security-review-mode-item${selectedFinding?.id === finding.id ? " security-review-mode-item-active" : ""}`}
              onClick={() => onSelectFinding(finding.id)}
            >
              <span className={`application-review-priority-chip ${reviewPriorityTone(finding.priority)}`}>
                {reviewPriorityLabel(finding.priority)}
              </span>
              <strong>{findingTitle(finding)}</strong>
              <p>{finding.rationale_excerpt ?? finding.why_now}</p>
            </button>
          ))}
        </div>
      </div>
      <div className="security-review-mode-detail">
        {selectedFinding ? (
          <>
            <SecurityReviewFindingDetail
              finding={selectedFinding}
              threat={selectedThreat}
              queueUpdating={queueUpdatingId === selectedFinding.id}
              statusUpdating={statusUpdatingId === selectedFinding.id}
              artifactCreatingKind={
                artifactCreatingId === selectedFinding.id ? artifactCreatingKind : null
              }
              onQueueBucketChange={(bucket) => onQueueBucketChange(selectedFinding, bucket)}
              onStatusChange={(status) => onStatusChange(selectedFinding, status)}
              onRiskAcceptanceSubmit={
                onRiskAcceptanceSubmit
                  ? (payload) => onRiskAcceptanceSubmit(selectedFinding, payload)
                  : undefined
              }
              onCreateArtifact={(kind) => onCreateArtifact(selectedFinding, kind)}
            />
            {selectedFinding.threat_id ? (
              <div className="security-review-threat-context-panel">
                <ThreatDeepDivePanel
                  threatModelId={threatModelId}
                  model={model}
                  threats={threats}
                  focusedThreatId={selectedFinding.threat_id}
                />
              </div>
            ) : null}
          </>
        ) : (
          <SecurityReviewFindingDetail
            finding={null}
          />
        )}
      </div>
    </div>
  );
}
