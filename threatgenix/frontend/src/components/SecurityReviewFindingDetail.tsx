import { useState, type FormEvent } from "react";

import type {
  ReviewArtifactKind,
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewFinding,
  SecurityReviewRiskAcceptanceRequest,
  ThreatResponse,
} from "../types/api";
import {
  findingTitle,
  reviewFindingKindLabel,
  reviewPriorityLabel,
  reviewPriorityTone,
  reviewQueueBucketLabel,
  reviewStatusLabel,
  reviewArtifactKindLabel,
} from "./securityReviewWorkbenchUtils";

interface SecurityReviewFindingDetailProps {
  finding: SecurityReviewFinding | null;
  threat?: ThreatResponse | null;
  queueUpdating?: boolean;
  statusUpdating?: boolean;
  riskAcceptanceSubmitting?: boolean;
  artifactCreatingKind?: ReviewArtifactKind | null;
  onQueueBucketChange?: (bucket: ReviewQueueBucket) => void;
  onStatusChange?: (status: ReviewStatus) => void;
  onRiskAcceptanceSubmit?: (
    payload: SecurityReviewRiskAcceptanceRequest,
  ) => Promise<void> | void;
  onCreateArtifact?: (kind: ReviewArtifactKind) => void;
}

interface RiskAcceptanceFormState {
  accepted_by: string;
  expires_at: string;
  acceptance_rationale: string;
  compensating_control: string;
}

const THREAT_STATUS_OPTIONS: ReviewStatus[] = [
  "open",
  "in_progress",
  "mitigated",
  "accepted",
  "dismissed",
];
const SYSTEMIC_STATUS_OPTIONS: ReviewStatus[] = [
  "open",
  "in_progress",
  "accepted",
  "dismissed",
];

function reviewSignalLabel(
  active: boolean,
  onLabel: string,
  offLabel: string,
): string {
  return active ? onLabel : offLabel;
}

function codeRelationshipLabel(
  relationship: SecurityReviewFinding["code_links"][number]["relationship"],
): string {
  switch (relationship) {
    case "confirms_missing_control":
      return "Missing control";
    case "shows_compensating_control":
      return "Control evidence";
    case "needs_evidence":
      return "Needs evidence";
    case "unmodeled_surface":
      return "Needs DFD mapping";
    default:
      return relationship;
  }
}

function toDateInputValue(value: string | null | undefined): string {
  if (!value) {
    return "";
  }
  return value.slice(0, 10);
}

function formatRiskAcceptanceDate(value: string): string {
  return value.slice(0, 10);
}

function createRiskAcceptanceFormState(
  finding: SecurityReviewFinding,
): RiskAcceptanceFormState {
  return {
    accepted_by: finding.risk_acceptance?.accepted_by ?? finding.owner ?? "",
    expires_at: toDateInputValue(finding.risk_acceptance?.expires_at),
    acceptance_rationale:
      finding.risk_acceptance?.acceptance_rationale ??
      finding.note ??
      finding.next_best_action ??
      "",
    compensating_control:
      finding.risk_acceptance?.compensating_control ?? finding.note ?? "",
  };
}

function normalizeExpiryInput(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const normalizedValue = /^\d{4}-\d{2}-\d{2}$/.test(trimmed)
    ? `${trimmed}T00:00:00Z`
    : trimmed;
  const parsedDate = new Date(normalizedValue);
  if (Number.isNaN(parsedDate.getTime())) {
    throw new Error("Expiry must be a valid date or ISO timestamp.");
  }
  return parsedDate.toISOString();
}

export function SecurityReviewFindingDetail({
  finding,
  threat = null,
  queueUpdating = false,
  statusUpdating = false,
  riskAcceptanceSubmitting = false,
  artifactCreatingKind = null,
  onQueueBucketChange,
  onStatusChange,
  onRiskAcceptanceSubmit,
  onCreateArtifact,
}: SecurityReviewFindingDetailProps): JSX.Element {
  const [copiedArtifactId, setCopiedArtifactId] = useState<string | null>(null);
  const [riskAcceptanceDraft, setRiskAcceptanceDraft] =
    useState<RiskAcceptanceFormState | null>(null);
  const [riskAcceptanceError, setRiskAcceptanceError] = useState<string | null>(
    null,
  );

  if (!finding) {
    return (
      <div className="security-review-detail-empty">
        <strong>Select a review finding.</strong>
        <p>
          Use the queue or the findings list to inspect the highest-signal work
          in context.
        </p>
      </div>
    );
  }

  const activeFinding = finding;
  const statusOptions = threat
    ? THREAT_STATUS_OPTIONS
    : SYSTEMIC_STATUS_OPTIONS;
  const artifacts = finding.artifacts ?? [];
  const codeLinks = finding.code_links ?? [];
  const suggestedArtifactKinds: ReviewArtifactKind[] = [];
  if (finding.needs_engineering_change || finding.queue_bucket === "fix_now") {
    suggestedArtifactKinds.push("remediation_note");
  }
  if (finding.queue_bucket === "verify") {
    suggestedArtifactKinds.push("verification_note");
  }
  if (finding.needs_evidence || finding.queue_bucket === "gather_evidence") {
    suggestedArtifactKinds.push("evidence_request");
  }
  if (suggestedArtifactKinds.length === 0) {
    suggestedArtifactKinds.push("remediation_note");
  }

  async function handleCopyArtifact(artifactId: string, body: string) {
    try {
      await navigator.clipboard.writeText(body);
      setCopiedArtifactId(artifactId);
      window.setTimeout(
        () =>
          setCopiedArtifactId((current) =>
            current === artifactId ? null : current,
          ),
        1800,
      );
    } catch {
      setCopiedArtifactId(null);
    }
  }

  function handleLifecycleClick(status: ReviewStatus) {
    if (status === "accepted" && onRiskAcceptanceSubmit) {
      setRiskAcceptanceDraft(createRiskAcceptanceFormState(activeFinding));
      setRiskAcceptanceError(null);
      return;
    }
    onStatusChange?.(status);
  }

  async function handleRiskAcceptanceSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    if (!riskAcceptanceDraft || !onRiskAcceptanceSubmit) {
      return;
    }
    const rationale = riskAcceptanceDraft.acceptance_rationale.trim();
    if (!rationale) {
      setRiskAcceptanceError("Acceptance rationale is required.");
      return;
    }
    let expiresAt: string | null;
    try {
      expiresAt = normalizeExpiryInput(riskAcceptanceDraft.expires_at);
    } catch (nextError) {
      setRiskAcceptanceError(
        nextError instanceof Error ? nextError.message : "Expiry is invalid.",
      );
      return;
    }
    setRiskAcceptanceError(null);
    try {
      await onRiskAcceptanceSubmit({
        accepted_by: riskAcceptanceDraft.accepted_by.trim() || null,
        expires_at: expiresAt,
        acceptance_rationale: rationale,
        compensating_control:
          riskAcceptanceDraft.compensating_control.trim() || null,
      });
      setRiskAcceptanceDraft(null);
    } catch (nextError) {
      setRiskAcceptanceError(
        nextError instanceof Error
          ? nextError.message
          : "Risk acceptance failed.",
      );
    }
  }

  return (
    <article className="security-review-detail-card">
      <div className="security-review-detail-topline">
        <span
          className={`security-review-detail-priority ${reviewPriorityTone(finding.priority)}`}
        >
          {reviewPriorityLabel(finding.priority)}
        </span>
        <span className="security-review-detail-kind">
          {reviewFindingKindLabel(finding.display_kind)}
        </span>
      </div>
      <h5>{findingTitle(finding)}</h5>
      <p>{finding.why_now}</p>
      <div className="security-review-detail-meta">
        <span>Status: {reviewStatusLabel(finding.review_status)}</span>
        {finding.queue_bucket ? (
          <span>Queue: {reviewQueueBucketLabel(finding.queue_bucket)}</span>
        ) : null}
        {finding.entry_point ? <span>Entry: {finding.entry_point}</span> : null}
        {finding.impacted_assets[0] ? (
          <span>Asset: {finding.impacted_assets.join(", ")}</span>
        ) : null}
        {finding.owner ? <span>Owner: {finding.owner}</span> : null}
        {finding.due_at ? (
          <span>Due: {new Date(finding.due_at).toLocaleDateString()}</span>
        ) : null}
      </div>

      {finding.rationale_excerpt ? (
        <div className="security-review-detail-section">
          <strong>Why This Matters</strong>
          <p>{finding.rationale_excerpt}</p>
        </div>
      ) : null}

      {finding.risk_acceptance ? (
        <div className="security-review-detail-section">
          <strong>Risk Acceptance</strong>
          <p>
            {finding.risk_acceptance.status.replace(/_/g, " ")}
            {finding.risk_acceptance.accepted_by
              ? ` by ${finding.risk_acceptance.accepted_by}`
              : ""}
            {finding.risk_acceptance.expires_at
              ? ` until ${formatRiskAcceptanceDate(finding.risk_acceptance.expires_at)}`
              : ""}
            .
          </p>
          {finding.risk_acceptance.acceptance_rationale ? (
            <p>{finding.risk_acceptance.acceptance_rationale}</p>
          ) : null}
          {finding.risk_acceptance.compensating_control ? (
            <p>Control: {finding.risk_acceptance.compensating_control}</p>
          ) : null}
          {finding.risk_acceptance.reopen_triggers.length > 0 ? (
            <p>
              Reopen triggers: {finding.risk_acceptance.reopen_triggers.join(", ")}
            </p>
          ) : null}
        </div>
      ) : null}

      {riskAcceptanceDraft && onRiskAcceptanceSubmit ? (
        <form
          className="security-review-acceptance-form"
          onSubmit={(event) => void handleRiskAcceptanceSubmit(event)}
        >
          <strong>Accept Risk</strong>
          {riskAcceptanceError ? (
            <p className="security-review-acceptance-error" role="alert">
              {riskAcceptanceError}
            </p>
          ) : null}
          <label>
            Accepted by
            <input
              type="text"
              value={riskAcceptanceDraft.accepted_by}
              disabled={riskAcceptanceSubmitting}
              onChange={(event) =>
                setRiskAcceptanceDraft((current) =>
                  current
                    ? { ...current, accepted_by: event.target.value }
                    : current,
                )
              }
            />
          </label>
          <label>
            Expiry
            <input
              type="text"
              placeholder="YYYY-MM-DD"
              value={riskAcceptanceDraft.expires_at}
              disabled={riskAcceptanceSubmitting}
              onChange={(event) =>
                setRiskAcceptanceDraft((current) =>
                  current
                    ? { ...current, expires_at: event.target.value }
                    : current,
                )
              }
            />
          </label>
          <label>
            Rationale
            <textarea
              value={riskAcceptanceDraft.acceptance_rationale}
              disabled={riskAcceptanceSubmitting}
              required
              rows={4}
              onChange={(event) =>
                setRiskAcceptanceDraft((current) =>
                  current
                    ? {
                        ...current,
                        acceptance_rationale: event.target.value,
                      }
                    : current,
                )
              }
            />
          </label>
          <label>
            Compensating control
            <textarea
              value={riskAcceptanceDraft.compensating_control}
              disabled={riskAcceptanceSubmitting}
              rows={3}
              onChange={(event) =>
                setRiskAcceptanceDraft((current) =>
                  current
                    ? {
                        ...current,
                        compensating_control: event.target.value,
                      }
                    : current,
                )
              }
            />
          </label>
          <div className="security-review-detail-actions">
            <button
              type="submit"
              className="security-review-action-chip security-review-action-chip-active"
              disabled={riskAcceptanceSubmitting}
            >
              {riskAcceptanceSubmitting ? "Saving acceptance..." : "Save acceptance"}
            </button>
            <button
              type="button"
              className="security-review-action-chip"
              disabled={riskAcceptanceSubmitting}
              onClick={() => {
                setRiskAcceptanceDraft(null);
                setRiskAcceptanceError(null);
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <div className="security-review-detail-section">
        <strong>Review Signals</strong>
        <div className="security-review-detail-tags">
          <span className="security-review-detail-tag">
            {reviewSignalLabel(finding.is_real, "Real now", "Contextual")}
          </span>
          <span className="security-review-detail-tag">
            {reviewSignalLabel(finding.is_urgent, "Urgent", "Not urgent yet")}
          </span>
          <span className="security-review-detail-tag">
            {reviewSignalLabel(
              finding.is_exploitable_in_context,
              "Exploitable in context",
              "Exploitability not yet proven",
            )}
          </span>
          <span className="security-review-detail-tag">
            {reviewSignalLabel(
              finding.is_regulatory_or_control_relevant,
              "Control / regulatory relevant",
              "Hardening oriented",
            )}
          </span>
          <span className="security-review-detail-tag">
            {reviewSignalLabel(
              finding.needs_engineering_change,
              "Needs engineering change",
              "No engineering change implied",
            )}
          </span>
          <span className="security-review-detail-tag">
            {reviewSignalLabel(
              finding.needs_evidence,
              "Needs evidence",
              "Evidence not primary gap",
            )}
          </span>
          <span className="security-review-detail-tag">
            Score {finding.numeric_score}
          </span>
          {finding.exploitability ? (
            <span className="security-review-detail-tag">
              Exploitability {finding.exploitability}
            </span>
          ) : null}
          {finding.urgency ? (
            <span className="security-review-detail-tag">
              Urgency {finding.urgency}
            </span>
          ) : null}
          {finding.regulatory_pressure ? (
            <span className="security-review-detail-tag">
              Regulatory {finding.regulatory_pressure}
            </span>
          ) : null}
        </div>
      </div>

      {finding.next_best_action || finding.next_step ? (
        <div className="security-review-detail-section">
          <strong>Next Best Action</strong>
          <p>{finding.next_best_action ?? finding.next_step}</p>
        </div>
      ) : null}

      {codeLinks.length > 0 ? (
        <div className="security-review-detail-section">
          <strong>Code Evidence</strong>
          <div className="security-review-code-evidence-list">
            {codeLinks.map((link, index) => (
              <div
                key={[
                  link.surface_id,
                  link.source_file,
                  link.line_number ?? "no-line",
                  link.relationship,
                  index,
                ].join("-")}
                className="security-review-code-evidence-row"
              >
                <div className="security-review-code-evidence-topline">
                  <span className="security-review-detail-tag">
                    {codeRelationshipLabel(link.relationship)}
                  </span>
                  <code>
                    {link.source_file}
                    {link.line_number ? `:${link.line_number}` : ""}
                  </code>
                </div>
                <strong>{link.surface_name}</strong>
                <p>{link.summary}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {onCreateArtifact ? (
        <div className="security-review-detail-section">
          <strong>Engineer Artifacts</strong>
          <p className="security-review-detail-helper">
            Draft a concrete artifact the engineer can reuse in the ticket,
            review, or control follow-up.
          </p>
          <div className="security-review-detail-actions">
            {suggestedArtifactKinds.map((kind) => (
              <button
                key={kind}
                type="button"
                className={`security-review-action-chip${artifactCreatingKind === kind ? " security-review-action-chip-active" : ""}`}
                disabled={artifactCreatingKind !== null}
                onClick={() => onCreateArtifact(kind)}
              >
                {artifactCreatingKind === kind
                  ? `Drafting ${reviewArtifactKindLabel(kind)}…`
                  : reviewArtifactKindLabel(kind)}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {artifacts.length > 0 ? (
        <div className="security-review-detail-section">
          <strong>Saved Artifacts</strong>
          <div className="security-review-artifact-list">
            {artifacts.map((artifact) => (
              <article
                key={artifact.id}
                className="security-review-artifact-card"
              >
                <div className="security-review-artifact-topline">
                  <span className="security-review-detail-tag">
                    {reviewArtifactKindLabel(artifact.kind)}
                  </span>
                  <span>{new Date(artifact.created_at).toLocaleString()}</span>
                </div>
                <h6>{artifact.title}</h6>
                <p>{artifact.summary}</p>
                <pre className="security-review-artifact-body">
                  {artifact.body}
                </pre>
                <div className="security-review-detail-actions">
                  <button
                    type="button"
                    className="security-review-action-chip"
                    onClick={() =>
                      void handleCopyArtifact(artifact.id, artifact.body)
                    }
                  >
                    {copiedArtifactId === artifact.id ? "Copied" : "Copy"}
                  </button>
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {finding.evidence_refs.length > 0 ? (
        <div className="security-review-detail-section">
          <strong>Evidence Sources</strong>
          <div className="security-review-detail-tags">
            {finding.evidence_refs.map((item, index) => (
              <span
                key={`${item}-${index}`}
                className="security-review-detail-tag"
              >
                {item}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {onQueueBucketChange ? (
        <div className="security-review-detail-section">
          <strong>Queue Bucket</strong>
          <div className="security-review-detail-actions">
            {(
              [
                "fix_now",
                "verify",
                "gather_evidence",
                "backlog",
              ] as ReviewQueueBucket[]
            ).map((bucket) => (
              <button
                key={bucket}
                type="button"
                className={`security-review-action-chip${finding.queue_bucket === bucket ? " security-review-action-chip-active" : ""}`}
                aria-pressed={finding.queue_bucket === bucket}
                disabled={queueUpdating}
                onClick={() => onQueueBucketChange(bucket)}
              >
                {reviewQueueBucketLabel(bucket)}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {onStatusChange ? (
        <div className="security-review-detail-section">
          <strong>Lifecycle</strong>
          <div className="security-review-detail-actions">
            {statusOptions.map((status) => (
              <button
                key={status}
                type="button"
                className={`security-review-action-chip${finding.review_status === status ? " security-review-action-chip-active" : ""}`}
                aria-pressed={finding.review_status === status}
                disabled={statusUpdating}
                onClick={() => handleLifecycleClick(status)}
              >
                {reviewStatusLabel(status)}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {threat ? (
        <div className="security-review-detail-section">
          <strong>Threat Context</strong>
          <p>
            STRIDE: {threat.stride_category} · Severity: {threat.severity} ·
            Source: {threat.source}
          </p>
        </div>
      ) : null}
    </article>
  );
}
