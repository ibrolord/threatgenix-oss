import { useEffect, useState } from "react";

import { api } from "../../api/client";
import type {
  ThreatModelElementCoverageSummary,
  ThreatModelReviewFreshnessSummary,
  ThreatModelScorecardResponse,
} from "../../types/api";

interface ThreatModelScorecardPanelProps {
  threatModelId: string;
  refreshToken?: number;
}

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function formatStatusLabel(status: ThreatModelScorecardResponse["overall_status"]): string {
  switch (status) {
    case "good":
      return "Strong";
    case "attention":
      return "Needs Attention";
    case "action_required":
      return "Action Required";
    default:
      return status;
  }
}

function formatReviewFreshnessLabel(status: ThreatModelReviewFreshnessSummary["status"]): string {
  switch (status) {
    case "current":
      return "Current";
    case "stale":
      return "Stale";
    case "pending":
      return "Pending";
    case "changes_requested":
      return "Changes Requested";
    case "unreviewed":
      return "Unreviewed";
    default:
      return status;
  }
}

function getReviewFreshnessTone(
  status: ThreatModelReviewFreshnessSummary["status"]
): ThreatModelScorecardResponse["overall_status"] {
  switch (status) {
    case "current":
      return "good";
    case "stale":
    case "changes_requested":
      return "action_required";
    case "pending":
    case "unreviewed":
      return "attention";
    default:
      return "attention";
  }
}

function formatSignedDelta(value: number, label: string): string {
  const prefix = value > 0 ? "+" : "";
  return `${prefix}${value} ${label}`;
}

function formatDateTime(value: string | null): string | null {
  if (!value) {
    return null;
  }
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function renderCoverageRow(
  title: string,
  noun: string,
  summary: ThreatModelElementCoverageSummary
): JSX.Element {
  return (
    <div className="tm-scorecard-coverage-row">
      <div>
        <strong>{title}</strong>
        <p>
          {summary.with_stride_coverage}/{summary.total} with STRIDE coverage,{" "}
          {summary.with_assumptions} with anchored assumptions.
        </p>
        {summary.uncovered_labels.length > 0 ? (
          <p className="tm-scorecard-inline-note">
            Gaps: {summary.uncovered_labels.join(", ")}
          </p>
        ) : null}
      </div>
      <span className="tm-scorecard-coverage-metric">
        {summary.without_stride_coverage === 0
          ? "Covered"
          : pluralize(summary.without_stride_coverage, noun)}
      </span>
    </div>
  );
}

export function ThreatModelScorecardPanel({
  threatModelId,
  refreshToken = 0,
}: ThreatModelScorecardPanelProps): JSX.Element {
  const [summary, setSummary] = useState<ThreatModelScorecardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const nextSummary = await api.getThreatModelScorecard(threatModelId);
        if (!cancelled) {
          setSummary(nextSummary);
        }
      } catch (caught) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Failed to load scorecard");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [refreshToken, threatModelId]);

  if (loading) {
    return (
      <section className="tm-section">
        <h3>Review Scorecard</h3>
        <div className="tm-scorecard-panel">
          <p className="tm-scorecard-empty">Calculating review readiness…</p>
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="tm-section">
        <h3>Review Scorecard</h3>
        <div className="tm-scorecard-panel">
          <p className="tm-scorecard-empty">{error}</p>
        </div>
      </section>
    );
  }

  if (!summary) {
    return (
      <section className="tm-section">
        <h3>Review Scorecard</h3>
        <div className="tm-scorecard-panel">
          <p className="tm-scorecard-empty">
            The scorecard is unavailable right now. Refresh the page and try again.
          </p>
        </div>
      </section>
    );
  }

  const unresolvedAssumptions =
    summary.assumption_summary.open + summary.assumption_summary.challenged;
  const qualityIssues =
    summary.quality_gates.blocking_count + summary.quality_gates.warning_count;
  const residualHighRisk =
    (summary.residual_risk_by_level.Critical ?? 0) + (summary.residual_risk_by_level.High ?? 0);
  const totalCoverageGaps =
    summary.coverage_summary.nodes.without_stride_coverage
    + summary.coverage_summary.edges.without_stride_coverage
    + summary.coverage_summary.boundaries.without_stride_coverage;
  const freshnessTone = getReviewFreshnessTone(summary.review_freshness.status);
  const reviewDate = formatDateTime(summary.review_freshness.reviewed_at);
  const reviewDiff = summary.review_freshness.changes_since_review;

  return (
    <section className="tm-section">
      <div className="tm-scorecard-header">
        <div>
          <h3>Review Scorecard</h3>
          <p>{summary.overall_summary}</p>
        </div>
        <span className={`tm-scorecard-status tm-scorecard-status-${summary.overall_status}`}>
          {formatStatusLabel(summary.overall_status)}
        </span>
      </div>

      <div className="tm-scorecard-grid">
        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Completeness</span>
          <strong>{summary.architecture_validation.completeness_score}/100</strong>
          <p>
            {summary.architecture_validation.mapped_discovered_components}/
            {summary.architecture_validation.discovered_components} discovered components mapped.
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">DFD Quality</span>
          <strong>{pluralize(qualityIssues, "issue")}</strong>
          <p>
            {summary.quality_gates.blocking_count} blocking, {summary.quality_gates.warning_count} warning.
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Assumptions</span>
          <strong>{pluralize(summary.assumption_summary.total, "entry")}</strong>
          <p>
            {pluralize(unresolvedAssumptions, "unresolved assumption")}, {summary.assumption_summary.validated} validated.
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Mitigations</span>
          <strong>{pluralize(summary.mitigation_summary.active, "active threat")}</strong>
          <p>
            {summary.mitigation_summary.with_plan} with plans, {summary.mitigation_summary.with_owner} with owners.
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Controls</span>
          <strong>{pluralize(summary.control_summary.total, "control")}</strong>
          <p>
            {summary.control_summary.implemented} implemented, {summary.control_summary.with_evidence} with evidence.
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Reviews</span>
          <strong>{pluralize(summary.review_summary.total, "review")}</strong>
          <p>
            {summary.review_summary.pending} pending, {summary.review_summary.changes_requested} requesting changes.
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Coverage</span>
          <strong>{summary.coverage_summary.coverage_score}/100</strong>
          <p>
            {summary.coverage_summary.covered_elements}/{summary.coverage_summary.total_elements} model elements with mapped STRIDE coverage.
            {summary.coverage_summary.total_elements === 0
              ? " Add nodes, flows, and trust boundaries to measure coverage."
              : ""}
          </p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Review Freshness</span>
          <strong>{formatReviewFreshnessLabel(summary.review_freshness.status)}</strong>
          <p>{summary.review_freshness.summary}</p>
        </article>

        <article className="tm-scorecard-card">
          <span className="tm-scorecard-label">Residual Risk</span>
          <strong>{pluralize(residualHighRisk, "high-risk finding", "high-risk findings")}</strong>
          <p>
            {summary.residual_risk_by_level.Medium ?? 0} medium, {summary.residual_risk_by_level.Low ?? 0} low.
          </p>
        </article>
      </div>

      <div className="tm-scorecard-detail-grid">
        <article className="tm-scorecard-detail-card">
          <h4>Coverage Gaps</h4>
          <p className="tm-scorecard-empty">
            {summary.coverage_summary.total_elements === 0
              ? "The model has no nodes, flows, or trust boundaries yet."
              : `${pluralize(totalCoverageGaps, "gap")} still have no mapped STRIDE coverage.`}
          </p>
          <div className="tm-scorecard-coverage-list">
            {renderCoverageRow("Nodes", "node", summary.coverage_summary.nodes)}
            {renderCoverageRow("Flows", "flow", summary.coverage_summary.edges)}
            {renderCoverageRow("Boundaries", "boundary gap", summary.coverage_summary.boundaries)}
          </div>
          <p className="tm-scorecard-inline-note">
            {summary.coverage_summary.missing_stride_categories.length > 0
              ? `Missing model-level STRIDE categories: ${summary.coverage_summary.missing_stride_categories.join(", ")}.`
              : `All STRIDE categories are represented somewhere in the model: ${summary.coverage_summary.stride_categories_seen.join(", ")}.`}
          </p>
        </article>

        <article className="tm-scorecard-detail-card">
          <div className="tm-scorecard-detail-header">
            <h4>Review Freshness</h4>
            <span className={`tm-scorecard-status tm-scorecard-status-${freshnessTone}`}>
              {formatReviewFreshnessLabel(summary.review_freshness.status)}
            </span>
          </div>
          <p className="tm-scorecard-empty">{summary.review_freshness.summary}</p>
          {summary.review_freshness.reviewed_snapshot_name ? (
            <p className="tm-scorecard-inline-note">
              Last approved snapshot: {summary.review_freshness.reviewed_snapshot_name}
              {reviewDate ? ` · ${reviewDate}` : ""}
            </p>
          ) : null}
          {summary.review_freshness.latest_review_title ? (
            <p className="tm-scorecard-inline-note">
              Latest review: {summary.review_freshness.latest_review_title}
              {summary.review_freshness.latest_review_status
                ? ` (${summary.review_freshness.latest_review_status.replace("_", " ")})`
                : ""}
            </p>
          ) : null}
          {reviewDiff ? (
            <>
              <div className="tm-scorecard-diff-grid">
                <span>{formatSignedDelta(reviewDiff.node_delta, "nodes")}</span>
                <span>{formatSignedDelta(reviewDiff.edge_delta, "flows")}</span>
                <span>{formatSignedDelta(reviewDiff.boundary_delta, "boundaries")}</span>
                <span>{formatSignedDelta(reviewDiff.threat_delta, "threats")}</span>
              </div>
              {reviewDiff.added_nodes.length > 0 ? (
                <p className="tm-scorecard-inline-note">
                  Added nodes: {reviewDiff.added_nodes.join(", ")}
                </p>
              ) : null}
              {reviewDiff.removed_nodes.length > 0 ? (
                <p className="tm-scorecard-inline-note">
                  Removed nodes: {reviewDiff.removed_nodes.join(", ")}
                </p>
              ) : null}
              {reviewDiff.added_threats.length > 0 ? (
                <p className="tm-scorecard-inline-note">
                  Added threats: {reviewDiff.added_threats.join(", ")}
                </p>
              ) : null}
              {reviewDiff.removed_threats.length > 0 ? (
                <p className="tm-scorecard-inline-note">
                  Removed threats: {reviewDiff.removed_threats.join(", ")}
                </p>
              ) : null}
            </>
          ) : null}
        </article>
      </div>

      <div className="tm-scorecard-actions">
        <h4>Next Actions</h4>
        {summary.top_actions.length > 0 ? (
          <ul className="tm-scorecard-action-list">
            {summary.top_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        ) : (
          <p className="tm-scorecard-empty">No major follow-up is currently flagged.</p>
        )}
      </div>
    </section>
  );
}
