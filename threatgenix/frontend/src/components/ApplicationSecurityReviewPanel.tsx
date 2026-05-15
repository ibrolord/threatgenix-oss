import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  SecurityReviewApplicationSummary,
  SecurityReviewBucketCount,
  SecurityReviewFindingSummary,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";

interface ApplicationSecurityReviewPanelProps {
  threatModelId: string;
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  refreshToken?: number;
}

function priorityLabel(priority: SecurityReviewApplicationSummary["overall_priority"]): string {
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

function priorityTone(priority: SecurityReviewApplicationSummary["overall_priority"]): string {
  switch (priority) {
    case "p0_blocker":
      return "application-review-priority-critical";
    case "p1_now":
      return "application-review-priority-high";
    case "p2_sprint":
      return "application-review-priority-medium";
    default:
      return "application-review-priority-low";
  }
}

function findingTitle(finding: SecurityReviewFindingSummary): string {
  return finding.display_id ? `${finding.display_id} · ${finding.title}` : finding.title;
}

function countValue(counts: SecurityReviewBucketCount[], key: string): number {
  return counts.find((item) => item.key === key)?.count ?? 0;
}

export function ApplicationSecurityReviewPanel({
  threatModelId,
  model,
  threats,
  refreshToken = 0,
}: ApplicationSecurityReviewPanelProps): JSX.Element {
  const [summary, setSummary] = useState<SecurityReviewApplicationSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api
      .getThreatModelSecurityReview(threatModelId)
      .then((response) => {
        if (cancelled) return;
        setSummary(response);
      })
      .catch((nextError: Error) => {
        if (cancelled) return;
        setError(nextError.message);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [threatModelId, refreshToken]);

  const metrics = useMemo(() => {
    if (!summary) return [];
    return [
      {
        label: "P0 / P1 queue",
        value: countValue(summary.priority_counts, "p0_blocker") + countValue(summary.priority_counts, "p1_now"),
        note: "Immediate interruption work",
      },
      {
        label: "Blind spots",
        value: summary.blind_spots.length,
        note: "Systemic evidence or control gaps",
      },
      {
        label: "Attack paths",
        value: summary.coverage.attack_paths,
        note: "Multi-step attacker chains",
      },
      {
        label: "Accepted / reopened",
        value: summary.risk_acceptance_summary.active + summary.risk_acceptance_summary.reopened,
        note: "Review continuity pressure",
      },
    ];
  }, [summary]);

  if (loading) {
    return <div className="application-review-panel-state">Loading full application review…</div>;
  }

  if (error || summary === null) {
    return (
      <div className="application-review-panel-state">
        <strong>Application review unavailable.</strong>
        <p>{error ?? "The review summary could not be loaded right now."}</p>
      </div>
    );
  }

  return (
    <div className="application-review-panel">
      <section className="application-review-hero">
        <div className="application-review-hero-topline">
          <span className={`application-review-priority-chip ${priorityTone(summary.overall_priority)}`}>
            {priorityLabel(summary.overall_priority)}
          </span>
          <span className="application-review-updated">
            Updated from the live model and evidence
          </span>
        </div>
        <h4>Full Application Security Review</h4>
        <p>{summary.focus_statement}</p>
        <div className="application-review-context-line">
          <span>{model.data_classification}</span>
          <span>{model.regulatory_scope.length > 0 ? model.regulatory_scope.join(", ") : "No regulatory scope attached"}</span>
          <span>{summary.coverage.open_threats} active threats</span>
          <span>{threats.length} total threats</span>
        </div>
      </section>

      <section className="application-review-metric-grid">
        {metrics.map((metric) => (
          <article key={metric.label} className="application-review-metric-card">
            <span className="application-review-metric-label">{metric.label}</span>
            <strong>{metric.value}</strong>
            <p>{metric.note}</p>
          </article>
        ))}
      </section>

      <section className="application-review-section">
        <div className="application-review-section-header">
          <h5>What Is Real Right Now</h5>
          <span>{summary.top_findings.length} leading finding(s)</span>
        </div>
        {summary.top_findings.length > 0 ? (
          <div className="application-review-finding-list">
            {summary.top_findings.map((finding) => (
              <article
                key={`${finding.finding_key ?? finding.title}:${finding.priority}`}
                className="application-review-finding-card"
              >
                <div className="application-review-finding-header">
                  <span className={`application-review-priority-chip ${priorityTone(finding.priority)}`}>
                    {priorityLabel(finding.priority)}
                  </span>
                  {finding.systemic ? (
                    <span className="application-review-finding-kind">Systemic</span>
                  ) : (
                    <span className="application-review-finding-kind">Threat-linked</span>
                  )}
                </div>
                <strong>{findingTitle(finding)}</strong>
                {finding.rationale_excerpt ? <p>{finding.rationale_excerpt}</p> : null}
                <div className="application-review-finding-meta">
                  {finding.entry_point ? <span>Entry: {finding.entry_point}</span> : null}
                  {finding.target_asset ? <span>Target: {finding.target_asset}</span> : null}
                  <span>{finding.related_attack_path_count} path(s)</span>
                  <span>{finding.evidence_adjustment_count} evidence adjustment(s)</span>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">
            No application-level findings are currently elevated above monitor mode.
          </p>
        )}
      </section>

      <section className="application-review-section">
        <div className="application-review-section-header">
          <h5>Blind Spots And Evidence Gaps</h5>
          <span>{summary.blind_spots.length} gap(s)</span>
        </div>
        {summary.blind_spots.length > 0 ? (
          <ul className="application-review-bullets">
            {summary.blind_spots.map((finding) => (
              <li key={`${finding.finding_key ?? finding.title}:blind-spot`}>
                <strong>{findingTitle(finding)}</strong>
                {finding.next_step ? ` — ${finding.next_step}` : ""}
              </li>
            ))}
          </ul>
        ) : (
          <p className="application-review-empty">
            No systemic blind spots are currently outranking the live threat signal.
          </p>
        )}
      </section>

      <section className="application-review-section">
        <div className="application-review-section-header">
          <h5>Attack Paths And Review Continuity</h5>
          <span>{summary.attack_paths.length} synthesized path(s)</span>
        </div>
        <div className="application-review-dual-grid">
          <div className="application-review-subpanel">
            {summary.attack_paths.length > 0 ? (
              <ul className="application-review-bullets">
                {summary.attack_paths.map((path) => (
                  <li key={path.path_id}>
                    <strong>{path.chain_description}</strong>
                    {path.entry_point || path.target_asset
                      ? ` — ${path.entry_point ?? "Unknown entry"} to ${path.target_asset ?? "Unknown target"}`
                      : ""}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="application-review-empty">
                No multi-step attack chains are currently synthesized across the model.
              </p>
            )}
          </div>
          <div className="application-review-subpanel">
            <ul className="application-review-bullets">
              <li>
                <strong>{summary.risk_acceptance_summary.active}</strong> active accepted risk item(s)
              </li>
              <li>
                <strong>{summary.risk_acceptance_summary.reopened}</strong> reopened acceptance(s)
              </li>
              <li>
                <strong>{summary.review_delta_summary.escalated_findings}</strong> escalated since the last review
              </li>
              <li>
                <strong>{summary.review_delta_summary.new_findings}</strong> new finding(s) in this review window
              </li>
            </ul>
          </div>
        </div>
      </section>

      <section className="application-review-section">
        <div className="application-review-section-header">
          <h5>What To Do Next</h5>
          <span>{summary.next_steps.length} recommended step(s)</span>
        </div>
        <ul className="application-review-bullets">
          {summary.next_steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
