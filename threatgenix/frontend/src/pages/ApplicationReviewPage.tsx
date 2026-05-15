import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type {
  ApplicationReview,
  ApplicationReviewAIExplanation,
  ApplicationReviewArtifact,
  ApplicationReviewContextPacket,
  ApplicationReviewContextSearchResponse,
  ApplicationReviewDecision,
  AgentReviewStatus,
} from "../types/api";

function decisionLabel(decision: string | null): string {
  if (!decision) return "Pending";
  return decision.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function sourceRefLabel(ref: Record<string, unknown>): string {
  const type = typeof ref.type === "string" ? ref.type : "source";
  const value =
    typeof ref.path === "string"
      ? ref.path
      : typeof ref.key === "string"
        ? ref.key
        : typeof ref.id === "string"
          ? ref.id
          : "";
  return value ? `${type}: ${value}` : type;
}

function shortHash(value: string | null | undefined): string {
  if (!value) return "Unavailable";
  return value.length > 12 ? `${value.slice(0, 12)}...` : value;
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function recordString(record: Record<string, unknown> | null | undefined, key: string): string | null {
  const value = record?.[key];
  return typeof value === "string" ? value : null;
}

function buildCustomerReport(
  review: ApplicationReview,
  packet: ApplicationReviewContextPacket | null,
  context: ApplicationReviewContextSearchResponse | null,
  artifact: ApplicationReviewArtifact | null,
  decision: ApplicationReviewDecision | null,
  aiExplanation: ApplicationReviewAIExplanation | null,
): string {
  const currentDecision = decision?.decision ?? review.decision ?? "pending";
  const findings =
    context?.results.filter((entry) => entry.item_type === "scanner_finding") ?? [];
  const missing = packet?.missing_evidence ?? [];
  const evidenceHashes =
    decision?.evidence_hashes ?? packet?.entries.map((entry) => entry.content_hash) ?? [];
  const findingLines = findings.length
    ? findings
        .map((finding, index) => {
          const refs = finding.source_refs.map(sourceRefLabel).join(", ") || "No source refs";
          return `${index + 1}. ${finding.title}\n   Evidence: ${refs}\n   Hash: ${shortHash(finding.content_hash)}`;
        })
        .join("\n")
    : "No scanner findings were indexed for this review.";
  const gapLines = missing.length
    ? missing.map((item) => `- ${item}`).join("\n")
    : "- No missing evidence reported.";
  const aiSummary = aiExplanation?.output?.summary ?? "No grounded AI explanation is available yet.";
  const fixPlan = aiExplanation?.output?.fix_plan.length
    ? aiExplanation.output.fix_plan
        .map((step, index) => `${index + 1}. ${step.title}\n   ${step.remediation}`)
        .join("\n")
    : artifact?.fix_plan.length
      ? artifact.fix_plan
          .map(
            (step, index) =>
              `${index + 1}. ${step.title}\n   ${step.action}\n   Verify: ${step.verification}`,
          )
          .join("\n")
    : "No grounded fix plan is available yet.";
  const evidenceChainLines = artifact?.evidence_chains.length
    ? artifact.evidence_chains
        .slice(0, 10)
        .map((chain, index) => {
          const refs = chain.source_refs.map(sourceRefLabel).join(", ") || "No source refs";
          return `${index + 1}. ${chain.title}\n   Status: ${chain.status}${chain.stale_reason ? ` (${chain.stale_reason})` : ""}\n   Evidence: ${refs}\n   Hash: ${chain.content_hash}`;
        })
        .join("\n")
    : "No evidence chains are available yet.";
  const graphSummary = artifact?.graph_slice
    ? `${artifact.graph_slice.nodes.length} nodes, ${artifact.graph_slice.edges.length} edges`
    : "Unavailable";
  const rerunLines = artifact?.rerun_history.length
    ? artifact.rerun_history
        .map(
          (entry, index) =>
            `${index + 1}. ${entry.status} / ${decisionLabel(entry.decision)} / ${entry.commit_sha ?? "no commit"} / ${formatDateTime(entry.updated_at)}`,
        )
        .join("\n")
    : "No rerun history is available yet.";
  return [
    `# Security Review Report: ${review.app_name}`,
    "",
    `Decision: ${decisionLabel(currentDecision)}`,
    `Status: ${review.status}`,
    `Invocation: ${review.invocation_surface.toUpperCase()} / ${review.input_kind}`,
    `Commit: ${review.commit_sha ?? "Not provided"}`,
    `Evidence snapshot: ${packet?.evidence_snapshot_hash ?? "Unavailable"}`,
    "",
    "## Executive Summary",
    decision?.reason ?? review.result_summary ?? "No evaluated decision summary is available yet.",
    "",
    "## Grounded AI Explanation",
    aiSummary,
    "",
    "## Grounded Fix Plan",
    fixPlan,
    "",
    "## Evidence Chains",
    evidenceChainLines,
    "",
    "## Graph Slice",
    graphSummary,
    "",
    "## Rerun History",
    rerunLines,
    "",
    "## Evidence-Backed Findings",
    findingLines,
    "",
    "## Evidence Gaps",
    gapLines,
    "",
    "## Evidence Hashes",
    evidenceHashes.length
      ? evidenceHashes.map((hash) => `- ${hash}`).join("\n")
      : "- No evidence hashes available.",
  ].join("\n");
}

function ApplicationReviewPage() {
  const { reviewId } = useParams<{ reviewId: string }>();
  const [review, setReview] = useState<ApplicationReview | null>(null);
  const [artifact, setArtifact] = useState<ApplicationReviewArtifact | null>(null);
  const [context, setContext] = useState<ApplicationReviewContextSearchResponse | null>(null);
  const [packet, setPacket] = useState<ApplicationReviewContextPacket | null>(null);
  const [aiExplanation, setAiExplanation] = useState<ApplicationReviewAIExplanation | null>(null);
  const [agentStatus, setAgentStatus] = useState<AgentReviewStatus | null>(null);
  const [decision, setDecision] = useState<ApplicationReviewDecision | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);

  const loadReview = useCallback(async () => {
    if (!reviewId) return;
    setLoading(true);
    setError(null);
    try {
      const [nextReview, nextArtifact, nextContext, nextPacket, nextAIExplanation, nextAgentStatus] = await Promise.all([
        api.getApplicationReview(reviewId),
        api.getApplicationReviewArtifact(reviewId).catch(() => null),
        api.searchApplicationReviewContext(reviewId, "", 50),
        api.getApplicationReviewContextPacket(reviewId, "", 50),
        api.getApplicationReviewAIExplanation(reviewId, "", 50).catch(() => null),
        api.getAgentReviewStatus(reviewId).catch(() => null),
      ]);
      setReview(nextReview);
      setArtifact(nextArtifact);
      setContext(nextContext);
      setPacket(nextPacket);
      setAiExplanation(nextAIExplanation);
      setAgentStatus(nextAgentStatus);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Review failed to load.");
    } finally {
      setLoading(false);
    }
  }, [reviewId]);

  useEffect(() => {
    void loadReview();
  }, [loadReview]);

  const rawEvidence = useMemo(
    () => artifact?.raw_evidence ?? context?.results ?? [],
    [artifact?.raw_evidence, context?.results],
  );
  const scannerFindings = useMemo(
    () => rawEvidence.filter((entry) => entry.item_type === "scanner_finding"),
    [rawEvidence],
  );
  const missingEvidence = packet?.missing_evidence ?? [];
  const artifactMissingEvidence = artifact?.missing_evidence ?? [];
  const allMissingEvidence = Array.from(new Set([...missingEvidence, ...artifactMissingEvidence]));
  const evidenceChains = artifact?.evidence_chains ?? [];
  const graphSlice = artifact?.graph_slice ?? { nodes: [], edges: [], missing_context: [] };
  const artifactFixPlan = artifact?.fix_plan ?? [];
  const acceptedRisks = artifact?.accepted_risks ?? [];
  const rerunHistory = artifact?.rerun_history ?? [];
  const decisionRecord = artifact?.decision_record ?? null;
  const durableWebUrl = artifact?.web_url ?? agentStatus?.web_url ?? window.location.href;
  const decisionSnapshotHash =
    decision?.evidence_snapshot_hash ??
    recordString(decisionRecord, "evidence_snapshot_hash") ??
    packet?.evidence_snapshot_hash ??
    null;
  const decisionEngineVersion =
    decision?.decision_engine_version ?? recordString(decisionRecord, "decision_engine_version");
  const decisionTrace = decision?.decision_trace ?? (
    Array.isArray(decisionRecord?.decision_trace)
      ? decisionRecord.decision_trace.filter((item): item is string => typeof item === "string")
      : []
  );
  const contextTypeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of rawEvidence) {
      counts.set(entry.item_type, (counts.get(entry.item_type) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort(([left], [right]) => left.localeCompare(right));
  }, [rawEvidence]);
  const customerReport = useMemo(
    () => (review ? buildCustomerReport(review, packet, context, artifact, decision, aiExplanation) : ""),
    [aiExplanation, artifact, context, decision, packet, review],
  );

  const handleRebuild = async () => {
    if (!reviewId) return;
    setBusy(true);
    try {
      await api.rebuildApplicationReviewContextIndex(reviewId);
      await loadReview();
    } finally {
      setBusy(false);
    }
  };

  const handleEvaluate = async () => {
    if (!reviewId) return;
    setBusy(true);
    try {
      const nextDecision = await api.evaluateApplicationReviewDecision(reviewId);
      setDecision(nextDecision);
      await loadReview();
    } finally {
      setBusy(false);
    }
  };

  const handleCopyReport = async () => {
    if (!customerReport) return;
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable.");
      }
      await navigator.clipboard.writeText(customerReport);
      setCopyNotice("Copied report.");
    } catch {
      setCopyNotice("Copy unavailable.");
    }
  };

  if (!reviewId) {
    return <div className="page-loading">Review not found.</div>;
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="dfd-spinner" />
        <span>Loading application review...</span>
      </div>
    );
  }

  if (error || !review) {
    return (
      <div className="not-found-page">
        <div className="not-found-card">
          <h2 className="not-found-code">404</h2>
          <h3 className="not-found-title">Application review not found</h3>
          <p className="not-found-copy">
            This review may have been deleted, or your current workspace may not have access.
          </p>
          <Link to="/dashboard" className="btn-create not-found-link">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="application-review-page">
      <section className="application-review-header">
        <div>
          <Link to="/dashboard" className="tm-back-link">
            Back to Dashboard
          </Link>
          <h2>{review.app_name}</h2>
          <p>
            {review.invocation_surface.toUpperCase()} review for{" "}
            {review.commit_sha ? `commit ${review.commit_sha}` : review.input_kind}
          </p>
        </div>
        <div className={`application-review-decision application-review-decision-${review.decision ?? "pending"}`}>
          <span>Decision</span>
          <strong>{decisionLabel(decision?.decision ?? review.decision)}</strong>
        </div>
      </section>

      <section className="application-review-actions" aria-label="Review actions">
        <button type="button" className="tm-secondary-btn" onClick={handleRebuild} disabled={busy}>
          Rebuild Context
        </button>
        <button type="button" className="tm-primary-btn" onClick={handleEvaluate} disabled={busy}>
          Evaluate Decision
        </button>
        <button type="button" className="tm-secondary-btn" onClick={handleCopyReport} disabled={!customerReport}>
          Copy Report
        </button>
        {copyNotice ? <span className="application-review-action-note">{copyNotice}</span> : null}
      </section>

      <section className="application-review-section">
        <div className="application-review-section-heading">
          <div>
            <h3>Invoke Anywhere</h3>
            <p>
              Authenticated terminal and agent entry points for this exact tenant-scoped review.
            </p>
          </div>
          {agentStatus?.web_url ? (
            <a className="tm-secondary-btn" href={agentStatus.web_url}>
              Open Web Review
            </a>
          ) : null}
        </div>
        <div className="application-review-command-grid">
          {(agentStatus?.terminal_commands ?? []).map((item) => (
            <article key={item.label}>
              <strong>{item.label}</strong>
              <p>{item.description}</p>
              <code>{item.command}</code>
            </article>
          ))}
          {!agentStatus?.terminal_commands.length ? (
            <p className="application-review-empty">
              Agent status metadata is unavailable. The review itself loaded successfully.
            </p>
          ) : null}
        </div>
        <div className="application-review-source-row application-review-tool-row">
          {(agentStatus?.agent_tools ?? []).map((tool) => (
            <span key={tool.name}>
              {tool.method} {tool.name}
            </span>
          ))}
        </div>
      </section>

      <section className="application-review-grid">
        <article>
          <h3>Review Artifact</h3>
          <dl>
            <div>
              <dt>Durable URL</dt>
              <dd className="application-review-mono">{durableWebUrl}</dd>
            </div>
            <div>
              <dt>Raw Evidence</dt>
              <dd>{artifact?.raw_evidence_count ?? rawEvidence.length} entries</dd>
            </div>
            <div>
              <dt>Source References</dt>
              <dd>{artifact?.source_ref_count ?? rawEvidence.reduce((count, entry) => count + entry.source_refs.length, 0)}</dd>
            </div>
            <div>
              <dt>Redaction</dt>
              <dd>{artifact?.redacted ? "Enabled" : "Unavailable"}</dd>
            </div>
          </dl>
        </article>

        <article>
          <h3>Decision Summary</h3>
          <dl>
            <div>
              <dt>Status</dt>
              <dd>{review.status}</dd>
            </div>
            <div>
              <dt>Reason</dt>
              <dd>{decision?.reason ?? review.result_summary ?? "No decision has been evaluated yet."}</dd>
            </div>
            <div>
              <dt>Scanner Only</dt>
              <dd>{decision?.scanner_only ? "Yes" : "No"}</dd>
            </div>
            <div>
              <dt>Engine</dt>
              <dd className="application-review-mono">{decisionEngineVersion ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>{decision?.replayed ? "Replayed" : decisionRecord ? "Recorded" : "Not recorded"}</dd>
            </div>
          </dl>
        </article>

        <article>
          <h3>Evidence Snapshot</h3>
          <dl>
            <div>
              <dt>Context Entries</dt>
              <dd>{context?.results.length ?? 0}</dd>
            </div>
            <div>
              <dt>Scanner Findings</dt>
              <dd>{scannerFindings.length}</dd>
            </div>
            <div>
              <dt>Snapshot Hash</dt>
              <dd className="application-review-mono">{decisionSnapshotHash ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Evidence Types</dt>
              <dd>
                {contextTypeCounts.length
                  ? contextTypeCounts.map(([type, count]) => `${type}=${count}`).join(", ")
                  : "No indexed context"}
              </dd>
            </div>
          </dl>
        </article>
      </section>

      <section className="application-review-section">
        <h3>Decision Trace</h3>
        {decisionTrace.length ? (
          <div className="application-review-source-row">
            {decisionTrace.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No deterministic decision trace has been recorded yet.</p>
        )}
      </section>

      <section className="application-review-section">
        <div className="application-review-section-heading">
          <div>
            <h3>Evidence Chains</h3>
            <p>Source-backed paths from indexed review evidence to the code, scanner, policy, or document refs supporting it.</p>
          </div>
          <span className="application-review-count">{evidenceChains.length} chains</span>
        </div>
        {evidenceChains.length ? (
          <div className="application-review-list">
            {evidenceChains.map((chain) => (
              <article key={chain.chain_id}>
                <strong>{chain.title}</strong>
                <div className="application-review-source-row">
                  <span>{chain.item_type}</span>
                  <span>{chain.status}</span>
                  {chain.stale_reason ? <span>{chain.stale_reason}</span> : null}
                  <span>{shortHash(chain.content_hash)}</span>
                </div>
                <ol className="application-review-chain-list">
                  {chain.steps.map((step, index) => (
                    <li key={`${chain.chain_id}-${index}`}>
                      <span>{step.step_type}</span>
                      <strong>{step.label}</strong>
                    </li>
                  ))}
                </ol>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No evidence chains are available yet.</p>
        )}
      </section>

      <section className="application-review-section">
        <div className="application-review-section-heading">
          <div>
            <h3>Graph Slice</h3>
            <p>Review-local semantic graph built from the current evidence packet and source refs.</p>
          </div>
          <span className="application-review-count">
            {graphSlice.nodes.length} nodes / {graphSlice.edges.length} edges
          </span>
        </div>
        {graphSlice.nodes.length ? (
          <div className="application-review-graph-layout">
            <div>
              <h4>Nodes</h4>
              <div className="application-review-source-row">
                {graphSlice.nodes.slice(0, 24).map((node) => (
                  <span key={node.id} title={node.id}>
                    {node.node_type}: {node.label}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h4>Edges</h4>
              <div className="application-review-source-row">
                {graphSlice.edges.slice(0, 24).map((edge, index) => (
                  <span key={`${edge.source}-${edge.target}-${index}`}>
                    {edge.relationship}: {shortHash(edge.evidence_hashes[0])}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <p className="application-review-empty">No graph slice can be built until evidence is indexed.</p>
        )}
        {graphSlice.missing_context.length ? (
          <ul className="application-review-compact-list">
            {graphSlice.missing_context.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : null}
      </section>

      <section className="application-review-section">
        <h3>Artifact Fix Plan</h3>
        {artifactFixPlan.length ? (
          <div className="application-review-list">
            {artifactFixPlan.map((step) => (
              <article key={step.title}>
                <strong>{step.title}</strong>
                <p>{step.action}</p>
                <p>
                  <strong>Verify:</strong> {step.verification}
                </p>
                <div className="application-review-source-row">
                  {step.cited_content_hashes.map((hash) => (
                    <span key={hash}>{shortHash(hash)}</span>
                  ))}
                  {step.source_refs.map((ref, index) => (
                    <span key={`${step.title}-${index}`}>{sourceRefLabel(ref)}</span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No artifact fix plan is available yet.</p>
        )}
      </section>

      <section className="application-review-section">
        <h3>Rerun History</h3>
        {rerunHistory.length ? (
          <div className="application-review-list">
            {rerunHistory.map((entry) => (
              <article key={entry.review_id}>
                <strong>{decisionLabel(entry.decision)}</strong>
                <dl className="application-review-inline-dl">
                  <div>
                    <dt>Status</dt>
                    <dd>{entry.status}</dd>
                  </div>
                  <div>
                    <dt>Commit</dt>
                    <dd className="application-review-mono">{entry.commit_sha ?? "Unavailable"}</dd>
                  </div>
                  <div>
                    <dt>Snapshot</dt>
                    <dd className="application-review-mono">{shortHash(entry.evidence_snapshot_hash)}</dd>
                  </div>
                  <div>
                    <dt>Updated</dt>
                    <dd>{formatDateTime(entry.updated_at)}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No rerun history has been recorded yet.</p>
        )}
      </section>

      <section className="application-review-section">
        <h3>Accepted Risks</h3>
        {acceptedRisks.length ? (
          <div className="application-review-list">
            {acceptedRisks.map((risk) => (
              <article key={risk.id}>
                <strong>{risk.title}</strong>
                <p>{risk.body}</p>
                <code>{risk.content_hash}</code>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No accepted risks are indexed for this review.</p>
        )}
      </section>

      <section className="application-review-section">
        <h3>Grounded AI Explanation</h3>
        {aiExplanation?.output ? (
          <div className="application-review-list">
            <article>
              <strong>{decisionLabel(aiExplanation.output.proposed_decision)}</strong>
              <p>{aiExplanation.output.summary}</p>
              <div className="application-review-source-row">
                <span>{aiExplanation.explanation_status}</span>
                <span>{aiExplanation.validation.valid ? "validated" : "invalid"}</span>
              </div>
            </article>
            {aiExplanation.output.fix_plan.map((step) => (
              <article key={step.title}>
                <strong>{step.title}</strong>
                <p>{step.remediation}</p>
                <div className="application-review-source-row">
                  {step.cited_content_hashes.map((hash) => (
                    <span key={hash}>{shortHash(hash)}</span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">
            {aiExplanation?.validation.errors[0] ?? "No grounded AI explanation has been generated yet."}
          </p>
        )}
      </section>

      <section className="application-review-section">
        <h3>Customer-Ready Report</h3>
        <div className="application-review-report-preview">
          <pre>{customerReport}</pre>
        </div>
      </section>

      <section className="application-review-section">
        <h3>Findings</h3>
        {scannerFindings.length ? (
          <div className="application-review-list">
            {scannerFindings.map((finding) => (
              <article key={finding.id}>
                <strong>{finding.title}</strong>
                <p>{finding.body}</p>
                <div className="application-review-source-row">
                  {finding.source_refs.map((ref, index) => (
                    <span key={`${finding.id}-${index}`}>{sourceRefLabel(ref)}</span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No scanner findings are indexed for this review.</p>
        )}
      </section>

      <section className="application-review-section">
        <h3>Missing Evidence</h3>
        {allMissingEvidence.length ? (
          <ul>
            {allMissingEvidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="application-review-empty">No missing evidence was reported by the context packet.</p>
        )}
      </section>

      <section className="application-review-section">
        <h3>Context Packet</h3>
        <div className="application-review-list">
          {(packet?.entries ?? []).map((entry) => (
            <article key={entry.entry_id}>
              <strong>{entry.title}</strong>
              <p>{entry.untrusted_text}</p>
              <code>{entry.content_hash}</code>
            </article>
          ))}
        </div>
      </section>

      <section className="application-review-section">
        <h3>Raw Evidence</h3>
        {rawEvidence.length ? (
          <div className="application-review-list">
            {rawEvidence.map((entry) => (
              <article key={`raw-${entry.id}`}>
                <strong>{entry.title}</strong>
                <div className="application-review-source-row">
                  <span>{entry.item_type}</span>
                  <span>{entry.source_type}</span>
                  <span>{entry.status}</span>
                  {entry.stale_reason ? <span>{entry.stale_reason}</span> : null}
                </div>
                <pre className="application-review-raw-evidence">{entry.body}</pre>
                <code>{entry.content_hash}</code>
                <div className="application-review-source-row">
                  {entry.source_refs.map((ref, index) => (
                    <span key={`${entry.id}-raw-${index}`}>{sourceRefLabel(ref)}</span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="application-review-empty">No raw evidence has been indexed for this review.</p>
        )}
      </section>
    </div>
  );
}

export default ApplicationReviewPage;
