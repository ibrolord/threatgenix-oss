import { useEffect, useState } from "react";

import { api } from "../api/client";
import type {
  AgentCiContract,
  AgentRemediationPlanResponse,
  AgentRemediationProviderWebhookTestResponse,
  AgentReleaseDecision,
  AgentSecurityReviewResponse,
  CustomerSecurityPacketResponse,
  SecurityReviewApplicationSummary,
  SecurityReviewAttackPath,
  SecurityReviewBucketCount,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewFindingSummary,
  ThreatModelResponse,
  ThreatResponse,
  ValidationRunbookResponse,
} from "../types/api";
import {
  reviewFindingKindLabel,
  reviewPriorityLabel,
  reviewPriorityTone,
  reviewQueueBucketLabel,
} from "./securityReviewWorkbenchUtils";

interface SecurityReviewReportPanelProps {
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  summary: SecurityReviewApplicationSummary | null;
  findingsResponse: SecurityReviewFindingListResponse | null;
  onOpenFinding?: (finding: SecurityReviewFinding) => void;
}

interface DistributionSegment {
  key: string;
  label: string;
  count: number;
}

type WebhookProviderSetup = NonNullable<
  AgentRemediationPlanResponse["actions"][number]["ticket_draft"]["callback_setup"]
>;

interface WebhookTestDraft {
  payloadText: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

function bucketCount(counts: SecurityReviewBucketCount[], key: string): number {
  return counts.find((item) => item.key === key)?.count ?? 0;
}

function percent(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

function formatGeneratedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatRiskAcceptanceDate(value: string): string {
  return value.slice(0, 10);
}

function webhookSetupClipboardText(
  setup: WebhookProviderSetup,
): string {
  return [
    `${setup.provider_label} remediation webhook setup`,
    `Callback URL: ${setup.callback_url}`,
    `Action marker: ${setup.action_marker}`,
    `Events: ${setup.event_filters.join(", ")}`,
    `Signature scheme: ${setup.signature_scheme}`,
    `Signature base string: ${setup.signature_base_string}`,
    "Required headers:",
    ...Object.entries(setup.required_headers).map(
      ([name, value]) => `- ${name}: ${value}`,
    ),
    "Registration steps:",
    ...setup.registration_steps.map((step) => `- ${step}`),
    "Signer helper:",
    "python3 threatgenix/backend/scripts/remediation_webhook_signer.py --payload-file ssr-callback-payload.json --provider " +
      setup.provider +
      " --format tester-json",
    setup.signing_secret_hint,
  ].join("\n");
}

function webhookSignerCliClipboardText(
  action: AgentRemediationPlanResponse["actions"][number],
  setup: WebhookProviderSetup,
): string {
  const payloadFile = `ssr-${setup.provider}-callback-payload.json`;
  return [
    `cat > ${payloadFile} <<'JSON'`,
    sampleProviderWebhookPayload(action, setup),
    "JSON",
    "REMEDIATION_WEBHOOK_SIGNATURE_SECRET=\"$SSR_WEBHOOK_SECRET\" \\",
    "python3 threatgenix/backend/scripts/remediation_webhook_signer.py \\",
    `  --payload-file ${payloadFile} \\`,
    `  --provider ${setup.provider} \\`,
    "  --format tester-json",
  ].join("\n");
}

function webhookTestKey(
  action: AgentRemediationPlanResponse["actions"][number],
  setup: WebhookProviderSetup,
): string {
  return `${action.action_id}:${setup.provider}`;
}

function sampleProviderWebhookPayload(
  action: AgentRemediationPlanResponse["actions"][number],
  setup: WebhookProviderSetup,
): string {
  if (setup.provider === "linear") {
    return JSON.stringify(
      {
        action: "update",
        data: {
          identifier: "SEC-42",
          title: action.ticket_draft.title,
          url: "https://linear.app/acme/issue/SEC-42",
          description: `${action.instruction}\n\n${setup.action_marker}`,
        },
      },
      null,
      2,
    );
  }
  if (setup.provider === "jira") {
    return JSON.stringify(
      {
        webhookEvent: "jira:issue_updated",
        jira_base_url: "https://acme.atlassian.net",
        issue: {
          key: "SEC-42",
          fields: {
            summary: action.ticket_draft.title,
            description: `${action.instruction}\n\n${setup.action_marker}`,
          },
        },
      },
      null,
      2,
    );
  }
  return JSON.stringify(
    {
      action: "closed",
      repository: { full_name: "acme/app" },
      issue: {
        number: 42,
        title: action.ticket_draft.title,
        html_url: "https://github.com/acme/app/issues/42",
        body: `${action.instruction}\n\n${setup.action_marker}`,
      },
    },
    null,
    2,
  );
}

function webhookTestDraftFor(
  action: AgentRemediationPlanResponse["actions"][number],
  setup: WebhookProviderSetup,
  drafts: Record<string, WebhookTestDraft>,
): WebhookTestDraft {
  return (
    drafts[webhookTestKey(action, setup)] ?? {
      payloadText: sampleProviderWebhookPayload(action, setup),
      timestamp: "",
      nonce: "",
      signature: "",
    }
  );
}

function webhookTestEventLabel(
  event: AgentRemediationProviderWebhookTestResponse["normalized_provider_event"],
): string {
  return event.replace(/_/g, " ");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Callback test failed";
}

async function copyTextToClipboard(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    return;
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "0";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(textarea);
    if (!copied) {
      throw new Error("Clipboard copy failed");
    }
  }
}

function evidenceSourceLabel(source: string): string {
  switch (source) {
    case "dfd":
      return "DFD";
    case "document":
      return "Document evidence";
    case "scan":
      return "Runtime scan";
    case "repository":
      return "Code evidence";
    case "compliance":
      return "Compliance framework";
    case "cloud":
      return "Cloud evidence";
    case "manual":
      return "Manual evidence";
    case "threat_intel":
      return "Threat intel";
    case "iac":
      return "IaC";
    case "sdlc":
      return "SDLC";
    default:
      return source
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

function truthStatusLabel(status: string): string {
  switch (status) {
    case "validated":
      return "Validated";
    case "strongly_indicated":
      return "Strongly indicated";
    case "contextual":
      return "Contextual";
    case "theoretical":
      return "Theoretical";
    default:
      return status
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

function agentDecisionLabel(decision: AgentReleaseDecision): string {
  switch (decision) {
    case "ship":
      return "Ship";
    case "block":
      return "Block";
    case "fix_now":
      return "Fix Now";
    case "verify":
      return "Verify";
    case "gather_evidence":
      return "Gather Evidence";
    case "accept_risk":
      return "Accept Risk";
  }
}

function agentDecisionTone(decision: AgentReleaseDecision): string {
  switch (decision) {
    case "block":
      return reviewPriorityTone("p0_blocker");
    case "fix_now":
      return reviewPriorityTone("p1_now");
    case "verify":
    case "gather_evidence":
      return reviewPriorityTone("p2_sprint");
    case "accept_risk":
      return reviewPriorityTone("p3_backlog");
    case "ship":
      return reviewPriorityTone("p4_monitor");
  }
}

function agentCiContract(
  decision: AgentReleaseDecision,
  ci: AgentCiContract | undefined,
): AgentCiContract {
  if (ci) return ci;
  const shouldFail = decision === "block";
  return {
    fail_policy: "block_only",
    blocking_decisions: ["block"],
    should_fail: shouldFail,
    exit_code: shouldFail ? 1 : 0,
    reason: shouldFail
      ? "CI should fail because decision `block` is included in policy `block_only`."
      : `CI should continue because decision \`${decision}\` is not included in policy \`block_only\`.`,
  };
}

function remediationActionLabel(
  actionKind: AgentRemediationPlanResponse["actions"][number]["action_kind"],
): string {
  switch (actionKind) {
    case "patch_guidance":
      return "Patch guidance";
    case "verification":
      return "Verification";
    case "evidence_request":
      return "Evidence request";
  }
}

function remediationTransitionLabel(
  status: AgentRemediationPlanResponse["actions"][number]["transition"]["status"],
): string {
  return status
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function agentEvidenceLabel(
  evidence: AgentSecurityReviewResponse["findings"][number]["evidence"][number],
): string {
  if (evidence.location) return evidence.location;
  if (evidence.source_object_type && evidence.source_object_id) {
    return `${evidence.source_object_type}:${evidence.source_object_id}`;
  }
  return evidence.reference;
}

function agentEvidenceSummary(
  evidence: AgentSecurityReviewResponse["findings"][number]["evidence"],
): string {
  const labels: string[] = [];

  const addLabel = (
    item: AgentSecurityReviewResponse["findings"][number]["evidence"][number],
  ) => {
    const label = agentEvidenceLabel(item);
    if (!labels.includes(label)) labels.push(label);
  };

  const codeLocator = evidence.find(
    (item) =>
      item.type === "code" || item.source_object_type === "code_surface",
  );
  if (codeLocator) addLabel(codeLocator);

  const objectLocator = evidence.find(
    (item) =>
      item.source_object_type !== undefined &&
      item.source_object_type !== "code_surface",
  );
  if (objectLocator) addLabel(objectLocator);

  for (const item of evidence) {
    if (labels.length === 2) break;
    addLabel(item);
  }

  return labels.slice(0, 2).join(" · ");
}

function customerPacketStatusLabel(
  status: CustomerSecurityPacketResponse["validated_risks"][number]["customer_status"],
): string {
  switch (status) {
    case "validated_risk":
      return "Validated risk";
    case "accepted_risk":
      return "Accepted risk";
    case "needs_verification":
      return "Needs verification";
    case "evidence_gap":
      return "Evidence gap";
  }
}

function packetSourceTypeLabel(
  sourceType: CustomerSecurityPacketResponse["source_fingerprints"][number]["source_type"],
): string {
  switch (sourceType) {
    case "review_summary":
      return "Review summary";
    case "review_findings":
      return "Review findings";
    case "agent_decision":
      return "Agent decision";
    case "repository":
      return "Repository";
    case "pull_request":
      return "Pull request";
    case "scan":
      return "Validation scan";
    case "cloud_scan":
      return "Cloud scan";
    case "iac":
      return "IaC";
  }
}

function shortPacketHash(value: string): string {
  return value.length > 28 ? `${value.slice(0, 19)}...${value.slice(-8)}` : value;
}

function customerPacketSensitiveSourceLabelCount(
  packet: CustomerSecurityPacketResponse,
): number {
  return packet.source_fingerprints.filter((source) =>
    ["repository", "pull_request", "scan", "cloud_scan", "iac"].includes(
      source.source_type,
    ),
  ).length;
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function segmentToneClass(key: string, index: number): string {
  if (["p0_blocker", "validated", "Spoofing", "threat"].includes(key)) {
    return "security-review-report-segment-critical";
  }
  if (["p1_now", "strongly_indicated", "Tampering"].includes(key)) {
    return "security-review-report-segment-high";
  }
  if (["contextual", "Repudiation", "Information Disclosure"].includes(key)) {
    return "security-review-report-segment-medium";
  }
  if (
    ["theoretical", "Denial of Service", "Elevation of Privilege"].includes(key)
  ) {
    return "security-review-report-segment-muted";
  }
  return `security-review-report-segment-${(index % 4) + 1}`;
}

function countSegments(
  items: string[],
  labelForKey: (key: string) => string = (key) => key,
): DistributionSegment[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = item || "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, label: labelForKey(key), count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function reportFindingTitle(finding: SecurityReviewFindingSummary): string {
  if (!finding.display_id) return finding.title;
  const title = finding.title
    .replace(
      new RegExp(`^${escapeRegExp(finding.display_id)}\\s*[·:-]?\\s*`, "i"),
      "",
    )
    .trim();
  return `${finding.display_id} · ${title || finding.title}`;
}

function findMatchingFinding(
  summaryFinding: SecurityReviewFindingSummary,
  findings: SecurityReviewFinding[],
): SecurityReviewFinding | null {
  if (summaryFinding.threat_id) {
    const byThreat = findings.find(
      (finding) => finding.threat_id === summaryFinding.threat_id,
    );
    if (byThreat) return byThreat;
  }
  if (summaryFinding.finding_key) {
    const byKey = findings.find(
      (finding) =>
        finding.id === summaryFinding.finding_key ||
        finding.source_object_id === summaryFinding.finding_key,
    );
    if (byKey) return byKey;
  }
  return (
    findings.find(
      (finding) =>
        finding.display_id === summaryFinding.display_id &&
        finding.title === summaryFinding.title,
    ) ?? null
  );
}

function findAttackPathFinding(
  path: SecurityReviewAttackPath,
  findings: SecurityReviewFinding[],
): SecurityReviewFinding | null {
  const findingKeys = new Set(path.finding_keys ?? []);
  const findingTitles = new Set(path.finding_titles ?? []);

  return (
    findings.find(
      (finding) =>
        findingKeys.has(finding.id) ||
        findingKeys.has(finding.source_object_id) ||
        (finding.threat_id ? findingKeys.has(finding.threat_id) : false),
    ) ??
    findings.find(
      (finding) =>
        findingTitles.has(finding.title) ||
        (finding.display_id
          ? (path.finding_titles ?? []).some((title) =>
              title.startsWith(finding.display_id ?? ""),
            )
          : false),
    ) ??
    null
  );
}

function findingEvidenceSignalLabel(finding: SecurityReviewFindingSummary): string {
  if (finding.finding_kind === "evidence_gap") return "evidence missing";
  if (finding.finding_kind === "compliance_gap") return "compliance gap";
  if (finding.finding_kind === "control_gap") return "control gap";
  return finding.truth_status.replace(/_/g, " ");
}

function hasAttackPathDetails(path: SecurityReviewAttackPath): boolean {
  return (
    (path.path_nodes?.length ?? 0) > 0 ||
    path.finding_titles.length > 0 ||
    (path.relationship_reasons?.length ?? 0) > 0 ||
    (path.verification_steps?.length ?? 0) > 0
  );
}

function riskPostureLabel(
  p0Count: number,
  p1Count: number,
  evidenceGapCount: number,
): string {
  const evidenceQualifier = evidenceGapCount > 0 ? " · evidence-limited" : "";
  if (p0Count > 0) return `Release blocker posture${evidenceQualifier}`;
  if (p1Count > 0) return `Fix-before-confidence posture${evidenceQualifier}`;
  if (evidenceGapCount > 0) return "Evidence-limited posture";
  return "Monitor with normal governance";
}

function buildReportMarkdown({
  model,
  summary,
  p0Count,
  p1Count,
  fixNowCount,
  evidenceGapCount,
  unownedHighRiskCount,
  progressValue,
  validationRunbook,
}: {
  model: ThreatModelResponse;
  summary: SecurityReviewApplicationSummary;
  p0Count: number;
  p1Count: number;
  fixNowCount: number;
  evidenceGapCount: number;
  unownedHighRiskCount: number;
  progressValue: number;
  validationRunbook?: ValidationRunbookResponse | null;
}): string {
  const topRisks = summary.top_findings.slice(0, 5).map((finding, index) => {
    const target = finding.target_asset ? ` -> ${finding.target_asset}` : "";
    return `${index + 1}. ${reviewPriorityLabel(finding.priority)}: ${reportFindingTitle(finding)}${target}`;
  });
  const blindSpots = summary.blind_spots
    .slice(0, 4)
    .map((finding, index) => `${index + 1}. ${reportFindingTitle(finding)}`);
  const attackPaths = summary.attack_paths.slice(0, 4).map((path, index) => {
    const route =
      path.entry_point || path.target_asset
        ? ` (${path.entry_point ?? "unknown entry"} -> ${path.target_asset ?? "unknown target"})`
        : "";
    return `${index + 1}. ${reviewPriorityLabel(path.composite_priority)}: ${path.chain_description}${route}`;
  });
  const nextSteps = summary.next_steps
    .slice(0, 5)
    .map((item, index) => `${index + 1}. ${item}`);
  const validationCoverage = validationRunbook
    ? [
        `- Validated threats: ${validationRunbook.coverage.validated_threat_count}`,
        `- Indicated threats: ${validationRunbook.coverage.indicated_threat_count}`,
        `- Unbound findings: ${validationRunbook.coverage.unbound_finding_count}`,
        `- Untested threats: ${validationRunbook.coverage.untested_threat_count}`,
        `- Findings: ${validationRunbook.coverage.finding_count} total (${validationRunbook.coverage.deterministic_finding_count} deterministic, ${validationRunbook.coverage.assisted_finding_count} non-deterministic)`,
        `- Risk scores: ${validationRunbook.coverage.validated_risk_score} validated / ${validationRunbook.coverage.indicated_risk_score} indicated / ${validationRunbook.coverage.ai_assisted_risk_score} non-deterministic`,
        `- Target binding: ${validationRunbook.coverage.target_binding.replace(/_/g, " ")}`,
        ...validationRunbook.mapped_threats
          .filter((threat) => threat.confidence_label !== "validated")
          .slice(0, 5)
          .map((threat) => `- ${threat.threat_display_id}: ${threat.confidence_label}, risk ${threat.risk_score}, next action: ${threat.next_action}`),
      ]
    : ["No validation runbook attached."];

  return [
    `# ${model.system_name} Security Review Report`,
    "",
    `Verdict: ${reviewPriorityLabel(summary.overall_priority)} - ${summary.focus_statement}`,
    `Generated: ${formatGeneratedAt(summary.generated_at)}`,
    `Scope: ${model.data_classification} / ${model.deployment_model ?? "deployment unspecified"} / ${
      model.regulatory_scope.length > 0
        ? model.regulatory_scope.join(", ")
        : "no regulatory scope attached"
    }`,
    "",
    "## Key Counts",
    `- P0 blockers: ${p0Count}`,
    `- P1 now: ${p1Count}`,
    `- Fix Now queue: ${fixNowCount}`,
    `- Evidence gaps: ${evidenceGapCount}`,
    `- Unowned high-risk findings: ${unownedHighRiskCount}`,
    `- Resolved, accepted, or dismissed: ${progressValue}%`,
    "",
    "## Top Risks",
    ...(topRisks.length > 0 ? topRisks : ["No top risks attached."]),
    "",
    "## Blind Spots",
    ...(blindSpots.length > 0
      ? blindSpots
      : ["No blind spots currently flagged."]),
    "",
    "## Projected Attack Paths",
    ...(attackPaths.length > 0
      ? attackPaths
      : ["No aggregate attack paths attached."]),
    "",
    "## Validation Coverage",
    ...validationCoverage,
    "",
    "## Next Steps",
    ...(nextSteps.length > 0 ? nextSteps : ["No next steps attached."]),
  ].join("\n");
}

function DistributionBreakdown({
  title,
  subtitle,
  segments,
}: {
  title: string;
  subtitle: string;
  segments: DistributionSegment[];
}): JSX.Element {
  const total = segments.reduce((sum, segment) => sum + segment.count, 0);

  return (
    <article className="security-review-report-breakdown">
      <div>
        <strong>{title}</strong>
        <p>{subtitle}</p>
      </div>
      {total > 0 ? (
        <>
          <div className="security-review-report-stacked-bar">
            {segments.map((segment, index) => (
              <span
                key={segment.key}
                className={segmentToneClass(segment.key, index)}
                style={{
                  width: `${Math.max(percent(segment.count, total), 2)}%`,
                }}
                title={`${segment.label}: ${segment.count}`}
              />
            ))}
          </div>
          <div className="security-review-report-breakdown-legend">
            {segments.slice(0, 6).map((segment, index) => (
              <span key={segment.key}>
                <i className={segmentToneClass(segment.key, index)} />
                {segment.label}: {segment.count}
              </span>
            ))}
          </div>
        </>
      ) : (
        <p className="security-review-report-muted">
          No distribution data attached.
        </p>
      )}
    </article>
  );
}

function ActionableFindingRow({
  item,
  matchingFinding,
  onOpenFinding,
}: {
  item: SecurityReviewFindingSummary;
  matchingFinding: SecurityReviewFinding | null;
  onOpenFinding?: (finding: SecurityReviewFinding) => void;
}): JSX.Element {
  const content = (
    <>
      <span
        className={`application-review-priority-chip ${reviewPriorityTone(item.priority)}`}
      >
        {reviewPriorityLabel(item.priority)}
      </span>
      <strong>{reportFindingTitle(item)}</strong>
      <p>
        {item.rationale_excerpt ??
          item.next_step ??
          "No summary rationale attached yet."}
      </p>
      <span className="security-review-report-row-meta">
        {findingEvidenceSignalLabel(item)} ·{" "}
        {item.urgency.replace(/_/g, " ")}
        {item.entry_point ? ` · Entry: ${item.entry_point}` : ""}
        {item.target_asset ? ` · Target: ${item.target_asset}` : ""}
      </span>
    </>
  );

  if (matchingFinding && onOpenFinding) {
    return (
      <button
        type="button"
        className="security-review-report-finding-row security-review-report-finding-row-button"
        onClick={() => onOpenFinding(matchingFinding)}
      >
        {content}
      </button>
    );
  }

  return (
    <article className="security-review-report-finding-row">{content}</article>
  );
}

function AttackPathRow({
  path,
  matchingFinding,
  onOpenFinding,
  isExpanded,
  onToggleDetails,
}: {
  path: SecurityReviewAttackPath;
  matchingFinding: SecurityReviewFinding | null;
  onOpenFinding?: (finding: SecurityReviewFinding) => void;
  isExpanded: boolean;
  onToggleDetails: () => void;
}): JSX.Element {
  const supportCount = path.support_count ?? path.finding_titles.length;
  const modeledStepCount =
    path.path_nodes && path.path_nodes.length > 1
      ? path.path_nodes.length - 1
      : path.hop_count;
  const hasDetails = hasAttackPathDetails(path);

  return (
    <article className="security-review-report-path-row">
      <div>
        <strong>{path.chain_description}</strong>
        <p>
          {path.entry_point ?? "Unknown entry"} to{" "}
          {path.target_asset ?? "unknown target"} · {modeledStepCount} modeled{" "}
          {modeledStepCount === 1 ? "step" : "steps"} · {supportCount}{" "}
          supporting {supportCount === 1 ? "finding" : "findings"}
        </p>
      </div>
      <div className="security-review-report-chip-row">
        <span
          className={`application-review-priority-chip ${reviewPriorityTone(path.composite_priority)}`}
        >
          {reviewPriorityLabel(path.composite_priority)}
        </span>
        <span className="security-review-detail-tag">
          {path.composite_exploitability} exploitability
        </span>
        {(path.evidence_sources ?? []).slice(0, 3).map((source) => (
          <span key={source} className="security-review-detail-tag">
            {evidenceSourceLabel(source)}
          </span>
        ))}
        {hasDetails ? (
          <button
            type="button"
            className="security-review-report-path-action"
            aria-expanded={isExpanded}
            aria-label={`${isExpanded ? "Show less for" : "See more about"} ${path.chain_description}`}
            onClick={onToggleDetails}
          >
            {isExpanded ? "Show less" : "See more"}
          </button>
        ) : null}
        {matchingFinding && onOpenFinding ? (
          <button
            type="button"
            className="security-review-report-path-action security-review-report-path-action-primary"
            aria-label={`Open finding for ${path.chain_description}`}
            onClick={() => onOpenFinding(matchingFinding)}
          >
            Open finding
          </button>
        ) : null}
      </div>
      {isExpanded && hasDetails ? (
        <div className="security-review-report-path-details">
          {path.path_nodes && path.path_nodes.length > 0 ? (
            <div>
              <strong>Modeled route</strong>
              <div className="security-review-report-path-node-row">
                {path.path_nodes.map((node, index) => (
                  <span key={`${path.path_id}-node-${index}`}>
                    <span>{node}</span>
                    {index < (path.path_nodes?.length ?? 0) - 1 ? (
                      <i>-&gt;</i>
                    ) : null}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
          {path.finding_titles.length > 0 ? (
            <div>
              <strong>Linked findings</strong>
              <ul>
                {path.finding_titles.map((title, index) => (
                  <li key={`${path.path_id}-finding-${index}`}>{title}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {path.relationship_reasons && path.relationship_reasons.length > 0 ? (
            <div>
              <strong>Why linked</strong>
              <ul>
                {path.relationship_reasons.map((reason, index) => (
                  <li key={`${path.path_id}-reason-${index}`}>{reason}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {path.verification_steps && path.verification_steps.length > 0 ? (
            <div>
              <strong>Verification</strong>
              <ul>
                {path.verification_steps.map((step, index) => (
                  <li key={`${path.path_id}-verification-${index}`}>{step}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}

export function SecurityReviewReportPanel({
  model,
  threats,
  summary,
  findingsResponse,
  onOpenFinding,
}: SecurityReviewReportPanelProps): JSX.Element {
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "failed">(
    "idle",
  );
  const [customerPacketCopyStatus, setCustomerPacketCopyStatus] = useState<
    "idle" | "copied" | "failed"
  >("idle");
  const [customerPacketPdfExportStatus, setCustomerPacketPdfExportStatus] =
    useState<"idle" | "exporting" | "exported" | "failed">("idle");
  const [customerPacketCsvExportStatus, setCustomerPacketCsvExportStatus] =
    useState<"idle" | "exporting" | "exported" | "failed">("idle");
  const [includeCustomerPacketSourceLabels, setIncludeCustomerPacketSourceLabels] =
    useState(false);
  const [expandedAttackPathIds, setExpandedAttackPathIds] = useState<
    Set<string>
  >(() => new Set());
  const [validationRunbook, setValidationRunbook] =
    useState<ValidationRunbookResponse | null>(null);
  const [validationRunbookLoading, setValidationRunbookLoading] = useState(false);
  const [agentDecision, setAgentDecision] =
    useState<AgentSecurityReviewResponse | null>(null);
  const [agentDecisionLoading, setAgentDecisionLoading] = useState(false);
  const [remediationPlan, setRemediationPlan] =
    useState<AgentRemediationPlanResponse | null>(null);
  const [remediationPlanLoading, setRemediationPlanLoading] = useState(false);
  const [remediationApplyStatus, setRemediationApplyStatus] = useState<
    "idle" | "applying" | "applied" | "failed"
  >("idle");
  const [ticketCreationStatus, setTicketCreationStatus] = useState<
    Record<string, "idle" | "creating" | "created" | "failed">
  >({});
  const [webhookSetupCopyStatus, setWebhookSetupCopyStatus] = useState<
    Record<string, "copied" | "failed">
  >({});
  const [webhookTestDrafts, setWebhookTestDrafts] = useState<
    Record<string, WebhookTestDraft>
  >({});
  const [webhookTestStatus, setWebhookTestStatus] = useState<
    Record<string, "idle" | "testing" | "verified" | "failed">
  >({});
  const [webhookTestResults, setWebhookTestResults] = useState<
    Record<string, AgentRemediationProviderWebhookTestResponse>
  >({});
  const [webhookTestErrors, setWebhookTestErrors] = useState<
    Record<string, string>
  >({});
  const [customerPacket, setCustomerPacket] =
    useState<CustomerSecurityPacketResponse | null>(null);
  const [customerPacketLoading, setCustomerPacketLoading] = useState(false);

  useEffect(() => {
    let active = true;
    setValidationRunbookLoading(true);
    api
      .getLatestScanRunbook(model.id)
      .then((runbook) => {
        if (active) setValidationRunbook(runbook);
      })
      .catch(() => {
        if (active) setValidationRunbook(null);
      })
      .finally(() => {
        if (active) setValidationRunbookLoading(false);
      });
    return () => {
      active = false;
    };
  }, [model.id, summary?.generated_at]);

  useEffect(() => {
    let active = true;
    setAgentDecisionLoading(true);
    api
      .getThreatModelAgentReleaseDecision(model.id)
      .then((decision) => {
        if (active) setAgentDecision(decision);
      })
      .catch(() => {
        if (active) setAgentDecision(null);
      })
      .finally(() => {
        if (active) setAgentDecisionLoading(false);
      });
    return () => {
      active = false;
    };
  }, [model.id, summary?.generated_at, findingsResponse?.generated_at]);

  useEffect(() => {
    let active = true;
    setRemediationPlanLoading(true);
    api
      .getThreatModelAgentRemediationPlan(model.id)
      .then((plan) => {
        if (active) setRemediationPlan(plan);
      })
      .catch(() => {
        if (active) setRemediationPlan(null);
      })
      .finally(() => {
        if (active) setRemediationPlanLoading(false);
      });
    return () => {
      active = false;
    };
  }, [model.id, summary?.generated_at, findingsResponse?.generated_at]);

  useEffect(() => {
    let active = true;
    setCustomerPacketLoading(true);
    api
      .getThreatModelCustomerPacket(model.id)
      .then((packet) => {
        if (active) setCustomerPacket(packet);
      })
      .catch(() => {
        if (active) setCustomerPacket(null);
      })
      .finally(() => {
        if (active) setCustomerPacketLoading(false);
      });
    return () => {
      active = false;
    };
  }, [model.id, summary?.generated_at, findingsResponse?.generated_at]);

  if (!summary || !findingsResponse) {
    return (
      <div className="application-review-panel-state">Loading report…</div>
    );
  }

  const findings = findingsResponse.findings;
  const p0Count = bucketCount(summary.priority_counts, "p0_blocker");
  const p1Count = bucketCount(summary.priority_counts, "p1_now");
  const fixNowCount = bucketCount(findingsResponse.queue_counts, "fix_now");
  const verifyCount = bucketCount(findingsResponse.queue_counts, "verify");
  const evidenceQueueCount = bucketCount(
    findingsResponse.queue_counts,
    "gather_evidence",
  );
  const backlogCount = bucketCount(findingsResponse.queue_counts, "backlog");
  const openCount = bucketCount(findingsResponse.review_status_counts, "open");
  const inProgressCount = bucketCount(
    findingsResponse.review_status_counts,
    "in_progress",
  );
  const mitigatedCount = bucketCount(
    findingsResponse.review_status_counts,
    "mitigated",
  );
  const acceptedCount = bucketCount(
    findingsResponse.review_status_counts,
    "accepted",
  );
  const dismissedCount = bucketCount(
    findingsResponse.review_status_counts,
    "dismissed",
  );
  const closedCount = mitigatedCount + acceptedCount + dismissedCount;
  const acceptedRiskFindings = findings.filter(
    (finding) => finding.risk_acceptance || finding.review_status === "accepted",
  );
  const activeAcceptanceCount = acceptedRiskFindings.filter(
    (finding) =>
      !finding.risk_acceptance || finding.risk_acceptance.status === "active",
  ).length;
  const reopenedAcceptanceCount = acceptedRiskFindings.filter(
    (finding) => finding.risk_acceptance?.status === "reopened",
  ).length;
  const expiredAcceptanceCount = acceptedRiskFindings.filter(
    (finding) => finding.risk_acceptance?.status === "expired",
  ).length;
  const evidenceGapCount = findings.filter(
    (finding) => finding.needs_evidence,
  ).length;
  const engineeringChangeCount = findings.filter(
    (finding) => finding.needs_engineering_change,
  ).length;
  const activeThreatCount = threats.filter(
    (threat) => threat.status === "Open" || threat.status === "In Progress",
  ).length;
  const unownedHighRiskCount = findings.filter(
    (finding) =>
      (finding.priority === "p0_blocker" || finding.priority === "p1_now") &&
      (finding.review_status === "open" ||
        finding.review_status === "in_progress") &&
      !finding.owner,
  ).length;
  const uniqueEvidenceRefs = new Set(
    findings.flatMap((finding) => finding.evidence_refs),
  );
  const progressValue = percent(closedCount, findings.length);
  const posture = riskPostureLabel(p0Count, p1Count, evidenceGapCount);
  const findingKindSegments = countSegments(
    findings.map((finding) => finding.display_kind),
    (kind) =>
      reviewFindingKindLabel(kind as SecurityReviewFinding["display_kind"]),
  );
  const truthStatusSegments = summary.truth_status_counts
    .map((item) => ({
      key: item.key,
      label: truthStatusLabel(item.key),
      count: item.count,
    }))
    .filter((item) => item.count > 0);
  const strideSegments = countSegments(
    threats.map((threat) => threat.stride_category),
  );
  const clipboardReport = buildReportMarkdown({
    model,
    summary,
    p0Count,
    p1Count,
    fixNowCount,
    evidenceGapCount,
    unownedHighRiskCount,
    progressValue,
    validationRunbook,
  });

  async function handleCopyReport() {
    try {
      await copyTextToClipboard(clipboardReport);
      setCopyStatus("copied");
      window.setTimeout(() => setCopyStatus("idle"), 1800);
    } catch {
      setCopyStatus("failed");
    }
  }

  async function handleCopyCustomerPacket() {
    if (!customerPacket) return;
    try {
      await copyTextToClipboard(customerPacket.customer_safe_markdown);
      setCustomerPacketCopyStatus("copied");
      window.setTimeout(() => setCustomerPacketCopyStatus("idle"), 1800);
    } catch {
      setCustomerPacketCopyStatus("failed");
    }
  }

  async function handleExportCustomerPacket(format: "pdf" | "csv") {
    if (!customerPacket) return;
    const setStatus =
      format === "pdf"
        ? setCustomerPacketPdfExportStatus
        : setCustomerPacketCsvExportStatus;
    try {
      setStatus("exporting");
      const blob =
        format === "pdf"
          ? await api.exportThreatModelCustomerPacketPDF(model.id, {
              includeSourceLabels: includeCustomerPacketSourceLabels,
            })
          : await api.exportThreatModelCustomerPacketCSV(model.id, {
              includeSourceLabels: includeCustomerPacketSourceLabels,
            });
      downloadBlob(blob, `customer-security-packet-${model.id}.${format}`);
      setStatus("exported");
      window.setTimeout(() => setStatus("idle"), 2200);
    } catch {
      setStatus("failed");
    }
  }

  async function handleApplyRemediationPlan() {
    if (!remediationPlan || remediationPlan.actions.length === 0) return;
    try {
      setRemediationApplyStatus("applying");
      const response = await api.applyThreatModelAgentRemediationPlan(model.id);
      setRemediationPlan(response.plan);
      setRemediationApplyStatus("applied");
      window.setTimeout(() => setRemediationApplyStatus("idle"), 2200);
    } catch {
      setRemediationApplyStatus("failed");
    }
  }

  async function handleConfirmExternalTicket(
    action: AgentRemediationPlanResponse["actions"][number],
  ) {
    try {
      setTicketCreationStatus((current) => ({
        ...current,
        [action.action_id]: "creating",
      }));
      const response = await api.createThreatModelAgentRemediationTicket(model.id, {
        action_id: action.action_id,
        provider: action.ticket_draft.provider,
        confirmed: true,
        external_ticket_id:
          action.ticket_draft.external_ticket_id ??
          `${action.ticket_draft.provider}:${action.finding_id}`,
        external_ticket_url: action.ticket_draft.external_ticket_url,
      });
      setRemediationPlan(response.plan);
      setTicketCreationStatus((current) => ({
        ...current,
        [action.action_id]: "created",
      }));
    } catch {
      setTicketCreationStatus((current) => ({
        ...current,
        [action.action_id]: "failed",
      }));
    }
  }

  async function handleCopyWebhookSetup(
    action: AgentRemediationPlanResponse["actions"][number],
    setup: WebhookProviderSetup,
  ) {
    const key = `${action.action_id}:${setup.provider}`;
    try {
      await copyTextToClipboard(webhookSetupClipboardText(setup));
      setWebhookSetupCopyStatus((current) => ({ ...current, [key]: "copied" }));
      window.setTimeout(() => {
        setWebhookSetupCopyStatus((current) => {
          const next = { ...current };
          delete next[key];
          return next;
        });
      }, 1800);
    } catch {
      setWebhookSetupCopyStatus((current) => ({ ...current, [key]: "failed" }));
    }
  }

  async function handleCopyWebhookSignerCli(
    action: AgentRemediationPlanResponse["actions"][number],
    setup: WebhookProviderSetup,
  ) {
    const key = `${action.action_id}:${setup.provider}:signer`;
    try {
      await copyTextToClipboard(webhookSignerCliClipboardText(action, setup));
      setWebhookSetupCopyStatus((current) => ({ ...current, [key]: "copied" }));
      window.setTimeout(() => {
        setWebhookSetupCopyStatus((current) => {
          const next = { ...current };
          delete next[key];
          return next;
        });
      }, 1800);
    } catch {
      setWebhookSetupCopyStatus((current) => ({ ...current, [key]: "failed" }));
    }
  }

  function updateWebhookTestDraft(
    action: AgentRemediationPlanResponse["actions"][number],
    setup: WebhookProviderSetup,
    patch: Partial<WebhookTestDraft>,
  ) {
    const key = webhookTestKey(action, setup);
    setWebhookTestDrafts((current) => ({
      ...current,
      [key]: {
        ...webhookTestDraftFor(action, setup, current),
        ...patch,
      },
    }));
  }

  async function handleTestProviderWebhook(
    action: AgentRemediationPlanResponse["actions"][number],
    setup: WebhookProviderSetup,
  ) {
    const key = webhookTestKey(action, setup);
    const draft = webhookTestDraftFor(action, setup, webhookTestDrafts);
    try {
      setWebhookTestStatus((current) => ({ ...current, [key]: "testing" }));
      setWebhookTestErrors((current) => {
        const next = { ...current };
        delete next[key];
        return next;
      });
      const response = await api.testThreatModelAgentRemediationProviderWebhook(
        model.id,
        setup.provider,
        {
          provider: setup.provider,
          payload_text: draft.payloadText,
          headers: {
            "X-SSR-Webhook-Timestamp": draft.timestamp,
            "X-SSR-Webhook-Nonce": draft.nonce,
            "X-SSR-Webhook-Signature": draft.signature,
          },
        },
      );
      setWebhookTestResults((current) => ({ ...current, [key]: response }));
      setWebhookTestStatus((current) => ({ ...current, [key]: "verified" }));
    } catch (error) {
      setWebhookTestStatus((current) => ({ ...current, [key]: "failed" }));
      setWebhookTestErrors((current) => ({
        ...current,
        [key]: errorMessage(error),
      }));
    }
  }

  function toggleAttackPathDetails(pathId: string) {
    setExpandedAttackPathIds((current) => {
      const next = new Set(current);
      if (next.has(pathId)) {
        next.delete(pathId);
      } else {
        next.add(pathId);
      }
      return next;
    });
  }

  const riskMetrics = [
    {
      label: "P0 blockers",
      value: p0Count,
      note: "must be resolved or explicitly accepted",
      tone: "critical",
    },
    {
      label: "P1 now",
      value: p1Count,
      note: "current-cycle engineering or verification",
      tone: "high",
    },
    {
      label: "Fix Now queue",
      value: fixNowCount,
      note: "active remediation demand",
      tone: "high",
    },
    {
      label: "Evidence gaps",
      value: evidenceGapCount,
      note: "review confidence limiters",
      tone: "medium",
    },
    {
      label: "Engineering changes",
      value: engineeringChangeCount,
      note: "findings needing code, config, or control work",
      tone: "neutral",
    },
    {
      label: "Unowned high risk",
      value: unownedHighRiskCount,
      note: "P0/P1 work without an assigned owner",
      tone: "critical",
    },
    {
      label: "Active threats",
      value: activeThreatCount,
      note: "open or in-progress threat records",
      tone: "neutral",
    },
  ];

  const attackSurfaceMetrics = [
    {
      label: "Public entry points",
      value: summary.coverage.public_entry_points,
    },
    {
      label: "Privileged surfaces",
      value: summary.coverage.privileged_surfaces,
    },
    { label: "Restricted assets", value: summary.coverage.restricted_assets },
    { label: "Projected attack paths", value: summary.coverage.attack_paths },
    { label: "Systemic findings", value: summary.coverage.systemic_findings },
    {
      label: "Evidence sources",
      value: summary.coverage.attached_evidence_sources,
    },
  ];
  const agentCi = agentDecision
    ? agentCiContract(agentDecision.decision, agentDecision.ci)
    : null;

  return (
    <div className="security-review-report">
      <section
        className={`security-review-report-hero security-review-report-hero-${summary.overall_priority}`}
      >
        <div className="security-review-report-verdict-main">
          <span className="security-review-report-kicker">
            Stakeholder report
          </span>
          <span
            className={`security-review-report-verdict-chip ${reviewPriorityTone(summary.overall_priority)}`}
          >
            {reviewPriorityLabel(summary.overall_priority)}
          </span>
          <h4>{posture}</h4>
          <p>{summary.focus_statement}</p>
          <div className="security-review-report-meta-line">
            <span>{model.system_name}</span>
            <span>{model.data_classification}</span>
            <span>{model.deployment_model ?? "deployment unspecified"}</span>
            <span>
              {model.regulatory_scope.length > 0
                ? model.regulatory_scope.join(", ")
                : "No regulatory scope attached"}
            </span>
            <span>Generated {formatGeneratedAt(summary.generated_at)}</span>
          </div>
        </div>
        <button
          type="button"
          className="security-review-report-copy-btn"
          onClick={() => void handleCopyReport()}
        >
          {copyStatus === "copied"
            ? "Copied"
            : copyStatus === "failed"
              ? "Copy failed"
              : "Copy report"}
        </button>
      </section>

      <section className="security-review-report-exec">
        <div className="security-review-report-section-header">
          <div>
            <h5>Executive Readout</h5>
            <p>Why the posture matters and what needs to happen next.</p>
          </div>
          <span>Review engine</span>
        </div>
        <div className="security-review-report-two-column-list">
          <div>
            <strong>Why this matters</strong>
            <ul>
              {summary.rationale.slice(0, 3).map((item, index) => (
                <li key={`rationale-${index}`}>{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <strong>Next steps</strong>
            <ul>
              {summary.next_steps.slice(0, 3).map((item, index) => (
                <li key={`next-${index}`}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Customer Security Packet</h5>
            <p>External-facing summary of what is proven, assumed, and still unknown.</p>
          </div>
          <span>{customerPacketLoading ? "loading" : "export packet"}</span>
        </div>
        {customerPacket ? (
          <>
            <div className="security-review-report-chip-row">
              <span
                className={`application-review-priority-chip ${agentDecisionTone(customerPacket.release_decision)}`}
              >
                {agentDecisionLabel(customerPacket.release_decision)}
              </span>
              <span className="security-review-detail-tag">
                {customerPacket.validated_risks.length} customer-visible risks
              </span>
              <span className="security-review-detail-tag">
                {customerPacket.evidence_gaps.length} packet evidence gaps
              </span>
              <span className="security-review-detail-tag">
                {customerPacket.packet_version}
              </span>
              <span className="security-review-detail-tag">
                Packet hash {shortPacketHash(customerPacket.packet_hash)}
              </span>
              <button
                type="button"
                className="security-review-report-path-action security-review-report-path-action-primary"
                onClick={() => void handleCopyCustomerPacket()}
              >
                {customerPacketCopyStatus === "copied"
                  ? "Copied packet"
                  : customerPacketCopyStatus === "failed"
                    ? "Copy failed"
                    : "Copy customer packet"}
              </button>
              <button
                type="button"
                className="security-review-report-path-action"
                disabled={customerPacketPdfExportStatus === "exporting"}
                onClick={() => void handleExportCustomerPacket("pdf")}
              >
                {customerPacketPdfExportStatus === "exporting"
                  ? "Exporting PDF"
                  : customerPacketPdfExportStatus === "exported"
                    ? "PDF ready"
                    : customerPacketPdfExportStatus === "failed"
                      ? "Export failed"
                      : "Export PDF"}
              </button>
              <button
                type="button"
                className="security-review-report-path-action"
                disabled={customerPacketCsvExportStatus === "exporting"}
                onClick={() => void handleExportCustomerPacket("csv")}
              >
                {customerPacketCsvExportStatus === "exporting"
                  ? "Exporting CSV"
                  : customerPacketCsvExportStatus === "exported"
                    ? "CSV ready"
                    : customerPacketCsvExportStatus === "failed"
                      ? "Export failed"
                      : "Export CSV"}
              </button>
            </div>
            {customerPacketSensitiveSourceLabelCount(customerPacket) > 0 ? (
              <label className="security-review-report-export-approval">
                <input
                  type="checkbox"
                  checked={includeCustomerPacketSourceLabels}
                  onChange={(event) =>
                    setIncludeCustomerPacketSourceLabels(event.currentTarget.checked)
                  }
                />
                <span>
                  Reviewer approved source labels for export (
                  {customerPacketSensitiveSourceLabelCount(customerPacket)} sensitive
                  source
                  {customerPacketSensitiveSourceLabelCount(customerPacket) === 1
                    ? ""
                    : "s"}
                  )
                </span>
              </label>
            ) : null}
            <p className="security-review-report-muted">
              {customerPacket.decision_summary}
            </p>
            <div className="security-review-report-two-column-list">
              <div>
                <strong>What is proven</strong>
                <ul>
                  {customerPacket.proven.slice(0, 4).map((item, index) => (
                    <li key={`customer-proven-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>What remains unknown</strong>
                <ul>
                  {customerPacket.unknowns.map((item, index) => (
                    <li key={`customer-unknown-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="security-review-report-two-column-list">
              <div>
                <strong>Source fingerprints</strong>
                <ul>
                  {customerPacket.source_fingerprints
                    .slice(0, 8)
                    .map((source) => (
                      <li key={`${source.source_type}-${source.source_id}`}>
                        {packetSourceTypeLabel(source.source_type)}: {source.label} ·{" "}
                        {shortPacketHash(source.fingerprint)}
                      </li>
                    ))}
                  {customerPacket.source_fingerprints.length > 8 ? (
                    <li>{customerPacket.source_fingerprints.length - 8} more source fingerprint(s) hidden.</li>
                  ) : null}
                  {customerPacket.source_fingerprints.length === 0 ? (
                    <li>No source fingerprints recorded.</li>
                  ) : null}
                </ul>
              </div>
              <div>
                <strong>External sharing controls</strong>
                <ul>
                  {customerPacket.redaction_notes.slice(0, 3).map((item, index) => (
                    <li key={`customer-redaction-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="security-review-report-list">
              {customerPacket.validated_risks.map((finding) => (
                <article
                  key={`customer-risk-${finding.title}`}
                  className="security-review-report-finding-row"
                >
                  <span className="security-review-detail-tag">
                    {customerPacketStatusLabel(finding.customer_status)}
                  </span>
                  <strong>{finding.title}</strong>
                  <p>{finding.evidence_summary}</p>
                  <span className="security-review-report-row-meta">
                    {finding.next_step ?? "No next step recorded."}
                  </span>
                </article>
              ))}
              {customerPacket.evidence_gaps.map((finding) => (
                <article
                  key={`customer-gap-${finding.title}`}
                  className="security-review-report-finding-row"
                >
                  <span className="security-review-detail-tag">
                    {customerPacketStatusLabel(finding.customer_status)}
                  </span>
                  <strong>{finding.title}</strong>
                  <p>{finding.evidence_summary}</p>
                  <span className="security-review-report-row-meta">
                    {finding.next_step ?? "Attach evidence before sharing as proven."}
                  </span>
                </article>
              ))}
            </div>
          </>
        ) : (
          <p className="security-review-report-muted">
            {customerPacketLoading
              ? "Loading customer security packet..."
              : "Customer security packet is not available for this review yet."}
          </p>
        )}
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Agent/API Release Decision</h5>
            <p>The machine-readable decision uses the same review findings and pass semantics as this report.</p>
          </div>
          <span>{agentDecisionLoading ? "loading" : "agent contract"}</span>
        </div>
        {agentDecision ? (
          <>
            <div className="security-review-report-chip-row">
              <span
                className={`application-review-priority-chip ${agentDecisionTone(agentDecision.decision)}`}
              >
                {agentDecisionLabel(agentDecision.decision)}
              </span>
              <span className="security-review-detail-tag">
                {agentDecision.findings.length} agent-visible findings
              </span>
              <span className="security-review-detail-tag">
                {agentDecision.evidence_gaps.length} evidence gaps
              </span>
              <span className="security-review-detail-tag">
                CI exit {agentCi?.exit_code ?? 0}
              </span>
            </div>
            <p className="security-review-report-muted">
              {agentDecision.decision_reason}
            </p>
            <p className="security-review-report-muted">
              {agentCi?.reason}
            </p>
            {agentDecision.findings.length > 0 ? (
              <div className="security-review-report-list">
                {agentDecision.findings.slice(0, 3).map((finding) => (
                  <article
                    key={finding.finding_id}
                    className="security-review-report-finding-row"
                  >
                    <span
                      className={`application-review-priority-chip ${agentDecisionTone(finding.decision)}`}
                    >
                      {agentDecisionLabel(finding.decision)}
                    </span>
                    <strong>{finding.title}</strong>
                    <p>
                      {finding.fix_instructions[0] ??
                        finding.verification.suggested_test ??
                        "No agent instruction attached yet."}
                    </p>
                    <span className="security-review-report-row-meta">
                      {finding.evidence.length} evidence refs ·{" "}
                      {finding.evidence.length > 0
                        ? `${agentEvidenceSummary(finding.evidence)} · `
                        : ""}
                      {finding.verification.required
                        ? "verification required"
                        : "no verification required"}
                    </span>
                  </article>
                ))}
              </div>
            ) : null}
          </>
        ) : (
          <p className="security-review-report-muted">
            {agentDecisionLoading
              ? "Loading agent release decision..."
              : "Agent release decision is not available for this review yet."}
          </p>
        )}
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Agent Remediation Loop</h5>
            <p>Patch guidance, verification, and evidence requests generated from the current release decision.</p>
          </div>
          <span>{remediationPlanLoading ? "loading" : "remediation loop"}</span>
        </div>
        {remediationPlan ? (
          <>
            <div className="security-review-report-chip-row">
              <span
                className={`application-review-priority-chip ${agentDecisionTone(remediationPlan.current_decision)}`}
              >
                {agentDecisionLabel(remediationPlan.current_decision)}
              </span>
              <span className="security-review-detail-tag">
                {remediationPlan.actions.length} loop actions
              </span>
              <span className="security-review-detail-tag">
                {remediationPlan.loop_status.replace(/_/g, " ")}
              </span>
              <button
                type="button"
                className="security-review-report-path-action security-review-report-path-action-primary"
                disabled={
                  remediationPlan.actions.length === 0 ||
                  remediationApplyStatus === "applying"
                }
                onClick={() => void handleApplyRemediationPlan()}
              >
                {remediationApplyStatus === "applying"
                  ? "Creating artifacts"
                  : remediationApplyStatus === "applied"
                    ? "Artifacts created"
                    : remediationApplyStatus === "failed"
                      ? "Create failed"
                      : "Create remediation artifacts"}
              </button>
            </div>
            <p className="security-review-report-muted">{remediationPlan.summary}</p>
            <div className="security-review-report-list">
              {remediationPlan.actions.slice(0, 3).map((action) => {
                const webhookSetups =
                  action.ticket_draft.callback_setups?.length
                    ? action.ticket_draft.callback_setups
                    : action.ticket_draft.callback_setup
                      ? [action.ticket_draft.callback_setup]
                      : [];

                return (
                  <article
                    key={action.action_id}
                    className="security-review-report-finding-row"
                  >
                    <span className="security-review-detail-tag">
                      {remediationActionLabel(action.action_kind)}
                    </span>
                    <span className="security-review-detail-tag">
                      {remediationTransitionLabel(action.transition.status)}
                    </span>
                    <strong>{action.title}</strong>
                    <p>{action.instruction}</p>
                    <p className="security-review-report-muted">
                      Ticket draft:{" "}
                      {action.ticket_draft.provider.replace(/_/g, " ")} ·{" "}
                      {action.ticket_draft.title} ·{" "}
                      {action.ticket_draft.external_creation_status.replace(
                        /_/g,
                        " ",
                      )}
                      {action.ticket_draft.external_ticket_id
                        ? ` · ${action.ticket_draft.external_ticket_id}`
                        : ""}
                    </p>
                    <p className="security-review-report-muted">
                      Connector creation:{" "}
                      {(
                        action.ticket_draft.connector_creation_status ??
                        "available_with_confirmation"
                      ).replace(/_/g, " ")}{" "}
                      ·{" "}
                      {action.ticket_draft.connector_confirmation_hint ??
                        "Direct provider creation requires explicit confirmation and a customer-owned provider token at action time."}
                    </p>
                    <p className="security-review-report-muted">
                      Callback security:{" "}
                      {(
                        action.ticket_draft.callback_security_status ??
                        "signed_hmac_required"
                      ).replace(/_/g, " ")}{" "}
                      ·{" "}
                      {action.ticket_draft.callback_security_hint ??
                        "Provider evidence callbacks must include timestamp, nonce, and HMAC-SHA256 signature headers before evidence is ingested."}
                    </p>
                    {webhookSetups.length > 0 ? (
                      <div className="security-review-report-webhook-setup">
                        <div className="security-review-report-webhook-setup-header">
                          <strong>Webhook setup</strong>
                          <span>Provider callbacks for this action</span>
                        </div>
                        <div className="security-review-report-webhook-setup-grid">
                          {webhookSetups.map((setup) => {
                            const copyKey = `${action.action_id}:${setup.provider}`;
                            const signerCopyKey = `${copyKey}:signer`;
                            const testKey = webhookTestKey(action, setup);
                            const testDraft = webhookTestDraftFor(
                              action,
                              setup,
                              webhookTestDrafts,
                            );
                            const testResult = webhookTestResults[testKey];
                            return (
                              <div
                                key={setup.provider}
                                className="security-review-report-webhook-provider"
                              >
                                <div className="security-review-report-webhook-provider-header">
                                  <strong>{setup.provider_label}</strong>
                                  <button
                                    type="button"
                                    className="security-review-report-path-action"
                                    onClick={() =>
                                      void handleCopyWebhookSetup(action, setup)
                                    }
                                  >
                                    {webhookSetupCopyStatus[copyKey] === "copied"
                                      ? "Copied"
                                      : webhookSetupCopyStatus[copyKey] === "failed"
                                        ? "Copy failed"
                                        : "Copy setup"}
                                  </button>
                                  <button
                                    type="button"
                                    className="security-review-report-path-action"
                                    onClick={() =>
                                      void handleCopyWebhookSignerCli(action, setup)
                                    }
                                  >
                                    {webhookSetupCopyStatus[signerCopyKey] ===
                                    "copied"
                                      ? "Signer copied"
                                      : webhookSetupCopyStatus[signerCopyKey] ===
                                          "failed"
                                        ? "Copy failed"
                                        : "Copy signer CLI"}
                                  </button>
                                </div>
                                <code>{setup.callback_url}</code>
                                <p>
                                  Events:{" "}
                                  {setup.event_filters.length > 0
                                    ? setup.event_filters.join(", ")
                                    : "provider remediation evidence events"}
                                </p>
                                <p>
                                  Marker: <code>{setup.action_marker}</code>
                                </p>
                                <p>{setup.signing_secret_hint}</p>
                                <ul>
                                  {setup.registration_steps
                                    .slice(0, 3)
                                    .map((step, index) => (
                                      <li key={`${setup.provider}-step-${index}`}>
                                        {step}
                                      </li>
                                    ))}
                                </ul>
                                <div className="security-review-report-webhook-test">
                                  <div className="security-review-report-webhook-test-header">
                                    <strong>Signed callback tester</strong>
                                    <span>Dry run</span>
                                  </div>
                                  <label>
                                    {setup.provider_label} callback payload
                                    <textarea
                                      aria-label={`${setup.provider_label} callback payload`}
                                      value={testDraft.payloadText}
                                      onChange={(event) =>
                                        updateWebhookTestDraft(action, setup, {
                                          payloadText: event.target.value,
                                        })
                                      }
                                    />
                                  </label>
                                  <div className="security-review-report-webhook-test-fields">
                                    <label>
                                      Timestamp
                                      <input
                                        aria-label={`${setup.provider_label} callback timestamp`}
                                        value={testDraft.timestamp}
                                        onChange={(event) =>
                                          updateWebhookTestDraft(action, setup, {
                                            timestamp: event.target.value,
                                          })
                                        }
                                        placeholder="1700000000"
                                      />
                                    </label>
                                    <label>
                                      Nonce
                                      <input
                                        aria-label={`${setup.provider_label} callback nonce`}
                                        value={testDraft.nonce}
                                        onChange={(event) =>
                                          updateWebhookTestDraft(action, setup, {
                                            nonce: event.target.value,
                                          })
                                        }
                                        placeholder="unique nonce"
                                      />
                                    </label>
                                  </div>
                                  <label>
                                    Signature
                                    <input
                                      aria-label={`${setup.provider_label} callback signature`}
                                      value={testDraft.signature}
                                      onChange={(event) =>
                                        updateWebhookTestDraft(action, setup, {
                                          signature: event.target.value,
                                        })
                                      }
                                      placeholder="sha256=..."
                                    />
                                  </label>
                                  <div className="security-review-report-webhook-test-actions">
                                    <button
                                      type="button"
                                      className="security-review-report-path-action"
                                      disabled={
                                        webhookTestStatus[testKey] === "testing"
                                      }
                                      onClick={() =>
                                        void handleTestProviderWebhook(action, setup)
                                      }
                                    >
                                      {webhookTestStatus[testKey] === "testing"
                                        ? "Testing callback"
                                        : webhookTestStatus[testKey] === "verified"
                                          ? "Callback verified"
                                          : "Test callback"}
                                    </button>
                                    <span>
                                      Sign the exact payload text with the remediation
                                      webhook secret before testing.
                                    </span>
                                  </div>
                                  {testResult ? (
                                    <p className="security-review-report-webhook-test-success">
                                      Verified{" "}
                                      {webhookTestEventLabel(
                                        testResult.normalized_provider_event,
                                      )}{" "}
                                      · {testResult.action_title}
                                    </p>
                                  ) : null}
                                  {webhookTestErrors[testKey] ? (
                                    <p className="security-review-report-webhook-test-error">
                                      {webhookTestErrors[testKey]}
                                    </p>
                                  ) : null}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ) : null}
                    <div className="security-review-report-chip-row">
                      <button
                        type="button"
                        className="security-review-report-path-action"
                        disabled={
                          action.ticket_draft.external_creation_status ===
                            "created" ||
                          ticketCreationStatus[action.action_id] === "creating"
                        }
                        onClick={() => void handleConfirmExternalTicket(action)}
                      >
                        {ticketCreationStatus[action.action_id] === "creating"
                          ? "Confirming ticket"
                          : action.ticket_draft.external_creation_status ===
                                "created" ||
                              ticketCreationStatus[action.action_id] === "created"
                            ? "Ticket confirmed"
                            : ticketCreationStatus[action.action_id] === "failed"
                              ? "Ticket failed"
                              : "Confirm ticket handoff"}
                      </button>
                      <span className="security-review-detail-tag">
                        PR/evidence webhook ready
                      </span>
                    </div>
                    <span className="security-review-report-row-meta">
                      creates {action.artifact_kind.replace("_", " ")} ·{" "}
                      {action.transition.artifact_count} local artifact
                      {action.transition.artifact_count === 1 ? "" : "s"} · expect{" "}
                      {agentDecisionLabel(action.expected_next_decision)} after proof ·{" "}
                      {action.evidence_needed.length > 0
                        ? `${action.evidence_needed.join(", ")} needed`
                        : "no named evidence gap"}
                    </span>
                  </article>
                );
              })}
            </div>
            <div className="security-review-report-two-column-list">
              <div>
                <strong>Rerun instructions</strong>
                <ul>
                  {remediationPlan.rerun_instructions.slice(0, 4).map((item, index) => (
                    <li key={`remediation-rerun-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>Decision guardrail</strong>
                <p className="security-review-report-muted">
                  Creating artifacts records the next action only. The decision improves
                  after the fix or evidence exists and the release decision endpoint is
                  rerun. Confirmed ticket handoffs and PR/evidence webhooks attach proof
                  to the same finding history before rerun.
                </p>
              </div>
            </div>
            {remediationPlan.action_history.length > 0 ? (
              <div className="security-review-report-list">
                {remediationPlan.action_history.slice(0, 4).map((item) => (
                  <article
                    key={`${item.action_id}:${item.created_at}`}
                    className="security-review-report-finding-row"
                  >
                    <span className="security-review-detail-tag">
                      {item.transition_status.replace(/_/g, " ")}
                    </span>
                    <strong>{item.artifact_title}</strong>
                    <span className="security-review-report-row-meta">
                      Action history · {item.artifact_kind.replace("_", " ")} ·{" "}
                      {formatGeneratedAt(item.created_at)}
                    </span>
                  </article>
                ))}
              </div>
            ) : null}
          </>
        ) : (
          <p className="security-review-report-muted">
            {remediationPlanLoading
              ? "Loading agent remediation loop..."
              : "Agent remediation loop is not available for this review yet."}
          </p>
        )}
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Quantified Risk Inventory</h5>
            <p>Hard counts from the current review findings and queue state.</p>
          </div>
          <span>{findings.length} findings</span>
        </div>
        <div className="security-review-report-metric-grid">
          {riskMetrics.map((metric) => (
            <article
              key={metric.label}
              className={`security-review-report-metric security-review-report-metric-${metric.tone}`}
            >
              <strong>{metric.value}</strong>
              <span>{metric.label}</span>
              <p>{metric.note}</p>
            </article>
          ))}
        </div>
        <div className="security-review-report-breakdown-grid">
          <DistributionBreakdown
            title="Finding type"
            subtitle="What kind of security work is in the queue."
            segments={findingKindSegments}
          />
          <DistributionBreakdown
            title="Evidence confidence"
            subtitle="Validated versus contextual or theoretical signals."
            segments={truthStatusSegments}
          />
          <DistributionBreakdown
            title="STRIDE shape"
            subtitle="Threat categories represented in the current model."
            segments={strideSegments}
          />
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Validation Coverage</h5>
            <p>Validation evidence mapped against semantic threats.</p>
          </div>
          <span>
            {validationRunbook
              ? validationRunbook.coverage.tool_names.join(", ") || "validation"
              : validationRunbookLoading
                ? "loading"
                : "no runbook"}
          </span>
        </div>
        {validationRunbook ? (
          <>
            <div className="security-review-report-metric-grid">
              <article className="security-review-report-metric security-review-report-metric-neutral">
                <strong>{validationRunbook.coverage.validated_threat_count}</strong>
                <span>Validated threats</span>
                <p>node-bound validation evidence</p>
              </article>
              <article className="security-review-report-metric security-review-report-metric-medium">
                <strong>{validationRunbook.coverage.indicated_threat_count}</strong>
                <span>Indicated threats</span>
                <p>evidence needs stronger binding</p>
              </article>
              <article className="security-review-report-metric security-review-report-metric-high">
                <strong>{validationRunbook.coverage.unbound_finding_count}</strong>
                <span>Unbound findings</span>
                <p>retained but not semantic validation</p>
              </article>
              <article className="security-review-report-metric security-review-report-metric-neutral">
                <strong>{validationRunbook.coverage.untested_threat_count}</strong>
                <span>Untested threats</span>
                <p>still need validation evidence</p>
              </article>
            </div>
            <p className="security-review-report-muted">
              {validationRunbook.executive_summary}
            </p>
            <div className="security-review-report-chip-row">
              <span className="security-review-detail-tag">
                {validationRunbook.coverage.target_binding.replace(/_/g, " ")}
              </span>
              <span className="security-review-detail-tag">
                {validationRunbook.coverage.deterministic_finding_count} deterministic findings
              </span>
              <span className="security-review-detail-tag">
                validated risk {validationRunbook.coverage.validated_risk_score}
              </span>
              <span className="security-review-detail-tag">
                indicated risk {validationRunbook.coverage.indicated_risk_score}
              </span>
              {validationRunbook.coverage.assisted_finding_count > 0 ? (
                <span className="security-review-detail-tag">
                  {validationRunbook.coverage.assisted_finding_count} non-deterministic findings · risk {validationRunbook.coverage.ai_assisted_risk_score}
                </span>
              ) : null}
              {validationRunbook.coverage.tool_names.map((toolName) => (
                <span key={toolName} className="security-review-detail-tag">
                  {toolName}
                </span>
              ))}
            </div>
            <div className="security-review-report-two-column-list security-review-report-validation-splits">
              <div>
                <strong>Validated and indicated threats</strong>
                <ul>
                  {validationRunbook.mapped_threats
                    .filter((threat) => threat.confidence_label !== "untested")
                    .slice(0, 5)
                    .map((threat) => (
                      <li key={threat.threat_id}>
                        {threat.threat_display_id} · {threat.confidence_label} · risk {threat.risk_score} · {threat.proof_class}
                      </li>
                    ))}
                  {validationRunbook.mapped_threats.every((threat) => threat.confidence_label === "untested") ? (
                    <li>No threat has validation evidence yet.</li>
                  ) : null}
                </ul>
              </div>
              <div>
                <strong>Unvalidated next actions</strong>
                <ul>
                  {validationRunbook.mapped_threats
                    .filter((threat) => threat.confidence_label === "untested")
                    .slice(0, 5)
                    .map((threat) => (
                      <li key={threat.threat_id}>
                        {threat.threat_display_id} · {threat.next_action}
                      </li>
                    ))}
                  {validationRunbook.mapped_threats.some((threat) => threat.confidence_label === "untested") ? null : (
                    <li>No mapped threat is currently untested in this runbook.</li>
                  )}
                </ul>
              </div>
            </div>
            <div className="security-review-report-two-column-list">
              <div>
                <strong>Coverage gaps</strong>
                <ul>
                  {validationRunbook.gaps.slice(0, 4).map((gap) => (
                    <li key={gap}>{gap}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>Unbound evidence</strong>
                <ul>
                  {validationRunbook.unbound_findings.slice(0, 4).map((finding) => (
                    <li key={finding.finding_id}>
                      {finding.title} · {finding.severity}
                    </li>
                  ))}
                  {validationRunbook.unbound_findings.length === 0 ? (
                    <li>No unbound validation evidence.</li>
                  ) : null}
                </ul>
              </div>
            </div>
          </>
        ) : (
          <p className="security-review-report-muted">
            {validationRunbookLoading
              ? "Loading validation coverage..."
              : "No completed validation runbook is available yet."}
          </p>
        )}
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Review Progress</h5>
            <p>Lifecycle state across all normalized findings.</p>
          </div>
          <span>{progressValue}% resolved, accepted, or dismissed</span>
        </div>
        <div
          className="security-review-report-progress"
          aria-label="Review completion"
        >
          <span style={{ width: `${progressValue}%` }} />
        </div>
        <div className="security-review-report-chip-row">
          <span className="security-review-detail-tag">{openCount} open</span>
          <span className="security-review-detail-tag">
            {inProgressCount} in progress
          </span>
          <span className="security-review-detail-tag">
            {mitigatedCount} mitigated
          </span>
          <span className="security-review-detail-tag">
            {acceptedCount} accepted
          </span>
          <span className="security-review-detail-tag">
            {dismissedCount} dismissed
          </span>
        </div>
        <div className="security-review-report-chip-row">
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("fix_now")}: {fixNowCount}
          </span>
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("verify")}: {verifyCount}
          </span>
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("gather_evidence")}: {evidenceQueueCount}
          </span>
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("backlog")}: {backlogCount}
          </span>
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Top Risks</h5>
            <p>Prioritized findings from review scoring and evidence context.</p>
          </div>
          <span>Review engine</span>
        </div>
        <div className="security-review-report-list">
          {summary.top_findings.slice(0, 8).map((item) => (
            <ActionableFindingRow
              key={`${item.finding_key ?? item.threat_id ?? item.title}-top`}
              item={item}
              matchingFinding={findMatchingFinding(item, findings)}
              onOpenFinding={onOpenFinding}
            />
          ))}
          {summary.top_findings.length === 0 ? (
            <p className="security-review-report-muted">
              No top findings are attached yet.
            </p>
          ) : null}
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Projected Attack Paths</h5>
            <p>Modeled routes, not measured network distance.</p>
          </div>
          <span>Modeled paths</span>
        </div>
        <div className="security-review-report-path-list">
          {summary.attack_paths.slice(0, 5).map((path) => (
            <AttackPathRow
              key={path.path_id}
              path={path}
              matchingFinding={findAttackPathFinding(path, findings)}
              onOpenFinding={onOpenFinding}
              isExpanded={expandedAttackPathIds.has(path.path_id)}
              onToggleDetails={() => toggleAttackPathDetails(path.path_id)}
            />
          ))}
          {summary.attack_paths.length === 0 ? (
            <p className="security-review-report-muted">
              No aggregate attack path is attached yet.
            </p>
          ) : null}
        </div>
      </section>

      <section className="security-review-report-grid">
        <div className="security-review-report-section">
          <div className="security-review-report-section-header">
            <div>
              <h5>Blind Spots</h5>
              <p>Potential gaps identified by the review engine.</p>
            </div>
            <span>Review engine</span>
          </div>
          <div className="security-review-report-list">
            {summary.blind_spots.slice(0, 6).map((item) => (
              <ActionableFindingRow
                key={`${item.finding_key ?? item.threat_id ?? item.title}-blind`}
                item={item}
                matchingFinding={findMatchingFinding(item, findings)}
                onOpenFinding={onOpenFinding}
              />
            ))}
            {summary.blind_spots.length === 0 ? (
              <p className="security-review-report-muted">
                No blind spots are currently flagged.
              </p>
            ) : null}
          </div>
        </div>

        <div className="security-review-report-section">
          <div className="security-review-report-section-header">
            <div>
              <h5>Risk Acceptances</h5>
              <p>Accepted risk that still needs governance visibility.</p>
            </div>
            <span>Hard state counts</span>
          </div>
          <div className="security-review-report-delta-strip">
            <span>
              {Math.max(summary.risk_acceptance_summary.active, activeAcceptanceCount)} active
            </span>
            <span>
              {Math.max(summary.risk_acceptance_summary.reopened, reopenedAcceptanceCount)} reopened
            </span>
            <span>
              {Math.max(summary.risk_acceptance_summary.expired, expiredAcceptanceCount)} expired
            </span>
          </div>
          {acceptedRiskFindings.length > 0 ? (
            <div className="security-review-report-list">
              {acceptedRiskFindings.slice(0, 4).map((finding) => (
                <article
                  key={`accepted-risk-${finding.id}`}
                  className="security-review-report-finding-row"
                >
                  <span className="security-review-detail-tag">
                    {finding.risk_acceptance?.status ?? "accepted"}
                  </span>
                  <strong>{finding.title}</strong>
                  <p>
                    {finding.risk_acceptance?.acceptance_rationale ??
                      finding.note ??
                      "Accepted risk requires a recorded rationale."}
                  </p>
                  <span className="security-review-report-row-meta">
                    {finding.risk_acceptance?.accepted_by
                      ? `accepted by ${finding.risk_acceptance.accepted_by}`
                      : "accepted owner not recorded"}
                    {finding.risk_acceptance?.expires_at
                      ? ` · expires ${formatRiskAcceptanceDate(finding.risk_acceptance.expires_at)}`
                      : " · no expiry recorded"}
                    {finding.risk_acceptance?.compensating_control
                      ? ` · control ${finding.risk_acceptance.compensating_control}`
                      : ""}
                  </span>
                </article>
              ))}
            </div>
          ) : (
            <p className="security-review-report-muted">
              No governed risk acceptance is recorded for this review.
            </p>
          )}
        </div>
      </section>

      <details className="security-review-report-supporting">
        <summary>
          <span>Supporting Analysis</span>
          <strong>Attack surface, delta, and evidence coverage</strong>
        </summary>
        <div className="security-review-report-supporting-grid">
          <div className="security-review-report-section">
            <div className="security-review-report-section-header">
              <div>
                <h5>Attack Surface Shape</h5>
                <p>
                  Modeled exposure, privileged paths, restricted assets, and
                  evidence coverage.
                </p>
              </div>
              <span>Hard model counts</span>
            </div>
            <div className="security-review-report-surface-grid">
              {attackSurfaceMetrics.map((metric) => (
                <div
                  key={metric.label}
                  className="security-review-report-surface-item"
                >
                  <strong>{metric.value}</strong>
                  <span>{metric.label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="security-review-report-section">
            <div className="security-review-report-section-header">
              <div>
                <h5>Delta Since Last Review</h5>
                <p>
                  Change pressure from the review engine's current delta
                  baseline.
                </p>
              </div>
              <span>Hard delta counts</span>
            </div>
            <div className="security-review-report-delta-strip">
              <span>+{summary.review_delta_summary.new_findings} new</span>
              <span>
                -{summary.review_delta_summary.resolved_findings} resolved
              </span>
              <span>
                {summary.review_delta_summary.reopened_findings} reopened
              </span>
              <span>
                {summary.review_delta_summary.escalated_findings} escalated
              </span>
              <span>
                {summary.review_delta_summary.deescalated_findings} de-escalated
              </span>
            </div>
          </div>

          <div className="security-review-report-section">
            <div className="security-review-report-section-header">
              <div>
                <h5>Evidence Coverage</h5>
                <p>How much proof is attached versus still missing.</p>
              </div>
              <span>{uniqueEvidenceRefs.size} referenced sources</span>
            </div>
            <div className="security-review-report-evidence">
              <strong>{summary.coverage.attached_evidence_sources}</strong>
              <span>attached source types</span>
              <p>
                {summary.coverage.missing_evidence_sources} source types still
                missing.
              </p>
            </div>
            <div className="security-review-report-chip-row">
              {[...uniqueEvidenceRefs].slice(0, 8).map((source) => (
                <span key={source} className="security-review-detail-tag">
                  {evidenceSourceLabel(source)}
                </span>
              ))}
            </div>
          </div>
        </div>
      </details>
    </div>
  );
}
