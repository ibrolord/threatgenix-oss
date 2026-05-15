import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import { SecurityReviewReportPanel } from "./SecurityReviewReportPanel";
import type {
  AgentRemediationProviderWebhookTestResponse,
  AgentRemediationWebhookSetup,
  SecurityReviewApplicationSummary,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";

vi.mock("../api/client", () => ({
  api: {
    getLatestScanRunbook: vi.fn(),
    getThreatModelAgentReleaseDecision: vi.fn(),
    getThreatModelAgentRemediationPlan: vi.fn(),
    applyThreatModelAgentRemediationPlan: vi.fn(),
    createThreatModelAgentRemediationTicket: vi.fn(),
    ingestThreatModelAgentRemediationEvidence: vi.fn(),
    testThreatModelAgentRemediationProviderWebhook: vi.fn(),
    getThreatModelCustomerPacket: vi.fn(),
    exportThreatModelCustomerPacketCSV: vi.fn(),
    exportThreatModelCustomerPacketPDF: vi.fn(),
  },
}));

const remediationWebhookSetups: AgentRemediationWebhookSetup[] = [
  {
    provider: "github",
    provider_label: "GitHub",
    callback_url:
      "https://api.threatgenix.test/api/threat-models/tm-1/agent/remediation-plan/webhooks/providers/github/evidence",
    action_marker: "action_id: threat:threat-1:remediation_note",
    action_marker_hint:
      "Keep this marker in the issue, PR, or ticket description so inbound provider events can map evidence back to this remediation action.",
    event_filters: [
      "pull_request.closed",
      "pull_request.synchronize",
      "issues.closed",
      "issues.edited",
    ],
    registration_steps: [
      "Create a repository webhook or app callback for pull request and issue events.",
      "Keep `action_id: threat:threat-1:remediation_note` in the issue or pull request body.",
      "Forward the raw GitHub JSON body with SSR timestamp, nonce, and HMAC signature headers.",
    ],
    required_headers: {
      "X-SSR-Webhook-Timestamp": "<unix timestamp seconds>",
      "X-SSR-Webhook-Nonce": "<unique replay nonce>",
      "X-SSR-Webhook-Signature": "sha256=<hex hmac>",
    },
    signature_scheme: "hmac_sha256_v1",
    signature_base_string: "timestamp + '.' + nonce + '.' + raw_request_body",
    signing_secret_hint:
      "Sign the raw provider payload with the ThreatGenix remediation webhook secret. Do not use a provider API token as the webhook signing secret.",
  },
  {
    provider: "linear",
    provider_label: "Linear",
    callback_url:
      "https://api.threatgenix.test/api/threat-models/tm-1/agent/remediation-plan/webhooks/providers/linear/evidence",
    action_marker: "action_id: threat:threat-1:remediation_note",
    action_marker_hint:
      "Keep this marker in the issue, PR, or ticket description so inbound provider events can map evidence back to this remediation action.",
    event_filters: ["Issue completed", "Issue updated"],
    registration_steps: [
      "Create a Linear webhook for issue updates in the remediation team workspace.",
    ],
    required_headers: {},
    signature_scheme: "hmac_sha256_v1",
    signature_base_string: "timestamp + '.' + nonce + '.' + raw_request_body",
    signing_secret_hint:
      "Sign the raw provider payload with the ThreatGenix remediation webhook secret.",
  },
  {
    provider: "jira",
    provider_label: "Jira",
    callback_url:
      "https://api.threatgenix.test/api/threat-models/tm-1/agent/remediation-plan/webhooks/providers/jira/evidence",
    action_marker: "action_id: threat:threat-1:remediation_note",
    action_marker_hint:
      "Keep this marker in the issue, PR, or ticket description so inbound provider events can map evidence back to this remediation action.",
    event_filters: ["jira:issue_updated", "issue_resolved"],
    registration_steps: [
      "Create a Jira automation or webhook for issue updated and resolved events.",
    ],
    required_headers: {},
    signature_scheme: "hmac_sha256_v1",
    signature_base_string: "timestamp + '.' + nonce + '.' + raw_request_body",
    signing_secret_hint:
      "Sign the raw provider payload with the ThreatGenix remediation webhook secret.",
  },
];

const remediationWebhookTestResponse: AgentRemediationProviderWebhookTestResponse = {
  generated_at: "2026-04-24T12:02:00Z",
  system_name: "Payments Platform",
  provider: "github",
  callback_security_status: "verified",
  nonce_status: "accepted",
  normalized_provider_event: "issue_evidence",
  action_id: "threat:threat-1:remediation_note",
  finding_id: "threat:threat-1",
  action_title: "Caller auth missing on public payment API",
  source_object_type: "threat",
  source_object_id: "threat-1",
  external_ticket_id: "acme/app#42",
  pull_request_url: null,
  commit_sha: null,
  evidence_url: "https://github.com/acme/app/issues/42",
  evidence_summary:
    "GitHub issue closed: [Security] Caller auth missing on public payment API",
  next_step:
    "Signature, nonce, provider parsing, and action mapping are verified.",
  plan: {
    generated_at: "2026-04-24T12:02:00Z",
    system_name: "Payments Platform",
    current_decision: "block",
    loop_status: "ready",
    summary:
      "1 remediation loop action is ready. Applying the plan creates local review artifacts; it does not clear a finding until new proof is attached and the release decision is rerun.",
    actions: [],
    action_history: [],
    rerun_instructions: [],
    plan_markdown: "# Payments Platform Agent Remediation Plan",
  },
};

const model: ThreatModelResponse = {
  id: "tm-1",
  system_name: "Payments Platform",
  description: "Handles merchant payments.",
  data_classification: "Restricted",
  regulatory_scope: ["PCI DSS"],
  deployment_model: "cloud",
  repository_evidence: null,
  cloud_scan_evidence: null,
  iac_evidence: null,
  environment_context_summary: null,
  report_templates: [],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const threat: ThreatResponse = {
  id: "threat-1",
  display_id: "T-001",
  description: "Caller auth missing on public payment API",
  stride_category: "Spoofing",
  threat_subtype: null,
  severity: "High",
  source: "Rules",
  status: "Open",
  dismiss_reason: null,
  rule_id: null,
  ai_enhanced: false,
  provider_managed: false,
  original_rule_threat_id: null,
  affected_node_ids: [],
  affected_edge_ids: [],
  relevance_rationale: null,
  mitigation_plan: null,
  mitigation_owner: null,
  due_date: null,
  mitigation_notes: null,
  control_effectiveness: "none",
  residual_risk_level: "High",
  closed_at: null,
  compliance_controls: [],
  qualification_score: null,
  qualification_label: null,
  qualification_note: null,
  auto_score: null,
  analyst_score: null,
  analyst_score_rationale: null,
  ai_likelihood_score: null,
  ai_likelihood_assessment: null,
  ai_likelihood_generated_at: null,
  cluster_id: null,
  false_positive_reason: null,
  qualification_completed_at: null,
  created_at: "2026-01-01T00:00:00Z",
};

const finding: SecurityReviewFinding = {
  id: "threat:threat-1",
  source_object_type: "threat",
  source_object_id: "threat-1",
  threat_id: "threat-1",
  display_id: "T-001",
  wire_kind: "threat",
  display_kind: "threat",
  source_provenance: "rules_engine",
  source_system: "threatgenix",
  title: "Caller auth missing on public payment API",
  priority: "p0_blocker",
  wire_action_bucket: "bright_red_line",
  queue_bucket: "fix_now",
  computed_queue_bucket: "fix_now",
  truth_status: "validated",
  numeric_score: 98,
  exploitability: "high",
  urgency: "immediate",
  business_impact: "severe",
  regulatory_pressure: "red_line",
  confidence: "high",
  is_real: true,
  is_urgent: true,
  is_exploitable_in_context: true,
  is_regulatory_or_control_relevant: true,
  needs_engineering_change: true,
  needs_evidence: false,
  why_now: "Public entry point reaches cardholder data processing.",
  impacted_assets: ["Payment API"],
  entry_point: "Public API Gateway",
  evidence_refs: ["dfd", "scan", "repository"],
  linked_threat_ids: ["threat-1"],
  linked_change_ids: [],
  linked_control_ids: [],
  code_links: [],
  owner: null,
  due_at: null,
  note: null,
  artifacts: [],
  review_status: "open",
  last_non_terminal_bucket: null,
  primary_mode: "findings",
  noise_disposition: "focus",
  computed_recommendation_changed: false,
  systemic: false,
  next_best_action:
    "Require authenticated caller identity before payment initiation.",
  next_step: "Block unauthenticated payment initiation.",
  rationale_excerpt:
    "Validated public entry point and restricted target asset.",
};

const acceptedFinding: SecurityReviewFinding = {
  ...finding,
  id: "application_review_finding:model:legacy-control",
  source_object_type: "application_review_finding",
  source_object_id: "model:legacy-control",
  threat_id: null,
  display_id: null,
  title: "Legacy control rollout is accepted temporarily",
  priority: "p3_backlog",
  numeric_score: 38,
  wire_action_bucket: "planned_hardening",
  queue_bucket: null,
  computed_queue_bucket: "backlog",
  truth_status: "contextual",
  needs_engineering_change: false,
  review_status: "accepted",
  last_non_terminal_bucket: "backlog",
  primary_mode: "model_health",
  systemic: true,
  next_best_action: "Review the compensating control before expiry.",
  next_step: "Review the compensating control before expiry.",
  rationale_excerpt: "Temporary acceptance is bounded by a control rollout.",
  risk_acceptance: {
    finding_title: "Legacy control rollout is accepted temporarily",
    status: "active",
    accepted_by: "Priya Reviewer",
    accepted_at: "2026-04-24T12:00:00Z",
    expires_at: "2026-06-01T00:00:00Z",
    acceptance_rationale: "Accepted until compensating control rollout completes.",
    compensating_control: "Manual reviewer attestation.",
    reopen_triggers: [],
  },
};

const summary: SecurityReviewApplicationSummary = {
  generated_at: "2026-04-24T12:00:00Z",
  system_name: "Payments Platform",
  overall_priority: "p0_blocker",
  overall_action_bucket: "bright_red_line",
  focus_statement:
    "Public payment initiation can reach restricted payment data without proof of caller identity.",
  rationale: [
    "A public entry point reaches a restricted payment workflow.",
    "The issue has direct PCI relevance and operational blast radius.",
  ],
  next_steps: [
    "Add caller authentication before payment creation.",
    "Attach scan and code evidence after remediation.",
  ],
  coverage: {
    total_findings: 1,
    threat_findings: 1,
    systemic_findings: 0,
    open_threats: 1,
    public_entry_points: 1,
    privileged_surfaces: 1,
    restricted_assets: 1,
    attack_paths: 1,
    attached_evidence_sources: 3,
    missing_evidence_sources: 1,
  },
  priority_counts: [{ key: "p0_blocker", label: "P0 blocker", count: 1 }],
  action_bucket_counts: [
    { key: "bright_red_line", label: "Bright red line", count: 1 },
  ],
  truth_status_counts: [{ key: "validated", label: "Validated", count: 1 }],
  noise_counts: [{ key: "focus", label: "Focus", count: 1 }],
  top_findings: [
    {
      finding_key: "threat:threat-1",
      threat_id: "threat-1",
      display_id: "T-001",
      finding_kind: "threat",
      title: "T-001 · Caller auth missing on public payment API",
      priority: "p0_blocker",
      action_bucket: "bright_red_line",
      truth_status: "validated",
      urgency: "immediate",
      noise_disposition: "focus",
      numeric_score: 98,
      entry_point: "Public API Gateway",
      target_asset: "Payment API",
      rationale_excerpt:
        "Validated public entry point and restricted target asset.",
      next_step: "Block unauthenticated payment initiation.",
      related_attack_path_count: 1,
      evidence_adjustment_count: 0,
      systemic: false,
    },
  ],
  blind_spots: [],
  attack_paths: [
    {
      path_id: "path-1",
      finding_keys: ["threat:threat-1"],
      finding_titles: ["Caller auth missing on public payment API"],
      chain_description:
        "Unauthenticated caller can initiate a payment workflow.",
      entry_point: "Public API Gateway",
      target_asset: "Payment API",
      hop_count: 2,
      support_count: 1,
      composite_exploitability: "high",
      composite_priority: "p0_blocker",
      path_nodes: ["Public API Gateway", "Payment API"],
      evidence_sources: ["dfd", "scan"],
      relationship_reasons: [
        "Public entry point reaches restricted payment workflow.",
      ],
      verification_steps: [
        "Confirm payment initiation rejects unauthenticated callers.",
      ],
    },
  ],
  risk_acceptance_summary: { active: 0, reopened: 0, expired: 0 },
  review_delta_summary: {
    new_findings: 1,
    resolved_findings: 0,
    reopened_findings: 0,
    escalated_findings: 1,
    deescalated_findings: 0,
  },
};

const findingsResponse: SecurityReviewFindingListResponse = {
  generated_at: "2026-04-24T12:00:00Z",
  system_name: "Payments Platform",
  queue_counts: [
    { key: "fix_now", label: "Fix Now", count: 1 },
    { key: "verify", label: "Verify", count: 0 },
    { key: "gather_evidence", label: "Gather Evidence", count: 0 },
    { key: "backlog", label: "Backlog", count: 0 },
  ],
  review_status_counts: [
    { key: "open", label: "Open", count: 1 },
    { key: "in_progress", label: "In Progress", count: 0 },
    { key: "mitigated", label: "Mitigated", count: 0 },
    { key: "accepted", label: "Accepted", count: 1 },
    { key: "dismissed", label: "Dismissed", count: 0 },
  ],
  default_finding_id: "threat:threat-1",
  findings: [finding, acceptedFinding],
};

describe("SecurityReviewReportPanel", () => {
  beforeEach(() => {
    vi.mocked(api.getLatestScanRunbook).mockRejectedValue(new Error("No scan"));
    vi.mocked(api.getThreatModelAgentReleaseDecision).mockResolvedValue({
      generated_at: "2026-04-24T12:00:00Z",
      system_name: "Payments Platform",
      decision: "block",
      decision_reason: "1 blocking finding is grounded enough to stop release.",
      pass_semantics:
        "Ship means no blocking finding based on currently connected evidence; it does not certify that the application is secure.",
      ci: {
        fail_policy: "block_only",
        blocking_decisions: ["block"],
        should_fail: true,
        exit_code: 1,
        reason:
          "CI should fail because decision `block` is included in policy `block_only`.",
      },
      evidence_gaps: [],
      findings: [
        {
          decision: "block",
          finding_id: "threat:threat-1",
          source_object_type: "threat",
          source_object_id: "threat-1",
          title: "Caller auth missing on public payment API",
          priority: "p0_blocker",
          confidence: "high",
          risk_path: ["Public API Gateway", "Payment API"],
          evidence: [
            {
              type: "repository",
              reference: "repository",
              claim: "repository evidence supports this review finding.",
              validated: true,
              source_object_type: "code_surface",
              source_object_id: "surface-payment-initiation",
              location: "app/api/payments.py:42",
              relationship: "confirms_missing_control",
              strength: "strong",
            },
            {
              type: "dfd",
              reference: "dfd_node:node-api",
              claim: "DFD node Public API Gateway is affected by this finding.",
              validated: true,
              source_object_type: "dfd_node",
              source_object_id: "node-api",
              location: "dfd_node:node-api",
              relationship: "affected_component",
              strength: "strong",
            },
          ],
          fix_instructions: [
            "Require authenticated caller identity before payment initiation.",
          ],
          verification: {
            required: true,
            suggested_test:
              "Confirm payment initiation rejects unauthenticated callers.",
            evidence_needed: [],
          },
        },
      ],
    });
    vi.mocked(api.getThreatModelAgentRemediationPlan).mockResolvedValue({
      generated_at: "2026-04-24T12:00:00Z",
      system_name: "Payments Platform",
      current_decision: "block",
      loop_status: "ready",
      summary:
        "1 remediation loop action is ready. Applying the plan creates local review artifacts; it does not clear a finding until new proof is attached and the release decision is rerun.",
      actions: [
        {
          action_id: "threat:threat-1:remediation_note",
          finding_id: "threat:threat-1",
          source_object_type: "threat",
          source_object_id: "threat-1",
          title: "Caller auth missing on public payment API",
          current_decision: "block",
          action_kind: "patch_guidance",
          artifact_kind: "remediation_note",
          priority: "p0_blocker",
          instruction:
            "Require authenticated caller identity before payment initiation.",
          verification_required: true,
          evidence_needed: [],
          expected_next_decision: "verify",
          rerun_required: true,
          ticket_draft: {
            provider: "github_issue",
            title: "[Security] Caller auth missing on public payment API",
            body: "## Security remediation",
            labels: ["security-review", "block", "p0-blocker"],
            priority: "p0_blocker",
            confirmation_required: true,
            external_creation_status: "draft_only",
            callback_setup: remediationWebhookSetups[0],
            callback_setups: remediationWebhookSetups,
            external_ticket_id: null,
            external_ticket_url: null,
          },
          transition: {
            status: "needs_action",
            current_decision: "block",
            expected_next_decision: "verify",
            rationale:
              "No local remediation, verification, or evidence-request artifact has been created for this action yet.",
            artifact_count: 0,
            latest_artifact_at: null,
            evidence_count: 1,
          },
        },
      ],
      action_history: [],
      rerun_instructions: [
        "Apply the patch, control change, or evidence request named in each action.",
        "Attach implementation proof, validation output, PR link, or reviewer evidence to the finding.",
        "Rerun GET /api/threat-models/{id}/review and GET /api/threat-models/{id}/agent/release-decision.",
      ],
      plan_markdown: "# Payments Platform Agent Remediation Plan",
    });
    vi.mocked(api.applyThreatModelAgentRemediationPlan).mockResolvedValue({
      generated_at: "2026-04-24T12:01:00Z",
      system_name: "Payments Platform",
      created_artifact_count: 1,
      updated_finding_ids: ["threat:threat-1"],
      plan: {
        generated_at: "2026-04-24T12:01:00Z",
        system_name: "Payments Platform",
        current_decision: "block",
        loop_status: "ready",
        summary:
          "1 remediation loop action is ready. Applying the plan creates local review artifacts; it does not clear a finding until new proof is attached and the release decision is rerun.",
        actions: [
          {
            action_id: "threat:threat-1:remediation_note",
            finding_id: "threat:threat-1",
            source_object_type: "threat",
            source_object_id: "threat-1",
            title: "Caller auth missing on public payment API",
            current_decision: "block",
            action_kind: "patch_guidance",
            artifact_kind: "remediation_note",
            priority: "p0_blocker",
            instruction:
              "Require authenticated caller identity before payment initiation.",
            verification_required: true,
            evidence_needed: [],
            expected_next_decision: "verify",
            rerun_required: true,
            ticket_draft: {
              provider: "github_issue",
              title: "[Security] Caller auth missing on public payment API",
              body: "## Security remediation",
              labels: ["security-review", "block", "p0-blocker"],
              priority: "p0_blocker",
            confirmation_required: true,
            external_creation_status: "draft_only",
            callback_setup: remediationWebhookSetups[0],
            callback_setups: remediationWebhookSetups,
            external_ticket_id: null,
            external_ticket_url: null,
          },
            transition: {
              status: "ready_for_verify",
              current_decision: "block",
              expected_next_decision: "verify",
              rationale:
                "A local remediation artifact exists; attach implementation proof and rerun the review before moving past verify.",
              artifact_count: 1,
              latest_artifact_at: "2026-04-24T12:01:00Z",
              evidence_count: 1,
            },
          },
        ],
        action_history: [
          {
            action_id: "threat:threat-1:remediation_note",
            finding_id: "threat:threat-1",
            artifact_kind: "remediation_note",
            artifact_title: "Remediation note for Caller auth missing on public payment API",
            created_at: "2026-04-24T12:01:00Z",
            transition_status: "ready_for_verify",
          },
        ],
        rerun_instructions: [
          "Apply the patch, control change, or evidence request named in each action.",
        ],
        plan_markdown: "# Payments Platform Agent Remediation Plan",
      },
    });
    vi.mocked(
      api.testThreatModelAgentRemediationProviderWebhook,
    ).mockResolvedValue(remediationWebhookTestResponse);
    vi.mocked(api.getThreatModelCustomerPacket).mockResolvedValue({
      generated_at: "2026-04-24T12:00:00Z",
      system_name: "Payments Platform",
      audience: "customer_security_review",
      packet_version: "customer_packet_v1",
      packet_hash:
        "sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
      redaction_profile: "customer_safe_v1",
      release_decision: "block",
      decision_summary: "1 blocking finding is grounded enough to stop release.",
      scope: ["System: Payments Platform.", "Repository evidence is attached."],
      proven: [
        "2 evidence source(s) are connected to this review.",
        "1 customer-visible risk item(s) have enough supporting context to discuss with a reviewer.",
      ],
      assumptions: [
        "Ship means no blocking finding based on currently connected evidence; it does not certify that the application is secure.",
      ],
      unknowns: [
        "2 expected evidence source(s) are still missing or incomplete.",
        "Evidence gap: Code surfaces need DFD mapping evidence",
        "Evidence gap: Cloud configuration evidence is missing for an in-scope deployment",
        "Evidence gap: Infrastructure-as-code evidence is missing for an in-scope deployment",
        "Scanner validation evidence is imported but not yet mapped to a customer-visible reviewed risk.",
      ],
      validated_risks: [
        {
          title: "Caller auth missing on public payment API",
          release_decision: "block",
          customer_status: "needs_verification",
          summary:
            "Caller auth missing on public payment API affects the reviewed path Public API Gateway -> Payment API.",
          evidence_summary:
            "1 evidence reference is connected across code; 1 is marked validated.",
          next_step:
            "Confirm payment initiation rejects unauthenticated callers.",
        },
      ],
      accepted_risks: [],
      evidence_gaps: [
        {
          title: "Cloud configuration evidence is missing for an in-scope deployment",
          release_decision: "gather_evidence",
          customer_status: "evidence_gap",
          summary:
            "Cloud configuration evidence is required before the packet can claim runtime controls.",
          evidence_summary:
            "No customer-safe validation evidence is connected yet. Expected evidence types: cloud.",
          next_step: "Attach cloud configuration evidence before sharing as proven.",
        },
        {
          title:
            "Infrastructure-as-code evidence is missing for an in-scope deployment",
          release_decision: "gather_evidence",
          customer_status: "evidence_gap",
          summary:
            "Infrastructure-as-code evidence is required before the packet can claim deployment controls.",
          evidence_summary:
            "No customer-safe validation evidence is connected yet. Expected evidence types: iac.",
          next_step: "Attach IaC evidence before sharing as proven.",
        },
        {
          title: "Threat model lacks DFD coverage",
          release_decision: "gather_evidence",
          customer_status: "evidence_gap",
          summary:
            "DFD coverage is required before the packet can claim data-flow review coverage.",
          evidence_summary:
            "No customer-safe validation evidence is connected yet. Expected evidence types: dfd.",
          next_step: "Add DFD coverage before sharing as proven.",
        },
      ],
      source_fingerprints: [
        {
          source_type: "review_summary",
          source_id: "application_review_summary",
          label: "Application review summary",
          fingerprint:
            "sha256:aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000",
          collected_at: "2026-04-24T12:00:00Z",
        },
        {
          source_type: "repository",
          source_id: "repository_evidence",
          label: "example-org/threatgenix",
          fingerprint:
            "sha256:bbbbccccddddeeeeffff1111222233334444555566667777888899990000aaaa",
          collected_at: "2026-04-24T11:55:00Z",
        },
        {
          source_type: "scan",
          source_id: "validation_scan:scan-semgrep-1",
          label: "Semgrep validation scan (2 findings)",
          fingerprint:
            "sha256:ccccddddeeeeffff1111222233334444555566667777888899990000aaaabbbb",
          collected_at: "2026-04-24T11:58:00Z",
        },
      ],
      redaction_notes: [
        "Customer packet omits raw repository contents, secret values, credentials, and internal evidence payloads.",
        "Packet fingerprints identify the reviewed evidence snapshot without disclosing the underlying evidence body.",
      ],
      customer_safe_markdown:
        "# Payments Platform Customer Security Review Packet\n\nPacket hash: sha256:111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000\n\n## What is proven\n2 evidence source(s) are connected to this review.\n\n## What remains unknown\nScanner validation evidence is imported but not yet mapped to a customer-visible reviewed risk.\n\n## Source fingerprints\n- Application review summary (review_summary): sha256:aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000",
    });
    vi.mocked(api.exportThreatModelCustomerPacketCSV).mockResolvedValue(
      new Blob(["section,item\nmetadata,Payments Platform"], {
        type: "text/csv",
      }),
    );
    vi.mocked(api.exportThreatModelCustomerPacketPDF).mockResolvedValue(
      new Blob(["%PDF-test%"], { type: "application/pdf" }),
    );
  });

  it("renders a full-picture stakeholder report from summary and finding data", async () => {
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(screen.getByText("Stakeholder report")).toBeInTheDocument();
    expect(screen.getByText("Release blocker posture")).toBeInTheDocument();
    expect(screen.getByText("Executive Readout")).toBeInTheDocument();
    expect(screen.getByText("Quantified Risk Inventory")).toBeInTheDocument();
    expect(screen.getByText("Agent/API Release Decision")).toBeInTheDocument();
    expect(screen.getByText("Agent Remediation Loop")).toBeInTheDocument();
    expect(screen.getByText("Customer Security Packet")).toBeInTheDocument();
    expect(screen.getByText("Risk Acceptances")).toBeInTheDocument();
    expect(
      screen.getByText("Legacy control rollout is accepted temporarily"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Accepted until compensating control rollout completes."),
    ).toBeInTheDocument();
    expect(screen.getByText(/accepted by Priya Reviewer/)).toBeInTheDocument();
    expect(screen.getByText(/expires 2026-06-01/)).toBeInTheDocument();
    expect(await screen.findByText("CI exit 1")).toBeInTheDocument();
    expect(await screen.findByText("Patch guidance")).toBeInTheDocument();
    expect(screen.getByText("Needs Action")).toBeInTheDocument();
    expect(screen.getByText(/Ticket draft: github issue/)).toBeInTheDocument();
    expect(screen.getByText(/draft only/)).toBeInTheDocument();
    expect(screen.getByText(/Connector creation:/)).toBeInTheDocument();
    expect(screen.getByText(/customer-owned provider token/)).toBeInTheDocument();
    expect(screen.getByText(/Callback security:/)).toBeInTheDocument();
    expect(screen.getByText(/HMAC-SHA256 signature headers/)).toBeInTheDocument();
    expect(screen.getByText("Webhook setup")).toBeInTheDocument();
    expect(screen.getByText("Provider callbacks for this action")).toBeInTheDocument();
    expect(screen.getAllByText("Signed callback tester")).toHaveLength(3);
    expect(screen.getByText("GitHub")).toBeInTheDocument();
    expect(screen.getByText("Linear")).toBeInTheDocument();
    expect(screen.getByText("Jira")).toBeInTheDocument();
    expect(screen.getByText(/providers\/github\/evidence/)).toBeInTheDocument();
    expect(screen.getByText(/pull_request.closed/)).toBeInTheDocument();
    expect(
      screen.getAllByText("action_id: threat:threat-1:remediation_note")[0],
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Copy setup" })).toHaveLength(3);
    expect(screen.getAllByRole("button", { name: "Copy signer CLI" })).toHaveLength(3);
    expect(screen.getAllByRole("button", { name: "Test callback" })).toHaveLength(3);
    expect(screen.getByText("Confirm ticket handoff")).toBeInTheDocument();
    expect(screen.getByText("PR/evidence webhook ready")).toBeInTheDocument();
    expect(
      screen.getByText("Create remediation artifacts"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export PDF" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export CSV" })).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Reviewer approved source labels for export/),
    ).toBeInTheDocument();
    expect(screen.getByText(/expect Verify after proof/)).toBeInTheDocument();
    expect(
      await screen.findByText("What remains unknown"),
    ).toBeInTheDocument();
    expect(screen.getByText("customer_packet_v1")).toBeInTheDocument();
    expect(screen.getByText(/Packet hash sha256:1111222233/)).toBeInTheDocument();
    expect(screen.getByText("Source fingerprints")).toBeInTheDocument();
    expect(screen.getByText(/Review summary: Application review summary/)).toBeInTheDocument();
    expect(screen.getByText("External sharing controls")).toBeInTheDocument();
    expect(screen.getByText(/raw repository contents/)).toBeInTheDocument();
    expect(
      screen.getByText(
        "Scanner validation evidence is imported but not yet mapped to a customer-visible reviewed risk.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Validation scan: Semgrep validation scan/),
    ).toBeInTheDocument();
    expect(screen.getByText("Threat model lacks DFD coverage")).toBeInTheDocument();
    expect(
      screen.getByText(
        "No customer-safe validation evidence is connected yet. Expected evidence types: dfd.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("app/api/payments.py:42", { exact: false }),
    ).toBeInTheDocument();
    expect(screen.getByText("Finding type")).toBeInTheDocument();
    expect(screen.getByText("Evidence confidence")).toBeInTheDocument();
    expect(screen.getByText("STRIDE shape")).toBeInTheDocument();
    expect(screen.getByText("Unowned high risk")).toBeInTheDocument();
    expect(screen.getByText("Review Progress")).toBeInTheDocument();
    expect(screen.getByText("Validation Coverage")).toBeInTheDocument();
    expect(screen.getByText("Attack Surface Shape")).toBeInTheDocument();
    expect(screen.getByText("Projected Attack Paths")).toBeInTheDocument();
    expect(screen.getByText("Supporting Analysis")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Hard counts from the current review findings and queue state.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Prioritized findings from review scoring and evidence context.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Modeled routes, not measured network distance."),
    ).toBeInTheDocument();

    const metricGrid = screen
      .getByText("P0 blockers")
      .closest(".security-review-report-metric-grid");
    expect(metricGrid).not.toBeNull();
    expect(
      within(metricGrid as HTMLElement).getAllByText("1").length,
    ).toBeGreaterThan(0);

    expect(screen.getByText("PCI DSS")).toBeInTheDocument();
    expect(screen.getAllByText("Runtime scan").length).toBeGreaterThan(0);
    expect(screen.getByText("Code evidence")).toBeInTheDocument();
    expect(
      screen.getByText((content) =>
        content.includes("app/api/payments.py:42") &&
        content.includes("dfd_node:node-api"),
      ),
    ).toBeInTheDocument();
  });

  it("renders older agent responses that do not include CI metadata", async () => {
    vi.mocked(api.getThreatModelAgentReleaseDecision).mockResolvedValueOnce({
      generated_at: "2026-04-24T12:00:00Z",
      system_name: "Payments Platform",
      decision: "fix_now",
      decision_reason:
        "1 finding requires current-cycle engineering work before confidence is defensible.",
      pass_semantics:
        "Ship means no blocking finding based on currently connected evidence; it does not certify that the application is secure.",
      evidence_gaps: [],
      findings: [],
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(await screen.findByText("CI exit 0")).toBeInTheDocument();
    expect(
      screen.getByText(
        "CI should continue because decision `fix_now` is not included in policy `block_only`.",
      ),
    ).toBeInTheDocument();
  });

  it("renders deterministic validation runbook coverage when available", async () => {
    vi.mocked(api.getLatestScanRunbook).mockResolvedValue({
      coverage: {
        scan_job_id: "scan-1",
        scan_completed_at: "2026-04-25T00:00:00Z",
        tool_names: ["semgrep", "trivy"],
        target_binding: "mixed",
        finding_count: 4,
        deterministic_finding_count: 4,
        assisted_finding_count: 0,
        artifact_count: 2,
        mapped_threat_count: 2,
        validated_threat_count: 1,
        indicated_threat_count: 1,
        unbound_finding_count: 2,
        untested_threat_count: 5,
        confidence_counts: { validated: 1, indicated: 1, untested: 5 },
        validated_risk_score: 80,
        indicated_risk_score: 60,
        ai_assisted_risk_score: 0,
      },
      executive_summary: "Semgrep and Trivy produced deterministic validation evidence.",
      gaps: ["2 validation finding(s) are retained as evidence but not bound to a semantic threat."],
      mapped_threats: [],
      unbound_findings: [
        {
          finding_id: "finding-1",
          title: "JWT verification disabled",
          severity: "high",
          tool_name: "semgrep",
          target: "/repo",
          matched_at: "app/auth.py:42",
          cve_ids: [],
          tags: ["jwt"],
          confidence_label: "untested",
          evidence_scope: "unbound",
          proof_class: "deterministic",
          evidence_quality: "moderate",
          risk_score: 44,
          next_action: "Bind this finding to an affected DFD node or mark it not applicable.",
          explanation: "Finding was retained as deterministic evidence.",
        },
      ],
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(await screen.findByText("Semgrep and Trivy produced deterministic validation evidence.")).toBeInTheDocument();
    expect(screen.getByText("Validated threats")).toBeInTheDocument();
    expect(screen.getByText("Unbound findings")).toBeInTheDocument();
    expect(screen.getByText("JWT verification disabled · high")).toBeInTheDocument();
  });

  it("copies a stakeholder-safe report summary", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Copy report" }));

    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("# Payments Platform Security Review Report"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("P0 blockers: 1"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("## Projected Attack Paths"),
    );
    expect(
      await screen.findByRole("button", { name: "Copied" }),
    ).toBeInTheDocument();
  });

  it("creates remediation artifacts from the agent remediation loop", async () => {
    const user = userEvent.setup();

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    await user.click(
      await screen.findByRole("button", {
        name: "Create remediation artifacts",
      }),
    );

    expect(api.applyThreatModelAgentRemediationPlan).toHaveBeenCalledWith("tm-1");
    expect(
      await screen.findByRole("button", { name: "Artifacts created" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Ready For Verify")).toBeInTheDocument();
    expect(screen.getByText(/Action history · remediation note/)).toBeInTheDocument();
  });

  it("copies provider webhook setup instructions from remediation actions", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    const [copySetupButton] = await screen.findAllByRole("button", {
      name: "Copy setup",
    });
    expect(copySetupButton).toBeDefined();
    await user.click(copySetupButton as HTMLElement);

    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("GitHub remediation webhook setup"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("/webhooks/providers/github/evidence"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("action_id: threat:threat-1:remediation_note"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("remediation_webhook_signer.py"),
    );
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("copies a provider signer CLI command with the exact sample payload", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    const [copySignerButton] = await screen.findAllByRole("button", {
      name: "Copy signer CLI",
    });
    expect(copySignerButton).toBeDefined();
    await user.click(copySignerButton as HTMLElement);

    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("cat > ssr-github-callback-payload.json"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining(
        "python3 threatgenix/backend/scripts/remediation_webhook_signer.py",
      ),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining(
        "action_id: threat:threat-1:remediation_note",
      ),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("--format tester-json"),
    );
    expect(
      await screen.findByRole("button", { name: "Signer copied" }),
    ).toBeInTheDocument();
  });

  it("tests a signed provider callback without ingesting evidence", async () => {
    const user = userEvent.setup();

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    await user.type(
      await screen.findByLabelText("GitHub callback timestamp"),
      "1700000000",
    );
    await user.type(
      screen.getByLabelText("GitHub callback nonce"),
      "nonce-callback-test",
    );
    await user.type(
      screen.getByLabelText("GitHub callback signature"),
      "sha256=abc123",
    );
    const [testButton] = screen.getAllByRole("button", {
      name: "Test callback",
    });
    expect(testButton).toBeDefined();
    await user.click(testButton as HTMLElement);

    expect(api.testThreatModelAgentRemediationProviderWebhook).toHaveBeenCalledWith(
      "tm-1",
      "github",
      expect.objectContaining({
        provider: "github",
        payload_text: expect.stringContaining(
          "action_id: threat:threat-1:remediation_note",
        ),
        headers: {
          "X-SSR-Webhook-Timestamp": "1700000000",
          "X-SSR-Webhook-Nonce": "nonce-callback-test",
          "X-SSR-Webhook-Signature": "sha256=abc123",
        },
      }),
    );
    expect(await screen.findByRole("button", { name: "Callback verified" }))
      .toBeInTheDocument();
    expect(
      screen.getByText(
        "Verified issue evidence · Caller auth missing on public payment API",
      ),
    ).toBeInTheDocument();
  });

  it("copies a customer security packet export", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Copy customer packet" }),
    );

    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining(
        "# Payments Platform Customer Security Review Packet",
      ),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("## What remains unknown"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("Packet hash: sha256:1111222233334444"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("## Source fingerprints"),
    );
    expect(
      await screen.findByRole("button", { name: "Copied packet" }),
    ).toBeInTheDocument();
  });

  it("exports customer security packet PDF and CSV with reviewer-approved labels", async () => {
    const user = userEvent.setup();
    const createObjectURL = vi
      .spyOn(URL, "createObjectURL")
      .mockReturnValue("blob:customer-packet");
    const revokeObjectURL = vi
      .spyOn(URL, "revokeObjectURL")
      .mockImplementation(() => {});

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "Export PDF" }));
    expect(api.exportThreatModelCustomerPacketPDF).toHaveBeenCalledWith("tm-1", {
      includeSourceLabels: false,
    });
    expect(createObjectURL).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:customer-packet");

    await user.click(
      screen.getByLabelText(/Reviewer approved source labels for export/),
    );
    await user.click(screen.getByRole("button", { name: "Export CSV" }));

    expect(api.exportThreatModelCustomerPacketCSV).toHaveBeenCalledWith("tm-1", {
      includeSourceLabels: true,
    });

    createObjectURL.mockRestore();
    revokeObjectURL.mockRestore();
  });

  it("opens the deep-dive workspace from a top-risk row", async () => {
    const user = userEvent.setup();
    const onOpenFinding = vi.fn();
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
        onOpenFinding={onOpenFinding}
      />,
    );

    await user.click(
      screen.getByRole("button", {
        name: /Caller auth missing on public payment API/i,
      }),
    );

    expect(onOpenFinding).toHaveBeenCalledWith(finding);
  });

  it("reveals attack path detail when more context is available", async () => {
    const user = userEvent.setup();
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(screen.queryByText("Modeled route")).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", {
        name: /See more about Unauthenticated caller can initiate a payment workflow/i,
      }),
    );

    expect(screen.getByText("Modeled route")).toBeInTheDocument();
    expect(screen.getByText("Linked findings")).toBeInTheDocument();
    expect(screen.getByText("Why linked")).toBeInTheDocument();
    expect(screen.getByText("Verification")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Public entry point reaches restricted payment workflow.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(
        "Confirm payment initiation rejects unauthenticated callers.",
      ).length,
    ).toBeGreaterThan(0);

    await user.click(
      screen.getByRole("button", {
        name: /Show less for Unauthenticated caller can initiate a payment workflow/i,
      }),
    );

    expect(screen.queryByText("Modeled route")).not.toBeInTheDocument();
  });

  it("opens the deep-dive workspace from an attack path action", async () => {
    const user = userEvent.setup();
    const onOpenFinding = vi.fn();
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
        onOpenFinding={onOpenFinding}
      />,
    );

    await user.click(
      screen.getByRole("button", {
        name: /Open finding for Unauthenticated caller can initiate a payment workflow/i,
      }),
    );

    expect(onOpenFinding).toHaveBeenCalledWith(finding);
  });
});
