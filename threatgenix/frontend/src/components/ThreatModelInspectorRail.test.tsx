import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  ReviewArtifactKind,
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
} from "../types/api";
import { ThreatModelInspectorRail } from "./ThreatModelInspectorRail";

const {
  getThreatModelSecurityReview,
  getThreatModelReviewFindings,
  triageThreat,
  updateThreatModelReviewFinding,
  acceptThreatModelReviewFindingRisk,
  createThreatModelReviewArtifact,
} = vi.hoisted(() => ({
  getThreatModelSecurityReview: vi.fn(),
  getThreatModelReviewFindings: vi.fn(),
  triageThreat: vi.fn(),
  updateThreatModelReviewFinding: vi.fn(),
  acceptThreatModelReviewFindingRisk: vi.fn(),
  createThreatModelReviewArtifact: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    getThreatModelSecurityReview,
    getThreatModelReviewFindings,
    triageThreat,
    updateThreatModelReviewFinding,
    acceptThreatModelReviewFindingRisk,
    createThreatModelReviewArtifact,
  },
}));

vi.mock("./SecurityReviewPanel", () => ({
  SecurityReviewPanel: ({
    findingsResponse,
    onQueueBucketChange,
    onStatusChange,
    onRiskAcceptanceSubmit,
    onCreateArtifact,
  }: {
    findingsResponse: Pick<SecurityReviewFindingListResponse, "findings"> | null;
    onQueueBucketChange?: (finding: SecurityReviewFinding, bucket: ReviewQueueBucket) => void;
    onStatusChange?: (finding: SecurityReviewFinding, status: ReviewStatus) => void;
    onRiskAcceptanceSubmit?: (
      finding: SecurityReviewFinding,
      payload: {
        accepted_by?: string | null;
        expires_at?: string | null;
        acceptance_rationale: string;
        compensating_control?: string | null;
      },
    ) => void | Promise<void>;
    onCreateArtifact?: (finding: SecurityReviewFinding, kind: ReviewArtifactKind) => void;
  }) => {
    const finding = findingsResponse?.findings[0] ?? null;
    return (
      <div>
        <div>Security Review Panel</div>
        {finding && onQueueBucketChange ? (
          <>
            <button
              type="button"
              onClick={() => onQueueBucketChange(finding, "verify")}
            >
              Queue To Verify
            </button>
            <button
              type="button"
              onClick={() => onQueueBucketChange(finding, "backlog")}
            >
              Queue To Backlog
            </button>
          </>
        ) : null}
        {finding ? (
          <div>Queue Bucket: {finding.queue_bucket ?? "none"}</div>
        ) : null}
        {finding && onStatusChange ? (
          <button
            type="button"
            onClick={() => onStatusChange(finding, "accepted")}
          >
            Mark Accepted
          </button>
        ) : null}
        {finding && onRiskAcceptanceSubmit ? (
          <button
            type="button"
            onClick={() =>
              onRiskAcceptanceSubmit(finding, {
                accepted_by: "Priya Reviewer",
                expires_at: "2026-06-01T00:00:00.000Z",
                acceptance_rationale:
                  "Accepted until repository access is approved.",
                compensating_control:
                  "Manual reviewer attestation is attached.",
              })
            }
          >
            Submit Acceptance
          </button>
        ) : null}
        {finding ? (
          <div>Review Status: {finding.review_status ?? "unknown"}</div>
        ) : null}
        {finding && onCreateArtifact ? (
          <button
            type="button"
            onClick={() => onCreateArtifact(finding, "remediation_note")}
          >
            Draft Remediation
          </button>
        ) : null}
      </div>
    );
  },
}));

vi.mock("./SecurityReviewFindingsPanel", () => ({
  SecurityReviewFindingsPanel: () => <div>Findings Panel</div>,
}));

vi.mock("./SecurityReviewCompliancePanel", () => ({
  SecurityReviewCompliancePanel: () => <div>Compliance Panel</div>,
}));

vi.mock("./SecurityReviewModelHealthPanel", () => ({
  SecurityReviewModelHealthPanel: () => <div>Model Health Panel</div>,
}));

vi.mock("./SecurityReviewReportPanel", () => ({
  SecurityReviewReportPanel: ({
    onOpenFinding,
  }: {
    onOpenFinding?: (finding: { id: string; primary_mode: "findings" }) => void;
  }) => (
    <div>
      <div>Report Panel</div>
      <button
        type="button"
        onClick={() =>
          onOpenFinding?.({
            id: "threat:threat-1",
            primary_mode: "findings",
          })
        }
      >
        Open Report Finding
      </button>
    </div>
  ),
}));

vi.mock("./assistant/ThreatModelAssistantPanel", () => ({
  ThreatModelAssistantPanel: ({
    onPersistActionArtifacts,
    selectedReviewFinding,
  }: {
    onPersistActionArtifacts?: (
      artifacts: Array<unknown>,
    ) => Promise<void> | void;
    selectedReviewFinding?: { display_id?: string | null } | null;
  }) => (
    <div>
      <div>Copilot Panel</div>
      <div>
        Copilot Focus: {selectedReviewFinding?.display_id ?? "Queue-wide"}
      </div>
      {onPersistActionArtifacts ? (
        <button
          type="button"
          onClick={() =>
            onPersistActionArtifacts([
              {
                kind: "verification_note",
                title: "Verification note · Spoofed caller identity",
                summary: "Prove the ingress control exists.",
                body: "Control to verify\n- Confirm authentication is enforced.",
                review_finding_id: "threat:threat-1",
                source_object_type: "threat",
                source_object_id: "threat-1",
                references: [],
              },
            ])
          }
        >
          Persist Copilot Artifact
        </button>
      ) : null}
    </div>
  ),
}));

describe("ThreatModelInspectorRail", () => {
  beforeEach(() => {
    getThreatModelSecurityReview.mockReset();
    getThreatModelReviewFindings.mockReset();
    triageThreat.mockReset();
    updateThreatModelReviewFinding.mockReset();
    acceptThreatModelReviewFindingRisk.mockReset();
    createThreatModelReviewArtifact.mockReset();
    getThreatModelSecurityReview.mockResolvedValue({
      generated_at: "2026-01-01T00:00:00Z",
      system_name: "Example",
      overall_priority: "p1_now",
      overall_action_bucket: "engineer_now",
      focus_statement: "Focus on the top queue item.",
      rationale: [],
      next_steps: [],
      coverage: {
        total_findings: 1,
        threat_findings: 1,
        systemic_findings: 0,
        open_threats: 1,
        public_entry_points: 1,
        privileged_surfaces: 0,
        restricted_assets: 0,
        attack_paths: 0,
        attached_evidence_sources: 0,
        missing_evidence_sources: 1,
      },
      priority_counts: [],
      action_bucket_counts: [],
      truth_status_counts: [],
      noise_counts: [],
      top_findings: [],
      blind_spots: [],
      attack_paths: [],
      risk_acceptance_summary: { active: 0, reopened: 0, expired: 0 },
      review_delta_summary: {
        new_findings: 1,
        resolved_findings: 0,
        reopened_findings: 0,
        escalated_findings: 0,
        deescalated_findings: 0,
      },
    });
    getThreatModelReviewFindings.mockResolvedValue({
      generated_at: "2026-01-01T00:00:00Z",
      system_name: "Example",
      queue_counts: [],
      review_status_counts: [],
      default_finding_id: "threat:threat-1",
      findings: [
        {
          id: "threat:threat-1",
          source_object_type: "threat",
          source_object_id: "threat-1",
          threat_id: "threat-1",
          display_id: "T-001",
          wire_kind: "threat",
          display_kind: "threat",
          source_provenance: "rules_engine",
          source_system: "threatgenix",
          title: "Spoofed caller identity",
          priority: "p1_now",
          wire_action_bucket: "engineer_now",
          queue_bucket: "fix_now",
          computed_queue_bucket: "fix_now",
          truth_status: "validated",
          numeric_score: 92,
          exploitability: "high",
          urgency: "immediate",
          business_impact: "high",
          regulatory_pressure: "high",
          confidence: "high",
          is_real: true,
          is_urgent: true,
          is_exploitable_in_context: true,
          is_regulatory_or_control_relevant: true,
          needs_engineering_change: true,
          needs_evidence: false,
          why_now: "This is active work.",
          impacted_assets: [],
          entry_point: "API Gateway",
          evidence_refs: ["dfd"],
          linked_threat_ids: ["threat-1"],
          linked_change_ids: [],
          linked_control_ids: [],
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
          next_best_action: "Assign an owner and tighten the ingress path.",
          next_step: "Assign an owner.",
          rationale_excerpt: "Validated against the architecture.",
        },
      ],
    });
  });

  it("renders the workbench tabs and keeps the copilot outside the tab set", async () => {
    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(5);
    expect(screen.getByRole("tab", { name: "Review" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Compliance" })).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: /Model Health/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Report" })).toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "Assistant" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Copilot Panel")).toBeInTheDocument();
    expect(screen.queryByText(/Phase A/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Phase 1/i)).not.toBeInTheDocument();
  });

  it("switches to Findings when a focused threat is selected from outside the rail", async () => {
    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[
          {
            id: "threat-1",
            display_id: "T-001",
            description: "Spoofed caller identity",
            stride_category: "Spoofing",
            severity: "High",
            source: "Rules",
            status: "Open",
            dismiss_reason: null,
            relevance_rationale: null,
            mitigation_plan: null,
            mitigation_owner: null,
            due_date: null,
            mitigation_notes: null,
            control_effectiveness: "none",
            residual_risk_level: "High",
            compliance_controls: [],
            threat_subtype: null,
            rule_id: null,
            ai_enhanced: false,
            provider_managed: false,
            original_rule_threat_id: null,
            affected_node_ids: [],
            affected_edge_ids: [],
            closed_at: null,
            auto_score: null,
            analyst_score: null,
            analyst_score_rationale: null,
            qualification_score: null,
            qualification_label: null,
            qualification_note: null,
            ai_likelihood_assessment: null,
            ai_likelihood_score: null,
            ai_likelihood_generated_at: null,
            cluster_id: null,
            false_positive_reason: null,
            qualification_completed_at: null,
            created_at: "2026-01-01T00:00:00Z",
            scan_status: undefined,
          },
        ]}
        focusedThreatId="threat-1"
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(await screen.findByText("Findings Panel")).toBeInTheDocument();
    expect(screen.queryByText("Security Review Panel")).not.toBeInTheDocument();
  });

  it("lets the user switch to model health manually", async () => {
    const user = userEvent.setup();
    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 2, warning_count: 0, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /Model Health/ }));
    expect(screen.getByText("Model Health Panel")).toBeInTheDocument();
  });

  it("switches to report without showing the copilot column", async () => {
    const user = userEvent.setup();
    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Report" }));

    expect(screen.getByText("Report Panel")).toBeInTheDocument();
    expect(screen.queryByText("Copilot Panel")).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Open Report Finding" }),
    );
    expect(screen.getByText("Findings Panel")).toBeInTheDocument();
    expect(screen.getByText("Copilot Panel")).toBeInTheDocument();
  });

  it("switches between findings, compliance, report, and review manually", async () => {
    const user = userEvent.setup();
    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Findings" }));
    expect(screen.getByText("Findings Panel")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Compliance" }));
    expect(screen.getByText("Compliance Panel")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Report" }));
    expect(screen.getByText("Report Panel")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Review" }));
    expect(screen.getByText("Security Review Panel")).toBeInTheDocument();
  });

  it("keeps copilot focused on the active mode finding", async () => {
    const user = userEvent.setup();
    getThreatModelReviewFindings.mockResolvedValueOnce({
      generated_at: "2026-01-01T00:00:00Z",
      system_name: "Example",
      queue_counts: [],
      review_status_counts: [],
      default_finding_id: "threat:threat-1",
      findings: [
        {
          id: "threat:threat-1",
          display_id: "T-001",
          display_kind: "threat",
          primary_mode: "findings",
          title: "Spoofed caller identity",
        },
        {
          id: "compliance:evidence-1",
          display_id: "C-001",
          display_kind: "evidence_gap",
          primary_mode: "compliance",
          title: "Missing scan authorization evidence",
        },
      ],
    });

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(await screen.findByText("Copilot Focus: T-001")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Compliance" }));
    expect(screen.getByText("Compliance Panel")).toBeInTheDocument();
    expect(screen.getByText("Copilot Focus: C-001")).toBeInTheDocument();
  });

  it("keeps the workbench mounted when a queue update is rejected", async () => {
    const user = userEvent.setup();
    updateThreatModelReviewFinding.mockRejectedValueOnce(
      new Error(
        '400: {"detail":"Terminal findings must be reopened before changing queue bucket."}',
      ),
    );

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Queue To Verify" }));

    expect(screen.getByText("Security Review Panel")).toBeInTheDocument();
    expect(
      screen.queryByText("Security review unavailable."),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Action blocked.");
    expect(screen.getByRole("alert")).toHaveTextContent(
      '400: {"detail":"Terminal findings must be reopened before changing queue bucket."}',
    );
  });

  it("updates queue controls optimistically while the review refresh is still pending", async () => {
    const user = userEvent.setup();
    updateThreatModelReviewFinding.mockImplementationOnce(
      () => new Promise(() => undefined),
    );

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Queue Bucket: fix_now"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Queue To Verify" }));

    expect(screen.getByText("Queue Bucket: verify")).toBeInTheDocument();
    expect(screen.getByText("Security Review Panel")).toBeInTheDocument();
  });

  it("does not let a stale background refresh overwrite a newer queue click", async () => {
    const user = userEvent.setup();
    const responseWithBucket = (bucket: "fix_now" | "verify" | "backlog") => ({
      generated_at: "2026-01-01T00:00:00Z",
      system_name: "Example",
      queue_counts: [],
      review_status_counts: [],
      default_finding_id: "threat:threat-1",
      findings: [
        {
          id: "threat:threat-1",
          source_object_type: "threat",
          source_object_id: "threat-1",
          threat_id: "threat-1",
          display_id: "T-001",
          display_kind: "threat",
          primary_mode: "findings",
          title: "Spoofed caller identity",
          queue_bucket: bucket,
          computed_queue_bucket: "fix_now",
          review_status: "open",
        },
      ],
    });
    let resolveStaleRefresh: (() => void) | undefined;

    getThreatModelReviewFindings
      .mockResolvedValueOnce(responseWithBucket("fix_now"))
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveStaleRefresh = () => resolve(responseWithBucket("verify"));
          }),
      )
      .mockImplementationOnce(() => new Promise(() => undefined));
    updateThreatModelReviewFinding
      .mockResolvedValueOnce({
        id: "threat:threat-1",
        queue_bucket: "verify",
      })
      .mockResolvedValueOnce({
        id: "threat:threat-1",
        queue_bucket: "backlog",
      });

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Queue Bucket: fix_now"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Queue To Verify" }));
    expect(await screen.findByText("Queue Bucket: verify")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Queue To Backlog" }));
    expect(
      await screen.findByText("Queue Bucket: backlog"),
    ).toBeInTheDocument();

    await act(async () => {
      resolveStaleRefresh?.();
    });

    expect(screen.getByText("Queue Bucket: backlog")).toBeInTheDocument();
    expect(screen.queryByText("Queue Bucket: verify")).not.toBeInTheDocument();
  });

  it("persists a drafted artifact without unmounting the workbench", async () => {
    const user = userEvent.setup();
    createThreatModelReviewArtifact.mockResolvedValue({
      id: "threat:threat-1",
      source_object_type: "threat",
      source_object_id: "threat-1",
      threat_id: "threat-1",
      display_id: "T-001",
      wire_kind: "threat",
      display_kind: "threat",
      source_provenance: "rules_engine",
      source_system: "threatgenix",
      title: "Spoofed caller identity",
      priority: "p1_now",
      wire_action_bucket: "engineer_now",
      queue_bucket: "fix_now",
      computed_queue_bucket: "fix_now",
      truth_status: "validated",
      numeric_score: 92,
      exploitability: "high",
      urgency: "immediate",
      business_impact: "high",
      regulatory_pressure: "high",
      confidence: "high",
      is_real: true,
      is_urgent: true,
      is_exploitable_in_context: true,
      is_regulatory_or_control_relevant: true,
      needs_engineering_change: true,
      needs_evidence: false,
      why_now: "This is active work.",
      impacted_assets: [],
      entry_point: "API Gateway",
      evidence_refs: ["dfd"],
      linked_threat_ids: ["threat-1"],
      linked_change_ids: [],
      linked_control_ids: [],
      owner: null,
      due_at: null,
      note: null,
      artifacts: [
        {
          id: "artifact-1",
          kind: "remediation_note",
          title: "Remediation note · Spoofed caller identity",
          summary: "Concrete engineering change.",
          body: "Objective\n- Reduce the risk.",
          created_at: "2026-04-23T12:00:00Z",
        },
      ],
      review_status: "open",
      last_non_terminal_bucket: null,
      primary_mode: "findings",
      noise_disposition: "focus",
      computed_recommendation_changed: false,
      systemic: false,
      next_best_action: "Assign an owner and tighten the ingress path.",
      next_step: "Assign an owner.",
      rationale_excerpt: "Validated against the architecture.",
    });

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Draft Remediation" }));

    expect(createThreatModelReviewArtifact).toHaveBeenCalledWith(
      "tm-1",
      "threat",
      "threat-1",
      { kind: "remediation_note" },
    );
    expect(screen.getByText("Security Review Panel")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("persists structured artifacts coming from the copilot", async () => {
    const user = userEvent.setup();
    createThreatModelReviewArtifact.mockResolvedValue({
      id: "threat:threat-1",
      source_object_type: "threat",
      source_object_id: "threat-1",
      threat_id: "threat-1",
      display_id: "T-001",
      wire_kind: "threat",
      display_kind: "threat",
      source_provenance: "rules_engine",
      source_system: "threatgenix",
      title: "Spoofed caller identity",
      priority: "p1_now",
      wire_action_bucket: "engineer_now",
      queue_bucket: "fix_now",
      computed_queue_bucket: "fix_now",
      truth_status: "validated",
      numeric_score: 92,
      exploitability: "high",
      urgency: "immediate",
      business_impact: "high",
      regulatory_pressure: "high",
      confidence: "high",
      is_real: true,
      is_urgent: true,
      is_exploitable_in_context: true,
      is_regulatory_or_control_relevant: true,
      needs_engineering_change: true,
      needs_evidence: false,
      why_now: "This is active work.",
      impacted_assets: [],
      entry_point: "API Gateway",
      evidence_refs: ["dfd"],
      linked_threat_ids: ["threat-1"],
      linked_change_ids: [],
      linked_control_ids: [],
      owner: null,
      due_at: null,
      note: null,
      artifacts: [
        {
          id: "artifact-2",
          kind: "verification_note",
          title: "Verification note · Spoofed caller identity",
          summary: "Prove the ingress control exists.",
          body: "Control to verify\n- Confirm authentication is enforced.",
          created_at: "2026-04-23T12:05:00Z",
        },
      ],
      review_status: "open",
      last_non_terminal_bucket: null,
      primary_mode: "findings",
      noise_disposition: "focus",
      computed_recommendation_changed: false,
      systemic: false,
      next_best_action: "Assign an owner and tighten the ingress path.",
      next_step: "Assign an owner.",
      rationale_excerpt: "Validated against the architecture.",
    });

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(await screen.findByText("Copilot Panel")).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Persist Copilot Artifact" }),
    );

    expect(createThreatModelReviewArtifact).toHaveBeenCalledWith(
      "tm-1",
      "threat",
      "threat-1",
      { kind: "verification_note" },
    );
  });

  it("routes non-threat risk acceptance through the governed acceptance endpoint", async () => {
    const user = userEvent.setup();
    getThreatModelReviewFindings.mockResolvedValueOnce({
      generated_at: "2026-01-01T00:00:00Z",
      system_name: "Example",
      queue_counts: [],
      review_status_counts: [],
      default_finding_id: "model:owner-gap",
      findings: [
        {
          id: "model:owner-gap",
          source_object_type: "model_review_finding",
          source_object_id: "model:owner-gap",
          threat_id: null,
          display_id: null,
          display_kind: "control_gap",
          primary_mode: "compliance",
          title: "Risk owner is missing",
          queue_bucket: "verify",
          computed_queue_bucket: "verify",
          review_status: "open",
        },
      ],
    });
    acceptThreatModelReviewFindingRisk.mockResolvedValueOnce({
      id: "model:owner-gap",
      source_object_type: "model_review_finding",
      source_object_id: "model:owner-gap",
      threat_id: null,
      display_id: null,
      display_kind: "control_gap",
      primary_mode: "compliance",
      title: "Risk owner is missing",
      queue_bucket: null,
      computed_queue_bucket: "verify",
      review_status: "accepted",
      risk_acceptance: {
        finding_title: "Risk owner is missing",
        status: "active",
        accepted_by: "Priya Reviewer",
        accepted_at: "2026-05-01T00:00:00Z",
        expires_at: "2026-06-01T00:00:00.000Z",
        acceptance_rationale:
          "Accepted until repository access is approved.",
        compensating_control:
          "Manual reviewer attestation is attached.",
        reopen_triggers: [],
      },
    });

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Submit Acceptance" }));

    expect(acceptThreatModelReviewFindingRisk).toHaveBeenCalledWith(
      "tm-1",
      "model_review_finding",
      "model:owner-gap",
      {
        accepted_by: "Priya Reviewer",
        expires_at: "2026-06-01T00:00:00.000Z",
        acceptance_rationale: "Accepted until repository access is approved.",
        compensating_control: "Manual reviewer attestation is attached.",
      },
    );
    expect(updateThreatModelReviewFinding).not.toHaveBeenCalled();
  });

  it("routes threat risk acceptance through threat triage metadata", async () => {
    const user = userEvent.setup();
    triageThreat.mockResolvedValueOnce({
      id: "threat-1",
      display_id: "T-001",
      description: "Spoofed caller identity",
      stride_category: "Spoofing",
      severity: "High",
      source: "Rules",
      status: "Accepted",
      dismiss_reason: "Accepted until repository access is approved.",
      relevance_rationale: null,
      mitigation_plan: "Manual reviewer attestation is attached.",
      mitigation_owner: "Priya Reviewer",
      due_date: "2026-06-01",
      mitigation_notes: "Accepted until repository access is approved.",
      control_effectiveness: "none",
      residual_risk_level: "High",
      compliance_controls: [],
      threat_subtype: null,
      rule_id: null,
      ai_enhanced: false,
      provider_managed: false,
      original_rule_threat_id: null,
      affected_node_ids: [],
      affected_edge_ids: [],
      closed_at: "2026-05-01T00:00:00Z",
      auto_score: null,
      analyst_score: null,
      analyst_score_rationale: null,
      qualification_score: null,
      qualification_label: null,
      qualification_note: null,
      ai_likelihood_assessment: null,
      ai_likelihood_score: null,
      ai_likelihood_generated_at: null,
      cluster_id: null,
      false_positive_reason: "accepted_risk",
      qualification_completed_at: null,
      created_at: "2026-01-01T00:00:00Z",
      scan_status: undefined,
    });

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[
          {
            id: "threat-1",
            display_id: "T-001",
            description: "Spoofed caller identity",
            stride_category: "Spoofing",
            severity: "High",
            source: "Rules",
            status: "Open",
            dismiss_reason: null,
            relevance_rationale: null,
            mitigation_plan: null,
            mitigation_owner: null,
            due_date: null,
            mitigation_notes: null,
            control_effectiveness: "none",
            residual_risk_level: "High",
            compliance_controls: [],
            threat_subtype: null,
            rule_id: null,
            ai_enhanced: false,
            provider_managed: false,
            original_rule_threat_id: null,
            affected_node_ids: [],
            affected_edge_ids: [],
            closed_at: null,
            auto_score: null,
            analyst_score: null,
            analyst_score_rationale: null,
            qualification_score: null,
            qualification_label: null,
            qualification_note: null,
            ai_likelihood_assessment: null,
            ai_likelihood_score: null,
            ai_likelihood_generated_at: null,
            cluster_id: null,
            false_positive_reason: null,
            qualification_completed_at: null,
            created_at: "2026-01-01T00:00:00Z",
            scan_status: undefined,
          },
        ]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(
      await screen.findByText("Security Review Panel"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Submit Acceptance" }));

    expect(triageThreat).toHaveBeenCalledWith(
      "tm-1",
      "threat-1",
      expect.objectContaining({
        status: "Accepted",
        risk_acceptance: {
          accepted_by: "Priya Reviewer",
          expires_at: "2026-06-01T00:00:00.000Z",
          acceptance_rationale: "Accepted until repository access is approved.",
          compensating_control: "Manual reviewer attestation is attached.",
        },
      }),
    );
    expect(acceptThreatModelReviewFindingRisk).not.toHaveBeenCalled();
  });

  it("keeps copilot failures visible without unmounting the review workspace", async () => {
    const user = userEvent.setup();
    createThreatModelReviewArtifact.mockRejectedValueOnce(
      new Error("Copilot artifact service unavailable."),
    );

    render(
      <ThreatModelInspectorRail
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Example",
          description: "Example model",
          data_classification: "Internal",
          regulatory_scope: [],
          deployment_model: "cloud",
          repository_evidence: null,
          cloud_scan_evidence: null,
          iac_evidence: null,
          environment_context_summary: null,
          report_templates: [],
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }}
        threats={[]}
        queuedAssistantRequest={null}
        onPendingAnchorConsumed={vi.fn()}
        pendingAssumptionAnchor={null}
        qualitySummary={{ blocking_count: 0, warning_count: 1, results: [] }}
      />,
    );

    expect(await screen.findByText("Copilot Panel")).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Persist Copilot Artifact" }),
    );

    expect(screen.getByText("Security Review Panel")).toBeInTheDocument();
    expect(screen.getByText("Copilot Panel")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Action blocked.");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Copilot artifact service unavailable.",
    );
  });
});
