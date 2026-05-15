import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { ApplicationSecurityReviewPanel } from "./ApplicationSecurityReviewPanel";

const { getThreatModelSecurityReview } = vi.hoisted(() => ({
  getThreatModelSecurityReview: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    getThreatModelSecurityReview,
  },
}));

describe("ApplicationSecurityReviewPanel", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    getThreatModelSecurityReview.mockResolvedValue({
      generated_at: "2026-04-18T12:00:00Z",
      system_name: "Payments API",
      overall_priority: "p1_now",
      overall_action_bucket: "engineer_now",
      focus_statement: "This application has immediate work in both active findings and systemic blind spots.",
      rationale: ["The application review found high-signal work."],
      next_steps: ["Assign an owner before the review exits triage."],
      coverage: {
        total_findings: 4,
        threat_findings: 2,
        systemic_findings: 2,
        open_threats: 2,
        public_entry_points: 1,
        privileged_surfaces: 1,
        restricted_assets: 1,
        attack_paths: 1,
        attached_evidence_sources: 1,
        missing_evidence_sources: 3,
      },
      priority_counts: [
        { key: "p0_blocker", label: "P0 blocker", count: 0 },
        { key: "p1_now", label: "P1 now", count: 2 },
        { key: "p2_sprint", label: "P2 sprint", count: 1 },
        { key: "p3_backlog", label: "P3 backlog", count: 1 },
        { key: "p4_monitor", label: "P4 monitor", count: 0 },
      ],
      action_bucket_counts: [],
      truth_status_counts: [],
      noise_counts: [],
      top_findings: [
        {
          finding_key: "threat-1",
          threat_id: "threat-1",
          display_id: "T-001",
          finding_kind: "threat",
          title: "Public API auth bypass",
          priority: "p1_now",
          action_bucket: "engineer_now",
          truth_status: "validated",
          urgency: "current_cycle",
          noise_disposition: "focus",
          numeric_score: 81,
          entry_point: "Public API",
          target_asset: "Token Vault",
          rationale_excerpt: "The affected surface is externally reachable.",
          next_step: "Contain the external exposure before the next deploy.",
          related_attack_path_count: 1,
          evidence_adjustment_count: 0,
          systemic: false,
        },
      ],
      blind_spots: [
        {
          finding_key: "model:cloud-evidence",
          threat_id: null,
          display_id: null,
          finding_kind: "evidence_gap",
          title: "Cloud configuration evidence is missing for an in-scope deployment",
          priority: "p2_sprint",
          action_bucket: "fill_evidence_gap",
          truth_status: "contextual",
          urgency: "current_cycle",
          noise_disposition: "queue",
          numeric_score: 63,
          entry_point: "Public API",
          target_asset: "Token Vault",
          rationale_excerpt: "The application is deployed in cloud infrastructure, but there is no attached cloud evidence.",
          next_step: "Attach a cloud evidence source before the review closes.",
          related_attack_path_count: 0,
          evidence_adjustment_count: 0,
          systemic: true,
        },
      ],
      attack_paths: [
        {
          path_id: "path-1",
          finding_keys: ["threat-1", "model:cloud-evidence"],
          finding_titles: ["T-001: Public API auth bypass", "Cloud evidence missing"],
          chain_description: "Public API -> Token Vault via unverified control coverage",
          entry_point: "Public API",
          target_asset: "Token Vault",
          hop_count: 2,
          composite_exploitability: "high",
          composite_priority: "p1_now",
        },
      ],
      risk_acceptance_summary: {
        active: 1,
        reopened: 1,
        expired: 0,
      },
      review_delta_summary: {
        new_findings: 1,
        resolved_findings: 0,
        reopened_findings: 1,
        escalated_findings: 1,
        deescalated_findings: 0,
      },
    });
  });

  it("renders the full application review summary", async () => {
    render(
      <ApplicationSecurityReviewPanel
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Payments API",
          description: "Handles regulated payment traffic.",
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
        }}
        threats={[
          {
            id: "threat-1",
            display_id: "T-001",
            description: "Public API auth bypass",
            stride_category: "Spoofing",
            threat_subtype: "Auth bypass",
            severity: "High",
            source: "Rules",
            status: "Open",
            dismiss_reason: null,
            rule_id: "RULE-1",
            ai_enhanced: false,
            provider_managed: false,
            original_rule_threat_id: null,
            affected_node_ids: ["node-1"],
            affected_edge_ids: [],
            relevance_rationale: null,
            mitigation_plan: null,
            mitigation_owner: null,
            due_date: null,
            mitigation_notes: null,
            control_effectiveness: "none",
            residual_risk_level: null,
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
            created_at: "2026-04-18T00:00:00Z",
            scan_status: "confirmed",
          },
        ]}
      />
    );

    await waitFor(() => {
      expect(getThreatModelSecurityReview).toHaveBeenCalledWith("tm-1");
    });

    expect(await screen.findByText("Full Application Security Review")).toBeInTheDocument();
    expect(screen.getByText(/immediate work in both active findings/i)).toBeInTheDocument();
    expect(screen.getByText("T-001 · Public API auth bypass")).toBeInTheDocument();
    expect(
      screen.getByText("Cloud configuration evidence is missing for an in-scope deployment")
    ).toBeInTheDocument();
    expect(screen.getByText(/Public API -> Token Vault via unverified control coverage/)).toBeInTheDocument();
    expect(screen.getByText(/Assign an owner before the review exits triage/)).toBeInTheDocument();
  });
});
