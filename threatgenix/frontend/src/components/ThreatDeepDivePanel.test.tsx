import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { ThreatDeepDivePanel } from "./ThreatDeepDivePanel";

const { getDFD, getThreatIntel, getThreatSecurityReview, assistantRespond } =
  vi.hoisted(() => ({
    getDFD: vi.fn(),
    getThreatIntel: vi.fn(),
    getThreatSecurityReview: vi.fn(),
    assistantRespond: vi.fn(),
  }));

vi.mock("../api/client", () => ({
  api: {
    getDFD,
    getThreatIntel,
    getThreatSecurityReview,
    assistantRespond,
  },
}));

describe("ThreatDeepDivePanel", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    getDFD.mockResolvedValue({
      nodes: [
        {
          id: "node-1",
          node_type: "process",
          name: "API Gateway",
          position_x: 0,
          position_y: 0,
          trust_boundary_id: null,
          properties: {},
        },
        {
          id: "node-2",
          node_type: "data_store",
          name: "Token Vault",
          position_x: 200,
          position_y: 0,
          trust_boundary_id: null,
          properties: {},
        },
      ],
      edges: [
        {
          id: "edge-1",
          source_node_id: "node-1",
          target_node_id: "node-2",
          label: "issue token",
          properties: {},
        },
      ],
      trust_boundaries: [],
    });
    getThreatIntel.mockResolvedValue({
      local_severity: "Critical",
      highest_external_severity: "High",
      semantic_matches_inferred: false,
      unavailable_reason: null,
      scan_cve_ids: [],
      severity_signals: [],
      attack_techniques: [
        {
          technique_id: "T1078",
          name: "Valid Accounts",
          tactic: "defense-evasion",
          description: "Technique description",
          url: "https://attack.mitre.org/techniques/T1078/",
          match_type: "exact",
        },
      ],
      attack_patterns: [],
      weaknesses: [],
      advisories: [],
      kev_entries: [
        {
          cve_id: "CVE-2026-0001",
          vendor_project: "Example",
          product: "Gateway",
          vulnerability_name: "Known issue",
          known_ransomware_use: "Known",
          date_added: "2026-04-01",
          match_type: "scan_cve",
        },
      ],
      cri_controls: [],
    });
    getThreatSecurityReview.mockResolvedValue({
      priority: "p0_blocker",
      action_bucket: "bright_red_line",
      truth_status: "validated",
      urgency: "immediate",
      exploitability: "proven",
      business_impact: "severe",
      regulatory_pressure: "high",
      noise_disposition: "focus",
      numeric_score: 91,
      score_breakdown: {
        reality: 88,
        exploitability: 93,
        business_impact: 79,
        regulatory_pressure: 74,
        noise_penalty: 4,
        total: 91,
      },
      evidence_adjustments: [
        {
          evidence_type: "scan",
          evidence_value: "latest validation scan marked the path mitigated",
          field_affected: "exploitability",
          original_value: "high",
          adjusted_value: "proven",
          justification: "Confirmed scan evidence should raise exploitability.",
        },
      ],
      related_attack_paths: [
        {
          path_id: "path-1",
          finding_keys: ["threat-1", "threat-2"],
          finding_titles: [
            "T-001: Attacker steals API credentials and pivots into payment flows.",
            "T-002: Broad vault permissions allow the compromised API path to reach restricted token material.",
          ],
          chain_description:
            "API Gateway -> Token Vault across 2 related findings",
          entry_point: "API Gateway",
          target_asset: "Token Vault",
          hop_count: 1,
          support_count: 2,
          composite_exploitability: "proven",
          composite_priority: "p0_blocker",
          path_nodes: ["API Gateway", "Payments Orchestrator", "Token Vault"],
          evidence_sources: ["scan", "repository", "dfd"],
          relationship_reasons: [
            "At least one supporting finding is externally reachable.",
            "Token Vault is on a restricted or confidential data path.",
          ],
          verification_steps: [
            "Trace runtime telemetry from API Gateway to Token Vault and confirm the expected intermediates only.",
            "Confirm Token Vault denies direct or over-broad access and requires a scoped service identity.",
          ],
        },
      ],
      risk_acceptance: {
        finding_title:
          "T-001: Attacker steals API credentials and pivots into payment flows.",
        status: "reopened",
        accepted_by: "priya",
        accepted_at: "2026-01-10T00:00:00Z",
        expires_at: null,
        acceptance_rationale: "Accepted until control rollout",
        reopen_triggers: ["validation scan confirmed the condition"],
      },
      review_delta: {
        disposition: "reopened",
        days_since_last_review: 45,
        new_findings_count: 0,
        resolved_count: 0,
        reopened_count: 1,
        escalated_count: 1,
      },
      rationale: [
        "A validation scan confirmed this condition, so the issue is no longer theoretical.",
        "The affected surface is externally reachable, which meaningfully raises exploitability and business exposure.",
      ],
      next_steps: [
        "Open an immediate engineering fix item and treat it as a release blocker until evidence changes.",
        "Contain or reduce external exposure before the next deploy where possible.",
      ],
    });
    assistantRespond.mockResolvedValue({
      mode: "review",
      answer:
        "Business context\n\nWhat is real\n\nWhat is urgent and exploitable",
      references: [],
      findings: [],
      guided_steps: [],
      proposal: null,
      degraded_reason: null,
    });
  });

  it("surfaces deterministic signals and can request AI guidance", async () => {
    const user = userEvent.setup();

    render(
      <ThreatDeepDivePanel
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Payments API",
          description: "Handles regulated customer transactions.",
          data_classification: "Restricted",
          regulatory_scope: ["PCI DSS", "OSFI B-13"],
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
            description:
              "Attacker steals API credentials and pivots into payment flows.",
            stride_category: "Elevation of Privilege",
            threat_subtype: "Credential theft",
            severity: "Critical",
            source: "AI+Rules",
            status: "Open",
            dismiss_reason: null,
            rule_id: "RULE-1",
            ai_enhanced: true,
            provider_managed: false,
            original_rule_threat_id: null,
            affected_node_ids: ["node-1"],
            affected_edge_ids: [],
            relevance_rationale:
              "The gateway is internet-facing and still depends on broad role assumptions.",
            mitigation_plan: null,
            mitigation_owner: null,
            due_date: null,
            mitigation_notes: null,
            control_effectiveness: "partial",
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
            created_at: "2026-04-17T00:00:00Z",
            scan_status: "confirmed",
          },
          {
            id: "threat-2",
            display_id: "T-002",
            description:
              "Broad vault permissions allow the compromised API path to reach restricted token material.",
            stride_category: "Information Disclosure",
            threat_subtype: "Vault over-read",
            severity: "High",
            source: "Rules",
            status: "Open",
            dismiss_reason: null,
            rule_id: "RULE-2",
            ai_enhanced: false,
            provider_managed: false,
            original_rule_threat_id: null,
            affected_node_ids: ["node-2"],
            affected_edge_ids: ["edge-1"],
            relevance_rationale:
              "The vault sits directly behind the gateway flow and holds restricted material.",
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
            created_at: "2026-04-17T00:00:00Z",
            scan_status: undefined,
          },
        ]}
      />,
    );

    await waitFor(() => {
      expect(getThreatIntel).toHaveBeenCalledWith("tm-1", "threat-1");
      expect(getThreatSecurityReview).toHaveBeenCalledWith("tm-1", "threat-1");
    });

    expect(await screen.findByText("Immediate")).toBeInTheDocument();
    expect(screen.getByText("Proven")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(
      screen.getByText(/issue is no longer theoretical/i),
    ).toBeInTheDocument();
    expect(screen.getAllByText("API Gateway").length).toBeGreaterThan(0);
    expect(screen.getByText("Entry")).toBeInTheDocument();
    expect(screen.getByText("Target")).toBeInTheDocument();
    expect(screen.getAllByText("Token Vault").length).toBeGreaterThan(0);
    expect(screen.getByText("2 modeled steps")).toBeInTheDocument();
    expect(screen.getByText("2 supporting findings")).toBeInTheDocument();
    expect(screen.getByText("P0 blocker")).toBeInTheDocument();
    expect(screen.getByText("Proven exploitability")).toBeInTheDocument();
    expect(screen.getByText("Modeled route")).toBeInTheDocument();
    expect(screen.getByText("Payments Orchestrator")).toBeInTheDocument();
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    expect(screen.getByText("Code evidence")).toBeInTheDocument();
    expect(screen.getByText("DFD")).toBeInTheDocument();
    expect(screen.getByText("Why linked")).toBeInTheDocument();
    expect(screen.getByText("Verify next")).toBeInTheDocument();
    expect(
      screen.getByText(/denies direct or over-broad access/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/release blocker/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Risk acceptance is currently/i),
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Generate AI Guidance" }),
    );

    await waitFor(() => {
      expect(assistantRespond).toHaveBeenCalledWith(
        "tm-1",
        expect.objectContaining({
          mode_hint: "review",
          anchor: { kind: "threat", id: "threat-1" },
        }),
      );
    });

    expect(
      await screen.findByText(/What is urgent and exploitable/),
    ).toBeInTheDocument();
  });

  it("renders degraded AI guidance so the analyst can still see the fallback", async () => {
    const user = userEvent.setup();
    assistantRespond.mockResolvedValueOnce({
      mode: "review",
      answer:
        "Business context\n\nUse deterministic signals while the primary model is unavailable.",
      references: [],
      findings: [],
      guided_steps: [],
      proposal: null,
      degraded_reason: "Primary LLM timed out; returned rules-only guidance.",
    });

    render(
      <ThreatDeepDivePanel
        threatModelId="tm-1"
        model={{
          id: "tm-1",
          system_name: "Payments API",
          description: "Handles regulated customer transactions.",
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
            description:
              "Attacker steals API credentials and pivots into payment flows.",
            stride_category: "Elevation of Privilege",
            threat_subtype: "Credential theft",
            severity: "Critical",
            source: "AI+Rules",
            status: "Open",
            dismiss_reason: null,
            rule_id: "RULE-1",
            ai_enhanced: true,
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
            created_at: "2026-04-17T00:00:00Z",
            scan_status: "confirmed",
          },
        ]}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Generate AI Guidance" }),
    );

    expect(await screen.findByText(/rules-only guidance/i)).toBeInTheDocument();
    expect(
      screen.getByText("Primary LLM timed out; returned rules-only guidance."),
    ).toBeInTheDocument();
    expect(assistantRespond).toHaveBeenCalledWith(
      "tm-1",
      expect.objectContaining({
        mode_hint: "review",
        anchor: { kind: "threat", id: "threat-1" },
      }),
    );
  });
});
