import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { SecurityReviewFinding, ThreatResponse } from "../types/api";
import { SecurityReviewFindingDetail } from "./SecurityReviewFindingDetail";

function makeFinding(
  overrides: Partial<SecurityReviewFinding> = {},
): SecurityReviewFinding {
  const finding: SecurityReviewFinding = {
    id: "finding-1",
    source_object_type: "application_review_finding",
    source_object_id: "surface:vendor-diagnostics",
    threat_id: null,
    display_id: null,
    wire_kind: "control_gap",
    display_kind: "control_gap",
    source_provenance: "app_review_projection",
    source_system: "threatgenix",
    title: "Code evidence found unprotected sensitive routes",
    priority: "p1_now",
    numeric_score: 88,
    wire_action_bucket: "engineer_now",
    queue_bucket: "fix_now",
    computed_queue_bucket: "fix_now",
    truth_status: "strongly_indicated",
    exploitability: "medium",
    urgency: "current_cycle",
    business_impact: "high",
    regulatory_pressure: "red_line",
    confidence: "high",
    is_real: true,
    is_urgent: true,
    is_exploitable_in_context: false,
    is_regulatory_or_control_relevant: true,
    needs_engineering_change: true,
    needs_evidence: false,
    why_now: "The route processes sensitive payment callback state without a clear guard.",
    impacted_assets: ["API Gateway"],
    entry_point: "API Gateway",
    evidence_refs: ["repository"],
    linked_threat_ids: [],
    linked_change_ids: [],
    linked_control_ids: [],
    owner: null,
    due_at: null,
    note: null,
    artifacts: [],
    review_status: "open",
    last_non_terminal_bucket: null,
    primary_mode: "compliance",
    noise_disposition: "focus",
    computed_recommendation_changed: false,
    systemic: true,
    next_best_action: "Create an engineering task with the affected route and missing control.",
    next_step: "Create an engineering task.",
    rationale_excerpt: "Externally reachable sensitive route.",
    code_links: [],
  };
  return Object.assign(finding, overrides);
}

function makeThreat(overrides: Partial<ThreatResponse> = {}): ThreatResponse {
  return {
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
    ...overrides,
  };
}

describe("SecurityReviewFindingDetail", () => {
  it("renders duplicate surface code evidence without React key warnings", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <SecurityReviewFindingDetail
        finding={makeFinding({
          code_links: [
            {
              finding_key: "finding-1",
              surface_id: "surface-post-vendor-diagnostics-session",
              relationship: "confirms_missing_control",
              source_file: "api_gateway_vendor_callbacks.js",
              line_number: 4,
              surface_name: "POST /vendor/diagnostics/session",
              summary: "No auth guard is detected.",
              control_signal_ids: [],
              risk_signal_ids: [],
            },
            {
              finding_key: "finding-1",
              surface_id: "surface-post-vendor-diagnostics-session",
              relationship: "confirms_missing_control",
              source_file: "api_gateway_vendor_callbacks.js",
              line_number: 5,
              surface_name: "POST /callbacks/vendor/payment-status",
              summary: "Sensitive callback state is accepted without a guard.",
              control_signal_ids: [],
              risk_signal_ids: [],
            },
          ],
        })}
      />,
    );

    expect(screen.getByText("POST /vendor/diagnostics/session")).toBeInTheDocument();
    expect(screen.getByText("POST /callbacks/vendor/payment-status")).toBeInTheDocument();
    expect(consoleError).not.toHaveBeenCalledWith(
      expect.stringContaining("Encountered two children with the same key"),
      expect.anything(),
      expect.anything(),
    );

    consoleError.mockRestore();
  });

  it("collects reviewer risk acceptance details before accepting systemic findings", async () => {
    const user = userEvent.setup();
    const onStatusChange = vi.fn();
    const onRiskAcceptanceSubmit = vi.fn().mockResolvedValue(undefined);

    render(
      <SecurityReviewFindingDetail
        finding={makeFinding({
          owner: "Priya Reviewer",
          note: "Feature flag keeps the route admin-only.",
        })}
        onStatusChange={onStatusChange}
        onRiskAcceptanceSubmit={onRiskAcceptanceSubmit}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Accepted" }));

    expect(onStatusChange).not.toHaveBeenCalled();
    expect(screen.getByText("Accept Risk")).toBeInTheDocument();
    expect(screen.getByLabelText("Accepted by")).toHaveValue("Priya Reviewer");
    expect(screen.getByLabelText("Compensating control")).toHaveValue(
      "Feature flag keeps the route admin-only.",
    );

    await user.clear(screen.getByLabelText("Rationale"));
    await user.type(
      screen.getByLabelText("Rationale"),
      "Accepted until repository access is approved.",
    );
    await user.clear(screen.getByLabelText("Compensating control"));
    await user.type(
      screen.getByLabelText("Compensating control"),
      "Manual reviewer attestation is attached.",
    );
    await user.type(screen.getByLabelText("Expiry"), "2026-06-01");
    await user.click(screen.getByRole("button", { name: "Save acceptance" }));

    expect(onRiskAcceptanceSubmit).toHaveBeenCalledWith({
      accepted_by: "Priya Reviewer",
      expires_at: "2026-06-01T00:00:00.000Z",
      acceptance_rationale: "Accepted until repository access is approved.",
      compensating_control: "Manual reviewer attestation is attached.",
    });
  });

  it("collects risk acceptance details before accepting threat findings", async () => {
    const user = userEvent.setup();
    const onStatusChange = vi.fn();
    const onRiskAcceptanceSubmit = vi.fn().mockResolvedValue(undefined);

    render(
      <SecurityReviewFindingDetail
        finding={makeFinding({
          source_object_type: "threat",
          source_object_id: "threat-1",
          threat_id: "threat-1",
          display_id: "T-001",
          wire_kind: "threat",
          display_kind: "threat",
          primary_mode: "findings",
        })}
        threat={makeThreat()}
        onStatusChange={onStatusChange}
        onRiskAcceptanceSubmit={onRiskAcceptanceSubmit}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Accepted" }));
    await user.clear(screen.getByLabelText("Rationale"));
    await user.type(
      screen.getByLabelText("Rationale"),
      "Threat acceptance rationale for customer review.",
    );
    await user.click(screen.getByRole("button", { name: "Save acceptance" }));

    expect(onStatusChange).not.toHaveBeenCalled();
    expect(onRiskAcceptanceSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        acceptance_rationale: "Threat acceptance rationale for customer review.",
      }),
    );
  });

  it("requires a rationale before submitting a risk acceptance", async () => {
    const user = userEvent.setup();
    const onRiskAcceptanceSubmit = vi.fn();

    render(
      <SecurityReviewFindingDetail
        finding={makeFinding({ note: null, next_best_action: null })}
        onStatusChange={vi.fn()}
        onRiskAcceptanceSubmit={onRiskAcceptanceSubmit}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Accepted" }));
    await user.type(screen.getByLabelText("Rationale"), "   ");
    await user.click(screen.getByRole("button", { name: "Save acceptance" }));

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Acceptance rationale is required.",
    );
    expect(onRiskAcceptanceSubmit).not.toHaveBeenCalled();
  });

  it("rejects invalid risk acceptance expiry values", async () => {
    const user = userEvent.setup();
    const onRiskAcceptanceSubmit = vi.fn();

    render(
      <SecurityReviewFindingDetail
        finding={makeFinding()}
        onStatusChange={vi.fn()}
        onRiskAcceptanceSubmit={onRiskAcceptanceSubmit}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Accepted" }));
    await user.type(screen.getByLabelText("Expiry"), "not-a-date");
    await user.click(screen.getByRole("button", { name: "Save acceptance" }));

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Expiry must be a valid date or ISO timestamp.",
    );
    expect(onRiskAcceptanceSubmit).not.toHaveBeenCalled();
  });
});
