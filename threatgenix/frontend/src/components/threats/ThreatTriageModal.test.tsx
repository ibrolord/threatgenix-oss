import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ThreatResponse } from "../../types/api";
import { ThreatTriageModal } from "./ThreatTriageModal";

const { getThreatHistory, triageThreat } = vi.hoisted(() => ({
  getThreatHistory: vi.fn(),
  triageThreat: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  api: {
    getThreatHistory,
    triageThreat,
  },
}));

function makeThreat(overrides: Partial<ThreatResponse> = {}): ThreatResponse {
  return {
    id: "threat-1",
    display_id: "T-001",
    description: "An attacker may spoof the API gateway.",
    stride_category: "Spoofing",
    threat_subtype: null,
    severity: "High",
    source: "Rules",
    status: "Open",
    dismiss_reason: null,
    rule_id: "S-01",
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
    created_at: "2026-04-18T10:00:00Z",
    ...overrides,
  };
}

describe("ThreatTriageModal", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    getThreatHistory.mockResolvedValue([]);
  });

  it("persists severity adjustments through the triage API", async () => {
    const user = userEvent.setup();
    const onTriaged = vi.fn();

    triageThreat.mockResolvedValue(
      makeThreat({
        severity: "Critical",
        residual_risk_level: "Critical",
      })
    );

    render(
      <ThreatTriageModal
        threat={makeThreat()}
        threatModelId="tm-1"
        onClose={vi.fn()}
        onTriaged={onTriaged}
      />
    );

    await waitFor(() => {
      expect(getThreatHistory).toHaveBeenCalledWith("tm-1", "threat-1");
    });

    await user.selectOptions(screen.getByLabelText("Severity"), "Critical");

    expect(screen.getAllByText("Critical").length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Save Details" }));

    await waitFor(() => {
      expect(triageThreat).toHaveBeenCalledWith(
        "tm-1",
        "threat-1",
        expect.objectContaining({
          status: "Open",
          severity: "Critical",
          control_effectiveness: "none",
        })
      );
    });

    expect(onTriaged).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: "Critical",
      })
    );
  });

  it("sends governed risk acceptance metadata when accepting a threat", async () => {
    const user = userEvent.setup();
    const onTriaged = vi.fn();

    triageThreat.mockResolvedValue(
      makeThreat({
        status: "Accepted",
        mitigation_owner: "Priya Reviewer",
        due_date: "2026-06-30",
        mitigation_notes: "Accepted until vendor fix ships.",
        mitigation_plan: "WAF rule and manual log review.",
        false_positive_reason: "accepted_risk",
      })
    );

    render(
      <ThreatTriageModal
        threat={makeThreat()}
        threatModelId="tm-1"
        onClose={vi.fn()}
        onTriaged={onTriaged}
      />
    );

    await user.type(screen.getByLabelText("Owner"), "Priya Reviewer");
    await user.type(screen.getByLabelText("Due Date"), "2026-06-30");
    await user.type(
      screen.getByLabelText("Mitigation Plan"),
      "WAF rule and manual log review.",
    );
    await user.type(
      screen.getByLabelText("Notes"),
      "Accepted until vendor fix ships.",
    );
    await user.click(screen.getByRole("button", { name: "Accept Risk" }));

    await waitFor(() => {
      expect(triageThreat).toHaveBeenCalledWith(
        "tm-1",
        "threat-1",
        expect.objectContaining({
          status: "Accepted",
          risk_acceptance: {
            accepted_by: "Priya Reviewer",
            expires_at: "2026-06-30T00:00:00Z",
            acceptance_rationale: "Accepted until vendor fix ships.",
            compensating_control: "WAF rule and manual log review.",
          },
        })
      );
    });
    expect(onTriaged).toHaveBeenCalledWith(
      expect.objectContaining({ status: "Accepted" })
    );
  });
});
