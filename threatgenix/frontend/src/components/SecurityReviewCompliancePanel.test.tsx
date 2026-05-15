import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
} from "../types/api";
import { SecurityReviewCompliancePanel } from "./SecurityReviewCompliancePanel";

function makeFinding(
  id: string,
  overrides: Partial<SecurityReviewFinding> = {},
): SecurityReviewFinding {
  const finding: SecurityReviewFinding = {
    id,
    source_object_type: "application_review_finding",
    source_object_id: id,
    threat_id: null,
    display_id: null,
    wire_kind: "evidence_gap",
    display_kind: "evidence_gap",
    source_provenance: "app_review_projection",
    source_system: "threatgenix",
    title: `Finding ${id}`,
    priority: "p2_sprint",
    numeric_score: 70,
    wire_action_bucket: "fill_evidence_gap",
    queue_bucket: "gather_evidence",
    computed_queue_bucket: "gather_evidence",
    truth_status: "contextual",
    exploitability: "medium",
    urgency: "current_cycle",
    business_impact: "moderate",
    regulatory_pressure: "high",
    confidence: "high",
    is_real: false,
    is_urgent: false,
    is_exploitable_in_context: false,
    is_regulatory_or_control_relevant: true,
    needs_engineering_change: false,
    needs_evidence: true,
    why_now: `Why now for ${id}`,
    impacted_assets: [],
    entry_point: null,
    evidence_refs: ["cloud"],
    linked_threat_ids: [],
    linked_change_ids: [],
    linked_control_ids: [],
    code_links: [],
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
    next_best_action: `Next step for ${id}`,
    next_step: `Next step for ${id}`,
    rationale_excerpt: `Rationale for ${id}`,
  };
  return Object.assign(finding, overrides);
}

describe("SecurityReviewCompliancePanel", () => {
  it("groups compliance work into blockers, evidence, follow-through, and resolved", async () => {
    const user = userEvent.setup();
    const findings = [
      makeFinding("control-blocker", {
        wire_kind: "control_gap",
        display_kind: "control_gap",
        title: "Logging control is missing",
        queue_bucket: "fix_now",
        computed_queue_bucket: "fix_now",
        wire_action_bucket: "engineer_now",
        needs_evidence: false,
        needs_engineering_change: true,
      }),
      makeFinding("evidence-gap", {
        title: "Cloud evidence is missing",
      }),
      makeFinding("follow-through", {
        wire_kind: "compliance_gap",
        display_kind: "compliance_gap",
        title: "Verify PCI retention evidence",
        queue_bucket: "verify",
        computed_queue_bucket: "verify",
        wire_action_bucket: "verify_control",
        needs_evidence: false,
        needs_engineering_change: false,
      }),
      makeFinding("accepted", {
        wire_kind: "compliance_gap",
        display_kind: "compliance_gap",
        title: "Accepted residual reporting gap",
        queue_bucket: null,
        review_status: "accepted",
        needs_evidence: false,
        needs_engineering_change: false,
      }),
    ];

    function Harness(): JSX.Element {
      const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
      return (
        <SecurityReviewCompliancePanel
          findingsResponse={{
            generated_at: "2026-04-22T00:00:00Z",
            system_name: "Aurora",
            queue_counts: [],
            review_status_counts: [],
            default_finding_id: "control-blocker",
            findings,
          } as SecurityReviewFindingListResponse}
          threats={[]}
          selectedFindingId={selectedFindingId}
          onSelectFinding={setSelectedFindingId}
          onQueueBucketChange={vi.fn()}
          onStatusChange={vi.fn()}
        />
      );
    }

    render(<Harness />);

    expect(screen.getByRole("heading", { name: "Compliance", level: 4 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Readiness blockers", level: 4 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Evidence needed", level: 4 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Control follow-through", level: 4 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Accepted or resolved", level: 4 })).toBeInTheDocument();
    expect(screen.getByText("Turn framework mapping into concrete evidence work, control changes, and readiness blockers.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Cloud evidence is missing/i }));

    const detailCard = screen
      .getByRole("heading", { name: "Cloud evidence is missing", level: 5 })
      .closest("article");
    expect(detailCard).not.toBeNull();

    const detail = within(detailCard as HTMLElement);
    expect(detail.getByText("Next step for evidence-gap")).toBeInTheDocument();
    expect(detail.getByText("Evidence gap")).toBeInTheDocument();
  });

  it("shows a concrete empty state when no compliance findings exist", () => {
    render(
      <SecurityReviewCompliancePanel
        findingsResponse={{
          generated_at: "2026-04-22T00:00:00Z",
          system_name: "Aurora",
          queue_counts: [],
          review_status_counts: [],
          default_finding_id: null,
          findings: [],
        } as SecurityReviewFindingListResponse}
        threats={[]}
        selectedFindingId={null}
        onSelectFinding={vi.fn()}
        onQueueBucketChange={vi.fn()}
        onStatusChange={vi.fn()}
      />,
    );

    expect(screen.getByText("No compliance blockers yet.")).toBeInTheDocument();
    expect(screen.getByText(/missing evidence, control gaps, or framework-mapped work/i)).toBeInTheDocument();
  });
});
