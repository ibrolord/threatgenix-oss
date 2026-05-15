import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  SecurityReviewApplicationSummary,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  ThreatModelResponse,
} from "../types/api";
import { SecurityReviewPanel } from "./SecurityReviewPanel";

function makeFinding(
  id: string,
  overrides: Partial<SecurityReviewFinding> = {},
): SecurityReviewFinding {
  const finding: SecurityReviewFinding = {
    id,
    source_object_type: "threat",
    source_object_id: id,
    threat_id: id,
    display_id: id.toUpperCase(),
    wire_kind: "threat",
    display_kind: "threat",
    source_provenance: "rules_engine",
    source_system: "threatgenix",
    title: `Finding ${id}`,
    priority: "p2_sprint",
    numeric_score: 70,
    wire_action_bucket: "verify_control",
    queue_bucket: "verify",
    computed_queue_bucket: "verify",
    truth_status: "strongly_indicated",
    exploitability: "medium",
    urgency: "current_cycle",
    business_impact: "moderate",
    regulatory_pressure: "moderate",
    confidence: "high",
    is_real: true,
    is_urgent: true,
    is_exploitable_in_context: false,
    is_regulatory_or_control_relevant: true,
    needs_engineering_change: true,
    needs_evidence: false,
    why_now: `Why now for ${id}`,
    impacted_assets: ["Payments API"],
    entry_point: "Public API",
    evidence_refs: ["dfd"],
    linked_threat_ids: [id],
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
    next_best_action: `Next step for ${id}`,
    next_step: `Next step for ${id}`,
    rationale_excerpt: `Rationale for ${id}`,
  };
  return Object.assign(finding, overrides);
}

describe("SecurityReviewPanel", () => {
  it("labels pre-DFD reviews as model readiness instead of semantic threat analysis", () => {
    render(
      <SecurityReviewPanel
        model={{
          id: "tm-1",
          system_name: "Aurora",
          description: "Pre-DFD review",
          data_classification: "Restricted",
          regulatory_scope: ["PCI DSS"],
        } as ThreatModelResponse}
        threats={[]}
        summary={{
          overall_priority: "p1_now",
          focus_statement: "Evidence gaps block generated threat review.",
          coverage: {
            open_threats: 0,
            attached_evidence_sources: 0,
          },
          review_delta_summary: {
            new_findings: 1,
          },
        } as SecurityReviewApplicationSummary}
        findingsResponse={{
          generated_at: "2026-04-22T00:00:00Z",
          system_name: "Aurora",
          queue_counts: [],
          review_status_counts: [],
          default_finding_id: "evidence-1",
          findings: [
            makeFinding("evidence-1", {
              title: "Threat model lacks DFD coverage",
              queue_bucket: "gather_evidence",
              computed_queue_bucket: "gather_evidence",
              needs_evidence: true,
            }),
          ],
        } as SecurityReviewFindingListResponse}
        selectedFindingId={null}
        onSelectFinding={vi.fn()}
        onOpenWorkspace={vi.fn()}
        onQueueBucketChange={vi.fn()}
        onStatusChange={vi.fn()}
        onCreateArtifact={vi.fn()}
        hasDfdContent={false}
      />,
    );

    expect(screen.getByText("Model readiness review")).toBeInTheDocument();
    expect(screen.getByText("0 generated findings")).toBeInTheDocument();
    expect(screen.queryByText("Semantic application review")).not.toBeInTheDocument();
  });

  it("keeps a threat-heavy queue grouped and updates detail focus when a finding is selected", async () => {
    const user = userEvent.setup();
    const findings = [
      makeFinding("fix-1", { title: "Priority gateway path", priority: "p1_now", queue_bucket: "fix_now", computed_queue_bucket: "fix_now", wire_action_bucket: "engineer_now", numeric_score: 96, is_exploitable_in_context: true }),
      makeFinding("fix-2", { title: "Control-plane identity path", priority: "p1_now", queue_bucket: "fix_now", computed_queue_bucket: "fix_now", wire_action_bucket: "engineer_now", numeric_score: 93, is_exploitable_in_context: true }),
      makeFinding("fix-3", { title: "Restricted data path", priority: "p1_now", queue_bucket: "fix_now", computed_queue_bucket: "fix_now", wire_action_bucket: "engineer_now", numeric_score: 91 }),
      makeFinding("verify-1", { title: "Verify ingress guard", queue_bucket: "verify", computed_queue_bucket: "verify", next_best_action: "Confirm the ingress policy is enforced in production." }),
      makeFinding("verify-2", { title: "Verify audit trail", queue_bucket: "verify", computed_queue_bucket: "verify", next_best_action: "Confirm immutable logging on the control API." }),
      makeFinding("evidence-1", { title: "Cloud evidence missing", source_object_type: "application_review_finding", source_object_id: "model:cloud-evidence", threat_id: null, display_id: null, display_kind: "evidence_gap", wire_kind: "evidence_gap", queue_bucket: "gather_evidence", computed_queue_bucket: "gather_evidence", wire_action_bucket: "fill_evidence_gap", needs_evidence: true, needs_engineering_change: false, next_best_action: "Upload supported cloud posture evidence.", why_now: "Cloud controls are unproven." }),
      makeFinding("evidence-2", { title: "IaC evidence missing", source_object_type: "application_review_finding", source_object_id: "model:iac-evidence", threat_id: null, display_id: null, display_kind: "evidence_gap", wire_kind: "evidence_gap", queue_bucket: "gather_evidence", computed_queue_bucket: "gather_evidence", wire_action_bucket: "fill_evidence_gap", needs_evidence: true, needs_engineering_change: false, next_best_action: "Attach Terraform or CloudFormation artifacts.", why_now: "Network and identity controls are unproven." }),
      makeFinding("backlog-1", { title: "Backlog hardening item", queue_bucket: "backlog", computed_queue_bucket: "backlog", wire_action_bucket: "planned_hardening", priority: "p4_monitor", review_status: "open", next_best_action: "Schedule the hardening change next sprint." }),
      makeFinding("accepted-1", { title: "Accepted residual risk", queue_bucket: null, computed_queue_bucket: "backlog", review_status: "accepted", wire_action_bucket: "planned_hardening", next_best_action: "Monitor until the next review window." }),
    ];

    function Harness(): JSX.Element {
      const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
      return (
        <SecurityReviewPanel
          model={{
            id: "tm-1",
            system_name: "Aurora",
            description: "DER review",
            data_classification: "Restricted",
            regulatory_scope: ["PCI DSS"],
          } as ThreatModelResponse}
          threats={[]}
          summary={{
            overall_priority: "p1_now",
            focus_statement: "This application is currently led by p1 now work.",
            coverage: {
              open_threats: 8,
              attached_evidence_sources: 2,
            },
            review_delta_summary: {
              new_findings: 4,
            },
          } as SecurityReviewApplicationSummary}
          findingsResponse={{
            generated_at: "2026-04-22T00:00:00Z",
            system_name: "Aurora",
            queue_counts: [],
            review_status_counts: [],
            default_finding_id: "fix-1",
            findings,
          } as SecurityReviewFindingListResponse}
          selectedFindingId={selectedFindingId}
          onSelectFinding={setSelectedFindingId}
          onOpenWorkspace={vi.fn()}
          onQueueBucketChange={vi.fn()}
          onStatusChange={vi.fn()}
          onCreateArtifact={vi.fn()}
        />
      );
    }

    render(<Harness />);

    expect(screen.getByText("What Matters Now")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Fix Now", level: 5 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Verify", level: 5 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Gather Evidence", level: 5 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Backlog", level: 5 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Accepted", level: 5 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Priority gateway path/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Cloud evidence missing/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Backlog hardening item/i })).toBeInTheDocument();
    expect(screen.getByText("Next step for fix-1")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Backlog hardening item/i }));

    expect(screen.getByText("Schedule the hardening change next sprint.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Open In Findings/i })).toBeInTheDocument();
  });
});
