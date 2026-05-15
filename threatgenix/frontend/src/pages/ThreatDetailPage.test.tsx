import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { ThreatRemediationRun, ThreatResponse, ThreatValidationRun } from "../types/api";
import ThreatDetailPage from "./ThreatDetailPage";

vi.mock("../api/client", () => ({
  api: {
    getThreat: vi.fn(),
    getThreatHistory: vi.fn(),
    getDFD: vi.fn(),
    getThreatCatalog: vi.fn(),
    getThreatIntel: vi.fn(),
    getLatestThreatScanCorrelation: vi.fn(),
    assistantRespond: vi.fn(),
    listThreatValidationRuns: vi.fn(),
    startThreatValidationRun: vi.fn(),
    proposeThreatScanPlan: vi.fn(),
    approveThreatScanPlan: vi.fn(),
    getThreatScanPlan: vi.fn(),
    rejectThreatScanPlan: vi.fn(),
    rerunThreatValidationRun: vi.fn(),
    startThreatRemediationRun: vi.fn(),
    confirmThreatRemediationHandoff: vi.fn(),
    attachThreatRemediationEvidence: vi.fn(),
  },
}));

vi.mock("../auth/useAuth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      email: "priya@example.com",
      role: "Security Reviewer",
      organization_name: "Northstar Bank",
    },
  }),
}));

vi.mock("../components/threats/ThreatIntelPanel", () => ({
  ThreatIntelPanel: () => <div data-testid="threat-intel-panel" />,
}));

vi.mock("../components/threats/ThreatTriageModal", () => ({
  ThreatTriageModal: () => <div data-testid="threat-triage-modal" />,
}));

const threat: ThreatResponse = {
  id: "threat-1",
  display_id: "T-001",
  description: "Sensitive export route may be missing authorization.",
  stride_category: "Elevation of Privilege",
  threat_subtype: "Missing Authorization",
  severity: "High",
  source: "scanner",
  status: "Open",
  dismiss_reason: null,
  rule_id: null,
  ai_enhanced: false,
  provider_managed: false,
  original_rule_threat_id: null,
  affected_node_ids: [],
  affected_edge_ids: [],
  relevance_rationale: "Export data contains sensitive customer records.",
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
  created_at: "2026-05-03T00:00:00Z",
};

const validationRun: ThreatValidationRun = {
  id: "validation-1",
  tenant_key: "user:user-1",
  owner_id: "user-1",
  organization_id: null,
  threat_model_id: "tm-1",
  threat_id: "threat-1",
  application_review_id: null,
  orchestration_job_id: "job-1",
  status: "completed",
  conclusion: "confirmed",
  question: "Validate sensitive export route authorization.",
  requested_tools: ["semgrep"],
  domain_agent_plan: [
    {
      domain_agent: "sast",
      label: "SAST Agent",
      tools: ["semgrep"],
      instructions: "Validate source-code exploitability and cite file, rule, and code-path evidence.",
    },
  ],
  domain_agent_results: [
    {
      domain_agent: "sast",
      label: "SAST Agent",
      status: "evidence_attached",
      tools: [
        {
          tool: "semgrep",
          status: "evidence_attached",
          evidence_refs: [
            {
              id: "evidence-1",
              title: "Semgrep finding: export route has no authorization guard",
            },
          ],
          task_id: "task-1",
          skipped_reason: null,
          started_at: "2026-05-03T00:00:00Z",
          completed_at: "2026-05-03T00:00:01Z",
        },
      ],
      evidence_refs: [
        {
          id: "evidence-1",
          title: "Semgrep finding: export route has no authorization guard",
        },
      ],
      skipped_reason: null,
      started_at: "2026-05-03T00:00:00Z",
      completed_at: "2026-05-03T00:00:01Z",
    },
  ],
  evidence_refs: [
    {
      id: "evidence-1",
      title: "Semgrep finding: export route has no authorization guard",
      item_type: "scanner_finding",
      content_hash: "d".repeat(64),
    },
  ],
  exploitability: {
    status: "exploitable",
    attacker_profile: "authenticated low-privilege tenant user",
    attack_path: [
      "Attacker authenticates with a normal tenant account.",
      "Attacker reaches the sensitive export route.",
      "The route accepts the export request without a scoped authorization guard.",
      "Sensitive customer export data can be returned outside intended permission.",
    ],
    preconditions: [
      "Valid low-privilege account exists.",
      "Export route is reachable from the application boundary.",
      "Route handles restricted or customer data.",
      "Scoped export authorization is missing or not enforced.",
    ],
    blocking_controls: [],
    evidence_refs: ["evidence-1"],
    confidence: "high",
    rationale: "Scanner, code-path, and data-context evidence support a realistic exploit path.",
  },
  summary: "Scanner and code evidence support the authorization finding.",
  failure_reason: null,
  metadata: {
    agent_type: "threat_validation",
    agent_version: "2026.05.v1",
    input_schema_version: "agent-input.v1",
    output_schema_version: "agent-output.v1",
    policy_version: "human-triggered-v1",
    tool_harness_versions: { semgrep: "fixture" },
    model_provider: null,
    model_name: null,
    prompt_version: null,
    model_output_hash: null,
    deterministic_fallback_used: true,
  },
  trace: {
    events: [
      {
        id: "event-1",
        job_id: "job-1",
        task_id: null,
        threat_model_id: "tm-1",
        event_type: "completed",
        level: "info",
        message: "Validation concluded from approved evidence.",
        payload: { agent_event: "validation.concluded" },
        created_at: "2026-05-03T00:00:00Z",
      },
    ],
  },
  created_at: "2026-05-03T00:00:00Z",
  updated_at: "2026-05-03T00:00:00Z",
};

const proposedValidationRun: ThreatValidationRun = {
  ...validationRun,
  id: "validation-plan-1",
  status: "created",
  conclusion: null,
  evidence_refs: [],
  summary: "Agent scan plan proposed. Review tools, targets, and instructions before approving execution.",
  exploitability: {
    status: "needs_more_evidence",
    attacker_profile: null,
    attack_path: [],
    preconditions: [],
    blocking_controls: [],
    evidence_refs: [],
    confidence: "low",
    rationale: "Agent scan plan is awaiting human approval before tools run.",
  },
  domain_agent_results: [
    {
      domain_agent: "sast",
      label: "SAST Agent",
      status: "planned",
      tools: [
        {
          tool: "semgrep",
          status: "planned",
          evidence_refs: [],
          task_id: null,
          scan_job_id: null,
          skipped_reason: null,
          started_at: null,
          completed_at: null,
        },
      ],
      evidence_refs: [],
      skipped_reason: null,
      started_at: null,
      completed_at: null,
    },
  ],
};

const remediationRun: ThreatRemediationRun = {
  id: "remediation-1",
  tenant_key: "user:user-1",
  owner_id: "user-1",
  organization_id: null,
  validation_run_id: "validation-1",
  threat_model_id: "tm-1",
  threat_id: "threat-1",
  application_review_id: null,
  orchestration_job_id: "job-2",
  agent_type: "code_fix",
  status: "awaiting_confirmation",
  fix_summary: "Add scoped authorization before serving sensitive export data.",
  patch_preview: "backend/app/api/exports.py: require export:read permission.",
  ticket_draft: {
    title: "Fix missing authorization on sensitive export route",
    body: "Evidence: Semgrep finding and backend/app/api/exports.py.",
  },
  pr_draft: {
    title: "Require authorization on export route",
    body: "Draft only; confirmation required.",
  },
  external_ticket_id: null,
  external_ticket_url: null,
  external_pr_url: null,
  handoff_delivery_status: "recorded",
  handoff_provider: null,
  handoff_error: null,
  handoff_idempotency_key: null,
  evidence_refs: [],
  failure_reason: null,
  metadata: {
    agent_type: "code_fix",
    agent_version: "2026.05.v1",
    input_schema_version: "agent-input.v1",
    output_schema_version: "agent-output.v1",
    policy_version: "human-triggered-v1",
    tool_harness_versions: {},
    model_provider: null,
    model_name: null,
    prompt_version: null,
    model_output_hash: null,
    deterministic_fallback_used: true,
  },
  trace: { events: [] },
  created_at: "2026-05-03T00:00:00Z",
  updated_at: "2026-05-03T00:00:00Z",
};

const handoffRun: ThreatRemediationRun = {
  ...remediationRun,
  status: "handoff_created",
  handoff_delivery_status: "recorded",
  handoff_provider: "manual",
  external_ticket_id: "SEC-123",
  external_ticket_url: "https://tickets.example/SEC-123",
};

const handoffRunWithEvidence: ThreatRemediationRun = {
  ...handoffRun,
  evidence_refs: [
    {
      type: "remediation_evidence",
      title: "Confirmed handoff evidence",
      evidence_summary: "Confirmed handoff evidence attached for rerun validation.",
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/threat-models/tm-1/threats/threat-1"]}>
      <Routes>
        <Route path="/threat-models/:threatModelId/threats/:threatId" element={<ThreatDetailPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ThreatDetailPage agent orchestration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getThreat).mockResolvedValue(threat);
    vi.mocked(api.getThreatHistory).mockResolvedValue([]);
    vi.mocked(api.getDFD).mockResolvedValue({ nodes: [], edges: [], trust_boundaries: [] });
    vi.mocked(api.getThreatCatalog).mockResolvedValue([]);
    vi.mocked(api.getThreatIntel).mockRejectedValue(new Error("Threat intel unavailable."));
    vi.mocked(api.getLatestThreatScanCorrelation).mockRejectedValue(
      new Error("No scan correlation.")
    );
    vi.mocked(api.listThreatValidationRuns).mockResolvedValue([]);
    vi.mocked(api.startThreatValidationRun).mockResolvedValue(validationRun);
    vi.mocked(api.proposeThreatScanPlan).mockResolvedValue(proposedValidationRun);
    vi.mocked(api.approveThreatScanPlan).mockResolvedValue({
      ...validationRun,
      id: "validation-plan-1",
      status: "running",
      conclusion: null,
      summary: "Approved domain-agent validation job(s) are running; evidence is pending.",
      domain_agent_results: [
        {
          domain_agent: "sast",
          label: "SAST Agent",
          status: "running",
          tools: [
            {
              tool: "semgrep",
              status: "authorized",
              evidence_refs: [],
              task_id: null,
              scan_job_id: "scan-job-1",
              skipped_reason: null,
              started_at: "2026-05-03T00:00:00Z",
              completed_at: null,
            },
          ],
          evidence_refs: [],
          skipped_reason: null,
          started_at: "2026-05-03T00:00:00Z",
          completed_at: null,
        },
      ],
    });
    vi.mocked(api.startThreatRemediationRun).mockResolvedValue(remediationRun);
    vi.mocked(api.confirmThreatRemediationHandoff).mockResolvedValue(handoffRun);
    vi.mocked(api.attachThreatRemediationEvidence).mockResolvedValue(handoffRunWithEvidence);
  });

  it("validates a threat, drafts a code fix, and requires confirmation for handoff", async () => {
    renderPage();

    expect(await screen.findByText("T-001")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Validate Threat" }));

    expect(await screen.findByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText("Deterministic fallback")).toBeInTheDocument();
    expect(screen.getByText("Exploitable")).toBeInTheDocument();
    expect(screen.getByText("authenticated low-privilege tenant user")).toBeInTheDocument();
    expect(
      screen.getByText("The route accepts the export request without a scoped authorization guard.")
    ).toBeInTheDocument();
    expect(
      screen.getByText("Semgrep finding: export route has no authorization guard")
    ).toBeInTheDocument();
    expect(screen.getByText("Domain Agent Plan")).toBeInTheDocument();
    expect(screen.getAllByText("SAST Agent").length).toBeGreaterThan(0);
    expect(screen.getByText(/Tools: Semgrep/)).toBeInTheDocument();
    expect(screen.getByText("Domain Execution")).toBeInTheDocument();
    expect(screen.getByText(/Semgrep: evidence_attached/)).toBeInTheDocument();
    await waitFor(() => {
      expect(api.startThreatValidationRun).toHaveBeenCalledWith("tm-1", "threat-1", {
        domain_agents: ["sast"],
        domain_agent_tools: { sast: ["semgrep"] },
        domain_agent_tool_mode: { sast: "recommended" },
        domain_agent_instructions: {},
        requested_tools: ["semgrep"],
      });
    });

    fireEvent.click(screen.getByRole("button", { name: "Generate Code Fix" }));

    expect(
      await screen.findByText("Add scoped authorization before serving sensitive export data.")
    ).toBeInTheDocument();
    expect(screen.getByText("Fallback draft")).toBeInTheDocument();
    expect(api.startThreatRemediationRun).toHaveBeenCalledWith("validation-1", "code_fix");

    fireEvent.click(screen.getByRole("button", { name: "Confirm Handoff" }));
    expect(await screen.findByRole("dialog", { name: "Confirm remediation handoff" })).toBeInTheDocument();
    expect(screen.queryByTitle("Customer-owned GitHub token used only for this request")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Create Handoff" }));

    await waitFor(() => {
      expect(api.confirmThreatRemediationHandoff).toHaveBeenCalledWith("remediation-1", {
        confirmed: true,
        provider: "manual",
        github_repository: null,
        access_token: null,
        confirmed_by: "priya@example.com",
      });
    });
    expect(await screen.findByText("Handoff Created")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Ticket" })).toHaveAttribute(
      "href",
      "https://tickets.example/SEC-123"
    );

    fireEvent.click(screen.getByRole("button", { name: "Attach Evidence" }));

    await waitFor(() => {
      expect(api.attachThreatRemediationEvidence).toHaveBeenCalledWith("remediation-1", {
        provider: "github_issue",
        evidence_summary: "Confirmed handoff evidence attached for rerun validation.",
        external_ticket_id: "SEC-123",
        external_ticket_url: "https://tickets.example/SEC-123",
        external_pr_url: null,
      });
    });
    expect(await screen.findByText("Confirmed handoff evidence")).toBeInTheDocument();
  });

  it("proposes and approves a controlled domain-agent scan plan", async () => {
    renderPage();

    expect(await screen.findByText("T-001")).toBeInTheDocument();

    fireEvent.change(screen.getByTitle("Controlled runner target reference"), {
      target: { value: "/tmp/threatgenix-demo-repo" },
    });
    fireEvent.click(screen.getByLabelText("I am authorized to validate this target."));
    fireEvent.click(screen.getByRole("button", { name: "Propose Scan Plan" }));

    expect(await screen.findByText("Needs More Evidence")).toBeInTheDocument();
    expect(screen.getByText(/Semgrep: planned/)).toBeInTheDocument();
    await waitFor(() => {
      expect(api.proposeThreatScanPlan).toHaveBeenCalledWith("tm-1", "threat-1", {
        domain_agents: ["sast"],
        domain_agent_tools: { sast: ["semgrep"] },
        domain_agent_tool_mode: { sast: "recommended" },
        domain_agent_instructions: {},
        requested_tools: ["semgrep"],
      });
    });

    fireEvent.click(screen.getByRole("button", { name: "Approve Scan Plan" }));

    await waitFor(() => {
      expect(api.approveThreatScanPlan).toHaveBeenCalledWith("validation-plan-1", {
        domain_agent_targets: {
          semgrep: {
            tool_name: "semgrep",
            target_type: "repository_path",
            target: "/tmp/threatgenix-demo-repo",
            scope: "internal",
            authorization_acknowledged: true,
          },
        },
        approval_note: "Reviewer authorized controlled domain-agent tool execution.",
      });
    });
    expect(await screen.findByText(/Semgrep: authorized/)).toBeInTheDocument();
  });
});
