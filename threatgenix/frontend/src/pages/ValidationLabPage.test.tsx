import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { OrchestrationJob, ValidationLabSummary } from "../types/api";
import ValidationLabPage from "./ValidationLabPage";

vi.mock("../api/client", () => ({
  api: {
    getValidationLab: vi.fn(),
    getDFD: vi.fn(),
    createValidationSchedule: vi.fn(),
    runValidationTool: vi.fn(),
    runValidationTrySandbox: vi.fn(),
    runValidationSchedule: vi.fn(),
    deleteValidationSchedule: vi.fn(),
    ingestScanEvidence: vi.fn(),
    uploadValidationTargetBundle: vi.fn(),
    uploadValidationArtifactBundle: vi.fn(),
	    getOrchestrationJobs: vi.fn(),
	    runOrchestrationJob: vi.fn(),
	    updateValidationCaseState: vi.fn(),
	    bindValidationEvidence: vi.fn(),
	  },
	}));

const labSummary: ValidationLabSummary = {
  threat_model_id: "tm-1",
  runtime: {
    mode: "self_hosted",
    run_submission_enabled: true,
    live_execution_enabled: true,
    inline_execution_enabled: true,
    worker_execution_enabled: true,
    managed_runner_enabled: false,
    try_sandbox_enabled: true,
    title: "Self-hosted validation runner",
    detail: "Live validation can execute approved tools against authorized targets in this trusted deployment.",
  },
  runner_status: {
    status: "ready",
    detail: "Managed validation runner is connected and idle.",
    pending_count: 0,
    running_count: 0,
    failed_count: 0,
    oldest_pending_age_seconds: null,
    oldest_running_age_seconds: null,
    stale_running_count: 0,
    active_worker_count: 1,
    last_heartbeat_at: "2026-04-26T12:00:00Z",
  },
  posture: {
    schedule_count: 1,
    enabled_schedule_count: 1,
    recent_scan_count: 1,
    ready_tool_count: 1,
    deterministic_tool_count: 1,
    ai_assisted_tool_count: 0,
    validated_threat_count: 2,
    indicated_threat_count: 1,
    untested_threat_count: 4,
    validated_risk_score: 80,
    indicated_risk_score: 60,
    ai_assisted_risk_score: 0,
  },
  tools: [
    {
      name: "semgrep",
      active: true,
      available: true,
      deterministic: true,
      runtime_strategy: "host_cli",
      runtime_detail: "Runs from a CLI installed on the validation runner host.",
      readiness_status: "ready",
      blocker_reasons: [],
      setup_actions: ["Create or run a validation target with per-run authorization."],
      install_hint: null,
      enablement_env: "THREATGENIX_VALIDATION_SEMGREP_ENABLED",
      local_allowlist_required: true,
      local_allowlist_configured: true,
      sandbox_mode: "process",
      container_runtime_available: true,
      container_image: "semgrep/semgrep:latest",
      container_image_present: false,
      container_pull_policy: "never",
      supported_targets: ["repository_path"],
      runs_in_sandbox_required: true,
      execution_enabled: true,
      network_mode: "none",
      max_runtime_seconds: 600,
      max_output_bytes: 5_000_000,
      artifact_capture_enabled: true,
      category: "static_code_analysis",
      proof_mode: "source-code evidence",
      safety_boundary: "Local path allowlist.",
      documentation_url: "https://semgrep.dev/docs/getting-started/cli",
      recommended_for: ["semantic code flaws"],
    },
  ],
  red_team_tools: [],
  setup_lanes: [
    {
      name: "Hosted SaaS",
      status: "available",
      summary: "Use Try Sandbox and imported evidence.",
      controls: ["Curated demo evidence", "Pre-captured scanner output import"],
    },
    {
      name: "Self-hosted runner",
      status: "active",
      summary: "Operator-owned deployment that can execute approved tools.",
      controls: ["THREATGENIX_VALIDATION_RUNTIME_MODE=self_hosted", "Per-run authorization"],
    },
    {
      name: "Managed isolated runner",
      status: "planned",
      summary: "Future SaaS worker pool.",
      controls: ["Ephemeral containers", "Tenant-scoped egress policy"],
    },
  ],
  tool_setup_profiles: [
    {
      tool_name: "semgrep",
      label: "Semgrep",
      setup_mode: "Runnable",
      runner_profile: "Process sandbox with no shell, sanitized env, bounded runtime, and output cap",
      prerequisites: ["Explicit authorization for the target scope", "Approved runner image: semgrep/semgrep:latest"],
      configuration: ["Targets: repository path", "Network: none", "Runtime cap: 600s"],
      safety_gates: ["Local path allowlist.", "Capture artifacts and map evidence to semantic threats"],
    },
  ],
  schedules: [
    {
      id: "sched-1",
      threat_model_id: "tm-1",
      name: "Repository SAST",
      tool_name: "semgrep",
      target_type: "repository_path",
      target: "/allowed/repo",
      target_node_id: null,
      scope: "external",
      cadence: "weekly",
      enabled: true,
      authorization_required: true,
      authorization_acknowledged_at: "2026-04-26T12:00:00Z",
      last_run_at: null,
      next_run_at: "2026-05-03T12:00:00Z",
      created_at: "2026-04-26T12:00:00Z",
      updated_at: "2026-04-26T12:00:00Z",
      runnable: true,
      blocked_reason: null,
    },
  ],
  recent_scans: [],
  latest_runbook: {
    coverage: {
      scan_job_id: "scan-1",
      scan_completed_at: "2026-04-26T12:00:00Z",
      tool_names: ["semgrep"],
      target_binding: "node_bound",
      finding_count: 2,
      deterministic_finding_count: 2,
      assisted_finding_count: 0,
      artifact_count: 1,
      mapped_threat_count: 1,
      validated_threat_count: 2,
      indicated_threat_count: 1,
      unbound_finding_count: 0,
      untested_threat_count: 4,
      confidence_counts: { validated: 2, indicated: 1, untested: 4 },
      validated_risk_score: 80,
      indicated_risk_score: 60,
      ai_assisted_risk_score: 0,
    },
    executive_summary: "Semgrep produced validation evidence.",
    gaps: [],
    mapped_threats: [
      {
        threat_id: "threat-1",
        threat_display_id: "T-001",
        threat_description: "JWT validation bypass",
        severity: "High",
        stride_category: "Spoofing",
        scan_status: "confirmed",
        confidence_label: "validated",
        explanation: "Node-bound evidence.",
        evidence_count: 1,
        risk_score: 80,
        evidence_quality: "strong",
        proof_class: "deterministic",
        next_action: "Verify owner, remediation plan, and retest window.",
        cve_ids: [],
        validation_tools: ["semgrep"],
      },
    ],
    unbound_findings: [],
  },
  product_security_cases: [
    {
      case_id: "threat-1",
      case_type: "threat",
      title: "T-001 · Spoofing",
      hypothesis: "JWT validation bypass",
      severity: "High",
      stride_category: "Spoofing",
      status: "validated",
      confidence_label: "high",
      confidence_score: 94,
      proof_level: "validated",
      proof_class: "deterministic",
      evidence_quality: "strong",
      evidence_count: 1,
      evidence_sources: ["semgrep"],
      risk_score: 80,
      product_questions: [
        "Can a caller assume another identity, role, or tenant context?",
        "Which authentication or token-verification control should block this?",
      ],
      recommended_checks: [
        {
          tool_name: "semgrep",
          target_type: "repository_path",
          priority: "P2",
          reason: "Retest the fix against source-code evidence before closing the case.",
        },
      ],
      next_action: "Verify owner, remediation plan, and retest window.",
      remediation_action: "Open a fix ticket, attach semgrep, assign an owner, and schedule a retest before closure.",
      workflow_status: "open",
      workflow_priority: null,
      owner_label: null,
      due_date: null,
      analyst_note: null,
      last_decision: null,
      workflow_updated_at: null,
      audit_events: [],
    },
  ],
  evidence_ledger: [
    {
      scan_id: "scan-1",
      tool_name: "semgrep",
      target_type: "repository_path",
      status: "completed",
      target_binding: "node_bound",
      finding_count: 2,
      mapped_threat_count: 1,
      validated_threat_count: 2,
      indicated_threat_count: 1,
      unbound_finding_count: 0,
      artifact_count: 1,
      deterministic_finding_count: 2,
      assisted_finding_count: 0,
      output_sha256: "abcdef1234567890",
      error_message: null,
      completed_at: "2026-04-26T12:00:00Z",
      created_at: "2026-04-26T12:00:00Z",
    },
  ],
  gaps: [
    {
      title: "Semantic threats still need validation",
      severity: "medium",
      detail: "4 active threat(s) have no validation evidence yet.",
      next_action: "Prioritize P1 recommendations.",
    },
  ],
  demo_scenario: {
    title: "Safe Semgrep JWT fixture",
    summary: "A deterministic source-code finding that can be imported without executing any scanner.",
    tool_name: "semgrep",
    target_type: "repository_path",
    target: "/allowed/repository/path",
    raw_output: JSON.stringify({ results: [] }),
    expected_signal: "Should create source-code evidence.",
  },
  safety_controls: [
    {
      name: "Authorization gate",
      status: "enforced",
      detail: "Every live run requires consent.",
    },
  ],
  recommended_next_runs: [
    {
      tool_name: "semgrep",
      target_type: "repository_path",
      priority: "P1",
      reason: "Validate semantic code flaws.",
      blocked_reason: null,
    },
  ],
  agentic_tool_bench: null,
};

const orchestrationJob: OrchestrationJob = {
  id: "orch-1",
  threat_model_id: "tm-1",
  owner_id: "user-1",
  job_kind: "validation_run",
  status: "pending",
  objective: "Run authorized validation tools and rebuild evidence.",
  requested_tools: ["semgrep"],
  idempotency_key: null,
  inputs: {},
  policy: {},
  result_summary: null,
  error_message: null,
  started_at: null,
  completed_at: null,
  created_at: "2026-04-26T12:00:00Z",
  updated_at: "2026-04-26T12:00:00Z",
  tasks: [
    {
      id: "task-1",
      job_id: "orch-1",
      threat_model_id: "tm-1",
      task_kind: "tool_execution",
      agent_name: null,
      tool_name: "semgrep",
      status: "pending",
      input_payload: {},
      output_payload: {},
      error_message: null,
      attempt_count: 0,
      max_attempts: 1,
      started_at: null,
      completed_at: null,
      created_at: "2026-04-26T12:00:00Z",
      updated_at: "2026-04-26T12:00:00Z",
    },
  ],
  events: [],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/threat-models/tm-1/validation-lab"]}>
      <Routes>
        <Route path="/threat-models/:id/validation-lab" element={<ValidationLabPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ValidationLabPage", () => {
  beforeEach(() => {
	    vi.clearAllMocks();
	    vi.mocked(api.getValidationLab).mockResolvedValue(labSummary);
	    vi.mocked(api.getDFD).mockResolvedValue({ nodes: [], edges: [], trust_boundaries: [] });
	    vi.mocked(api.getOrchestrationJobs).mockResolvedValue([]);
	    vi.mocked(api.runOrchestrationJob).mockResolvedValue({
	      ...orchestrationJob,
	      status: "blocked",
	      error_message: "Orchestration blocked with 1 blocked task(s) and 0 cancelled task(s).",
	      tasks: [
	        {
	          ...orchestrationJob.tasks[0]!,
	          status: "blocked",
	          attempt_count: 1,
	          error_message: "authorization_acknowledged=true is required before executing validation tools.",
	        },
	      ],
	      events: [
	        {
	          id: "event-1",
	          job_id: "orch-1",
	          task_id: "task-1",
	          threat_model_id: "tm-1",
	          event_type: "blocked",
	          level: "warning",
	          message: "Orchestration task blocked.",
	          payload: {},
	          created_at: "2026-04-26T12:00:01Z",
	        },
	      ],
	    });
	    vi.mocked(api.createValidationSchedule).mockResolvedValue(labSummary.schedules[0]!);
    vi.mocked(api.runValidationTool).mockResolvedValue({
      id: "scan-once-1",
      threat_model_id: "tm-1",
      status: "pending",
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "semgrep",
      target_type: "repository_path",
      targets: { direct: "/allowed/repo" },
      finding_count: 0,
      credential_id: null,
      started_at: null,
      completed_at: null,
      error_message: null,
      created_at: "2026-04-26T12:00:00Z",
    });
    vi.mocked(api.runValidationTrySandbox).mockResolvedValue({
      id: "scan-sandbox-1",
      threat_model_id: "tm-1",
      status: "completed",
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "semgrep",
      target_type: "repository_path",
      targets: { try_sandbox: "/try-sandbox/semgrep/jwt-service" },
      finding_count: 1,
      credential_id: null,
      started_at: "2026-04-26T12:00:00Z",
      completed_at: "2026-04-26T12:00:01Z",
      error_message: null,
      created_at: "2026-04-26T12:00:00Z",
    });
    vi.mocked(api.runValidationSchedule).mockResolvedValue({
      id: "scan-2",
      threat_model_id: "tm-1",
      status: "pending",
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "semgrep",
      target_type: "repository_path",
      targets: { direct: "/allowed/repo" },
      finding_count: 0,
      credential_id: null,
      started_at: null,
      completed_at: null,
      error_message: null,
      created_at: "2026-04-26T12:00:00Z",
    });
    vi.mocked(api.ingestScanEvidence).mockResolvedValue({
      id: "scan-import-1",
      threat_model_id: "tm-1",
      status: "completed",
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "semgrep",
      target_type: "repository_path",
      targets: { direct: "/allowed/repo" },
      finding_count: 1,
      credential_id: null,
      started_at: "2026-04-26T12:00:00Z",
      completed_at: "2026-04-26T12:00:01Z",
      error_message: null,
      created_at: "2026-04-26T12:00:00Z",
      findings: [],
      threat_results: [],
      execution_artifacts: [],
    });
    vi.mocked(api.uploadValidationArtifactBundle).mockResolvedValue({
      bundle: {
        id: "bundle-1",
        threat_model_id: "tm-1",
        owner_id: "user-1",
        organization_id: "org-1",
        filename: "semgrep.json",
        content_type: "application/json",
        byte_size: 14,
        sha256: "abcdef1234567890",
        status: "imported",
        manifest: {},
        storage_backend: "metadata_only",
        storage_key: null,
        error_message: null,
        item_count: 1,
        created_at: "2026-04-26T12:00:00Z",
        updated_at: "2026-04-26T12:00:00Z",
        items: [],
      },
      created_scans: [
        {
          id: "scan-import-1",
          threat_model_id: "tm-1",
          status: "completed",
          scan_type: "unauthenticated",
          scope: "external",
          tool_name: "semgrep",
          target_type: "repository_path",
          targets: { direct: "/allowed/repo" },
          finding_count: 1,
          credential_id: null,
          started_at: "2026-04-26T12:00:00Z",
          completed_at: "2026-04-26T12:00:01Z",
          error_message: null,
          created_at: "2026-04-26T12:00:00Z",
          findings: [],
          threat_results: [],
          execution_artifacts: [],
        },
      ],
    });
    vi.mocked(api.uploadValidationTargetBundle).mockResolvedValue({
      id: "target-bundle-1",
      threat_model_id: "tm-1",
      owner_id: "user-1",
      organization_id: "org-1",
      name: "Repository SAST baseline",
      filename: "repo.zip",
      content_type: "application/zip",
      byte_size: 2048,
      sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      status: "ready",
      storage_backend: "database",
      manifest: { file_count: 3 },
      target_ref: "tgx-target://11111111-1111-1111-1111-111111111111",
      retention_expires_at: "2026-05-03T12:00:00Z",
      created_at: "2026-04-26T12:00:00Z",
      updated_at: "2026-04-26T12:00:00Z",
    });
    vi.mocked(api.updateValidationCaseState).mockResolvedValue({
      ...labSummary.product_security_cases[0]!,
      workflow_status: "investigating",
      workflow_priority: "P1",
      owner_label: "Product Security",
      due_date: "2026-05-01",
      analyst_note: "Checking exploitability.",
      last_decision: "Needs source retest.",
      workflow_updated_at: "2026-04-26T12:30:00Z",
      audit_events: [
        {
          id: "event-1",
          action: "updated",
          changes: { workflow_status: { from: "open", to: "investigating" } },
          note: "Needs source retest.",
          actor_id: "user-1",
          created_at: "2026-04-26T12:30:00Z",
        },
      ],
    });
    vi.mocked(api.bindValidationEvidence).mockResolvedValue({
      finding_id: "finding-1",
      scan_id: "scan-1",
      threat_model_id: "tm-1",
      target_node_id: "node-1",
      target_node_name: "Authentication Service",
      binding_target: "path:app/auth.py",
      target_binding: "node_bound",
      mapped_threat_count: 1,
      unbound_finding_count: 0,
      message: "Evidence bound to Authentication Service and semantic mapping refreshed.",
    });
  });

  it("renders posture, tool readiness, and safety controls", async () => {
    renderPage();

    expect(await screen.findByText("Deterministic Evidence Workspace")).toBeInTheDocument();
    expect(screen.getByText("Ready tools")).toBeInTheDocument();
    expect(screen.getAllByText(/source-code evidence/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Authorization gate")).toBeInTheDocument();
    expect(screen.getByText("Semgrep produced validation evidence.")).toBeInTheDocument();
    expect(screen.getByText("Validation Cases")).toBeInTheDocument();
    expect(screen.getAllByText("JWT validation bypass").length).toBeGreaterThan(0);
    expect(screen.getByText("Open a fix ticket, attach semgrep, assign an owner, and schedule a retest before closure.")).toBeInTheDocument();
    expect(screen.getByText("Gap Closure Plan")).toBeInTheDocument();
    expect(screen.getByText("Runner Architecture")).toBeInTheDocument();
    expect(screen.getByText("Self-hosted runner")).toBeInTheDocument();
    expect(screen.getByText("Prerequisites")).toBeInTheDocument();
    expect(screen.getByText("Runs from a CLI installed on the validation runner host.")).toBeInTheDocument();
    expect(screen.getByText("Managed validation runner is connected and idle.")).toBeInTheDocument();
	    expect(screen.getByText("Evidence Ledger")).toBeInTheDocument();
	  });

  it("renders agentic tool planning with execution gates and critic rules", async () => {
    vi.mocked(api.getValidationLab).mockResolvedValue({
      ...labSummary,
      product_security_cases: [
        {
          ...labSummary.product_security_cases[0]!,
          status: "needs_evidence",
          proof_level: "none",
          evidence_count: 0,
        },
      ],
      agentic_tool_bench: {
        status: "ready",
        summary: "Agentic planning is ready for a policy-gated Semgrep run.",
        planning_inputs: ["1 product security case(s)", "1 saved validation target(s)"],
        capabilities: [
          {
            tool_name: "semgrep",
            label: "Semgrep",
            category: "static_code_analysis",
            target_types: ["repository_path"],
            proves: ["source-code security pattern", "auth implementation flaw"],
            best_for: ["semantic code flaws"],
            evidence_schema: ["source_path", "rule_id", "line"],
            execution_boundary: "Local path allowlist.",
            noise_controls: ["Map findings to DFD node metadata before semantic validation."],
            critic_checks: ["Require source path or component metadata before binding to a DFD node."],
          },
        ],
        recommendations: [
          {
            recommendation_id: "threat-1:semgrep:repository_path",
            priority: "P1",
            tool_name: "semgrep",
            target_type: "repository_path",
            objective: "Use Semgrep to collect evidence for JWT verifier accepts untrusted algorithms.",
            rationale: "Retest authentication source code with a deterministic SAST rule.",
            evidence_gap: "No concrete validation evidence has been captured for this case.",
            expected_evidence: "source-code security pattern on a repository path target with artifact provenance.",
            blocked_reason: null,
            saved_target_id: "sched-1",
            safety_gates: ["Per-run target authorization must be acknowledged."],
            critic_checks: ["Require source path or component metadata before binding to a DFD node."],
            workflow: [
              { step: "plan", owner: "Validation Planner", detail: "Choose Semgrep only when it can close a named evidence gap." },
              { step: "policy_gate", owner: "Policy Gate", detail: "Check tenant authorization and target type." },
              { step: "execute", owner: "Tool Executor", detail: "Run only the approved adapter through durable task execution; no freeform shell." },
              { step: "bind", owner: "Evidence Binder", detail: "Normalize output and bind it to modeled components." },
              { step: "critic", owner: "Evidence Critic", detail: "Demote noisy findings before they affect confidence." },
              { step: "report", owner: "Report Agent", detail: "Explain only cited evidence." },
            ],
          },
        ],
        execution_contract: [
          { step: "plan", owner: "Validation Planner", detail: "Choose Semgrep only when it can close a named evidence gap." },
          { step: "policy_gate", owner: "Policy Gate", detail: "Check tenant authorization and target type." },
          { step: "execute", owner: "Tool Executor", detail: "Run only the approved adapter through durable task execution; no freeform shell." },
          { step: "bind", owner: "Evidence Binder", detail: "Normalize output and bind it to modeled components." },
          { step: "critic", owner: "Evidence Critic", detail: "Demote noisy findings before they affect confidence." },
          { step: "report", owner: "Report Agent", detail: "Explain only cited evidence." },
        ],
        global_critic_rules: ["Never claim a vulnerability is validated without tool evidence."],
      },
    });
    renderPage();

    expect(await screen.findByText("Agentic Tool Bench")).toBeInTheDocument();
    expect(screen.getByText("Planner Queue")).toBeInTheDocument();
    expect(screen.getByText("Execution Contract")).toBeInTheDocument();
    expect(screen.getByText("Critic Rules")).toBeInTheDocument();
    expect(screen.getByText("Use Semgrep to collect evidence for JWT verifier accepts untrusted algorithms.")).toBeInTheDocument();
    expect(screen.getByText("Run only the approved adapter through durable task execution; no freeform shell.")).toBeInTheDocument();
    expect(screen.getByText("Never claim a vulnerability is validated without tool evidence.")).toBeInTheDocument();
  });

	  it("renders and runs orchestration jobs", async () => {
	    const user = userEvent.setup();
	    vi.mocked(api.getOrchestrationJobs).mockResolvedValue([orchestrationJob]);

	    renderPage();

	    expect(await screen.findByText("Agent and Tool Timeline")).toBeInTheDocument();
	    expect(screen.getByText("Run authorized validation tools and rebuild evidence.")).toBeInTheDocument();
	    await user.click(screen.getAllByRole("button", { name: "Run" })[0]!);

	    await waitFor(() => expect(api.runOrchestrationJob).toHaveBeenCalledWith("tm-1", "orch-1"));
	  });

  it("normalizes forbidden validation lab links without exposing raw API text", async () => {
    vi.mocked(api.getValidationLab).mockRejectedValue(new Error("403: Access denied"));

    renderPage();

    expect(await screen.findByText("Validation lab unavailable.")).toBeInTheDocument();
    expect(screen.getByText(/may not have access/i)).toBeInTheDocument();
    expect(screen.queryByText("403: Access denied")).not.toBeInTheDocument();
  });

  it("requires explicit consent before creating or running validation targets", async () => {
    const user = userEvent.setup();
    renderPage();

    const saveButton = await screen.findByRole("button", { name: "Save Target" });
    expect(saveButton).toBeDisabled();

    await user.type(screen.getByPlaceholderText("/allowed/repository/path"), "/allowed/repo");
    await user.click(screen.getByText("I am authorized to test this target and accept responsibility for the configured scope."));
    await user.click(saveButton);

    await waitFor(() => expect(api.createValidationSchedule).toHaveBeenCalledTimes(1));

    const runButton = screen.getByRole("button", { name: "Run" });
    expect(runButton).toBeDisabled();
    await user.click(screen.getByText("Authorized run"));
    await user.click(runButton);

    await waitFor(() => expect(api.runValidationSchedule).toHaveBeenCalledWith("tm-1", "sched-1", true));
  });

  it("uploads a hosted target bundle and applies the returned target reference", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Saved Validation Target")).toBeInTheDocument();
    await user.click(screen.getByText("I am authorized to test this target and accept responsibility for the configured scope."));
    const file = new File(["bundle"], "repo.zip", { type: "application/zip" });
    await user.upload(screen.getByLabelText("Target Bundle File"), file);
    await user.click(screen.getByRole("button", { name: "Upload Target Bundle" }));

    await waitFor(() => expect(api.uploadValidationTargetBundle).toHaveBeenCalledTimes(1));
    expect(api.uploadValidationTargetBundle).toHaveBeenCalledWith("tm-1", {
      file,
      name: undefined,
      authorization_acknowledged: true,
    });
    expect(await screen.findByText("Repository SAST baseline uploaded as a hosted validation target.")).toBeInTheDocument();
    expect(screen.getByDisplayValue("tgx-target://11111111-1111-1111-1111-111111111111")).toBeInTheDocument();
  });

  it("opens a validation case and saves workflow state", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Open Case" }));
    expect(screen.getByText("Case Detail")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Workflow Status"), "investigating");
    await user.selectOptions(screen.getByLabelText("Priority"), "P1");
    await user.type(screen.getByLabelText("Owner"), "Product Security");
    fireEvent.change(screen.getByLabelText("Due Date"), { target: { value: "2026-05-01" } });
    await user.type(screen.getByLabelText("Analyst Notes"), "Checking exploitability.");
    await user.type(screen.getByLabelText("Decision / Rationale"), "Needs source retest.");
    await user.click(screen.getByRole("button", { name: "Save Case State" }));

    await waitFor(() => expect(api.updateValidationCaseState).toHaveBeenCalledWith("tm-1", "threat-1", {
      workflow_status: "investigating",
      workflow_priority: "P1",
      clear_priority: false,
      owner_label: "Product Security",
      clear_owner: false,
      due_date: "2026-05-01",
      clear_due_date: false,
      analyst_note: "Checking exploitability.",
      last_decision: "Needs source retest.",
    }));
    expect(await screen.findByText("T-001 · Spoofing workflow saved.")).toBeInTheDocument();
  });

  it("binds unbound evidence to a selected DFD node", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getValidationLab).mockResolvedValue({
      ...labSummary,
      latest_runbook: {
        ...labSummary.latest_runbook!,
        coverage: {
          ...labSummary.latest_runbook!.coverage,
          target_binding: "global",
          mapped_threat_count: 0,
          validated_threat_count: 0,
          indicated_threat_count: 0,
          unbound_finding_count: 1,
        },
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
            explanation: "Finding is retained as validation evidence but is not bound to a semantic threat.",
          },
        ],
      },
      product_security_cases: [
        {
          ...labSummary.product_security_cases[0]!,
          case_id: "finding-1",
          case_type: "unbound_finding",
          title: "Unbound - JWT verification disabled",
          hypothesis: "Finding is retained as validation evidence but is not bound to a semantic threat.",
          status: "needs_binding",
          proof_level: "observed",
          remediation_action: "Bind this evidence to an affected DFD node before closure.",
        },
      ],
      evidence_ledger: [
        {
          ...labSummary.evidence_ledger[0]!,
          target_binding: "global",
          mapped_threat_count: 0,
          validated_threat_count: 0,
          indicated_threat_count: 0,
          unbound_finding_count: 1,
        },
      ],
    });
    vi.mocked(api.getDFD).mockResolvedValue({
      nodes: [
        {
          id: "node-1",
          node_type: "process",
          name: "Authentication Service",
          position_x: 0,
          position_y: 0,
          trust_boundary_id: null,
          scan_target_url: null,
          scan_target_ports: null,
          properties: {},
        },
      ],
      edges: [],
      trust_boundaries: [],
    });
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Open Case" }));
    expect(screen.getByText("Bind Evidence To DFD Component")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Bind To DFD Node"), "node-1");
    await user.click(screen.getByRole("button", { name: "Bind Evidence" }));

    await waitFor(() => expect(api.bindValidationEvidence).toHaveBeenCalledWith("tm-1", "finding-1", {
      target_node_id: "node-1",
    }));
    expect(await screen.findByText("Evidence bound to Authentication Service and semantic mapping refreshed.")).toBeInTheDocument();
  });

  it("queues a one-off validation run from a saved target draft", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(await screen.findByPlaceholderText("/allowed/repository/path"), "/allowed/repo");
    await user.click(screen.getByText("I am authorized to test this target and accept responsibility for the configured scope."));
    await user.click(screen.getByRole("button", { name: "Run Once" }));

    await waitFor(() => expect(api.runValidationTool).toHaveBeenCalledWith("tm-1", {
      tool_name: "semgrep",
      target_type: "repository_path",
      target: "/allowed/repo",
      target_node_id: null,
      scope: "external",
      authorization_acknowledged: true,
    }));
  });

  it("imports captured tool output without executing a scanner", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Import Captured Evidence")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Load Safe Sample" }));
    expect(screen.getByDisplayValue(JSON.stringify({ results: [] }))).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText("repository, lockfile, IaC path, or container image"), {
      target: { value: "/allowed/repo" },
    });
    fireEvent.change(screen.getByPlaceholderText("Paste JSON, JSONL, or text findings from a scanner, security platform, or pentest report"), {
      target: { value: JSON.stringify({ results: [] }) },
    });
    await user.click(screen.getByRole("button", { name: "Import Evidence" }));

    await waitFor(() => expect(api.ingestScanEvidence).toHaveBeenCalledTimes(1));
    expect(api.ingestScanEvidence).toHaveBeenCalledWith("tm-1", {
      tool_name: "semgrep",
      target_type: "repository_path",
      target: "/allowed/repo",
      target_node_id: null,
      raw_output: JSON.stringify({ results: [] }),
    });
  });

  it("uploads a captured evidence file as a validation artifact bundle", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Import Captured Evidence")).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("repository, lockfile, IaC path, or container image"), {
      target: { value: "/allowed/repo" },
    });
    const file = new File([JSON.stringify({ results: [] })], "semgrep.json", {
      type: "application/json",
    });
    await user.upload(screen.getByLabelText("Evidence File"), file);
    await user.click(screen.getByRole("button", { name: "Import File" }));

    await waitFor(() => expect(api.uploadValidationArtifactBundle).toHaveBeenCalledTimes(1));
    expect(api.uploadValidationArtifactBundle).toHaveBeenCalledWith("tm-1", {
      file,
      tool_name: "semgrep",
      target_type: "repository_path",
      target: "/allowed/repo",
      target_node_id: null,
    });
    expect(await screen.findByText("semgrep.json imported as 1 validation artifact.")).toBeInTheDocument();
  });

  it("uploads manifest bundles without requiring duplicate target metadata", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Import Captured Evidence")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Evidence file mode"), "manifest_bundle");
    expect(
      screen.getByText(
        "threatgenix-validation-manifest.json supplies tool, target, and evidence item metadata"
      )
    ).toBeInTheDocument();
    const file = new File(["bundle"], "threatgenix-validation-bundle.zip", {
      type: "application/zip",
    });
    await user.upload(screen.getByLabelText("Evidence File"), file);
    await user.click(screen.getByRole("button", { name: "Import File" }));

    await waitFor(() => expect(api.uploadValidationArtifactBundle).toHaveBeenCalledTimes(1));
    expect(api.uploadValidationArtifactBundle).toHaveBeenCalledWith("tm-1", {
      file,
    });
  });

  it("imports external and pentest evidence sources", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Import Captured Evidence")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Tool or Source"), "pentest-report");
    fireEvent.change(screen.getByPlaceholderText("https://api.example.com"), {
      target: { value: "Q2 pentest report" },
    });
    fireEvent.change(screen.getByPlaceholderText("Paste JSON, JSONL, or text findings from a scanner, security platform, or pentest report"), {
      target: { value: "High: API Gateway accepts unsigned JWTs" },
    });
    await user.click(screen.getByRole("button", { name: "Import Evidence" }));

    await waitFor(() => expect(api.ingestScanEvidence).toHaveBeenCalledTimes(1));
    expect(api.ingestScanEvidence).toHaveBeenCalledWith("tm-1", {
      tool_name: "pentest-report",
      target_type: "url",
      target: "Q2 pentest report",
      target_node_id: null,
      raw_output: "High: API Gateway accepts unsigned JWTs",
    });
  });

  it("shows hosted try sandbox mode and disables live target execution", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getValidationLab).mockResolvedValue({
      ...labSummary,
      runtime: {
        mode: "try_sandbox",
        live_execution_enabled: false,
        try_sandbox_enabled: true,
        title: "SaaS try sandbox",
        detail: "Hosted tenants can run curated demo evidence and import captured scanner output.",
      },
      posture: {
        ...labSummary.posture,
        ready_tool_count: 0,
        enabled_schedule_count: 0,
      },
      schedules: [],
    });
    renderPage();

    expect(await screen.findByText("SaaS try sandbox")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Target" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run Once" })).toBeDisabled();

    await user.click(screen.getAllByRole("button", { name: "Try Sandbox" })[0]!);
    await waitFor(() => expect(api.runValidationTrySandbox).toHaveBeenCalledWith("tm-1"));
  });

  it("enables live target submission when the managed runner is connected", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getValidationLab).mockResolvedValue({
      ...labSummary,
      runtime: {
        mode: "managed",
        run_submission_enabled: true,
        live_execution_enabled: false,
        inline_execution_enabled: false,
        worker_execution_enabled: false,
        managed_runner_enabled: true,
        try_sandbox_enabled: true,
        title: "Managed isolated runner",
        detail: "Live validation requests are queued to a dedicated validation worker.",
      },
    });
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "Managed isolated runner" }),
    ).toBeInTheDocument();
    expect(screen.getByText("1 worker connected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Once" })).toBeDisabled();

    await user.type(screen.getByPlaceholderText("/allowed/repository/path"), "/allowed/repo");
    await user.click(screen.getByText("I am authorized to test this target and accept responsibility for the configured scope."));
    await user.click(screen.getByRole("button", { name: "Run Once" }));

    await waitFor(() => expect(api.runValidationTool).toHaveBeenCalledTimes(1));
    expect(api.runValidationTool).toHaveBeenCalledWith("tm-1", {
      authorization_acknowledged: true,
      scope: "external",
      target: "/allowed/repo",
      target_node_id: null,
      target_type: "repository_path",
      tool_name: "semgrep",
    });
  });

  it("surfaces blocked readiness, missing safety controls, and DFD-needed binding state", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getValidationLab).mockResolvedValue({
      ...labSummary,
      posture: {
        ...labSummary.posture,
        ready_tool_count: 0,
        validated_threat_count: 0,
        indicated_threat_count: 0,
      },
      tools: [
        {
          ...labSummary.tools[0]!,
          available: false,
          readiness_status: "needs_configuration",
          blocker_reasons: [
            "Set THREATGENIX_VALIDATION_SEMGREP_ENABLED and install the CLI on the runner.",
          ],
          setup_actions: [
            "Install Semgrep on the validation runner.",
            "Configure the local path allowlist before live runs.",
          ],
          execution_enabled: false,
          local_allowlist_configured: false,
        },
      ],
      schedules: [],
      latest_runbook: {
        ...labSummary.latest_runbook!,
        coverage: {
          ...labSummary.latest_runbook!.coverage,
          target_binding: "global",
          mapped_threat_count: 0,
          validated_threat_count: 0,
          indicated_threat_count: 0,
          unbound_finding_count: 2,
          untested_threat_count: 7,
        },
        mapped_threats: [],
      },
      product_security_cases: [],
      evidence_ledger: [
        {
          ...labSummary.evidence_ledger[0]!,
          target_binding: "global",
          mapped_threat_count: 0,
          validated_threat_count: 0,
          indicated_threat_count: 0,
          unbound_finding_count: 2,
        },
      ],
      safety_controls: [
        {
          name: "Local path allowlist",
          status: "missing",
          detail:
            "Runner paths are not constrained yet, so live validation must remain blocked.",
        },
      ],
      gaps: [
        {
          title: "DFD binding required",
          severity: "high",
          detail:
            "Imported evidence cannot validate semantic threats until it is tied to modeled components.",
          next_action: "Add DFD nodes or bind imported findings to existing components.",
        },
      ],
    });

    renderPage();

    expect(await screen.findByText("Needs setup")).toBeInTheDocument();
    expect(screen.getAllByText("DFD needed").length).toBeGreaterThan(0);
    expect(
      screen.getByText(
        "Add DFD components or bind imported evidence so tool output can confirm semantic threats.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Local path allowlist")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Runner paths are not constrained yet, so live validation must remain blocked.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("DFD binding required")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Set THREATGENIX_VALIDATION_SEMGREP_ENABLED and install the CLI on the runner.",
      ),
    ).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("/allowed/repository/path"), "/allowed/repo");
    await user.click(screen.getByText("I am authorized to test this target and accept responsibility for the configured scope."));

    expect(screen.getByRole("button", { name: "Run Once" })).toBeDisabled();
    expect(api.runValidationTool).not.toHaveBeenCalled();
  });
});
