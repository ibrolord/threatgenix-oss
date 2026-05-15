import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../../api/client";
import type { ScanJobDetail, ValidationRunbookResponse, ValidationToolInventoryResponse } from "../../types/api";
import { ScanPanel } from "./ScanPanel";

vi.mock("../../api/client", () => ({
  api: {
    getDFD: vi.fn(),
    getValidationTools: vi.fn(),
    getScan: vi.fn(),
    getScanRunbook: vi.fn(),
    ingestScanEvidence: vi.fn(),
    runValidationTool: vi.fn(),
  },
}));

const validationTools: ValidationToolInventoryResponse = {
  tools: [
    {
      name: "nuclei",
      active: true,
      available: true,
      deterministic: true,
      runtime_strategy: "host_cli",
      runtime_detail: "Runs from a CLI installed on the validation runner host.",
      readiness_status: "ready",
      blocker_reasons: [],
      setup_actions: ["Create or run a validation target with per-run authorization."],
      install_hint: null,
      enablement_env: "THREATGENIX_VALIDATION_NUCLEI_ENABLED",
      local_allowlist_required: false,
      local_allowlist_configured: false,
      sandbox_mode: "process",
      container_runtime_available: true,
      container_image: null,
      container_image_present: false,
      container_pull_policy: "never",
      supported_targets: ["url"],
      runs_in_sandbox_required: false,
      execution_enabled: true,
      network_mode: "target_only",
      max_runtime_seconds: 600,
      max_output_bytes: 2_000_000,
      artifact_capture_enabled: true,
      category: "dynamic_template_scan",
      proof_mode: "HTTP proof of finding",
      safety_boundary: "Authorization required.",
      documentation_url: "https://docs.projectdiscovery.io/tools/nuclei/overview",
      recommended_for: ["known CVEs"],
    },
    {
      name: "semgrep",
      active: true,
      available: false,
      deterministic: true,
      runtime_strategy: "unavailable",
      runtime_detail: "semgrep CLI is not installed or not on PATH.",
      readiness_status: "policy_disabled",
      blocker_reasons: ["semgrep CLI is not installed or not on PATH."],
      setup_actions: ["brew install semgrep"],
      install_hint: "brew install semgrep",
      enablement_env: "THREATGENIX_VALIDATION_SEMGREP_ENABLED",
      local_allowlist_required: true,
      local_allowlist_configured: false,
      sandbox_mode: "process",
      container_runtime_available: true,
      container_image: "semgrep/semgrep:latest",
      container_image_present: false,
      container_pull_policy: "never",
      supported_targets: ["repository_path"],
      runs_in_sandbox_required: true,
      execution_enabled: false,
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
    {
      name: "trivy",
      active: true,
      available: true,
      deterministic: true,
      runtime_strategy: "host_cli",
      runtime_detail: "Runs from a CLI installed on the validation runner host.",
      readiness_status: "ready",
      blocker_reasons: [],
      setup_actions: ["Create or run a validation target with per-run authorization."],
      install_hint: null,
      enablement_env: "THREATGENIX_VALIDATION_TRIVY_ENABLED",
      local_allowlist_required: true,
      local_allowlist_configured: true,
      sandbox_mode: "process",
      container_runtime_available: true,
      container_image: "aquasec/trivy:latest",
      container_image_present: false,
      container_pull_policy: "never",
      supported_targets: ["repository_path", "iac_directory"],
      runs_in_sandbox_required: true,
      execution_enabled: true,
      network_mode: "none",
      max_runtime_seconds: 900,
      max_output_bytes: 10_000_000,
      artifact_capture_enabled: true,
      category: "misconfiguration_scan",
      proof_mode: "offline configuration evidence",
      safety_boundary: "Local path allowlist.",
      documentation_url: "https://trivy.dev/latest/",
      recommended_for: ["IaC misconfiguration"],
    },
  ],
  red_team_tools: [],
};

const scanDetail: ScanJobDetail = {
  id: "scan-1",
  threat_model_id: "tm-1",
  status: "completed",
  scan_type: "unauthenticated",
  scope: "external",
  tool_name: "semgrep",
  target_type: "repository_path",
  targets: { ingested: "/repo" },
  finding_count: 1,
  credential_id: null,
  started_at: "2026-04-25T00:00:00Z",
  completed_at: "2026-04-25T00:00:02Z",
  error_message: null,
  created_at: "2026-04-25T00:00:00Z",
  findings: [
    {
      id: "finding-1",
      template_id: "javascript.express.security.audit.csrf",
      template_name: "Express missing CSRF protection",
      severity: "high",
      matched_at: "/repo/src/app.ts:44",
      extracted_results: null,
      cve_ids: ["CVE-2026-1234"],
      tags: ["owasp", "csrf"],
      cvss_score: 7.4,
      tool_name: "semgrep",
      tool_version: "1.2.3",
      validation_target: "/repo",
      deterministic: true,
      created_at: "2026-04-25T00:00:02Z",
    },
  ],
  threat_results: [
    {
      id: "scan-threat-1",
      threat_id: "threat-1",
      scan_status: "confirmed",
      evidence: [
        {
          finding_id: "finding-1",
          template_id: "javascript.express.security.audit.csrf",
          template_name: "Express missing CSRF protection",
          severity: "high",
          matched_at: "/repo/src/app.ts:44",
          cve_ids: ["CVE-2026-1234"],
          tool_name: "semgrep",
          tool_version: "1.2.3",
          validation_target: "/repo",
          deterministic: true,
        },
      ],
      cve_ids: ["CVE-2026-1234"],
      created_at: "2026-04-25T00:00:02Z",
    },
  ],
  execution_artifacts: [
    {
      id: "artifact-1",
      scan_job_id: "scan-1",
      source: "execution",
      tool_name: "semgrep",
      target_type: "repository_path",
      target: "/repo",
      resolved_target: "/tmp/threatgenix-validation/repo",
      status: "completed",
      deterministic: true,
      sandboxed: true,
      sandbox_mode: "process",
      container_image: null,
      resource_limits: { timeout_seconds: "600", max_output_bytes: "5000000" },
      policy_decision: "allowed",
      command: ["semgrep", "--json", "/repo"],
      command_redacted: true,
      returncode: 0,
      timed_out: false,
      output_limit_exceeded: false,
      stdout_bytes: 2560,
      stderr_summary: null,
      network_mode: "none",
      max_runtime_seconds: 600,
      max_output_bytes: 5_000_000,
      started_at: "2026-04-25T00:00:00Z",
      completed_at: "2026-04-25T00:00:02Z",
      duration_ms: 1250,
      created_at: "2026-04-25T00:00:02Z",
    },
  ],
};

const runbook: ValidationRunbookResponse = {
  coverage: {
    scan_job_id: "scan-1",
    scan_completed_at: "2026-04-25T00:00:02Z",
    tool_names: ["semgrep"],
    target_binding: "global",
    finding_count: 1,
    deterministic_finding_count: 1,
    assisted_finding_count: 0,
    artifact_count: 1,
    mapped_threat_count: 1,
    validated_threat_count: 0,
    indicated_threat_count: 1,
    unbound_finding_count: 1,
    untested_threat_count: 3,
    confidence_counts: { indicated: 1, untested: 3 },
    validated_risk_score: 0,
    indicated_risk_score: 60,
    ai_assisted_risk_score: 0,
  },
  executive_summary: "Semgrep produced 1 deterministic finding(s), 0 validated threat(s), 1 indicated threat(s), and 1 unbound finding(s). 3 active threat(s) still need validation evidence.",
  gaps: ["Validation targets were not bound to DFD nodes."],
  mapped_threats: [
    {
      threat_id: "threat-1",
      threat_display_id: "T-001",
      threat_description: "Missing CSRF protection",
      severity: "High",
      stride_category: "Tampering",
      scan_status: "confirmed",
      confidence_label: "indicated",
      explanation: "Evidence exists, but it is not bound to a specific affected DFD node.",
      evidence_count: 1,
      risk_score: 60,
      evidence_quality: "moderate",
      proof_class: "deterministic",
      next_action: "Bind the target to a modeled component and rerun validation.",
      cve_ids: ["CVE-2026-1234"],
      validation_tools: ["semgrep"],
    },
  ],
  unbound_findings: [
    {
      finding_id: "finding-1",
      title: "Express missing CSRF protection",
      severity: "high",
      tool_name: "semgrep",
      target: "/repo",
      matched_at: "/repo/src/app.ts:44",
      cve_ids: ["CVE-2026-1234"],
      tags: ["owasp", "csrf"],
      confidence_label: "untested",
      evidence_scope: "unbound",
      proof_class: "deterministic",
      evidence_quality: "moderate",
      risk_score: 44,
      next_action: "Bind this finding to an affected DFD node or mark it not applicable.",
      explanation: "Finding was retained as deterministic evidence, but it is not validated against a specific semantic threat.",
    },
  ],
};

describe("ScanPanel", () => {
  let storage: Map<string, string>;

  beforeEach(() => {
    vi.clearAllMocks();
    storage = new Map([["tg_token", "token-123"]]);
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => storage.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => {
        storage.set(key, value);
      }),
      removeItem: vi.fn((key: string) => {
        storage.delete(key);
      }),
      clear: vi.fn(() => {
        storage.clear();
      }),
    });
    localStorage.setItem("tg_token", "token-123");
    vi.mocked(api.getDFD).mockResolvedValue({ nodes: [], edges: [], trust_boundaries: [] });
    vi.mocked(api.getValidationTools).mockResolvedValue(validationTools);
    vi.mocked(api.getScan).mockResolvedValue(scanDetail);
    vi.mocked(api.getScanRunbook).mockResolvedValue(runbook);
    vi.mocked(api.ingestScanEvidence).mockResolvedValue({
      id: "scan-import",
      threat_model_id: "tm-1",
      status: "completed",
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "semgrep",
      target_type: "repository_path",
      targets: { direct: "/repo" },
      finding_count: 1,
      credential_id: null,
      started_at: null,
      completed_at: "2026-04-25T00:00:00Z",
      error_message: null,
      created_at: "2026-04-25T00:00:00Z",
      findings: [],
      threat_results: [],
      execution_artifacts: [],
    });
    vi.mocked(api.runValidationTool).mockResolvedValue({
      id: "scan-run",
      threat_model_id: "tm-1",
      status: "pending",
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "trivy",
      target_type: "iac_directory",
      targets: { direct: "/repo/infra" },
      finding_count: 0,
      credential_id: null,
      started_at: null,
      completed_at: null,
      error_message: null,
      created_at: "2026-04-25T00:00:00Z",
    });
  });

  afterEach(() => {
    storage.clear();
    vi.unstubAllGlobals();
  });

  it("shows validation tool dispatch metadata on scan rows", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.includes("/scans")) {
          return new Response(
            JSON.stringify([
              {
                id: "scan-1",
                threat_model_id: "tm-1",
                status: "completed",
                scan_type: "unauthenticated",
                scope: "external",
                tool_name: "semgrep",
                target_type: "repository_path",
                targets: { ingested: "/repo" },
                finding_count: 2,
                credential_id: null,
                started_at: null,
                completed_at: "2026-04-25T00:00:00Z",
                error_message: null,
                created_at: "2026-04-25T00:00:00Z",
              },
            ]),
            { status: 200 }
          );
        }
        return new Response("{}", { status: 404 });
      })
    );

    render(<ScanPanel threatModelId="tm-1" />);

    expect(await screen.findByText("Threat Validation Scan")).toBeInTheDocument();
    expect(await screen.findByText("Semgrep")).toBeInTheDocument();
    expect(
      screen.getByText("Semgrep · repository path · unauthenticated · external")
    ).toBeInTheDocument();
  });

  it("loads detailed scan artifacts into the evidence ledger", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.includes("/scans")) {
          return new Response(
            JSON.stringify([
              {
                id: "scan-1",
                threat_model_id: "tm-1",
                status: "completed",
                scan_type: "unauthenticated",
                scope: "external",
                tool_name: "semgrep",
                target_type: "repository_path",
                targets: { ingested: "/repo" },
                finding_count: 1,
                credential_id: null,
                started_at: "2026-04-25T00:00:00Z",
                completed_at: "2026-04-25T00:00:02Z",
                error_message: null,
                created_at: "2026-04-25T00:00:00Z",
              },
            ]),
            { status: 200 }
          );
        }
        return new Response("{}", { status: 404 });
      })
    );
    const user = userEvent.setup();

    render(<ScanPanel threatModelId="tm-1" />);

    await user.click(await screen.findByRole("button", { name: "View Evidence" }));

    await waitFor(() => expect(api.getScan).toHaveBeenCalledWith("tm-1", "scan-1"));
    expect(api.getScanRunbook).toHaveBeenCalledWith("tm-1", "scan-1");
    expect(await screen.findByText("Validation Evidence Ledger")).toBeInTheDocument();
    expect(screen.getByText("Validation Runbook")).toBeInTheDocument();
    expect(screen.getByText("Unbound Evidence")).toBeInTheDocument();
    expect(screen.getByText("Semgrep · repository path")).toBeInTheDocument();
    expect(screen.getByText(/semgrep --json \/repo/)).toBeInTheDocument();
    expect(screen.getByText(/1 confirmed/)).toBeInTheDocument();
    expect(screen.getByText(/2.5 KB/)).toBeInTheDocument();
    expect(screen.getAllByText("Express missing CSRF protection").length).toBeGreaterThan(0);
  });

  it("keeps scan detail usable when the runbook endpoint is unavailable", async () => {
    vi.mocked(api.getScanRunbook).mockRejectedValue(new Error("No runbook"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.includes("/scans")) {
          return new Response(
            JSON.stringify([
              {
                id: "scan-1",
                threat_model_id: "tm-1",
                status: "completed",
                scan_type: "unauthenticated",
                scope: "external",
                tool_name: "semgrep",
                target_type: "repository_path",
                targets: { ingested: "/repo" },
                finding_count: 1,
                credential_id: null,
                started_at: "2026-04-25T00:00:00Z",
                completed_at: "2026-04-25T00:00:02Z",
                error_message: null,
                created_at: "2026-04-25T00:00:00Z",
              },
            ]),
            { status: 200 }
          );
        }
        return new Response("{}", { status: 404 });
      })
    );
    const user = userEvent.setup();

    render(<ScanPanel threatModelId="tm-1" />);

    await user.click(await screen.findByRole("button", { name: "View Evidence" }));

    expect(await screen.findByText("Validation Evidence Ledger")).toBeInTheDocument();
    expect(screen.getByText("Execution Provenance")).toBeInTheDocument();
    expect(screen.queryByText("Could not load scan evidence")).not.toBeInTheDocument();
  });

  it("submits nuclei URL dispatch fields for live scans", async () => {
    let postedBody: Record<string, unknown> | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.endsWith("/scans") && init?.method === "POST") {
          postedBody = JSON.parse(String(init.body));
          return new Response(
            JSON.stringify({
              id: "scan-2",
              threat_model_id: "tm-1",
              status: "pending",
              scan_type: "unauthenticated",
              scope: "external",
              tool_name: "nuclei",
              target_type: "url",
              targets: { "node-1": "https://api.example.com" },
              finding_count: 0,
              credential_id: null,
              started_at: null,
              completed_at: null,
              error_message: null,
              created_at: "2026-04-25T00:00:00Z",
            }),
            { status: 201 }
          );
        }
        if (url.includes("/scans")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response("{}", { status: 404 });
      })
    );
    const user = userEvent.setup();

    render(<ScanPanel threatModelId="tm-1" />);

    await user.click(await screen.findByRole("button", { name: "Run Scan" }));
    await user.click(screen.getByLabelText(/I confirm I am authorized/));
    await user.click(screen.getByRole("button", { name: /I Confirm/ }));

    await waitFor(() => expect(postedBody).not.toBeNull());
    expect(postedBody).toMatchObject({
      scan_type: "unauthenticated",
      scope: "external",
      tool_name: "nuclei",
      target_type: "url",
      authorization_acknowledged: true,
      credential_id: null,
    });
  });

  it("imports captured validation evidence with selected tool and target", async () => {
    vi.mocked(api.getDFD).mockResolvedValue({
      nodes: [
        {
          id: "node-1",
          node_type: "process",
          name: "API Gateway",
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
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.includes("/scans")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response("{}", { status: 404 });
      })
    );
    const user = userEvent.setup();

    render(<ScanPanel threatModelId="tm-1" />);

    await user.click(await screen.findByRole("button", { name: "Evidence" }));
    await user.type(screen.getByLabelText("Target"), "/repo");
    await user.selectOptions(screen.getByLabelText("DFD Node Binding"), "node-1");
    fireEvent.change(screen.getByLabelText("Evidence Output"), {
      target: { value: "{\"results\":[]}" },
    });
    await user.click(screen.getByRole("button", { name: "Import Evidence" }));

    await waitFor(() => expect(api.ingestScanEvidence).toHaveBeenCalledTimes(1));
    expect(api.ingestScanEvidence).toHaveBeenCalledWith("tm-1", {
      tool_name: "semgrep",
      target_type: "repository_path",
      target: "/repo",
      raw_output: "{\"results\":[]}",
      target_node_id: "node-1",
    });
  });

  it("imports external pentest report evidence from the scan modal", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.includes("/scans")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response("{}", { status: 404 });
      })
    );
    const user = userEvent.setup();

    render(<ScanPanel threatModelId="tm-1" />);

    await user.click(await screen.findByRole("button", { name: "Evidence" }));
    await user.selectOptions(screen.getByLabelText("Tool or Source"), "pentest-report");
    await user.type(screen.getByLabelText("Target"), "Q2 pentest report");
    fireEvent.change(screen.getByLabelText("Evidence Output"), {
      target: { value: "High: API Gateway accepts unsigned JWTs" },
    });
    await user.click(screen.getByRole("button", { name: "Import Evidence" }));

    await waitFor(() => expect(api.ingestScanEvidence).toHaveBeenCalledTimes(1));
    expect(api.ingestScanEvidence).toHaveBeenCalledWith("tm-1", {
      tool_name: "pentest-report",
      target_type: "url",
      target: "Q2 pentest report",
      raw_output: "High: API Gateway accepts unsigned JWTs",
      target_node_id: null,
    });
  });

  it("filters target types by selected validation tool for live runs", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scan-credentials")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.includes("/scans")) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response("{}", { status: 404 });
      })
    );
    const user = userEvent.setup();

    render(<ScanPanel threatModelId="tm-1" />);

    await user.click(await screen.findByRole("button", { name: "Evidence" }));
    await user.click(screen.getByRole("button", { name: "Run Tool" }));
    await user.selectOptions(screen.getByLabelText("Tool"), "trivy");
    await user.selectOptions(screen.getByLabelText("Target Type"), "iac_directory");
    await user.type(screen.getByLabelText("Target"), "/repo/infra");
    await user.click(screen.getByLabelText(/I confirm I am authorized/));
    await user.click(screen.getByRole("button", { name: "Run Validation" }));

    await waitFor(() => expect(api.runValidationTool).toHaveBeenCalledTimes(1));
    expect(api.runValidationTool).toHaveBeenCalledWith("tm-1", {
      tool_name: "trivy",
      target_type: "iac_directory",
      target: "/repo/infra",
      target_node_id: null,
      scope: "external",
      authorization_acknowledged: true,
    });
  });
});
