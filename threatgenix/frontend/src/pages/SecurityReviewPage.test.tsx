import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { ThreatModelResponse, ThreatResponse } from "../types/api";
import SecurityReviewPage from "./SecurityReviewPage";

vi.mock("../api/client", () => ({
  api: {
    getThreatModel: vi.fn(),
    getThreats: vi.fn(),
    getDFD: vi.fn(),
    getDFDQualityGates: vi.fn(),
    getThreatModelSecurityReview: vi.fn(),
    getThreatModelReviewFindings: vi.fn(),
  },
}));

vi.mock("../components/ThreatModelInspectorRail", () => ({
  ThreatModelInspectorRail: ({
    model,
    threats,
    initialSummary,
    initialFindingsResponse,
  }: {
    model: ThreatModelResponse;
    threats: ThreatResponse[];
    initialSummary: unknown;
    initialFindingsResponse: unknown;
  }) => (
    <section
      data-testid="security-review-workbench"
      data-initial-summary={String(initialSummary === null)}
      data-initial-findings={String(initialFindingsResponse === null)}
    >
      {model.system_name} review workspace · {threats.length} threats
    </section>
  ),
}));

const model: ThreatModelResponse = {
  id: "tm-1",
  system_name: "Northstar Bank Open Banking API",
  description: "Open banking API platform.",
  data_classification: "Restricted",
  regulatory_scope: [],
  deployment_model: null,
  repository_evidence: null,
  cloud_scan_evidence: null,
  iac_evidence: null,
  environment_context_summary: null,
  report_templates: [],
  created_at: "2026-04-28T00:00:00Z",
  updated_at: "2026-04-28T00:00:00Z",
};

const threat: ThreatResponse = {
  id: "threat-1",
  display_id: "T-001",
  description: "Token replay can bypass tenant isolation.",
  stride_category: "Spoofing",
  severity: "High",
  source: "rule",
  status: "Open",
  dismiss_reason: null,
  rule_id: null,
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
  created_at: "2026-04-28T00:00:00Z",
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/threat-models/tm-1/review?tab=findings"]}>
      <Routes>
        <Route path="/threat-models/:id/review" element={<SecurityReviewPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("SecurityReviewPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getThreatModel).mockResolvedValue(model);
    vi.mocked(api.getThreats).mockResolvedValue([threat]);
    vi.mocked(api.getDFD).mockResolvedValue({
      nodes: [],
      edges: [],
      trust_boundaries: [],
    });
    vi.mocked(api.getDFDQualityGates).mockRejectedValue(
      new Error("Quality gate summary unavailable."),
    );
  });

  it("renders the review shell without blocking on generated review data", async () => {
    renderPage();

    expect(await screen.findByText("Security Review")).toBeInTheDocument();
    expect(
      screen.getByText("Northstar Bank Open Banking API review workspace · 1 threats"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Loading security review…")).not.toBeInTheDocument();

    const workbench = screen.getByTestId("security-review-workbench");
    expect(workbench).toHaveAttribute("data-initial-summary", "true");
    expect(workbench).toHaveAttribute("data-initial-findings", "true");
    await waitFor(() => {
      expect(api.getThreatModelSecurityReview).not.toHaveBeenCalled();
      expect(api.getThreatModelReviewFindings).not.toHaveBeenCalled();
    });
  });

  it("shows repository evidence captured during intake", async () => {
    vi.mocked(api.getThreatModel).mockResolvedValue({
      ...model,
      repository_evidence: {
        source_type: "archive",
        filename: "example-org-threatgenix.zip",
        connection: {
          provider: "github",
          repository: "example-org/threatgenix",
          transport: "https",
          ref: "refs/pull/22/head",
          reference: "Pull request #22",
          connected_at: "2026-05-01T00:00:00Z",
          last_synced_at: "2026-05-01T00:00:00Z",
        },
        reference: "example-org/threatgenix@refs/pull/22/head :: Pull request #22",
        file_count: 42,
        pull_request: {
          provider: "github",
          repository: "example-org/threatgenix",
          number: 22,
          url: "https://github.com/example-org/threatgenix/pull/22",
          title: "Add review workflow",
          state: "open",
          base_ref: "main",
          head_ref: "review-workflow",
          head_sha: "abc123",
          changed_files: [
            {
              path: "frontend/src/pages/SecurityReviewPage.tsx",
              status: "modified",
              previous_path: null,
              additions: 12,
              deletions: 4,
              changes: 16,
            },
          ],
          changed_file_count: 3,
          truncated: false,
          fetched_at: "2026-05-01T00:00:00Z",
        },
        languages: ["TypeScript", "Python"],
        frameworks: ["React", "FastAPI"],
        entrypoints: [],
        api_routes: [],
        webhook_endpoints: [],
        route_auth_map: [],
        unprotected_routes: [],
        sensitive_routes: [],
        routes_with_raw_input: [],
        risky_routes: [],
        auth_surfaces: [],
        auth_mechanisms: [],
        data_stores: [],
        queues: [],
        external_integrations: [],
        outbound_calls: [],
        deployment_clues: [],
        infrastructure_resources: [],
        security_sensitive_paths: [],
        code_surfaces: [],
        code_control_signals: [],
        code_risk_signals: [],
        finding_code_links: [],
        code_evidence_summary: {
          surface_count: 0,
          route_count: 0,
          control_signal_count: 0,
          risk_signal_count: 0,
          linked_finding_count: 0,
          externally_reachable_surface_count: 0,
          unprotected_sensitive_surface_count: 0,
          verified_control_count: 0,
          missing_control_count: 0,
        },
        dfd_seed_suggestions: [
          {
            id: "repo-seed-api-layer",
            node_type: "process",
            label: "API layer",
            rationale: "Repository route definitions indicate externally reachable API surface.",
            source_refs: ["GET /api/reviews"],
            confidence: 0.82,
          },
          {
            id: "repo-seed-postgresql",
            node_type: "data_store",
            label: "PostgreSQL",
            rationale: "Repository dependency hints indicate a persisted data store.",
            source_refs: ["PostgreSQL"],
            confidence: 0.72,
          },
        ],
        warnings: [],
        parsed_at: "2026-05-01T00:00:00Z",
      },
    });

    renderPage();

    expect(
      await screen.findByText(
        /Repo evidence captured: example-org\/threatgenix@refs\/pull\/22\/head/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/42 files/)).toBeInTheDocument();
    expect(screen.getByText(/3 PR files changed/)).toBeInTheDocument();
    expect(screen.getByText(/2 DFD seeds/)).toBeInTheDocument();
  });

  it("normalizes forbidden review links into the branded not-found state", async () => {
    vi.mocked(api.getThreatModel).mockRejectedValue(new Error("403 Forbidden"));

    renderPage();

    expect(await screen.findByRole("heading", { name: "Security review not found" })).toBeInTheDocument();
    expect(screen.getByText(/may not have access/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to Dashboard" })).toHaveAttribute(
      "href",
      "/dashboard",
    );
    expect(screen.queryByText("403 Forbidden")).not.toBeInTheDocument();
  });
});
